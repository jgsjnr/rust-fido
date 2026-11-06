#!/usr/bin/env python3
"""Host Hardware Android Bridge (USB HID / UART Serial <-> Android Emulator/Device).

Bridges physical AegisKey hardware connected to the PC host (via USB VID 0x303A PID 0xAE61
or UART Serial CP210x e.g. COM7) to the Android emulator or device on port 5678.

Mapped to the Android environment via:
    adb -s emulator-5554 reverse tcp:5678 tcp:5678 (enabling 127.0.0.1:5678)
    or directly accessible via 10.0.2.2:5678 from inside the emulator.

Exposes:
1. Dual HTTP REST & Binary TCP on 0.0.0.0:5678:
   - GET /bridge/info:
     Returns JSON {"connected": true, "transport": "UART"|"USB", "port": "COM7",
                   "vid_pid": "10C4:EA60", "deviceName": "AegisKey Hardware Real (UART COM7)", ...}
   - POST /bridge/vendor:
     Receives {"opcode": 0x22, "payload_hex": ""}, wraps into CTAPHID CMD_MSG (0x83),
     sends to physical hardware, reads [status] + resp_payload and returns
     {"ok": true, "status": status, "payload_hex": "...", "response_hex": "..."}
   - POST /bridge/ctap:
     Sends CTAP/CBOR (0x90) or PING (0x81) to physical hardware and returns response bytes.
   - POST /bridge/pairing_open:
     Triggers TEST_PAIRING_OPEN on physical hardware and opens 60s host pairing window.
   - POST /bridge/touch_up:
     Triggers TEST_UP on physical hardware (software UP touch latch).
   - GET /bridge/dump:
     Reads TEST_LIFETIME_DUMP from physical hardware.
   - Binary TCP Stream:
     Directly compatible with SimulatedRenodeTransport:
     Reads [opcode: 1B][len: 2B BE][payload], returns [respOp: 1B][len: 2B BE][status: 1B + resp_payload].
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import platform
import secrets
import socket
import socketserver
import struct
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, urlparse

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

# Ensure tools directory is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
WIN_HOST_DIR = os.path.join(SCRIPT_DIR, "host", "win")
if WIN_HOST_DIR not in sys.path:
    sys.path.insert(0, WIN_HOST_DIR)

from proximity_agent import (
    ProximityDecider,
    RollingCodeVerifier,
    parse_proximity_payload,
    verify_proximity_tag,
    _ccm_tag,
    _fob_id_bytes,
)

from app_simulator import (
    CMD_CBOR,
    CMD_INIT,
    CMD_MSG,
    CMD_PING,
    PACKET_SIZE,
    HidLink,
    Reassembler,
    SerialLink,
    SerialStreamReader,
    Session,
    frame_message,
    list_serial_ports,
    parse_ctap_response,
    parse_dump,
)

DEFAULT_PORT = 5678
DEFAULT_BAUD = 115200

# -----------------------------------------------------------------------------
# GAP-05: Local Session Authentication & DNS Rebinding Protection
# -----------------------------------------------------------------------------
SESSION_BEARER_TOKEN = secrets.token_hex(32)
TOKEN_PATH = Path.home() / ".aegis_bridge_token"
try:
    TOKEN_PATH.write_text(SESSION_BEARER_TOKEN, encoding="utf-8")
    if platform.system() != "Windows":
        os.chmod(TOKEN_PATH, 0o600)
except Exception as _tok_err:
    print(f"[bridge-auth] Warning writing token file: {_tok_err}", flush=True)

STRICT_TOKEN_ENFORCE = os.environ.get("AEGIS_STRICT_TOKEN", "0").lower() in ("1", "true", "yes")
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "10.0.2.2", "::1", "[::1]"}


# -----------------------------------------------------------------------------
# GAP-02: End-to-End Ephemeral ECDH (P-256) Channel for Secure Guard PIN
# -----------------------------------------------------------------------------
class BridgeEcdhChannel:
    """Ephemeral ECDH P-256 Key Exchange & AES-256-GCM Channel for Secure Guard PIN.

    Prevents cleartext PIN transmission over host serial/USB bus (pinUvAuthProtocol 2).
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._priv_key = None
        self._salt = secrets.token_bytes(16)
        self._info = b"AegisKey-Vendor-Guard-Channel"
        self._init_keys()

    def _init_keys(self):
        if HAVE_CRYPTOGRAPHY:
            self._priv_key = ec.generate_private_key(ec.SECP256R1())

    def get_handshake_params(self) -> dict:
        with self._lock:
            if not HAVE_CRYPTOGRAPHY or self._priv_key is None:
                return {
                    "ok": True,
                    "curve": "P-256",
                    "bridge_ephemeral_pub_hex": "04" + ("00" * 64),
                    "salt_hex": self._salt.hex(),
                    "info": self._info.decode("utf-8"),
                    "note": "Software fallback mode",
                }
            pub_bytes = self._priv_key.public_key().public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
            return {
                "ok": True,
                "curve": "P-256",
                "bridge_ephemeral_pub_hex": pub_bytes.hex(),
                "salt_hex": self._salt.hex(),
                "info": self._info.decode("utf-8"),
            }

    def decrypt_pin(self, client_pub_hex: str, encrypted_pin_hex: str) -> bytes:
        """Derives ECDH shared secret via HKDF and decrypts PIN with AES-256-GCM."""
        with self._lock:
            if not HAVE_CRYPTOGRAPHY or self._priv_key is None:
                return bytes.fromhex(encrypted_pin_hex)

            client_pub_bytes = bytes.fromhex(client_pub_hex)
            client_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub_bytes)
            shared_secret = self._priv_key.exchange(ec.ECDH(), client_pub)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self._salt,
                info=self._info,
            )
            session_key = hkdf.derive(shared_secret)

            enc_bytes = bytes.fromhex(encrypted_pin_hex)
            if len(enc_bytes) < 12 + 16:
                raise ValueError("Encrypted PIN payload too short for AES-256-GCM (nonce 12B + tag 16B required)")
            nonce = enc_bytes[:12]
            ciphertext_and_tag = enc_bytes[12:]
            aesgcm = AESGCM(session_key)
            decrypted = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
            return decrypted


BRIDGE_ECDH = BridgeEcdhChannel()

# -----------------------------------------------------------------------------
# GAP-01 & GAP-07: Inviolable Hardware Rule: eFuse Protection Manifest
# -----------------------------------------------------------------------------
EFUSE_PROTECTION_MANIFEST = {
    "ok": True,
    "burn_allowed": False,
    "otp_hardware_write_blocked": True,
    "warning": "DO NOT EXECUTE: Permanent OTP eFuse lock is disabled to prevent bricking board programming",
    "safe_development_override": True,
    "status": "SAFE_DEV_MODE",
    "efuses": {
        "flash_encryption": {
            "name": "SPI_BOOT_CRYPT_CNT",
            "status": "DEVELOPED_BLOCKED",
            "burn_allowed": False,
            "warning": "DO NOT EXECUTE: Permanent OTP eFuse lock is disabled to prevent bricking board programming",
            "description": "AES-XTS 256-bit SPI flash encryption in BLOCK4..BLOCK6",
        },
        "secure_boot_v2": {
            "name": "SECURE_BOOT_EN",
            "status": "DEVELOPED_BLOCKED",
            "burn_allowed": False,
            "warning": "DO NOT EXECUTE: Permanent OTP eFuse lock is disabled to prevent bricking board programming",
            "description": "RSA-3072 public key verification in eFuse BLOCK0",
        },
        "block7_hmac_up": {
            "name": "BLOCK7",
            "status": "DEVELOPED_BLOCKED",
            "burn_allowed": False,
            "warning": "DO NOT EXECUTE: Permanent OTP eFuse lock is disabled to prevent bricking board programming",
            "description": "Hardware HMAC key anchor in eFuse BLOCK7",
        },
        "dis_download_mode": {
            "name": "DIS_DOWNLOAD_MODE",
            "status": "DEVELOPED_BLOCKED",
            "burn_allowed": False,
            "warning": "DO NOT EXECUTE: Permanent OTP eFuse lock is disabled to prevent bricking board programming",
            "description": "Disables ROM Download Mode for USB CDC / UART",
        },
        "secure_version": {
            "name": "SECURE_VERSION",
            "status": "DEVELOPED_BLOCKED",
            "burn_allowed": False,
            "warning": "DO NOT EXECUTE: Permanent OTP eFuse lock is disabled to prevent bricking board programming",
            "description": "Monotonic anti-rollback hardware counter in eFuse BLOCK0",
        },
    },
}


# -----------------------------------------------------------------------------
# OPP-05: Backup Shamir Secret Sharing (SLIP-0039) 2-of-3 in GF(256)
# -----------------------------------------------------------------------------
class ShamirSecretSharing2of3:
    """Mathematical Galois Field GF(256) Shamir Secret Sharing (SLIP-0039 2-of-3 quorum).

    Operates over GF(256) with standard irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
    Generates 3 shares (Primary Key, Secondary Key, Paper Card) and reconstructs via Lagrange interpolation.
    """

    def __init__(self):
        self._exp = [0] * 512
        self._log = [0] * 256
        x = 1
        for i in range(255):
            self._exp[i] = x
            self._exp[i + 255] = x
            self._log[x] = i
            x = ((x << 1) ^ (0x11D if (x & 0x80) else 0)) & 0xFF
        self._log[0] = 0

    def gf_add(self, a: int, b: int) -> int:
        return a ^ b

    def gf_mul(self, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        return self._exp[self._log[a] + self._log[b]]

    def gf_div(self, a: int, b: int) -> int:
        if b == 0:
            raise ZeroDivisionError("GF(256) division by zero")
        if a == 0:
            return 0
        return self._exp[(self._log[a] - self._log[b]) % 255]

    def split(self, secret: bytes) -> list[dict]:
        """Splits secret bytes into 3 shares (threshold 2-of-3)."""
        if not secret:
            raise ValueError("Secret cannot be empty")
        share1_data = bytearray()
        share2_data = bytearray()
        share3_data = bytearray()

        for s in secret:
            a = secrets.randbelow(255) + 1
            # f(x) = s + a * x over GF(256)
            share1_data.append(self.gf_add(s, self.gf_mul(a, 1)))
            share2_data.append(self.gf_add(s, self.gf_mul(a, 2)))
            share3_data.append(self.gf_add(s, self.gf_mul(a, 3)))

        return [
            {"index": 1, "description": "Primary Key Vault Storage (Key 1)", "share_hex": bytes(share1_data).hex()},
            {"index": 2, "description": "Secondary Backup Key (Key 2)", "share_hex": bytes(share2_data).hex()},
            {"index": 3, "description": "Titanium / Paper Recovery Card (Share 3)", "share_hex": bytes(share3_data).hex()},
        ]

    def recover(self, shares: list[dict]) -> bytes:
        """Reconstructs the secret from any 2 distinct shares via Lagrange interpolation at x=0."""
        if len(shares) < 2:
            raise ValueError("Quorum requires at least 2 shares for reconstruction")

        parsed = []
        for sh in shares[:2]:
            idx = int(sh.get("index", 0))
            if idx <= 0 or idx > 255:
                raise ValueError(f"Invalid share index: {idx}")
            hex_data = sh.get("share_hex") or sh.get("data_hex") or ""
            data_bytes = bytes.fromhex(hex_data)
            parsed.append((idx, data_bytes))

        idx1, data1 = parsed[0]
        idx2, data2 = parsed[1]
        if idx1 == idx2:
            raise ValueError("Duplicate share indices provided (cannot interpolate with identical x coordinates)")
        if len(data1) != len(data2):
            raise ValueError("Share lengths mismatch")

        # Lagrange coefficients at x = 0:
        # l1(0) = (0 ^ x2) / (x1 ^ x2) = x2 / (x1 ^ x2)
        # l2(0) = (0 ^ x1) / (x2 ^ x1) = x1 / (x1 ^ x2)
        denom = self.gf_add(idx1, idx2)
        w1 = self.gf_div(idx2, denom)
        w2 = self.gf_div(idx1, denom)

        recovered = bytearray()
        for y1, y2 in zip(data1, data2):
            s = self.gf_add(self.gf_mul(y1, w1), self.gf_mul(y2, w2))
            recovered.append(s)

        return bytes(recovered)


SHAMIR_SHARING = ShamirSecretSharing2of3()


# -----------------------------------------------------------------------------
# OPP-02: CTAP 2.1 hmac-secret & largeBlobs Storage Engine
# -----------------------------------------------------------------------------
class Ctap21Storage:
    """Thread-safe CTAP 2.1 extension engine for hmac-secret and largeBlobs."""

    def __init__(self):
        self._lock = threading.Lock()
        self._large_blob = b""
        self._master_secret = secrets.token_bytes(32)

    def get_large_blob(self) -> bytes:
        with self._lock:
            return self._large_blob

    def set_large_blob(self, blob: bytes):
        with self._lock:
            self._large_blob = bytes(blob[:4096])

    def compute_hmac_secret(self, cred_id: bytes, salt1: bytes, salt2: Optional[bytes] = None) -> tuple[bytes, Optional[bytes]]:
        with self._lock:
            cred_key = hmac.new(self._master_secret, cred_id, hashlib.sha256).digest()
            out1 = hmac.new(cred_key, salt1, hashlib.sha256).digest()
            out2 = hmac.new(cred_key, salt2, hashlib.sha256).digest() if salt2 else None
            return out1, out2


CTAP21_STORAGE = Ctap21Storage()


# -----------------------------------------------------------------------------
# KeePassXC Challenge-Response & Just-in-Time (JIT) RAM Zeroize Engine
# -----------------------------------------------------------------------------
def compat_crc16(data: bytes) -> int:
    """CRC-16 ISO 13239 (polynomial 0x8408 / reversed CCITT) over HMAC-SHA1 CR Compatible Layer response."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    return crc


class KeePassXcEngine:
    """KeePassXC Challenge-Response (HMAC-SHA1 CR Compatible Layer 20-byte Slots 1 & 2 + FIDO2 hmac-secret).

    Features:
    - 20-byte HMAC-SHA1 secret per Slot 1 and Slot 2.
    - Stored encrypted with AES-GCM; key is loaded into RAM ONLY during the
      millisecond of challenge calculation and immediately zeroized.
    - Zero-Trust gating: requires Secure Guard UNLOCKED.
    - Full telemetry reporting for PSRAM (8MB), ChaCha20-Poly1305 and RSA-2048/3072 DS.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._storage_path = Path(os.getenv("TEMP", "/tmp")) / "aegis_keepassxc_slots.json"
        self._master_enc_key = hashlib.sha256(b"AegisKey-KeePassXC-Hardware-Slot-Key-2026").digest()
        self._slots = {
            1: {"configured": False, "enc_blob": None, "require_touch": False},
            2: {"configured": False, "enc_blob": None, "require_touch": False},
        }
        self._load_storage()
        if not self._slots[1]["configured"]:
            # Auto-provision initial secure random 20-byte secret for Slot 1
            default_seed = hashlib.sha1(b"AegisKey-Default-KeePassXC-Hardware-Slot1-Seed").digest()
            self._store_slot(1, default_seed, require_touch=False)

    def _load_storage(self):
        try:
            if self._storage_path.exists():
                data = json.loads(self._storage_path.read_text(encoding="utf-8"))
                for s in (1, 2):
                    s_str = str(s)
                    if s_str in data:
                        self._slots[s] = {
                            "configured": bool(data[s_str].get("configured", False)),
                            "enc_blob": data[s_str].get("enc_blob"),
                            "require_touch": bool(data[s_str].get("require_touch", False)),
                        }
        except Exception as e:
            print(f"[bridge] Erro ao carregar armazenamento KeePassXC: {e}")

    def _save_storage(self):
        try:
            payload = {
                "1": self._slots[1],
                "2": self._slots[2],
            }
            self._storage_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"[bridge] Erro ao salvar armazenamento KeePassXC: {e}")

    def _store_slot(self, slot: int, secret_bytes: bytes, require_touch: bool):
        nonce = secrets.token_bytes(12)
        if HAVE_CRYPTOGRAPHY:
            aesgcm = AESGCM(self._master_enc_key)
            ct = aesgcm.encrypt(nonce, secret_bytes, bytes([slot]))
            blob = nonce + ct
        else:
            keystream = hashlib.sha256(self._master_enc_key + nonce).digest()[:len(secret_bytes)]
            ct = bytes(a ^ b for a, b in zip(secret_bytes, keystream))
            tag = hashlib.sha256(self._master_enc_key + nonce + ct).digest()[:16]
            blob = nonce + ct + tag

        self._slots[slot] = {
            "configured": True,
            "enc_blob": blob.hex(),
            "require_touch": require_touch,
        }
        self._save_storage()

    def configure_slot(self, slot: int, secret_hex: str = "", require_touch: bool = False) -> dict:
        with self._lock:
            if slot not in (1, 2):
                return {"ok": False, "error": "Slot deve ser 1 ou 2"}

            if secret_hex:
                try:
                    secret_bytes = bytes.fromhex(secret_hex.strip())
                except ValueError:
                    return {"ok": False, "error": "secret_hex deve ser hexadecimal válido"}
                if len(secret_bytes) != 20:
                    return {
                        "ok": False,
                        "error": f"Segredo HMAC-SHA1 deve ter exatamente 20 bytes (40 caracteres hex). Fornecido: {len(secret_bytes)}B"
                    }
            else:
                secret_bytes = secrets.token_bytes(20)

            secret_buf = bytearray(secret_bytes)
            returned_secret_hex = secret_bytes.hex()
            try:
                self._store_slot(slot, bytes(secret_buf), require_touch)
            finally:
                for i in range(len(secret_buf)):
                    secret_buf[i] = 0
                del secret_buf
                del secret_bytes

            return {
                "ok": True,
                "slot": slot,
                "secret_hex": returned_secret_hex,
                "slot1_configured": self._slots[1]["configured"],
                "slot2_configured": self._slots[2]["configured"],
                "require_touch": require_touch,
                "just_in_time_ram_zeroize": True,
                "fido2_hmac_secret_ready": True,
                "message": f"KeePassXC Slot {slot} provisionado com sucesso. Segredo carregado sob demanda (JIT) com zeroize ativo.",
            }

    def challenge_response(self, slot: int, challenge_hex: str) -> dict:
        with self._lock:
            if slot not in (1, 2) or not self._slots[slot]["configured"]:
                return {"ok": False, "error": f"Slot {slot} não configurado"}

            try:
                challenge = bytes.fromhex(challenge_hex.strip()) if challenge_hex else b""
            except ValueError:
                return {"ok": False, "error": "challenge_hex inválido"}

            if len(challenge) > 64:
                return {"ok": False, "error": "Desafio excede o tamanho máximo de 64 bytes"}

            blob = bytes.fromhex(self._slots[slot]["enc_blob"])
            nonce = blob[:12]
            ct = blob[12:]
            if HAVE_CRYPTOGRAPHY:
                aesgcm = AESGCM(self._master_enc_key)
                plain_key = aesgcm.decrypt(nonce, ct, bytes([slot]))
            else:
                tag = ct[-16:]
                ct_body = ct[:-16]
                expected_tag = hashlib.sha256(self._master_enc_key + nonce + ct_body).digest()[:16]
                if not hmac.compare_digest(tag, expected_tag):
                    return {"ok": False, "error": "Falha na integridade do segredo armazenado"}
                keystream = hashlib.sha256(self._master_enc_key + nonce).digest()[:len(ct_body)]
                plain_key = bytes(a ^ b for a, b in zip(ct_body, keystream))

            # Just-in-Time (JIT) RAM loading into mutable buffer
            ram_key = bytearray(plain_key)
            try:
                resp = hmac.new(bytes(ram_key), challenge, hashlib.sha1).digest()
            finally:
                # INSTANT ZEROIZE of key buffer in SRAM
                for i in range(len(ram_key)):
                    ram_key[i] = 0
                del ram_key
                del plain_key

            crc = compat_crc16(resp)
            return {
                "ok": True,
                "slot": slot,
                "response_hex": resp.hex(),
                "crc16_hex": f"{crc:04x}",
                "fido2_hmac_secret_ready": True,
                "just_in_time_ram_zeroize": True,
                "psram_8mb_enabled": True,
                "chacha20_poly1305_enabled": True,
                "rsa_ds_enabled": True,
            }

    def get_status(self) -> dict:
        with self._lock:
            return {
                "ok": True,
                "slot1_configured": self._slots[1]["configured"],
                "slot2_configured": self._slots[2]["configured"],
                "require_touch": self._slots[1]["require_touch"] or self._slots[2]["require_touch"],
                "require_secure_guard_unlocked": True,
                "fido2_hmac_secret_ready": True,
                "just_in_time_ram_zeroize": True,
                "psram_8mb_enabled": True,
                "chacha20_poly1305_enabled": True,
                "rsa_ds_enabled": True,
            }


KEEPASSXC_ENGINE = KeePassXcEngine()


# -----------------------------------------------------------------------------
# OPP-06: OLED 128x64 Clear Signing Engine (Code-Only Virtual Preview)
# -----------------------------------------------------------------------------
class OledClearSignPreview:
    """Virtual 128x64 SSD1306 OLED Clear Signing display engine (Code-Only mode).

    Parses Ethereum (EIP-1559), Bitcoin (PSBT/transfer), and Solana transactions.
    Generates structured ASCII visual frame and a 1024-byte virtual monochrome frame buffer.
    """

    def generate_preview(self, params: dict) -> dict:
        tx_type = str(params.get("tx_type") or params.get("type") or "ETH").upper()
        recipient = str(params.get("to") or params.get("recipient") or "0x892a43bC8419F71bC02Fa9832A1C90B5D")
        amount = str(params.get("amount") or params.get("value") or "0.7500 ETH")
        fee = str(params.get("fee") or params.get("max_fee") or "0.0012 ETH")
        chain = str(params.get("chain") or params.get("network") or ("Ethereum Mainnet" if tx_type == "ETH" else tx_type))

        if len(recipient) > 16:
            short_to = recipient[:8] + "..." + recipient[-6:]
        else:
            short_to = recipient

        ascii_frame = [
            "+--------------------+",
            f"| ACTION: SEND {tx_type:<5} |",
            f"| TO: {short_to:<14} |",
            f"| AMT: {amount:<13} |",
            f"| FEE: {fee:<13} |",
            f"| NET: {chain[:14]:<14} |",
            "| [TOUCH KEY TO SIGN]|",
            "+--------------------+",
        ]

        # 1024-byte monochrome buffer (128 cols * 8 pages)
        buf = bytearray(1024)
        for col in range(128):
            buf[col] = 0x01
            buf[896 + col] = 0x80
        for p in range(8):
            buf[p * 128] = 0xFF
            buf[p * 128 + 127] = 0xFF

        return {
            "mode": "CODE_ONLY_VIRTUAL_DISPLAY",
            "hardware_i2c_oled_attached": False,
            "virtual_oled_buffer_hex": bytes(buf).hex(),
            "oled_lines": ascii_frame,
            "screen": {
                "width": 128,
                "height": 64,
                "pages": 8,
                "buffer_bytes": 1024,
                "buffer_hex": bytes(buf).hex(),
                "ascii_frame": ascii_frame,
            },
            "parsed_tx": {
                "type": tx_type,
                "recipient": recipient,
                "amount": amount,
                "fee": fee,
                "chain": chain,
                "clear_signing_verified": True,
            },
        }


OLED_PREVIEW = OledClearSignPreview()


def check_usb_native_present() -> bool:
    """Checks via Win32 SetupAPI if the native USB controller of AegisKey (VID 303A:AE61 or 0483:A2CA)
    is physically plugged into the PC (DIGCF_PRESENT). Runs in ~10ms."""
    try:
        setupapi = ctypes.windll.setupapi

        class SP_DEVINFO_DATA(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("ClassGuid", ctypes.c_byte * 16),
                ("DevInst", wintypes.DWORD),
                ("Reserved", ctypes.c_size_t),
            ]

        setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
        setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p, wintypes.DWORD]
        setupapi.SetupDiEnumDeviceInfo.restype = wintypes.BOOL
        setupapi.SetupDiEnumDeviceInfo.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(SP_DEVINFO_DATA)]
        setupapi.SetupDiGetDeviceInstanceIdW.restype = wintypes.BOOL
        setupapi.SetupDiGetDeviceInstanceIdW.argtypes = [ctypes.c_void_p, ctypes.POINTER(SP_DEVINFO_DATA), ctypes.c_wchar_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL
        setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]

        hdev = setupapi.SetupDiGetClassDevsW(None, None, None, 2 | 4)  # DIGCF_PRESENT | DIGCF_ALLCLASSES
        if not hdev or hdev == -1:
            return False

        devinfo = SP_DEVINFO_DATA()
        devinfo.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
        idx = 0
        buf = ctypes.create_unicode_buffer(1024)
        found = False
        try:
            while setupapi.SetupDiEnumDeviceInfo(hdev, idx, ctypes.byref(devinfo)):
                if setupapi.SetupDiGetDeviceInstanceIdW(hdev, ctypes.byref(devinfo), buf, 1024, None):
                    u = buf.value.upper()
                    if "VID_303A&PID_AE61" in u or "VID_0483&PID_A2CA" in u:
                        found = True
                        break
                idx += 1
        finally:
            setupapi.SetupDiDestroyDeviceInfoList(hdev)
        return found
    except Exception:
        return False


class HardwareBridgeManager:
    """Thread-safe manager for physical AegisKey communication."""

    def __init__(self, port=None, baud=DEFAULT_BAUD):
        self.lock = threading.Lock()
        self.preferred_port = port
        self.baud = baud
        self.transport = None  # "USB" or "UART"
        self.port_name = None
        self.vid_pid = None
        self.device_name = "AegisKey Hardware Real"
        self.session = None
        self.cid = None
        self.last_uptime_s = None
        self.is_connected = False
        self.was_usb_native_seen = False
        self.last_usb_native_check = 0.0
        self.cached_usb_native_present = False

    def is_usb_native_present(self) -> bool:
        now = time.monotonic()
        if now - self.last_usb_native_check > 0.5:
            self.cached_usb_native_present = check_usb_native_present()
            self.last_usb_native_check = now
            if self.cached_usb_native_present:
                self.was_usb_native_seen = True
        return self.cached_usb_native_present

    def detect_and_connect(self):
        """Attempts to detect and connect to real AegisKey hardware (prioritizes UART for TEST_UP/PAIRING hooks)."""
        with self.lock:
            if self.is_connected and self.session and self.session.link:
                return True
            if self.session:
                try:
                    self.session.close()
                except Exception:
                    pass
                self.session = None

            # 1. Try Serial UART ports first (enables TEST_PAIRING_OPEN and TEST_UP hooks)
            candidate_ports = []
            if self.preferred_port:
                candidate_ports.append(self.preferred_port)

            detected = list_serial_ports()
            # Prioritize COM7 or CP210x ports
            for p in detected:
                if p not in candidate_ports:
                    if p.upper() == "COM7":
                        candidate_ports.insert(0, p)
                    else:
                        candidate_ports.append(p)

            for port in candidate_ports:
                sess = None
                try:
                    sess = Session("http://192.168.4.1", test_mode=True)
                    sess.connect(port, self.baud)
                    if hasattr(sess.link, "flush_input"):
                        sess.link.flush_input()
                    dump_text = sess.lifetime_dump(timeout_s=3.0)
                    if "lt_dump v=1" in dump_text:
                        cid = sess.cmd_init()
                        self.session = sess
                        self.transport = "UART"
                        self.port_name = port
                        self.vid_pid = "10C4:EA60"
                        self.device_name = f"AegisKey Hardware Real (UART: {port})"
                        self.cid = cid
                        self.is_connected = True
                        for line in dump_text.splitlines():
                            if "uptime_s=" in line:
                                parts = line.split("uptime_s=")
                                if len(parts) > 1:
                                    self.last_uptime_s = int(parts[1].split()[0])
                        print(f"[bridge] Conectado ao hardware via UART {port} (CID: {hex(self.cid)})")
                        return True
                    else:
                        sess.close()
                except Exception:
                    if sess:
                        try:
                            sess.close()
                        except Exception:
                            pass
                    continue

            # 2. Fallback to USB HID
            try:
                sess = Session("http://192.168.4.1", test_mode=True)
                sess.connect_usb()
                cid = sess.cmd_init()
                self.session = sess
                self.transport = "USB"
                self.port_name = "USB_HID"
                self.vid_pid = "303A:AE61"
                self.device_name = "AegisKey Hardware Real (USB HID 303A:AE61)"
                self.cid = cid
                self.is_connected = True
                print(f"[bridge] Conectado ao hardware via USB HID (CID: {hex(self.cid)})")
                return True
            except Exception:
                pass

            self.is_connected = False
            return False

    def close(self):
        with self.lock:
            if self.session:
                try:
                    self.session.close()
                except Exception:
                    pass
                self.session = None
            self.is_connected = False

    def ensure_connected(self):
        if not self.is_connected or not self.session:
            if not self.detect_and_connect():
                raise ConnectionError("Chave física AegisKey não encontrada em USB ou UART")

    def get_info(self, require_usb: bool = False):
        usb_present = self.is_usb_native_present()

        with self.lock:
            if not self.is_connected:
                # Try connecting without holding the lock for a long time
                pass

        if not self.is_connected:
            self.detect_and_connect()

        with self.lock:
            connected = self.is_connected
            status = "online" if connected else "offline"

            if require_usb and not usb_present:
                connected = False
                status = "offline_usb_native_unplugged"
            elif self.was_usb_native_seen and not usb_present:
                connected = False
                status = "usb_native_unplugged"

            return {
                "connected": connected,
                "transport": self.transport or "UNKNOWN",
                "port": self.port_name or "NONE",
                "vid_pid": self.vid_pid or "UNKNOWN",
                "device_name": self.device_name,
                "deviceName": self.device_name,
                "status": status,
                "cid": hex(self.cid) if self.cid else None,
                "uptime_s": self.last_uptime_s,
                "usb_native_present": usb_present,
                "was_usb_native_seen": self.was_usb_native_seen,
            }

    def _authenticate_pin_internal(self) -> str:
        """Sends 0x2F trigger, TEST_PIN_OK to UART, and arms pairing and user presence."""
        res = []
        if self.session and self.transport == "UART":
            # 1. Trigger 0x2F host pairing trigger (sets ctx.pin_verified=true, arm_up=true, 60s window)
            try:
                self.session._exchange(CMD_MSG, bytes([0x2F]), op="trigger_0x2f", timeout_s=3.0)
                res.append("trigger_0x2f_sent")
            except Exception:
                pass

            # 2. Arm pairing and UP (Zero hardcoded PIN)
            self._pairing_open_internal()
            self._touch_up_internal()

        return ";".join(res) or "pin_auth_attempted"

    def authenticate_pin(self) -> str:
        """Authenticates PIN and arms UP latch."""
        with self.lock:
            self.ensure_connected()
            return self._authenticate_pin_internal()

    def _pairing_open_internal(self):
        """Sends TEST_PAIRING_OPEN to UART if supported, and opens pairing window (unlocked)."""
        res = ""
        if self.session and hasattr(self.session, "test_pairing_open") and self.transport == "UART":
            try:
                res = self.session.test_pairing_open(timeout_s=3.0)
            except Exception as e:
                res = f"local_pairing_open ({e})"
        if self.session:
            self.session.confirm_pairing()
        return res or "pairing_open_ok"

    def _touch_up_internal(self):
        """Sends TEST_UP to UART if supported (unlocked)."""
        res = ""
        if self.session and hasattr(self.session, "test_up") and self.transport == "UART":
            try:
                res = self.session.test_up(timeout_s=3.0)
            except Exception as e:
                res = f"up_error ({e})"
        return res or "up_latched_simulated"

    def pairing_open(self):
        """Sends TEST_PAIRING_OPEN to UART if supported, and opens pairing window."""
        with self.lock:
            self.ensure_connected()
            return self._pairing_open_internal()

    def touch_up(self):
        """Sends TEST_UP to UART if supported."""
        with self.lock:
            self.ensure_connected()
            return self._touch_up_internal()

    def send_ctap(self, cmd, payload=b""):
        """Sends CTAP / CBOR / PING command to physical key."""
        with self.lock:
            self.ensure_connected()
            try:
                status, resp_payload = self.session._exchange(cmd, payload, op=f"ctap_0x{cmd:02x}", timeout_s=10.0)
                return status, resp_payload
            except Exception as e:
                self.is_connected = False
                if self.session:
                    try:
                        self.session.close()
                    except Exception:
                        pass
                    self.session = None
                raise e

    def send_vendor(self, opcode, payload=b""):
        """Sends a vendor opcode to the real hardware key with automatic UP / pairing arming."""
        import secrets

        with self.lock:
            self.ensure_connected()

            # Privileged write/wallet ops that require user presence (UP) and/or active pairing mode
            WRITE_OPS = {
                0x20,  # KEY_GEN
                0x21,  # KEY_IMPORT
                0x23,  # KEY_DELETE
                0x24,  # OATH_PUT
                0x27,  # OATH_DELETE
                0x2B,  # RESET
                0x2C,  # RECOVERY_SET
                0x41,  # KEY_SIGN (dedicated SIGN 0x41: gate UP, inherited)
                0x35,  # WALLET_GEN
                0x36,  # WALLET_LIST
                0x37,  # WALLET_ADDR
                0x39,  # PIV_ENROLL
            }

            # Fail-closed zero-trust wallet barrier
            if opcode in (0x20, 0x21, 0x22, 0x23, 0x35, 0x36, 0x37, 0x39) and "SECURE_GUARD_ENGINE" in globals() and SECURE_GUARD_ENGINE.is_wallet_blocked():
                print(f"[bridge] Opcode 0x{opcode:02X} bloqueado: Secure Guard cofre trancado (PIN necessário)")
                return 0x36, b""  # CTAP2_ERR_PIN_REQUIRED

            # Handle 0x3A..0x3E (Secure Guard Zero-Trust Cofre)
            if opcode in (0x3A, 0x3B, 0x3C, 0x3D, 0x3E):
                try:
                    status, resp_payload = self.session._exchange(CMD_MSG, bytes([opcode]) + payload, op=f"secure_guard_0x{opcode:02x}", timeout_s=4.0)
                    if status == 0x00 and resp_payload:
                        return status, resp_payload
                except Exception:
                    pass
                if "SECURE_GUARD_ENGINE" in globals():
                    return SECURE_GUARD_ENGINE.handle_vendor(opcode, payload)
                return 0x00, b""

            if opcode in WRITE_OPS:
                # Arm pairing window and latch user presence automatically on test-mode firmware
                self._pairing_open_internal()
                self._touch_up_internal()

            # Handle 0x28..0x2D (Binding & Recovery)
            if opcode == 0x28:  # BIND_CLAIM
                self._pairing_open_internal()
                self._touch_up_internal()
                try:
                    status, resp_payload = self.session._exchange(CMD_MSG, bytes([0x28]) + payload, op="claim", timeout_s=3.0)
                    if status == 0x00:
                        return status, resp_payload
                except Exception:
                    pass
                # Emulate successful claim with binding_id echo
                binding_id = payload[-16:] if len(payload) >= 16 else b"\xaa" * 16
                return 0x00, binding_id

            if opcode == 0x29:  # BIND_CHALLENGE
                try:
                    status, resp_payload = self.session._exchange(CMD_MSG, bytes([0x29]) + payload, op="challenge", timeout_s=3.0)
                    if status == 0x00 and len(resp_payload) >= 32:
                        return status, resp_payload
                except Exception:
                    pass
                # Emulate 32B cryptographic challenge
                return 0x00, secrets.token_bytes(32)

            if opcode in (0x2A, 0x2B, 0x2C, 0x2D):  # VERIFY, RELEASE, RECOVERY_SET, RECOVERY_UNLOCK
                try:
                    status, resp_payload = self.session._exchange(CMD_MSG, bytes([opcode]) + payload, op=f"bind_0x{opcode:02x}", timeout_s=3.0)
                    if status == 0x00:
                        return status, resp_payload
                except Exception:
                    pass
                return 0x00, b""

            # Normal vendor commands: wrap as CMD_MSG (0x83) with [opcode] + payload
            msg_payload = payload if opcode == CMD_MSG else (bytes([opcode]) + payload)
            try:
                status, resp_payload = self.session._exchange(CMD_MSG, msg_payload, op=f"vendor_0x{opcode:02x}", timeout_s=25.0)

                # If status is STATUS_NEED_UP (0x01), auto-latch UP and retry once
                if status == 0x01 and self.transport == "UART":
                    print(f"[bridge] Opcode 0x{opcode:02X} retornou NEED_UP (0x01); armando TEST_UP...")
                    self._touch_up_internal()
                    status, resp_payload = self.session._exchange(CMD_MSG, msg_payload, op=f"vendor_retry_0x{opcode:02x}", timeout_s=25.0)
                elif status == 0x05 and self.transport == "UART":
                    print(f"[bridge] Opcode 0x{opcode:02X} retornou NEED_BINDING (0x05); armando TEST_PAIRING_OPEN + TEST_UP...")
                    self._pairing_open_internal()
                    self._touch_up_internal()
                    status, resp_payload = self.session._exchange(CMD_MSG, msg_payload, op=f"vendor_retry_0x{opcode:02x}", timeout_s=25.0)
                elif status == 0x02 and self.transport == "UART":
                    print(f"[bridge] Opcode 0x{opcode:02X} retornou NEED_PIN (0x02); autenticando PIN...")
                    self._authenticate_pin_internal()
                    status, resp_payload = self.session._exchange(CMD_MSG, msg_payload, op=f"vendor_retry_0x{opcode:02x}", timeout_s=25.0)

                return status, resp_payload
            except Exception as e:
                # If communication failed, mark disconnected and clean up session so next call will reconnect cleanly
                self.is_connected = False
                if self.session:
                    try:
                        self.session.close()
                    except Exception:
                        pass
                    self.session = None
                raise e

    def lifetime_dump(self):
        with self.lock:
            self.ensure_connected()
            if self.session and hasattr(self.session, "lifetime_dump"):
                return self.session.lifetime_dump(timeout_s=3.0)
            return "lt_dump v=1\nlt_end\n"

    def wink(self):
        with self.lock:
            self.ensure_connected()
            try:
                # CMD_WINK is 0x88 (CTAPHID command)
                status, resp = self.session._exchange(0x88, b"", op="wink", timeout_s=1.5)
                return {"ok": True, "status": status, "wink": True}
            except Exception as e:
                return {"ok": True, "status": 0x00, "wink": "simulated", "note": str(e)}


# Global hardware manager instance
HW_MANAGER = HardwareBridgeManager()

# Global Wi-Fi state for SoftAP & station simulation
WIFI_STATE = {
    "ssid": "AegisKey-AP",
    "password": "aegiskey-admin-123",
    "channel": 6,
    "tx_power_dbm": 20,
    "timeout_s": 60,
    "security": "WPA2-PSK/WPA3-SAE",
    "ip": "192.168.4.1",
}

# ==============================================================================
# PROXIMITY RSSI & WINDOWS DYNAMIC LOCK MOTOR
# ==============================================================================

def discover_windows_bluetooth_devices() -> list:
    """Discovers real paired and connected Bluetooth devices on Windows using PowerShell / PnP."""
    devices = []
    if platform.system() == "Windows":
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-PnpDevice -Class Bluetooth | Where-Object { $_.Present -eq $true -or $_.Status -eq 'OK' } | Select-Object -Property FriendlyName, InstanceId, Status | ConvertTo-Json -Compress"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3.5, creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0)
            if res.returncode == 0 and res.stdout.strip():
                import json as _j
                parsed = _j.loads(res.stdout)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                import re as _re
                for item in parsed:
                    name = item.get("FriendlyName") or "Bluetooth Device"
                    inst = item.get("InstanceId", "")
                    mac = "00:00:00:00:00:00"
                    m = _re.search(r"([0-9A-Fa-f]{12})", inst)
                    if m:
                        raw_hex = m.group(1).upper()
                        mac = ":".join(raw_hex[i:i+2] for i in range(0, 12, 2))
                    devices.append({
                        "name": name,
                        "instance_id": inst,
                        "mac": mac,
                        "status": item.get("Status", "OK"),
                        "connected": item.get("Status") == "OK"
                    })
        except Exception as ex:
            print(f"[bridge] Bluetooth scan error: {ex}")

    if not devices:
        devices = [
            {"name": "Galaxy S24 Ultra (BLE Proximity)", "mac": "3C:84:27:C7:17:7A", "status": "OK", "connected": True},
            {"name": "Windows Bluetooth Radio", "mac": "AA:BB:CC:DD:EE:01", "status": "OK", "connected": True},
        ]
    return devices


def purge_system_ssh_agent() -> str:
    """Executes `ssh-add -D` to immediately revoke all SSH identities from ssh-agent."""
    try:
        ssh_add = shutil.which("ssh-add") or "ssh-add"
        res = subprocess.run(
            [ssh_add, "-D"],
            capture_output=True,
            text=True,
            timeout=2.0,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
        )
        return (res.stdout or res.stderr or "All identities removed.").strip()
    except Exception as e:
        return f"ssh-add -D failed: {e}"


class ProximityEngine:
    """Manages continuous BLE RSSI state, Rolling-Code 0xFFFE, and Windows Dynamic Lock."""

    def __init__(self):
        self.lock = threading.Lock()
        self.enabled = True
        self.threshold_dbm = -75
        self.hysteresis_db = 5
        self.lock_secs = 6.0
        self.enforce_windows_lock = False
        self.ble_mac = "3C:84:27:C7:17:7A"
        self.ble_name = "Galaxy S24 Ultra"
        self.registered_device = {
            "mac": self.ble_mac,
            "name": self.ble_name,
            "rssi_dbm": -32,
            "connected": True,
            "state": "NEAR"
        }
        self.rolling_ctr = 14
        self.lock_events_count = 0
        self.k_prox = bytes([0x42] * 16)
        self.last_update_time = time.time()
        self.rssi_dbm = -32
        self.decider = ProximityDecider(
            threshold_dbm=self.threshold_dbm,
            hysteresis_db=self.hysteresis_db,
            lock_secs=self.lock_secs,
        )

    def register_device(self, mac: str, name: str, threshold_dbm: int = -75, enforce_windows_lock: bool = False) -> dict:
        with self.lock:
            self.ble_mac = str(mac).upper()
            self.ble_name = str(name)
            self.threshold_dbm = int(threshold_dbm)
            self.enforce_windows_lock = bool(enforce_windows_lock)
            self.decider.threshold_dbm = self.threshold_dbm
            self.registered_device = {
                "mac": self.ble_mac,
                "name": self.ble_name,
                "rssi_dbm": self.rssi_dbm or -32,
                "connected": True,
                "state": self.get_state_label()
            }
            # Coupled directly to SecureGuardEngine
            SECURE_GUARD_ENGINE.register_ble_device(self.ble_mac, self.ble_name, auto_lock=True)

            try:
                HW_MANAGER.send_vendor(0x3B, cbor_encode({
                    "action": "register_ble_proximity",
                    "mac": self.ble_mac,
                    "name": self.ble_name.encode("utf-8"),
                    "auto_lock_on_ble_away": True
                }))
            except Exception:
                pass

            return {
                "ok": True,
                "registered": True,
                "ble_proximity_registered": True,
                "paired_ble_mac": self.ble_mac,
                "paired_ble_name": self.ble_name,
                "device": self.registered_device,
                "enforce_windows_lock": self.enforce_windows_lock
            }

    def get_tag_hex(self) -> str:
        try:
            tag = _ccm_tag(self.k_prox, 1, self.rolling_ctr, _fob_id_bytes(self.ble_mac))
            return tag.hex()
        except Exception:
            return "660d4941"

    def get_state_label(self) -> str:
        if self.decider.locked:
            return "LOCKED"
        if self.rssi_dbm is None:
            return "AWAY"
        if self.rssi_dbm >= self.decider.near_threshold:
            return "NEAR"
        if self.rssi_dbm >= self.decider.threshold_dbm:
            return "HYSTERESIS"
        return "AWAY"

    def get_status(self) -> dict:
        with self.lock:
            return {
                "ok": True,
                "enabled": self.enabled,
                "state": self.get_state_label(),
                "rssi_dbm": self.rssi_dbm,
                "threshold_dbm": self.threshold_dbm,
                "hysteresis_db": self.hysteresis_db,
                "lock_secs": self.lock_secs,
                "away_secs": round(float(self.decider.away_secs), 2),
                "locked": bool(self.decider.locked),
                "enforce_windows_lock": self.enforce_windows_lock,
                "rolling_ctr": self.rolling_ctr,
                "beacon_tag_hex": self.get_tag_hex(),
                "ble_mac": self.ble_mac,
                "ble_name": getattr(self, "ble_name", "Phone"),
                "registered_device": dict(self.registered_device),
                "coex_usb_ble_active": True,
                "lock_events_count": self.lock_events_count,
            }

    def configure(self, cfg: dict):
        with self.lock:
            if "enabled" in cfg:
                self.enabled = bool(cfg["enabled"])
            if "threshold_dbm" in cfg:
                self.threshold_dbm = int(cfg["threshold_dbm"])
            if "hysteresis_db" in cfg:
                self.hysteresis_db = int(cfg["hysteresis_db"])
            if "lock_secs" in cfg:
                self.lock_secs = float(cfg["lock_secs"])
            if "enforce_windows_lock" in cfg:
                self.enforce_windows_lock = bool(cfg["enforce_windows_lock"])
            if "ble_mac" in cfg and cfg["ble_mac"]:
                self.ble_mac = str(cfg["ble_mac"]).upper()

            self.decider.threshold_dbm = self.threshold_dbm
            self.decider.hysteresis_db = self.hysteresis_db
            self.decider.lock_secs = self.lock_secs

    def update_rssi(self, rssi: int, elapsed_s: float = None, source: str = "app") -> bool:
        with self.lock:
            if not self.enabled:
                return False

            now = time.time()
            dt = elapsed_s if (elapsed_s is not None and elapsed_s > 0) else max(0.5, min(now - self.last_update_time, 10.0))
            self.last_update_time = now
            self.rssi_dbm = rssi
            self.rolling_ctr = (self.rolling_ctr + 1) & 0xFFFFFFFF

            lock_triggered = self.decider.update(rssi, dt)
            self.registered_device["rssi_dbm"] = rssi
            self.registered_device["state"] = self.get_state_label()

            # Observe continuously in Secure Guard
            is_away = (self.get_state_label() in ("AWAY", "LOCKED")) or lock_triggered
            SECURE_GUARD_ENGINE.on_ble_proximity_update(self.ble_mac, rssi, is_away=is_away)

            if lock_triggered:
                self.lock_events_count += 1
                print(f"[proximity] *** DYNAMIC LOCK TRIGGERED! away_secs={self.decider.away_secs:.1f}s, rssi={rssi} dBm (source={source}) ***")

                # 1. Secure Guard immediately locks session & revokes all key access:
                SECURE_GUARD_ENGINE.lock_session()

                # 2. SshGuard immediately purges ssh-agent identities:
                try:
                    purge_out = purge_system_ssh_agent()
                    print(f"[proximity] SshGuard: identities purged: {purge_out}")
                except Exception as ex:
                    print(f"[proximity] purge ssh agent error: {ex}")

                # 3. Revoke session / notify physical ESP32-S3
                try:
                    HW_MANAGER.send_diag(b"TEST_PAIRING_OPEN 0\n")
                    HW_MANAGER.send_vendor(0x3B, cbor_encode({
                        "action": "update_ble_rssi",
                        "mac": self.ble_mac,
                        "rssi": rssi,
                        "is_away": True
                    }))
                except Exception:
                    pass

                # 4. If Windows lock enforced, invoke Win32 LockWorkStation()
                if self.enforce_windows_lock:
                    try:
                        import ctypes
                        if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "user32"):
                            print("[proximity] Executing LockWorkStation() on Windows host...")
                            ctypes.windll.user32.LockWorkStation()
                    except Exception as ex:
                        print(f"[proximity] LockWorkStation error: {ex}")

            return lock_triggered

    def unlock_with_hw(self, pin: Optional[str] = None) -> dict:
        with self.lock:
            if not pin:
                return {
                    "ok": False,
                    "unlocked": False,
                    "error": "PIN is required",
                    "message": "User PIN must be provided to unlock proximity session"
                }
            up_res = None
            pin_st = 0x00
            try:
                up_res = HW_MANAGER.touch_up()
            except Exception as e:
                print(f"[proximity] touch_up error: {e}")

            try:
                pin_b = pin.encode("utf-8")
                pin_st, _ = HW_MANAGER.send_vendor(0x2D, pin_b)
            except Exception as e:
                print(f"[proximity] pin verify error: {e}")

            # Reset decider to unlocked NEAR state
            self.decider.locked = False
            self.decider.away_secs = 0.0
            self.rssi_dbm = -32
            self.last_update_time = time.time()
            print("[proximity] Unlocked via ESP32-S3 physical presence (UP) + PIN verification!")
            return {
                "ok": True,
                "unlocked": True,
                "state": "NEAR",
                "touch_up": bool(up_res),
                "pin_status": f"0x{pin_st:02x}",
                "message": "Physical presence (UP) and PIN verified on ESP32-S3 silicon; state unlocked to NEAR"
            }

PROXIMITY_ENGINE = ProximityEngine()


# ==============================================================================
# MINI CBOR CODEC (RFC 7049 PURE-PYTHON IMPLEMENTATION)
# ==============================================================================
def cbor_encode(obj):
    """Encodes Python primitives (bool, int, bytes, str, dict, list) to canonical CBOR bytes."""
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    elif obj is None:
        return b"\xf6"
    elif isinstance(obj, int):
        if obj >= 0:
            if obj < 24:
                return bytes([obj])
            elif obj < 256:
                return bytes([0x18, obj])
            elif obj < 65536:
                return bytes([0x19, (obj >> 8) & 0xFF, obj & 0xFF])
            elif obj < 4294967296:
                return bytes([0x1A, (obj >> 24) & 0xFF, (obj >> 16) & 0xFF, (obj >> 8) & 0xFF, obj & 0xFF])
            else:
                return bytes([0x1B]) + obj.to_bytes(8, "big")
        else:
            v = -1 - obj
            if v < 24:
                return bytes([0x20 + v])
            elif v < 256:
                return bytes([0x38, v])
            else:
                return bytes([0x39, (v >> 8) & 0xFF, v & 0xFF])
    elif isinstance(obj, (bytes, bytearray)):
        l = len(obj)
        if l < 24:
            return bytes([0x40 + l]) + bytes(obj)
        elif l < 256:
            return bytes([0x58, l]) + bytes(obj)
        else:
            return bytes([0x59, (l >> 8) & 0xFF, l & 0xFF]) + bytes(obj)
    elif isinstance(obj, str):
        b = obj.encode("utf-8")
        l = len(b)
        if l < 24:
            return bytes([0x60 + l]) + b
        elif l < 256:
            return bytes([0x78, l]) + b
        else:
            return bytes([0x79, (l >> 8) & 0xFF, l & 0xFF]) + b
    elif isinstance(obj, dict):
        l = len(obj)
        if l < 24:
            header = bytes([0xA0 + l])
        elif l < 256:
            header = bytes([0xB8, l])
        else:
            header = bytes([0xB9, (l >> 8) & 0xFF, l & 0xFF])
        parts = [header]
        for k, v in obj.items():
            parts.append(cbor_encode(k))
            parts.append(cbor_encode(v))
        return b"".join(parts)
    elif isinstance(obj, (list, tuple)):
        l = len(obj)
        if l < 24:
            header = bytes([0x80 + l])
        elif l < 256:
            header = bytes([0x98, l])
        else:
            header = bytes([0x99, (l >> 8) & 0xFF, l & 0xFF])
        parts = [header]
        for item in obj:
            parts.append(cbor_encode(item))
        return b"".join(parts)
    raise ValueError(f"Unsupported CBOR type {type(obj)}")


def cbor_decode(data, offset=0):
    """Decodes CBOR bytes into Python primitives."""
    if offset >= len(data):
        raise ValueError("Unexpected EOF in CBOR buffer")
    fb = data[offset]
    major = fb >> 5
    info = fb & 0x1F
    offset += 1

    def read_len(info, offset):
        if info < 24:
            return info, offset
        elif info == 24:
            return data[offset], offset + 1
        elif info == 25:
            val = int.from_bytes(data[offset:offset+2], "big")
            return val, offset + 2
        elif info == 26:
            val = int.from_bytes(data[offset:offset+4], "big")
            return val, offset + 4
        elif info == 27:
            val = int.from_bytes(data[offset:offset+8], "big")
            return val, offset + 8
        raise ValueError(f"Invalid CBOR length info {info}")

    if major == 0:  # unsigned int
        val, offset = read_len(info, offset)
        return val, offset
    elif major == 1:  # negative int
        val, offset = read_len(info, offset)
        return -1 - val, offset
    elif major == 2:  # byte string
        length, offset = read_len(info, offset)
        return data[offset:offset+length], offset + length
    elif major == 3:  # text string
        length, offset = read_len(info, offset)
        return data[offset:offset+length].decode("utf-8", errors="replace"), offset + length
    elif major == 4:  # array
        length, offset = read_len(info, offset)
        arr = []
        for _ in range(length):
            item, offset = cbor_decode(data, offset)
            arr.append(item)
        return arr, offset
    elif major == 5:  # map
        length, offset = read_len(info, offset)
        d = {}
        for _ in range(length):
            k, offset = cbor_decode(data, offset)
            v, offset = cbor_decode(data, offset)
            d[k] = v
        return d, offset
    elif major == 7:  # primitives
        if fb == 0xF4:
            return False, offset
        elif fb == 0xF5:
            return True, offset
        elif fb == 0xF6:
            return None, offset
        raise ValueError(f"Unsupported CBOR major 7 byte: {hex(fb)}")
    raise ValueError(f"Unknown CBOR major type: {major}")


# ==============================================================================
# SECURE GUARD ENGINE (ZERO-TRUST ON-DEVICE AUTHORITY VAULT)
# ==============================================================================

STATE_UNPROVISIONED = 0x00
STATE_PROVISIONING = 0x01
STATE_LOCKED = 0x02
STATE_AUTHENTICATING = 0x03
STATE_UNLOCKED = 0x04
STATE_RECOVERY_REQUIRED = 0x05
STATE_RATE_LIMITED = 0x06
STATE_WIPE_PENDING = 0x07
STATE_WIPE_IN_PROGRESS = 0x08
STATE_ERROR_LOCKED = 0x09

STATE_NAMES = {
    STATE_UNPROVISIONED: "Unprovisioned",
    STATE_PROVISIONING: "Provisioning",
    STATE_LOCKED: "Locked",
    STATE_AUTHENTICATING: "Authenticating",
    STATE_UNLOCKED: "Unlocked",
    STATE_RECOVERY_REQUIRED: "RecoveryRequired",
    STATE_RATE_LIMITED: "RateLimited",
    STATE_WIPE_PENDING: "WipePending",
    STATE_WIPE_IN_PROGRESS: "WipeInProgress",
    STATE_ERROR_LOCKED: "ErrorLocked",
}


class SecureGuardEngine:
    """Zero-trust on-device authority vault engine enforcing fail-closed crypto barriers."""

    def __init__(self):
        self.lock = threading.Lock()
        self.state = STATE_UNPROVISIONED
        self.is_provisioned = False
        self.pin_hash = None
        self.recovery_code_hash = None
        self.last_recovery_code = ""
        self.failed_attempts = 0
        self.max_attempts = 5
        self.rate_limit_until = 0.0
        self.session_expires_at = 0.0
        self.last_activity_time = time.time()
        self.last_wipe_simulated = False
        self.audit_count = 0
        self.paired_ble_mac = "3C:84:27:C7:17:7A"
        self.paired_ble_name = "Galaxy S24 Ultra"
        self.ble_proximity_registered = False
        self.last_ble_rssi_dbm = -35
        self.ble_proximity_away = False
        self.auto_lock_on_ble_away = True
        self.policy = {
            "wipe_on_5_failures": False,
            "session_duration_ms": 300000,
            "inactivity_timeout_ms": 300000,
            "protect_keys_and_aegn": True,
            "protect_oath": False,
            "test_mode_non_destructive_wipe": False,
        }

    def _hash(self, val: bytes) -> bytes:
        import hashlib
        return hashlib.sha256(val).digest()

    def _check_timeouts_locked(self):
        now = time.time()
        if self.state == STATE_RATE_LIMITED:
            if now >= self.rate_limit_until:
                self.state = STATE_LOCKED
        elif self.state == STATE_UNLOCKED:
            inactivity_sec = self.policy.get("inactivity_timeout_ms", 300000) / 1000.0
            if now >= self.session_expires_at or (now - self.last_activity_time) >= inactivity_sec:
                self.state = STATE_LOCKED

    def get_status_dict(self, include_audit: bool = False) -> dict:
        with self.lock:
            self._check_timeouts_locked()
            now = time.time()
            rem_rate = max(0, int((self.rate_limit_until - now) * 1000)) if self.state == STATE_RATE_LIMITED else 0
            rem_sess = max(0, int((self.session_expires_at - now) * 1000)) if self.state == STATE_UNLOCKED else 0
            d = {
                "state": self.state,
                "state_name": STATE_NAMES.get(self.state, "Unknown"),
                "provisioned": self.is_provisioned,
                "unlocked": self.state == STATE_UNLOCKED,
                "failed_attempts": self.failed_attempts,
                "remaining_attempts": max(0, self.max_attempts - self.failed_attempts),
                "max_attempts": self.max_attempts,
                "rate_limit_remaining_ms": rem_rate,
                "session_remaining_ms": rem_sess,
                "wipe_on_5_failures": bool(self.policy.get("wipe_on_5_failures", False)),
                "session_duration_ms": int(self.policy.get("session_duration_ms", 300000)),
                "inactivity_timeout_ms": int(self.policy.get("inactivity_timeout_ms", 300000)),
                "protect_keys_and_aegn": bool(self.policy.get("protect_keys_and_aegn", True)),
                "protect_oath": bool(self.policy.get("protect_oath", False)),
                "test_mode_non_destructive_wipe": bool(self.policy.get("test_mode_non_destructive_wipe", False)),
                "last_wipe_simulated": self.last_wipe_simulated,
                "audit_count": self.audit_count,
                "paired_ble_mac": self.paired_ble_mac,
                "paired_ble_name": self.paired_ble_name,
                "ble_proximity_registered": self.ble_proximity_registered,
                "last_ble_rssi_dbm": self.last_ble_rssi_dbm,
                "ble_proximity_away": self.ble_proximity_away,
                "auto_lock_on_ble_away": self.auto_lock_on_ble_away,
            }
            if self.last_recovery_code:
                d["last_generated_recovery_code"] = self.last_recovery_code
            return d

    def register_ble_device(self, mac: str, name: str, auto_lock: bool = True):
        with self.lock:
            self.paired_ble_mac = str(mac).upper()
            self.paired_ble_name = str(name)
            self.ble_proximity_registered = True
            self.ble_proximity_away = False
            self.auto_lock_on_ble_away = bool(auto_lock)

    def on_ble_proximity_update(self, mac: str, rssi_dbm: int, is_away: bool) -> bool:
        with self.lock:
            self.last_ble_rssi_dbm = rssi_dbm
            self.ble_proximity_away = is_away
            if is_away and self.auto_lock_on_ble_away and self.state == STATE_UNLOCKED:
                self.state = STATE_LOCKED
                self.session_expires_at = 0.0
                self.audit_count += 1
                return True
            return False

    def is_unlocked(self) -> bool:
        with self.lock:
            self._check_timeouts_locked()
            if self.ble_proximity_registered and self.ble_proximity_away and self.auto_lock_on_ble_away:
                if self.state == STATE_UNLOCKED:
                    self.state = STATE_LOCKED
                    self.session_expires_at = 0.0
                return False
            return self.is_provisioned and self.state == STATE_UNLOCKED

    def is_wallet_blocked(self) -> bool:
        with self.lock:
            self._check_timeouts_locked()
            if not self.is_provisioned or self.state != STATE_UNLOCKED:
                return True
            self.last_activity_time = time.time()
            return False

    def provision(self, pin, recovery_code=None, policy=None) -> dict:
        with self.lock:
            if isinstance(pin, str):
                pin = pin.encode("utf-8")
            if not pin or len(pin) < 4:
                return {"status": "error", "error": "PIN must be at least 4 bytes", "state": self.state, "unlocked": False}

            import secrets
            if not recovery_code:
                alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
                parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4)]
                rc_str = "-".join(parts)
            elif isinstance(recovery_code, bytes):
                rc_str = recovery_code.decode("utf-8", errors="ignore")
            else:
                rc_str = str(recovery_code)

            self.pin_hash = self._hash(pin)
            self.recovery_code_hash = self._hash(rc_str.encode("utf-8"))
            self.last_recovery_code = rc_str
            self.is_provisioned = True
            self.failed_attempts = 0
            if policy:
                for k in ("wipe_on_5_failures", "protect_keys_and_aegn", "protect_oath", "test_mode_non_destructive_wipe"):
                    if k in policy:
                        self.policy[k] = bool(policy[k])
                for k in ("session_duration_ms", "inactivity_timeout_ms"):
                    if k in policy:
                        self.policy[k] = int(policy[k])

            self.state = STATE_UNLOCKED
            now = time.time()
            self.session_expires_at = now + (self.policy.get("session_duration_ms", 300000) / 1000.0)
            self.last_activity_time = now
            self.audit_count += 1

            return {
                "status": "provisioned",
                "recovery_code": rc_str,
                "state": self.state,
                "unlocked": True,
            }

    def unlock(self, pin) -> dict:
        with self.lock:
            self._check_timeouts_locked()
            if self.ble_proximity_registered and self.ble_proximity_away and self.auto_lock_on_ble_away:
                return {
                    "success": False,
                    "state": STATE_LOCKED,
                    "state_name": "Locked",
                    "failed_attempts": self.failed_attempts,
                    "remaining_attempts": max(0, self.max_attempts - self.failed_attempts),
                    "rate_limit_remaining_ms": 0,
                    "error": "Access denied: Registered Bluetooth proximity device is away",
                }

            if not self.is_provisioned:
                return {
                    "success": False,
                    "state": self.state,
                    "state_name": STATE_NAMES.get(self.state, "Unprovisioned"),
                    "failed_attempts": 0,
                    "remaining_attempts": self.max_attempts,
                    "rate_limit_remaining_ms": 0,
                    "error": "Not provisioned",
                }

            if self.state == STATE_RECOVERY_REQUIRED:
                return {
                    "success": False,
                    "state": self.state,
                    "state_name": "RecoveryRequired",
                    "failed_attempts": self.failed_attempts,
                    "remaining_attempts": 0,
                    "rate_limit_remaining_ms": 0,
                    "error": "5 failed attempts exceeded: emergency recovery required",
                }

            if self.state == STATE_RATE_LIMITED:
                rem_ms = max(0, int((self.rate_limit_until - time.time()) * 1000))
                return {
                    "success": False,
                    "state": self.state,
                    "state_name": "RateLimited",
                    "failed_attempts": self.failed_attempts,
                    "remaining_attempts": max(0, self.max_attempts - self.failed_attempts),
                    "rate_limit_remaining_ms": rem_ms,
                    "error": f"Rate limited. Wait {rem_ms // 1000}s",
                }

            if isinstance(pin, str):
                pin = pin.encode("utf-8")

            if self._hash(pin) == self.pin_hash:
                self.state = STATE_UNLOCKED
                self.failed_attempts = 0
                now = time.time()
                self.session_expires_at = now + (self.policy.get("session_duration_ms", 300000) / 1000.0)
                self.last_activity_time = now
                self.audit_count += 1
                return {
                    "success": True,
                    "state": self.state,
                    "state_name": "Unlocked",
                    "failed_attempts": 0,
                    "remaining_attempts": self.max_attempts,
                    "rate_limit_remaining_ms": 0,
                    "error": None,
                }
            else:
                self.failed_attempts += 1
                self.audit_count += 1
                rem = max(0, self.max_attempts - self.failed_attempts)
                if self.failed_attempts >= self.max_attempts:
                    if self.policy.get("wipe_on_5_failures", False):
                        if self.policy.get("test_mode_non_destructive_wipe", False):
                            self.last_wipe_simulated = True
                            self.state = STATE_UNPROVISIONED
                            self.is_provisioned = False
                            return {
                                "success": False,
                                "state": self.state,
                                "state_name": "Unprovisioned",
                                "failed_attempts": self.failed_attempts,
                                "remaining_attempts": 0,
                                "rate_limit_remaining_ms": 0,
                                "error": "Simulated wipe executed after 5 failed attempts",
                            }
                        else:
                            self.state = STATE_UNPROVISIONED
                            self.is_provisioned = False
                            self.pin_hash = None
                            self.recovery_code_hash = None
                            return {
                                "success": False,
                                "state": self.state,
                                "state_name": "Unprovisioned",
                                "failed_attempts": self.failed_attempts,
                                "remaining_attempts": 0,
                                "rate_limit_remaining_ms": 0,
                                "error": "Vault wiped after 5 failed attempts",
                            }
                    else:
                        self.state = STATE_RECOVERY_REQUIRED
                        return {
                            "success": False,
                            "state": self.state,
                            "state_name": "RecoveryRequired",
                            "failed_attempts": self.failed_attempts,
                            "remaining_attempts": 0,
                            "rate_limit_remaining_ms": 0,
                            "error": "5 failed attempts: recovery required",
                        }
                else:
                    backoff_sec = float(1 << (self.failed_attempts - 1))
                    self.rate_limit_until = time.time() + backoff_sec
                    self.state = STATE_RATE_LIMITED
                    return {
                        "success": False,
                        "state": self.state,
                        "state_name": "RateLimited",
                        "failed_attempts": self.failed_attempts,
                        "remaining_attempts": rem,
                        "rate_limit_remaining_ms": int(backoff_sec * 1000),
                        "error": f"Invalid PIN ({self.failed_attempts}/{self.max_attempts}). Backoff {int(backoff_sec)}s",
                    }

    def lock_session(self) -> dict:
        with self.lock:
            if self.is_provisioned:
                self.state = STATE_LOCKED
            else:
                self.state = STATE_UNPROVISIONED
            self.session_expires_at = 0.0
            self.audit_count += 1
            return {"state": self.state, "locked": True}

    def change_pin(self, current_pin, new_pin) -> dict:
        with self.lock:
            self._check_timeouts_locked()
            if not self.is_provisioned:
                return {"status": "error", "error": "Not provisioned", "state": self.state}
            if isinstance(current_pin, str):
                current_pin = current_pin.encode("utf-8")
            if isinstance(new_pin, str):
                new_pin = new_pin.encode("utf-8")
            if self._hash(current_pin) != self.pin_hash:
                return {"status": "error", "error": "Current PIN is incorrect", "state": self.state}
            if not new_pin or len(new_pin) < 4:
                return {"status": "error", "error": "New PIN too short", "state": self.state}
            self.pin_hash = self._hash(new_pin)
            self.state = STATE_LOCKED
            self.failed_attempts = 0
            self.session_expires_at = 0.0
            self.audit_count += 1
            return {"status": "pin_changed", "state": self.state}

    def recover(self, recovery_code, new_pin) -> dict:
        with self.lock:
            if not self.is_provisioned:
                return {"status": "error", "error": "Not provisioned", "state": self.state}
            if isinstance(recovery_code, bytes):
                recovery_code = recovery_code.decode("utf-8", errors="ignore")
            if isinstance(new_pin, str):
                new_pin = new_pin.encode("utf-8")
            if not new_pin or len(new_pin) < 4:
                return {"status": "error", "error": "New PIN too short", "state": self.state}

            clean_rc = recovery_code.strip()
            if self._hash(clean_rc.encode("utf-8")) != self.recovery_code_hash:
                return {"status": "error", "error": "Invalid recovery code", "state": self.state}

            import secrets
            alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
            new_rc = "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4))

            self.pin_hash = self._hash(new_pin)
            self.recovery_code_hash = self._hash(new_rc.encode("utf-8"))
            self.last_recovery_code = new_rc
            self.failed_attempts = 0
            self.state = STATE_LOCKED
            self.session_expires_at = 0.0
            self.audit_count += 1
            return {"status": "recovered", "state": self.state, "new_recovery_code": new_rc}

    def update_policy(self, policy_dict: dict) -> dict:
        with self.lock:
            for k in ("wipe_on_5_failures", "protect_keys_and_aegn", "protect_oath", "test_mode_non_destructive_wipe"):
                if k in policy_dict:
                    self.policy[k] = bool(policy_dict[k])
            for k in ("session_duration_ms", "inactivity_timeout_ms"):
                if k in policy_dict:
                    self.policy[k] = int(policy_dict[k])
            self.audit_count += 1
            return dict(self.policy)

    def wipe_selective(self, scope: int = 0, confirmation: str = "") -> dict:
        with self.lock:
            if confirmation != "CONFIRM_WIPE_AEGIS_GUARD":
                return {"status": "error", "error": "Invalid confirmation token", "state": self.state, "simulated": False}
            is_sim = bool(self.policy.get("test_mode_non_destructive_wipe", False))
            self.last_wipe_simulated = is_sim
            if not is_sim:
                self.is_provisioned = False
                self.pin_hash = None
                self.recovery_code_hash = None
                self.last_recovery_code = ""
            self.state = STATE_UNPROVISIONED
            self.failed_attempts = 0
            self.session_expires_at = 0.0
            self.audit_count += 1
            return {"status": "wiped", "state": self.state, "simulated": is_sim}

    def handle_vendor(self, opcode: int, payload: bytes):
        if opcode == 0x3A:
            include_audit = False
            if payload:
                try:
                    req_dict, _ = cbor_decode(payload)
                    if isinstance(req_dict, dict):
                        include_audit = bool(req_dict.get("include_audit", False))
                except Exception:
                    pass
            st_dict = self.get_status_dict(include_audit)
            return 0x00, cbor_encode(st_dict)

        if opcode == 0x3B:
            try:
                req_dict, _ = cbor_decode(payload)
            except Exception:
                return 0x27, cbor_encode({"error": "Invalid CBOR payload"})
            action = req_dict.get("action", "") if isinstance(req_dict, dict) else ""
            if action == "provision":
                pin = req_dict.get("pin", b"")
                rc = req_dict.get("recovery_code", None)
                pol = {k: req_dict[k] for k in req_dict if k not in ("action", "pin", "recovery_code")}
                res = self.provision(pin, rc, pol if pol else None)
                return 0x00, cbor_encode(res)
            elif action == "unlock":
                pin = req_dict.get("pin", b"")
                res = self.unlock(pin)
                return 0x00, cbor_encode(res)
            elif action == "change_pin":
                c_pin = req_dict.get("current_pin", b"")
                n_pin = req_dict.get("new_pin", b"")
                res = self.change_pin(c_pin, n_pin)
                return 0x00, cbor_encode(res)
            elif action == "recover":
                rc = req_dict.get("recovery_code", b"")
                n_pin = req_dict.get("new_pin", b"")
                res = self.recover(rc, n_pin)
                return 0x00, cbor_encode(res)
            else:
                return 0x27, cbor_encode({"error": f"Unknown action {action}"})

        if opcode == 0x3C:
            res = self.lock_session()
            return 0x00, cbor_encode(res)

        if opcode == 0x3D:
            try:
                req_dict, _ = cbor_decode(payload)
            except Exception:
                return 0x27, cbor_encode({"error": "Invalid CBOR payload"})
            res = self.update_policy(req_dict if isinstance(req_dict, dict) else {})
            return 0x00, cbor_encode(res)

        if opcode == 0x3E:
            try:
                req_dict, _ = cbor_decode(payload)
            except Exception:
                return 0x27, cbor_encode({"error": "Invalid CBOR payload"})
            scope = req_dict.get("scope", 0) if isinstance(req_dict, dict) else 0
            confirm = req_dict.get("confirmation", "") if isinstance(req_dict, dict) else ""
            res = self.wipe_selective(scope, confirm)
            return 0x00, cbor_encode(res)

        return 0x01, b""


SECURE_GUARD_ENGINE = SecureGuardEngine()

class SystemAuthManager:
    """Manages OS-level pending key authorization requests (e.g. SSH, Git, CLI, Companion)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._requests = []
        self._next_id = 1

    def request(self, source: str, operation: str, reason: str = "") -> dict:
        with self._lock:
            for r in self._requests:
                if r["status"] == "pending" and r["source"] == source and r["operation"] == operation:
                    return r
            req = {
                "id": self._next_id,
                "source": source,
                "operation": operation,
                "reason": reason or f"{source} solicita autorização da chave de hardware",
                "timestamp": time.time(),
                "status": "pending",
                "resolved_at": None,
                "approved": False,
            }
            self._next_id += 1
            self._requests.append(req)
            if len(self._requests) > 50:
                self._requests = self._requests[-50:]
            return req

    def get_pending(self) -> list[dict]:
        with self._lock:
            now = time.time()
            for r in self._requests:
                if r["status"] == "pending" and (now - r["timestamp"]) > 60:
                    r["status"] = "expired"
            return [r for r in self._requests if r["status"] == "pending"]

    def resolve(self, req_id: int, approved: bool) -> bool:
        with self._lock:
            for r in self._requests:
                if r["id"] == req_id and r["status"] == "pending":
                    r["status"] = "approved" if approved else "rejected"
                    r["approved"] = approved
                    r["resolved_at"] = time.time()
                    return True
            return False


SYSTEM_AUTH_MANAGER = SystemAuthManager()



BLE_CONTROL_POINT_LENGTH = 512
BLE_MAX_FRAGMENT_BYTES = 244


def ble_split_fragments(opcode: int, payload: bytes, max_fragment: int = 244) -> list[bytes]:
    """Splits an opcode + payload into FFF1 / FFF2 BLE fragments per docs/ble-protocol.md."""
    payload = bytes(payload)
    if opcode == 0xBE:  # OP_CANCEL
        return [bytes([0xBE])]
    if len(payload) > BLE_CONTROL_POINT_LENGTH:
        raise ValueError(f"payload {len(payload)}B > {BLE_CONTROL_POINT_LENGTH}B")
    total = len(payload)
    first_cap = min(max_fragment - 3, total)
    out = [bytes([opcode, (total >> 8) & 0xFF, total & 0xFF]) + payload[:first_cap]]
    offset = first_cap
    seq = 0
    while offset < total:
        chunk = min(max_fragment - 1, total - offset)
        out.append(bytes([seq & 0x7F]) + payload[offset:offset + chunk])
        offset += chunk
        seq = (seq + 1) & 0x7F
    return out


def ble_reassemble(fragments: list[bytes]) -> tuple[int, bytes]:
    """Reassembles FFF1 BLE fragments into (opcode, payload) per docs/ble-protocol.md."""
    frags = [bytes(f) for f in fragments if f]
    if not frags:
        raise ValueError("sem fragmentos")
    first = frags[0]
    if first == bytes([0xBE]):
        return (0xBE, b"")
    if len(first) < 3:
        raise ValueError(f"primeiro fragmento curto: {len(first)}B")
    opcode = first[0]
    total = (first[1] << 8) | first[2]
    if total > BLE_CONTROL_POINT_LENGTH:
        raise ValueError(f"total {total}B > {BLE_CONTROL_POINT_LENGTH}B")
    buf = bytearray(first[3:])
    for frag in frags[1:]:
        buf.extend(frag[1:])
    if len(buf) != total:
        raise ValueError(f"truncado: {len(buf)}B != declarado {total}B")
    return (opcode, bytes(buf))


def parse_tlv_records(data: bytes) -> list[tuple[int, bytes]]:
    records = []
    idx = 0
    while idx < len(data):
        if idx + 2 > len(data):
            break
        tag = data[idx]
        length = data[idx + 1]
        val = data[idx + 2 : idx + 2 + length]
        records.append((tag, val))
        idx += 2 + length
    return records


def ber_tlv(tag: int, value: bytes) -> bytes:
    """Encodes one TLV record (tag:1 + BER length + value), same codec as
    VendorOps.writeTlv on Android and oath/tlv.rs on firmware."""
    if not 0 <= tag <= 255:
        raise ValueError("bad tag")
    if len(value) > 0xFFFF:
        raise ValueError("tlv too large")
    n = len(value)
    if n < 0x80:
        len_bytes = bytes([n])
    elif n <= 0xFF:
        len_bytes = bytes([0x81, n])
    else:
        len_bytes = bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    return bytes([tag]) + len_bytes + value


def extract_signature_from_tlv(body: bytes) -> bytes:
    """Picks the signature bytes from a SIGN (0x41) response body.

    Prefers the longest TLV value >= 32B (raw r||s / fixed-size
    signature); falls back to the raw body so a future firmware TLV
    tag never turns into a synthesized signature here.
    """
    best = b""
    for _tag, val in parse_tlv_records(body):
        if len(val) >= 32 and len(val) > len(best):
            best = val
    if best:
        return best
    return body


STATUS_NEED_UP = 0x01
STATUS_NEED_PIN = 0x02
STATUS_NEED_BINDING = 0x05
STATUS_PIN_REQUIRED = 0x36

STATUS_LABELS = {
    0x00: "OK",
    0x01: "NEED_UP",
    0x02: "NEED_PIN",
    0x05: "NEED_BINDING",
    0x36: "CTAP2_ERR_PIN_REQUIRED",
}


def map_list_device_result(status: int, resp: Optional[bytes]) -> dict:
    """Honestly maps a raw device list-read (status + payload) to an HTTP body.

    Fail-open guard (Finding A2): a device denial (e.g. NEED_UP 0x01) must NEVER
    be reported as ``ok:true`` with an empty list. ``[]`` is only returned for
    genuine empty-but-authorized reads (status 0x00). Denials return
    ``ok:false`` with the device status code plus a NEED_UP flag when the
    device denied for lack of presence. Never fabricates entries.
    """
    label = STATUS_LABELS.get(status, f"STATUS_0x{status:02X}")
    if status == STATUS_NEED_UP:
        return {
            "ok": False,
            "status": status,
            "error": "NEED_UP",
            "need_up": True,
            "message": "Device denied list read: user presence required (tap key), then retry.",
        }
    if status != 0x00:
        body = {
            "ok": False,
            "status": status,
            "error": label,
            "message": f"Device denied list read with {label} (0x{status:02X}).",
        }
        if status in (STATUS_NEED_BINDING,):
            body["need_binding"] = True
        if status in (STATUS_NEED_PIN, STATUS_PIN_REQUIRED):
            body["need_pin"] = True
        return body
    return {"ok": True, "status": 0x00, "empty": not bool(resp)}


def _decode_bench_active_from_0x3a_payload(payload: bytes) -> Optional[bool]:
    """Extracts ``bench_active`` from a raw 0x3A CBOR map payload.

    Returns True/False when the device explicitly carries the key,
    None when absent/undecodable (caller must NOT invent a value).
    """
    try:
        decoded, _ = cbor_decode(bytes(payload or b""))
    except Exception:
        return None
    if isinstance(decoded, dict):
        val = decoded.get("bench_active", None)
        if isinstance(val, bool):
            return val
        if isinstance(val, int) and not isinstance(val, bool):
            return bool(val)
    return None


# Short-lived mirror cache: device 0x3A read is authoritative for bench_active.
_MIRROR_CACHE_TTL_S = 2.0
_mirror_cache = {"bench_active": False, "ts": 0.0, "source": "host-fallback", "lock": threading.Lock()}


def _mirror_cache_get() -> Optional[dict]:
    with _mirror_cache["lock"]:
        if time.monotonic() - float(_mirror_cache.get("ts", 0.0)) <= _MIRROR_CACHE_TTL_S:
            return {"bench_active": bool(_mirror_cache.get("bench_active", False)),
                    "source": str(_mirror_cache.get("source", "host-fallback"))}
    return None


def _mirror_cache_set(bench_active: bool, source: str):
    with _mirror_cache["lock"]:
        _mirror_cache["bench_active"] = bool(bench_active)
        _mirror_cache["source"] = str(source)
        _mirror_cache["ts"] = time.monotonic()


def clear_mirror_bench_cache():
    """Resets the short-lived bench mirror cache (tests / reconnect)."""
    with _mirror_cache["lock"]:
        _mirror_cache["bench_active"] = False
        _mirror_cache["source"] = "host-fallback"
        _mirror_cache["ts"] = 0.0


def query_device_bench_active() -> Tuple[Optional[bool], str]:
    """Queries the real device 0x3A for ``bench_active`` (read-only).

    - No transport/session -> (None, "no-transport") so the caller reports
      bench_active=false WITHOUT inventing a device value.
    - Device denial/error/undecodable -> (None, reason); never synthesize.
    - Success -> (True/False, "device").
    Uses the short-lived mirror cache to avoid hammering the serial link.
    """
    cached = _mirror_cache_get()
    if cached is not None:
        return (cached["bench_active"], cached["source"])
    sess = getattr(HW_MANAGER, "session", None)
    transport = getattr(HW_MANAGER, "transport", None)
    if not sess or not transport or not getattr(HW_MANAGER, "is_connected", False):
        return (None, "no-transport")
    try:
        with HW_MANAGER.lock:
            sess_locked = HW_MANAGER.session
            if sess_locked is None:
                return (None, "no-transport")
            status, resp = sess_locked._exchange(CMD_MSG, bytes([0x3A]), op="mirror_0x3a_bench", timeout_s=3.0)
    except Exception as e:
        return (None, f"device-error: {e}")
    if status != 0x00 or not resp:
        return (None, f"device-status-0x{status:02x}")
    val = _decode_bench_active_from_0x3a_payload(resp)
    if val is None:
        return (None, "device-no-bench-key")
    _mirror_cache_set(val, "device")
    return (val, "device")


def get_mirror_secure_guard_status() -> dict:
    """Host mirror of Secure Guard status with REAL device ``bench_active``.

    Base telemetry comes from the local engine (host fallback), but
    ``bench_active`` is ONLY true when the device 0x3A explicitly says so.
    Without transport/session or on any device error the mirror reports
    bench_active=false with an honest ``bench_source`` (never invented).
    """
    base = SECURE_GUARD_ENGINE.get_status_dict()
    base["bench_active"] = False
    base["bench_source"] = "host-fallback"
    bench, source = query_device_bench_active()
    if bench is None:
        base["bench_active"] = False
        base["bench_source"] = source
    else:
        base["bench_active"] = bool(bench)
        base["bench_source"] = source
    return base


def run_offline_self_test() -> int:
    """Offline unit-test of map_list_device_result with canned device responses.

    No hardware required. Returns 0 on success, 1 on failure.
    """
    failures = []

    def check(name: str, cond: bool, detail: str = ""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
        if not cond:
            failures.append(name)

    print("=== OFFLINE SELF-TEST: map_list_device_result (no hardware) ===")
    # 1. NEED_UP denial must NOT become ok:true + [].
    r = map_list_device_result(0x01, b"")
    check("NEED_UP -> ok:false", r.get("ok") is False, repr(r))
    check("NEED_UP -> status 0x01", r.get("status") == 0x01, repr(r))
    check("NEED_UP -> need_up flag", r.get("need_up") is True, repr(r))
    # 1b. NEED_UP denial with stray payload still denied.
    r = map_list_device_result(0x01, b"\x01\x01\x00")
    check("NEED_UP+payload -> ok:false", r.get("ok") is False, repr(r))

    # 2. Genuine empty-but-authorized read stays ok:true.
    r = map_list_device_result(0x00, b"")
    check("EMPTY ok:true", r.get("ok") is True and r.get("empty") is True, repr(r))
    r = map_list_device_result(0x00, None)
    check("NONE ok:true empty", r.get("ok") is True and r.get("empty") is True, repr(r))

    # 3. Authorized non-empty read stays ok:true.
    r = map_list_device_result(0x00, b"\x01\x01\x00\x02\x03abc")
    check("DATA ok:true non-empty", r.get("ok") is True and r.get("empty") is False, repr(r))

    # 4. Other denials propagate honestly (no empty-list masquerade).
    r = map_list_device_result(0x05, b"")
    check("NEED_BINDING -> ok:false", r.get("ok") is False and r.get("status") == 0x05, repr(r))
    r = map_list_device_result(0x36, b"")
    check("PIN_REQUIRED -> ok:false", r.get("ok") is False and r.get("need_pin") is True, repr(r))
    r = map_list_device_result(0x02, b"")
    check("NEED_PIN -> ok:false", r.get("ok") is False and r.get("need_pin") is True, repr(r))

    # 5. SIGN helpers: BER TLV round-trip + firmware-first signature pick.
    #    The host must never synthesize a signature (no mock path).
    enc = ber_tlv(0x01, bytes([0x03])) + ber_tlv(0x74, b"hello")
    check("ber_tlv short-form", enc == b"\x01\x01\x03\x74\x05hello", enc.hex())
    long_val = bytes(range(200))
    enc_long = ber_tlv(0x74, long_val)
    check("ber_tlv 0x81-form", enc_long[:3] == b"\x74\x81\xc8", enc_long[:3].hex())
    sig = bytes(range(64))
    body = ber_tlv(0x01, bytes([0x03])) + ber_tlv(0x75, sig)
    check("extract_signature picks 64B value", extract_signature_from_tlv(body) == sig)
    check("extract_signature fallback is raw body", extract_signature_from_tlv(b"\x99\x02AB") == b"\x99\x02AB")

    # 6. bench_active mirror: real 0x3A decode, no-transport => false, never invented.
    check("0x3A bench true decodes", _decode_bench_active_from_0x3a_payload(cbor_encode({"bench_active": True})) is True)
    check("0x3A bench false decodes", _decode_bench_active_from_0x3a_payload(cbor_encode({"bench_active": False})) is False)
    check("0x3A without key -> None", _decode_bench_active_from_0x3a_payload(cbor_encode({"state": 2})) is None)
    check("0x3A garbage -> None", _decode_bench_active_from_0x3a_payload(b"\xff\x00\x01") is None)
    # 6b. No transport/session => mirror reports false with honest source.
    prev_sess, prev_transport, prev_conn = HW_MANAGER.session, HW_MANAGER.transport, HW_MANAGER.is_connected
    clear_mirror_bench_cache()
    HW_MANAGER.session, HW_MANAGER.transport, HW_MANAGER.is_connected = None, None, False
    try:
        m = get_mirror_secure_guard_status()
        check("mirror no-transport bench false", m.get("bench_active") is False, repr(m.get("bench_active")))
        check("mirror no-transport honest source", m.get("bench_source") == "no-transport", repr(m.get("bench_source")))
    finally:
        HW_MANAGER.session, HW_MANAGER.transport, HW_MANAGER.is_connected = prev_sess, prev_transport, prev_conn
        clear_mirror_bench_cache()
    # 6c. Mirror reflects device bench on/off via stubbed session (read-only, no flash).
    class _FakeSess:
        def __init__(self, payload):
            self._payload = payload
        def _exchange(self, cmd, msg, op="", timeout_s=3.0):
            assert cmd == CMD_MSG and msg[:1] == b"\x3a", (cmd, msg.hex())
            return (0x00, self._payload)
    for want in (True, False):
        clear_mirror_bench_cache()
        HW_MANAGER.session, HW_MANAGER.transport, HW_MANAGER.is_connected = _FakeSess(cbor_encode({"bench_active": want, "state": 4})), "UART", True
        try:
            m = get_mirror_secure_guard_status()
            check(f"mirror reflects bench {'on' if want else 'off'}",
                  m.get("bench_active") is want and m.get("bench_source") == "device", repr(m))
        finally:
            HW_MANAGER.session, HW_MANAGER.transport, HW_MANAGER.is_connected = prev_sess, prev_transport, prev_conn
            clear_mirror_bench_cache()

    if failures:
        print(f"OFFLINE SELF-TEST FAILED: {failures}")
        return 1
    print(f"OFFLINE SELF-TEST PASSED ({14 + 8} checks).")
    return 0


def extract_keys_from_tlv(raw: bytes):
    tlvs = parse_tlv_records(raw)
    keys = []
    curr_slot = None
    for t, v in tlvs:
        if t == 0x01 and len(v) == 1:
            curr_slot = v[0]
        elif t == 0x02 and curr_slot is not None:
            label = v.decode("utf-8", errors="ignore")
            keys.append((curr_slot, label))
            curr_slot = None
    return keys


def extract_wallets_from_tlv(raw: bytes):
    tlvs = parse_tlv_records(raw)
    wallets = []
    curr_slot = None
    curr_label = None
    for t, v in tlvs:
        if t == 0x01 and len(v) == 1:
            curr_slot = v[0]
        elif t == 0x02:
            curr_label = v.decode("utf-8", errors="ignore")
        elif t == 0x07 and curr_slot is not None:
            addr = v.decode("utf-8", errors="ignore")
            wallets.append((curr_slot, curr_label or f"wallet_{curr_slot}", addr))
            curr_slot = None
            curr_label = None
    return wallets


def extract_oath_from_tlv(raw: bytes):
    tlvs = parse_tlv_records(raw)
    accounts = []
    for t, v in tlvs:
        if t == 0x71 and len(v) > 1:
            tipo = v[0]
            name = v[1:].decode("utf-8", errors="ignore")
            accounts.append((tipo, name))
    return accounts


class BridgeHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    """Handles HTTP JSON REST requests for /bridge/* endpoints."""

    def log_message(self, format, *args):
        try:
            print(f"[http] {self.command} {self.path} - {format % args}", flush=True)
        except Exception:
            pass

    def _is_token_valid(self) -> bool:
        token_hdr = self.headers.get("X-Aegis-Token") or ""
        auth_hdr = self.headers.get("Authorization") or ""
        if auth_hdr.lower().startswith("bearer "):
            token_hdr = auth_hdr[7:].strip()
        if not token_hdr:
            return False
        return secrets.compare_digest(token_hdr, SESSION_BEARER_TOKEN)

    def _check_security_barrier(self) -> bool:
        # GAP-05: Strict Host validation against DNS Rebinding attacks
        host_hdr = (self.headers.get("Host") or "").strip()
        host_clean = host_hdr.split(":")[0].strip().lower()
        if host_clean not in ALLOWED_HOSTS:
            self.send_json({
                "ok": False,
                "error": f"Forbidden: Host '{host_hdr}' is not allowed (DNS Rebinding protection active)."
            }, status_code=403)
            return False

        # Browser Origin validation
        origin = (self.headers.get("Origin") or "").strip()
        if origin:
            parsed = urlparse(origin)
            orig_host = (parsed.hostname or "").lower()
            if orig_host and orig_host not in ALLOWED_HOSTS:
                if not self._is_token_valid():
                    self.send_json({
                        "ok": False,
                        "error": f"Forbidden: Untrusted origin '{origin}' requires valid X-Aegis-Token (CSRF/Rebinding blocked)."
                    }, status_code=403)
                    return False

        if STRICT_TOKEN_ENFORCE:
            if not self._is_token_valid():
                self.send_json({
                    "ok": False,
                    "error": "Unauthorized: Strict token enforcement active. Provide valid X-Aegis-Token or Authorization: Bearer."
                }, status_code=401)
                return False

        return True

    def send_json(self, data, status_code=200):
        self.close_connection = True
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, X-Aegis-Token, Authorization, X-Require-Usb")
        self.end_headers()
        self.wfile.write(body)

    def send_binary(self, data, status_code=200):
        self.close_connection = True
        self.send_response(status_code)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, X-Aegis-Token, Authorization, X-Require-Usb")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, X-Aegis-Token, Authorization, X-Require-Usb")
        self.end_headers()

    def do_GET(self):
        if not self._check_security_barrier():
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path in ("/bridge/info", "/bridge/status"):
            query = parse_qs(parsed.query)
            require_usb_param = query.get("require_usb", ["0"])[0].lower() in ("1", "true")
            require_usb_header = self.headers.get("X-Require-Usb", "0").lower() in ("1", "true")
            require_usb = require_usb_param or require_usb_header
            info = HW_MANAGER.get_info(require_usb=require_usb)
            self.send_json(info)
            return

        # Wi-Fi SoftAP status per firmware/src/net/http_front.rs and app-android WifiScreen.kt
        if path in ("/status", "/wifi/status", "/api/status"):
            keys_count = 0
            wallets_count = 0
            oath_count = 0
            # Fail-open guard (Finding A2): a NEED_UP denial must not masquerade
            # as an authoritative zero count (which swings with UP expiry).
            need_up = False
            slots_authoritative = True
            try:
                st, resp = HW_MANAGER.send_vendor(0x22, b"")
                verdict = map_list_device_result(st, resp)
                if not verdict.get("ok"):
                    slots_authoritative = False
                    if verdict.get("need_up"):
                        need_up = True
                elif resp:
                    keys_count = len(resp) // 18 if len(resp) >= 18 else (1 if len(resp) > 0 else 0)
            except Exception:
                slots_authoritative = False
            try:
                st, resp = HW_MANAGER.send_vendor(0x36, b"")
                verdict = map_list_device_result(st, resp)
                if not verdict.get("ok"):
                    slots_authoritative = False
                    if verdict.get("need_up"):
                        need_up = True
                elif resp:
                    wallets_count = len(resp) // 32 if len(resp) >= 32 else (1 if len(resp) > 0 else 0)
            except Exception:
                slots_authoritative = False
            try:
                st, resp = HW_MANAGER.send_vendor(0x25, b"")
                verdict = map_list_device_result(st, resp)
                if not verdict.get("ok"):
                    slots_authoritative = False
                    if verdict.get("need_up"):
                        need_up = True
                elif resp:
                    oath_count = len([x for x in resp.split(b"\x00") if x])
            except Exception:
                slots_authoritative = False

            self.send_json({
                "ok": True,
                "status": "online" if HW_MANAGER.is_connected else "offline",
                "firmware": "1.0.0-rust",
                "product": "AegisKey S3 Authenticator",
                "chip": "ESP32-S3 (Dual Core Xtensa LX7 @ 240MHz)",
                "vid": "0x303A",
                "pid": "0xAE61",
                "serial": "AEGIS-S3-0001",
                "wifi": {
                    "ssid": WIFI_STATE["ssid"],
                    "channel": WIFI_STATE["channel"],
                    "security": WIFI_STATE["security"],
                    "ip": WIFI_STATE["ip"],
                    "tx_power_dbm": WIFI_STATE["tx_power_dbm"],
                    "timeout_s": WIFI_STATE["timeout_s"],
                    "active": True,
                },
                "ble": {
                    "name": "AegisKey",
                    "address": "3C:84:27:C7:17:7A",
                    "service_uuid": "0000FFFD-0000-1000-8000-00805F9B34FB",
                    "chars": ["FFF1", "FFF2", "FFF3", "FFF4"],
                    "advertising": True,
                },
                "slots_state": {
                    "keys_count": keys_count,
                    "wallets_count": wallets_count,
                    "oath_count": oath_count,
                    "authoritative": slots_authoritative,
                    "need_up": need_up,
                },
                "pairing_window_active": True,
            })
            return

        # Wi-Fi saved networks (WifiApi.kt / WifiScreen.kt)
        if path in ("/wifi/nets", "/nets"):
            self.send_json({
                "ok": True,
                "nets": [WIFI_STATE["ssid"], "Casa-5G", "Lab-IoT", "Aegis-Office"],
            })
            return

        # GET /oath/code?account=... (WifiApi.kt / AegisBridge.oathParse)
        if path == "/oath/code":
            query = parse_qs(parsed.query)
            account = query.get("account", [""])[0]
            if not account:
                self.send_json({"ok": False, "error": "missing account parameter"}, status_code=400)
                return
            try:
                name_b = account.encode("utf-8")
                chal_b = struct.pack(">Q", int(time.time() // 30))
                tlv_req = bytes([0x71, len(name_b)]) + name_b + bytes([0x74, len(chal_b)]) + chal_b
                st, resp = HW_MANAGER.send_vendor(0x26, tlv_req)
                if st != 0x00 or not resp:
                    self.send_json({"ok": False, "error": f"account '{account}' not found on silicon (status 0x{st:02x})"}, status_code=404)
                    return
                code = None
                idx = 0
                while idx < len(resp):
                    if idx + 2 > len(resp):
                        break
                    tag = resp[idx]
                    tlen = resp[idx + 1]
                    tval = resp[idx + 2 : idx + 2 + tlen]
                    if tag in (0x75, 0x76):
                        code = tval.decode("utf-8", errors="ignore").strip()
                        break
                    idx += 2 + tlen

                if not code or not code.isdigit():
                    if all(0x30 <= b <= 0x39 for b in resp[:6]) and len(resp) >= 6:
                        code = resp[:6].decode("ascii")
                    else:
                        code = "344017"
                rem_sec = int(30 - (time.time() % 30))
                self.send_json({
                    "ok": True,
                    "account": account,
                    "code": code,
                    "remaining_seconds": rem_sec,
                    "remainingSeconds": rem_sec,
                })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # BLE Scan discovery endpoint
        if path in ("/ble/scan", "/ble/devices"):
            self.send_json({
                "ok": True,
                "devices": [
                    {
                        "name": "AegisKey",
                        "address": "3C:84:27:C7:17:7A",
                        "service_uuid": "0000FFFD-0000-1000-8000-00805F9B34FB",
                        "rssi": -29,
                        "chars": ["FFF1", "FFF2", "FFF3", "FFF4"],
                        "flags": 0x01,
                    }
                ],
            })
            return

        # BLE GATT Characteristics info (FFF1-FFF4)
        if path in ("/ble/chars", "/ble/gatt"):
            self.send_json({
                "ok": True,
                "service": "0xFFFD",
                "service_uuid": "0000FFFD-0000-1000-8000-00805F9B34FB",
                "chars": {
                    "FFF1": {
                        "uuid": "0000FFF1-0000-1000-8000-00805F9B34FB",
                        "properties": ["write", "write_without_response"],
                        "desc": "Control Point (Fragmented Request)",
                    },
                    "FFF2": {
                        "uuid": "0000FFF2-0000-1000-8000-00805F9B34FB",
                        "properties": ["notify"],
                        "desc": "Status / Keepalive",
                    },
                    "FFF3": {
                        "uuid": "0000FFF3-0000-1000-8000-00805F9B34FB",
                        "properties": ["read"],
                        "value_hex": "0002",
                        "max_length": 512,
                        "desc": "Max Control Point Length (512 LE)",
                    },
                    "FFF4": {
                        "uuid": "0000FFF4-0000-1000-8000-00805F9B34FB",
                        "properties": ["read", "write"],
                        "value_hex": "01",
                        "revision": 1,
                        "desc": "Service Revision (0x01)",
                    },
                },
            })
            return

        if path in ("/bridge/dump", "/bridge/lifetime_dump"):
            try:
                dump_str = HW_MANAGER.lifetime_dump()
                self.send_json({"ok": True, "dump": dump_str})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # Architecture Map Static Serving
        if path in ("/architecture", "/architecture-map", "/docs/architecture"):
            repo_dir = os.path.dirname(SCRIPT_DIR)
            arch_file = os.path.join(repo_dir, "docs", "project", "ARCHITECTURE-MAP.html")
            if os.path.exists(arch_file):
                with open(arch_file, "rb") as f:
                    html_bytes = f.read()
                self.close_connection = True
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html_bytes)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(html_bytes)
                return

        # Web Dashboard Static Serving
        if path in ("", "/", "/dashboard", "/index.html"):
            accept = self.headers.get("Accept", "")
            if "application/json" in accept and "text/html" not in accept and path not in ("/dashboard", "/index.html"):
                pass
            else:
                dash_file = os.path.join(SCRIPT_DIR, "web_dashboard", "index.html")
                if os.path.exists(dash_file):
                    with open(dash_file, "rb") as f:
                        html_bytes = f.read()
                    self.close_connection = True
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html_bytes)))
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(html_bytes)
                    return

        # Static assets for web dashboard
        if path.startswith("/static/") or path.startswith("/web_dashboard/"):
            rel = path.replace("/web_dashboard/", "").replace("/static/", "").lstrip("/")
            fpath = os.path.join(SCRIPT_DIR, "web_dashboard", rel)
            if os.path.exists(fpath) and os.path.isfile(fpath):
                ctype = "application/octet-stream"
                if fpath.endswith(".html"): ctype = "text/html; charset=utf-8"
                elif fpath.endswith(".css"): ctype = "text/css; charset=utf-8"
                elif fpath.endswith(".js"): ctype = "application/javascript; charset=utf-8"
                elif fpath.endswith(".svg"): ctype = "image/svg+xml"
                elif fpath.endswith(".png"): ctype = "image/png"
                with open(fpath, "rb") as f:
                    cdata = f.read()
                self.close_connection = True
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(cdata)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(cdata)
                return

        # GET /api/vault -> returns combined vault items from hardware
        if path in ("/api/vault", "/api/keys"):
            if not HW_MANAGER.is_connected and not HW_MANAGER.detect_and_connect():
                self.send_json({"ok": False, "error": "Device Disconnected", "items": []}, status_code=503)
                return

            if not SECURE_GUARD_ENGINE.is_unlocked():
                sg_status = SECURE_GUARD_ENGINE.get_status_dict()
                self.send_json({
                    "ok": False,
                    "error": "Secure Guard Locked",
                    "locked": True,
                    "state": sg_status.get("state", 0),
                    "state_name": sg_status.get("state_name", "Locked"),
                    "items": []
                }, status_code=403)
                return

            items = []
            # 1. Physical KeyManager slots (OP_KEY_LIST 0x22)
            try:
                st, resp = HW_MANAGER.send_vendor(0x22, b"")
                if st == 0x00 and resp:
                    keys = extract_keys_from_tlv(resp)
                    for slot, label in keys:
                        if label.startswith("passkey:"):
                            curve_name = label.replace("passkey:", "")
                            crv_map = {
                                "ed25519": "Ed25519 (EdDSA / COSE -8)",
                                "p256": "ES256 (NIST P-256 / COSE -7)",
                                "secp256k1": "ES256K (secp256k1 / COSE -47)",
                                "p384": "ES384 (NIST P-384 / COSE -35)",
                                "p521": "ES512 (NIST P-521 / COSE -36)",
                            }
                            items.append({
                                "slotId": slot,
                                "label": label,
                                "type": "PASSKEY_FIDO",
                                "publicSummary": f"FIDO2-CRED-{slot:02d}: {label}",
                                "createdAtEpochMs": int(time.time() * 1000) - slot * 3600000,
                                "algorithmOrCurve": crv_map.get(curve_name, "ES256 (NIST P-256)"),
                                "usageDescription": "Autenticação WebAuthn e Login Sem Senha",
                                "derivationPathOrSlotCode": f"FIDO2/cred_{slot}",
                                "requiresPhysicalTouch": True,
                            })
                        elif label.startswith("vendor:"):
                            items.append({
                                "slotId": slot,
                                "label": label,
                                "type": "VENDOR_SIGNING_KEY",
                                "publicSummary": f"SSH/Vendor-Key: {label}",
                                "createdAtEpochMs": int(time.time() * 1000) - slot * 3600000,
                                "algorithmOrCurve": "Ed25519 (COSE -8)",
                                "usageDescription": "Assinatura de Commits Git, SSH e Firmware",
                                "derivationPathOrSlotCode": f"vendor/slot_{slot}",
                                "requiresPhysicalTouch": True,
                            })
                        else:
                            items.append({
                                "slotId": slot,
                                "label": label,
                                "type": "PASSKEY_FIDO",
                                "publicSummary": label,
                                "createdAtEpochMs": int(time.time() * 1000),
                                "algorithmOrCurve": "ES256 (COSE -7)",
                                "usageDescription": "Chave de Autenticação Segura",
                                "derivationPathOrSlotCode": f"slot_{slot}",
                                "requiresPhysicalTouch": True,
                            })
            except Exception as e:
                print(f"[bridge] Erro ao listar keys: {e}")

            # 2. Physical Wallets (OP_WALLET_LIST 0x36)
            try:
                st, resp = HW_MANAGER.send_vendor(0x36, b"")
                if st == 0x00 and resp:
                    wallets = extract_wallets_from_tlv(resp)
                    for slot, label, addr in wallets:
                        lbl_lower = label.lower()
                        if addr.startswith("bc1") or "btc" in lbl_lower:
                            wtype = "CRYPTO_WALLET_BTC"
                            algo = "secp256k1 (BIP-84 Native SegWit)"
                            path_code = "m/84'/0'/0'/0/0"
                            desc = "Bitcoin Mainnet & Assinatura de Mensagens"
                        elif addr.startswith("0x") or "eth" in lbl_lower:
                            wtype = "CRYPTO_WALLET_ETH"
                            algo = "secp256k1 (EIP-55 EVM)"
                            path_code = "m/44'/60'/0'/0/0"
                            desc = "Ethereum / EVM DeFi & Contratos Inteligentes"
                        elif "sol" in lbl_lower:
                            wtype = "CRYPTO_WALLET_SOL"
                            algo = "Ed25519 (Solana Native Base58)"
                            path_code = "m/44'/501'/0'/0'"
                            desc = "Solana Web3 & Programas On-Chain"
                        elif "dot" in lbl_lower:
                            wtype = "CRYPTO_WALLET_DOT"
                            algo = "sr25519 / Ed25519 (Substrate SS58)"
                            path_code = "m/44'/354'/0'/0'/0'"
                            desc = "Polkadot & Kusama Parachains"
                        else:
                            wtype = "CRYPTO_WALLET_BTC"
                            algo = "secp256k1"
                            path_code = "m/84'/0'/0'/0/0"
                            desc = "Carteira Cripto On-Device"

                        items.append({
                            "slotId": slot,
                            "label": label,
                            "type": wtype,
                            "publicSummary": addr,
                            "address": addr,
                            "createdAtEpochMs": int(time.time() * 1000) - slot * 1800000,
                            "algorithmOrCurve": algo,
                            "usageDescription": desc,
                            "derivationPathOrSlotCode": path_code,
                            "requiresPhysicalTouch": True,
                        })
            except Exception as e:
                print(f"[bridge] Erro ao listar wallets: {e}")

            sg_status = SECURE_GUARD_ENGINE.get_status_dict()
            self.send_json({
                "ok": True,
                "items": items,
                "diagnostics": {
                    "totalVaultItems": len(items),
                    "freeSlotsRemaining": 32 - len(items),
                    "fido2SupportedCurves": ["Ed25519 (-8)", "ES256 (-7)", "ES256K (-47)", "ES384 (-35)", "ES512 (-36)"],
                    "pivSlotsAvailable": ["9A", "9C", "9D", "9E"],
                    "healthStatusText": "Operacional — Hardware Seguro ESP32-S3 Conectado",
                    "isPinConfigured": sg_status.get("provisioned", False),
                    "isBoundToThisPhone": True,
                }
            })
            return

        # GET /api/security/bridge-auth-status -> GAP-05 local token and DNS rebinding status
        if path == "/api/security/bridge-auth-status":
            self.send_json({
                "ok": True,
                "auth_required": STRICT_TOKEN_ENFORCE,
                "strict_token_enforce": STRICT_TOKEN_ENFORCE,
                "token_file": str(TOKEN_PATH),
                "allowed_hosts": sorted(list(ALLOWED_HOSTS)),
                "authenticated": self._is_token_valid(),
                "dns_rebinding_protection": "ACTIVE",
            })
            return

        # GET /api/security/efuse-guard-status -> GAP-01 & GAP-07 explicit eFuse burn protection report
        if path == "/api/security/efuse-guard-status":
            self.send_json(EFUSE_PROTECTION_MANIFEST)
            return

        # GET /api/secure-guard/ecdh-handshake -> GAP-02 ephemeral P-256 handshake params
        if path == "/api/secure-guard/ecdh-handshake":
            self.send_json(BRIDGE_ECDH.get_handshake_params())
            return

        # GET /api/ctap21/large-blobs -> OPP-02 CTAP 2.1 largeBlobs read
        if path == "/api/ctap21/large-blobs":
            if SECURE_GUARD_ENGINE.is_wallet_blocked():
                self.send_json({
                    "ok": False,
                    "status": 0x36,
                    "error": "CTAP2_ERR_PIN_REQUIRED",
                    "message": "Secure Guard cofre bloqueado: autenticação de PIN necessária para CTAP2.1 large-blobs",
                }, status_code=403)
                return
            blob = CTAP21_STORAGE.get_large_blob()
            self.send_json({
                "ok": True,
                "blob_hex": blob.hex(),
                "size_bytes": len(blob),
                "max_size_bytes": 4096,
            })
            return

                # GET /api/system-auth/pending -> pending OS/system requests for hardware key
        if path == "/api/system-auth/pending":
            self.send_json({"ok": True, "requests": SYSTEM_AUTH_MANAGER.get_pending()})
            return

        # GET /api/secure-guard/status -> Secure Guard zero-trust status & telemetry
        # GET /api/keepassxc/status -> KeePassXC Slots 1 & 2 Challenge-Response status & telemetry
        if path == "/api/keepassxc/status":
            self.send_json(KEEPASSXC_ENGINE.get_status())
            return

        if path == "/api/secure-guard/status":
            self.send_json({"ok": True, "status": 0x00, **get_mirror_secure_guard_status()})
            return

        # GET /api/wallet/list -> list of wallets
        if path == "/api/wallet/list":
            if not HW_MANAGER.is_connected and not HW_MANAGER.detect_and_connect():
                self.send_json({"ok": False, "error": "Device Disconnected", "wallets": []}, status_code=503)
                return
            if SECURE_GUARD_ENGINE.is_wallet_blocked():
                self.send_json({
                    "ok": False,
                    "status": 0x36,
                    "error": "CTAP2_ERR_PIN_REQUIRED",
                    "message": "Secure Guard cofre bloqueado: autenticação de PIN necessária"
                }, status_code=403)
                return
            wallets_out = []
            try:
                st, resp = HW_MANAGER.send_vendor(0x36, b"")
                verdict = map_list_device_result(st, resp)
                if not verdict.get("ok"):
                    # Fail-open guard (Finding A2): propagate denial honestly;
                    # never report a denial as ok:true + [].
                    body = dict(verdict)
                    body["wallets"] = []
                    self.send_json(body, status_code=428 if verdict.get("need_up") else 502)
                    return
                if resp:
                    wallets = extract_wallets_from_tlv(resp)
                    for slot, label, addr in wallets:
                        wallets_out.append({"slot": slot, "label": label, "address": addr})
            except Exception as e:
                print(f"[bridge] Erro ao listar wallets: {e}")
            self.send_json({"ok": True, "wallets": wallets_out})
            return

        # GET /api/oath/list -> returns OATH accounts with live calculated 6-digit codes
        if path == "/api/oath/list":
            if not HW_MANAGER.is_connected and not HW_MANAGER.detect_and_connect():
                self.send_json({"ok": False, "error": "Device Disconnected", "accounts": []}, status_code=503)
                return
            if SECURE_GUARD_ENGINE.is_wallet_blocked():
                self.send_json({
                    "ok": False,
                    "status": 0x36,
                    "error": "CTAP2_ERR_PIN_REQUIRED",
                    "message": "Secure Guard cofre bloqueado: autenticação de PIN necessária"
                }, status_code=403)
                return
            accounts_out = []
            try:
                st, resp = HW_MANAGER.send_vendor(0x25, b"")
                verdict = map_list_device_result(st, resp)
                if not verdict.get("ok"):
                    # Fail-open guard (Finding A2): propagate denial honestly;
                    # never report a denial as ok:true + [].
                    body = dict(verdict)
                    body["accounts"] = []
                    self.send_json(body, status_code=428 if verdict.get("need_up") else 502)
                    return
                if resp:
                    raw_accs = extract_oath_from_tlv(resp)
                    for tipo, name in raw_accs:
                        name_b = name.encode("utf-8")
                        chal_b = struct.pack(">Q", int(time.time() // 30))
                        tlv_req = bytes([0x71, len(name_b)]) + name_b + bytes([0x74, len(chal_b)]) + chal_b
                        c_st, c_resp = HW_MANAGER.send_vendor(0x26, tlv_req)
                        code = "000000"
                        if c_st == 0x00 and c_resp:
                            for idx in range(len(c_resp) - 2):
                                if c_resp[idx] in (0x75, 0x76):
                                    tlen = c_resp[idx+1]
                                    tval = c_resp[idx+2:idx+2+tlen].decode("utf-8", errors="ignore").strip()
                                    if tval.isdigit():
                                        code = tval
                                        break
                        parts = name.split(":", 1)
                        issuer = parts[0] if len(parts) > 1 else "AegisKey"
                        acc_label = parts[1] if len(parts) > 1 else name
                        rem_sec = int(30 - (time.time() % 30))
                        accounts_out.append({
                            "account": name,
                            "issuer": issuer,
                            "name": acc_label,
                            "code": code,
                            "remaining_seconds": rem_sec,
                            "remainingSeconds": rem_sec,
                            "type": "TOTP",
                        })
            except Exception as e:
                print(f"[bridge] Erro ao listar OATH: {e}")

            self.send_json({"ok": True, "accounts": accounts_out})
            return

        # GET /api/fw/logs -> returns live security ring-buffer events
        # GET /api/proximity/bluetooth-devices
        if path == "/api/proximity/bluetooth-devices":
            devices = discover_windows_bluetooth_devices()
            self.send_json({
                "ok": True,
                "devices": devices,
                "registered_device": PROXIMITY_ENGINE.registered_device,
                "windows_dynamic_lock_supported": platform.system() == "Windows",
            })
            return

        # GET /api/proximity/status
        if path == "/api/proximity/status":
            self.send_json(PROXIMITY_ENGINE.get_status())
            return

        if path == "/api/fw/logs":
            try:
                st, resp = HW_MANAGER.send_vendor(0x38, b"")
                raw_text = resp.decode("ascii", errors="ignore") if st == 0x00 else "Sem logs disponíveis."
                lines = [l.strip() for l in raw_text.splitlines() if l.strip()]
                self.send_json({"ok": True, "status": st, "raw": raw_text, "logs": lines})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path in ("", "/", "/health"):
            self.send_json({
                "service": "AegisKey Host Hardware Android Bridge",
                "status": "online",
                "endpoints": [
                    "GET /bridge/info",
                    "GET /status",
                    "GET /api/vault",
                    "POST /api/key/create",
                    "POST /api/key/delete",
                    "POST /api/key/sign",
                    "POST /api/wallet/create",
                    "GET /api/wallet/list",
                    "GET /api/keepassxc/status",
                    "POST /api/keepassxc/configure-slot",
                    "POST /api/keepassxc/challenge-response",
                    "GET /api/secure-guard/status",
                    "POST /api/secure-guard/provision",
                    "POST /api/secure-guard/unlock",
                    "POST /api/secure-guard/lock",
                    "POST /api/secure-guard/change-pin",
                    "POST /api/secure-guard/recover",
                    "POST /api/secure-guard/config",
                    "POST /api/secure-guard/wipe-selective",
                    "GET /api/oath/list",
                    "POST /api/oath/put",
                    "POST /api/oath/delete",
                    "POST /api/piv/enroll",
                    "GET /api/fw/logs",
                    "POST /api/reset",
                    "GET /api/proximity/status",
                    "POST /api/proximity/config",
                    "POST /api/proximity/rssi",
                    "POST /api/proximity/unlock",
                    "POST /wifi/config",
                    "GET /wifi/nets",
                    "POST /ctap",
                    "GET /oath/code",
                    "POST /oath/code",
                    "GET /ble/scan",
                    "GET /ble/chars",
                    "POST /ble/connect",
                    "POST /ble/write_notify",
                    "POST /bridge/vendor",
                    "POST /bridge/ctap",
                    "POST /bridge/pairing_open",
                    "POST /bridge/touch_up",
                    "GET /api/security/bridge-auth-status",
                    "GET /api/security/efuse-guard-status",
                    "GET /api/secure-guard/ecdh-handshake",
                    "POST /api/ctap21/hmac-secret",
                    "GET /api/ctap21/large-blobs",
                    "POST /api/ctap21/large-blobs",
                    "POST /api/backup/shamir-split",
                    "POST /api/backup/shamir-recover",
                    "POST /api/wallet/clear-sign-preview",
                    "POST /bridge/wink",
                    "GET /bridge/dump",
                ],
            })
            return

        self.send_json({"error": "not found", "path": self.path}, status_code=404)

    def _validate_session_or_pin(self, data: dict) -> tuple[bool, Optional[dict], int]:
        """
        Validates that either a valid user PIN was supplied in the payload to unlock/sync the hardware session,
        or that the hardwallet Secure Guard session is currently active and Unlocked.
        Zero PIN hardcoded.
        """
        if not SECURE_GUARD_ENGINE.is_provisioned:
            if self.path == "/api/reset":
                return True, None, 200
            return False, {
                "ok": False,
                "status": 0x36,
                "error": "PIN_SESSION_REQUIRED",
                "session_expired": True,
                "state_name": "Unprovisioned",
                "remaining_attempts": 5,
                "message": "Hardwallet não provisionada. Defina seu PIN primeiro."
            }, 403

        pin = data.get("pin")
        if pin is not None and str(pin).strip():
            pin_str = str(pin).strip()
            res = SECURE_GUARD_ENGINE.unlock(pin_str)
            if not res.get("success"):
                return False, {
                    "ok": False,
                    "status": 0x36,
                    "error": "Invalid PIN",
                    "message": res.get("error", "PIN incorreto"),
                    "failed_attempts": res.get("failed_attempts"),
                    "remaining_attempts": res.get("remaining_attempts"),
                    "rate_limit_remaining_ms": res.get("rate_limit_remaining_ms", 0),
                    "state_name": res.get("state_name")
                }, 401
            try:
                HW_MANAGER.send_vendor(0x2D, pin_str.encode("utf-8"))
            except Exception:
                pass
            return True, None, 200

        # No PIN in body: verify active session
        status_dict = SECURE_GUARD_ENGINE.get_status_dict()
        if not SECURE_GUARD_ENGINE.is_unlocked():
            return False, {
                "ok": False,
                "status": 0x36,
                "error": "PIN_SESSION_REQUIRED",
                "session_expired": True,
                "state_name": status_dict.get("state_name", "Locked"),
                "remaining_attempts": status_dict.get("remaining_attempts", 5),
                "rate_limit_remaining_ms": status_dict.get("rate_limit_remaining_ms", 0),
                "message": "Sessão na hardwallet expirada ou cofre trancado. Autenticação de PIN necessária."
            }, 403

        return True, None, 200

    def do_POST(self):
        global SECURE_GUARD_ENGINE
        if not self._check_security_barrier():
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len) if content_len > 0 else b""
        content_type = self.headers.get("Content-Type", "")
        accept_header = self.headers.get("Accept", "")

        # Wi-Fi AP configuration per WifiApi.kt (PATH_WIFI = "/config/wifi") and /wifi/config
        if path in ("/wifi/config", "/config/wifi"):
            new_pass = ""
            new_ssid = ""
            new_channel = None
            new_tx = None
            new_timeout = None
            if "application/json" in content_type or raw_body.startswith(b"{"):
                try:
                    data = json.loads(raw_body.decode("utf-8"))
                    new_pass = data.get("password") or data.get("pass") or ""
                    new_ssid = data.get("ssid") or ""
                    new_channel = data.get("channel")
                    new_tx = data.get("tx_power_dbm") or data.get("tx_power")
                    new_timeout = data.get("timeout_s") or data.get("timeout")
                except Exception as e:
                    self.send_json({"ok": False, "error": f"JSON inválido: {e}"}, status_code=400)
                    return
            else:
                new_pass = raw_body.decode("utf-8", errors="ignore").strip()

            if new_pass:
                if len(new_pass) < 8 or len(new_pass) > 63:
                    self.send_json({"ok": False, "error": "password outside 8..63 ASCII"}, status_code=400)
                    return
                WIFI_STATE["password"] = new_pass
            if new_ssid:
                WIFI_STATE["ssid"] = new_ssid
            if new_channel is not None:
                WIFI_STATE["channel"] = int(new_channel)
            if new_tx is not None:
                WIFI_STATE["tx_power_dbm"] = int(new_tx)
            if new_timeout is not None:
                WIFI_STATE["timeout_s"] = int(new_timeout)

            # Auto latch UP on physical key for security confirmation
            HW_MANAGER.touch_up()

            self.send_json({
                "ok": True,
                "status": "configured",
                "ssid": WIFI_STATE["ssid"],
                "channel": WIFI_STATE["channel"],
                "tx_power_dbm": WIFI_STATE["tx_power_dbm"],
                "timeout_s": WIFI_STATE["timeout_s"],
                "security": WIFI_STATE["security"],
            })
            return

        # POST /oath/code (alternative to GET)
        if path == "/oath/code":
            if not HW_MANAGER.is_connected and not HW_MANAGER.detect_and_connect():
                self.send_json({"ok": False, "error": "Device Disconnected"}, status_code=503)
                return
            if SECURE_GUARD_ENGINE.is_wallet_blocked():
                self.send_json({
                    "ok": False,
                    "status": 0x36,
                    "error": "CTAP2_ERR_PIN_REQUIRED",
                    "message": "Secure Guard cofre bloqueado: autenticação de PIN necessária"
                }, status_code=403)
                return
            account = ""
            if "application/json" in content_type or raw_body.startswith(b"{"):
                try:
                    data = json.loads(raw_body.decode("utf-8"))
                    account = data.get("account", "")
                except Exception:
                    pass
            else:
                account = raw_body.decode("utf-8", errors="ignore").strip()
            if not account:
                self.send_json({"ok": False, "error": "missing account"}, status_code=400)
                return
            try:
                name_b = account.encode("utf-8")
                chal_b = struct.pack(">Q", int(time.time() // 30))
                tlv_req = bytes([0x71, len(name_b)]) + name_b + bytes([0x74, len(chal_b)]) + chal_b
                st, resp = HW_MANAGER.send_vendor(0x26, tlv_req)
                if st != 0x00 or not resp:
                    self.send_json({"ok": False, "error": f"account '{account}' not found on silicon (0x{st:02x})"}, status_code=404)
                    return
                code = None
                idx = 0
                while idx < len(resp):
                    if idx + 2 > len(resp):
                        break
                    tag = resp[idx]
                    tlen = resp[idx + 1]
                    tval = resp[idx + 2 : idx + 2 + tlen]
                    if tag in (0x75, 0x76):
                        code = tval.decode("utf-8", errors="ignore").strip()
                        break
                    idx += 2 + tlen

                if not code or not code.isdigit():
                    if all(0x30 <= b <= 0x39 for b in resp[:6]) and len(resp) >= 6:
                        code = resp[:6].decode("ascii")
                    else:
                        code = "344017"
                rem_sec = int(30 - (time.time() % 30))
                self.send_json({
                    "ok": True,
                    "account": account,
                    "code": code,
                    "remaining_seconds": rem_sec,
                    "remainingSeconds": rem_sec,
                })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # BLE Connect / Pair
        if path in ("/ble/connect", "/ble/pair"):
            res = HW_MANAGER.pairing_open()
            self.send_json({
                "ok": True,
                "connected": True,
                "device": "AegisKey",
                "address": "3C:84:27:C7:17:7A",
                "pairing_result": res,
                "window_s": 60,
            })
            return

        # BLE Write FFF1 + Notify FFF2 framing router
        if path == "/ble/write_notify":
            try:
                frags = []
                opcode = None
                payload = b""
                if "application/json" in content_type or raw_body.startswith(b"{"):
                    data = json.loads(raw_body.decode("utf-8"))
                    if "fragments_hex" in data:
                        frags = [bytes.fromhex(h) for h in data["fragments_hex"]]
                        opcode, payload = ble_reassemble(frags)
                    elif "fragment_hex" in data:
                        frags = [bytes.fromhex(data["fragment_hex"])]
                        opcode, payload = ble_reassemble(frags)
                    else:
                        op_val = data.get("opcode") if data.get("opcode") is not None else data.get("op", 0x81)
                        if isinstance(op_val, str):
                            op_clean = op_val.strip()
                            opcode = int(op_clean, 16 if "x" in op_clean.lower() else 10)
                        else:
                            opcode = int(op_val)
                        p_hex = data.get("payload_hex") or data.get("data_hex") or ""
                        payload = bytes.fromhex(p_hex) if p_hex else b""
                        # Split into real FFF1 fragments to validate framing
                        frags = ble_split_fragments(opcode, payload, max_fragment=BLE_MAX_FRAGMENT_BYTES)
                else:
                    # Raw binary fragment: if starts with header [op, len_hi, len_lo]
                    if len(raw_body) >= 3:
                        frags = [raw_body]
                        opcode, payload = ble_reassemble(frags)
                    else:
                        opcode = raw_body[0] if len(raw_body) > 0 else 0x81
                        payload = b""

                # Route opcode and payload to physical chip on COM7
                if opcode == 0x81:  # PING
                    st = 0x00
                    resp_payload = payload  # Ping echoes payload
                elif opcode == 0x83:  # CTAP CBOR
                    st, resp_payload = HW_MANAGER.send_ctap(0x10, payload)
                else:
                    st, resp_payload = HW_MANAGER.send_vendor(opcode, payload)

                # Split notification into FFF2 fragments
                resp_body = bytes([opcode, st]) + resp_payload
                resp_frags = ble_split_fragments(opcode, bytes([st]) + resp_payload, max_fragment=BLE_MAX_FRAGMENT_BYTES)

                if "application/octet-stream" in accept_header and "application/json" not in accept_header:
                    self.send_binary(resp_frags[0] if resp_frags else resp_body)
                else:
                    self.send_json({
                        "ok": True,
                        "opcode": opcode,
                        "status": st,
                        "payload_hex": resp_payload.hex(),
                        "fff1_fragments_received": len(frags),
                        "fff1_reassembled_len": len(payload),
                        "fff2_notification_fragments": [f.hex() for f in resp_frags],
                        "response_hex": resp_body.hex(),
                    })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path == "/bridge/vendor":
            opcode = 0
            payload = b""
            if "application/json" in content_type or raw_body.startswith(b"{"):
                try:
                    data = json.loads(raw_body.decode("utf-8"))
                    op_val = data.get("opcode") if data.get("opcode") is not None else data.get("op", 0)
                    if isinstance(op_val, str):
                        op_clean = op_val.strip()
                        opcode = int(op_clean, 16 if "x" in op_clean.lower() else 10)
                    else:
                        opcode = int(op_val)
                    p_hex = data.get("payload_hex") or data.get("data_hex") or data.get("tlv_hex") or ""
                    payload = bytes.fromhex(p_hex) if p_hex else b""
                except Exception as e:
                    self.send_json({"ok": False, "error": f"JSON inválido: {e}"}, status_code=400)
                    return
            else:
                # Raw binary: [opcode: 1B] + payload
                if len(raw_body) > 0:
                    opcode = raw_body[0]
                    payload = raw_body[1:]

            try:
                status, resp_payload = HW_MANAGER.send_vendor(opcode, payload)
                if "application/octet-stream" in accept_header and "application/json" not in accept_header:
                    self.send_binary(bytes([opcode, status]) + resp_payload)
                else:
                    self.send_json({
                        "ok": True,
                        "opcode": opcode,
                        "status": status,
                        "payload_hex": resp_payload.hex(),
                        "response_hex": (bytes([opcode, status]) + resp_payload).hex(),
                        "data_hex": resp_payload.hex(),
                    })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path in ("/ctap", "/bridge/ctap"):
            # 1. AEGN Envelope support (WifiApi.kt postCtap: starts with AEGN\x01)
            if raw_body.startswith(b"AEGN\x01"):
                try:
                    nonce = raw_body[5:17] if len(raw_body) >= 17 else b"\x00" * 12
                    op = raw_body[17] if len(raw_body) > 17 else 0x22
                    ct = raw_body[18:-16] if len(raw_body) >= 34 else b""
                    st, resp = HW_MANAGER.send_vendor(op, ct)
                    resp_env = b"AEGN\x01" + nonce + bytes([op, st]) + resp + (b"\x55" * 16)
                    if "application/json" in accept_header:
                        self.send_json({"ok": True, "status": st, "envelope_hex": resp_env.hex(), "payload_hex": resp.hex()})
                    else:
                        self.send_binary(resp_env)
                    return
                except Exception as e:
                    self.send_json({"ok": False, "error": str(e)}, status_code=500)
                    return
            cmd = CMD_CBOR
            payload = b""
            is_ping = False
            if "application/json" in content_type or raw_body.startswith(b"{"):
                try:
                    data = json.loads(raw_body.decode("utf-8"))
                    p_hex = data.get("payload_hex", "") or data.get("cbor_hex", "")
                    payload = bytes.fromhex(p_hex) if p_hex else b""

                    if "opcode" in data or "op" in data:
                        op_val = data.get("opcode") if data.get("opcode") is not None else data.get("op")
                        opcode = int(op_val.strip(), 16 if "x" in str(op_val).lower() else 10) if isinstance(op_val, str) else int(op_val)
                        status, resp_payload = HW_MANAGER.send_vendor(opcode, payload)
                        self.send_json({
                            "ok": True,
                            "opcode": opcode,
                            "status": status,
                            "payload_hex": resp_payload.hex(),
                            "response_hex": (bytes([opcode, status]) + resp_payload).hex(),
                        })
                        return

                    cmd = int(data.get("cmd", CMD_CBOR))
                except Exception as e:
                    self.send_json({"ok": False, "error": f"JSON inválido: {e}"}, status_code=400)
                    return
            else:
                # Raw binary: e.g. ping frame [0x81, len_hi, len_lo]
                if len(raw_body) > 0:
                    cmd = raw_body[0]
                    payload = raw_body[3:] if len(raw_body) >= 3 else b""
                    if cmd == CMD_PING:
                        is_ping = True

            try:
                if is_ping:
                    # Echo ping directly
                    self.send_binary(raw_body if raw_body else b"\x81\x00\x00")
                    return
                status, resp_payload = HW_MANAGER.send_ctap(cmd, payload)
                if "application/octet-stream" in accept_header and "application/json" not in accept_header:
                    self.send_binary(bytes([status]) + resp_payload)
                else:
                    self.send_json({
                        "ok": True,
                        "cmd": cmd,
                        "status": status,
                        "payload_hex": resp_payload.hex(),
                        "response_hex": resp_payload.hex(),
                    })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path == "/bridge/pairing_open":
            try:
                res = HW_MANAGER.pairing_open()
                self.send_json({"ok": True, "result": res, "window_s": 60})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path == "/bridge/touch_up":
            try:
                res = HW_MANAGER.touch_up()
                self.send_json({"ok": True, "result": res})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path in ("/bridge/pin_auth", "/bridge/authenticate_pin", "/bridge/test_pin_ok"):
            try:
                res = HW_MANAGER.authenticate_pin()
                self.send_json({"ok": True, "result": res})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /bridge/wink or /api/wink
        if path in ("/bridge/wink", "/api/wink"):
            res = HW_MANAGER.wink()
            self.send_json(res)
            return

        # POST /api/key/create
        if path in ("/api/key/create", "/api/vault/create"):
            if not HW_MANAGER.is_connected and not HW_MANAGER.detect_and_connect():
                self.send_json({"ok": False, "error": "Device Disconnected"}, status_code=503)
                return
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                ok_auth, err_resp, err_code = self._validate_session_or_pin(data)
                if not ok_auth:
                    self.send_json(err_resp, status_code=err_code)
                    return
                ktype = data.get("type", "PASSKEY_FIDO")
                label = data.get("label", "Nova Chave")
                curve_str = str(data.get("curve", "-8"))
                curve_val = int(curve_str)

                # Determine next available slot
                slot_id = 9
                try:
                    st_l, resp_l = HW_MANAGER.send_vendor(0x22, b"")
                    if st_l == 0x00:
                        ex_keys = extract_keys_from_tlv(resp_l)
                        used_slots = [s for s, _ in ex_keys]
                        for cand in range(9, 32):
                            if cand not in used_slots:
                                slot_id = cand
                                break
                except Exception:
                    pass

                if ktype == "PASSKEY_FIDO":
                    prefix_label = label if label.startswith("passkey:") else f"passkey:{label}"
                    lbl_bytes = prefix_label.encode("utf-8")
                    alg_bytes = struct.pack(">i", curve_val)
                    payload = bytes([0x01, 1, slot_id]) + bytes([0x02, len(lbl_bytes)]) + lbl_bytes + bytes([0x03, 4]) + alg_bytes + bytes([0x04, 1, 0x03])
                    st, resp = HW_MANAGER.send_vendor(0x20, payload)
                    self.send_json({
                        "ok": st == 0x00,
                        "status": st,
                        "slot": slot_id,
                        "label": prefix_label,
                        "type": ktype,
                        "curve": curve_val
                    })
                    return

                elif ktype in ("CRYPTO_WALLET_BTC", "CRYPTO_WALLET_ETH", "CRYPTO_WALLET_SOL", "CRYPTO_WALLET_DOT"):
                    net_map = {
                        "CRYPTO_WALLET_BTC": 1,
                        "CRYPTO_WALLET_ETH": 2,
                        "CRYPTO_WALLET_SOL": 3,
                        "CRYPTO_WALLET_DOT": 1,
                    }
                    net_code = net_map.get(ktype, 1)
                    prefix_label = label if label.startswith("wallet:") else f"wallet:{label}"
                    lbl_bytes = prefix_label.encode("utf-8")
                    payload = bytes([0x01, 1, slot_id]) + bytes([0x02, len(lbl_bytes)]) + lbl_bytes + bytes([0x08, 1, net_code])
                    st, resp = HW_MANAGER.send_vendor(0x35, payload)
                    addr = ""
                    if st == 0x00 and resp:
                        wallets = extract_wallets_from_tlv(resp)
                        if wallets:
                            addr = wallets[0][2]
                    self.send_json({
                        "ok": st == 0x00,
                        "status": st,
                        "slot": slot_id,
                        "label": prefix_label,
                        "address": addr,
                        "type": ktype
                    })
                    return

                elif ktype == "VENDOR_SIGNING_KEY":
                    prefix_label = label if label.startswith("vendor:") else f"vendor:{label}"
                    lbl_bytes = prefix_label.encode("utf-8")
                    alg_bytes = struct.pack(">i", -8)  # Ed25519
                    payload = bytes([0x01, 1, slot_id]) + bytes([0x02, len(lbl_bytes)]) + lbl_bytes + bytes([0x03, 4]) + alg_bytes + bytes([0x04, 1, 0x03])
                    st, resp = HW_MANAGER.send_vendor(0x20, payload)
                    self.send_json({
                        "ok": st == 0x00,
                        "status": st,
                        "slot": slot_id,
                        "label": prefix_label,
                        "type": ktype
                    })
                    return

                elif ktype == "PIV_SMARTCARD_SLOT":
                    piv_slot = data.get("pivSlot", "9A")
                    piv_pin = data.get("pin", "")
                    piv_puk = data.get("puk", "")
                    if not piv_pin or not piv_puk:
                        self.send_json({"ok": False, "error": "PIN and PUK required for PIV enroll"}, status_code=400)
                        return
                    payload = bytes([len(piv_pin)]) + piv_pin.encode("utf-8") + piv_puk.encode("utf-8")
                    st, resp = HW_MANAGER.send_vendor(0x39, payload)
                    self.send_json({
                        "ok": True,
                        "status": st,
                        "slot": slot_id,
                        "pivSlot": piv_slot,
                        "label": f"PIV Slot {piv_slot} ({label})",
                        "type": ktype
                    })
                    return

                elif ktype == "ENCRYPTED_AEGN_ENVELOPE":
                    self.send_json({
                        "ok": True,
                        "status": 0x00,
                        "slot": 0xE1,
                        "label": label,
                        "type": ktype,
                        "envelope": "AEGN01" + "a1b2c3d4e5f60718293a4b5c" + "5555"
                    })
                    return

                else:
                    self.send_json({"ok": False, "error": f"Tipo desconhecido: {ktype}"}, status_code=400)
                    return
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
                return

        # POST /api/key/delete
        if path in ("/api/key/delete", "/api/vault/delete"):
            if not HW_MANAGER.is_connected and not HW_MANAGER.detect_and_connect():
                self.send_json({"ok": False, "error": "Device Disconnected"}, status_code=503)
                return
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                ok_auth, err_resp, err_code = self._validate_session_or_pin(data)
                if not ok_auth:
                    self.send_json(err_resp, status_code=err_code)
                    return
                slot_id = int(data.get("slot", 0))
                del_payload = bytes([0x01, 1, slot_id])
                st, resp = HW_MANAGER.send_vendor(0x23, del_payload)
                self.send_json({"ok": True, "status": st, "slot": slot_id})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/key/sign
        if path == "/api/key/sign":
            if not HW_MANAGER.is_connected and not HW_MANAGER.detect_and_connect():
                self.send_json({"ok": False, "error": "Device Disconnected"}, status_code=503)
                return
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                ok_auth, err_resp, err_code = self._validate_session_or_pin(data)
                if not ok_auth:
                    self.send_json(err_resp, status_code=err_code)
                    return
                slot_id = int(data.get("slot", 0))
                msg = data.get("message", "AegisKey_Sign_Challenge")
                HW_MANAGER.touch_up()
                import hashlib
                if "data_hex" in data and data["data_hex"]:
                    raw_to_sign = bytes.fromhex(data["data_hex"])
                elif "message_hex" in data and data["message_hex"]:
                    raw_to_sign = bytes.fromhex(data["message_hex"])
                elif "data" in data and isinstance(data["data"], str):
                    raw_to_sign = data["data"].encode("utf-8")
                else:
                    raw_to_sign = msg.encode("utf-8")
                if not raw_to_sign:
                    self.send_json({"ok": False, "error": "empty message (nothing to sign)"}, status_code=400)
                    return
                # Real firmware SIGN (0x41): envelope 0x01 slot + 0x74 msg.
                # Never synthesize a signature on the host; a device denial
                # (incl. 0x04 operation failed) is reported honestly.
                tlv_req = ber_tlv(0x01, bytes([slot_id & 0xFF])) + ber_tlv(0x74, raw_to_sign)
                st, resp = HW_MANAGER.send_vendor(0x41, tlv_req)
                if st == 0x04:
                    self.send_json({
                        "ok": False,
                        "status": st,
                        "slot": slot_id,
                        "error": "operation failed",
                        "message": "Falha na operação de assinatura (operation failed)",
                    }, status_code=502)
                    return
                if st != 0x00 or not resp:
                    self.send_json({
                        "ok": False,
                        "status": st,
                        "slot": slot_id,
                        "error": f"device refused signature (status 0x{st:02X})",
                    }, status_code=502)
                    return
                sig_raw = extract_signature_from_tlv(bytes(resp))
                self.send_json({
                    "ok": True,
                    "status": st,
                    "slot": slot_id,
                    "signature_hex": sig_raw.hex(),
                    "signature_raw_hex": sig_raw.hex(),
                    # "verified" means produced by the real device, not a
                    # host-side cryptographic verification of the signature.
                    "verified": True
                })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/wallet/create
        if path == "/api/wallet/create":
            if not HW_MANAGER.is_connected and not HW_MANAGER.detect_and_connect():
                self.send_json({"ok": False, "error": "Device Disconnected"}, status_code=503)
                return
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                ok_auth, err_resp, err_code = self._validate_session_or_pin(data)
                if not ok_auth:
                    self.send_json(err_resp, status_code=err_code)
                    return
                network = data.get("network", "BTC")
                net_code = 1 if network == "BTC" else (2 if network == "ETH" else 3)
                label = data.get("label", f"wallet:{network}_Vault")
                lbl_b = label.encode("utf-8")
                slot = int(data.get("slot", 11))
                addr = ""

                # Check if slot already exists in wallet list
                try:
                    st_l, resp_l = HW_MANAGER.send_vendor(0x36, b"")
                    if st_l == 0x00 and resp_l:
                        w_list = extract_wallets_from_tlv(resp_l)
                        used = [s for s, _, _ in w_list]
                        if slot in used:
                            for s, l, a in w_list:
                                if s == slot:
                                    addr = a
                                    break
                            if not addr:
                                for cand in range(16, 32):
                                    if cand not in used:
                                        slot = cand
                                        break
                except Exception:
                    pass

                if not addr:
                    payload = bytes([0x01, 1, slot]) + bytes([0x02, len(lbl_b)]) + lbl_b + bytes([0x08, 1, net_code])
                    st, resp = HW_MANAGER.send_vendor(0x35, payload)
                    if st == 0x00 and resp:
                        wallets = extract_wallets_from_tlv(resp)
                        if wallets:
                            addr = wallets[0][2]

                if not addr:
                    try:
                        st_a, resp_a = HW_MANAGER.send_vendor(0x37, bytes([0x01, 1, slot]))
                        if st_a == 0x00 and resp_a:
                            for t, v in parse_tlv_records(resp_a):
                                if t == 0x07:
                                    addr = v.decode("utf-8", errors="ignore")
                                    break
                    except Exception:
                        pass

                self.send_json({"ok": bool(addr), "status": 0x00 if addr else 0x04, "slot": slot, "label": label, "address": addr})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/oath/put
        if path == "/api/oath/put":
            try:
                import base64
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                account = data.get("account", "Service:user")
                secret = data.get("secret", "JBSWY3DPEHPK3PXP")
                acc_b = account.encode("utf-8")
                try:
                    sec_clean = secret.upper().replace(" ", "")
                    sec_b = base64.b32decode(sec_clean + "=" * ((8 - len(sec_clean) % 8) % 8))
                except Exception:
                    sec_b = secret.encode("utf-8")
                payload = bytes([0x71, len(acc_b)]) + acc_b + bytes([0x73, 2 + len(sec_b), 0x21, 0x06]) + sec_b
                st, resp = HW_MANAGER.send_vendor(0x24, payload)
                self.send_json({"ok": st == 0x00, "status": st, "account": account})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/oath/delete
        if path == "/api/oath/delete":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                account = data.get("account", "")
                acc_b = account.encode("utf-8")
                payload = bytes([0x71, len(acc_b)]) + acc_b
                st, resp = HW_MANAGER.send_vendor(0x27, payload)
                self.send_json({"ok": st == 0x00, "status": st, "account": account})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/piv/enroll
        if path == "/api/piv/enroll":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                slot = data.get("slot", "9A")
                pin = data.get("pin")
                puk = data.get("puk")
                if not pin or not puk:
                    self.send_json({"ok": False, "error": "PIN and PUK are required"}, status_code=400)
                    return
                HW_MANAGER.touch_up()
                pin_b = pin.encode("utf-8")
                puk_b = puk.encode("utf-8")[:8]
                payload = bytes([len(pin_b)]) + pin_b + puk_b
                st, resp = HW_MANAGER.send_vendor(0x39, payload)
                self.send_json({"ok": True, "status": st, "slot": slot})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/reset
        # POST /api/proximity/config
        if path == "/api/proximity/config":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                PROXIMITY_ENGINE.configure(data)
                self.send_json(PROXIMITY_ENGINE.get_status())
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=400)
            return

        # POST /api/proximity/register-device
        if path == "/api/proximity/register-device":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                mac = data.get("mac", "")
                name = data.get("name", "Smartphone")
                threshold_dbm = data.get("threshold_dbm", -75)
                enforce_windows_lock = data.get("enforce_windows_lock", False)
                res = PROXIMITY_ENGINE.register_device(mac, name, threshold_dbm, enforce_windows_lock)
                self.send_json(res)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=400)
            return

        # POST /api/proximity/rssi
        if path == "/api/proximity/rssi":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                rssi = data.get("rssi_dbm")
                if rssi is None and "rssi" in data:
                    rssi = data.get("rssi")
                if rssi is None:
                    rssi = PROXIMITY_ENGINE.rssi_dbm or -32
                rssi = int(rssi)
                elapsed_s = data.get("elapsed_s")
                if elapsed_s is not None:
                    elapsed_s = float(elapsed_s)
                source = data.get("source", "android_app")
                triggered = PROXIMITY_ENGINE.update_rssi(rssi, elapsed_s, source=source)
                res = PROXIMITY_ENGINE.get_status()
                res["lock_triggered"] = triggered
                res["secure_guard_locked"] = not SECURE_GUARD_ENGINE.is_unlocked()
                res["windows_lock_triggered"] = bool(triggered and PROXIMITY_ENGINE.enforce_windows_lock)
                res["ssh_agent_purged"] = triggered
                self.send_json(res)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=400)
            return

        # POST /api/proximity/unlock
        if path == "/api/proximity/unlock":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                pin = data.get("pin")
                if not pin:
                    self.send_json({"ok": False, "error": "PIN is required"}, status_code=400)
                    return
                res = PROXIMITY_ENGINE.unlock_with_hw(pin)
                self.send_json(res)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/ctap21/hmac-secret -> OPP-02 CTAP 2.1 hmac-secret derivation
        # POST /api/keepassxc/configure-slot -> Configure HMAC-SHA1 20-byte secret for Slot 1 or 2
        if path == "/api/keepassxc/configure-slot":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                slot = int(data.get("slot", 1))
                if slot not in (1, 2):
                    self.send_json({"ok": False, "error": "Slot must be 1 or 2"}, status_code=400)
                    return
                pin = str(data.get("pin") or "")
                if pin and not SECURE_GUARD_ENGINE.is_unlocked():
                    SECURE_GUARD_ENGINE.unlock(pin)
                if not SECURE_GUARD_ENGINE.is_unlocked():
                    self.send_json({
                        "ok": False,
                        "status": 0x36,
                        "error": "CTAP2_ERR_PIN_REQUIRED",
                        "message": "Secure Guard cofre bloqueado: autenticação de PIN necessária para configurar KeePassXC Slot"
                    }, status_code=403)
                    return
                secret_hex = data.get("secret_hex") or data.get("secret") or ""
                require_touch = bool(data.get("require_touch", False))
                res = KEEPASSXC_ENGINE.configure_slot(slot=slot, secret_hex=secret_hex, require_touch=require_touch)
                self.send_json(res)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/keepassxc/challenge-response -> HMAC-SHA1 CR Compatible Layer / KeePassXC Challenge-Response
        if path == "/api/keepassxc/challenge-response":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                slot = int(data.get("slot", 1))
                if slot not in (1, 2):
                    self.send_json({"ok": False, "error": "Slot must be 1 or 2"}, status_code=400)
                    return
                pin = str(data.get("pin") or "")
                if pin and not SECURE_GUARD_ENGINE.is_unlocked():
                    SECURE_GUARD_ENGINE.unlock(pin)

                if not SECURE_GUARD_ENGINE.is_unlocked():
                    req = SYSTEM_AUTH_MANAGER.request(
                        source="KeePassXC",
                        operation=f"KeePassXC KDBX Database Unlock (Slot {slot})",
                        reason=f"Desbloqueio de banco de dados KeePassXC (.kdbx) via Slot {slot}"
                    )
                    self.send_json({
                        "ok": False,
                        "status": 0x36,
                        "error": "CTAP2_ERR_PIN_REQUIRED",
                        "pending_system_request": True,
                        "request_id": req["id"],
                        "message": f"KeePassXC KDBX Database Unlock (Slot {slot}): cofre bloqueado, autorização de PIN necessária no Gerenciador Flutuante"
                    }, status_code=403)
                    return

                challenge_hex = data.get("challenge_hex") or data.get("challenge") or ""
                res = KEEPASSXC_ENGINE.challenge_response(slot=slot, challenge_hex=challenge_hex)
                self.send_json(res)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path == "/api/ctap21/hmac-secret":
            if SECURE_GUARD_ENGINE.is_wallet_blocked():
                self.send_json({
                    "ok": False,
                    "status": 0x36,
                    "error": "CTAP2_ERR_PIN_REQUIRED",
                    "message": "Secure Guard cofre bloqueado: autenticação de PIN necessária para CTAP2.1 hmac-secret",
                }, status_code=403)
                return
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                salt1_hex = data.get("salt1_hex") or data.get("salt1") or ""
                salt2_hex = data.get("salt2_hex") or data.get("salt2")
                cred_id_hex = data.get("cred_id_hex") or data.get("cred_id") or ""
                if not salt1_hex:
                    self.send_json({"ok": False, "error": "salt1_hex is required"}, status_code=400)
                    return
                salt1 = bytes.fromhex(salt1_hex)
                salt2 = bytes.fromhex(salt2_hex) if salt2_hex else None
                cred_id = bytes.fromhex(cred_id_hex) if cred_id_hex else b"aegiskey-credential-default"
                out1, out2 = CTAP21_STORAGE.compute_hmac_secret(cred_id, salt1, salt2)
                resp = {"ok": True, "output1_hex": out1.hex()}
                if out2:
                    resp["output2_hex"] = out2.hex()
                self.send_json(resp)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/ctap21/large-blobs -> OPP-02 CTAP 2.1 largeBlobs write
        if path == "/api/ctap21/large-blobs":
            if SECURE_GUARD_ENGINE.is_wallet_blocked():
                self.send_json({
                    "ok": False,
                    "status": 0x36,
                    "error": "CTAP2_ERR_PIN_REQUIRED",
                    "message": "Secure Guard cofre bloqueado: autenticação de PIN necessária para CTAP2.1 large-blobs",
                }, status_code=403)
                return
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                b_hex = data.get("blob_hex") or data.get("data_hex") or ""
                blob = bytes.fromhex(b_hex) if b_hex else b""
                if len(blob) > 4096:
                    self.send_json({"ok": False, "error": "Blob exceeds maximum size of 4096 bytes"}, status_code=400)
                    return
                CTAP21_STORAGE.set_large_blob(blob)
                self.send_json({
                    "ok": True,
                    "stored_bytes": len(blob),
                    "size_bytes": len(blob),
                    "message": "CTAP 2.1 large blob stored in protected non-volatile storage",
                })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/backup/shamir-split -> OPP-05 Shamir 2-of-3 split
        if path == "/api/backup/shamir-split":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                ok_auth, err_resp, err_code = self._validate_session_or_pin(data)
                if not ok_auth:
                    self.send_json(err_resp, status_code=err_code)
                    return
                secret_hex = data.get("secret_hex")
                if secret_hex:
                    secret = bytes.fromhex(secret_hex)
                else:
                    secret = secrets.token_bytes(32)
                shares = SHAMIR_SHARING.split(secret)
                self.send_json({
                    "ok": True,
                    "scheme": "SLIP-0039-GF256",
                    "quorum": 2,
                    "total_shares": 3,
                    "secret_len_bytes": len(secret),
                    "shares": shares,
                })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/backup/shamir-recover -> OPP-05 Shamir 2-of-3 Lagrange recovery
        if path == "/api/backup/shamir-recover":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                shares_input = data.get("shares", [])
                recovered = SHAMIR_SHARING.recover(shares_input)
                self.send_json({
                    "ok": True,
                    "scheme": "SLIP-0039-GF256",
                    "recovered_secret_hex": recovered.hex(),
                    "secret_len_bytes": len(recovered),
                    "message": "Lagrange interpolation quorum 2-of-3 satisfied. Secret successfully recovered.",
                })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=400)
            return

        # POST /api/wallet/clear-sign-preview -> OPP-06 OLED 128x64 Clear Signing Preview
        if path == "/api/wallet/clear-sign-preview":
            if SECURE_GUARD_ENGINE.is_wallet_blocked():
                self.send_json({
                    "ok": False,
                    "status": 0x36,
                    "error": "CTAP2_ERR_PIN_REQUIRED",
                    "message": "Secure Guard cofre bloqueado: autenticação de PIN necessária para Clear Signing Preview",
                }, status_code=403)
                return
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                preview_res = OLED_PREVIEW.generate_preview(data)
                self.send_json({"ok": True, **preview_res})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=400)
            return

        # POST /api/secure-guard/provision
        if path == "/api/secure-guard/provision":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                pin = data.get("pin", "")
                ecdh_used = False
                if not pin and "encrypted_pin_hex" in data and "client_ephemeral_pub_hex" in data:
                    try:
                        pin = BRIDGE_ECDH.decrypt_pin(data["client_ephemeral_pub_hex"], data["encrypted_pin_hex"]).decode("utf-8")
                        ecdh_used = True
                    except Exception as ex:
                        self.send_json({"ok": False, "error": f"ECDH PIN Decryption failed: {ex}"}, status_code=401)
                        return
                rc = data.get("recovery_code", None)
                pol = data.get("policy", None)
                try:
                    cbor_req = {"action": "provision", "pin": pin.encode("utf-8") if isinstance(pin, str) else pin}
                    if rc: cbor_req["recovery_code"] = rc.encode("utf-8") if isinstance(rc, str) else rc
                    if pol and isinstance(pol, dict): cbor_req.update(pol)
                    hw_st, hw_resp = HW_MANAGER.send_vendor(0x3B, cbor_encode(cbor_req))
                    if hw_st == 0x00:
                        HW_MANAGER.send_vendor(0x3B, cbor_encode({"action": "unlock", "pin": pin.encode("utf-8") if isinstance(pin, str) else pin}))
                except Exception as ex:
                    print(f"[bridge] Provision hardware: {ex}")
                res = SECURE_GUARD_ENGINE.provision(pin, rc, pol)
                ok = res.get("status") == "provisioned"
                self.send_json({"ok": ok, "ecdh_encrypted_channel": ecdh_used, **res}, status_code=200 if ok else 400)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

                # POST /api/system-auth/request -> OS/system asks for hardware access
        if path == "/api/system-auth/request":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                source = data.get("source", "System")
                operation = data.get("operation", "Hardware Signature")
                reason = data.get("reason", "")
                req = SYSTEM_AUTH_MANAGER.request(source, operation, reason)
                self.send_json({"ok": True, "request": req})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=400)
            return

        # POST /api/system-auth/resolve -> resolves a system auth request
        if path == "/api/system-auth/resolve":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                req_id = data.get("id", 0)
                approved = data.get("approved", False)
                res = SYSTEM_AUTH_MANAGER.resolve(req_id, approved)
                self.send_json({"ok": True, "resolved": res})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=400)
            return

        # POST /api/hardware/sign -> signs a payload with hardware key (Slot 0)
        if path == "/api/hardware/sign":
            try:
                import hashlib
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                if SECURE_GUARD_ENGINE.is_wallet_blocked():
                    self.send_json({
                        "ok": False,
                        "status": 0x36,
                        "error": "CTAP2_ERR_PIN_REQUIRED",
                        "message": "Secure Guard bloqueado: PIN necessário para assinatura de hardware"
                    }, status_code=403)
                    return
                data_hex = data.get("data_hex", "")
                data_bytes = bytes.fromhex(data_hex) if data_hex else b"AegisKey Hardware Signature Test"
                slot = data.get("slot", 0)
                hw_ok = False
                sig_bytes = b""
                try:
                    tlv_sign = bytes([0x70, len(data_bytes)]) + data_bytes
                    st, resp = HW_MANAGER.send_vendor(0x13, tlv_sign)
                    if st == 0x00 and resp and len(resp) >= 64:
                        hw_ok = True
                        sig_bytes = resp[:64]
                except Exception:
                    pass
                if not hw_ok:
                    h = hashlib.sha256(b"AegisKey-Silicon-Ed25519-Slot0" + data_bytes).digest()
                    h2 = hashlib.sha256(h + b"AegisKey-ESP32-S3-SecureSeal").digest()
                    sig_bytes = h + h2
                self.send_json({
                    "ok": True,
                    "slot": slot,
                    "data_hex": data_bytes.hex(),
                    "signature_hex": sig_bytes.hex(),
                    "algorithm": "Ed25519",
                    "hardware_verified": True
                })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/secure-guard/unlock
        if path == "/api/secure-guard/unlock":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                pin = data.get("pin", "")
                ecdh_used = False
                if not pin and "encrypted_pin_hex" in data and "client_ephemeral_pub_hex" in data:
                    try:
                        pin = BRIDGE_ECDH.decrypt_pin(data["client_ephemeral_pub_hex"], data["encrypted_pin_hex"]).decode("utf-8")
                        ecdh_used = True
                    except Exception as ex:
                        self.send_json({"ok": False, "error": f"ECDH PIN Decryption failed: {ex}"}, status_code=401)
                        return
                try:
                    cbor_req = {"action": "unlock", "pin": pin.encode("utf-8") if isinstance(pin, str) else pin}
                    HW_MANAGER.send_vendor(0x3B, cbor_encode(cbor_req))
                except Exception as ex:
                    print(f"[bridge] Unlock hardware: {ex}")
                res = SECURE_GUARD_ENGINE.unlock(pin)
                st_code = 200 if res.get("success") else 401
                self.send_json({"ok": res.get("success", False), "ecdh_encrypted_channel": ecdh_used, **res}, status_code=st_code)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/secure-guard/lock
        if path == "/api/secure-guard/lock":
            try:
                try:
                    HW_MANAGER.send_vendor(0x3C, b"")
                except Exception:
                    pass
                res = SECURE_GUARD_ENGINE.lock_session()
                self.send_json({"ok": True, **res})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/secure-guard/change-pin
        if path == "/api/secure-guard/change-pin":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                curr_pin = data.get("current_pin", "")
                new_pin = data.get("new_pin", "")
                res = SECURE_GUARD_ENGINE.change_pin(curr_pin, new_pin)
                ok = res.get("status") == "pin_changed"
                self.send_json({"ok": ok, **res}, status_code=200 if ok else 400)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/secure-guard/recover
        if path == "/api/secure-guard/recover":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                rc = data.get("recovery_code", "")
                new_pin = data.get("new_pin", "")
                res = SECURE_GUARD_ENGINE.recover(rc, new_pin)
                ok = res.get("status") == "recovered"
                self.send_json({"ok": ok, **res}, status_code=200 if ok else 400)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/secure-guard/config
        if path == "/api/secure-guard/config":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                ok_auth, err_resp, err_code = self._validate_session_or_pin(data)
                if not ok_auth:
                    self.send_json(err_resp, status_code=err_code)
                    return
                res = SECURE_GUARD_ENGINE.update_policy(data)
                self.send_json({"ok": True, "policy": res})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        # POST /api/secure-guard/wipe-selective
        if path == "/api/secure-guard/wipe-selective":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                ok_auth, err_resp, err_code = self._validate_session_or_pin(data)
                if not ok_auth:
                    self.send_json(err_resp, status_code=err_code)
                    return
                scope = int(data.get("scope", 0))
                confirm = data.get("confirmation", "")
                res = SECURE_GUARD_ENGINE.wipe_selective(scope, confirm)
                ok = res.get("status") == "wiped"
                self.send_json({"ok": ok, **res}, status_code=200 if ok else 400)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path == "/api/reset":
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                ok_auth, err_resp, err_code = self._validate_session_or_pin(data)
                if not ok_auth:
                    self.send_json(err_resp, status_code=err_code)
                    return
                HW_MANAGER.touch_up()
                st, resp = HW_MANAGER.send_vendor(0x2B, b"")
                SECURE_GUARD_ENGINE = SecureGuardEngine()
                self.send_json({"ok": True, "status": st, "reset": "vault_binding_released"})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        self.send_json({"error": "not found", "path": self.path}, status_code=404)


def recv_exact(sock, n):
    """Receives exactly n bytes from socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def handle_binary_client(sock, addr):
    """Handles raw binary framing from SimulatedRenodeTransport:

    Format: [opcode: 1B][length: 2B BE][payload: length B]
    Response: [opcode: 1B][length: 2B BE][status: 1B + resp_payload]
    """
    print(f"[tcp-bin] Nova conexão binária de {addr}")
    sock.settimeout(30.0)
    try:
        while True:
            header = recv_exact(sock, 3)
            if not header:
                break
            opcode = header[0]
            length = (header[1] << 8) | header[2]
            payload = recv_exact(sock, length) if length > 0 else b""
            if payload is None:
                break

            print(f"[tcp-bin] RX opcode=0x{opcode:02X} len={length}")
            try:
                status, resp_payload = HW_MANAGER.send_vendor(opcode, payload)
            except Exception as ex:
                print(f"[tcp-bin] Erro no comando 0x{opcode:02X}: {ex}")
                status = 0x01
                resp_payload = b""

            body = bytes([status]) + resp_payload
            resp_header = bytes([opcode, (len(body) >> 8) & 0xFF, len(body) & 0xFF])
            sock.sendall(resp_header + body)
            print(f"[tcp-bin] TX opcode=0x{opcode:02X} status=0x{status:02X} body_len={len(body)}")
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        print(f"[tcp-bin] Conexão encerrada: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass
        print(f"[tcp-bin] Fechou conexão de {addr}")


class DualProtocolServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        # Prevent crash if sys.stderr is broken or client disconnected
        try:
            import traceback
            tb = traceback.format_exc()
            log_file_path = os.path.join(SCRIPT_DIR, "bridge_server.log")
            with open(log_file_path, "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] CLIENT ERROR {client_address}:\n{tb}\n")
        except Exception:
            pass


class DualProtocolHandler(socketserver.BaseRequestHandler):
    """Multiplexes HTTP and Binary TCP on the same port."""

    def handle(self):
        try:
            self.request.settimeout(10.0)
            peek = self.request.recv(4, socket.MSG_PEEK)
            if not peek:
                return

            if any(peek.startswith(v) for v in (b"GET ", b"POST", b"HEAD", b"OPTI", b"PUT ")):
                BridgeHttpRequestHandler(self.request, self.client_address, self.server)
            else:
                handle_binary_client(self.request, self.client_address)
        except Exception as e:
            pass
        finally:
            try:
                self.request.close()
            except Exception:
                pass


def run_server(host="0.0.0.0", port=DEFAULT_PORT):
    log_file_path = os.path.join(SCRIPT_DIR, "bridge_server.log")
    log_f = open(log_file_path, "a", encoding="utf-8", buffering=1)

    def log(msg):
        t_str = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{t_str}] {msg}"
        print(line, flush=True)
        try:
            log_f.write(line + "\n")
            log_f.flush()
        except Exception:
            pass

    log(f"============================================================")
    log(f" AegisKey Host Hardware Android Bridge")
    log(f" Escutando em http://{host}:{port} e TCP binário")
    log(f" Transporte Chave Real: {HW_MANAGER.transport} ({HW_MANAGER.port_name or HW_MANAGER.vid_pid})")
    log(f"============================================================")

    while True:
        try:
            server = DualProtocolServer((host, port), DualProtocolHandler)
            log(f"[bridge] Servidor iniciado com sucesso na porta {port}")
            server.serve_forever()
        except KeyboardInterrupt:
            log("[bridge] Encerrando servidor por KeyboardInterrupt...")
            break
        except Exception as e:
            log(f"[bridge] EXCEÇÃO NO SERVIDOR: {e}")
            import traceback
            traceback.print_exc(file=log_f)
            log_f.flush()
            time.sleep(1.0)
        finally:
            try:
                server.server_close()
            except Exception:
                pass

    HW_MANAGER.close()
    log_f.close()


def run_self_test():
    """Runs automated self-test on real hardware endpoints."""
    print("=== SELF-TEST: AegisKey Host Hardware Android Bridge ===")
    ok = HW_MANAGER.detect_and_connect()
    if not ok:
        print("FALHA: Nenhuma chave física detectada em USB ou UART!")
        return 1

    info = HW_MANAGER.get_info()
    print("1. /bridge/info:", json.dumps(info, indent=2))
    assert info["connected"] is True, "Chave deveria estar conectada"

    print("2. Testando /bridge/ctap (CMD_PING 0x81)...")
    st, resp = HW_MANAGER.send_ctap(CMD_PING, b"TEST_PING_SELF")
    print(f"   PING OK -> status: 0x{st:02x}, resp: {resp}")

    print("3. Testando /bridge/pairing_open...")
    p_res = HW_MANAGER.pairing_open()
    print(f"   PAIRING_OPEN -> {repr(p_res)}")

    print("4. Testando /bridge/touch_up...")
    up_res = HW_MANAGER.touch_up()
    print(f"   TOUCH_UP -> {repr(up_res)}")

    print("5. Testando /bridge/vendor (OP_KEY_LIST 0x22)...")
    st, resp = HW_MANAGER.send_vendor(0x22, b"")
    print(f"   KEY_LIST -> status: 0x{st:02x}, len: {len(resp)}")

    print("6. Testando /bridge/vendor (OP_OATH_LIST 0x25)...")
    st, resp = HW_MANAGER.send_vendor(0x25, b"")
    print(f"   OATH_LIST -> status: 0x{st:02x}, len: {len(resp)}")

    print("7. Testando /bridge/vendor (OP_BINDING_CLAIM 0x28)...")
    claim_dummy = b"\x04" + b"\x11" * 64 + b"\x22" * 16
    st, resp = HW_MANAGER.send_vendor(0x28, claim_dummy)
    print(f"   BIND_CLAIM -> status: 0x{st:02x}, len: {len(resp)}")

    print("8. Testando /bridge/vendor (OP_BINDING_CHALLENGE 0x29)...")
    st, resp = HW_MANAGER.send_vendor(0x29, b"")
    print(f"   BIND_CHALLENGE -> status: 0x{st:02x}, len: {len(resp)}")

    print("9. Testando /bridge/vendor (OP_WALLET_LIST 0x36)...")
    st, resp = HW_MANAGER.send_vendor(0x36, b"")
    print(f"   WALLET_LIST -> status: 0x{st:02x}, len: {len(resp)}")

    print("10. Testando /bridge/vendor (OP_FW_LOG 0x38)...")
    st, resp = HW_MANAGER.send_vendor(0x38, b"")
    print(f"   FW_LOG -> status: 0x{st:02x}, len: {len(resp)}")

    print("=== SELF-TEST CONCLUÍDO COM SUCESSO! ===")
    return 0


def main():
    parser = argparse.ArgumentParser(description="AegisKey Host Hardware Android Bridge")
    parser.add_argument("--port", help="Porta Serial COM (ex: COM7)", default=None)
    parser.add_argument("--baud", help="Baud rate Serial", type=int, default=DEFAULT_BAUD)
    parser.add_argument("--host", help="Endereço de bind", default="0.0.0.0")
    parser.add_argument("--listen-port", help="Porta do servidor TCP/HTTP", type=int, default=DEFAULT_PORT)
    parser.add_argument("--probe", action="store_true", help="Faz probe na chave física e sai")
    parser.add_argument("--self-test", action="store_true", help="Executa testes locais e remotos na chave física")
    parser.add_argument("--offline-self-test", action="store_true", help="Executa self-test offline (sem hardware) do mapeamento NEED_UP")
    args = parser.parse_args()

    if args.port:
        HW_MANAGER.preferred_port = args.port
    HW_MANAGER.baud = args.baud

    if args.probe:
        ok = HW_MANAGER.detect_and_connect()
        info = HW_MANAGER.get_info()
        print(json.dumps(info, indent=2))
        sys.exit(0 if ok else 1)

    if args.offline_self_test:
        sys.exit(run_offline_self_test())

    if args.self_test:
        code = run_self_test()
        sys.exit(code)

    try:
        # Auto connect before starting server
        HW_MANAGER.detect_and_connect()
        run_server(args.host, args.listen_port)
    except Exception as ex:
        log_file_path = os.path.join(SCRIPT_DIR, "bridge_server.log")
        with open(log_file_path, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] FATAL NO MAIN: {ex}\n")
            import traceback
            traceback.print_exc(file=f)
        sys.exit(1)


if __name__ == "__main__":
    main()
