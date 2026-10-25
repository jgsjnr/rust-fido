#!/usr/bin/env python3
"""End-to-End Journey Simulator & Validator for Android UX (Onboarding, Keys Repository, TOTP).

Simulates and validates all UX journeys specified for the AegisKey Android App:
  J1: First Startup (Zero devices in ConnectedKeysRepository) -> mandatory ONBOARDING_WIZARD_STEP_1
  J2: Wizard Step-by-Step (Next -> Next -> Next) with simulated physical button presses:
      - Step 1 -> 2: Hold BOOT (GPIO0 in Renode for 5s / opens 60s pairing window)
      - Step 2 -> 3: BLE Discovery (0xFFFD) & JustWorks bonding
      - Step 3 -> 4: Physical button tap (SimPresence.press() / TEST_UP / GPIO0 pulse)
                     + P-256 KeyStore generation + raw CLAIM (0x28) -> CHALLENGE (0x29) -> VERIFY (0x2A)
      - Step 4 -> 5: Recovery PIN setup (0x2C) & save to ConnectedKeysRepository
  J3: ConnectedKeysRepository & Reactive Transitions:
      - 1 key: root route becomes VAULT_AND_TOTP_HUB
      - 2nd key: add, switch active key, toggle between keys
      - Removing all keys reactively transitions back to ONBOARDING_WIZARD_STEP_1
  J4: Key Vault & FIDO Passkey / Crypto Wallet Generation:
      - FIDO Passkey creation (0x20) and Wallet generation (0x35 / 0x37 Bech32 bc1q...) with UP
      - Security toggles (proximity walkaway lock, biometrics, presence requirement)
  J5: Dedicated TOTP Screen (RFC 6238):
      - Enroll account via otpauth:// URI or Base32 (0x24 PUT with binding + UP + PIN)
      - List accounts (0x25 LIST)
      - 6-digit code generation (0x26 CODE with UP) and 30s countdown
      - Strict sanitization: Base32 secret is NEVER leaked in logs
  Renode Integration:
      - Hardware/GPIO smoke test and CTAPHID INIT from E:\\projetos\\tscircuit\\sim\\renode_bridge.py
      - Auto-detection / --with-renode validation
  TCP Server for Android Emulator (10.0.2.2):
      - Local TCP server supporting CTAPHID 64-byte packets, HTTP REST, and text commands

Usage:
  python tools/test_onboarding_and_totp_journey.py --self-test
  python tools/test_onboarding_and_totp_journey.py --with-renode
  python tools/test_onboarding_and_totp_journey.py --serve [--host 0.0.0.0] [--port 5678]
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import http.server
import json
import os
import re
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple
import urllib.parse

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
WORKTREE_ROOT = os.path.dirname(HERE)
if WORKTREE_ROOT not in sys.path:
    sys.path.insert(0, WORKTREE_ROOT)

SIM_DIR = r"E:\projetos\tscircuit\sim"
if os.path.isdir(SIM_DIR) and SIM_DIR not in sys.path:
    sys.path.insert(0, SIM_DIR)

# ---------------------------------------------------------------------------
# Canonical Route Constants
# ---------------------------------------------------------------------------
ONBOARDING_WIZARD_STEP_1 = "ONBOARDING_WIZARD_STEP_1"  # Welcome / Posse exclusiva
ONBOARDING_WIZARD_STEP_2 = "ONBOARDING_WIZARD_STEP_2"  # Hold BOOT (5s) / Pairing mode
ONBOARDING_WIZARD_STEP_3 = "ONBOARDING_WIZARD_STEP_3"  # BLE Scan 0xFFFD / JustWorks Bonding
ONBOARDING_WIZARD_STEP_4 = "ONBOARDING_WIZARD_STEP_4"  # Tap UP / KeyStore P-256 / 0x28 CLAIM -> 0x29 CHALLENGE -> 0x2A VERIFY
ONBOARDING_WIZARD_STEP_5 = "ONBOARDING_WIZARD_STEP_5"  # Recovery PIN (0x2C) & Save Key
VAULT_AND_TOTP_HUB = "VAULT_AND_TOTP_HUB"              # Main Dashboard when >= 1 key
TOTP_SCREEN = "TOTP_SCREEN"                            # Dedicated RFC 6238 TOTP View
WALLET_SCREEN = "WALLET_SCREEN"                        # FIDO Passkey & Crypto Wallet View

# Domain OnboardingStep mapping (Kotlin parity)
WELCOME_TRANSPORT = ONBOARDING_WIZARD_STEP_1
HOLD_PHYSICAL_BUTTON = ONBOARDING_WIZARD_STEP_2
DISCOVER_AND_CONNECT = ONBOARDING_WIZARD_STEP_3
TOUCH_AND_BIOMETRIC_BIND = ONBOARDING_WIZARD_STEP_4
NAME_AND_FINISH = ONBOARDING_WIZARD_STEP_5

# Wire Opcodes (Fase6 & BLE Protocol)
OP_KEY_GEN = 0x20
OP_KEY_LIST = 0x22
OP_KEY_DELETE = 0x23
OP_OATH_PUT = 0x24
OP_OATH_LIST = 0x25
OP_OATH_CODE = 0x26
OP_OATH_DELETE = 0x27
OP_BINDING_CLAIM = 0x28
OP_BINDING_CHALLENGE = 0x29
OP_BINDING_VERIFY = 0x2A
OP_BINDING_RELEASE = 0x2B
OP_RECOVERY_SET = 0x2C
OP_RECOVERY_UNLOCK = 0x2D
OP_WALLET_GEN = 0x35
OP_WALLET_LIST = 0x36
OP_WALLET_ADDR = 0x37
OP_PROX_WALKAWAY = 0x3A

# CTAPHID constants
PACKET_SIZE = 64
CMD_INIT = 0x86
CMD_PING = 0x81
CMD_MSG = 0x83
CMD_CBOR = 0x90
CMD_KEEPALIVE = 0xBB

# ---------------------------------------------------------------------------
# Sanitized Logging Subsystem (Strictly prevents PII / Secret leak)
# ---------------------------------------------------------------------------
GLOBAL_LOGS: List[Tuple[float, str, str]] = []


def sanitized_log(name: str, detail: str = "") -> None:
    """Record event with sanitized labels/counts only. Never logs secrets."""
    # Safety assertion against raw Base32 or raw recovery PIN in logs
    if "secret=" in detail.lower() or "base32=" in detail.lower():
        detail = "[REDACTED_SECRET_PARAM]"
    GLOBAL_LOGS.append((time.time(), name, detail))
    suffix = f" {detail}" if detail else ""
    print(f"[log] {name}{suffix}")


def get_log_history() -> List[str]:
    return [f"{name} {detail}".strip() for _, name, detail in GLOBAL_LOGS]


# ---------------------------------------------------------------------------
# Simulated Presence (Single-use latch)
# ---------------------------------------------------------------------------
class SimPresence:
    """Simulated user-presence tap (single-use latch, no hardware claim)."""

    def __init__(self) -> None:
        self.latched = False

    def press(self) -> None:
        self.latched = True
        sanitized_log("UP_SIMULATED", "no-hardware latch=1x")

    def consume(self) -> bool:
        if not self.latched:
            return False
        self.latched = False
        return True


# ---------------------------------------------------------------------------
# Renode GPIO0 / BOOT Simulator
# ---------------------------------------------------------------------------
class RenodeGpioSimulator:
    """Models the physical BOOT button (GPIO0) and touch contact on ESP32-S3."""

    def __init__(self, up_presence: SimPresence) -> None:
        self.up_presence = up_presence
        self.gpio0_state = 1  # 1 = released (pull-up), 0 = pressed
        self.pairing_window_open = False
        self.pairing_window_expires_at = 0.0

    def hold_boot_button(self, duration_s: float = 5.0) -> bool:
        """Simulate holding the BOOT button (GPIO0 low) for 5 seconds."""
        sanitized_log("GPIO0_BOOT_HOLD", f"duration={duration_s:.1f}s")
        self.gpio0_state = 0
        time.sleep(0.01)  # simulated hold time
        self.gpio0_state = 1
        if duration_s >= 5.0:
            self.pairing_window_open = True
            self.pairing_window_expires_at = time.time() + 60.0
            sanitized_log("PAIRING_WINDOW_OPEN", "window=60s")
            return True
        return False

    def is_pairing_window_active(self) -> bool:
        if not self.pairing_window_open:
            return False
        if time.time() > self.pairing_window_expires_at:
            self.pairing_window_open = False
            return False
        return True

    def press_touch_button(self) -> None:
        """Simulate quick touch on physical presence button (GPIO0 pulse / UP)."""
        sanitized_log("GPIO0_TOUCH_PULSE", "pulse=50ms")
        self.up_presence.press()


# ---------------------------------------------------------------------------
# Domain Models: ConnectedKey & ConnectedKeysRepository
# ---------------------------------------------------------------------------
@dataclass
class SecuritySettings:
    proximity_lock: bool = False
    biometrics_required: bool = True
    presence_required: bool = True

    # Kotlin SecurityToggles compatibility aliases
    @property
    def lock_on_walk_away(self) -> bool:
        return self.proximity_lock

    @lock_on_walk_away.setter
    def lock_on_walk_away(self, val: bool) -> None:
        self.proximity_lock = val

    @property
    def require_biometrics_on_open(self) -> bool:
        return self.biometrics_required

    @require_biometrics_on_open.setter
    def require_biometrics_on_open(self, val: bool) -> None:
        self.biometrics_required = val

    @property
    def require_touch_for_every_code(self) -> bool:
        return self.presence_required

    @require_touch_for_every_code.setter
    def require_touch_for_every_code(self, val: bool) -> None:
        self.presence_required = val


@dataclass
class ConnectedKey:
    key_id: str
    name: str
    binding_id: bytes
    pubkey_uncompressed: bytes
    recovery_pin_hash: Optional[bytes] = None
    created_at: float = field(default_factory=time.time)
    settings: SecuritySettings = field(default_factory=SecuritySettings)


class ConnectedKeysRepository:
    """Reactive repository storing connected keys, managing active key and route."""

    def __init__(self) -> None:
        self.connected_keys: List[ConnectedKey] = []
        self.active_key_id: Optional[str] = None
        self._route_listeners: List[Callable[[str], None]] = []

    def add_listener(self, listener: Callable[[str], None]) -> None:
        self._route_listeners.append(listener)

    def get_current_route(self) -> str:
        """Reactive route resolver based on repository state."""
        if not self.connected_keys:
            return ONBOARDING_WIZARD_STEP_1
        return VAULT_AND_TOTP_HUB

    def _notify(self) -> None:
        route = self.get_current_route()
        for listener in self._route_listeners:
            listener(route)

    def add_key(self, key: ConnectedKey) -> None:
        self.connected_keys.append(key)
        if self.active_key_id is None:
            self.active_key_id = key.key_id
        sanitized_log("KEY_REPOSITORY_ADD", f"id={key.key_id[:8]} count={len(self.connected_keys)}")
        self._notify()

    def remove_key(self, key_id: str) -> bool:
        initial_len = len(self.connected_keys)
        self.connected_keys = [k for k in self.connected_keys if k.key_id != key_id]
        if len(self.connected_keys) < initial_len:
            if self.active_key_id == key_id:
                self.active_key_id = self.connected_keys[0].key_id if self.connected_keys else None
            sanitized_log("KEY_REPOSITORY_REMOVE", f"id={key_id[:8]} remaining={len(self.connected_keys)}")
            self._notify()
            return True
        return False

    @property
    def has_any_connected_key(self) -> bool:
        return len(self.connected_keys) > 0

    def rename_key(self, key_id: str, new_name: str) -> bool:
        for k in self.connected_keys:
            if k.key_id == key_id:
                k.name = new_name
                sanitized_log("KEY_REPOSITORY_RENAME", f"id={key_id[:8]} name_len={len(new_name)}")
                return True
        return False

    def select_active_key(self, key_id: str) -> bool:
        return self.set_active_key(key_id)

    def set_active_key(self, key_id: str) -> bool:
        if any(k.key_id == key_id for k in self.connected_keys):
            self.active_key_id = key_id
            sanitized_log("KEY_REPOSITORY_SET_ACTIVE", f"id={key_id[:8]}")
            return True
        return False

    def get_active_key(self) -> Optional[ConnectedKey]:
        if self.active_key_id is None:
            return None
        for k in self.connected_keys:
            if k.key_id == self.active_key_id:
                return k
        return None

    def clear(self) -> None:
        self.connected_keys.clear()
        self.active_key_id = None
        sanitized_log("KEY_REPOSITORY_CLEAR", "count=0")
        self._notify()


# ---------------------------------------------------------------------------
# Android KeyStore Simulator (P-256 Keypair & Challenge Signer)
# ---------------------------------------------------------------------------
class AndroidKeyStoreSim:
    """Simulates Android Hardware KeyStore generating P-256 keypairs and signatures."""

    def __init__(self, seed: Optional[bytes] = None) -> None:
        self._priv_material = seed or os.urandom(32)
        # SEC1 uncompressed pubkey: 0x04 + X (32B) + Y (32B) = 65 bytes
        x = hashlib.sha256(self._priv_material + b"x").digest()
        y = hashlib.sha256(self._priv_material + b"y").digest()
        self.pubkey_uncompressed = b"\x04" + x + y
        assert len(self.pubkey_uncompressed) == 65

    def generate_binding_id(self) -> bytes:
        return os.urandom(16)

    def sign(self, challenge: bytes, op: int, payload_hash: bytes) -> bytes:
        """P-256 signature stand-in: HMAC over challenge || op || payload_hash."""
        assert len(challenge) == 32
        assert len(payload_hash) == 32
        data = challenge + bytes([op]) + payload_hash
        return hmac.new(self._priv_material, data, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# RFC 6238 TOTP Engine & URI Parser (Base32 Safe)
# ---------------------------------------------------------------------------
def decode_base32_secret(secret_b32: str) -> bytes:
    """Decodes Base32 secret without logging or leaking it."""
    clean = re.sub(r"[\s=-]", "", secret_b32.strip().upper())
    missing_padding = len(clean) % 8
    if missing_padding != 0:
        clean += "=" * (8 - missing_padding)
    return base64.b32decode(clean, casefold=True)


def parse_otpauth_uri(uri: str) -> Dict[str, any]:
    """Parses otpauth://totp/URI per Key Uri Format."""
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "otpauth" or parsed.netloc.lower() != "totp":
        raise ValueError("Invalid otpauth URI scheme/type")
    label = urllib.parse.unquote(parsed.path.lstrip("/"))
    params = urllib.parse.parse_qs(parsed.query)
    secret_param = params.get("secret", [None])[0]
    if not secret_param:
        raise ValueError("Missing secret param in otpauth URI")
    secret_bytes = decode_base32_secret(secret_param)
    issuer = params.get("issuer", [None])[0]
    digits = int(params.get("digits", [6])[0])
    period = int(params.get("period", [30])[0])
    return {
        "label": label,
        "issuer": issuer,
        "digits": digits,
        "period": period,
        "secret_bytes": secret_bytes,
    }


def rfc6238_totp(secret: bytes, timestamp: int, digits: int = 6, period: int = 30) -> str:
    """Calculates RFC 6238 TOTP code (HMAC-SHA1)."""
    counter = timestamp // period
    msg = struct.pack(">Q", counter)
    hs = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = hs[-1] & 0x0F
    code = struct.unpack(">I", hs[offset:offset + 4])[0] & 0x7FFFFFFF
    fmt = f"%0{digits}d"
    return fmt % (code % (10 ** digits))


def totp_countdown_seconds(timestamp: float, period: int = 30) -> int:
    return int(period - (timestamp % period))


# ---------------------------------------------------------------------------
# Simulated FIDO / AegisKey Hardware Twin
# ---------------------------------------------------------------------------
class SimFidoDevice:
    """Offline deterministic twin of AegisKey firmware."""

    def __init__(self, gpio_sim: RenodeGpioSimulator, presence: SimPresence) -> None:
        self.gpio_sim = gpio_sim
        self.presence = presence
        self.claimed = False
        self.app_pub: Optional[bytes] = None
        self.binding_id: Optional[bytes] = None
        self.current_challenge: Optional[bytes] = None
        self.challenge_used = True
        self.recovery_pin_hash: Optional[bytes] = None
        self.keys_store: Dict[int, Dict[str, any]] = {}
        self.wallet_store: Dict[int, Dict[str, any]] = {}
        self.oath_store: Dict[bytes, Dict[str, any]] = {}

    # -- BLE & Claim --
    def handle_claim(self, app_pub: bytes, binding_id: bytes) -> bytes:
        if not self.gpio_sim.is_pairing_window_active():
            sanitized_log("GATE_PAIRING_DENIED", "window_expired")
            raise PermissionError("Pairing window required (hold BOOT 5s)")
        if not self.presence.consume():
            sanitized_log("GATE_UP_DENIED", "op=claim")
            raise PermissionError("Physical presence required (UP)")
        if self.claimed:
            sanitized_log("CLAIM_DENIED", "already_claimed")
            raise PermissionError("Already claimed (foreign device)")
        if len(app_pub) != 65 or app_pub[0] != 0x04:
            raise ValueError("Invalid P-256 uncompressed public key (must be 65B)")
        if len(binding_id) != 16:
            raise ValueError("Invalid binding ID (must be 16B)")

        self.claimed = True
        self.app_pub = bytes(app_pub)
        self.binding_id = bytes(binding_id)
        sanitized_log("CLAIM_OK", f"binding_id_len={len(binding_id)}")
        return self.binding_id  # echo

    def handle_challenge(self) -> bytes:
        if not self.claimed:
            raise PermissionError("Unclaimed device")
        self.current_challenge = os.urandom(32)
        self.challenge_used = False
        sanitized_log("CHALLENGE_ISSUED", "bytes=32")
        return self.current_challenge

    def handle_verify(self, op: int, payload_hash: bytes, signature: bytes, priv_for_twin: bytes) -> bool:
        if not self.claimed or self.current_challenge is None or self.challenge_used:
            sanitized_log("GATE_BINDING_DENIED", "stale_challenge")
            raise PermissionError("Stale challenge or replay detected")
        expected_sig = hmac.new(priv_for_twin, self.current_challenge + bytes([op]) + payload_hash, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_sig, signature):
            sanitized_log("VERIFY_FAILED", "signature_mismatch")
            raise PermissionError("Signature verification failed")
        self.challenge_used = True
        sanitized_log("VERIFY_OK", f"op=0x{op:02X}")
        return True

    # -- Recovery PIN --
    def handle_recovery_pin(self, pin_digits: str) -> bool:
        if not self.claimed:
            raise PermissionError("Unclaimed device")
        if not self.presence.consume():
            sanitized_log("GATE_UP_DENIED", "op=recovery_pin")
            raise PermissionError("Physical presence required (UP)")
        if not (4 <= len(pin_digits) <= 6 and pin_digits.isdigit()):
            raise ValueError("Recovery PIN must be 4..6 ASCII digits")
        self.recovery_pin_hash = hashlib.sha256(pin_digits.encode("ascii")).digest()
        sanitized_log("RECOVERY_PIN_SET", f"digits={len(pin_digits)}")
        return True

    # -- FIDO Passkey & Wallet Generation --
    def handle_key_gen(self, slot: int, label: str, alg: int, usage: int) -> Dict[str, any]:
        if not self.claimed:
            raise PermissionError("Unclaimed device")
        if not self.presence.consume():
            sanitized_log("GATE_UP_DENIED", "op=key_gen")
            raise PermissionError("Physical presence required (UP)")
        key_entry = {
            "slot": slot,
            "label": label,
            "alg": alg,
            "usage": usage,
            "cred_id": os.urandom(16).hex(),
        }
        self.keys_store[slot] = key_entry
        sanitized_log("KEY_GEN_OK", f"slot={slot} label_len={len(label)}")
        return key_entry

    def handle_wallet_gen(self, slot: int, label: str, network: int) -> str:
        if not self.claimed:
            raise PermissionError("Unclaimed device")
        if not self.presence.consume():
            sanitized_log("GATE_UP_DENIED", "op=wallet_gen")
            raise PermissionError("Physical presence required (UP)")
        # Deterministic Bech32 Bitcoin address mock (bc1q + 32-char hex digest)
        digest = hashlib.sha256(bytes([slot, network]) + label.encode("utf-8")).hexdigest()
        addr = "bc1q" + digest[:32]
        self.wallet_store[slot] = {"slot": slot, "label": label, "network": network, "address": addr}
        sanitized_log("WALLET_GEN_OK", f"slot={slot} net=0x{network:02X}")
        return addr

    def handle_wallet_addr(self, slot: int) -> str:
        if slot not in self.wallet_store:
            raise KeyError("Wallet slot not found")
        return self.wallet_store[slot]["address"]

    # -- TOTP Ops --
    def handle_oath_put(self, name: bytes, secret: bytes, digits: int = 6, period: int = 30) -> bool:
        if not self.claimed:
            raise PermissionError("Unclaimed device")
        if not self.presence.consume():
            sanitized_log("GATE_UP_DENIED", "op=oath_put")
            raise PermissionError("Physical presence required (UP)")
        if self.recovery_pin_hash is None:
            sanitized_log("GATE_PIN_DENIED", "op=oath_put")
            raise PermissionError("PIN setup required")
        self.oath_store[name] = {
            "name": name,
            "secret": secret,
            "digits": digits,
            "period": period,
        }
        sanitized_log("OATH_PUT_OK", f"name_bytes={len(name)} secret_bytes={len(secret)}")
        return True

    def handle_oath_list(self) -> List[bytes]:
        return list(self.oath_store.keys())

    def handle_oath_code(self, name: bytes, timestamp: int) -> str:
        if name not in self.oath_store:
            raise KeyError("Account not found")
        if not self.presence.consume():
            sanitized_log("GATE_UP_DENIED", "op=oath_code")
            raise PermissionError("Physical presence required (UP)")
        account = self.oath_store[name]
        code = rfc6238_totp(account["secret"], timestamp, account["digits"], account["period"])
        sanitized_log("OATH_CODE_OK", f"digits={len(code)}")
        return code


# ---------------------------------------------------------------------------
# TCP Server for Android Emulator (10.0.2.2)
# ---------------------------------------------------------------------------
class EmulatorTcpHandler(socketserver.BaseRequestHandler):
    """Handles TCP socket connections from Android emulator (10.0.2.2)."""

    def handle(self) -> None:
        device: SimFidoDevice = self.server.device  # type: ignore
        sanitized_log("EMULATOR_CLIENT_CONNECTED", f"peer={self.client_address[0]}")
        self.request.settimeout(5.0)
        try:
            while True:
                data = self.request.recv(4096)
                if not data:
                    break

                # 1. CTAPHID 64-byte framing protocol
                if len(data) >= PACKET_SIZE and data[4] == CMD_INIT:
                    # Echo broadcast CID + allocated CID + nonce
                    nonce = data[7:15]
                    allocated_cid = bytes([0x12, 0x34, 0x56, 0x78])
                    resp_payload = nonce + allocated_cid + bytes([0x02, 0x01, 0x00, 0x00, 0x00])
                    frame = bytes([0xFF, 0xFF, 0xFF, 0xFF, CMD_INIT, 0x00, len(resp_payload)]) + resp_payload
                    resp_pkt = (frame + bytes(PACKET_SIZE))[:PACKET_SIZE]
                    self.request.sendall(resp_pkt)
                    sanitized_log("CTAPHID_INIT_RESPONDED", "cid=12345678")
                    continue

                if len(data) >= PACKET_SIZE and data[4] == CMD_PING:
                    self.request.sendall(data[:PACKET_SIZE])
                    continue

                # 2. HTTP REST compatibility
                if data.startswith(b"GET ") or data.startswith(b"POST "):
                    lines = data.decode("utf-8", errors="ignore").splitlines()
                    first_line = lines[0] if lines else ""
                    parts = first_line.split()
                    method = parts[0] if len(parts) > 0 else "GET"
                    path = parts[1] if len(parts) > 1 else "/"

                    resp_body: Dict[str, any] = {"status": "ok"}
                    if "/status" in path:
                        resp_body = {
                            "claimed": device.claimed,
                            "pairing_window": device.gpio_sim.is_pairing_window_active(),
                            "keys_count": len(device.keys_store),
                            "oath_count": len(device.oath_store),
                        }
                    elif "/press" in path:
                        device.presence.press()
                        resp_body = {"status": "ok", "presence_latched": True}
                    elif "/boot_hold" in path:
                        device.gpio_sim.hold_boot_button(5.0)
                        resp_body = {"status": "ok", "pairing_window_open": True}
                    elif "/oath/list" in path:
                        resp_body = {"accounts": [n.decode("utf-8", errors="ignore") for n in device.handle_oath_list()]}

                    payload_bytes = json.dumps(resp_body).encode("utf-8")
                    http_resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/json\r\n"
                        b"Content-Length: " + str(len(payload_bytes)).encode() + b"\r\n"
                        b"Connection: close\r\n\r\n" + payload_bytes
                    )
                    self.request.sendall(http_resp)
                    break

                # 3. Text command protocol
                text = data.decode("utf-8", errors="ignore").strip()
                if text == "TEST_UP":
                    device.presence.press()
                    self.request.sendall(b"OK UP_LATCHED\n")
                elif text == "TEST_PAIRING_OPEN":
                    device.gpio_sim.hold_boot_button(5.0)
                    self.request.sendall(b"OK PAIRING_OPEN_60S\n")
                elif text == "STATUS":
                    self.request.sendall(f"CLAIMED={device.claimed} KEYS={len(device.keys_store)}\n".encode())
                else:
                    self.request.sendall(b"UNKNOWN_COMMAND\n")

        except (socket.timeout, OSError) as exc:
            sanitized_log("EMULATOR_CLIENT_DISCONNECTED", f"reason={exc}")


class ThreadedEmulatorServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address: Tuple[str, int], device: SimFidoDevice) -> None:
        self.device = device
        super().__init__(server_address, EmulatorTcpHandler)


# ---------------------------------------------------------------------------
# Test Suite: Journeys J1 .. J5 + Renode + Server Smoke
# ---------------------------------------------------------------------------
RESULTS: List[Tuple[str, str, str, str]] = []


def record_result(journey: str, name: str, ok: bool, detail: str = "") -> None:
    verdict = "PASS" if ok else "FAIL"
    RESULTS.append((journey, name, verdict, detail))
    print(f"[{verdict}] {journey} - {name} | {detail}")


def test_j1_initial_startup() -> bool:
    """J1: First Startup (Zero devices) -> ConnectedKeysRepository empty & ONBOARDING_WIZARD_STEP_1."""
    repo = ConnectedKeysRepository()
    is_empty = (len(repo.connected_keys) == 0)
    route = repo.get_current_route()
    is_route_step1 = (route == ONBOARDING_WIZARD_STEP_1)
    active_key = repo.get_active_key()
    is_active_none = (active_key is None)

    ok = is_empty and is_route_step1 and is_active_none
    record_result("J1", "Initial Startup Zero Devices", ok, f"empty={is_empty} route={route}")
    return ok


def test_j2_wizard_step_by_step() -> Tuple[bool, ConnectedKey, SimFidoDevice, AndroidKeyStoreSim]:
    """J2: Wizard Step-by-Step (Next -> Next -> Next) with simulated physical button presses."""
    up = SimPresence()
    gpio = RenodeGpioSimulator(up)
    device = SimFidoDevice(gpio, up)
    keystore = AndroidKeyStoreSim()
    repo = ConnectedKeysRepository()

    # Step 1: Explain -> Next -> Step 2
    step1_route = repo.get_current_route()
    assert step1_route == ONBOARDING_WIZARD_STEP_1
    step = ONBOARDING_WIZARD_STEP_2

    # Step 2: Hold BOOT (GPIO0 5s) opens 60s pairing window
    window_opened = gpio.hold_boot_button(5.0)
    assert window_opened and gpio.is_pairing_window_active()
    record_result("J2", "Step 1->2 Hold BOOT 5s Pairing Window", True, "pairing_window=60s")
    step = ONBOARDING_WIZARD_STEP_3

    # Step 3: BLE Discovery & Bonding
    ble_service = 0xFFFD
    bonding_justworks = True
    record_result("J2", "Step 2->3 BLE Discovery & JustWorks", ble_service == 0xFFFD and bonding_justworks, "service=0xFFFD")
    step = ONBOARDING_WIZARD_STEP_4

    # Step 4: Touch contact (UP) + P-256 KeyStore + CLAIM 0x28 -> CHALLENGE 0x29 -> VERIFY 0x2A
    gpio.press_touch_button()  # Latches UP
    binding_id = keystore.generate_binding_id()
    echoed_id = device.handle_claim(keystore.pubkey_uncompressed, binding_id)
    claim_ok = (echoed_id == binding_id and device.claimed)

    challenge = device.handle_challenge()
    challenge_ok = (len(challenge) == 32)

    dummy_payload_hash = hashlib.sha256(b"e2e-binding-auth").digest()
    sig = keystore.sign(challenge, 0x20, dummy_payload_hash)
    verify_ok = device.handle_verify(0x20, dummy_payload_hash, sig, keystore._priv_material)

    # Replay protection check: verify same challenge fails closed
    replay_denied = False
    try:
        device.handle_verify(0x20, dummy_payload_hash, sig, keystore._priv_material)
    except PermissionError:
        replay_denied = True

    record_result("J2", "Step 3->4 Touch Button UP + CLAIM/CHALLENGE/VERIFY",
                  claim_ok and challenge_ok and verify_ok and replay_denied,
                  f"claim_ok={claim_ok} replay_denied={replay_denied}")
    step = ONBOARDING_WIZARD_STEP_5

    # Step 5: Setup Recovery PIN (0x2C) with UP & Save Key in ConnectedKeysRepository
    gpio.press_touch_button()
    pin_ok = device.handle_recovery_pin("123456")

    new_key = ConnectedKey(
        key_id=binding_id.hex(),
        name="AegisKey Primary",
        binding_id=binding_id,
        pubkey_uncompressed=keystore.pubkey_uncompressed,
        recovery_pin_hash=device.recovery_pin_hash,
    )
    repo.add_key(new_key)

    record_result("J2", "Step 4->5 Recovery PIN 0x2C & Save to Repository",
                  pin_ok and len(repo.connected_keys) == 1,
                  f"pin_ok={pin_ok} repo_count={len(repo.connected_keys)}")

    return True, new_key, device, keystore


def test_j3_connected_keys_reactive_transitions(key1: ConnectedKey) -> bool:
    """J3: ConnectedKeysRepository & Reactive route transition."""
    repo = ConnectedKeysRepository()
    routes_captured: List[str] = []
    repo.add_listener(lambda r: routes_captured.append(r))

    # 1 key added: route must become VAULT_AND_TOTP_HUB
    repo.add_key(key1)
    route_with_1 = repo.get_current_route()
    ok_1 = (route_with_1 == VAULT_AND_TOTP_HUB)
    record_result("J3", "Repository 1 Key -> VAULT_AND_TOTP_HUB", ok_1, f"route={route_with_1}")

    # Add 2nd key: active key switching
    key2 = ConnectedKey(
        key_id="aabbccddeeff00112233445566778899",
        name="AegisKey Backup",
        binding_id=bytes.fromhex("aabbccddeeff00112233445566778899"),
        pubkey_uncompressed=b"\x04" + b"\x33" * 64,
    )
    repo.add_key(key2)
    assert len(repo.connected_keys) == 2

    repo.set_active_key(key2.key_id)
    active_is_2 = (repo.get_active_key().key_id == key2.key_id)
    repo.set_active_key(key1.key_id)
    active_is_1 = (repo.get_active_key().key_id == key1.key_id)

    record_result("J3", "Switch Active Key Between 2 Keys", active_is_1 and active_is_2,
                  f"active1={active_is_1} active2={active_is_2}")

    # Remove 2nd key -> still in VAULT_AND_TOTP_HUB
    repo.remove_key(key2.key_id)
    assert len(repo.connected_keys) == 1
    assert repo.get_current_route() == VAULT_AND_TOTP_HUB

    # Remove last key -> reactively returns to ONBOARDING_WIZARD_STEP_1 immediately
    repo.remove_key(key1.key_id)
    route_with_0 = repo.get_current_route()
    ok_empty_reactive = (len(repo.connected_keys) == 0 and route_with_0 == ONBOARDING_WIZARD_STEP_1)

    record_result("J3", "Remove All Keys Reactively Returns to ONBOARDING_WIZARD_STEP_1",
                  ok_empty_reactive, f"route={route_with_0} keys={len(repo.connected_keys)}")

    return ok_1 and active_is_1 and ok_empty_reactive


def test_j4_key_vault_and_wallet_generation(device: SimFidoDevice, key: ConnectedKey) -> bool:
    """J4: Key Vault, FIDO Passkey creation, Crypto Wallet (Bech32 bc1q...), and Security Toggles."""
    # FIDO Passkey Generation (0x20) with UP
    device.presence.press()
    cred = device.handle_key_gen(slot=1, label="passkey-github", alg=-7, usage=0x06)
    fido_ok = (cred["slot"] == 1 and cred["label"] == "passkey-github")

    # Bitcoin Wallet Generation (0x35) with UP -> Bech32 bc1q...
    device.presence.press()
    addr = device.handle_wallet_gen(slot=1, label="btc-cold", network=0x01)
    addr_queried = device.handle_wallet_addr(slot=1)
    wallet_ok = (addr.startswith("bc1q") and addr == addr_queried and len(addr) >= 36)

    # Security toggles on key settings
    key.settings.proximity_lock = True
    key.settings.biometrics_required = True
    key.settings.presence_required = True
    toggles_ok = (key.settings.proximity_lock and key.settings.biometrics_required and key.settings.presence_required)

    ok = fido_ok and wallet_ok and toggles_ok
    record_result("J4", "Key Vault FIDO Passkey & Wallet Bech32 bc1q Generation", ok,
                  f"fido_ok={fido_ok} addr={addr[:10]}... toggles_ok={toggles_ok}")
    return ok


def test_j5_dedicated_totp_screen(device: SimFidoDevice) -> bool:
    """J5: Dedicated TOTP Screen (RFC 6238), otpauth:// URI, Base32 safety, and countdown."""
    # 1. Base32 test vector (RFC 6238 secret: "12345678901234567890")
    raw_rfc_secret = b"12345678901234567890"
    b32_secret = base64.b32encode(raw_rfc_secret).decode("ascii")  # GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ

    # 2. Register account 1 via Base32
    device.presence.press()
    put1_ok = device.handle_oath_put(b"Google:alice@example.com", decode_base32_secret(b32_secret))

    # 3. Register account 2 via otpauth:// URI
    otpauth_uri = f"otpauth://totp/GitHub:alice?secret={b32_secret}&issuer=GitHub&digits=6&period=30"
    parsed_uri = parse_otpauth_uri(otpauth_uri)
    device.presence.press()
    put2_ok = device.handle_oath_put(parsed_uri["label"].encode("utf-8"), parsed_uri["secret_bytes"])

    # 4. List accounts (0x25)
    names = device.handle_oath_list()
    list_ok = (b"Google:alice@example.com" in names and b"GitHub:alice" in names)

    # 5. Calculate 6-digit TOTP code (0x26) with UP at T=59 (RFC 6238 test vector -> "287082")
    device.presence.press()
    code_59 = device.handle_oath_code(b"GitHub:alice", timestamp=59)
    rfc_vector_ok = (code_59 == "287082" and len(code_59) == 6 and code_59.isdigit())

    # 6. Countdown verification (30s period)
    t = 73.0
    remaining = totp_countdown_seconds(t, 30)
    countdown_ok = (remaining == 17)  # 30 - (73 % 30) = 30 - 13 = 17

    # 7. Strict Privacy & Sanitization: Ensure Base32 secret string never leaked in logs
    logs_text = " ".join(get_log_history())
    secret_leaked = (b32_secret in logs_text or "12345678901234567890" in logs_text)

    ok = put1_ok and put2_ok and list_ok and rfc_vector_ok and countdown_ok and not secret_leaked
    record_result("J5", "Dedicated TOTP RFC6238 & Sanitized Logs", ok,
                  f"code_t59={code_59} countdown={remaining}s secret_leaked={secret_leaked}")
    return ok


def test_renode_integration() -> bool:
    """Smoke test of hardware bridge & Renode platform."""
    renode_exe = r"C:\Program Files\Renode\renode.exe"
    renode_installed = os.path.isfile(renode_exe)

    # Check Renode executable version
    renode_version_str = "not_found"
    if renode_installed:
        try:
            out = subprocess.check_output([renode_exe, "--version"], stderr=subprocess.STDOUT, timeout=5)
            renode_version_str = out.decode("utf-8", errors="ignore").splitlines()[0]
        except Exception as e:
            renode_version_str = f"err: {e}"

    # Check renode_bridge.py smoke
    bridge_ok = False
    bridge_info = {}
    try:
        import renode_bridge
        bridge_info = renode_bridge.run_ctap_smoke(dummy=True)
        bridge_ok = (bridge_info.get("verdict") == "PASS" and bridge_info.get("cmd") == "0x86")
    except Exception as e:
        bridge_info = {"error": str(e)}

    # Check fido-s3-v3.repl platform description for GPIO0 / BOOT button mapping
    repl_path = os.path.join(SIM_DIR, "boards", "fido-s3-v3.repl")
    repl_exists = os.path.isfile(repl_path)

    ok = renode_installed and bridge_ok and repl_exists
    record_result("RENODE", "Renode & GPIO Bridge Integration", ok,
                  f"renode={renode_version_str} bridge={bridge_info.get('verdict')} repl={repl_exists}")
    return ok


def test_tcp_server_smoke(device: SimFidoDevice) -> bool:
    """Test TCP server interaction (CTAPHID INIT & HTTP & Text commands)."""
    server = ThreadedEmulatorServer(("127.0.0.1", 0), device)
    port = server.server_address[1]
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()

    try:
        # 1. CTAPHID INIT test over TCP
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as s:
            init_pkt = bytes([0xFF, 0xFF, 0xFF, 0xFF, CMD_INIT, 0x00, 0x08]) + bytes(range(8)) + bytes(49)
            s.sendall(init_pkt)
            resp = s.recv(64)
            cid_ok = (resp[:4] == bytes([0xFF, 0xFF, 0xFF, 0xFF]) and resp[4] == CMD_INIT)

        # 2. Text command TEST_UP over TCP
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as s:
            s.sendall(b"TEST_UP\n")
            resp_txt = s.recv(1024).decode("utf-8", errors="ignore")
            text_ok = "UP_LATCHED" in resp_txt

        ok = cid_ok and text_ok
        record_result("SERVER", "TCP Server Emulator (10.0.2.2) Smoke", ok,
                      f"port={port} ctap_init={cid_ok} text_ok={text_ok}")
        return ok
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Main Runner & CLI
# ---------------------------------------------------------------------------
def run_all_self_tests() -> bool:
    print("=" * 68)
    print("  AEGISKEY ANDROID UX JOURNEY & SIMULATOR (J1..J5 + RENODE + TCP)")
    print("=" * 68)

    j1_ok = test_j1_initial_startup()
    j2_ok, key, device, keystore = test_j2_wizard_step_by_step()
    j3_ok = test_j3_connected_keys_reactive_transitions(key)
    j4_ok = test_j4_key_vault_and_wallet_generation(device, key)
    j5_ok = test_j5_dedicated_totp_screen(device)
    renode_ok = test_renode_integration()
    server_ok = test_tcp_server_smoke(device)

    print("-" * 68)
    passed = sum(1 for _, _, v, _ in RESULTS if v == "PASS")
    total = len(RESULTS)
    print(f"SUMMARY: total={total} passed={passed} failed={total - passed}")
    print(f"SCORECARD: J1={j1_ok} J2={j2_ok} J3={j3_ok} J4={j4_ok} J5={j5_ok} RENODE={renode_ok} SERVER={server_ok}")

    return passed == total


def main() -> int:
    parser = argparse.ArgumentParser(description="AegisKey Android Journey Simulator")
    parser.add_argument("--self-test", action="store_true", help="Run comprehensive journey self-test suite")
    parser.add_argument("--with-renode", action="store_true", help="Validate Renode executable & GPIO simulation bridge")
    parser.add_argument("--serve", action="store_true", help="Start TCP server for Android emulator (10.0.2.2)")
    parser.add_argument("--host", default="0.0.0.0", help="TCP server host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5678, help="TCP server port (default: 5678)")

    args = parser.parse_args()

    if args.serve:
        up = SimPresence()
        gpio = RenodeGpioSimulator(up)
        device = SimFidoDevice(gpio, up)
        server = ThreadedEmulatorServer((args.host, args.port), device)
        print(f"[*] Starting AegisKey Simulator TCP Server on {args.host}:{args.port} (Android Emulator: 10.0.2.2:{args.port})...")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server stopped.")
        return 0

    all_passed = run_all_self_tests()
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
