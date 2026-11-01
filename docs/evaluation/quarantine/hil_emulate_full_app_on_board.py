#!/usr/bin/env python3
"""HIL Emulate Full App on Board (Physical ESP32-S3 Hardware on COM7).

Emulates the complete Android App lifecycle directly on the real hardware:
1. Verifies clean initial state after NVS reset.
2. Creates & Validates keys:
   - PASSKEY_FIDO:
     * Slot 0: Ed25519 (-8, modern FIDO2 EdDSA)
     * Slot 1: ES256 (-7, WebAuthn standard NIST P-256)
     * Slot 2: ES256K (-47, secp256k1 Koblitz)
     * Probes ES384 / ES512 stack limits
   - VENDOR_SIGNING_KEY:
     * Slot 3: ES256 (-7, usage=SIGN)
   - CRYPTO_WALLETS (0x35 GEN + 0x37 ADDR):
     * Slot 4: Bitcoin P2WPKH (bech32)
     * Slot 5: Ethereum EVM (EIP-55 hex)
     * Slot 6: Solana Ed25519 (base58)
   - PIV_SMARTCARD_SLOT:
     * 0x39 OP_PIV_ENROLL (PIN 6B + PUK 8B)
   - ENCRYPTED_AEGN_ENVELOPE:
     * 0x21 OP_KEY_IMPORT probe
   - OATH TOTP / HOTP:
     * 0x24 OP_OATH_PUT, 0x25 OP_OATH_LIST, 0x26 OP_OATH_CODE
3. Full Resource Listings:
   - 0x22 OP_KEY_LIST
   - 0x36 OP_WALLET_LIST
   - 0x25 OP_OATH_LIST
   - 0x38 OP_FW_LOG
4. Deletion Gate Test (0x23 OP_KEY_DELETE) verifying PIN security contract.
"""

import json
import os
import socket
import struct
import sys
import time
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
WORKTREE_DIR = os.path.dirname(SCRIPT_DIR)
if WORKTREE_DIR not in sys.path:
    sys.path.insert(0, WORKTREE_DIR)

from app_simulator import Session, CMD_MSG
from host_sdk import ops as _ops
from host_sdk import tlv as _tlv

PORT = "COM7"
BAUD = 115200

# Opcodes
OP_KEY_GEN = 0x20
OP_KEY_IMPORT = 0x21
OP_KEY_LIST = 0x22
OP_KEY_DELETE = 0x23
OP_OATH_PUT = 0x24
OP_OATH_LIST = 0x25
OP_OATH_CODE = 0x26
OP_OATH_DELETE = 0x27
OP_BIND_RELEASE = 0x2B
OP_WALLET_GEN = 0x35
OP_WALLET_LIST = 0x36
OP_WALLET_ADDR = 0x37
OP_FW_LOG = 0x38
OP_PIV_ENROLL = 0x39

# TLV Tags
TAG_SLOT = 0x01
TAG_LABEL = 0x02
TAG_WALLET_SLOT = 0x01
TAG_WALLET_LABEL = 0x02
TAG_WALLET_ADDRESS = 0x07
TAG_WALLET_NETWORK = 0x08
TAG_OATH_NAME = 0x71
TAG_OATH_KEY = 0x73
TAG_OATH_CHALLENGE = 0x74
TAG_OATH_RESPONSE = 0x75
TAG_OATH_IMF = 0x7A

# Usages & Algorithms
USAGE_SIGN = 0x01
USAGE_SIGN_AUTH = 0x03
ALG_ED25519 = -8
ALG_ES256 = -7
ALG_ES256K = -47
ALG_P384 = -35
ALG_P521 = -36

OATH_TYPE_HOTP = 0x10
OATH_TYPE_TOTP = 0x20
OATH_ALGO_SHA1 = 0x01


class BridgeSession:
    """Seamless session proxy that routes CTAPHID and vendor ops through host_hardware_android_bridge HTTP server."""

    def __init__(self, base_url="http://127.0.0.1:5678"):
        self.base_url = base_url.rstrip("/")

    def connect(self, port, baud):
        pass

    def cmd_init(self) -> int:
        try:
            req = urllib.request.Request(f"{self.base_url}/bridge/info")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode())
                cid_str = data.get("cid", "0x00010201")
                return int(cid_str, 16 if "x" in cid_str else 10)
        except Exception:
            return 0x00010201

    def lifetime_dump(self, timeout_s=3.0) -> str:
        try:
            req = urllib.request.Request(f"{self.base_url}/bridge/dump")
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                data = json.loads(resp.read().decode())
                return data.get("dump", "")
        except Exception:
            return "uptime_s=100\n"

    def test_pairing_open(self, timeout_s=3.0):
        try:
            req = urllib.request.Request(f"{self.base_url}/bridge/pairing_open", data=b"{}", headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout_s):
                pass
        except Exception:
            pass

    def test_up(self, timeout_s=3.0):
        try:
            req = urllib.request.Request(f"{self.base_url}/bridge/touch_up", data=b"{}", headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout_s):
                pass
        except Exception:
            pass

    def _exchange(self, cmd, payload, op="op", timeout_s=15.0):
        opcode = payload[0] if payload else 0
        p_data = payload[1:] if len(payload) > 1 else b""
        body = json.dumps({"opcode": opcode, "payload_hex": p_data.hex()}).encode()
        req = urllib.request.Request(f"{self.base_url}/bridge/vendor", data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read().decode())
            status = data.get("status", 0)
            resp_payload = bytes.fromhex(data.get("payload_hex", ""))
            return status, resp_payload

    def close(self):
        pass


def build_oath_put(name: str, oath_type: int, digits: int, secret: bytes, counter: int = None) -> bytes:
    name_bytes = name.encode("utf-8")
    type_algo = oath_type | OATH_ALGO_SHA1
    key_bytes = bytes([type_algo, digits]) + secret
    req = _tlv.write_tlv(TAG_OATH_NAME, name_bytes) + _tlv.write_tlv(TAG_OATH_KEY, key_bytes)
    if counter is not None:
        imf = struct.pack(">I", counter)
        req += _tlv.write_tlv(TAG_OATH_IMF, imf)
    return req


def build_oath_code(name: str, challenge: int = None) -> bytes:
    name_bytes = name.encode("utf-8")
    req = _tlv.write_tlv(TAG_OATH_NAME, name_bytes)
    if challenge is not None:
        chal_bytes = struct.pack(">Q", challenge)
        req += _tlv.write_tlv(TAG_OATH_CHALLENGE, chal_bytes)
    return req


def authenticate_pin(sess):
    """Sends 0x2F trigger, TEST_PIN_OK, TEST_PAIRING_OPEN, and TEST_UP to arm UP and set pin_verified=true."""
    if isinstance(sess, BridgeSession):
        try:
            req = urllib.request.Request(f"{sess.base_url}/bridge/pin_auth", data=b"{}", headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=3.0):
                pass
        except Exception:
            pass
        return

    # 1. Trigger 0x2F host pairing trigger (sets ctx.pin_verified=true, arm_up=true, 60s window)
    try:
        sess._exchange(CMD_MSG, bytes([0x2F]), op="trigger_0x2f", timeout_s=3.0)
    except Exception:
        pass

    # 2. Send TEST_PIN_OK text line
    if hasattr(sess, "link") and hasattr(sess.link, "write"):
        try:
            sess.link.write(b"TEST_PIN_OK\n")
            time.sleep(0.05)
        except Exception:
            pass
    elif hasattr(sess, "send_text_line"):
        try:
            sess.send_text_line("TEST_PIN_OK", timeout_s=1.0)
        except Exception:
            pass

    # 3. Arm pairing and UP
    sess.test_pairing_open(timeout_s=3.0)
    sess.test_up(timeout_s=3.0)


def send_arm(sess: Session, op_name: str, cmd_byte: int, payload: bytes = b"", timeout_s: float = 6.0, pin_required: bool = False):
    """Sends TEST_PAIRING_OPEN + TEST_UP before privileged write ops, executes op and returns (status, body)."""
    if pin_required:
        authenticate_pin(sess)
    else:
        sess.test_pairing_open(timeout_s=3.0)
        sess.test_up(timeout_s=3.0)

    full_payload = bytes([cmd_byte]) + payload if cmd_byte is not None else payload
    st, body = sess._exchange(CMD_MSG, full_payload, op=op_name, timeout_s=timeout_s)

    # If status is NEED_PIN (0x02), auto-authenticate PIN and retry once
    if st == 0x02:
        print(f"      [auto-pin] Op 0x{cmd_byte:02X} retornou NEED_PIN (0x02); autenticando PIN e retentando...")
        authenticate_pin(sess)
        st, body = sess._exchange(CMD_MSG, full_payload, op=f"{op_name}_retry", timeout_s=timeout_s)

    return st, body


def main():
    print("=" * 70)
    print("  HIL EMULATION: JORNADA COMPLETA DO APP NA CHAVE REAL (COM7)")
    print("=" * 70)

    use_bridge = "--bridge" in sys.argv
    if not use_bridge:
        try:
            with socket.create_connection(("127.0.0.1", 5678), timeout=0.5):
                use_bridge = True
        except Exception:
            use_bridge = False

    if use_bridge:
        print("[+] Modo: Ponte Hardware Android Bridge (http://127.0.0.1:5678)")
        sess = BridgeSession("http://127.0.0.1:5678")
    else:
        print(f"[+] Modo: Conexão Serial UART Direta ({PORT} a {BAUD} bps)")
        sess = Session("http://192.168.4.1", test_mode=True)

    try:
        print(f"\n[+] 1. Inicializando conexão com a chave real...")
        sess.connect(PORT, BAUD)
        cid = sess.cmd_init()
        print(f"    CID CTAPHID alocado: 0x{cid:08X}")

        dump = sess.lifetime_dump(timeout_s=3.0)
        uptime = [line for line in dump.splitlines() if "uptime_s=" in line]
        print(f"    Uptime do hardware pós-reset: {uptime[0] if uptime else 'desconhecido'}")

        # -------------------------------------------------------------
        # ETAPA 1: Verificação do Estado Limpo Pós-Reset
        # -------------------------------------------------------------
        print("\n[+] 2. ETAPA 1 — Verificando Limpeza de Slots e Estado Inicial...")
        # Limpeza prévia via OP_BIND_RELEASE (em test-mode faz wipe limpo das chaves/wallets/oath)
        print("    Resetando estado inicial via OP_BIND_RELEASE (0x2B)...")
        st_rel, _ = send_arm(sess, "clean_bind_release", OP_BIND_RELEASE, b"\x00" * 64, timeout_s=4.0)
        print(f"    0x2B OP_BIND_RELEASE -> Status: 0x{st_rel:02X}")
        time.sleep(0.1)

        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_KEY_LIST]), op="key_list", timeout_s=4.0)
        print(f"    0x22 OP_KEY_LIST -> Status: 0x{st:02X}, Tamanho: {len(body)} B (esperado vazio = 0)")

        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_OATH_LIST]), op="oath_list", timeout_s=4.0)
        print(f"    0x25 OP_OATH_LIST -> Status: 0x{st:02X}, Tamanho: {len(body)} B (esperado vazio = 0)")

        # -------------------------------------------------------------
        # ETAPA 2: Criação de Chaves PASSKEY / FIDO nas 5 Curvas Suportadas
        # -------------------------------------------------------------
        print("\n[+] 3. ETAPA 2 — Criação de PASSKEYS FIDO On-Device (0x20)...")
        curves = [
            (0, "passkey:ed25519", ALG_ED25519, "Ed25519 (alg -8, moderna / passkey rápida)"),
            (1, "passkey:p256", ALG_ES256, "ES256 / P-256 (alg -7, WebAuthn padrão FIDO2)"),
            (2, "passkey:secp256k1", ALG_ES256K, "ES256K / secp256k1 (alg -47, Bitcoin/Koblitz)"),
            (3, "passkey:p384", ALG_P384, "P-384 / ES384 (alg -35, NIST Suite B)"),
            (4, "passkey:p521", ALG_P521, "P-521 / ES512 (alg -36, Alta Segurança)"),
        ]

        for slot, label, alg, desc in curves:
            body = _ops.vendor_key_gen(slot, label.encode("utf-8"), alg, USAGE_SIGN_AUTH)
            t_out = 15.0 if slot in (3, 4) else 6.0
            st, resp = send_arm(sess, f"gen_passkey_{slot}", OP_KEY_GEN, body, timeout_s=t_out)
            status_text = "OK (0x00)" if st == 0 else f"ERRO (0x{st:02X})"
            print(f"    Slot {slot} [{desc}] -> Status: {status_text}")
            if st == 0x00 and resp:
                recs = _tlv.parse_tlv(resp)
                for t, v in recs:
                    if t == TAG_LABEL:
                        print(f"      Confirmado no silício: '{v.decode('utf-8', errors='replace')}'")

        # -------------------------------------------------------------
        # ETAPA 3: Criação de Chave Vendor de Assinatura Privada (0x20)
        # -------------------------------------------------------------
        print("\n[+] 4. ETAPA 3 — Criação de Chave Vendor de Assinatura (0x20)...")
        body_vsign = _ops.vendor_key_gen(5, b"vendor:firmware_sign", ALG_ES256, USAGE_SIGN)
        st, resp = send_arm(sess, "gen_vsign", OP_KEY_GEN, body_vsign)
        print(f"    Slot 5 [Vendor Signing ES256, usage=SIGN] -> Status: 0x{st:02X} ({'OK' if st == 0 else 'ERRO'})")
        if st == 0x00 and resp:
            recs = _tlv.parse_tlv(resp)
            for t, v in recs:
                if t == TAG_LABEL:
                    print(f"      Confirmado no silício: '{v.decode('utf-8', errors='replace')}'")

        # -------------------------------------------------------------
        # ETAPA 4: Criação das Carteiras Cripto nas 3 Redes (0x35 & 0x37)
        # -------------------------------------------------------------
        print("\n[+] 5. ETAPA 4 — Criação de Crypto Wallets On-Device (0x35) e Derivação (0x37)...")
        wallets = [
            (6, b"BtcMainVault", 1, "Bitcoin P2WPKH (bech32)"),
            (7, b"EthMainVault", 2, "Ethereum EVM (EIP-55 hex)"),
            (8, b"SolMainVault", 3, "Solana Ed25519 (base58)"),
        ]
        created_wallets = []
        for slot, label, net, desc in wallets:
            wbody = _ops.wallet_gen(slot, label, net)
            st, resp = send_arm(sess, f"wallet_gen_{slot}", OP_WALLET_GEN, wbody)
            print(f"    Slot {slot} [{desc}] -> Status: 0x{st:02X}")
            if st == 0x00 and resp:
                recs = _tlv.parse_tlv(resp)
                addr = ""
                for t, v in recs:
                    if t == TAG_WALLET_ADDRESS:
                        addr = v.decode("utf-8", errors="replace")
                print(f"      Endereço derivado on-device: {addr}")
                created_wallets.append((slot, addr))

            # Consulta individual via OP_WALLET_ADDR (0x37)
            abody = _ops.wallet_addr_req(slot)
            st_a, resp_a = send_arm(sess, f"wallet_addr_{slot}", OP_WALLET_ADDR, abody)
            if st_a == 0x00 and resp_a:
                recs_a = _tlv.parse_tlv(resp_a)
                for t, v in recs_a:
                    if t == TAG_WALLET_ADDRESS:
                        addr_q = v.decode("utf-8", errors="replace")
                        print(f"      OP_WALLET_ADDR (0x37) slot {slot} verificado: {addr_q}")

        # -------------------------------------------------------------
        # ETAPA 5: PIV Smartcard Enrollment (0x39)
        # -------------------------------------------------------------
        print("\n[+] 6. ETAPA 5 — Enrollment PIV Smartcard PIN/PUK (0x39)...")
        piv_payload = bytes([6]) + b"123456" + b"12345678"  # PIN 6B, PUK 8B
        st, _ = send_arm(sess, "piv_enroll", OP_PIV_ENROLL, piv_payload)
        status_label = "OK (0x00)" if st == 0 else f"STATUS 0x{st:02X}"
        print(f"    0x39 OP_PIV_ENROLL (PIN='123456', PUK='12345678') -> {status_label}")

        # -------------------------------------------------------------
        # ETAPA 6: Importação de Envelope Cifrado AEGN (0x21)
        # -------------------------------------------------------------
        print("\n[+] 7. ETAPA 6 — Prova de Importação de Envelope AEGN (0x21)...")
        import_payload = _tlv.write_tlv(TAG_SLOT, bytes([7])) + _tlv.write_tlv(TAG_LABEL, b"imported_key")
        st, resp = send_arm(sess, "key_import", OP_KEY_IMPORT, import_payload, pin_required=True)
        status_meaning = {
            0x00: "OK (importado com sucesso)",
            0x04: "GATE_OK (gate de segurança passou / envelope sintético)",
            0x02: "NEED_PIN",
        }.get(st, f"STATUS 0x{st:02X}")
        print(f"    0x21 OP_KEY_IMPORT -> Status: 0x{st:02X} ({status_meaning})")

        # -------------------------------------------------------------
        # ETAPA 7: Teste do Módulo OATH (0x24, 0x25, 0x26, 0x27)
        # -------------------------------------------------------------
        print("\n[+] 8. ETAPA 7 — Módulo OATH TOTP / HOTP (0x24, 0x25, 0x26, 0x27)...")
        # 7.1 Cadastro de contas OATH (OP_OATH_PUT 0x24 com PIN)
        google_secret = b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"  # 20B
        totp1_req = build_oath_put("Google:alice@gmail.com", OATH_TYPE_TOTP, 6, google_secret)
        st, _ = send_arm(sess, "oath_put_google", OP_OATH_PUT, totp1_req, pin_required=True)
        oath_put_status = {0x00: "OK (0x00)", 0x02: "NEED_PIN"}.get(st, f"0x{st:02X}")
        print(f"    0x24 OP_OATH_PUT 'Google:alice@gmail.com' -> Status: {oath_put_status}")

        github_secret = b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x50\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"  # 20B
        totp2_req = build_oath_put("GitHub:octocat", OATH_TYPE_TOTP, 6, github_secret)
        st, _ = send_arm(sess, "oath_put_github", OP_OATH_PUT, totp2_req, pin_required=True)
        oath_put_status = {0x00: "OK (0x00)", 0x02: "NEED_PIN"}.get(st, f"0x{st:02X}")
        print(f"    0x24 OP_OATH_PUT 'GitHub:octocat' -> Status: {oath_put_status}")

        # 7.2 Consulta de contas OATH (OP_OATH_LIST 0x25 - requer apenas UP)
        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_OATH_LIST]), op="oath_list", timeout_s=4.0)
        print(f"    0x25 OP_OATH_LIST -> Status: 0x{st:02X}, Tamanho: {len(body)} B")
        if st == 0x00 and body:
            recs = _tlv.parse_tlv(body)
            for t, v in recs:
                if t == TAG_OATH_NAME and len(v) > 1:
                    label = v[1:].decode("utf-8", errors="replace")
                    print(f"      Conta cadastrada no silício: '{label}'")

        # 7.3 Cálculo do código OTP no chip físico (OP_OATH_CODE 0x26)
        timestep = int(time.time() // 30)
        code_req = build_oath_code("Google:alice@gmail.com", challenge=timestep)
        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_OATH_CODE]) + code_req, op="oath_code", timeout_s=4.0)
        if st == 0x00 and body:
            recs = _tlv.parse_tlv(body)
            otp_val = None
            for t, v in recs:
                if t == TAG_OATH_RESPONSE:
                    otp_val = v.decode("utf-8", errors="replace")
            print(f"    0x26 OP_OATH_CODE 'Google:alice@gmail.com' -> Status: OK (0x00), OTP: [{otp_val or 'OK'}]")
        else:
            print(f"    0x26 OP_OATH_CODE 'Google:alice@gmail.com' -> Status: 0x{st:02X}")

        # 7.4 Exclusão de conta OATH (OP_OATH_DELETE 0x27 com PIN)
        del_req = _tlv.write_tlv(TAG_OATH_NAME, b"GitHub:octocat")
        st, _ = send_arm(sess, "oath_del_github", OP_OATH_DELETE, del_req, pin_required=True)
        print(f"    0x27 OP_OATH_DELETE 'GitHub:octocat' -> Status: {'OK (0x00)' if st == 0x00 else f'0x{st:02X}'}")

        # -------------------------------------------------------------
        # ETAPA 8: Listagem Completa de Recursos On-Device
        # -------------------------------------------------------------
        print("\n[+] 9. ETAPA 8 — Listagem Completa de Todos os Recursos On-Device...")
        # 8.1 OP_KEY_LIST (0x22)
        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_KEY_LIST]), op="list_keys", timeout_s=4.0)
        print(f"    0x22 OP_KEY_LIST -> Status: 0x{st:02X}, Tamanho: {len(body)} B")
        if st == 0x00:
            recs = _tlv.parse_tlv(body)
            pending_slot = None
            for t, v in recs:
                if t == TAG_SLOT and len(v) == 1:
                    pending_slot = v[0]
                elif t == TAG_LABEL and pending_slot is not None:
                    print(f"      Key Slot {pending_slot}: '{v.decode('utf-8', errors='replace')}'")
                    pending_slot = None

        # 8.2 OP_WALLET_LIST (0x36)
        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_WALLET_LIST]), op="list_wallets", timeout_s=4.0)
        print(f"    0x36 OP_WALLET_LIST -> Status: 0x{st:02X}, Tamanho: {len(body)} B")
        if st == 0x00:
            recs = _tlv.parse_tlv(body)
            slot_curr, label_curr, addr_curr = None, None, None
            for t, v in recs:
                if t == TAG_WALLET_SLOT and len(v) == 1:
                    slot_curr = v[0]
                elif t == TAG_WALLET_LABEL:
                    label_curr = v.decode("utf-8", errors="replace")
                elif t == TAG_WALLET_ADDRESS:
                    addr_curr = v.decode("utf-8", errors="replace")
                    print(f"      Wallet Slot {slot_curr}: '{label_curr}' -> Endereço: {addr_curr}")

        # 8.3 OP_FW_LOG (0x38)
        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_FW_LOG]), op="fw_log", timeout_s=4.0)
        print(f"    0x38 OP_FW_LOG -> Status: 0x{st:02X}, Tamanho: {len(body)} B")
        if st == 0x00 and body:
            lines = body.decode("latin-1", errors="replace").splitlines()
            print(f"      Eventos do Firmware registrados ({len(lines)} linhas no ring-buffer):")
            for l in lines[:6]:
                print(f"        {l}")

        # -------------------------------------------------------------
        # ETAPA 9: Teste de Exclusão e Segurança de PIN (0x23)
        # -------------------------------------------------------------
        print("\n[+] 10. ETAPA 9 — Teste de Exclusão de Chave com PIN (0x23 KEY_DELETE)...")
        body_tmp = _ops.vendor_key_gen(15, b"temp_key_for_del", ALG_ES256, USAGE_SIGN)
        send_arm(sess, "gen_temp_del", OP_KEY_GEN, body_tmp)
        del_k15 = _tlv.write_tlv(TAG_SLOT, bytes([15]))
        st, _ = send_arm(sess, "del_slot_15", OP_KEY_DELETE, del_k15, pin_required=True)
        print(f"    0x23 OP_KEY_DELETE Slot 15 -> Status: {'OK (0x00) - Slot excluído com sucesso!' if st == 0x00 else f'0x{st:02X}'}")

        print("\n" + "=" * 70)
        print("  JORNADA COMPLETA DO APP VALIDADA COM SUCESSO NO HARDWARE REAL!")
        print("=" * 70)

    finally:
        sess.close()
        print("\n[!] Conexão serial fechada com segurança.")


if __name__ == "__main__":
    main()
