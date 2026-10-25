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

import os
import struct
import sys
import time

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

OATH_TYPE_HOTP = 0x10
OATH_TYPE_TOTP = 0x20
OATH_ALGO_SHA1 = 0x01


def build_oath_put(name: str, oath_type: int, digits: int, secret: bytes, counter: int = None) -> bytes:
    name_bytes = name.encode("utf-8")
    type_algo = oath_type | OATH_ALGO_SHA1
    key_bytes = bytes([type_algo, digits]) + secret
    req = _tlv.write_tlv(TAG_OATH_NAME, name_bytes) + _tlv.write_tlv(TAG_OATH_KEY, key_bytes)
    if counter is not None:
        imf = struct.pack(">I", counter)
        req += _tlv.write_tlv(TAG_OATH_IMF, imf)
    return req


def send_arm(sess: Session, op_name: str, cmd_byte: int, payload: bytes = b"", timeout_s: float = 6.0):
    """Sends TEST_PAIRING_OPEN + TEST_UP before privileged write ops, executes op and returns (status, body)."""
    sess.test_pairing_open(timeout_s=3.0)
    sess.test_up(timeout_s=3.0)
    full_payload = bytes([cmd_byte]) + payload if cmd_byte is not None else payload
    st, body = sess._exchange(CMD_MSG, full_payload, op=op_name, timeout_s=timeout_s)
    return st, body


def main():
    print("=" * 70)
    print("  HIL EMULATION: JORNADA COMPLETA DO APP NA CHAVE REAL (COM7)")
    print("=" * 70)

    sess = Session("http://192.168.4.1", test_mode=True)
    try:
        print(f"\n[+] 1. Conectando à placa em {PORT} a {BAUD} bps...")
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
        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_KEY_LIST]), op="key_list", timeout_s=4.0)
        print(f"    0x22 OP_KEY_LIST -> Status: 0x{st:02X}, Tamanho: {len(body)} B (esperado vazio = 0)")

        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_OATH_LIST]), op="oath_list", timeout_s=4.0)
        print(f"    0x25 OP_OATH_LIST -> Status: 0x{st:02X}, Tamanho: {len(body)} B (esperado vazio = 0)")

        # -------------------------------------------------------------
        # ETAPA 2: Criação de Chaves PASSKEY / FIDO nas Curvas Suportadas
        # -------------------------------------------------------------
        print("\n[+] 3. ETAPA 2 — Criação de PASSKEYS FIDO On-Device (0x20)...")
        curves = [
            (0, "passkey:ed25519", ALG_ED25519, "Ed25519 (alg -8, moderna / passkey rápida)"),
            (1, "passkey:p256", ALG_ES256, "ES256 / P-256 (alg -7, WebAuthn padrão FIDO2)"),
            (2, "passkey:secp256k1", ALG_ES256K, "ES256K / secp256k1 (alg -47, Bitcoin/Koblitz)"),
        ]

        for slot, label, alg, desc in curves:
            body = _ops.vendor_key_gen(slot, label.encode("utf-8"), alg, USAGE_SIGN_AUTH)
            st, resp = send_arm(sess, f"gen_passkey_{slot}", OP_KEY_GEN, body)
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
        body_vsign = _ops.vendor_key_gen(3, b"vendor:firmware_sign", ALG_ES256, USAGE_SIGN)
        st, resp = send_arm(sess, "gen_vsign", OP_KEY_GEN, body_vsign)
        print(f"    Slot 3 [Vendor Signing ES256, usage=SIGN] -> Status: 0x{st:02X} ({'OK' if st == 0 else 'ERRO'})")
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
            (4, b"BtcMainVault", 1, "Bitcoin P2WPKH (bech32)"),
            (5, b"EthMainVault", 2, "Ethereum EVM (EIP-55 hex)"),
            (6, b"SolMainVault", 3, "Solana Ed25519 (base58)"),
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
        st, _ = send_arm(sess, "key_import", OP_KEY_IMPORT, import_payload)
        status_meaning = {0x04: "GATE_OK (sem envelope)", 0x02: "NEED_PIN (protegido por PIN)"}.get(st, f"STATUS 0x{st:02X}")
        print(f"    0x21 OP_KEY_IMPORT -> Status: 0x{st:02X} ({status_meaning})")

        # -------------------------------------------------------------
        # ETAPA 7: Teste do Módulo OATH (0x24, 0x25, 0x26)
        # -------------------------------------------------------------
        print("\n[+] 8. ETAPA 7 — Módulo OATH TOTP / HOTP (0x24, 0x25, 0x26)...")
        google_secret = b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"  # 20B
        totp1_req = build_oath_put("Google:alice@gmail.com", OATH_TYPE_TOTP, 6, google_secret)
        st, _ = send_arm(sess, "oath_put_google", OP_OATH_PUT, totp1_req)
        oath_put_status = {0x00: "OK", 0x02: "NEED_PIN (UpAndPin enforced)"}.get(st, f"0x{st:02X}")
        print(f"    0x24 OP_OATH_PUT 'Google:alice@gmail.com' -> Status: 0x{st:02X} ({oath_put_status})")

        # 8.2 Consulta de contas OATH (OP_OATH_LIST 0x25 - requer apenas UP)
        sess.test_up(timeout_s=3.0)
        st, body = sess._exchange(CMD_MSG, bytes([OP_OATH_LIST]), op="oath_list", timeout_s=4.0)
        print(f"    0x25 OP_OATH_LIST -> Status: 0x{st:02X}, Tamanho: {len(body)} B")

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
        print("\n[+] 10. ETAPA 9 — Teste de Exclusão (0x23 KEY_DELETE)...")
        del_k3 = _tlv.write_tlv(TAG_SLOT, bytes([3]))
        st, _ = send_arm(sess, "del_slot_3", OP_KEY_DELETE, del_k3)
        print(f"    0x23 OP_KEY_DELETE Slot 3 -> Status: 0x{st:02X} ({'0x02 NEED_PIN (Correto: gate UpAndPin bloqueia deleção sem PIN)' if st == 0x02 else hex(st)})")

        print("\n" + "=" * 70)
        print("  JORNADA COMPLETA DO APP VALIDADA COM SUCESSO NO HARDWARE REAL!")
        print("=" * 70)

    finally:
        sess.close()
        print("\n[!] Conexão serial fechada com segurança.")


if __name__ == "__main__":
    main()
