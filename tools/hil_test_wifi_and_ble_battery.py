#!/usr/bin/env python3
"""Bateria Completa de Testes de Conexão e Configuração via Wi-Fi e Bluetooth (Hardware Real + Bridge)

Valida de ponta a ponta:
- BLE GATT (0xFFFD):
  * Janela de pareamento 60s (0x2F / TEST_PAIRING_OPEN) e descoberta do anúncio BLE
  * Leitura de FFF3 (Max Control Point Length = 512) e FFF4 (Service Revision = 0x01)
  * Escrita em FFF1 e Notificação em FFF2 com fragmentação MTU (INIT + CONT seq 0x00..0x7F)
    - 0x81 (PING echo)
    - 0x28 / 0x29 / 0x2A (Binding Claim, Challenge, Verify)
    - 0x2C / 0x2D (Recovery / PIN set e unlock via BLE)
    - 0x20 / 0x22 (Criação e Listagem de Passkey via BLE)
    - 0x35 / 0x36 / 0x37 (Criação e Endereço de Wallet via BLE)
    - 0x24 / 0x25 / 0x26 (Cadastro, Listagem e Código TOTP via BLE)
- Wi-Fi SoftAP / HTTP:
  * GET /status (firmware, SSID, canal, segurança WPA2/WPA3, slots_state)
  * POST /wifi/config (configuração de SSID, canal, potência TX e timeout)
  * GET /wifi/nets (redes salvas compatível com WifiScreen.kt)
  * POST /ctap (frames CTAP / AEGN envelope via HTTP Wi-Fi)
  * GET /oath/code e POST /oath/code (cálculo de TOTP on-device com remaining_seconds)
"""

import argparse
import asyncio
import hashlib
import json
import os
import struct
import sys
import time
import urllib.parse
import urllib.request

# Constantes de Protocolo BLE GATT 0xFFFD
BLE_SERVICE_UUID = "0000fffd-0000-1000-8000-00805f9b34fb"
CHAR_FFF1_UUID = "0000fff1-0000-1000-8000-00805f9b34fb"
CHAR_FFF2_UUID = "0000fff2-0000-1000-8000-00805f9b34fb"
CHAR_FFF3_UUID = "0000fff3-0000-1000-8000-00805f9b34fb"
CHAR_FFF4_UUID = "0000fff4-0000-1000-8000-00805f9b34fb"

CONTROL_POINT_LENGTH = 512
MAX_FRAGMENT_BYTES = 244
GATT_REVISION = 0x01

# Opcodes
OP_PING = 0x81
OP_MSG = 0x83
OP_CANCEL = 0xBE

OP_KEY_GEN = 0x20
OP_KEY_IMPORT = 0x21
OP_KEY_LIST = 0x22
OP_KEY_DELETE = 0x23
OP_OATH_PUT = 0x24
OP_OATH_LIST = 0x25
OP_OATH_CODE = 0x26
OP_OATH_DELETE = 0x27

OP_BIND_CLAIM = 0x28
OP_BIND_CHALLENGE = 0x29
OP_BIND_VERIFY = 0x2A
OP_BIND_RELEASE = 0x2B
OP_RECOVERY_SET = 0x2C
OP_RECOVERY_UNLOCK = 0x2D

OP_WALLET_GEN = 0x35
OP_WALLET_LIST = 0x36
OP_WALLET_ADDR = 0x37
OP_FW_LOG = 0x38
OP_PIV_ENROLL = 0x39

TAG_OATH_NAME = 0x71
TAG_OATH_KEY = 0x73
TAG_OATH_CHALLENGE = 0x74
TAG_OATH_RESPONSE = 0x75

TAG_WALLET_SLOT = 0x01
TAG_WALLET_LABEL = 0x02
TAG_WALLET_ADDRESS = 0x07
TAG_WALLET_NETWORK = 0x08

TEST_RESULTS = []


def record(suite: str, step: str, ok: bool, details: str = ""):
    status = "PASS" if ok else "FAIL"
    TEST_RESULTS.append((suite, step, status, details))
    mark = "[+]" if ok else "[-]"
    print(f"  {mark} [{suite}] {step:<40} -> {status} ({details})")


def ble_split_fragments(opcode: int, payload: bytes, max_fragment: int = 244) -> list[bytes]:
    """Fragmenta payload para FFF1 (espelha ble_split_fragments do firmware)."""
    payload = bytes(payload)
    if opcode == OP_CANCEL:
        return [bytes([OP_CANCEL])]
    if len(payload) > CONTROL_POINT_LENGTH:
        raise ValueError(f"payload {len(payload)}B > {CONTROL_POINT_LENGTH}B")
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
    """Reassembla fragmentos FFF1/FFF2 em (opcode, payload)."""
    frags = [bytes(f) for f in fragments if f]
    if not frags:
        raise ValueError("sem fragmentos")
    first = frags[0]
    if first == bytes([OP_CANCEL]):
        return (OP_CANCEL, b"")
    if len(first) < 3:
        raise ValueError(f"primeiro fragmento curto: {len(first)}B")
    opcode = first[0]
    total = (first[1] << 8) | first[2]
    if total > CONTROL_POINT_LENGTH:
        raise ValueError(f"total {total}B > {CONTROL_POINT_LENGTH}B")
    buf = bytearray(first[3:])
    for frag in frags[1:]:
        buf.extend(frag[1:])
    if len(buf) != total:
        raise ValueError(f"truncado: {len(buf)}B != {total}B")
    return (opcode, bytes(buf))


class BridgeClient:
    """Cliente HTTP para comunicação com o host_hardware_android_bridge."""

    def __init__(self, base_url="http://127.0.0.1:5678"):
        self.base_url = base_url.rstrip("/")

    def get(self, path: str, timeout: float = 10.0) -> dict:
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def post(self, path: str, data: dict, timeout: float = 25.0) -> dict:
        url = f"{self.base_url}{path}"
        raw_body = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=raw_body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def post_raw(self, path: str, raw_bytes: bytes, content_type: str = "application/octet-stream", timeout: float = 15.0) -> bytes:
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(
            url,
            data=raw_bytes,
            headers={"Content-Type": content_type, "Accept": "application/octet-stream"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()


async def scan_ble_air(timeout_s: float = 5.0) -> dict:
    """Realiza scan over-the-air via Bluetooth nativo do host usando bleak."""
    try:
        import bleak
        scanner = bleak.BleakScanner()
        devs = await bleak.BleakScanner.discover(timeout=timeout_s, return_adv=True)
        for addr, (dev, adv) in devs.items():
            name = dev.name or adv.local_name or ""
            uuids = [str(u).lower() for u in adv.service_uuids]
            if "0000fffd-0000-1000-8000-00805f9b34fb" in uuids or name.startswith("AegisKey"):
                return {
                    "found": True,
                    "name": name,
                    "address": addr,
                    "rssi": adv.rssi,
                    "service_uuids": adv.service_uuids,
                }
        return {"found": False, "error": "device_not_in_range"}
    except Exception as ex:
        return {"found": False, "error": str(ex)}


def test_ble_battery(client: BridgeClient):
    print("\n" + "=" * 70)
    print("  PARTE 1: BATERIA BLUETOOTH (BLE GATT 0xFFFD / FFF1-FFF4)")
    print("=" * 70)

    # 1. Abertura de janela de pareamento 60s
    try:
        p_res = client.post("/bridge/pairing_open", {})
        ok = p_res.get("ok") is True and p_res.get("window_s", 0) >= 60
        record("BLE", "1. Janela Pareamento 60s (0x2F / TEST_PAIRING_OPEN)", ok, f"window={p_res.get('window_s')}s")
    except Exception as e:
        record("BLE", "1. Janela Pareamento 60s", False, str(e))

    # 2. Descoberta BLE Over-The-Air (bleak scan nativo)
    try:
        scan_res = asyncio.run(scan_ble_air(timeout_s=4.0))
        if scan_res.get("found"):
            record(
                "BLE",
                "2. Descoberta Anúncio BLE OTA (bleak / 0xFFFD)",
                True,
                f"name='{scan_res.get('name')}', MAC={scan_res.get('address')}, RSSI={scan_res.get('rssi')}dBm",
            )
        else:
            # Fallback para endpoint de scan do bridge
            b_scan = client.get("/ble/scan")
            devs = b_scan.get("devices", [])
            ok = len(devs) > 0 and devs[0].get("service_uuid", "").lower() == BLE_SERVICE_UUID
            record("BLE", "2. Descoberta Anúncio BLE (Bridge / 0xFFFD)", ok, f"device={devs[0].get('name')} RSSI={devs[0].get('rssi')}dBm")
    except Exception as e:
        record("BLE", "2. Descoberta Anúncio BLE", False, str(e))

    # 3. Leitura de FFF3 e FFF4
    try:
        chars_res = client.get("/ble/chars")
        chars = chars_res.get("chars", {})
        fff3_ok = chars.get("FFF3", {}).get("max_length") == 512
        fff4_ok = chars.get("FFF4", {}).get("revision") == 0x01
        record(
            "BLE",
            "3. Leitura FFF3 (Max Length=512) e FFF4 (Rev=0x01)",
            fff3_ok and fff4_ok,
            f"FFF3_len={chars.get('FFF3', {}).get('max_length')}B, FFF4_rev=0x{chars.get('FFF4', {}).get('revision', 0):02X}",
        )
    except Exception as e:
        record("BLE", "3. Leitura FFF3/FFF4", False, str(e))

    # 4. Escrita em FFF1 e Notificação em FFF2 (0x81 PING)
    try:
        ping_payload = b"aegis-ble-ping-test"
        frags = ble_split_fragments(OP_PING, ping_payload, max_fragment=12)  # Força múltiplos fragmentos
        res = client.post("/ble/write_notify", {"fragments_hex": [f.hex() for f in frags]})
        ret_opcode = res.get("opcode")
        ret_status = res.get("status")
        ret_payload = bytes.fromhex(res.get("payload_hex", ""))
        ok = ret_opcode == OP_PING and ret_status == 0x00 and ret_payload == ping_payload
        record(
            "BLE",
            "4. 0x81 (PING) via FFF1 MTU Fragmentation -> FFF2",
            ok,
            f"frags_tx={len(frags)}, echoed={len(ret_payload)}B, status=0x{ret_status:02X}",
        )
    except Exception as e:
        record("BLE", "4. 0x81 PING Fragmentation", False, str(e))

    # 5. Binding Management via BLE Framing (0x28 CLAIM, 0x29 CHALLENGE, 0x2A VERIFY)
    # 5.1 OP_BIND_CLAIM (0x28) - 81B (65B SEC1 pubkey + 16B binding ID)
    try:
        dummy_claim = b"\x04" + (b"\x11" * 64) + (b"\x22" * 16)
        frags = ble_split_fragments(OP_BIND_CLAIM, dummy_claim, max_fragment=32)
        res = client.post("/ble/write_notify", {"fragments_hex": [f.hex() for f in frags]})
        st = res.get("status")
        ok = res.get("ok") is True and st in (0x00, 0x04)
        record(
            "BLE",
            "5.1 0x28 (BIND_CLAIM) 81B via FFF1/FFF2",
            ok,
            f"frags={len(frags)}, status=0x{st:02X}",
        )
    except Exception as e:
        record("BLE", "5.1 0x28 BIND_CLAIM", False, str(e))

    # 5.2 OP_BIND_CHALLENGE (0x29) - 0B req -> 32B nonce resp
    try:
        frags = ble_split_fragments(OP_BIND_CHALLENGE, b"")
        res = client.post("/ble/write_notify", {"fragments_hex": [f.hex() for f in frags]})
        st = res.get("status")
        payload = bytes.fromhex(res.get("payload_hex", ""))
        ok = res.get("ok") is True and st == 0x00 and len(payload) == 32
        record(
            "BLE",
            "5.2 0x29 (BIND_CHALLENGE) 32B via FFF1/FFF2",
            ok,
            f"nonce={payload.hex()[:16]}... len={len(payload)}B",
        )
    except Exception as e:
        record("BLE", "5.2 0x29 BIND_CHALLENGE", False, str(e))

    # 5.3 OP_BIND_VERIFY (0x2A)
    try:
        verify_dummy = bytes([0x20]) + (b"\x33" * 32) + (b"\x44" * 32) + (b"\x55" * 64)
        frags = ble_split_fragments(OP_BIND_VERIFY, verify_dummy, max_fragment=48)
        res = client.post("/ble/write_notify", {"fragments_hex": [f.hex() for f in frags]})
        st = res.get("status")
        ok = res.get("ok") is True and st in (0x00, 0x04)
        record(
            "BLE",
            "5.3 0x2A (BIND_VERIFY) via FFF1/FFF2",
            ok,
            f"frags={len(frags)}, status=0x{st:02X}",
        )
    except Exception as e:
        record("BLE", "5.3 0x2A BIND_VERIFY", False, str(e))

    # 6. Recovery / PIN Management via BLE Framing (0x2C RECOVERY_SET, 0x2D RECOVERY_UNLOCK)
    try:
        pin_payload = b"123456"
        frags = ble_split_fragments(OP_RECOVERY_SET, pin_payload)
        res = client.post("/ble/write_notify", {"fragments_hex": [f.hex() for f in frags]})
        st = res.get("status")
        ok = res.get("ok") is True and st in (0x00, 0x04)
        record("BLE", "6.1 0x2C (RECOVERY_SET) via FFF1/FFF2", ok, f"status=0x{st:02X}")
    except Exception as e:
        record("BLE", "6.1 0x2C RECOVERY_SET", False, str(e))

    try:
        frags = ble_split_fragments(OP_RECOVERY_UNLOCK, pin_payload)
        res = client.post("/ble/write_notify", {"fragments_hex": [f.hex() for f in frags]})
        st = res.get("status")
        ok = res.get("ok") is True and st in (0x00, 0x04)
        record("BLE", "6.2 0x2D (RECOVERY_UNLOCK) via FFF1/FFF2", ok, f"status=0x{st:02X}")
    except Exception as e:
        record("BLE", "6.2 0x2D RECOVERY_UNLOCK", False, str(e))

    # 7. Passkeys via BLE Framing (0x20 KEY_GEN, 0x22 KEY_LIST)
    try:
        # Criação de chave Slot 0 (Ed25519) via BLE
        key_gen_req = bytes([0x01, 0x01, 0x00]) + bytes([0x02, 0x0F]) + b"passkey:ble_ed" + bytes([0x03, 0x01, 0xF8])
        frags = ble_split_fragments(OP_KEY_GEN, key_gen_req, max_fragment=16)
        res = client.post("/ble/write_notify", {"fragments_hex": [f.hex() for f in frags]})
        st = res.get("status")
        ok = res.get("ok") is True and st in (0x00, 0x04)
        record("BLE", "7.1 0x20 (KEY_GEN Passkey Ed25519) via BLE", ok, f"frags={len(frags)}, status=0x{st:02X}")
    except Exception as e:
        record("BLE", "7.1 0x20 KEY_GEN", False, str(e))

    try:
        frags = ble_split_fragments(OP_KEY_LIST, b"")
        res = client.post("/ble/write_notify", {"fragments_hex": [f.hex() for f in frags]})
        st = res.get("status")
        payload = bytes.fromhex(res.get("payload_hex", ""))
        ok = res.get("ok") is True and st == 0x00 and len(payload) > 0
        record("BLE", "7.2 0x22 (KEY_LIST) via BLE FFF1/FFF2", ok, f"status=0x{st:02X}, len={len(payload)}B")
    except Exception as e:
        record("BLE", "7.2 0x22 KEY_LIST", False, str(e))

    # 8. Crypto Wallets via BLE Framing (0x35 WALLET_GEN, 0x36 WALLET_LIST, 0x37 WALLET_ADDR)
    try:
        # Gera carteira BTC (Slot 6)
        wallet_gen_req = bytes([0x01, 0x01, 0x06]) + bytes([0x02, 0x0E]) + b"wallet:BtcBle" + bytes([0x08, 0x01, 0x01])
        frags = ble_split_fragments(OP_WALLET_GEN, wallet_gen_req)
        res = client.post("/ble/write_notify", {"fragments_hex": [f.hex() for f in frags]})
        st = res.get("status")
        ok = res.get("ok") is True and st in (0x00, 0x04)
        record("BLE", "8.1 0x35 (WALLET_GEN BtcBle) via BLE", ok, f"status=0x{st:02X}")
    except Exception as e:
        record("BLE", "8.1 0x35 WALLET_GEN", False, str(e))

    try:
        frags = ble_split_fragments(OP_WALLET_LIST, b"")
        res = client.post("/ble/write_notify", {"fragments_hex": [f.hex() for f in frags]})
        st = res.get("status")
        payload = bytes.fromhex(res.get("payload_hex", ""))
        ok = res.get("ok") is True and st == 0x00 and len(payload) > 0
        record("BLE", "8.2 0x36 (WALLET_LIST) via BLE", ok, f"status=0x{st:02X}, len={len(payload)}B")
    except Exception as e:
        record("BLE", "8.2 0x36 WALLET_LIST", False, str(e))

    try:
        # Consulta endereço Slot 6
        frags = ble_split_fragments(OP_WALLET_ADDR, bytes([TAG_WALLET_SLOT, 0x01, 0x06]))
        res = client.post("/ble/write_notify", {"fragments_hex": [f.hex() for f in frags]})
        st = res.get("status")
        payload = bytes.fromhex(res.get("payload_hex", ""))
        addr_str = payload.decode("ascii", errors="ignore")
        ok = res.get("ok") is True and st == 0x00 and "bc1" in addr_str
        record("BLE", "8.3 0x37 (WALLET_ADDR) via BLE", ok, f"addr={addr_str[:24]}...")
    except Exception as e:
        record("BLE", "8.3 0x37 WALLET_ADDR", False, str(e))

    # 9. TOTP / OATH via BLE Framing (0x24 PUT, 0x25 LIST, 0x26 CODE)
    try:
        # Cadastra TOTP 'BleService:bob@aegis'
        oath_name = b"BleService:bob@aegis"
        oath_secret = b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
        put_req = (
            bytes([TAG_OATH_NAME, len(oath_name)]) + oath_name
            + bytes([TAG_OATH_KEY, len(oath_secret) + 2, 0x21, 0x06]) + oath_secret
        )
        frags = ble_split_fragments(OP_OATH_PUT, put_req, max_fragment=20)
        res = client.post("/ble/write_notify", {"fragments_hex": [f.hex() for f in frags]})
        st = res.get("status")
        ok = res.get("ok") is True and st in (0x00, 0x04)
        record("BLE", "9.1 0x24 (OATH_PUT) via BLE FFF1/FFF2", ok, f"status=0x{st:02X}")
    except Exception as e:
        record("BLE", "9.1 0x24 OATH_PUT", False, str(e))

    try:
        frags = ble_split_fragments(OP_OATH_LIST, b"")
        res = client.post("/ble/write_notify", {"fragments_hex": [f.hex() for f in frags]})
        st = res.get("status")
        payload = bytes.fromhex(res.get("payload_hex", ""))
        ok = res.get("ok") is True and st == 0x00 and len(payload) > 0
        record("BLE", "9.2 0x25 (OATH_LIST) via BLE", ok, f"status=0x{st:02X}, len={len(payload)}B")
    except Exception as e:
        record("BLE", "9.2 0x25 OATH_LIST", False, str(e))

    try:
        # Calcula OTP no chip físico via BLE
        chal_bytes = struct.pack(">Q", int(time.time() // 30))
        code_req = bytes([TAG_OATH_NAME, len(oath_name)]) + oath_name + bytes([TAG_OATH_CHALLENGE, len(chal_bytes)]) + chal_bytes
        frags = ble_split_fragments(OP_OATH_CODE, code_req)
        res = client.post("/ble/write_notify", {"fragments_hex": [f.hex() for f in frags]})
        st = res.get("status")
        payload = bytes.fromhex(res.get("payload_hex", ""))
        code_val = ""
        idx = 0
        while idx < len(payload):
            if idx + 2 > len(payload):
                break
            tag = payload[idx]
            tlen = payload[idx + 1]
            tval = payload[idx + 2 : idx + 2 + tlen]
            if tag in (TAG_OATH_RESPONSE, 0x76):
                code_val = tval.decode("ascii", errors="ignore").strip()
                break
            idx += 2 + tlen
        if not code_val:
            code_val = payload.decode("ascii", errors="ignore").strip()
        ok = res.get("ok") is True and st == 0x00 and len(code_val) >= 6
        record("BLE", "9.3 0x26 (OATH_CODE) OTP On-Device via BLE", ok, f"status=0x{st:02X}, OTP=[{code_val[:6]}]")
    except Exception as e:
        record("BLE", "9.3 0x26 OATH_CODE", False, str(e))


def test_wifi_battery(client: BridgeClient):
    print("\n" + "=" * 70)
    print("  PARTE 2: BATERIA WI-FI (HTTP /status, /wifi/config, /ctap, /oath/code)")
    print("=" * 70)

    # 1. GET /status (firmware version, SSID, canal, segurança WPA2/WPA3, slots_state)
    try:
        st_res = client.get("/status")
        wifi = st_res.get("wifi", {})
        slots = st_res.get("slots_state", {})
        ok = (
            st_res.get("ok") is True
            and "AegisKey" in wifi.get("ssid", "")
            and wifi.get("channel") in (1, 6, 11)
            and "WPA" in wifi.get("security", "")
            and "keys_count" in slots
        )
        record(
            "WIFI",
            "1. GET /status (SoftAP & Firmware State)",
            ok,
            f"SSID={wifi.get('ssid')}, ch={wifi.get('channel')}, sec={wifi.get('security')}, keys={slots.get('keys_count')}",
        )
    except Exception as e:
        record("WIFI", "1. GET /status", False, str(e))

    # 2. POST /wifi/config (alteração de SSID, canal, potência TX e timeout)
    try:
        cfg_res = client.post(
            "/wifi/config",
            {
                "ssid": "AegisKey-AP-Fast",
                "channel": 11,
                "tx_power_dbm": 20,
                "timeout_s": 60,
                "password": "senha-segura-wifi-123",
            },
        )
        ok = (
            cfg_res.get("ok") is True
            and cfg_res.get("ssid") == "AegisKey-AP-Fast"
            and cfg_res.get("channel") == 11
            and cfg_res.get("status") == "configured"
        )
        record(
            "WIFI",
            "2.1 POST /wifi/config (SSID, Canal, Senha WPA2)",
            ok,
            f"status={cfg_res.get('status')}, ssid={cfg_res.get('ssid')}, ch={cfg_res.get('channel')}",
        )
    except Exception as e:
        record("WIFI", "2.1 POST /wifi/config", False, str(e))

    # 2.2 Rejeição de senha inválida (<8 chars)
    try:
        bad_req = urllib.request.Request(
            f"{client.base_url}/wifi/config",
            data=json.dumps({"password": "curta"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(bad_req, timeout=5) as resp:
                ok = False
        except urllib.error.HTTPError as ex:
            ok = ex.code == 400
        record("WIFI", "2.2 POST /wifi/config (Rejeita senha < 8 chars)", ok, "HTTP 400 Bad Request")
    except Exception as e:
        record("WIFI", "2.2 POST /wifi/config Bounds", False, str(e))

    # 3. GET /wifi/nets (listagem de redes salvas)
    try:
        nets_res = client.get("/wifi/nets")
        nets = nets_res.get("nets", [])
        ok = nets_res.get("ok") is True and len(nets) > 0 and "AegisKey" in nets[0]
        record("WIFI", "3. GET /wifi/nets (Nets Salvas no Device)", ok, f"count={len(nets)}, top='{nets[0]}'")
    except Exception as e:
        record("WIFI", "3. GET /wifi/nets", False, str(e))

    # 4. POST /ctap (frames CTAP / AEGN Envelope via Wi-Fi)
    try:
        # Envia envelope sintético AEGN para listar chaves (0x22)
        nonce = b"\x01" * 12
        env_raw = b"AEGN\x01" + nonce + bytes([OP_KEY_LIST]) + (b"\x00" * 16)
        resp_env = client.post_raw("/ctap", env_raw)
        ok = len(resp_env) >= 18 and resp_env.startswith(b"AEGN\x01")
        record("WIFI", "4.1 POST /ctap (AEGN Envelope E2E via Wi-Fi)", ok, f"rx={len(resp_env)}B, header={resp_env[:5]}")
    except Exception as e:
        record("WIFI", "4.1 POST /ctap AEGN", False, str(e))

    try:
        # Envia comando de consulta de carteiras (0x36) via /ctap JSON
        res = client.post("/ctap", {"opcode": OP_WALLET_LIST, "payload_hex": ""})
        st = res.get("status")
        payload = bytes.fromhex(res.get("payload_hex", ""))
        ok = res.get("ok") is True and st == 0x00 and len(payload) > 0
        record("WIFI", "4.2 POST /ctap (OP_WALLET_LIST on Silicon)", ok, f"status=0x{st:02X}, len={len(payload)}B")
    except Exception as e:
        record("WIFI", "4.2 POST /ctap JSON", False, str(e))

    # 5. GET /oath/code e POST /oath/code (TOTP On-Device via Wi-Fi)
    try:
        account_name = "Google:alice@gmail.com"
        get_res = client.get(f"/oath/code?account={urllib.parse.quote(account_name)}")
        code = get_res.get("code", "")
        rem = get_res.get("remaining_seconds", 0)
        ok = get_res.get("ok") is True and len(code) == 6 and code.isdigit()
        record(
            "WIFI",
            "5.1 GET /oath/code (TOTP 6-dig On-Device)",
            ok,
            f"account='{account_name}', code=[{code}], rem={rem}s",
        )
    except Exception as e:
        record("WIFI", "5.1 GET /oath/code", False, str(e))

    try:
        post_res = client.post("/oath/code", {"account": "BleService:bob@aegis"})
        code = post_res.get("code", "")
        rem = post_res.get("remaining_seconds", 0)
        ok = post_res.get("ok") is True and len(code) == 6 and code.isdigit()
        record(
            "WIFI",
            "5.2 POST /oath/code (TOTP 6-dig On-Device)",
            ok,
            f"account='BleService:bob@aegis', code=[{code}], rem={rem}s",
        )
    except Exception as e:
        record("WIFI", "5.2 POST /oath/code", False, str(e))


def main():
    parser = argparse.ArgumentParser(description="Bateria Completa de Testes Wi-Fi & BLE no Hardware Real")
    parser.add_argument("--url", default="http://127.0.0.1:5678", help="URL do Bridge Daemon")
    args = parser.parse_args()

    print("=" * 70)
    print("  AEGISKEY HIL: BATERIA COMPLETA DE WI-FI E BLUETOOTH")
    print(f"  Target Bridge: {args.url}")
    print("=" * 70)

    client = BridgeClient(args.url)

    # 1. Sanidade inicial de conectividade
    try:
        info = client.get("/bridge/info")
        print(f"[+] Bridge Online! Chave Real: {info.get('device_name')} (Transporte: {info.get('transport')})")
        print(f"    USB Nativo Presente: {info.get('usb_native_present')}, CID: {info.get('cid')}")
    except Exception as ex:
        print(f"[-] Erro ao conectar no bridge em {args.url}: {ex}")
        print("    Certifique-se de que tools/host_hardware_android_bridge.py está ativo na porta 5678.")
        return 1

    # Executa bateria BLE
    test_ble_battery(client)

    # Executa bateria Wi-Fi
    test_wifi_battery(client)

    # Placar final
    print("\n" + "=" * 70)
    print("  PLACAR FINAL DA BATERIA WI-FI & BLUETOOTH")
    print("=" * 70)
    total = len(TEST_RESULTS)
    passes = sum(1 for _, _, st, _ in TEST_RESULTS if st == "PASS")
    fails = sum(1 for _, _, st, _ in TEST_RESULTS if st == "FAIL")

    ble_passes = sum(1 for s, _, st, _ in TEST_RESULTS if s == "BLE" and st == "PASS")
    ble_total = sum(1 for s, _, _, _ in TEST_RESULTS if s == "BLE")

    wifi_passes = sum(1 for s, _, st, _ in TEST_RESULTS if s == "WIFI" and st == "PASS")
    wifi_total = sum(1 for s, _, _, _ in TEST_RESULTS if s == "WIFI")

    print(f"  TOTAL DE TESTES : {total}")
    print(f"  BLUETOOTH (BLE) : {ble_passes}/{ble_total} PASS")
    print(f"  WI-FI (SoftAP)  : {wifi_passes}/{wifi_total} PASS")
    print(f"  RESULTADO FINAL : {'100% SUCESSO' if fails == 0 else f'{fails} FALHA(S)'}")
    print("=" * 70 + "\n")

    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
