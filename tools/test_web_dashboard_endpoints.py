#!/usr/bin/env python3
"""Automated Test Battery for AegisKey Web Dashboard & Bridge API Endpoints.

Tests 100% of the Web Dashboard endpoints against the physical ESP32-S3 silicon
connected via UART (COM7) and HTTP on http://127.0.0.1:5678/.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:5678"

passed_tests = 0
failed_tests = 0


def log_test(name, success, details=""):
    global passed_tests, failed_tests
    if success:
        passed_tests += 1
        print(f" [PASS] {name} -> {details}")
    else:
        failed_tests += 1
        print(f" [FAIL] {name} -> {details}")


def http_get(path, headers=None):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        return resp.status, resp.headers, resp.read()


def http_post_json(path, data_dict, headers=None):
    url = f"{BASE_URL}{path}"
    body = json.dumps(data_dict).encode("utf-8")
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=body, headers=h)
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        return resp.status, resp.headers, json.loads(resp.read().decode("utf-8"))


def run_battery():
    print("=" * 70)
    print(" BATERIA DE TESTES: AegisKey Web Dashboard & Endpoints de API Real")
    print(f" Alvo: {BASE_URL} (Hardware Real ESP32-S3 em COM7)")
    print("=" * 70)

    # 1. Web Dashboard Serving
    try:
        st, headers, body = http_get("/", headers={"Accept": "text/html"})
        html = body.decode("utf-8")
        ok = (st == 200) and ("AegisKey" in html) and ("WS2812 RGB" in html) and ("Meu Cofre" in html)
        log_test("1.1 GET / (Web Dashboard HTML)", ok, f"status={st}, len={len(body)}B")
    except Exception as e:
        log_test("1.1 GET / (Web Dashboard HTML)", False, str(e))

    try:
        st, headers, body = http_get("/dashboard", headers={"Accept": "text/html"})
        html = body.decode("utf-8")
        ok = (st == 200) and ("tab-vault" in html) and ("tab-totp" in html)
        log_test("1.2 GET /dashboard (Rota alternativa)", ok, f"status={st}, len={len(body)}B")
    except Exception as e:
        log_test("1.2 GET /dashboard (Rota alternativa)", False, str(e))

    # 2. Hardware Telemetry & Status
    try:
        st, _, data = http_get("/bridge/info")
        info = json.loads(data.decode("utf-8"))
        ok = (st == 200) and (info.get("connected") is True) and ("COM7" in str(info.get("port")))
        log_test("2.1 GET /bridge/info (Telemetria)", ok, f"conn={info.get('connected')}, port={info.get('port')}, uptime={info.get('uptime_s')}s")
    except Exception as e:
        log_test("2.1 GET /bridge/info (Telemetria)", False, str(e))

    try:
        st, _, data = http_get("/status")
        stat = json.loads(data.decode("utf-8"))
        ok = (st == 200) and (stat.get("ok") is True) and (stat.get("chip") is not None)
        log_test("2.2 GET /status (Wi-Fi SoftAP & Chave)", ok, f"chip={stat.get('chip')}, ssid={stat.get('wifi', {}).get('ssid')}")
    except Exception as e:
        log_test("2.2 GET /status (Wi-Fi SoftAP & Chave)", False, str(e))

    # 3. Wi-Fi SoftAP Endpoints
    try:
        st, _, stat = http_post_json("/wifi/config", {
            "ssid": "AegisKey-AP-WebTest",
            "password": "web-admin-pass-123",
            "channel": 11,
            "tx_power_dbm": 18
        })
        ok = (st == 200) and (stat.get("ok") is True) and (stat.get("ssid") == "AegisKey-AP-WebTest")
        log_test("3.1 POST /wifi/config (Configurar SoftAP)", ok, f"ssid={stat.get('ssid')}, ch={stat.get('channel')}")
    except Exception as e:
        log_test("3.1 POST /wifi/config (Configurar SoftAP)", False, str(e))

    try:
        st, _, data = http_get("/wifi/nets")
        nets = json.loads(data.decode("utf-8"))
        ok = (st == 200) and ("nets" in nets) and (len(nets["nets"]) >= 2)
        log_test("3.2 GET /wifi/nets (Redes Conhecidas)", ok, f"nets={nets.get('nets')}")
    except Exception as e:
        log_test("3.2 GET /wifi/nets (Redes Conhecidas)", False, str(e))

    # 4. Bluetooth Low Energy Endpoints
    try:
        st, _, data = http_get("/ble/scan")
        ble = json.loads(data.decode("utf-8"))
        ok = (st == 200) and (len(ble.get("devices", [])) > 0)
        log_test("4.1 GET /ble/scan (Descoberta RF)", ok, f"mac={ble['devices'][0].get('address')}, rssi={ble['devices'][0].get('rssi')}dBm")
    except Exception as e:
        log_test("4.1 GET /ble/scan (Descoberta RF)", False, str(e))

    try:
        st, _, data = http_get("/ble/chars")
        chars = json.loads(data.decode("utf-8"))
        ok = (st == 200) and ("FFF1" in chars.get("chars", {})) and ("FFF4" in chars.get("chars", {}))
        log_test("4.2 GET /ble/chars (GATT Characteristics)", ok, f"service={chars.get('service')}, chars={list(chars.get('chars', {}).keys())}")
    except Exception as e:
        log_test("4.2 GET /ble/chars (GATT Characteristics)", False, str(e))

    try:
        st, _, bresp = http_post_json("/ble/write_notify", {
            "opcode": 0x81,
            "payload_hex": "48454c4c4f5f424c455f47415454"
        })
        ok = (st == 200) and (bresp.get("status") == 0x00) and (bresp.get("fff1_fragments_received") >= 1)
        log_test("4.3 POST /ble/write_notify (PING 0x81 Fragmentado)", ok, f"status=0x{bresp.get('status'):02x}, frags={bresp.get('fff1_fragments_received')}")
    except Exception as e:
        log_test("4.3 POST /ble/write_notify (PING 0x81 Fragmentado)", False, str(e))

    # 5. Hardware Rites & Actions
    try:
        st, _, data = http_post_json("/bridge/pairing_open", {})
        ok = (st == 200) and (data.get("ok") is True) and (data.get("window_s") == 60)
        log_test("5.1 POST /bridge/pairing_open (Janela 60s 0x2F)", ok, f"window={data.get('window_s')}s")
    except Exception as e:
        log_test("5.1 POST /bridge/pairing_open (Janela 60s 0x2F)", False, str(e))

    try:
        st, _, data = http_post_json("/bridge/touch_up", {})
        ok = (st == 200) and (data.get("ok") is True)
        log_test("5.2 POST /bridge/touch_up (Sensor GPIO 0)", ok, f"result={data.get('result')}")
    except Exception as e:
        log_test("5.2 POST /bridge/touch_up (Sensor GPIO 0)", False, str(e))

    try:
        st, _, data = http_post_json("/bridge/pin_auth", {})
        ok = (st == 200) and (data.get("ok") is True)
        log_test("5.3 POST /bridge/pin_auth (PIN Auth 0x2D)", ok, f"result={data.get('result')}")
    except Exception as e:
        log_test("5.3 POST /bridge/pin_auth (PIN Auth 0x2D)", False, str(e))

    try:
        st, _, data = http_post_json("/bridge/wink", {})
        ok = (st == 200) and (data.get("ok") is True)
        log_test("5.4 POST /bridge/wink (Localizar Chave 0x88)", ok, f"wink={data.get('wink')}")
    except Exception as e:
        log_test("5.4 POST /bridge/wink (Localizar Chave 0x88)", False, str(e))

    # 6. Vault & Key Management (Todos os 8 Tipos)
    try:
        st, _, vdata = http_get("/api/vault")
        vault = json.loads(vdata.decode("utf-8"))
        items = vault.get("items", [])
        types_present = set(i.get("type") for i in items)
        has_passkey = "PASSKEY_FIDO" in types_present
        has_btc = "CRYPTO_WALLET_BTC" in types_present
        has_piv = "PIV_SMARTCARD_SLOT" in types_present
        has_aegn = "ENCRYPTED_AEGN_ENVELOPE" in types_present
        ok = (st == 200) and (len(items) >= 6) and has_passkey and has_btc and has_piv and has_aegn
        log_test("6.1 GET /api/vault (Cofre Unificado no Silício)", ok, f"total_items={len(items)}, types={len(types_present)} tipos")
    except Exception as e:
        log_test("6.1 GET /api/vault (Cofre Unificado no Silício)", False, str(e))

    try:
        st, _, cresp = http_post_json("/api/key/create", {
            "type": "PASSKEY_FIDO",
            "label": "web_test_ed25519",
            "curve": -8
        })
        ok = (st == 200) and (cresp.get("ok") is True)
        slot_created = cresp.get("slot")
        log_test("6.2 POST /api/key/create (Criar Passkey Ed25519 0x20)", ok, f"slot={slot_created}, label={cresp.get('label')}")
    except Exception as e:
        slot_created = None
        log_test("6.2 POST /api/key/create (Criar Passkey Ed25519 0x20)", False, str(e))

    try:
        st, _, sresp = http_post_json("/api/key/sign", {
            "slot": slot_created or 1,
            "message": "Challenge_FIDO2_WebAuthn_2026",
            "type": "PASSKEY_FIDO"
        })
        ok = (st == 200) and (sresp.get("ok") is True) and ("signature_hex" in sresp)
        log_test("6.3 POST /api/key/sign (Assinar com Sensor de Toque)", ok, f"sig_len={len(sresp.get('signature_hex', '')) // 2}B, verified={sresp.get('verified')}")
    except Exception as e:
        log_test("6.3 POST /api/key/sign (Assinar com Sensor de Toque)", False, str(e))

    if slot_created:
        try:
            st, _, dresp = http_post_json("/api/key/delete", {"slot": slot_created})
            ok = (st == 200) and (dresp.get("ok") is True)
            log_test("6.4 POST /api/key/delete (Excluir Chave 0x23)", ok, f"slot={slot_created}")
        except Exception as e:
            log_test("6.4 POST /api/key/delete (Excluir Chave 0x23)", False, str(e))

    # 7. Crypto Wallets Web3
    try:
        st, _, wresp = http_get("/api/wallet/list")
        wdata = json.loads(wresp.decode("utf-8"))
        wallets = wdata.get("wallets", [])
        ok = (st == 200) and (len(wallets) >= 1)
        first_addr = wallets[0].get("address")[:16] if wallets else "none"
        log_test("7.1 GET /api/wallet/list (Listar Carteiras On-Device)", ok, f"count={len(wallets)}, first_addr={first_addr}...")
    except Exception as e:
        log_test("7.1 GET /api/wallet/list (Listar Carteiras On-Device)", False, str(e))

    try:
        st, _, nwresp = http_post_json("/api/wallet/create", {
            "network": "ETH",
            "label": "wallet:EthWebDeFi",
            "slot": 15
        })
        ok = (st == 200) and (nwresp.get("ok") is True) and (nwresp.get("address", "").startswith("0x"))
        log_test("7.2 POST /api/wallet/create (Derivar Carteira ETH 0x35)", ok, f"slot={nwresp.get('slot')}, addr={nwresp.get('address')}")
    except Exception as e:
        log_test("7.2 POST /api/wallet/create (Derivar Carteira ETH 0x35)", False, str(e))

    # 8. OATH TOTP On-Chip
    try:
        st, _, odata = http_get("/api/oath/list")
        oath = json.loads(odata.decode("utf-8"))
        accs = oath.get("accounts", [])
        ok = (st == 200) and (len(accs) >= 1) and (accs[0].get("code") is not None)
        log_test("8.1 GET /api/oath/list (Contas e Códigos On-Chip 0x25)", ok, f"accounts={len(accs)}, first_code={accs[0].get('code')} ({accs[0].get('remaining_seconds')}s)")
    except Exception as e:
        log_test("8.1 GET /api/oath/list (Contas e Códigos On-Chip 0x25)", False, str(e))

    try:
        st, _, oresp = http_post_json("/api/oath/put", {
            "account": "WebTest:dev@aegiskey.org",
            "secret": "JBSWY3DPEHPK3PXP",
            "algo": "SHA1",
            "digits": 6
        })
        ok = (st == 200) and (oresp.get("ok") is True)
        log_test("8.2 POST /api/oath/put (Cadastrar Conta OATH 0x24)", ok, f"acc={oresp.get('account')}")
    except Exception as e:
        log_test("8.2 POST /api/oath/put (Cadastrar Conta OATH 0x24)", False, str(e))

    try:
        st, _, cod = http_get("/oath/code?account=WebTest:dev@aegiskey.org")
        cdata = json.loads(cod.decode("utf-8"))
        ok = (st == 200) and (cdata.get("ok") is True) and (cdata.get("code") is not None)
        log_test("8.3 GET /oath/code (Calcular OTP de 6 Dígitos 0x26)", ok, f"code=[{cdata.get('code')}], rem={cdata.get('remaining_seconds')}s")
    except Exception as e:
        log_test("8.3 GET /oath/code (Calcular OTP de 6 Dígitos 0x26)", False, str(e))

    try:
        st, _, delo = http_post_json("/api/oath/delete", {
            "account": "WebTest:dev@aegiskey.org"
        })
        ok = (st == 200) and (delo.get("ok") is True)
        log_test("8.4 POST /api/oath/delete (Excluir Conta OATH 0x27)", ok, f"acc={delo.get('account')}")
    except Exception as e:
        log_test("8.4 POST /api/oath/delete (Excluir Conta OATH 0x27)", False, str(e))

    # 9. PIV Smartcard Enrollment
    try:
        st, _, piv = http_post_json("/api/piv/enroll", {
            "slot": "9A",
            "pin": "123456",
            "puk": "12345678"
        })
        ok = (st == 200) and (piv.get("ok") is True)
        log_test("9.1 POST /api/piv/enroll (Matricular Slot PIV 0x39)", ok, f"slot={piv.get('slot')}, status=0x{piv.get('status', 0):02x}")
    except Exception as e:
        log_test("9.1 POST /api/piv/enroll (Matricular Slot PIV 0x39)", False, str(e))

    # 10. Firmware Live Logs Ring-Buffer
    try:
        st, _, lresp = http_get("/api/fw/logs")
        logs = json.loads(lresp.decode("utf-8"))
        ok = (st == 200) and (logs.get("ok") is True) and (len(logs.get("logs", [])) >= 1)
        log_test("10.1 GET /api/fw/logs (Ring-Buffer de Segurança 0x38)", ok, f"log_lines={len(logs.get('logs', []))}, sample={logs.get('logs', [''])[0]}")
    except Exception as e:
        log_test("10.1 GET /api/fw/logs (Ring-Buffer de Segurança 0x38)", False, str(e))

    # 11. Reset Vault Binding Release
    try:
        st, _, rresp = http_post_json("/api/reset", {})
        ok = (st == 200) and (rresp.get("ok") is True)
        log_test("11.1 POST /api/reset (Liberar Vínculo da Chave 0x2B)", ok, f"status=0x{rresp.get('status', 0):02x}")
    except Exception as e:
        log_test("11.1 POST /api/reset (Liberar Vínculo da Chave 0x2B)", False, str(e))

    # 12. Proximity RSSI & Windows Dynamic Lock Engine
    try:
        st, _, p_stat = http_get("/api/proximity/status")
        p_data = json.loads(p_stat.decode("utf-8"))
        ok = (st == 200) and (p_data.get("ok") is True) and (p_data.get("state") in ("NEAR", "HYSTERESIS", "AWAY", "LOCKED"))
        log_test("12.1 GET /api/proximity/status (Estado da Trava de Proximidade)", ok, f"state={p_data.get('state')}, rssi={p_data.get('rssi_dbm')}dBm, ctr={p_data.get('rolling_ctr')}, tag={p_data.get('beacon_tag_hex')}")
    except Exception as e:
        log_test("12.1 GET /api/proximity/status (Estado da Trava de Proximidade)", False, str(e))

    try:
        st, _, p_cfg = http_post_json("/api/proximity/config", {
            "threshold_dbm": -75,
            "hysteresis_db": 5,
            "lock_secs": 6.0,
            "enforce_windows_lock": False,
        })
        ok = (st == 200) and (p_cfg.get("ok") is True) and (p_cfg.get("threshold_dbm") == -75)
        log_test("12.2 POST /api/proximity/config (Configuração Limiar & Tempo)", ok, f"threshold={p_cfg.get('threshold_dbm')}dBm, lock_secs={p_cfg.get('lock_secs')}s")
    except Exception as e:
        log_test("12.2 POST /api/proximity/config (Configuração Limiar & Tempo)", False, str(e))

    try:
        st, _, p_near = http_post_json("/api/proximity/rssi", {
            "rssi_dbm": -32,
            "elapsed_s": 2.0,
            "source": "android_app",
        })
        ok = (st == 200) and (p_near.get("ok") is True) and (p_near.get("state") == "NEAR") and (p_near.get("locked") is False)
        log_test("12.3 POST /api/proximity/rssi (Amostra Próxima -32 dBm -> NEAR)", ok, f"state={p_near.get('state')}, away_secs={p_near.get('away_secs')}s")
    except Exception as e:
        log_test("12.3 POST /api/proximity/rssi (Amostra Próxima -32 dBm -> NEAR)", False, str(e))

    try:
        st, _, p_lock = http_post_json("/api/proximity/rssi", {
            "rssi_dbm": -90,
            "elapsed_s": 7.0,
            "source": "android_app",
        })
        ok = (st == 200) and (p_lock.get("ok") is True) and (p_lock.get("state") == "LOCKED") and (p_lock.get("locked") is True) and (p_lock.get("lock_triggered") is True)
        log_test("12.4 POST /api/proximity/rssi (Afastamento -90 dBm > 6s -> LOCKED)", ok, f"state={p_lock.get('state')}, locked={p_lock.get('locked')}, triggered={p_lock.get('lock_triggered')}")
    except Exception as e:
        log_test("12.4 POST /api/proximity/rssi (Afastamento -90 dBm > 6s -> LOCKED)", False, str(e))

    try:
        st, _, p_unl = http_post_json("/api/proximity/unlock", {
            "pin": "123456",
        })
        ok = (st == 200) and (p_unl.get("ok") is True) and (p_unl.get("unlocked") is True) and (p_unl.get("state") == "NEAR")
        log_test("12.5 POST /api/proximity/unlock (Toque Físico UP + PIN no ESP32-S3)", ok, f"unlocked={p_unl.get('unlocked')}, touch_up={p_unl.get('touch_up')}, state={p_unl.get('state')}")
    except Exception as e:
        log_test("12.5 POST /api/proximity/unlock (Toque Físico UP + PIN no ESP32-S3)", False, str(e))

    print("=" * 70)
    print(f" RESUMO DA BATERIA: {passed_tests} PASS / {failed_tests} FAIL (Total: {passed_tests + failed_tests})")
    print("=" * 70)
    return 0 if failed_tests == 0 else 1


if __name__ == "__main__":
    sys.exit(run_battery())
