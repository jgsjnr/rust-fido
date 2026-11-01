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

    try:
        st, headers, body = http_get("/architecture", headers={"Accept": "text/html"})
        html = body.decode("utf-8")
        ok = (st == 200) and ("AegisKey Architecture Map" in html) and ("freertos_route.rs" in html)
        log_test("1.3 GET /architecture (Mapa Interativo da Arquitetura)", ok, f"status={st}, len={len(body)}B")
    except Exception as e:
        log_test("1.3 GET /architecture (Mapa Interativo da Arquitetura)", False, str(e))

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

    # Ensure Secure Guard is provisioned and unlocked with PIN 123456 before Vault & Key operations
    try:
        st_sg, _, sg_raw = http_get("/api/secure-guard/status")
        sg_st = json.loads(sg_raw.decode("utf-8"))
        if not sg_st.get("provisioned", False):
            http_post_json("/api/secure-guard/provision", {
                "pin": "123456",
                "policy": {"test_mode_non_destructive_wipe": True}
            })
        elif not sg_st.get("unlocked", False):
            unlocked = False
            for test_pin in ("849201", "123456", "112233", "654321"):
                try:
                    st_u, _, _ = http_post_json("/api/secure-guard/unlock", {"pin": test_pin})
                    if st_u == 200:
                        unlocked = True
                        break
                except Exception:
                    pass
            if not unlocked:
                http_post_json("/api/reset", {})
                http_post_json("/api/secure-guard/provision", {
                    "pin": "123456",
                    "policy": {"test_mode_non_destructive_wipe": True}
                })
    except Exception as e:
        print(f"Notice setting up Secure Guard: {e}")

    # 6. Vault & Key Management
    try:
        st, _, vdata = http_get("/api/vault")
        vault = json.loads(vdata.decode("utf-8"))
        items = vault.get("items", [])
        ok = (st == 200) and (vault.get("ok") is True) and isinstance(items, list)
        log_test("6.1 GET /api/vault (Cofre Unificado no Silício)", ok, f"total_items={len(items)}")
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
            st, _, vdata2 = http_get("/api/vault")
            v2 = json.loads(vdata2.decode("utf-8"))
            items2 = v2.get("items", [])
            found_created = any(i.get("slotId") == slot_created for i in items2)
            ok = (st == 200) and found_created
            log_test("6.3b GET /api/vault (Verificar Chave Real no Cofre)", ok, f"encontrada={found_created}, total={len(items2)}")
        except Exception as e:
            log_test("6.3b GET /api/vault (Verificar Chave Real no Cofre)", False, str(e))

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
        ok = (st == 200) and (wdata.get("ok") is True) and isinstance(wallets, list)
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
        ok = (st == 200) and (oath.get("ok") is True) and isinstance(accs, list)
        log_test("8.1 GET /api/oath/list (Contas e Códigos On-Chip 0x25)", ok, f"accounts={len(accs)}")
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

    # 13. Secure Guard Zero-Trust On-Device Authority Vault
    recovery_code_saved = ""
    try:
        st, _, sg_stat = http_get("/api/secure-guard/status")
        stat_data = json.loads(sg_stat.decode("utf-8"))
        ok = (st == 200) and (stat_data.get("ok") is True) and ("state" in stat_data)
        log_test("13.1 GET /api/secure-guard/status (Telemetria Inicial)", ok, f"state={stat_data.get('state_name')}, prov={stat_data.get('provisioned')}")
    except Exception as e:
        log_test("13.1 GET /api/secure-guard/status (Telemetria Inicial)", False, str(e))

    try:
        st, _, sg_prov = http_post_json("/api/secure-guard/provision", {
            "pin": "123456",
            "policy": {
                "wipe_on_5_failures": False,
                "protect_keys_and_aegn": True,
                "test_mode_non_destructive_wipe": True,
            }
        })
        recovery_code_saved = sg_prov.get("recovery_code", "")
        ok = (st == 200) and (sg_prov.get("ok") is True) and (sg_prov.get("unlocked") is True) and (len(recovery_code_saved) >= 16)
        log_test("13.2 POST /api/secure-guard/provision (Provisionar PIN 123456 + Recovery Code)", ok, f"state={sg_prov.get('state')}, rc={recovery_code_saved}")
    except Exception as e:
        log_test("13.2 POST /api/secure-guard/provision (Provisionar PIN 123456 + Recovery Code)", False, str(e))

    try:
        st, _, sg_cfg = http_post_json("/api/secure-guard/config", {
            "wipe_on_5_failures": False,
            "session_duration_ms": 300000,
            "inactivity_timeout_ms": 120000,
            "protect_keys_and_aegn": True,
            "protect_oath": False,
            "test_mode_non_destructive_wipe": True,
        })
        ok = (st == 200) and (sg_cfg.get("ok") is True) and (sg_cfg.get("policy", {}).get("test_mode_non_destructive_wipe") is True)
        log_test("13.3 POST /api/secure-guard/config (Atualizar Políticas NVS)", ok, f"policy={sg_cfg.get('policy')}")
    except Exception as e:
        log_test("13.3 POST /api/secure-guard/config (Atualizar Políticas NVS)", False, str(e))

    try:
        st, _, sg_lock = http_post_json("/api/secure-guard/lock", {})
        ok = (st == 200) and (sg_lock.get("ok") is True) and (sg_lock.get("state") == 2)  # STATE_LOCKED = 2
        log_test("13.4 POST /api/secure-guard/lock (Bloquear Sessão Imediata)", ok, f"state={sg_lock.get('state')}, locked={sg_lock.get('locked')}")
    except Exception as e:
        log_test("13.4 POST /api/secure-guard/lock (Bloquear Sessão Imediata)", False, str(e))

    # 13.5 Fail-Closed Barrier Test: Wallets must be blocked with HTTP 403 when Locked
    try:
        wallet_blocked = False
        try:
            http_get("/api/wallet/list")
        except urllib.error.HTTPError as he:
            wallet_blocked = (he.code == 403)
        log_test("13.5 GET /api/wallet/list (Fail-Closed Barrier: 403 quando Locked)", wallet_blocked, "Bloqueado com sucesso (403 CTAP2_ERR_PIN_REQUIRED)")
    except Exception as e:
        log_test("13.5 GET /api/wallet/list (Fail-Closed Barrier: 403 quando Locked)", False, str(e))

    # 13.6 Wrong PIN Attempt -> Rate Limiting / Decrement attempts
    try:
        wrong_rejected = False
        try:
            http_post_json("/api/secure-guard/unlock", {"pin": "999999"})
        except urllib.error.HTTPError as he:
            wrong_rejected = (he.code == 401)
        log_test("13.6 POST /api/secure-guard/unlock (PIN Incorreto -> 401 / Penalidade)", wrong_rejected, "PIN incorreto rejeitado corretamente")
    except Exception as e:
        log_test("13.6 POST /api/secure-guard/unlock (PIN Incorreto -> 401 / Penalidade)", False, str(e))

    # Wait for rate limit backoff (1s for first wrong attempt)
    time.sleep(1.2)

    # 13.7 Correct PIN Unlock
    try:
        st, _, sg_unl = http_post_json("/api/secure-guard/unlock", {"pin": "123456"})
        ok = (st == 200) and (sg_unl.get("ok") is True) and (sg_unl.get("state") == 4)  # STATE_UNLOCKED = 4
        log_test("13.7 POST /api/secure-guard/unlock (PIN Correto -> Desbloqueado)", ok, f"state={sg_unl.get('state')}, attempts_reset={sg_unl.get('failed_attempts')}")
    except Exception as e:
        log_test("13.7 POST /api/secure-guard/unlock (PIN Correto -> Desbloqueado)", False, str(e))

    # 13.8 Wallet Unblocked Test: When Unlocked, wallets must be accessible
    try:
        st, _, w_data = http_get("/api/wallet/list")
        wallets = json.loads(w_data.decode("utf-8"))
        ok = (st == 200) and (wallets.get("ok") is True)
        log_test("13.8 GET /api/wallet/list (Acesso Liberado quando Unlocked)", ok, f"wallets_count={len(wallets.get('wallets', []))}")
    except Exception as e:
        log_test("13.8 GET /api/wallet/list (Acesso Liberado quando Unlocked)", False, str(e))

    # 13.9 Change PIN
    try:
        st, _, sg_chg = http_post_json("/api/secure-guard/change-pin", {
            "current_pin": "123456",
            "new_pin": "654321",
        })
        ok = (st == 200) and (sg_chg.get("ok") is True) and (sg_chg.get("status") == "pin_changed")
        log_test("13.9 POST /api/secure-guard/change-pin (Troca Autenticada de PIN)", ok, f"status={sg_chg.get('status')}")
    except Exception as e:
        log_test("13.9 POST /api/secure-guard/change-pin (Troca Autenticada de PIN)", False, str(e))

    # 13.10 Emergency Recovery with saved recovery code
    try:
        st, _, sg_rec = http_post_json("/api/secure-guard/recover", {
            "recovery_code": recovery_code_saved,
            "new_pin": "112233",
        })
        ok = (st == 200) and (sg_rec.get("ok") is True) and (sg_rec.get("status") == "recovered")
        log_test("13.10 POST /api/secure-guard/recover (Recuperação de Emergência)", ok, f"status={sg_rec.get('status')}, new_rc={sg_rec.get('new_recovery_code')}")
    except Exception as e:
        log_test("13.10 POST /api/secure-guard/recover (Recuperação de Emergência)", False, str(e))

    # 13.11 Selective Wipe Test
    try:
        st, _, sg_wipe = http_post_json("/api/secure-guard/wipe-selective", {
            "scope": 0,
            "confirmation": "CONFIRM_WIPE_AEGIS_GUARD",
        })
        ok = (st == 200) and (sg_wipe.get("ok") is True) and (sg_wipe.get("state") == 0)  # STATE_UNPROVISIONED = 0
        log_test("13.11 POST /api/secure-guard/wipe-selective (Wipe Seguro / Simulado)", ok, f"state={sg_wipe.get('state')}, simulated={sg_wipe.get('simulated')}")
    except Exception as e:
        log_test("13.11 POST /api/secure-guard/wipe-selective (Wipe Seguro / Simulado)", False, str(e))

    # Teardown / Restore unlocked state with PIN 123456 for repeatable runs
    try:
        http_post_json("/api/secure-guard/provision", {
            "pin": "123456",
            "policy": {
                "wipe_on_5_failures": False,
                "protect_keys_and_aegn": True,
                "test_mode_non_destructive_wipe": True,
            }
        })
    except Exception:
        pass

    print("=" * 70)
    print(f" RESUMO DA BATERIA: {passed_tests} PASS / {failed_tests} FAIL (Total: {passed_tests + failed_tests})")
    print("=" * 70)
    return 0 if failed_tests == 0 else 1


if __name__ == "__main__":
    sys.exit(run_battery())
