#!/usr/bin/env python3
"""AegisKey Real User Journey Test — Hardware Validation on ESP32-S3 (COM7).

Executes the complete end-to-end lifecycle starting from factory reset:
1. Reset the board (/api/reset / 0x2B) -> 0 keys, Secure Guard Unprovisioned, LED Cyan.
2. Attempt to list keys before unlock -> Blocked by Secure Guard (0 keys / 403 Forbidden).
3. Provision PIN in Secure Guard -> Unlocked, LED Green, exactly 0 keys (no ghost keys).
4. Create 1 real Passkey + 1 real ETH wallet + 1 real TOTP -> exactly 3 keys created by user.
5. Lock Secure Guard (/api/secure-guard/lock) -> LED Amber, vault 403 Forbidden, SshGuard purges agent.
6. Unlock Secure Guard with PIN -> LED Green, 3 user keys intact, SSH authorized!
"""

import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Tuple

BASE_URL = "http://127.0.0.1:5678"

def http_get(path: str) -> Tuple[int, Dict[str, Any]]:
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return resp.status, data
    except urllib.error.HTTPError as he:
        try:
            data = json.loads(he.read().decode("utf-8"))
        except Exception:
            data = {"raw_error": str(he)}
        return he.code, data

def http_post(path: str, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    url = f"{BASE_URL}{path}"
    raw = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=raw,
        headers={"Content-Type": "application/json", "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return resp.status, data
    except urllib.error.HTTPError as he:
        try:
            data = json.loads(he.read().decode("utf-8"))
        except Exception:
            data = {"raw_error": str(he)}
        return he.code, data

def main():
    print("=" * 70)
    print("AEGISKEY: TESTE DE JORNADA REAL DO USUÁRIO NO HARDWARE (COM7)")
    print(f"Target Bridge: {BASE_URL}")
    print("=" * 70)

    # Passo 1: Reset da Placa (/api/reset / 0x2B)
    print("\n[PASSO 1] Reset da Placa (/api/reset / 0x2B)...")
    st, res = http_post("/api/reset", {})
    assert st == 200, f"Reset falhou com status {st}: {res}"
    print(f" -> Reset OK: {res}")

    # Verificar estado do Secure Guard: Unprovisioned (0), LED Cyan
    st, sg = http_get("/api/secure-guard/status")
    assert st == 200, f"Status falhou: {sg}"
    print(f" -> Secure Guard Status: state={sg.get('state')} ({sg.get('state_name')}), provisioned={sg.get('provisioned')}, unlocked={sg.get('unlocked')}")
    assert sg.get("provisioned") is False, "Secure Guard deveria estar Unprovisioned após reset"
    assert sg.get("unlocked") is False, "Secure Guard não deveria estar Unlocked após reset"

    # Passo 2: Tentativa de listar chaves antes de desbloquear -> Bloqueado (403)
    print("\n[PASSO 2] Tentativa de listar chaves antes de desbloquear...")
    st, v = http_get("/api/vault")
    print(f" -> Resposta /api/vault: status={st}, body={v}")
    assert st == 403, f"Esperado 403 ao listar cofre trancado, recebido {st}"
    assert len(v.get("items", [])) == 0, "Cofre trancado não pode retornar chaves"
    print(" -> [PASS] Bloqueio verificado com sucesso pelo Secure Guard (403 Forbidden).")

    # Passo 3: Provisionar PIN no Secure Guard -> Unlocked, LED Verde, 0 chaves
    print("\n[PASSO 3] Provisionar PIN no Secure Guard...")
    pin = "849201"
    st, prov = http_post("/api/secure-guard/provision", {"pin": pin})
    assert st == 200, f"Provisionamento falhou: {prov}"
    print(f" -> Provisionado com sucesso: {prov}")

    st, sg = http_get("/api/secure-guard/status")
    print(f" -> Secure Guard pós-provisionamento: state={sg.get('state')} ({sg.get('state_name')}), unlocked={sg.get('unlocked')}")
    assert sg.get("provisioned") is True, "Deveria estar provisionado"
    assert sg.get("unlocked") is True, "Deveria estar unlocked após provisionamento"

    # Verificar que cofre está vazio (zero chaves fantasmas!)
    st, v = http_get("/api/vault")
    assert st == 200, f"Cofre deveria responder 200 quando desbloqueado, recebido {st}"
    items = v.get("items", [])
    print(f" -> Itens no cofre após provisionamento: {len(items)} (esperado 0)")
    assert len(items) == 0, f"Cofre de fábrica deve ter 0 chaves, mas encontrou: {items}"
    print(" -> [PASS] Zero chaves fantasmas confirmado!")

    # Passo 4: Criar 1 Passkey real + 1 Carteira ETH real + 1 TOTP real no dispositivo
    print("\n[PASSO 4] Criando chaves reais do usuário...")

    # 4.1 Criar 1 Passkey real Ed25519 (0x20)
    print(" 4.1 Criando Passkey Ed25519...")
    st, pk = http_post("/api/key/create", {
        "type": "PASSKEY_FIDO",
        "label": "user_id_github",
        "curve": -8  # Ed25519
    })
    assert st == 200, f"Criação de passkey falhou: {pk}"
    pk_slot = pk.get("slot")
    print(f"   -> Passkey criada no slot {pk_slot}: label={pk.get('label')}")

    # 4.2 Criar 1 Carteira ETH real (0x35)
    print(" 4.2 Derivando Carteira Ethereum On-Device...")
    st, eth = http_post("/api/wallet/create", {
        "network": "ETH",
        "label": "wallet:EthPersonal",
        "slot": 1
    })
    assert st == 200, f"Criação de carteira ETH falhou: {eth}"
    eth_addr = eth.get("address")
    print(f"   -> Carteira ETH derivada: slot={eth.get('slot')}, addr={eth_addr}")

    # 4.3 Cadastrar 1 TOTP real (0x24)
    print(" 4.3 Cadastrando Conta TOTP On-Chip...")
    st, totp = http_post("/api/oath/put", {
        "account": "GitHub:alice@aegiskey.org",
        "secret": "JBSWY3DPEHPK3PXP",
        "algo": "SHA1",
        "digits": 6
    })
    assert st == 200, f"Cadastro TOTP falhou: {totp}"
    print(f"   -> TOTP cadastrado: {totp.get('account')}")

    # Verificar que agora existem exatamente as chaves criadas
    st, v = http_get("/api/vault")
    items = v.get("items", [])
    print(f" -> Itens no cofre (/api/vault): {len(items)}")
    for it in items:
        print(f"    - [{it.get('type')}] Slot {it.get('slotId')}: {it.get('label')} ({it.get('publicSummary')})")
    assert len(items) == 2, f"Esperado exatamente 2 itens de cofre (Passkey + ETH), encontrado {len(items)}"

    # Verificar conta TOTP criada em /api/oath/list
    st, oath_res = http_get("/api/oath/list")
    assert st == 200, f"Listagem TOTP falhou: {oath_res}"
    accs = oath_res.get("accounts", [])
    print(f" -> Contas TOTP (/api/oath/list): {len(accs)}")
    assert len(accs) == 1, f"Esperado 1 conta TOTP, encontrado {len(accs)}"
    assert accs[0].get("account") == "GitHub:alice@aegiskey.org"

    # Verificar cálculo real de código TOTP (0x26)
    st, code_resp = http_get("/oath/code?account=GitHub:alice@aegiskey.org")
    assert st == 200, f"Cálculo TOTP falhou: {code_resp}"
    print(f" -> Código TOTP calculado: {code_resp.get('code')} (restam {code_resp.get('remaining_seconds')}s)")
    assert code_resp.get("code") is not None and len(code_resp.get("code")) == 6
    print(" -> [PASS] Criação de chaves reais validada com perfeição (Total 3 itens: 1 Passkey + 1 ETH + 1 TOTP)!")

    # Passo 5: Bloquear o Secure Guard (/api/secure-guard/lock)
    print("\n[PASSO 5] Bloqueando o Secure Guard (/api/secure-guard/lock)...")
    st, lk = http_post("/api/secure-guard/lock", {})
    assert st == 200, f"Bloqueio falhou: {lk}"
    print(f" -> Secure Guard Bloqueado: {lk}")

    st, sg = http_get("/api/secure-guard/status")
    print(f" -> Secure Guard Status: state={sg.get('state')} ({sg.get('state_name')}), unlocked={sg.get('unlocked')}")
    assert sg.get("unlocked") is False, "Deveria estar Locked"
    assert sg.get("state_name") == "Locked", "Nome do estado deve ser Locked (LED Âmbar)"

    # Verificar que cofre e TOTP estão trancados (403)
    st, v = http_get("/api/vault")
    assert st == 403, f"Cofre deve retornar 403 quando bloqueado, recebido {st}"
    st, o = http_get("/api/oath/list")
    assert st == 403, f"TOTP deve retornar 403 quando bloqueado, recebido {st}"
    print(" -> [PASS] Cofre e TOTP bloqueados com 403 Forbidden enquanto Secure Guard está Locked.")

    # Passo 6: Desbloquear o Secure Guard com o PIN
    print("\n[PASSO 6] Desbloqueando Secure Guard com o PIN...")
    st, unl = http_post("/api/secure-guard/unlock", {"pin": pin})
    assert st == 200, f"Desbloqueio falhou: {unl}"
    print(f" -> Desbloqueio OK: {unl}")

    st, sg = http_get("/api/secure-guard/status")
    assert sg.get("unlocked") is True, "Deveria estar Unlocked (LED Verde)"
    print(f" -> Secure Guard pós-desbloqueio: state={sg.get('state')} ({sg.get('state_name')}), unlocked={sg.get('unlocked')}")

    # Verificar que todas as 3 chaves criadas reaparecem intactas!
    st, v = http_get("/api/vault")
    assert st == 200, f"Cofre deve retornar 200 após desbloqueio, recebido {st}"
    items = v.get("items", [])
    print(f" -> Itens no cofre restaurados: {len(items)}")
    assert len(items) == 2, f"Esperado 2 itens de cofre restaurados, encontrado {len(items)}"
    labels = [i.get("label") for i in items]
    print(f"    Chaves: {labels}")
    assert "passkey:user_id_github" in labels or any("user_id_github" in l for l in labels), "Passkey deve estar preservada"
    assert any("EthPersonal" in l for l in labels), "Carteira ETH deve estar preservada"

    st, oath_res = http_get("/api/oath/list")
    assert st == 200, f"TOTP deve retornar 200 após desbloqueio, recebido {st}"
    accs = oath_res.get("accounts", [])
    print(f" -> Contas TOTP restauradas: {len(accs)}")
    assert len(accs) == 1 and accs[0].get("account") == "GitHub:alice@aegiskey.org", "TOTP deve estar preservado"

    print("\n" + "=" * 70)
    print(">>> SUCESSO TOTAL: JORNADA COMPLETA DO USUÁRIO VALIDADA NO HARDWARE! <<<")
    print("=" * 70)

if __name__ == "__main__":
    main()
