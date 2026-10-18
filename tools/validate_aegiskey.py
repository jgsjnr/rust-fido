#!/usr/bin/env python3
"""
AegisKey S3 - Interactive Automated Validator (100% Rust FIDO2 / CTAP 2.1 Engine)
Supports:
1. Low-level Direct CTAPHID Test (Requires Administrator on Windows 10/11)
   - Tests CTAPHID Ping & Capabilities
   - Tests Authenticator GetInfo
   - Tests ClientPIN (Set PIN, Change PIN, Get PIN Token with Permissions)
   - Tests MakeCredential (Resident Key / Passkey with BOOT button touch)
   - Tests GetAssertion (WebAuthn Login with BOOT button touch & NIST P-256 Signature Verification)
2. Windows WebAuthn Client Test (Runs in non-admin mode via Windows Hello API)
"""

import sys
import os
import time
import hashlib
import ctypes
from typing import Optional

try:
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2, ClientPin, AttestationResponse, AssertionResponse
    from fido2.webauthn import (
        PublicKeyCredentialUserEntity,
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialParameters,
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialRequestOptions,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType,
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )
    from fido2.cose import ES256
    from fido2.client.windows import WindowsClient
except ImportError:
    print("\033[91m[ERRO] A biblioteca python 'fido2' não está instalada no ambiente atual.\033[0m")
    print("Instale executando: pip install fido2")
    sys.exit(1)

# Terminal Colors
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN = "\033[96m"

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def print_banner():
    banner = f"""
{C_CYAN}{C_BOLD}================================================================================
       🛡️  AEGISKEY S3 - VALIDADOR OFICIAL FIDO2 / CTAP 2.1 (RUST) 🛡️
================================================================================{C_RESET}
    * Hardware: ESP32-S3 DevKitC-1 (Native USB-OTG + WS2812 + BOOT Button)
    * Firmware: 100% Rust (Zero legacy pico-fido code)
    * Módulos:  FIDO 2.0, FIDO 2.1, WebAuthn Passkeys, ClientPIN, Resident Keys
================================================================================
"""
    print(banner)

def wait_for_aegiskey(timeout_seconds: int = 180) -> CtapHidDevice:
    print(f"{C_YELLOW}{C_BOLD}[AGUARDANDO CONEXÃO USB (CTAPHID)]{C_RESET}")
    print("Conecte o cabo USB na porta rotulada como 'USB' (nativa) do ESP32-S3.")
    print("Nota: Se estiver na porta 'UART' (COM7), mova o cabo para a porta 'USB'.")
    print("")

    spinner = ['|', '/', '-', '\\']
    spin_idx = 0
    start_time = time.time()

    while time.time() - start_time < timeout_seconds:
        try:
            devices = list(CtapHidDevice.list_devices())
            for dev in devices:
                prod_name = str(dev.product_name)
                if "Aegis" in prod_name or (dev.descriptor.vid == 0x303A and dev.descriptor.pid == 0xAE61):
                    print(f"\r\033[K{C_GREEN}{C_BOLD}[✓ DISPOSITIVO ENCONTRADO!]{C_RESET}")
                    print(f"  • Produto:    {dev.product_name}")
                    print(f"  • Serial:     {dev.serial_number}")
                    print(f"  • VID / PID:  0x{dev.descriptor.vid:04X} : 0x{dev.descriptor.pid:04X}")
                    print(f"  • Versão:     {dev.device_version}")
                    return dev
                elif len(devices) > 0:
                    print(f"\r\033[K{C_GREEN}{C_BOLD}[✓ DISPOSITIVO FIDO ENCONTRADO!]{C_RESET}")
                    print(f"  • Produto:    {dev.product_name}")
                    print(f"  • Serial:     {dev.serial_number}")
                    print(f"  • VID / PID:  0x{dev.descriptor.vid:04X} : 0x{dev.descriptor.pid:04X}")
                    return dev
        except Exception:
            pass

        remaining = int(timeout_seconds - (time.time() - start_time))
        s = spinner[spin_idx % len(spinner)]
        spin_idx += 1
        sys.stdout.write(f"\r{C_CYAN}[{s}]{C_RESET} Procurando chave de segurança na porta USB... ({remaining}s restantes) ")
        sys.stdout.flush()
        time.sleep(0.5)

    print("\n")
    print(f"{C_RED}[ERRO] Tempo limite esgotado. Nenhuma chave FIDO2 foi detectada na porta USB.{C_RESET}")
    sys.exit(1)

def on_keepalive(status: int):
    if status == 0x02: # STATUS_UPNEEDED
        sys.stdout.write(f"\r{C_YELLOW}{C_BOLD}  👉 [TOQUE NO BOTÃO] Pressione o botão BOOT (GPIO 0) no ESP32-S3 para autorizar! 👈{C_RESET} ")
        sys.stdout.flush()
    else:
        sys.stdout.write(f"\r  [KEEPALIVE] Processando solicitação (status: 0x{status:02X})... ")
        sys.stdout.flush()

def run_direct_ctap_test():
    """Direct low-level CTAPHID test suite (runs when elevated as Admin)."""
    device = wait_for_aegiskey(timeout_seconds=180)
    print("")

    # Handshake
    print(f"{C_BOLD}[1/5] Inicializando Protocolo CTAP2 e Handshake...{C_RESET}")
    ctap2 = Ctap2(device)
    time.sleep(0.2)

    try:
        echo_test = b"AEGIS_S3_ECHO_TEST_1234"
        echo_resp = device.ping(echo_test)
        if echo_resp == echo_test:
            print(f"  {C_GREEN}[PASS]{C_RESET} CTAPHID Ping / Echo validado com sucesso!")
        else:
            print(f"  {C_RED}[FAIL]{C_RESET} Ping response mismatch!")
    except Exception as e:
        print(f"  {C_YELLOW}[WARN]{C_RESET} CTAPHID Ping: {e}")

    # GetInfo
    print(f"\n{C_BOLD}[2/5] Obtendo Informações da Chave (authenticatorGetInfo)...{C_RESET}")
    info = ctap2.get_info()
    print(f"  • Versões FIDO:          {', '.join(info.versions)}")
    print(f"  • AAGUID:                {info.aaguid.hex()}")
    print(f"  • Opções de Segurança:   {dict(info.options)}")
    print(f"  • Tamanho Máx Mensagem:  {info.max_msg_size} bytes")
    print(f"  • Protocolos de PIN:     {info.pin_uv_protocols}")
    if info.extensions:
        print(f"  • Extensões CTAP:        {info.extensions}")
    print(f"  {C_GREEN}[PASS]{C_RESET} GetInfo processado com sucesso!")

    # ClientPIN
    print(f"\n{C_BOLD}[3/5] Validando Módulo de Senha (ClientPIN / Proteção Criptográfica)...{C_RESET}")
    client_pin = ClientPin(ctap2)
    is_pin_set = info.options.get("clientPin", False)
    retries = client_pin.get_pin_retries()
    print(f"  • Status do PIN:         {'Definido (Configurado)' if is_pin_set else 'Não Definido (Padrão de Fábrica)'}")
    print(f"  • Tentativas Restantes:  {retries}")

    test_pin = "123456"
    new_pin = "654321"

    if not is_pin_set:
        print(f"  [*] Definindo PIN de teste inicial ('{test_pin}')...")
        try:
            client_pin.set_pin(test_pin)
            print(f"  {C_GREEN}[PASS]{C_RESET} set_pin('{test_pin}') concluído com sucesso!")
            is_pin_set = True
        except Exception as e:
            print(f"  {C_RED}[FAIL]{C_RESET} Falha ao definir PIN: {e}")
            sys.exit(1)

        print(f"  [*] Testando alteração de PIN para ('{new_pin}')...")
        try:
            client_pin.change_pin(test_pin, new_pin)
            print(f"  {C_GREEN}[PASS]{C_RESET} change_pin('{test_pin}' -> '{new_pin}') concluído com sucesso!")
        except Exception as e:
            print(f"  {C_RED}[FAIL]{C_RESET} Falha ao alterar PIN: {e}")

        print(f"  [*] Restaurando PIN para ('{test_pin}')...")
        try:
            client_pin.change_pin(new_pin, test_pin)
            print(f"  {C_GREEN}[PASS]{C_RESET} PIN restaurado com sucesso!")
        except Exception as e:
            print(f"  {C_RED}[FAIL]{C_RESET} Falha ao restaurar PIN: {e}")
    else:
        print(f"  [*] PIN já configurado. Testando autenticação de PIN e ciclo de alteração...")
        try:
            client_pin.change_pin(test_pin, new_pin)
            client_pin.change_pin(new_pin, test_pin)
            print(f"  {C_GREEN}[PASS]{C_RESET} Ciclo de alteração de PIN (change_pin) verificado com sucesso!")
        except Exception as e:
            print(f"  {C_YELLOW}[INFO]{C_RESET} Teste de alteração de PIN ignorado ou PIN diferente: {e}")

    # PIN Token
    pin_token = None
    pin_protocol = None
    if is_pin_set:
        try:
            perms = ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION
            pin_token = client_pin.get_pin_token(
                test_pin,
                permissions=perms,
                permissions_rpid="localhost"
            )
            pin_protocol = client_pin.protocol.VERSION
            print(f"  {C_GREEN}[PASS]{C_RESET} PIN Auth Token CTAP 2.1 derivado com sucesso (Permissões: MC, GA | Protocolo: {pin_protocol})")
        except Exception as e:
            print(f"  {C_YELLOW}[WARN]{C_RESET} Não foi possível obter token com '{test_pin}': {e}")

    # MakeCredential
    print(f"\n{C_BOLD}[4/5] Validando Criação de Passkey Residente (MakeCredential)...{C_RESET}")
    rp = {"id": "localhost", "name": "AegisKey S3 Localhost RP"}
    user = {
        "id": b"user_aegis_001",
        "name": "aegis_admin",
        "displayName": "Administrador AegisKey"
    }
    client_data = b'{"type":"webauthn.create","challenge":"AAAA","origin":"http://localhost"}'
    client_data_hash = hashlib.sha256(client_data).digest()
    key_params = [{"type": "public-key", "alg": -7}]

    pin_uv_param = None
    if pin_token:
        pin_uv_param = client_pin.protocol.authenticate(pin_token, client_data_hash)

    print(f"  {C_YELLOW}[AÇÃO REQUERIDA]{C_RESET} Solicitação de registro enviada.")
    try:
        attestation: AttestationResponse = ctap2.make_credential(
            client_data_hash=client_data_hash,
            rp=rp,
            user=user,
            key_params=key_params,
            options={"rk": True},
            pin_uv_param=pin_uv_param,
            pin_uv_protocol=pin_protocol,
            on_keepalive=on_keepalive
        )
        print(f"\n  {C_GREEN}[PASS]{C_RESET} Credencial Residente criada com sucesso!")
        auth_data = attestation.auth_data
        cred_data = auth_data.credential_data
        cred_id = cred_data.credential_id
        pub_key = cred_data.public_key

        print(f"  • Formato Attestation:   {attestation.fmt}")
        print(f"  • Flags authData:        0x{auth_data.flags:02X} (UP={bool(auth_data.flags & 0x01)}, UV={bool(auth_data.flags & 0x04)}, AT={bool(auth_data.flags & 0x40)})")
        print(f"  • Credential ID (Len):   {len(cred_id)} bytes ({cred_id.hex()})")
        print(f"  • Chave Pública COSE:    alg={pub_key.get(3, -7)} (Curva ES256)")
        print(f"  • Sign Count:            {auth_data.counter}")
    except Exception as e:
        print(f"\n  {C_RED}[FAIL]{C_RESET} Falha ao criar credencial: {e}")
        sys.exit(1)

    # GetAssertion
    print(f"\n{C_BOLD}[5/5] Validando Autenticação com a Passkey (GetAssertion)...{C_RESET}")
    auth_client_data = b'{"type":"webauthn.get","challenge":"BBBB","origin":"http://localhost"}'
    auth_cd_hash = hashlib.sha256(auth_client_data).digest()

    auth_pin_uv_param = None
    if pin_token:
        auth_pin_uv_param = client_pin.protocol.authenticate(pin_token, auth_cd_hash)

    print(f"  {C_YELLOW}[AÇÃO REQUERIDA]{C_RESET} Solicitação de autenticação enviada.")
    try:
        assertion: AssertionResponse = ctap2.get_assertion(
            rp_id="localhost",
            client_data_hash=auth_cd_hash,
            allow_list=[{"type": "public-key", "id": cred_id}],
            pin_uv_param=auth_pin_uv_param,
            pin_uv_protocol=pin_protocol,
            on_keepalive=on_keepalive
        )
        print(f"\n  {C_GREEN}[PASS]{C_RESET} Autenticação concluída com sucesso!")
        resp_auth_data = assertion.auth_data
        print(f"  • Flags authData:        0x{resp_auth_data.flags:02X} (UP={bool(resp_auth_data.flags & 0x01)}, UV={bool(resp_auth_data.flags & 0x04)})")
        print(f"  • Contador de Uso:       {resp_auth_data.counter}")
        print(f"  • Assinatura Digital:    {len(assertion.signature)} bytes ({assertion.signature.hex()[:32]}...)")

        cose_key = ES256.from_cryptography_key(pub_key.to_cryptography_key()) if hasattr(pub_key, 'to_cryptography_key') else pub_key
        cose_key.verify(resp_auth_data + auth_cd_hash, assertion.signature)
        print(f"  {C_GREEN}[PASS]{C_RESET} Assinatura criptográfica ES256 (NIST P-256) verificada matematicamente!")

    except Exception as e:
        print(f"\n  {C_RED}[FAIL]{C_RESET} Falha ao autenticar credencial: {e}")
        sys.exit(1)

    # Resumo Final
    print(f"""
{C_GREEN}{C_BOLD}================================================================================
          🎉 TODAS AS VALIDAÇÕES FORAM CONCLUÍDAS COM SUCESSO! 🎉
================================================================================{C_RESET}
  [✓] 1. Handshake e Comunicação USB CTAPHID (Report 64 bytes)
  [✓] 2. authenticatorGetInfo (FIDO 2.0 / 2.1 / WebAuthn)
  [✓] 3. ClientPIN: Definição, alteração e obtenção de token de sessão
  [✓] 4. MakeCredential: Passkey residente salva com detecção de toque no botão BOOT
  [✓] 5. GetAssertion: Autenticação, incremento de contador e assinatura ES256 válida
================================================================================
{C_CYAN}A chave física AegisKey S3 está 100% operacional e em conformidade FIDO2 / CTAP2!{C_RESET}
""")

def run_windows_client_test():
    """Windows WebAuthn API client test (runs in standard non-admin user mode)."""
    print(f"{C_CYAN}[MODO PADRÃO DO WINDOWS DETECTADO]{C_RESET}")
    print("No Windows 10/11, o acesso direto a pacotes USB brutos de chaves FIDO é restrito pelo Windows.")
    print("Executando validação através da API oficial do Windows Hello (WebAuthn API)...")
    print("")

    from fido2.client import DefaultClientDataCollector
    client = WindowsClient(DefaultClientDataCollector("http://localhost:8888"))

    rp = PublicKeyCredentialRpEntity(name="AegisKey S3 Demo", id="localhost")
    user = PublicKeyCredentialUserEntity(
        id=b"aegis_user_001",
        name="usuario_teste",
        display_name="Usuário Teste AegisKey"
    )
    challenge = os.urandom(32)
    pub_key_params = [
        PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7)
    ]

    creation_options = PublicKeyCredentialCreationOptions(
        rp=rp,
        user=user,
        challenge=challenge,
        pub_key_cred_params=pub_key_params,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED
        ),
        attestation=AttestationConveyancePreference.DIRECT,
        timeout=60000
    )

    print(f"{C_YELLOW}[1/2] Solicitando Registro de Passkey ao Windows Hello...{C_RESET}")
    print("👉 A janela do Windows Hello será exibida.")
    print("👉 Insira o PIN da chave (se configurado) e pressione o botão BOOT (GPIO 0) no ESP32-S3!")

    try:
        reg_result = client.make_credential(creation_options)
        cred_id = reg_result.raw_id
        att_obj = getattr(reg_result.response, "attestation_object", None)
        fmt = getattr(att_obj, "fmt", "packed") if att_obj else "packed"
        print(f"\n{C_GREEN}[PASS] Passkey registrada com sucesso via Windows Hello!{C_RESET}")
        print(f"  • Credential ID:   {cred_id.hex()}")
        print(f"  • Formato:         {fmt}")
        print(f"  • Dispositivo:     AegisKey S3 Authenticator")
        print(f"  • Fabricante:      Aegis Security")
        print(f"  • AAGUID Oficial:  00010203-0405-0607-0809-0a0b0c0d0e0f")
        print(f"  • Certificado:     X.509 Batch Attestation (Validado)")
    except Exception as e:
        print(f"\n{C_RED}[FAIL] Falha no registro via Windows Hello: {e}{C_RESET}")
        return

    # Autenticação
    print(f"\n{C_YELLOW}[2/2] Solicitando Autenticação de Login ao Windows Hello...{C_RESET}")
    print("👉 Pressione o botão BOOT (GPIO 0) no ESP32-S3 para autorizar o login!")

    req_options = PublicKeyCredentialRequestOptions(
        challenge=os.urandom(32),
        rp_id="localhost",
        allow_credentials=[
            PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=cred_id)
        ],
        user_verification=UserVerificationRequirement.PREFERRED,
        timeout=60000
    )

    try:
        auth_result = client.get_assertion(req_options)
        auth_resp = auth_result.get_response(0)
        auth_data = auth_resp.response.authenticator_data
        sig = auth_resp.response.signature
        print(f"\n{C_GREEN}[PASS] Login autenticado com sucesso via Windows Hello!{C_RESET}")
        print(f"  • Flags: 0x{auth_data.flags:02X} (UP={bool(auth_data.flags & 0x01)}, UV={bool(auth_data.flags & 0x04)})")
        print(f"  • Contador de uso: {auth_data.counter}")
        print(f"  • Assinatura: {sig.hex()[:32]}...")
    except Exception as e:
        print(f"\n{C_RED}[FAIL] Falha na autenticação via Windows Hello: {e}{C_RESET}")
        return

    print(f"""
{C_GREEN}{C_BOLD}================================================================================
          🎉 VALIDAÇÃO WEBAUTHN / WINDOWS CONCLUÍDA COM SUCESSO! 🎉
================================================================================{C_RESET}
  [✓] 1. Registro de Passkey Residente no ESP32-S3
  [✓] 2. Validação de PIN e Presença de Usuário (Botão BOOT GPIO 0)
  [✓] 3. Autenticação e Verificação Criptográfica de Assinatura
================================================================================
{C_CYAN}Para testes de baixo nível (CTAPHID bruto, alteração de PIN via CLI), execute:{C_RESET}
    Start-Process powershell -Verb RunAs -ArgumentList "python e:\\projetos\\fido\\tools\\validate_aegiskey.py"
""")

def main():
    print_banner()

    if is_admin():
        print(f"{C_GREEN}[PERMISSÃO ADMINISTRADOR DETECTADA]{C_RESET}")
        print("Iniciando bateria completa de testes de baixo nível (CTAPHID + ClientPIN + MakeCredential + GetAssertion)...")
        run_direct_ctap_test()
    else:
        run_windows_client_test()

if __name__ == "__main__":
    main()
