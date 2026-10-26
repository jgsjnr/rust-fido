# Plano de Testes e Matriz de Homologação — AegisKey Secure Guard

> **Projeto:** AegisKey FIDO2 & Multi-Protocol Hardware Authenticator  
> **Subsistema:** Secure Guard (Validação de Confiabilidade, Segurança e Hardware)  
> **Status:** Documento Normativo de Qualidade e Plano de Homologação (Seção 12 / 14)  
> **Data:** 25 de Outubro de 2026  
> **Ambientes de Teste:** Host Local (Cargo/Rust), Emulador Android (`emulator-5554`), Bridge Hardware (`host_hardware_android_bridge.py`), e Silício Real ESP32-S3 (`COM7` / USB `0x303A:0xAE61`)  

---

## 1. Visão Geral da Estratégia de Homologação

A validação do subsistema **Secure Guard** segue uma abordagem piramidal de 5 camadas concêntricas, assegurando cobertura matemática e operacional desde as operações aritméticas do KDF até o comportamento físico dos sinais elétricos no microcontrolador ESP32-S3:

```
                      +------------------------------------------+
                     /   12.5 HARDWARE-IN-THE-LOOP (COM7 / USB)   \
                    +----------------------------------------------+
                   /      12.4 ANDROID E2E & JORNADAS (EMULATOR)    \
                  +--------------------------------------------------+
                 /        12.3 TESTES DE SEGURANÇA E ABUSO / FUZZING  \
                +------------------------------------------------------+
               /         12.2 TESTES DE INTEGRAÇÃO MULTICRATES & BRIDGE \
              +----------------------------------------------------------+
             /           12.1 TESTES UNITÁRIOS RUST CORE & FIRMWARE       \
            +--------------------------------------------------------------+
```

---

## 2. Seção 12.1: Testes Unitários Rust (Core e Firmware)

Validação pura em nível de funções e estruturas isoladas (`no_std` + `alloc`), rodando na máquina de desenvolvimento via `cargo test`.

### 2.1. Suíte `aegis-fido-core::secure_guard`

| Identificador | Caso de Teste | Módulo / Função | Condição de Entrada | Resultado Esperado |
|---|---|---|---|---|
| **UNIT-CORE-01** | Validação de Tamanho de PIN | `policy::validate_pin` | PIN com 2 bytes (`b"12"`) e com 18 bytes. | Retorna erro `PinTooShort` e `PinTooLong` respectivamente. |
| **UNIT-CORE-02** | Rejeição de PIN Trivial Repetido | `policy::validate_pin` | PINs `b"0000"`, `b"1111"`, `b"aaaa"`. | Rejeitado com `SecureGuardError::TrivialPinRejected`. |
| **UNIT-CORE-03** | Rejeição de PIN Sequencial | `policy::validate_pin` | PINs ascendentes (`"1234"`, `"2345"`) e descendentes (`"4321"`, `"6543"`). | Rejeitado com `SecureGuardError::TrivialPinRejected`. |
| **UNIT-CORE-04** | Aceite de PIN Válido Não-Trivial | `policy::validate_pin` | PINs `b"4927"`, `b"8193"`, `b"a1b2c3"`. | Retorna `Ok(())`. |
| **UNIT-CORE-05** | Cálculo de Backoff Progressivo | `policy::compute_backoff_ms`| Avaliação dos índices de falha `0..=4`. | `0`->0ms, `1`->0ms, `2`->2.000ms, `3`->5.000ms, `4`->15.000ms. |
| **UNIT-CORE-06** | Consistência RFC 8018 PBKDF2 | `crypto::pbkdf2_hmac_sha256`| Vetores com $c=1, 2, 3$ contra HMAC-SHA256 incremental. | Blocos $U_1, U_2, U_3$ e $T_1$ satisfazem estritamente a especificação. |
| **UNIT-CORE-07** | Comparação em Tempo Constante | `crypto::constant_time_eq_32`| Buffers idênticos e buffers divergentes no byte 0, 15 e 31. | `true` para idênticos; `false` para qualquer discrepância com branch invariante. |
| **UNIT-CORE-08** | Verificação de Integridade CRC32 | `crypto::crc32` | Vetor de teste ASCII `"123456789"`. | Retorna exatamente `0xCBF43926`. |
| **UNIT-CORE-09** | FSM: Matriz de Transições Válidas | `state::can_transition_to` | Avaliação combinatória dos 10 estados canônicos. | Transições legais retornam `true`; saltos ilegais retornam `false`. |
| **UNIT-CORE-10** | FSM: Transição Universal p/ ErrorLocked| `state::can_transition_to` | Qualquer um dos 10 estados transitando para `ErrorLocked`. | Retorna `true` (capacidade de contenção fail-closed). |
| **UNIT-CORE-11** | Serialização Roundtrip do Record | `persistence::to_bytes / from_bytes`| Registro completo com dados de política e verificadores. | Array de 256 bytes desserializa com igualdade absoluta (`assert_eq!(record, parsed)`). |
| **UNIT-CORE-12** | Corrupção de CRC32 no Record | `persistence::from_bytes` | Alteração de 1 bit no byte 20 do payload. | Falha com `SecureGuardError::PersistenceCorrupted("CRC32 mismatch")`. |
| **UNIT-CORE-13** | Corrupção de Magic Header | `persistence::from_bytes` | Byte 0 alterado para `b'X'`. | Falha com `SecureGuardError::PersistenceCorrupted("Invalid magic bytes")`. |
| **UNIT-CORE-14** | Ring Buffer de Auditoria: Sobrescrita | `audit::AuditRingBuffer` | Inserção de 37 eventos em fila de capacidade 32. | Buffer armazena os 32 eventos mais recentes (`len() == 32`). |
| **UNIT-CORE-15** | Provisionamento e Bloqueio Inicial | `engine::provision_pin` | Dispositivo de fábrica recebe PIN `"4927"`. | Estado transita de `Unprovisioned` para `Locked`. Retorna recovery code de 16B. |
| **UNIT-CORE-16** | Desbloqueio e Expiração de Sessão | `engine::unlock_with_pin / check_and_touch_session` | PIN correto no tempo $T_0$; avanço de tempo para $T_0 + 130s$ (> 120s inatividade). | Sessão transita autonomamente de `Unlocked` para `Locked`. |

### 2.2. Comandos de Execução
```powershell
# Execução da suíte completa de testes unitários do Core
cargo test -p aegis-fido-core --lib secure_guard

# Verificação de cobertura e ausência de warnings com Clippy
cargo clippy -p aegis-fido-core -- -D warnings
```

---

## 3. Seção 12.2: Testes de Integração (App <-> Bridge <-> Firmware)

Verifica a comunicação entre os componentes de software através das fronteiras de serialização, bindings UniFFI e barreiras de autorização de opcodes.

### 3.1. Casos de Teste de Integração

| Identificador | Cenário de Teste | Componentes Envolvidos | Procedimento de Verificação |
|---|---|---|---|
| **INT-01** | Consulta de Status Não-Autenticado | `Host Bridge` <-> `freertos_route` <-> `SecureGuardEngine` | Envio de `0x3A OP_SECURE_GUARD_STATUS`. Valida resposta com estado, contadores e políticas em CBOR válido. |
| **INT-02** | Barreira de Carteira Cripto (`Locked`) | `universal-device-sdk` <-> `freertos_route` | Chamar `0x35 OP_WALLET_GEN` com o dispositivo em `Locked`. A requisição deve ser interceptada e rejeitada com `0x27 CTAP2_ERR_PIN_REQUIRED`. |
| **INT-03** | Coexistência FIDO2 WebAuthn (`Locked`)| `CtapEngine` <-> `SecureGuardEngine` | Executar `MakeCredential` (0x01) e `GetAssertion` (0x02) enquanto o Secure Guard está `Locked`. As operações FIDO2 devem ter sucesso sem exigir PIN do Secure Guard. |
| **INT-04** | Coexistência FIDO2 em `RecoveryRequired` | `CtapEngine` <-> `SecureGuardEngine` | Com o Secure Guard bloqueado permanentemente por 5 falhas, solicitar asserção WebAuthn. O login WebAuthn deve ser concluído com sucesso. |
| **INT-05** | Ciclo Completo de Desbloqueio e Uso | `Android App` <-> `uniffi-bridge` <-> `Firmware` | 1. Envio de `0x3B unlock`; 2. Verificação de status `Unlocked`; 3. Execução de `0x35 OP_WALLET_GEN` (gera endereço BTC com sucesso); 4. Envio de `0x3C lock`. |
| **INT-06** | Alteração Transacional de PIN | `Universal SDK` <-> `Firmware` | Envio de `0x3B change_pin` com PIN atual correto e novo PIN. Testa que o PIN anterior é invalidado e o novo passa a autenticar. |

---

## 4. Seção 12.3: Testes de Segurança, Abuso e Resiliência (Fuzzing)

Testes deliberados de injeção de comportamento anômalo e ataques físicos simulados para comprovar os requisitos da modelagem STRIDE.

### 4.1. Bateria de Abuso e Evasão

```
+-------------------------------------------------------------------------------------------------+
|                                 FLUXO DO TESTE DE EVASÃO POR REBOOT                             |
+-------------------------------------------------------------------------------------------------+
|                                                                                                 |
|   1. Dispositivo no estado Locked (0 falhas)                                                    |
|   2. Submete PIN Incorreto -> Falha 1 (NVS commita failed_attempts = 1)                         |
|   3. Submete PIN Incorreto -> Falha 2 (NVS commita failed_attempts = 2, Backoff 2s)             |
|   4. Submete PIN Incorreto -> Falha 3 (NVS commita failed_attempts = 3, Backoff 5s)             |
|   5. Submete PIN Incorreto -> Falha 4 (NVS commita failed_attempts = 4, Backoff 15s)            |
|   6. CORTE BRUSCO DE ALIMENTAÇÃO USB (Hard Power-Off / Reset da Placa)                          |
|   7. Religamento e Leitura Imediata de Status (0x3A)                                            |
|      --> ASSERÇÃO: failed_attempts DEVE SER EXATAMENTE 4 (Não pode ter resetado para 0).        |
|   8. Submete PIN Incorreto -> Falha 5                                                           |
|      --> ASSERÇÃO: Transita imediatamente para RecoveryRequired ou WipePending.                 |
+-------------------------------------------------------------------------------------------------+
```

| Identificador | Teste de Segurança | Vetor de Abuso | Critério Estrito de Aceite (Pass/Fail) |
|---|---|---|---|
| **SEC-01** | Tentativa de Envio Pré-Backoff | Enviar PIN incorreto no milissegundo 500 durante uma janela de penalidade de 2.000 ms. | **PASS:** Resposta imediata `0x3A CTAP2_ERR_TOO_MANY_PIN_ATTEMPTS` sem executar KDF na CPU. |
| **SEC-02** | Evasão de Contador por Reboot | Executar 4 tentativas incorretas seguidas de reset elétrico por chaveamento de VBUS. | **PASS:** Ao inicializar, o contador reporta 4 falhas e impõe penalidade de rate-limit persistida. |
| **SEC-03** | 5ª Falha Consecutiva e Lockout | Executar a 5ª tentativa consecutiva incorreta com política `wipe_on_5_failures = false`. | **PASS:** Motor transita para `RecoveryRequired`; qualquer tentativa de PIN subsequente é sumariamente bloqueada. |
| **SEC-04** | Wipe Seletivo Isolado | Executar a 5ª falha consecutiva com `wipe_on_5_failures = true`. | **PASS:** Carteiras Web3 apagadas da Flash; credenciais FIDO2 permanecem 100% íntegras e autenticando. |
| **SEC-05** | Simulação Não-Destrutiva | Acionar wipe com `test_mode_non_destructive_wipe = true`. | **PASS:** `last_wipe_simulated` reporta `true`; chaves reais em Flash não são destruídas. |
| **SEC-06** | Recuperação com Código Válido | Enviar código de recuperação de 16 bytes legítimo com novo PIN. | **PASS:** Dispositivo retorna para `Locked`, falhas zeradas e código de recuperação rotacionado. |
| **SEC-07** | Replay de Código de Recuperação | Reutilizar o código de recuperação anterior após uma recuperação bem-sucedida. | **PASS:** Rejeição com `SecureGuardError::InvalidRecoveryCode`. Códigos são estritamente descartáveis. |

---

## 5. Seção 12.4: Testes de Interface e Experiência Android

Cobertura completa da camada de apresentação em Jetpack Compose e casos de uso de negócio através de testes unitários (Robolectric) e testes instrumentados no emulador Android (`emulator-5554`).

### 5.1. As 13 Jornadas de Tela e Estados Homologados

```
[ JORNADAS DE EXPERIÊNCIA DO USUÁRIO NO APP ANDROID ]
1.  Jornada de Primeiro Acesso (Dispositivo Unprovisioned detectado via USB)
2.  Onboarding: Definição do Primeiro PIN no Teclado Numérico Atômico
3.  Onboarding: Apresentação e Confirmação de Cópia do Recovery Code de 16 Bytes
4.  Hub Principal: Estado Bloqueado com Cartões de Carteiras Ofuscados
5.  Modal de Desbloqueio: Entrada Rápida de PIN com Indicadores de Ponto
6.  Transição para Desbloqueado: Desofuscação Fluida e Acesso a Carteiras Web3
7.  Aviso de Inatividade: Contagem Regressiva Visual de 30 Segundos Pré-Bloqueio
8.  Bloqueio por Inatividade: Retorno Automático ao Estado Locked
9.  Tratamento de Rate-Limit: Bloqueio do Teclado com Barra de Progresso de Backoff (2s, 5s, 15s)
10. Alerta Crítico de Última Tentativa: Modal Vermelho na 4ª Tentativa Falha
11. Tela de Bloqueio Definitivo: Esgotamento de 5 Tentativas e Solicitação de Recovery Code
12. Fluxo de Recuperação de Emergência: Validação do Recovery Code e Cadastro de Novo PIN
13. Configurações Avançadas: Ajuste de Timeouts de Sessão e Auditoria de Log
```

### 5.2. Comandos de Homologação Android
```powershell
cd app-android

# 1. Execução de testes unitários de ViewModel e UseCases (Zero-Mocks)
./gradlew testDebugUnitTest --tests "dev.aegiskey.app.domain.usecase.SecureGuardUseCasesTest"

# 2. Execução dos testes de UI no emulador conectado
./gradlew connectedDebugAndroidTest
```

---

## 6. Seção 12.5: Testes Hardware-in-the-Loop (HIL) em Silício Real

Validação definitiva no microcontrolador ESP32-S3 de bancada conectado fisicamente via porta USB nativa (`VID 0x303A : PID 0xAE61`) e console de depuração UART (`COM7` em 115200 8N1).

```
+-------------------------------------------------------------------------------------------------+
|                                 BANCADA DE TESTES FÍSICOS HIL (COM7)                            |
+-------------------------------------------------------------------------------------------------+
|                                                                                                 |
|   +-----------------------+     USB Native (0x303A:0xAE61)      +---------------------------+   |
|   | Host PC (Python / SDK)| <=================================> | Placa ESP32-S3-WROOM-1    |   |
|   |  - scripts HIL        |                                     |  - Firmware FreeRTOS      |   |
|   |  - Bridge HTTP 5678   | <---------------------------------> |  - Partição NVS Flash 16MB|   |
|   +-----------------------+       UART0 Serial (COM7 115200)    +---------------------------+   |
|                                                                                                 |
+-------------------------------------------------------------------------------------------------+
```

### 6.1. Protocolo de Verificação em 9 Etapas HIL

| Etapa HIL | Descrição da Ação Física | Comando / Script | Verificação Obrigatória em Silício Real |
|---|---|---|---|
| **HIL-E1** | Gravação Limpa de Firmware | `esptool.py write_flash 0x10000 aegis-app-freertos-s3-testmode.bin` | Dispositivo reinicia limpo; log UART emite `[SG] Initialized state: Unprovisioned`. |
| **HIL-E2** | Provisionamento via USB | `python tools/hil_secure_guard.py --action provision --pin 4927` | LED RGB pisca ciano; chave NVS `sg_state` gravada com 256 bytes e Magic `AEGSG001`. |
| **HIL-E3** | Consulta de Status | `python tools/hil_secure_guard.py --action status` | Retorna `state: Locked (0x02)`, `is_provisioned: true`, `failed_attempts: 0`. |
| **HIL-E4** | Rejeição de Carteira Bloqueada | `python tools/hil_secure_guard.py --action wallet_gen --curve secp256k1` | Opcode `0x35` rejeitado com status `0x27 CTAP2_ERR_PIN_REQUIRED`. |
| **HIL-E5** | Teste de Falha e Backoff | `python tools/hil_secure_guard.py --action unlock --pin 0000` | LED RGB pisca vermelho; UART confirma `[SG] Failed attempt 1/5`; backoff 0ms. |
| **HIL-E6** | Teste de Desbloqueio Válido | `python tools/hil_secure_guard.py --action unlock --pin 4927` | LED RGB pulsa verde suave; retorno `0x00 SUCCESS`; timer de 300s iniciado. |
| **HIL-E7** | Geração Autorizada de Carteira | `python tools/hil_secure_guard.py --action wallet_gen --curve secp256k1` | Operação autorizada pelo Secure Guard. Retorna endereço Bitcoin válido `bc1q...`. |
| **HIL-E8** | Teste de Timeout de Inatividade| Aguardar 125 segundos sem envio de comandos pela porta USB. | Tarefa de firmware expira sessão autonomamente; status transita para `Locked`. |
| **HIL-E9** | Coexistência FIDO2 WebAuthn | Enviar asserção WebAuthn real via CTAPHID com o Secure Guard bloqueado. | Asserção FIDO2 P-256 concluída com sucesso imediato sem impacto pelo Secure Guard. |

### 6.2. Comandos de Inicialização da Bancada HIL
```powershell
# 1. Compilar firmware com símbolos de diagnóstico e modo de teste
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-freertos-s3-testmode.ps1

# 2. Gravar o binário na placa conectada em COM7
python -m esptool --chip esp32s3 --port COM7 --baud 921600 write_flash 0x10000 C:\t\aegis-app-freertos-s3-testmode.bin

# 3. Iniciar o servidor de ponte de hardware com suporte Win32 e Android
python tools/host_hardware_android_bridge.py --port COM7 --baud 115200

# 4. Executar a bateria completa de testes HIL em silício
python tools/hil_emulate_full_app_on_board.py
```
