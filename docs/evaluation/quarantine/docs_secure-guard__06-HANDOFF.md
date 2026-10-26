# Guia Canônico de Handoff e Continuidade Técnica — AegisKey Secure Guard

> **Projeto:** AegisKey FIDO2 & Multi-Protocol Hardware Authenticator  
> **Subsistema:** Secure Guard (Cofre Local de Autoridade, Zero-Trust On-Device)  
> **Status:** Documento Normativo de Transição e Handoff Técnico (Seção 14)  
> **Data:** 25 de Outubro de 2026  
> **Destinatários:** Engenheiros de Firmware, Criptógrafos, Desenvolvedores Android e Auditores de Segurança  

---

## 1. Visão Geral e Propósito do Handoff

Este documento estabelece o **guia definitivo de continuidade operacional e de engenharia** para o subsistema **AegisKey Secure Guard**. Ele consolida o mapeamento de arquivos, o histórico cronológico de commits atômicos, os procedimentos reprodutíveis de compilação e teste para todas as camadas da stack, o roteiro de operação do modo laboratorial não-destrutivo e as **invariantes de segurança invioláveis** que devem ser preservadas em qualquer ciclo de vida futuro do software.

```
+-------------------------------------------------------------------------------------------------------------------+
|                                  FLUXO DE INTEGRAÇÃO DAS CAMADAS DO SECURE GUARD                                  |
+-------------------------------------------------------------------------------------------------------------------+
|                                                                                                                   |
|   [ Core Rust (no_std) ]  -------->  [ Firmware FreeRTOS ESP32-S3 ]  <-------> [ USB COM7 / BLE GATT ]            |
|     - state.rs                         - secure_guard_exec.rs                    - host_hardware_android_bridge   |
|     - crypto.rs                        - secure_guard_sched.rs                   - Web Dashboard (HTTP 5678)      |
|     - policy.rs                        - secure_guard_storage.rs                                 |                |
|     - persistence.rs                   - freertos_route.rs (Enforcement Barrier)                 v                |
|           |                                                                         [ Android App Material 3 ]    |
|           +----------------------->  [ universal-device-sdk / uniffi-bridge ] --->   - Atomic UI Components       |
|                                        - UniversalSecureGuardClient                  - SecureGuardViewModel       |
|                                        - libaegis_bridge.so                          - SecureGuardJourneyTest     |
+-------------------------------------------------------------------------------------------------------------------+
```

---

## 2. Mapa Exato de Arquivos Criados e Modificados por Camada

A implementação da missão Secure Guard envolveu modificações e adições cirúrgicas em 5 camadas concêntricas do repositório `e:/projetos/fido/`:

### 2.1. Camada de Núcleo Criptográfico e Regras de Negócio (`crates/aegis-fido-core/`)
- [`crates/aegis-fido-core/src/lib.rs`](file:///e:/projetos/fido/crates/aegis-fido-core/src/lib.rs): Exportação pública do módulo `secure_guard`.
- [`crates/aegis-fido-core/src/secure_guard/mod.rs`](file:///e:/projetos/fido/crates/aegis-fido-core/src/secure_guard/mod.rs): Módulo raiz do subsistema com re-exportação de tipos e suíte com 16 testes de integração de domínio.
- [`crates/aegis-fido-core/src/secure_guard/state.rs`](file:///e:/projetos/fido/crates/aegis-fido-core/src/secure_guard/state.rs): Máquina de estados formal (`SecureGuardState`) com 10 estados canônicos e matriz de transição.
- [`crates/aegis-fido-core/src/secure_guard/crypto.rs`](file:///e:/projetos/fido/crates/aegis-fido-core/src/secure_guard/crypto.rs): Algoritmos PBKDF2-HMAC-SHA256, `constant_time_eq_32` com `subtle`, CRC32 e zeroização.
- [`crates/aegis-fido-core/src/secure_guard/policy.rs`](file:///e:/projetos/fido/crates/aegis-fido-core/src/secure_guard/policy.rs): Políticas de segurança, limites de 5 tentativas e backoff progressivo.
- [`crates/aegis-fido-core/src/secure_guard/persistence.rs`](file:///e:/projetos/fido/crates/aegis-fido-core/src/secure_guard/persistence.rs): Serializador determinístico de 256 bytes (`SecureGuardPersistentRecord`) com Magic `AEGSG001` e CRC32.
- [`crates/aegis-fido-core/src/secure_guard/audit.rs`](file:///e:/projetos/fido/crates/aegis-fido-core/src/secure_guard/audit.rs): Ring buffer de auditoria (`AuditRingBuffer`) com capacidade de 32 registros estritamente numéricos.
- [`crates/aegis-fido-core/src/secure_guard/resource.rs`](file:///e:/projetos/fido/crates/aegis-fido-core/src/secure_guard/resource.rs): Classificador de opcodes protegidos (`ProtectedResourceClass`) e escopos de wipe.
- [`crates/aegis-fido-core/src/secure_guard/engine.rs`](file:///e:/projetos/fido/crates/aegis-fido-core/src/secure_guard/engine.rs): Fachada centralizadora (`SecureGuardEngine`) com métodos de provisionamento, desbloqueio, expiração e barreira.
- [`crates/aegis-fido-core/src/secure_guard/error.rs`](file:///e:/projetos/fido/crates/aegis-fido-core/src/secure_guard/error.rs): Tipagem rigorosa de erros de cofre (`SecureGuardError`).

### 2.2. Camada de Firmware Embarcado FreeRTOS ESP32-S3 (`crates/aegis-fido-firmware/`)
- [`crates/aegis-fido-firmware/src/lib.rs`](file:///e:/projetos/fido/crates/aegis-fido-firmware/src/lib.rs): Registro dos novos módulos `secure_guard_storage`, `secure_guard_sched` e `secure_guard_exec`.
- [`crates/aegis-fido-firmware/src/freertos_sched.rs`](file:///e:/projetos/fido/crates/aegis-fido-firmware/src/freertos_sched.rs): Alocação de `TaskId::SecureGuard` com 32 KiB de stack e canais de alimentação TWDT.
- [`crates/aegis-fido-firmware/src/secure_guard_storage.rs`](file:///e:/projetos/fido/crates/aegis-fido-firmware/src/secure_guard_storage.rs): Persistência em Flash NVS sob a chave `sg_record_v1` com padrão persistência pré-resposta.
- [`crates/aegis-fido-firmware/src/secure_guard_sched.rs`](file:///e:/projetos/fido/crates/aegis-fido-firmware/src/secure_guard_sched.rs): Thread de background e gestão de timers monotônicos de sessão e rate-limit.
- [`crates/aegis-fido-firmware/src/secure_guard_exec.rs`](file:///e:/projetos/fido/crates/aegis-fido-firmware/src/secure_guard_exec.rs): Roteador e processador de opcodes CTAPHID `0x3A..0x3E` com decodificação CBOR.
- [`crates/aegis-fido-firmware/src/freertos_route.rs`](file:///e:/projetos/fido/crates/aegis-fido-firmware/src/freertos_route.rs): Interposição mandatória da Barreira de Autorização nos opcodes de carteiras e chaves.
- [`crates/aegis-fido-firmware/tests/secure_guard_integration.rs`](file:///e:/projetos/fido/crates/aegis-fido-firmware/tests/secure_guard_integration.rs): Testes de integração fim a fim no firmware com validação de wipe escopado.

### 2.3. Camada de SDK, UniFFI Bridge e Dashboard Web
- [`crates/universal-device-sdk/src/lib.rs`](file:///e:/projetos/fido/crates/universal-device-sdk/src/lib.rs): Exportação pública do módulo `secure_guard`.
- [`crates/universal-device-sdk/src/secure_guard.rs`](file:///e:/projetos/fido/crates/universal-device-sdk/src/secure_guard.rs): DTOs serializáveis CBOR e cliente de alto nível `UniversalSecureGuardClient`.
- [`crates/uniffi-bridge/src/aegis_bridge.udl`](file:///e:/projetos/fido/crates/uniffi-bridge/src/aegis_bridge.udl): Definição de interface UDL para exportação de métodos de cofre.
- [`crates/uniffi-bridge/src/lib.rs`](file:///e:/projetos/fido/crates/uniffi-bridge/src/lib.rs): Implementação dos adaptadores UniFFI C-ABI/JNI.
- [`tools/host_hardware_android_bridge.py`](file:///e:/projetos/fido/tools/host_hardware_android_bridge.py): Servidor HTTP na porta 5678 com rotas `/api/secure-guard/*` e suporte serial `COM7`.
- [`tools/web_dashboard/index.html`](file:///e:/projetos/fido/tools/web_dashboard/index.html): Interface web Material 3 com controles interativos de cofre e telemetria viva.
- [`tools/test_web_dashboard_endpoints.py`](file:///e:/projetos/fido/tools/test_web_dashboard_endpoints.py): Bateria de testes de bancada expandida para 42 testes cobrindo endpoints de Secure Guard.

### 2.4. Camada de Aplicativo Android (`app-android/`)
- [`app/src/main/java/dev/aegiskey/app/domain/model/SecureGuardModels.kt`](file:///e:/projetos/fido/app-android/app/src/main/java/dev/aegiskey/app/domain/model/SecureGuardModels.kt): Modelos puros de domínio (`SecureGuardStatus`, `SecureGuardPolicy`, `SecureGuardStateEnum`).
- [`app/src/main/java/dev/aegiskey/app/domain/repository/SecureGuardRepository.kt`](file:///e:/projetos/fido/app-android/app/src/main/java/dev/aegiskey/app/domain/repository/SecureGuardRepository.kt): Contrato de repositório.
- [`app/src/main/java/dev/aegiskey/app/domain/usecase/SecureGuardUseCases.kt`](file:///e:/projetos/fido/app-android/app/src/main/java/dev/aegiskey/app/domain/usecase/SecureGuardUseCases.kt): Casos de uso de negócio para provisionamento, desbloqueio, troca de PIN, recuperação e wipe.
- [`app/src/main/java/dev/aegiskey/app/data/repository/SecureGuardRepositoryImpl.kt`](file:///e:/projetos/fido/app-android/app/src/main/java/dev/aegiskey/app/data/repository/SecureGuardRepositoryImpl.kt): Implementação real do repositório.
- [`app/src/main/java/dev/aegiskey/app/ui/atomic/atoms/SecureGuardBadgeAtom.kt`](file:///e:/projetos/fido/app-android/app/src/main/java/dev/aegiskey/app/ui/atomic/atoms/SecureGuardBadgeAtom.kt): Átomo visual de status.
- [`app/src/main/java/dev/aegiskey/app/ui/atomic/molecules/SecurePinKeypadMolecule.kt`](file:///e:/projetos/fido/app-android/app/src/main/java/dev/aegiskey/app/ui/atomic/molecules/SecurePinKeypadMolecule.kt): Molécula de teclado de segurança com botões randomizáveis.
- [`app/src/main/java/dev/aegiskey/app/ui/atomic/molecules/RateLimitTimerMolecule.kt`](file:///e:/projetos/fido/app-android/app/src/main/java/dev/aegiskey/app/ui/atomic/molecules/RateLimitTimerMolecule.kt): Barra visual de penalidade temporal de backoff.
- [`app/src/main/java/dev/aegiskey/app/ui/atomic/molecules/SessionExpiryTimerMolecule.kt`](file:///e:/projetos/fido/app-android/app/src/main/java/dev/aegiskey/app/ui/atomic/molecules/SessionExpiryTimerMolecule.kt): Indicador de tempo restante de sessão.
- [`app/src/main/java/dev/aegiskey/app/ui/atomic/organisms/SecureGuardCardOrganism.kt`](file:///e:/projetos/fido/app-android/app/src/main/java/dev/aegiskey/app/ui/atomic/organisms/SecureGuardCardOrganism.kt): Organismo integrador do cofre no Hub.
- [`app/src/main/java/dev/aegiskey/app/ui/viewmodel/SecureGuardViewModel.kt`](file:///e:/projetos/fido/app-android/app/src/main/java/dev/aegiskey/app/ui/viewmodel/SecureGuardViewModel.kt): ViewModel reativo gerenciando StateFlow e polling.
- [`app/src/test/java/dev/aegiskey/app/SecureGuardJourneyTest.kt`](file:///e:/projetos/fido/app-android/app/src/test/java/dev/aegiskey/app/SecureGuardJourneyTest.kt): Suíte com as 13 jornadas completas de usuário.

---

## 3. Sequência de Commits Atômicos Realizados

O projeto seguiu rigorosamente uma progressão ordenada de commits atômicos rastreáveis:

| Hash do Commit | Mensagem do Commit | Escopo e Entregas Consolidadas |
|:---:|:---|:---|
| **`e99992e`** | `docs(secure-guard): add baseline, architecture, threat model, protocol, test plan and industrial design` | Documentos normativos iniciais: `00-BASELINE.md`, `01-ARCHITECTURE.md`, `02-THREAT-MODEL.md`, `03-PROTOCOL.md`, `04-TEST-PLAN.md` e `07-DESIGN-INDUSTRIAL.md`. |
| **`aa0a1ce`** | `feat(core): implement SecureGuardEngine state machine, PBKDF2 verifier, 5-attempt policy and persistence` | Núcleo criptográfico em `crates/aegis-fido-core/src/secure_guard/`: FSM de 10 estados, PBKDF2, constant time, 5 erros, record binário de 256B e ring buffer de 32 eventos. |
| **`2d0a21f`** | `feat(firmware): add FreeRTOS Secure Guard task, NVS storage, 0x3A-0x3E opcodes and enforcement barrier` | Firmware embarcado: `TaskId::SecureGuard` com stack de 32 KiB, chave NVS `sg_record_v1`, opcodes `0x3A..0x3E`, barreira em `freertos_route.rs` e testes de integração. |
| **`2bb5bb8`** | `feat(sdk): expose Secure Guard DTOs in universal-device-sdk, UniFFI bridge, hardware bridge and Web Dashboard` | SDK universal tipado, bindings UniFFI C-ABI/JNI, servidor bridge em Python 3 com novos endpoints REST e painel Material 3 no Web Dashboard. |
| **`98f9858`** | `feat(android): implement Secure Guard UX components, ViewModel, state machine and 13-journey tests` | Camada Android Clean Architecture + Atomic Design, ViewModel reativo, organism `SecureGuardCardOrganism` e suíte de 13 jornadas em `SecureGuardJourneyTest.kt`. |

---

## 4. Guia de Compilação, Teste e Depuração por Camada

### 4.1. Rust Core, SDK e UniFFI Bridge (Ambiente Host)
O workspace Rust pode ser compilado e testado em qualquer terminal PowerShell ou Bash com Cargo:

```powershell
# Configurar PATH do Cargo se necessário
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

# 1. Executar testes de todas as suítes Rust
cargo test --workspace

# 2. Executar testes específicos do Secure Guard no Core
cargo test -p aegis-fido-core --lib secure_guard

# 3. Executar testes do SDK e Bridge UniFFI
cargo test -p universal-device-sdk -p uniffi-bridge

# 4. Análise estática com Clippy (Zero Warnings)
cargo clippy --all-targets -- -D warnings
```

### 4.2. Firmware Embarcado ESP32-S3 (FreeRTOS)
A compilação do firmware requer a toolchain Xtensa (`espup`):

```powershell
# 1. Carregar variáveis de ambiente da toolchain Xtensa
. ./export-esp.ps1

# 2. Compilar binário de produção/teste de bancada
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-freertos-s3-testmode.ps1
# Gera: C:\t\aegis-app-freertos-s3-testmode.bin

# 3. Gravar na placa física conectada em COM7 via esptool
python -m esptool --chip esp32s3 --port COM7 --baud 921600 write_flash 0x10000 C:\t\aegis-app-freertos-s3-testmode.bin

# 4. Monitorar logs do console UART (115200 8N1)
python -m serial.tools.miniterm COM7 115200
```

### 4.3. Servidor de Hardware Bridge & Web Dashboard
A ponte atua como o multiplexador local entre hardware serial/USB, Android e Web:

```powershell
# Inicializar o servidor da ponte na porta 5678 conectando ao ESP32-S3 em COM7
& "C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe" tools/host_hardware_android_bridge.py --port COM7 --baud 115200

# Executar a bateria de testes automatizados dos endpoints HTTP (42 testes)
& "C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe" tools/test_web_dashboard_endpoints.py

# Acessar o Web Dashboard interativo no navegador
Start-Process "http://127.0.0.1:5678/"
```

### 4.4. Aplicativo Android (Gradle 8.7)
Os testes unitários e de jornadas de tela rodam via Gradle:

```powershell
# 1. Executar testes unitários de ViewModel e Jornadas de UX
& "C:\Users\junior\.gradle\wrapper\dists\gradle-8.7-bin\bhs2wmbdwecv87pi65oeuq5iu\gradle-8.7\bin\gradle.bat" -p app-android testDebugUnitTest --tests "dev.aegiskey.app.SecureGuardJourneyTest"

# 2. Compilar APKs de Debug e Release
& "C:\Users\junior\.gradle\wrapper\dists\gradle-8.7-bin\bhs2wmbdwecv87pi65oeuq5iu\gradle-8.7\bin\gradle.bat" -p app-android assembleDebug assembleRelease

# 3. Auditar ausência absoluta de mocks no APK de Release
& "C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe" tools/check_android_release_no_mocks.py
```

---

## 5. Como Operar o Modo de Teste Não-Destrutivo (`test_mode_non_destructive_wipe`)

Durante ensaios de laboratório, baterias HIL e validações em linha de montagem, é necessário testar a exaustão das 5 tentativas de PIN sem destruir as chaves criptográficas reais gravadas na partição flash do dispositivo.

Para esse propósito, o Secure Guard disponibiliza a flag de política **`test_mode_non_destructive_wipe`**:

### Procedimento de Operação:
1. **Ativação da Flag na Política:**
   Ao provisionar ou reconfigurar a política via opcode `0x3D` (ou endpoint `/api/secure-guard/config`), inclua o parâmetro:
   ```json
   {
     "wipe_on_5_failures": true,
     "test_mode_non_destructive_wipe": true
   }
   ```
2. **Execução das 5 Tentativas Incorretas:**
   Envie 5 PINs incorretos consecutivos. Ao atingir a 5ª falha:
   - O contador é registrado e atinge 5.
   - O estado transita formalmente para `Unprovisioned` (ou `WipePending` seguido de limpeza simulada).
   - O registro persistente é zerado (`provisioned = false`), mas a partição de dados protegidos reais **não é formatada**.
   - O flag `last_wipe_simulated` na resposta de telemetria (opcode `0x3A` chave `0x09` / JSON `last_wipe_simulated`) retorna **`true`**.
3. **Restauração Rápida:**
   Como as chaves físicas não foram corrompidas, um novo comando de provisionamento (`provision_pin`) restaura o funcionamento do cofre sem necessidade de re-flash completo do microcontrolador.

> [!WARNING]
> Em compilações finais de produção (dispositivos destinados a usuários finais em mercado), a flag `test_mode_non_destructive_wipe` é desabilitada por política padrão (`false`), garantindo que o wipe físico destrua irrevogavelmente todas as chaves protegidas com sobrescrita de zeros (`zeroize`).

---

## 6. Invariantes de Segurança Críticas (Regras Invioláveis para Engenharia Futura)

Qualquer desenvolvedor, agente ou auditor que venha a manter ou estender este repositório deve respeitar rigorosamente as seguintes 10 invariantes:

1. **Invariante 1 — Soberania Local do Firmware (Zero-Trust):**
   O microcontrolador nunca confia em flags de autenticação vindas do aplicativo Android ou host. O destravamento ocorre unicamente após validação local de PIN no silício.
2. **Invariante 2 — Isolamento Absoluto de FIDO2 / WebAuthn:**
   As passkeys residentes FIDO2 (`0x01..0x0D`) **nunca devem depender do destravamento do Secure Guard** e **nunca devem ser apagadas pelo wipe do Secure Guard**.
3. **Invariante 3 — Persistência Pré-Resposta:**
   Toda falha de autenticação de PIN deve ser incrementada e commitada na memória Flash NVS **antes** de enviar a resposta de erro ao canal de comunicação USB/BLE.
4. **Invariante 4 — Verificação em Tempo Constante:**
   Comparação de hashes de PIN e códigos de recuperação deve utilizar estritamente funções invariantes de branch (`subtle::ConstantTimeEq`). Nunca use `==` ou `memcmp` padrão em segredos.
5. **Invariante 5 — Limpeza de Memória (Zeroize):**
   Todos os buffers transitórios contendo senhas, salts ou chaves derivadas em RAM devem ser limpos com zeroização imediata (`Zeroize::zeroize`) antes de sair de escopo.
6. **Invariante 6 — Teto de 5 Tentativas:**
   O limite de 5 tentativas consecutivas de PIN é fixo e inegociável. Não é permitido criar portas de escape ("backdoors") ou contadores flexíveis em compilações de produção.
7. **Invariante 7 — Stack Seguro de 32 KiB:**
   A tarefa FreeRTOS do Secure Guard e quaisquer tarefas que executem PBKDF2 ou curvas elípticas devem possuir no mínimo 32 KiB (`32 * 1024` bytes) de stack alocado para evitar overflow de pilha no ESP32-S3.
8. **Invariante 8 — Zero Secrets in Logs:**
   É estritamente proibido emitir strings de PIN, chaves privadas ou bytes de recuperação em mensagens de log UART, Logcat Android ou buffers de telemetria.
9. **Invariante 9 — Segregação Anti-Mock em Release:**
   O APK de produção (`Release`) não pode conter nenhuma classe, constante ou stub de simulação de hardware em seu bytecode DEX compilado.
10. **Invariante 10 — Fail-Closed Universal (`ErrorLocked`):**
    Qualquer detecção de anomalia física, falha de integridade de CRC32 Flash ou violação de transição de estado deve forçar a FSM imediatamente para o estado terminal `ErrorLocked`.
