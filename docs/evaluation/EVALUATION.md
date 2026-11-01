# EVALUATION — Quarantine index (what moved, why, pending decision)

> Scope: index of every legacy markdown moved to `docs/evaluation/quarantine/`.
> Rule: quarantine is the only exception to one-file-per-folder.
> Status convention: SUPERSEDED (content merged), HISTORICAL (keep for audit), PENDING (needs decision).

## 1. Rule

- Keep 3 consolidated files plus this index plus root files only.
- Move every other own markdown to quarantine with a flattened name.
- Delete emptied legacy folders after move. Touch no code file.
- Touch no `.slim/`, `target/`, `*.apk`, vendored crates, `.opencode/node_modules`.

## 2. Quarantine table (old path → quarantine name → fate)

| Old path | Quarantine name | Fate | Pending decision |
|---|---|---|---|
| `docs/APP_ANDROID_KEY_LIFECYCLE.md` | `docs_APP_ANDROID_KEY_LIFECYCLE.md` | SUPERSEDED by PROJECT.md sec 7 | None |
| `docs/APP_ANDROID_UX_ARCHITECTURE.md` | `docs_APP_ANDROID_UX_ARCHITECTURE.md` | SUPERSEDED by PROJECT.md sec 7 | None |
| `docs/app-android-clean-atomic-architecture.md` | `docs_app-android-clean-atomic-architecture.md` | SUPERSEDED by PROJECT.md sec 7 | None |
| `docs/APP-INTEGRACAO.md` | `docs_APP-INTEGRACAO.md` | SUPERSEDED by PROJECT.md sec 6-7 | None |
| `docs/app-journey.md` | `docs_app-journey.md` | SUPERSEDED by PROJECT.md sec 7 | None |
| `docs/app-mapa.md` | `docs_app-mapa.md` | SUPERSEDED by PROJECT.md sec 7 | None |
| `docs/APP-PLANO-NOVOS-MODULOS.md` | `docs_APP-PLANO-NOVOS-MODULOS.md` | SUPERSEDED by PLANS.md sec 4 | Confirm lane ownership |
| `docs/auditoria-mocks.md` | `docs_auditoria-mocks.md` | HISTORICAL, summarized PLANS.md sec 4 | None |
| `docs/bateria-serial.md` | `docs_bateria-serial.md` | SUPERSEDED by TASKS.md sec 3.1 | None |
| `docs/bench-destructive.md` | `docs_bench-destructive.md` | SUPERSEDED by TASKS.md sec 3.3 | Needs factory approval for live run |
| `docs/bench-freertos-s3.md` | `docs_bench-freertos-s3.md` | SUPERSEDED by TASKS.md sec 3.2 | None |
| `docs/binding.md` | `docs_binding.md` | SUPERSEDED by PROJECT.md sec 6.2 | None |
| `docs/ble-nimble.md` | `docs_ble-nimble.md` | SUPERSEDED by PROJECT.md sec 6.1 | None |
| `docs/ble-protocol.md` | `docs_ble-protocol.md` | SUPERSEDED by PROJECT.md sec 6.1 | Frozen contract, no change without major |
| `docs/bonding-walkaway.md` | `docs_bonding-walkaway.md` | SUPERSEDED by TASKS.md sec 4.2 | RF test pending |
| `docs/capacidades-modulos.md` | `docs_capacidades-modulos.md` | SUPERSEDED by PROJECT.md sec 5 | None |
| `docs/carteira-cripto.md` | `docs_carteira-cripto.md` | SUPERSEDED by PLANS.md sec 4 | None |
| `docs/checklist-usuario.md` | `docs_checklist-usuario.md` | SUPERSEDED by TASKS.md sec 4.1 | None |
| `docs/COMMS-map.md` | `docs_COMMS-map.md` | SUPERSEDED by PROJECT.md sec 6 | Section 8 validation stays normative |
| `docs/DESACOPLAMENTO.md` | `docs_DESACOPLAMENTO.md` | SUPERSEDED by PROJECT.md sec 4.3 | None |
| `docs/emuladores-pre-flash.md` | `docs_emuladores-pre-flash.md` | SUPERSEDED by TASKS.md sec 3.4 | None |
| `docs/estado-final-firmware.md` | `docs_estado-final-firmware.md` | HISTORICAL, summarized PLANS.md sec 6 | Confirm test-mode inbox state |
| `docs/excecoes-paridade.md` | `docs_excecoes-paridade.md` | SUPERSEDED by PROJECT.md sec 5 | None |
| `docs/finalizacao-freertos-rust.md` | `docs_finalizacao-freertos-rust.md` | HISTORICAL, summarized PLANS.md sec 6 | None |
| `docs/finalizacoes.md` | `docs_finalizacoes.md` | HISTORICAL, merged PLANS.md sec 6 | None, one of 4 finals |
| `docs/firmware-fina.md` | `docs_firmware-fina.md` | HISTORICAL, merged PLANS.md sec 6 | None, one of 4 finals |
| `docs/freertos-rust.md` | `docs_freertos-rust.md` | SUPERSEDED by PROJECT.md sec 4.2 | None |
| `docs/GUIA_DISPLAY_LCD_RUST_C.md` | `docs_GUIA_DISPLAY_LCD_RUST_C.md` | SUPERSEDED by PROJECT.md sec 8 | None |
| `docs/GUIA_RITOS_CONEXAO_USB_BLE_LED_E_WALLETS.md` | `docs_GUIA_RITOS_CONEXAO_USB_BLE_LED_E_WALLETS.md` | SUPERSEDED by TASKS.md sec 5 | None |
| `docs/HANDOFF-2026-10-20.md` | `docs_HANDOFF-2026-10-20.md` | HISTORICAL, merged TASKS.md sec 6 | None, one of 3 handoffs |
| `docs/interop-matrix.md` | `docs_interop-matrix.md` | SUPERSEDED by PROJECT.md sec 5 | Never claim without vector |
| `docs/jornada-onboarding-totp-simulacao-renode.md` | `docs_jornada-onboarding-totp-simulacao-renode.md` | SUPERSEDED by PROJECT.md sec 7-8 | None |
| `docs/led-diagnostico.md` | `docs_led-diagnostico.md` | HISTORICAL, needs eyes | User must confirm LED order |
| `docs/lifetime-debug.md` | `docs_lifetime-debug.md` | SUPERSEDED by TASKS.md sec 5 | Keep OFF in release |
| `docs/linux-bringup.md` | `docs_linux-bringup.md` | SUPERSEDED by TASKS.md sec 3.6 | None |
| `docs/live-monitor.md` | `docs_live-monitor.md` | SUPERSEDED by TASKS.md sec 5 | Keep OFF in release |
| `docs/MACHINE.md` | `docs_MACHINE.md` | HISTORICAL, normative for ports | Revalidate on bench change |
| `docs/matriz-funcionalidades-esp32s3.md` | `docs_matriz-funcionalidades-esp32s3.md` | SUPERSEDED by PROJECT.md sec 5 | None |
| `docs/nvs_schema.md` | `docs_nvs_schema.md` | SUPERSEDED by PROJECT.md sec 6.3 | None |
| `docs/piv-ble-proximity.md` | `docs_piv-ble-proximity.md` | SUPERSEDED by PLANS.md sec 4 | None |
| `docs/plano-amarelos.md` | `docs_plano-amarelos.md` | SUPERSEDED by PLANS.md sec 3 | None, one of 6 pending lists |
| `docs/plano-followups.md` | `docs_plano-followups.md` | SUPERSEDED by PLANS.md sec 3 | None, one of 6 pending lists |
| `docs/plano-hw.md` | `docs_plano-hw.md` | SUPERSEDED by PROJECT.md sec 3 | None |
| `docs/plano-testes-hil.md` | `docs_plano-testes-hil.md` | SUPERSEDED by TASKS.md sec 2 | None |
| `docs/provisionamento-pins-integrity.md` | `docs_provisionamento-pins-integrity.md` | SUPERSEDED by PROJECT.md sec 9 | Confirm server pins |
| `docs/proximity-worktree-handoff.md` | `docs_proximity-worktree-handoff.md` | HISTORICAL, merged TASKS.md sec 6 | None, one of 3 handoffs |
| `docs/proximos-passos.md` | `docs_proximos-passos.md` | SUPERSEDED by PLANS.md sec 3 | None, one of 6 pending lists |
| `docs/qemu-s3.md` | `docs_qemu-s3.md` | SUPERSEDED by TASKS.md sec 3.5 | Smoke only |
| `docs/REGRAS-automacao.md` | `docs_REGRAS-automacao.md` | HISTORICAL, normative R1-R14 | Violation aborts lane |
| `docs/screen-journey.md` | `docs_screen-journey.md` | SUPERSEDED by TASKS.md sec 5 | None |
| `docs/secure-guard/00-BASELINE.md` | `docs_secure-guard__00-BASELINE.md` | SUPERSEDED by PROJECT.md sec 3-4 | None |
| `docs/secure-guard/01-ARCHITECTURE.md` | `docs_secure-guard__01-ARCHITECTURE.md` | SUPERSEDED by PROJECT.md sec 4 | None |
| `docs/secure-guard/02-THREAT-MODEL.md` | `docs_secure-guard__02-THREAT-MODEL.md` | SUPERSEDED by PROJECT.md sec 9 | None |
| `docs/secure-guard/03-PROTOCOL.md` | `docs_secure-guard__03-PROTOCOL.md` | SUPERSEDED by PROJECT.md sec 6 | None |
| `docs/secure-guard/04-TEST-PLAN.md` | `docs_secure-guard__04-TEST-PLAN.md` | SUPERSEDED by TASKS.md sec 2-3 | None |
| `docs/secure-guard/05-IMPLEMENTATION-STATUS.md` | `docs_secure-guard__05-IMPLEMENTATION-STATUS.md` | HISTORICAL, summarized PLANS.md | Reconcile with current code |
| `docs/secure-guard/06-HANDOFF.md` | `docs_secure-guard__06-HANDOFF.md` | HISTORICAL, merged TASKS.md sec 6 | None, one of 3 handoffs |
| `docs/secure-guard/07-DESIGN-INDUSTRIAL.md` | `docs_secure-guard__07-DESIGN-INDUSTRIAL.md` | SUPERSEDED by PROJECT.md sec 3 | Confirm keyfob dimensions |
| `docs/secure-guard/08-SECURITY-REVIEW.md` | `docs_secure-guard__08-SECURITY-REVIEW.md` | SUPERSEDED by PROJECT.md sec 9 | Enforce 20 rules plus 6 criteria |
| `docs/secure-guard/09-VALIDATION-RESULTS.md` | `docs_secure-guard__09-VALIDATION-RESULTS.md` | SUPERSEDED by TASKS.md sec 7 | Refresh after next HW run |
| `docs/seis-produtos.md` | `docs_seis-produtos.md` | SUPERSEDED by PLANS.md sec 4 | None |
| `docs/sessao-20-10-f4-ccid-opensc.md` | `docs_sessao-20-10-f4-ccid-opensc.md` | HISTORICAL, summarized PLANS.md sec 6 | None |
| `docs/size-wave1.md` | `docs_size-wave1.md` | HISTORICAL, summarized PLANS.md sec 5 | Re-measure on next S3 build |
| `docs/test-hooks.md` | `docs_test-hooks.md` | SUPERSEDED by TASKS.md sec 5 | Gate test-mode |
| `docs/teste-ponta-a-ponta.md` | `docs_teste-ponta-a-ponta.md` | HISTORICAL diary, map merged to TASKS.md | Keep as audit diary only |
| `docs/validacao-usb-telas.md` | `docs_validacao-usb-telas.md` | SUPERSEDED by PLANS.md sec 4 | COM8 reflash pending |
| `docs/wifi.md` | `docs_wifi.md` | SUPERSEDED by PROJECT.md sec 6 | None |
| `plans/carteira-cripto-store/*` (5) | `plans_carteira-cripto-store__*.md` | SUPERSEDED by PLANS.md sec 4 | None |
| `plans/conexao-ble-fim-a-fim/*` (4) | `plans_conexao-ble-fim-a-fim__*.md` | SUPERSEDED by PLANS.md sec 4 | RF pending |
| `plans/F2-F3-HIL-MAP.md` | `plans_F2-F3-HIL-MAP.md` | SUPERSEDED by TASKS.md sec 2 | F3 blocked on bad-sig |
| `plans/fido-auditoria/*` (3) | `plans_fido-auditoria__*.md` | HISTORICAL, summarized PLANS.md sec 4 | None |
| `plans/fido-ux-conex/plan.md` | `plans_fido-ux-conex__plan.md` | SUPERSEDED by PLANS.md sec 4 | One-line plan, keep |
| `plans/MATRIZ-TODO.md` | `plans_MATRIZ-TODO.md` | SUPERSEDED by PLANS.md sec 2 | Reconcile T-FIDO partial |
| `plans/piv-ble-proximity/*` (4) | `plans_piv-ble-proximity__*.md` | SUPERSEDED by PLANS.md sec 4 | RF pending |
| `plans/RELEASE-checklist.md` | `plans_RELEASE-checklist.md` | HISTORICAL normative, summarized PLANS.md sec 5 | Keep pipeline exact |
| `plans/risk-acceptance-secureboot.md` | `plans_risk-acceptance-secureboot.md` | HISTORICAL normative | Needs factory sign |
| `plans/seis-implementacoes-produto/*` (4) | `plans_seis-implementacoes-produto__*.md` | SUPERSEDED by PLANS.md sec 4 | None |
| `plans/SIMULACAO-final.md` | `plans_SIMULACAO-final.md` | HISTORICAL, summarized PLANS.md sec 6 | Zero-press blocked |
| `plans/sistema-ota/*` (4) | `plans_sistema-ota__*.md` | SUPERSEDED by PLANS.md sec 4 | OTA in progress |
| `plans/STATE.md` | `plans_STATE.md` | HISTORICAL, summarized PLANS.md sec 6 | Session log closed |
| `plans/TASKS-microdetalhe.md` | `plans_TASKS-microdetalhe.md` | SUPERSEDED by TASKS.md sec 1 | Keep T0-T13 order |
| `plans/unificacao-worktrees/*` (5) | `plans_unificacao-worktrees__*.md` | HISTORICAL, summarized PLANS.md sec 4-6 | Merge on demand |
| `plans/validacao-usb-telas/*` (4) | `plans_validacao-usb-telas__*.md` | SUPERSEDED by PLANS.md sec 4 | COM8 pending |
| `plans/vault-cofre-flash-seguro/*` (4) | `plans_vault-cofre-flash-seguro__*.md` | SUPERSEDED by PLANS.md sec 4 | Planned |
| `app-android/CHECKLIST.md` | `app-android_CHECKLIST.md` | SUPERSEDED by PROJECT.md sec 7 | Confirm UniFFI path |
| `scripts/README.md` | `scripts_README.md` | SUPERSEDED by TASKS.md sec 1 | Confirm PS1 names |
| `tools/host/linux/README.md` | `tools_host_linux_README.md` | SUPERSEDED by PROJECT.md sec 6.1 | Agent autostart pending |
| `tools/host/macos/README.md` | `tools_host_macos_README.md` | SUPERSEDED by PROJECT.md sec 6.1 | Agent autostart pending |
| `tools/host/win/README.md` | `tools_host_win_README.md` | SUPERSEDED by PROJECT.md sec 6.1 | Pairing steps pending |
| 15 single-use probes (`tools/*.py`: `bond_*`, `pair_*`, `usb_*`, `ble_hold_bond`, `need_hands`, `fw_rebuild`, `take_all_wave11c`, `audit_final_screenshots`) | same names in `quarantine/` | QUARANTINED, logic untouched | Indexed in `tools/_QUARANTINE_MANIFEST.txt` |
| `scripts/aegis_auto.py` | `tools/aegis_auto.py` (moved, not quarantined) | RELOCATED, zero changes | Update callers to `tools/` path |
| `scripts/build-diag.ps1` + `scripts/flash-diag.ps1` | `scripts/diag.ps1` (merged stubs) | CONSOLIDATED | None |
| `tools/e2e_user_test.py` + `tools/emulate_app_session.py` + `tools/hil_emulate_full_app_on_board.py` | `tools/e2e_harness.py` (subcommands user/session/onboard/bridge, 113/113 defs preserved, 0 dupes) + originals in `quarantine/` | FUSED, logic preserved | Callers rewired: `tools/aegis_auto.py` + `scripts/battery-serial.ps1` now use `e2e_harness.py user`; `host_hardware_android_bridge.py` kept (live import in `hil_test_ds_and_proximity_lock.py`) |

## 3. Consolidation decisions

- Merge 4 finals (`finalizacoes`, `firmware-fina`, `estado-final-firmware`, `finalizacao-freertos-rust`) into PLANS.md section 6. Keep originals as HISTORICAL.
- Merge 6 pending lists (`plano-amarelos`, `plano-followups`, `proximos-passos`, plus MATRIZ-TODO yellows, STATE next actions, TASKS-microdetalhe T-gates) into PLANS.md section 3.
- Merge 3 handoffs (`HANDOFF-2026-10-20`, `proximity-worktree-handoff`, `secure-guard/06-HANDOFF`) into TASKS.md section 6.
- Merge 8 app docs into PROJECT.md section 7.
- Merge 4 BLE/comms docs into PROJECT.md section 6.1.
- Merge 2 wallet docs into PLANS.md section 4.
- Merge 2 USB validation docs into PLANS.md section 4.

## 4. Pending external blockers

- Second device for zero-press and bonded RF walk-away.
- Factory approval for eFuse burn and destructive erase.
- User eyes for LED order and flicker.
- COM8 reflash for classic-path validation.
- Server pins for OTA and WiFi provision.


## 5. Auditoria de Segurança Ofensiva/Defensiva, Análise de Gaps e Oportunidades de Evolução

> **Data do Laudo**: 01/11/2026  
> **Auditor Responsável**: Agente 5 (Auditoria Ofensiva/Defensiva, Threat Modeling & Firmware Security)  
> **Escopo da Análise**: `crates/aegis-fido-core`, `crates/aegis-fido-firmware`, `crates/universal-device-sdk`, `crates/uniffi-bridge`, `app-android`, `tools/host_hardware_android_bridge.py`.  
> **Worktree Auditada**: `e:/projetos/fido-tray-guard` (`feat/responsive-guard-tray-ssh`).  

---

### 5.1. Sumário Executivo da Auditoria Técnica

Esta auditoria técnica aprofundada avaliou os componentes criptográficos, de barramento de transporte, gerenciamento de estado e proteções de hardware da plataforma **AegisKey S3 / FIDO2 Token**. O sistema apresenta uma arquitetura robusta de separação de domínios, com isolamento do `SecureGuardEngine`, persistência em envelopes `AEGN` cifrados via AES-256-GCM, políticas de presença de usuário (User Presence - UP) e suporte a FIDO2/CTAP2.1, OATH TOTP e carteiras cripto HD.

No entanto, foram mapeados **7 gaps de segurança críticos/altos/médios** no estado atual do código — a maioria decorrente da coexistência do modo de bancada/diagnóstico (`testmode` / `test-hooks`) com interfaces de comunicação local, além de limites de iterações criptográficas em MCU e dependência de armazenamento NVS para controles que demandam ancoragem irreversível em silício (eFuses).

Em paralelo, foram estruturadas **6 grandes oportunidades de evolução de produto** que posicionam o ecossistema AegisKey como referência de segurança para desenvolvedores, sysadmins e custódia patrimonial descentralizada (Web3/Hardware Wallet).

---

### 5.2. Análise Detalhada dos Gaps de Segurança Identificados no Código Real

#### Gap 1 — Flash Encryption & Secure Boot v2 no ESP32-S3 (Severidade: CRÍTICA)
- **Localização no Código**: `partitions.csv` (linhas 4 e 7), `crates/aegis-fido-firmware/src/efuse.rs` (linhas 7-15), `crates/aegis-fido-firmware/src/efuse_plan.rs`.
- **Diagnóstico no Silício**:
  A tabela de partições aloca:
  ```csv
  nvs,      data, nvs,     0x9000,   0x6000,
  storage,  data, nvs,     0x310000, 0x0e0000,
  ```
  No firmware em modo de bancada/diagnóstico (`testmode`), as partições `nvs` e `storage` residem em texto claro na flash SPI externa (NOR flash de 16MB). Um atacante com acesso físico temporário ao dispositivo pode conectá-lo via porta USB nativa ou UART serial e executar o utilitário de baixo nível da Espressif:
  ```bash
  esptool.py --port COMx read_flash 0x009000 0x006000 dump_nvs.bin
  esptool.py --port COMx read_flash 0x310000 0x0e0000 dump_storage.bin
  ```
  Isso permite a exfiltração integral dos registros brutos serializados em CBOR e dos envelopes `AEGN`, expondo hashes de PIN, salts de recuperação, metadados de credenciais FIDO e segredos OATH persistidos.
- **Vetor de Exploração**:
  Sem o `Flash Encryption` em modo `Release` e sem a queima dos eFuses de proteção, o bootloader de ROM do ESP32-S3 aceita comandos do `Download Mode` via USB CDC / UART0. Mesmo que o envelope `AEGN` seja cifrado com chave mestre derivada, a chave dev persistida (se `devkey_persist` estiver ativo) ou chaves efêmeras em NVS podem ser reconstruídas.
- **Remediação Obrigatória para Produção**:
  1. Habilitar `CONFIG_SECURE_FLASH_ENC_ENABLED=y` e `CONFIG_SECURE_BOOT_V2_ENABLED=y` nas configurações do ESP-IDF.
  2. Queimar de forma irreversível nos eFuses do ESP32-S3 (via `espefuse.py` em ambiente estéril de fábrica):
     - `SPI_BOOT_CRYPT_CNT = 0x7F` (ativa Flash Encryption permanente com chave de 256 bits AES-XTS em `BLOCK4..BLOCK6` protegida contra leitura `RD_DIS`).
     - Queimar o hash SHA-256 da chave pública RSA-3072 do Secure Boot em `BLOCK0` / `BLOCK1..BLOCK3`.
     - `DIS_DOWNLOAD_MODE = 1` ou `ENABLE_SECURITY_DOWNLOAD = 1` (desativa download mode irrestrito de ROM).
     - `DIS_PAD_JTAG = 1` e `DIS_USB_JTAG = 1` (desativa depuração JTAG por pinos e via porta USB nativa).

---

#### Gap 2 — Transporte Serial/USB Sem Canal Criptografado Ponta-a-Ponta (Severidade: ALTA)
- **Localização no Código**: `crates/aegis-fido-firmware/src/secure_guard_exec.rs` (linhas 204-209, 231-234, 388-396), `crates/universal-device-sdk/src/secure_guard.rs` (linhas 19-35).
- **Diagnóstico do Protocolo**:
  Os opcodes vendor do Secure Guard (`0x3A..0x3E`), em particular o opcode `0x3B` (`OP_SECURE_GUARD_UNLOCK`), trafegam payloads CBOR contendo a chave `"pin"` diretamente como bytes brutos ou texto UTF-8:
  ```rust
  // secure_guard_exec.rs linhas 206-209 e 388-390
  (Value::Text("action".into()), Value::Text("unlock".into())),
  (Value::Text("pin".into()), Value::Bytes(payload.to_vec())),
  ...
  let pin = match get_field(&entries, "pin").and_then(extract_bytes) { ... };
  ```
- **Vetor de Exploração (Host Malicioso / Malware Local)**:
  Enquanto o CTAP2 oficial especifica o `pinUvAuthProtocol = 2` com acordo efêmero ECDH (P-256 + AES-256-GCM + HKDF) para proteger o PIN no barramento físico, a camada vendor customizada transmite o PIN em CBOR desprotegido sobre o canal serial/HID. Qualquer processo com privilégios de usuário ou administrador no host executando sniffing de USB (via `USBPcap`, `Wireshark` ou hooks na API de porta serial Win32 `ReadFile`/`WriteFile`) captura o PIN da AegisKey em texto claro no momento da autenticação.
- **Remediação Obrigatória**:
  Implementar um protocolo de envelopamento criptográfico efêmero de sessão para o Secure Guard (`pinUvAuthProtocol = 2`):
  1. O cliente (SDK/Host/App) e o firmware realizam uma troca de chaves ECDH sobre a curva P-256: $S = ECDH(d_{hostPriv}, Q_{tokenPub})$.
  2. Derivar chave de sessão de 256 bits via HKDF-SHA256: $K_{session} = \text{HKDF-Expand}(\text{HKDF-Extract}(Salt, S), \text{"AegisKey-Vendor-Guard-Channel"}, 32)$.
  3. Cifrar todo o frame CBOR do opcode `0x3B` com `AES-256-GCM`, enviando o nonce (12 bytes), o ciphertext e a tag de integridade (16 bytes). O PIN jamais tocará o barramento USB em claro.

---

#### Gap 3 — Número de Iterações PBKDF2 em MCU (2.000 iterações) (Severidade: ALTA / MÉDIA com Flash Enc)
- **Localização no Código**: `crates/aegis-fido-core/src/secure_guard/crypto.rs` (linhas 13-14):
  ```rust
  /// Default iterations for MCU-optimized PBKDF2-HMAC-SHA256.
  pub const PBKDF2_DEFAULT_ITERATIONS: u32 = 2_000;
  ```
- **Diagnóstico Criptográfico**:
  O valor de 2.000 iterações de PBKDF2-HMAC-SHA256 foi delimitado para garantir que a derivação do verificador na CPU Xtensa LX7 (240 MHz) complete em ~15 a 30 ms sem estourar o watchdog do FreeRTOS e sem atrasar a resposta dos relatórios de interrupção USB CTAPHID.
  Contudo, segundo os padrões NIST SP 800-63B e OWASP Password Storage Guidelines (que recomendam mínimo de 600.000 iterações para PBKDF2-HMAC-SHA256 em servidores), 2.000 iterações são insuficientes contra ataques offline. Se a flash SPI for extraída por um invasor (conforme Gap 1), uma única placa de vídeo moderna (NVIDIA RTX 4090) processa mais de 50.000.000 de hashes PBKDF2 (com 2.000 rounds) por segundo, permitindo quebrar um PIN numérico de 6 dígitos em menos de 1 segundo e um PIN alfanumérico de 8 caracteres em poucos dias.
- **Remediação Obrigatória (HMAC-Keyed KDF com Hardware ESP32-S3)**:
  Não é viável aumentar as iterações de PBKDF2 no microcontrolador para 100.000 sem paralisar o sistema. A solução criptográfica definitiva para hardware embutido é a **ancoragem no silício via periférico de Hardware HMAC (`HMAC_UP` no ESP32-S3)**:
  1. Gravar uma chave secreta de 256 bits no eFuse `BLOCK7` ou `BLOCK8` configurada para uso exclusivo do periférico HMAC (`eFuse HMAC Key`), com leitura proibida pelo software (`RD_DIS`).
  2. A derivação do verificador de PIN deixa de ser puramente matemática na CPU e passa a envolver o acelerador de silício:
     $$\text{Salt}_{hw} = \text{ESP32\_Hardware\_HMAC}(\text{Key}_{eFuse}, \text{Salt}_{storage})$$
     $$\text{Verifier} = \text{ESP32\_Hardware\_HMAC}(\text{Key}_{eFuse}, \text{PBKDF2}(\text{PIN}, \text{Salt}_{hw}, 2000))$$
  3. **Impacto Defensivo**: O atacante com um dump de flash completo fica matematicamente impossibilitado de rodar Hashcat ou brute-force em GPU/cluster externo, pois o cálculo do hash depende exclusivamente do bloco analógico de eFuses dentro daquele chip físico específico.

---

#### Gap 4 — Presença Física (Botão GPIO 0) Opcional em Modo de Teste (Severidade: MÉDIA / ALTA em Release)
- **Localização no Código**: `crates/aegis-fido-firmware/src/freertos_route.rs` (linhas 254-256):
  ```rust
  let pin_effective = ctx.pin_uv_session
      || ctx.pin_verified
      || (cfg!(feature = "test-mode") && (ctx.pairing_open || ctx.up_latched));
  ```
  `crates/aegis-fido-firmware/src/test_hooks.rs` (linhas 20-34), `docs/test-hooks.md` (linhas 15-20: hook `TEST_UP`).
- **Diagnóstico Operacional**:
  Para viabilizar a automação dos testes de bancada Hardware-In-the-Loop (HIL) sem exigir que um operador pressione manualmente o botão BOOT (GPIO 0) a cada execução de teste, o firmware aceita o comando serial `TEST_UP` que arma um latch temporário de presença de usuário (`up_latched = true`).
  Além disso, no trecho acima de `freertos_route.rs`, se a compilação contiver `test-mode`, operações protegidas por PIN passam a considerar `pin_effective = true` apenas pela presença do latch de UP por software.
- **Vetor de Risco**:
  Se uma release for compilada sem a estrita exclusão de `test-mode` (ou se um artefato de teste for distribuído por engano a usuários finais), malwares rodando no computador conectado podem enviar comandos seriais em background para armar o `TEST_UP` e autorizar transações, assinaturas Web3 e exclusão de credenciais sem nenhum toque físico do usuário.
- **Remediação Obrigatória**:
  1. Adicionar uma trava de pré-compilação com checagem fail-closed em `crates/aegis-fido-firmware/src/lib.rs`:
     ```rust
     #[cfg(all(feature = "prod-strict", any(feature = "test-mode", feature = "dev-hooks")))]
     compile_error!("CRITICAL: Production strict builds must NEVER contain test-mode or simulation hooks!");
     ```
  2. Em `prod-strict`, o registrador de latch de presença física deve ser atualizado exclusivamente pela rotina de interrupção ISR do GPIO 0 (`button.rs`), exigindo transição física de nível lógico com filtro de debounce de 30-50 ms.

---

#### Gap 5 — Autenticação Mútua na Bridge Local (`127.0.0.1:5678`) (Severidade: ALTA)
- **Localização no Código**: `tools/host_hardware_android_bridge.py` (linhas 17-33), `app-android/app/src/main/java/dev/aegiskey/app/data/transport/HostUsbUartBridgeClient.kt` (linhas 19-80).
- **Diagnóstico de Conectividade**:
  O script `host_hardware_android_bridge.py` expõe um servidor HTTP REST na porta `5678` (com binding em `0.0.0.0:5678` ou `127.0.0.1:5678`). Os endpoints críticos incluem:
  - `POST /bridge/touch_up`: Força o disparo do `TEST_UP` no hardware físico.
  - `POST /bridge/vendor`: Despacha opcodes arbitrários com payloads hexadecimais brutos diretamente para o barramento CTAPHID (`0x83`).
  - `POST /bridge/pairing_open`: Dispara o `TEST_PAIRING_OPEN` e abre janela de 60 segundos de pareamento irrestrito.
  Nenhuma dessas rotas valida tokens de autorização, autenticação de sessão ou permissões de processo.
- **Vetor de Exploração (Ataque Local via Browser / Malware Privilegiado)**:
  Qualquer processo em execução na máquina do usuário (ou mesmo uma página web maliciosa executando JavaScript no navegador da vítima através de ataques de Cross-Origin DNS Rebinding contra `localhost:5678` se o CORS não for estritamente restritivo) pode enviar requisições HTTP POST para `/bridge/touch_up` e `/bridge/vendor`, manipulando a chave de hardware sem o consentimento do proprietário.
- **Remediação Obrigatória**:
  1. **Token de Sessão Aleatório em Arquivo Protegido (Bearer Auth)**: Ao inicializar, a bridge gera um token criptográfico de 256 bits (`secrets.token_hex(32)`) e o grava em arquivo restrito às ACLs do usuário do SO (`%LOCALAPPDATA%\AegisKey\bridge_session.token` no Windows / `~/.config/aegiskey/bridge_session.token` com permissão `0600` no Linux/macOS). O cliente Android (via adb push ou parâmetros) ou ferramentas locais devem fornecer o cabeçalho `Authorization: Bearer <token>` em todas as requisições.
  2. **Substituição de HTTP por Named Pipe / Unix Domain Socket**: No Windows, utilizar Named Pipes autenticados (`\\.\pipe\aegis_bridge`) com descriptor de segurança que restrinja acesso ao `TOKEN_USER` logado. No Linux, utilizar Unix Domain Socket com permissões de usuário (`/run/user/$UID/aegis_bridge.sock`).
  3. Desativar escuta em `0.0.0.0` e restringir bind estritamente a `127.0.0.1`.

---

#### Gap 6 — Proteção contra Side-Channel / Glitching de Tensão no Boot & Fault Injection (Severidade: MÉDIA / ALTA em Lab)
- **Localização no Código**: `crates/aegis-fido-firmware/src/ble/dispatch_bind.rs` (linhas 73-102: `authorize_vendor_op`), `crates/aegis-fido-core/src/secure_guard/crypto.rs` (linhas 59-61: `constant_time_eq_32`).
- **Diagnóstico do Fluxo de Controle**:
  A verificação de autorização de opcodes críticos segue um fluxo sequencial simples de branches booleanas:
  ```rust
  if !presence_confirmed {
      return Err(BleGattError::PresenceRequired);
  }
  if !binding_ok {
      return Err(BleGattError::NeedBinding);
  }
  if vendor_op_requires_pin(op) && !pin_authenticated {
      return Err(BleGattError::PinRequired);
  }
  Ok(())
  ```
- **Vetor de Exploração (Fault Injection / EMFI / Clock Glitching)**:
  Em ataques físicos de injeção de falhas (EMFI — Electromagnetic Fault Injection ou pulsos de queda de tensão controlados no pino VDD da CPU Xtensa), um invasor sincroniza um trigger elétrico com o clock da MCU e faz com que a instrução de salto condicional `bnez` / `beq` seja pulada ou interpretada como `nop`. Uma única instrução ignorada permite que `authorize_vendor_op` retorne `Ok(())` sem que a presença ou o PIN tenham sido verificados.
- **Remediação Obrigatória**:
  1. **Double-Check Redundante com Lógica Inversa**:
     Implementar verificações redundantes em registradores separados, com checagem de integridade de fluxo cruzada:
     ```rust
     let cond1 = is_authenticated();
     let cond2_inv = !is_authenticated();
     if cond1 == true && cond2_inv == false {
         // Segundo check redundante atrasado
         if is_authenticated() {
             proceed_critical_operation();
         } else {
             hard_fault_tamper_wipe();
         }
     } else {
         hard_fault_tamper_wipe();
     }
     ```
  2. **Injeção de Jitter Aleatório com Hardware TRNG**:
     Antes de qualquer comparação de hash (`constant_time_eq_32`) ou gate de segurança de opcode, ler um valor aleatório de 8 bits do registrador do gerador de números aleatórios em hardware do ESP32-S3 (`WIFI_RNG` / TRNG) e executar um loop de atraso de $N$ ciclos de clock. Esse jitter temporal elimina a previsibilidade determinística do clock, inviabilizando a sincronização de pulsos de laser/EMFI externos.

---

#### Gap 7 — Assinatura de Firmware OTA (`0x30..0x34`) & Anti-Rollback em Silício (Severidade: ALTA)
- **Localização no Código**: `crates/aegis-fido-firmware/src/ota.rs` (linhas 45-65), `crates/aegis-fido-firmware/src/anti_rollback.rs` (linhas 22-27: `ANTI_ROLLBACK_KEY = "fw/anti_rollback"`).
- **Diagnóstico de Persistência**:
  O mecanismo de proteção contra downgrade de firmware grava a versão atual do sistema em um registro dentro da partição de flash NVS:
  ```rust
  pub const ANTI_ROLLBACK_KEY: &str = "fw/anti_rollback";
  pub const ANTI_ROLLBACK_MAGIC: [u8; 4] = [0x41, 0x52, 0x30, 0x31];
  ```
- **Vetor de Downgrade Físico**:
  Caso o dispositivo não esteja com a criptografia de flash travada permanentemente nos eFuses (conforme Gap 1), um invasor com gravador externo de memória SPI flash (ex.: Raspberry Pi ou CH341A) pode sobrescrever a flash inteira com um dump de versão anterior (vulnerable firmware) contendo um registro `fw/anti_rollback` antigo. O firmware regredirá com sucesso para uma versão depreciada sem violar a verificação de integridade local.
- **Remediação Obrigatória**:
  1. **Contador Anti-Rollback Monotônico em eFuse de Hardware**:
     Utilizar o mecanismo nativo de Anti-Rollback do ESP32-S3 (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y`), que utiliza o campo `security_version` presente no cabeçalho das imagens ESP-IDF e queima permanentemente bits no eFuse `SECURE_VERSION` (`BLOCK0`). Como os transistores OTP de eFuse só queimam de 0 para 1 e não podem ser apagados eletricamente, nenhuma regravação de memória flash externa conseguirá inicializar uma imagem cuja `security_version` seja inferior aos bits queimados no chip.
  2. **Ancoragem da Chave Pública de OTA nos eFuses**:
     O hash da chave pública Ed25519 ou RSA-3072 usada para validar o manifesto OTA (`OP_OTA_FINISH`) deve ser gravado e protegido nos eFuses OTP de fábrica, garantindo que mesmo uma imagem staged maliciosa não consiga forçar a aceitação de chaves laboratoriais.

---

### 5.3. Matriz de Severidade e Remediações Técnicas dos Gaps

| ID | Vulnerabilidade / Gap Técnico | Severidade | Vetor de Ameaça | Esforço | Remediação Canônica Recomendada |
|---|---|---|---|---|---|
| **GAP-01** | Flash Encryption e Secure Boot inativos em testmode | **CRÍTICA** | Dump físico da flash via `esptool.py` (UART/USB) | Médio | Queima eFuse de `SPI_BOOT_CRYPT_CNT`, Secure Boot v2 RSA-3072 e disable JTAG/Download ROM |
| **GAP-02** | PIN em texto claro em CBOR serial/USB (`0x3B`) | **ALTA** | Sniffing USBpcap / porta serial no host local | Médio | Implementar ECDH P-256 efêmero + AES-256-GCM (`pinUvAuthProtocol = 2`) no canal vendor |
| **GAP-03** | 2.000 iterações PBKDF2 na MCU sem chave em silício | **ALTA** | Ataque offline de dicionário em GPU contra dump NVS | Médio | HMAC-Keyed KDF ancorado ao periférico de hardware HMAC do ESP32-S3 (`eFuse Key`) |
| **GAP-04** | Presença física emulável por comando serial (`TEST_UP`) | **ALTA** | Malware no PC simula toque e dispara assinaturas | Baixo | Feature flag `prod-strict` eliminando handlers de simulação; ISR física exclusiva no GPIO 0 |
| **GAP-05** | Bridge HTTP local (`127.0.0.1:5678`) sem autenticação | **ALTA** | DNS Rebinding / CSRF / processos locais disparam comandos | Baixo | Bearer Token por sessão via arquivo protegido + Named Pipe com ACL do usuário |
| **GAP-06** | Decisões de autorização vulneráveis a Fault Injection | **MÉDIA** | Glitching de tensão / EMFI no branch de verificação | Médio | Verificação dupla redundante com inversão lógica + jitter aleatório via hardware TRNG |
| **GAP-07** | Anti-rollback de firmware baseado em chave NVS na flash | **ALTA** | Regravação física de versão antiga via programador SPI | Médio | Ancoragem do contador monotônico no eFuse de hardware `SECURE_VERSION` do ESP32-S3 |

---

### 5.4. Oportunidades de Evolução e Novos Recursos de Produto (Roadmap Técnico)

#### Oportunidade 1 — Provedor Nativo OpenSSH (`sk-ssh-ed25519@openssh.com` / Named Pipe Windows / PKCS#11)
- **Proposta Técnica**:
  Expandir o Aegis System Tray App para atuar como um servidor local do protocolo OpenSSH Agent, ouvindo no Windows Named Pipe oficial:
  `\\.\pipe\openssh-ssh-agent` (ou `$SSH_AUTH_SOCK` no Linux/macOS).
- **Fluxo do Protocolo**:
  1. O cliente SSH (ex.: `ssh user@server`, `git commit -S`, `git push`) envia a mensagem `SSH_AGENTC_REQUEST_IDENTITIES`.
  2. O Tray App consulta as credenciais na AegisKey via opcode `0x22` (`OP_KEY_LIST`) e retorna as chaves públicas Ed25519 registradas no token.
  3. Ao receber um `SSH_AGENTC_SIGN_REQUEST`, o Tray App valida se o Secure Guard está em estado `Unlocked`.
  4. Se `Unlocked`, o hash do desafio de assinatura SSH é despachado via opcode `0x20` (`OP_KEY_SIGN`) para o microcontrolador ESP32-S3.
  5. O usuário confirma a operação com um toque físico no botão (GPIO 0). O firmware assina o desafio com a chave privada Ed25519 e devolve apenas a assinatura criptográfica de 64 bytes.
- **Vantagem Competitiva**:
  A chave privada SSH **nunca existe no computador host** — nem no disco rígido, nem no arquivo `~/.ssh/id_ed25519`, nem mesmo na memória RAM do processo `ssh-agent.exe`. Um malware com privilégios de kernel no Windows não consegue extrair a chave SSH, eliminando completamente vazamentos de credenciais corporativas e chaves de deploy de infraestrutura.

---

#### Oportunidade 2 — Credenciais FIDO2 `hmac-secret` e `largeBlobKey` (CTAP 2.1)
- **Proposta Técnica**:
  Habilitar integralmente a extensão `hmac-secret` (RFC 827) e a gestão de dados `largeBlobs` no motor CTAP2 da AegisKey (`crates/aegis-fido-core/src/extensions/mod.rs`), integrando o gatilho de execução à autorização do Secure Guard.
- **Casos de Uso de Alto Valor**:
  1. **KeePassXC / Bitwarden**: Desbloqueio de cofres de senhas através de desafio-resposta em hardware (`hmac-secret`), sem expor a senha mestra.
  2. **Criptografia de Disco Completo no Linux (LUKS / systemd-cryptenroll)**:
     ```bash
     systemd-cryptenroll --fido2-device=auto /dev/nvme0n1p3
     ```
     O sistema operacional só inicializa e decifra o disco rígido se a AegisKey estiver fisicamente inserida na porta USB e o usuário tocar no botão.
  3. **largeBlobKey**: Armazenamento de certificados digitais e credenciais de contingência (até 4 KiB) criptografados diretamente na partição `storage` da AegisKey.

---

#### Oportunidade 3 — Cofre de Senhas / Seeds BIP-39 Encriptado com Periférico DS/HMAC (`eFuse`)
- **Proposta Técnica**:
  Utilizar o acelerador em hardware de Assinatura Digital (DS) e HMAC integrado aos eFuses do ESP32-S3 para isolar a chave de cifragem KEK (Key Encryption Key) do cofre de credenciais e da semente BIP-39 de 24 palavras (`crates/aegis-fido-core/src/crypto/bip39.rs`).
- **Arquitetura de Isolamento de Memória**:
  - No ESP32-S3, o periférico HMAC aceita que uma chave de 256 bits gravada em eFuse seja conectada internamente por barramento de hardware seguro, sem trafegar pelos barramentos de instruções ou dados da CPU Xtensa.
  - O cofre é decifrado sob demanda em um bloco isolado de SRAM interna, com limpeza imediata (`zeroize`) após a derivação da chave-filha ou do token OTP solicitado.
  - Mesmo diante de uma vulnerabilidade de leitura remota de memória (ex.: buffer over-read em pilha BLE/Wi-Fi), a raiz de cifragem do cofre permanece inacessível na RAM.

---

#### Oportunidade 4 — Integração Windows Hello Companion Device Framework (CDF) & PAM Linux (`pam_u2f`)
- **Proposta Técnica**:
  Transformar a combinação AegisKey + Smartphone (via BLE Proximity Monitor) em um autenticador de proximidade para estações de trabalho corporativas.
- **Mecanismos de Bloqueio e Desbloqueio**:
  1. **Walk-Away Auto-Lock**: O daemon em background monitora o RSSI dos beacons BLE transmitidos pelo smartphone pareado. Quando o RSSI cai abaixo de -80 dBm (usuário se afastou da mesa por mais de 3 metros durante 10 segundos), o Windows é bloqueado imediatamente via chamada Win32 `LockWorkStation()`.
  2. **Zero-Password Touch Unlock**: Ao retornar para a estação de trabalho (RSSI > -65 dBm), o Windows Hello Companion Device Framework detecta a presença da chave e exibe: *"Toque no botão da AegisKey para desbloquear a sessão"*. Um único toque no GPIO 0 autentica o usuário sem necessidade de digitar senhas de rede.
  3. **PAM Linux (`pam_u2f`)**: No Linux, configuração de `/etc/pam.d/sudo` e `/etc/pam.d/gdm-password` para exigir a AegisKey em qualquer elevação de privilégio administrativo.

---

#### Oportunidade 5 — Backup Shamir Secret Sharing (SLIP-0039) 2-de-3 entre 2 Chaves AegisKey + Papel
- **Proposta Técnica**:
  Substituir o modelo convencional de backup BIP-39 de ponto único de falha (uma única lista de 24 palavras em papel) pelo padrão criptográfico de quórum de Shamir (SLIP-0039 / Shamir's M-of-N Secret Sharing).
- **Topologia de Segurança 2-de-3**:
  - A semente raiz de 256 bits é dividida matematicamente em 3 partes (*shares*):
    - **Parte 1 (Share 1)**: Gravada no cofre seguro cifrado da **AegisKey Primária**.
    - **Parte 2 (Share 2)**: Gravada no cofre seguro de uma **AegisKey Secundária/Reserva**.
    - **Parte 3 (Share 3)**: Impressa em um cartão de contingência / placa de titânio (conjunto de palavras mnemônicas de recuperação).
  - **Propriedade Criptográfica**: Nenhuma chave ou documento isolado possui o segredo completo.
    - Se a chave primária for perdida ou roubada, o atacante não consegue recuperar a carteira (pois falta a segunda parte).
    - O proprietário pega a chave secundária + a placa de papel e recupera 100% dos fundos e credenciais instantaneamente.
    - Se o papel for descoberto em uma gaveta, o invasor nada obtém sem possuir uma das chaves físicas.

---

#### Oportunidade 6 — Display OLED/Mini-Tela I2C Opcional (SSD1306) para Confirmação Visual de Endereço/Valor Web3 (Clear Signing)
- **Proposta Técnica**:
  Adicionar suporte no subsistema de display (`crates/aegis-fido-firmware/src/display/`) a displays OLED I2C de ultra-baixo custo (SSD1306 / SH1106 de 128x64 ou 128x32 pixels, pinos GPIO 4 SDA / GPIO 5 SCL) para viabilizar **Clear Signing** em operações financeiras e de blockchain.
- **Eliminação do Vetor de Blind Signing**:
  - Trojans e clipboards maliciosos no PC frequentemente interceptam transações e alteram o endereço de destino na memória antes de submetê-las ao token de segurança USB. Em tokens sem display, o usuário "assina às cegas" (*blind signing*).
  - Com o display OLED ativo:
    1. O firmware recebe a transação (Ethereum EIP-1559, Bitcoin PSBT ou transferência Solana), faz o parsing dos campos estruturados e exibe diretamente na tela da chave:
       ```text
       ┌──────────────────────┐
       │ SEND: 0.7500 ETH     │
       │ TO: 0x892a...4b1c    │
       │ FEE: 0.0012 ETH      │
       │ [PRESS TO CONFIRM]   │
       └──────────────────────┘
       ```
    2. O usuário só confirma fisicamente pressionando o botão se o valor e o endereço exibidos no visor da chave corresponderem exatamente ao pretendido.

---

### 5.5. Conclusão e Próximos Passos Priorizados

A arquitetura AegisKey já apresenta maturidade de código excepcional no ecossistema Rust embutido (`no_std`, isolamento de módulos, zeroize de buffers sensíveis, testes de vetores criptográficos e contratos estritos). 

A transição da bancada de laboratório para o nível industrial de produção requer o fechamento imediato dos gaps de segurança identificados, com destaque para a **queima dos eFuses de Flash Encryption e Secure Boot**, a **adoção do protocolo ECDH no opcode 0x3B** e a **trava `prod-strict` contra simulação de presença**.

Com a implementação simultânea do provedor nativo OpenSSH e da extensão `hmac-secret`, a AegisKey se consolidará como uma solução de segurança de hardware de ponta, substituindo simultaneamente tokens de autenticação corporativa, smartcards SSH e carteiras de custódia cripto em um único dispositivo unificado.
