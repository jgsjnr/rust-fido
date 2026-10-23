# REGRAS - Automacao total + Seguranca maxima (lane modular-solid-atomic)

> Lane: `.slim/worktrees/modular-solid-atomic` @20ffc71. Base: `docs/capacidades-modulos.md:1-551` + historico `docs/*.md`.
> Checkout principal intocado. Sem codigo Rust nesta lane - so estes 2 docs.
> Validacao dona: autor desta lane. Nao rode flash/COM7 nesta tarefa (so docs).

## Porta e telecomando

- Porta default: **COM7 - Silicon Labs CP210x USB to UART Bridge** (flash + console ESP, cf. MACHINE.md).
  Override via `%AEGIS_PORT%` / `--port COMx`. COM3/COM4 (Bluetooth) ignorar.
- Telecomando unico: `tools/app_simulator.py` (serial CTAPHID 64 B + HTTP AP `POST /ctap`, `POST /config/wifi`, `GET /oath/code`).
  Nenhum operador toca no PC alem de ver o resultado final (PASS/FAIL + evidencias).
- Operacoes destrutivas/privilegiadas (wipe/killswitch, OTA stage/apply/commit, provision load, recovery, BIND_RELEASE, PIV enroll `0x39`, wallet GEN, OATH PUT/DELETE, WiFi config) **so via flags `--confirm`** no orquestrador/simulador, com janela de pareamento (hold-5s BOOT, 60 s) + UP + PIN conforme gate. Sem `--confirm`, o comando aborta com `PermissionDenied`.

## R1-R11 (congeladas - violacao aborta a lane)

**R1. Zero toque PC:** uma unica entrada orquestra tudo (`scripts/aegis_auto.py full --port COM7` - a criar em lane de execucao). Todo comando recebe `--port %AEGIS_PORT%` (default `COM7`), `--baud 115200`, `--ap-base http://192.168.4.1`. Sem prompt interativo no caminho automatico.
**R2. App-simulator e o telecomando:** serial 64 B + HTTP AP; wipe, OTA, provision, recovery, bind/release, PIV `0x39`, wallet `0x01/02/07/08`, OATH, rescue `0x2E` via menus/flags (`--port`, `--demo`, `--self-test`, `--test-mode`). Probes (`test_aegiskey_rust.py`, `e2e_*.py`, `wallet_gate_probe.py`, `ota_deny_probe.py`, `killswitch_deny_probe.py`, `device_ops.py`, `factory_provision.py`) viram asserts do orquestrador.
**R3. Facade-first:** consumers via `universal-device-sdk` -> `uniffi-bridge` passthrough puro (sem gates/logica/cache de segredo). Nenhum script importa crate interna.
**R4. 7 estados, sem fallback sintetico:** `Success | Unsupported | Unavailable | PermissionDenied (NEED_BINDING 0x05) | NotCompiled (so feature omitida, stub API estavel padrao display/mod.rs) | ExternalBlocked | RealVerified (so com log teste/HIL)`. `NotCompiled` nunca para erro runtime. Lab-mocks OFF no artefacto; mock ligado = `ExternalBlocked`, nunca `Success`.
**R5. Fail-closed + ordem congelada:** `binding -> UP -> PIN` para CONFIG; USO nunca exige vinculo; USB/CTAP nunca ve `NEED_BINDING`. Zeros negam (OTA release key zeros). `Locked` so via `confirm_lock` unico. `NoSlot` sem sobrescrever (PIV slots 24-27). `6D 00` honesto fora de escopo. Segredos nunca no fio/log (so metadados/contagens, regra `SanitizedLog`).
**R6. Zero warnings bloqueante:** `cargo test` + `cargo clippy --all-targets -- -D warnings` com **zero warnings em todas as fases**. Warning = FAIL, sem `allow` novo sem task dedicada.
**R7. Test-mode gated:** nome no manifesto `src/test_hooks.rs` + handler `#[cfg(feature = "test-mode")]` + doc + `CI-GREP: TEST-HOOK`. Release provado por `scripts/check-release-clean.py` (strings do artefacto). `binding_bypass`, `OTA_TEST_PUBKEY`, `TEST_LIFETIME_DUMP`, `TEST_PAIRING_OPEN/TEST_UP`, reboot-download so em test-mode.
**R8. Sem eFuse fora de provision:** burn so em `provision.load_device_keys` via `factory_provision.py` real / `--dry-run` no pre-release. `RamEfuse/MockEfuse` so host/`cfg(test)`. Envelope unico AEGN v1 (AES-GCM + HKDF eFuse+salt + nonce unico), `verify-after-write`, `NVS_READ_MAX 8192`, snapshot+rollback antes de OTA `Applying`.
**R9. OTA/anti-rollback/zeroizacao:** Ed25519 fail-closed, manifesto 104 B validado antes de `Staged`, streaming sem RAM de imagem `Idle -> Staged -> Verified -> Applying -> Committed`; anti-rollback impede downgrade (recovery 8 tentativas NVS + wipe com UP); `zeroize` em PIN/salt/sessao antes de drop/reboot; tempo-constante em PIN/MAC/sig; TWDT ativo; coex `USB > WiFi > BLE`.
**R10. Um transporte por vez:** `main.rs` god-file nunca migrado inteiro. Ordem: serial -> USB -> BLE-GATT -> trust -> applets -> wifi -> scheduler. Cada passo compila com/sem feature (`NotCompiled` prova stub).
**R11. Cada mudanca grande = doc + build + flash COM7 + bateria.** Evidencia = log `cargo` + log flash `esptool` + log bateria + SHA256 artefacto.
**R12. Tudo mutavel e selecionavel no build:** todo modulo/capacidade atras de feature Cargo (`fido`, `hardwallet`, `ble`, `proximity`, `wifi`, `freertos`, `has-display`, `test-mode`, `lab-mocks`), com stub de API estavel quando off (padrao `display/mod.rs` stub headless). Off = `NotCompiled`, nunca `todo!()`, nunca quebra build. Nenhum modulo hard-coded no `main.rs`.
**R13. Secure-boot/eFuse so stub, nunca trava a placa:** secure-boot e burn eFuse ficam desabilitados em todos os perfis automaticos (dev/test/HIL/nightly/pre-release/release auto). Implementar apenas como stub/test-hook (`RamEfuse/MockEfuse`, `OTA_RELEASE_PUBKEY` zeros fail-closed) para provar o caminho sem gravar. Burn real e lock permanente so em procedimento manual assinado fora do loop, nunca via `aegis_auto.py`. Gate: apos todo flash HIL, re-flash precisa funcionar sem jig; placa travada = FAIL critico.
**R14. Hardware-first em toda reescrita:** em qualquer refactor, preferir periferico real da placa (TRNG/HW RNG, AES/SHA HW, eFuse leitura, LED/WS2812, LCD ST7789, USB PHY, BLE radio, watchdog/TWDT) via driver ja existente atras de trait, nunca emulacao host no firmware. Emulacao/shim so em `cfg(test)`/host. Evidencia: citar periferico usado no doc da task.

## Lifecycle industrial

| Fase | Nome comum | Comando (parametrizado) | Gate bloqueante |
|---|---|---|---|
| dev | `local check` | `cargo test` + `cargo clippy --all-targets -- -D warnings` | zero warnings + verde |
| HIL | `flash COM7 + bateria` | env (`scripts/common.ps1`, `env-check.ps1`) -> build esp -> `esptool --port COM7` flash -> `python tools/app_simulator.py --port COM7 --demo` + `test_aegiskey_rust.py --port COM7` + `e2e_user_test.py` + `e2e_zero_press.py` + probes gates | bateria verde no device real |
| nightly | `nightly/bench` | HIL + `live_monitor.py` + `stability_watch.py` + bench latencia + coex/TWDT | sem regressao, watchdog limpo |
| pre-release | `size + release-clean + provision dry-run` | teto binario + `python scripts/check-release-clean.py <artefacto>` + `python tools/factory_provision.py --dry-run --port COM7` + manifesto OTA 104 B (`ota_server.py` + `ota_registry.json.example`) | release-clean verde, sem burn |
| release | `tag + manifesto OTA 104B + rollback` | tag assinada + artefacto SHA256 + manifesto + rollback ensaiado (snapshot restore HIL) | tag + rollback testado |

`%AEGIS_PORT%` default `COM7`. QEMU-S3 so fumaca - nunca conta como `RealVerified`. Gaps conhecidos (detalhe em `plans/TASKS-microdetalhe.md` seccao Gaps): OTA-COMMIT so USB; `e2e_zero_press` hardcoded; `t_display` offline; burn eFuse manual.

