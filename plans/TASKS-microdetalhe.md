# TASKS microdetalhe - T0..T13 (lane modular-solid-atomic @20ffc71)

> Sem codigo Rust nesta lane - so plano executavel. Checkout principal intocado.
> Porta default: `COM7` (override `%AEGIS_PORT%` / `--port COMx`). Baud `115200`. AP `http://192.168.4.1`.
> Regras: `docs/REGRAS-automacao.md` (R1-R11). Nao rode flash/COM7 nesta tarefa (so docs).
> Comandos exatos abaixo sao para a lane de execucao; aqui ficam registrados, nao executados.

## Convencoes de comando

- `cargo test` = suite completa host. `cargo clippy --all-targets -- -D warnings` = zero warnings bloqueante (R6).
- Flash S3 (MACHINE.md): `. C:\Users\junior\export-esp.ps1`, `$env:IDF_PATH` = v5.3.1, `$env:ESP_IDF_SDKCONFIG_DEFAULTS` = repo `sdkconfig.defaults.esp32s3` (via `scripts/common.ps1`), depois `cargo +esp build -Zbuild-std=std,panic_abort --target xtensa-esp32s3-espidf` e `esptool --port COM7 write-flash ... <bin>` (ou `cargo-espflash --port COM7`).
- Bateria padrao pos-flash: `python tools/app_simulator.py --port COM7 --demo`, `python tools/test_aegiskey_rust.py --port COM7`, `python tools/e2e_user_test.py --port COM7`, `python tools/e2e_zero_press.py --port COM7`, probes `wallet_gate_probe.py`, `ota_deny_probe.py`, `killswitch_deny_probe.py` (todos com `--port COM7`).
- Destrutivos exigem `--confirm` (sem ele = `PermissionDenied`, R-regra de telecomando).

## T0. Congelar REGRAS + matriz COM7

- Dono: orquestracao. Arquivos: `docs/REGRAS-automacao.md` (esta lane), `scripts/env-check.ps1`, `docs/MACHINE.md`.
- Comando: `powershell scripts/env-check.ps1` (exit 0 = pronto).
- Gate: MACHINE.md revalidado (COM7 = CP210x; IDF v5.3.1; S3 identificado).
- Rollback: n/a (doc).

## T1. Orquestrador zero-toque (especificar aqui, codar em lane de execucao)

- Dono: host. Arquivos (novo): `scripts/aegis_auto.py` (ou `.ps1`): `full --port COM7 [--confirm]`, `hil-only`, `release-check`.
- Sequencia interna: env-check -> `cargo test` -> `clippy -D warnings` -> build esp -> flash `esptool --port COM7` -> boot `ONLINE & ACTIVE` no monitor -> `app_simulator.py --port COM7 --demo` -> `test_aegiskey_rust.py --port COM7` -> `e2e_*.py` -> probes gates -> `validate_aegiskey.py` -> relatorio PASS/FAIL + SHA256 artefacto.
- Comando: `python scripts/aegis_auto.py full --port COM7` (com `--confirm` quando houver wipe/OTA/provision).
- Gate: R6 + R11 (zero warnings + bateria verde no device real).
- Rollback: re-flash imagem anterior `aegis-app-esp32s3-devkitc.bin` (SHA em MACHINE.md).

## T2. Simulator como telecomando total

- Dono: host. Arquivos: `tools/app_simulator.py`, `tools/device_ops.py`, `tools/factory_provision.py`, `tools/ota_server.py`.
- Comandos: `python tools/app_simulator.py --self-test` (offline) -> `python tools/app_simulator.py --port COM7 --demo` (fumaca) -> menus: bind claim/challenge/verify/release, recovery PIN (8 tentativas), wipe killswitch `--confirm`, OTA stage/apply `--confirm`, provision load `--confirm`, PIV enroll `0x39`, wallet GEN/LIST/ADDR, OATH PUT/LIST/CODE/DELETE, `TEST_*` so com `--test-mode` contra fw `test-mode`.
- Gate: op privilegiada exige janela de pareamento 60 s pos hold-5s BOOT (menu 9) + UP + PIN; fora da janela = `NEED_BINDING 0x05`.
- Rollback: `BIND_RELEASE` / re-claim recovery.

## T3. A0 doc-sync (drift display stub + features reais)

- Dono: firmware. Arquivos: `docs/capacidades-modulos.md`, `crates/aegis-fido-firmware/src/display/mod.rs`, `crates/aegis-fido-firmware/Cargo.toml`, `crates/aegis-fido-firmware/src/main.rs` (gaps FreeRTOS `543-564`).
- Comando: `cargo test -p aegis-fido-firmware` + `cargo clippy --all-targets -- -D warnings`.
- Gate: stub real documentado; features reais listadas (`board-*`, `wifi`, `proximity`, `debug-terminal`, `test-mode`); gaps FreeRTOS mapeados.
- Rollback: revert doc.

## T4. A1 `tlv-core` (OATH TLV canonico)

- Dono: core. Arquivos: `crates/aegis-fido-core/src/oath/tlv.rs` -> util comum; `wallet_exec.rs`, `vendor_exec.rs`, probes python.
- Comando: `cargo test -p aegis-fido-core` + `python tools/app_simulator.py --self-test`.
- Gate: TLVs congelados (`0x01/02/07/08`, `0x20-0x27`, `0x2E`, `0x38`); testes TLV verdes; clippy zero.
- Rollback: revert crate.

## T5. A2+A3 `NamespacedStore` + `storage-secure` (quebra ciclo persistence<->ota)

- Dono: storage. Arquivos: `oath_store.rs`, `vault_store.rs`, `piv_store.rs`, `persistence.rs:18-22`, `ota.rs`, `nvs_backend.rs`, `src/migrations/`.
- Comando: `cargo test` + HIL `python tools/app_simulator.py --port COM7 --demo` + injecao de corrupcao NVS.
- Gate: `put/get/delete` + `verify-after-write` + quota; `OtaSink` vive em `ota`; AEGN v1 + `NVS_READ_MAX 8192` + fail-closed em corrupcao.
- Rollback: snapshot restore (migrations intactas).

## T6. A4 `OtaKeyProvider` injetado

- Dono: ota. Arquivos: `main.rs:483-513` (`OTA_*PUBKEY`), `ota.rs`.
- Comando: `cargo test` + `python tools/ota_deny_probe.py --port COM7` + `python scripts/check-release-clean.py <bin>`.
- Gate: assinatura errada nega; release zeros negam tudo; chave lab so com `test-mode`; release-clean verde.
- Rollback: revert constante.

## T7. A5->A7 transportes (serial -> USB -> BLE-GATT, um por vez, nunca main.rs inteiro)

- Dono: transport. Arquivos: `serial_ctaphid.rs`, `usb_descriptors.rs`, `components/aegis_usb/*`, `ble_gatt.rs`, `ble_nimble.rs`, `freertos.rs`, `main.rs:50-82,157-185,212-439`.
- Comandos: `cargo test` + `python tools/test_aegiskey_rust.py --port COM7` + `python tools/ble_hold_bond.py --port COM7` + `python tools/ble_connect_test.py`.
- Gate: paridade framing 64 B USB/serial byte-identica; `SerialBackend`/`UsbBackend` isolam `cfg(board-*)`; `ble_dispatch_complete` vira funcao injetavel (struct de deps, fim dos 12 args soltos); matriz opcodes x gates verde; coex `USB > WiFi > BLE`.
- Rollback: por transporte (revert trait, dispatcher legado intacto).

## T8. A8 `trust-binding` (TrustFacade)

- Dono: trust. Arquivos: `binding.rs`, `pairing*.rs`, `proximity.rs`, `recovery.rs`, `main.rs:543-564,567-797`.
- Comando: `cargo test` + HIL bind -> UP -> PIN em serial/BLE/HTTP + `python tools/pair_trigger_probe.py --port COM7` + walkaway RSSI `<-75 dBm/10 s` histerese 5 dB + recovery 8-tentativas com wipe + `python tools/led_probe.py --port COM7`.
- Gate: gaps FreeRTOS fechados ANTES de mover; `confirm_lock` unico; `NEED_BINDING 0x05` so BLE/WiFi; USB/CTAP isento.
- Rollback: vinculo legado release.

## T9. A9-A11 applets (oath -> wallet -> piv)

- Dono: applets. Arquivos: `core/src/oath|wallet/`, `oath_store.rs`, `wallet_exec.rs`, `totp_view.rs`, `wifi_ap.rs:17-19`, `usb/src/piv.rs|ccid.rs|keyboard.rs`, `piv_store.rs`, `ccid_dispatch.rs`, `vendor_exec.rs`.
- Comandos: `cargo test` + `python tools/app_simulator.py --port COM7 --demo` (OATH/wallet/PIV) + `GET /oath/code` (nunca secret) + `python tools/wallet_gate_probe.py --port COM7` + guiao OpenSC F4 (`docs/sessao-20-10-f4-ccid-opensc.md`).
- Gate: contrato de segredo (codigo sai, secret nunca; `SanitizedLog`); TLV OATH total <= 512 B + `validate_v6_label`; wallet RAM-only documentado; PIV slots 24-27 (9A/9C/9D/9E), RSA = `BadAlg`, fora de escopo = `6D 00`.
- Rollback: revert `vendor_exec`.

## T10. A12 `net-wifi` facade

- Dono: net. Arquivos: `wifi_ap.rs`, `wifi_station.rs`, `mdns.rs`, `components/aegis_wifi/*`.
- Comando: `cargo test` (com/sem `wifi`) + HIL AP `AegisKey-XXXX` + `POST /ctap` + `POST /config/wifi` (UP+PIN) + mDNS `aegiskey-XXXX.local`.
- Gate: AP so em pareamento/menu; senha NVS cifrada; radio C atras de trait (replica NimBLE); `wifi` off = `NotCompiled`.
- Rollback: revert wifi.

## T11. A13 `host-sdk` (eliminar drift)

- Dono: host. Arquivos: `tools/*.py`, `tools/host/*`, `tools/uniffi-gen/`, novo `host-sdk` (`VendorOps` TLV unico).
- Comando: `python tools/app_simulator.py --self-test` + bateria HIL via SDK (`--port COM7`).
- Gate: framing unico TLV/CBOR; probes = asserts sobre SDK; lab-mocks off por defeito (`ExternalBlocked`, nunca `Success`).
- Rollback: scripts legados ate paridade.

## T12. A14 scheduler FreeRTOS task-a-task

- Dono: firmware. Arquivos: `freertos.rs`, `main.rs:446-467,989-1204,1438+`.
- Comando: `cargo test` + HIL `python tools/live_monitor.py --port COM7` + `python tools/stability_watch.py --port COM7`.
- Gate: migracao task-a-task, super-loop canibalizado aos poucos; TWDT limpo; sem regressao latencia USB.
- Rollback: feature `freertos` off volta ao legado.

## T13. A15 endurecimento + A16 release industrial

- Dono: seguranca/release. Arquivos: secure-boot config, `sdkconfig.defaults.esp32s3`, `ota_registry.json(.example)`, `tools/ota_server.py`, `tools/factory_provision.py`.
- Comandos pre-release: teto `size` + `python scripts/check-release-clean.py <artefacto>` + `python tools/factory_provision.py --dry-run --port COM7` + manifesto OTA 104 B valido. Release: tag assinada + SHA256 + `ota_server.py` servindo manifesto + rollback ensaiado (snapshot restore HIL, `--confirm`).
- Gate: pre-release verde; tag + rollback testado.
- Rollback: OTA rollback (snapshot).

## Dependencias e compatibilidade

- Ordem: T0 -> T1 -> T2 -> (T3..T12 em ordem A) -> T13. Nenhuma T fecha sem `doc + build + flash COM7 + bateria` (R11).
- R12 mutavel: toda T que criar/mover modulo entrega feature + stub `NotCompiled` + matriz com/sem feature verde.
- R13 stub-only: nenhuma T liga secure-boot ou burn eFuse no caminho automatico; `factory_provision.py` real e burn manual ficam fora do `aegis_auto.py`; pre-release e release auto usam `--dry-run` + zeros fail-closed + re-flash provado.
- Congelado a partir de T4: opcodes/status wire (`0x05`, `6D 00`, `0x2E`, `0x39`, manifesto 104 B, slots 24-27, `oath6/`, `vault/`, `app_bind_*`). Mudanca wire = major + migracao `migrations/` + HIL.
- Evidencia por T: log `cargo test` + log `clippy -D warnings` zero + log HIL COM7 + (a partir de T6) `check-release-clean.py` quando tocar test-mode/OTA.

## Gaps conhecidos (nao escondidos -  entram nas tasks acima)

1. **OTA-COMMIT so USB:** commit/apply da imagem OTA so pelo caminho USB; BLE/WiFi fazem stage/verify mas COMMIT final e USB-only (limite do bootloader/rollback atual). Task afetada: T13 (documentar no manual release + gate HIL exige COMMIT via USB).
2. **`e2e_zero_press` hardcoded:** `tools/e2e_zero_press.py` tem timeouts/sequencia fixos (zero-press = sem toque fisico); fragil a variacao de boot. Task afetada: T1 (parametrizar `--port/--timeout`, retry boot `ONLINE & ACTIVE`) e T12 (revalidar pos-scheduler).
3. **`t_display` offline:** sem placa T-Display na bancada atual (so DevKitC-1 S3 na COM7); telas ST7789 validadas por stub + espelho serial + `t_display_simulator.py`. Task afetada: T3/T10 (nenhum teste display conta como `RealVerified` sem hardware; marcar `ExternalBlocked`).
4. **Burn eFuse manual (R13 stub-only):** `factory_provision.py` real exige procedimento manual supervisionado (leitura dupla BLOCK7/BLOCK8 + lock permanente); orquestrador so vai ate `--dry-run` + prova re-flash sem trava. Secure-boot/eFuse no firmware = stub (`RamEfuse/MockEfuse`, chave release zeros fail-closed). Task afetada: T13 (pre-release = dry-run; burn real = checklist manual assinado, fora do caminho automatico).
5. **Tudo mutavel (R12):** cada modulo novo precisa compilar ligado e desligado (`--no-default-features` + stub `NotCompiled`); `main.rs` nunca hard-coda modulo.
6. **Hardware-first (R14):** reescritas usam periferico real (TRNG, AES/SHA HW, watchdog/TWDT, USB PHY, BLE radio, LED/LCD) via trait existente; shim/host so em `cfg(test)`.

