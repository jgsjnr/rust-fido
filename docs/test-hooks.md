# Gatilhos de teste (TEST-hooks) — manifesto e garantias

Comandos que SÓ existem em firmware `test-mode` (diag). Release
(`test-mode` OFF, default do `Cargo.toml`) não contém nenhum handler:
linhas desconhecidas são ignoradas, gates fazem bypass NUNCA.

Convenção: todo handler tem `// CI-GREP: TEST-HOOK (test-mode only)` e
toda constante `TEST_*` fora de `#[cfg(test)]` mora em
`crates/aegis-fido-firmware/src/test_hooks.rs`. Hook novo sem linha aqui
quebra `test_hooks::manifest_bate_com_docs`; comportamento vazado no
release quebra `scripts/check-release-clean.py`.

## Hooks de texto (D1/UART, test-mode only)

| Hook | Handler gated | O que faz | Release |
|---|---|---|---|
| TEST_UP | main.rs D1 (`#[cfg(feature = "test-mode")]`) | 1 toque BOOT via software (latch 1x/1.5s) | linha ignorada |
| TEST_DOWNLOAD | main.rs D1 (gated) + `aegis_reboot_to_download` (RTC_CNTL) | reboot p/ download ROM sem botões (nunca retorna) | linha ignorada |
| TEST_USB_RECONNECT | main.rs D1 (gated) + `aegis_usb_reconnect` (`tud_disconnect/connect`) | drop + re-enumera o USB nativo sem replug físico | linha ignorada |
| TEST_PAIRING_OPEN | serial_ctaphid `dispatch_serial_pairing_line` (gated) | janela 60s software (UP/bond seguem) | `None` (ignorado) |
| TEST_PAIRING_OPEN_300 | idem (variante 300s p/ teste) | janela 300s software | `None` |
| TEST_PAIRING_CLOSE | serial_ctaphid `dispatch_serial_pairing_line` (gated) | fecha janela via `close_test_window` (vira `Locked`) | `None` (ignorado) |
| TEST_LIFETIME_DUMP | lifetime_trace `dispatch_test_command` (gated) | dump ltrace (sem segredos) | `None` |
| TEST_LED_STATE | main.rs D1b (gated) | devolve tela+efeito LED | linha ignorada |
| TEST_LED_RED | main.rs D1b (gated) | trava vermelho p/ olhos | linha ignorada |
| TEST_LED_GREEN | main.rs D1b (gated) | trava verde p/ olhos | linha ignorada |
| TEST_LED_BLUE | main.rs D1b (gated) | trava azul p/ olhos | linha ignorada |
| TEST_LED_OFF | main.rs D1b (gated) | apaga p/ olhos | linha ignorada |
| TEST_LED_RELEASE | main.rs D1b (gated) | devolve LED à jornada | linha ignorada |
| TEST_BENCH_ON | `dispatch_serial_bench_line` (gated) + `bench_enable` | sessao estendida 24 h em RAM (sem relock idle); NVS/eFuse intactos | `None` (ignorado) |
| TEST_BENCH_OFF | idem (`bench_disable`) | restaura policy salva; idle padrao volta | `None` (ignorado) |
| TEST_OTA_COMMIT_HOOK | D1 legado + dreno FreeRTOS (`handle_freertos_test_line`, gated) | arma hook 1x p/ COMMIT OTA sem BOOT (`up_hook` em `OtaRequestCtx`; BEGIN/CHUNK/FINISH inalterados; release ignora e exige BOOT) | linha ignorada |

## Bypasses (sem handler; `cfg!` em tempo de compilação)

| Bypass | Gate | Efeito só em test-mode | Release |
|---|---|---|---|
| binding_bypass | `binding_bypass_enabled()` = `cfg!(test-mode)` | vendor CONFIG sem claim (UP+PIN seguem) | sempre `false` |
| release_bypass | `dispatch_bind_release` + `cfg!(test-mode)` | RELEASE com só UP (wipe direto) | exige assinatura |
| devkey_persist | `load_or_create_dev_keys` + `cfg!(test-mode)` | chave-dev em flash NVS (sem burn, persiste reboot) | efêmera por boot |
| ota_test_key | `OTA_TEST_PUBKEY` + `cfg!(test-mode)` + bypass provisioned | e2e OTA com chave lab (privada fora do repo) | zeros fail-closed |

## Auditoria (como conferir)

1. `cargo test -p aegis-fido-firmware --lib test_hooks` — manifesto x docs.
2. `python scripts/check-release-clean.py` — build sem `test-mode` +
   scan de strings do artefato (nenhum marcador de runtime).
3. `grep -rn 'TEST_' crates/aegis-fido-firmware/src` — todo literal fora
   de `#[cfg(test)]` deve estar em `test_hooks.rs`, const gated
   (`pairing.rs`, `lifetime_trace.rs`) ou bloco D1 (main.rs).

## Complemento - inventario 24/10 (delta; a base acima nao muda)

Levantado por grep em crates/*/src + tools/*.py + scripts/* com leitura
dos handlers. Gatilho = texto UART (D1/UART ou dreno FreeRTOS); firmware
nunca se auto-estimula. SDK espelha os 13 nomes em
`crates/universal-device-sdk/src/test_hooks.rs` (`TestHookId`, teste
`names_match_manifest`); sem test-mode, `require_test_mode()` = NotCompiled.

| Hook | Gatilho | Efeito (legado / FreeRTOS) | Release | Cobertura |
|---|---|---|---|---|
| TEST_UP | linha `TEST_UP` | latch 1x 1.5s; FreeRTOS arma tambem `touch_latched`+UP sincrono; ack `up_latched source=software` | linha ignorada | unit run/mod.rs + freertos_route; e2e_user_test, aegis_auto, bond_talk, device_ops health, sim_ctap_init |
| TEST_DOWNLOAD | linha `TEST_DOWNLOAD` | ack + reboot download ROM via RTC_CNTL (nunca retorna); FreeRTOS via `TestLineOutcome` | linha ignorada | unit run/mod.rs; flash_soft.py, common.ps1 |
| TEST_USB_RECONNECT | linha `TEST_USB_RECONNECT` | ack + drop/re-enumera USB nativo; FreeRTOS via `TestLineOutcome` | linha ignorada | unit run/mod.rs; R2: sem emissor HW/e2e encontrado |
| TEST_PAIRING_OPEN | linha `TEST_PAIRING_OPEN` | janela 60s software (`dispatch_serial_pairing_line`); mesmo nos dois | `None` | unit pairing/serial_text/run; e2e_user_test, aegis_auto, bond_talk, app_simulator menu |
| TEST_PAIRING_OPEN_300 | linha `TEST_PAIRING_OPEN_300` | janela 300s software; mesmo nos dois | `None` | idem OPEN; bond_talk, e2e_zero_press, stability_watch |
| TEST_PAIRING_CLOSE | linha `TEST_PAIRING_CLOSE` | `close_test_window` (vira Locked); FreeRTOS fecha tambem pairing_mgr do host + desliga AP WiFi | `None` | unit pairing/run; e2e_user_test teardown |
| TEST_LIFETIME_DUMP | linha `TEST_LIFETIME_DUMP` | dump ltrace sem segredos; mesmo nos dois | `None` | unit lifetime_trace; device_ops health, app_simulator menu |
| TEST_LED_STATE | linha `TEST_LED_STATE` | legado: tela+pairing+bond+effect do display_mgr; FreeRTOS: `led_state screen=freertos pairing=<st> up_pending=<0/1> touch=<0/1> uptime_s=<s>` | linha ignorada | unit run/mod.rs; led_probe.py, device_ops health |
| TEST_LED_RED | linha `TEST_LED_RED` | legado trava vermelho; FreeRTOS so ack `led_set <CMD>` sem latch | linha ignorada | unit run/mod.rs; led_probe.py |
| TEST_LED_GREEN | linha `TEST_LED_GREEN` | legado trava verde; FreeRTOS so ack sem latch | linha ignorada | unit run/mod.rs; led_probe.py |
| TEST_LED_BLUE | linha `TEST_LED_BLUE` | legado trava azul; FreeRTOS so ack sem latch | linha ignorada | unit run/mod.rs; led_probe.py |
| TEST_LED_OFF | linha `TEST_LED_OFF` | legado apaga; FreeRTOS so ack sem latch | linha ignorada | unit run/mod.rs; led_probe.py |
| TEST_LED_RELEASE | linha `TEST_LED_RELEASE` | legado `led_test_hold=None` + ack `led_set released`; FreeRTOS mesmo ack sem efeito | linha ignorada | unit run/mod.rs; led_probe.py |
| TEST_BLE_PREINIT (DRIFT: fora de `TEST_COMMANDS`, do SDK e da base) | linha `TEST_BLE_PREINIT` (FreeRTOS, CTAPHID quieto) | log heap + `esp_ble_preinit()` on-demand; rc==0 arma `ble_preinit_ok`; ack `ble_preinit rc=<rc>`; gate `test-mode`+espidf | A-CONFIRMAR R1 | nenhum encontrado |
| TEST_WIFI_* | AUSENTE (grep repo-wide zero matches) | sem hook; WiFi de bancada via `TEST_PAIRING_CLOSE` (shutdown AP) | n/a | n/a |

Emissores: app_simulator `Session` (UP/OPEN/DUMP; `--self-test` offline, sem
serial); e2e_user_test (setup UP/OPEN + teardown CLOSE/LED_STATE);
aegis_auto (OPEN+UP); bond_talk (OPEN_300+UP); e2e_zero_press e
stability_watch (OPEN_300); flash_soft.py + common.ps1 (DOWNLOAD);
led_probe.py (LED_*); device_ops `health` (UP/LED_STATE/DUMP);
sim_ctap_init (guest QEMU, UP/DUMP); ble_connect_test so documenta;
killswitch/ota_deny probes nao usam TEST_* (CTAPHID binario);
build-freertos-s3-testmode.ps1 so builda bancada (NUNCA release);
qemu-s3.ps1 so boot+log. TEST_USB_RECONNECT e TEST_BLE_PREINIT sem
emissor host encontrado.

`scripts/check-release-clean.py`: FORBIDDEN = `source=software`,
`up_latched source=software`, `download_mode`, `pairing_open window_s=`,
`led_set ` (com espaco), `led_state screen=`, `lt_dump v=1`,
`binding-bypass`, `OTA_TEST_PUBKEY`, `TEST-OTA-KEY`. ALLOW_TEST_LITERAL =
`src/test_hooks.rs`, `src/pairing.rs`, `src/lifetime_trace.rs` (os dois
ultimos precisam citar o gate). NOTA: `ble_preinit rc=` e
`usb_reconnect source=software` NAO constam no FORBIDDEN.

A-CONFIRMAR (nao afirmar como verificado):
- R1: destino da linha `TEST_BLE_PREINIT`/dreno de texto no release
  FreeRTOS + cobertura do scan (`ble_preinit rc=` fora do FORBIDDEN).
- R2: `TEST_USB_RECONNECT` sem emissor host/e2e HW encontrado (so unit).
- R3: `TEST_BLE_PREINIT` fora do manifesto/SDK/base (14o. hook);
  `manifest_bate_com_docs` nao pega esse drift (so percorre TEST_COMMANDS).
