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
| TEST_LIFETIME_DUMP | lifetime_trace `dispatch_test_command` (gated) | dump ltrace (sem segredos) | `None` |
| TEST_LED_STATE | main.rs D1b (gated) | devolve tela+efeito LED | linha ignorada |
| TEST_LED_RED | main.rs D1b (gated) | trava vermelho p/ olhos | linha ignorada |
| TEST_LED_GREEN | main.rs D1b (gated) | trava verde p/ olhos | linha ignorada |
| TEST_LED_BLUE | main.rs D1b (gated) | trava azul p/ olhos | linha ignorada |
| TEST_LED_OFF | main.rs D1b (gated) | apaga p/ olhos | linha ignorada |
| TEST_LED_RELEASE | main.rs D1b (gated) | devolve LED à jornada | linha ignorada |

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
