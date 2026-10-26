# HANDOFF — Wave2 Step3 + validação em hardware (2026-10-20)

Leitura mínima para continuar: `plans/seis-implementacoes-produto/{plan,task,architecture}.md`,
`docs/MACHINE.md`, `docs/firmware-fina.md` (seção Delta Wave2 Step3).

## 1. O que foi feito

- Rescue `0x2E` fiado nos 3 transportes (`main.rs` USB-C, serial-D, BLE
  `OP_MSG`), UP do latch BOOT em uso único, PIN `false` (remoto nega
  fail-closed), resposta status-first, framing intacto.
- Fachada `otp/mod.rs` reexporta killswitch; `serial_ctaphid::{is_rescue_msg,
  dispatch_serial_rescue}` + 2 testes; teste de fronteira em `ble_gatt.rs`.
- Host: docstring do `proximity_agent.py` sem TODO obsoleto (backend por
  scanner injetável fail-closed).
- Ambiente: `espup uninstall` + `install -t esp32,esp32s3` (toolchain `esp`
  estava quebrado); `scripts/env-check.ps1` novo; `scripts/common.ps1` aplica
  `export-esp.ps1`, corrige hash SHA256 vazio e retorno do flash;
  `docs/MACHINE.md` com inventário, receita e placa.
- Placa COM7 identificada: ESP32-S3 QFN56 rev0.2 8MB MAC 80:65:99:df:4b:cc.

## 2. Evidências (tudo observado, nada suposto)

- `cargo test`: firmware+proximity 236 passed; core ok; usb 67 passed.
- `clippy -- -D warnings` (core+firmware+usb, bins+lib): exit 0.
- Python: host 20 ok, killswitch 13 ok, `--self-test ok`, `--dry-run` exit 0.
- `cargo +esp check` bins S3 (com IDF pin + sdkconfig): exit 0.
- Build release: S3 `aegis-app-esp32s3-devkitc.bin` 2.646.256 B (< factory
  3.145.728), classic `aegis-app-esp32.bin` 1.987.072 B; ambos exit 0.
- Flash COM7: `Wrote 2646256 bytes ... Hash of data verified`; boot mostra
  bootloader IDF v5.3.1, factory 0x10000 len 0x300000, app ONLINE & ACTIVE.

## 3. Pendências (com motivo)

- Plumbing ClientPIN→`pin_uv_authenticated` (CtapEngine é opaco; sem ele o
  killswitch remoto nega) — exige expor o resultado do token no core.
- Gesto de armar o hold físico (hold 5s é compartilhado com pareamento;
  armar ali seria colisão de modo) — decisão de UX pendente.
- App Android: referências conferidas por inspeção; build exige SDK, fora daqui.
- `docs/seis-produtos.md` (Step 6) e Wave 3 (carteira, telas Bitcoin) fora de escopo.
- Nada commitado: árvore com 14 modificados + 7 não rastreados para revisão.

## 4. Como operar

```powershell
.\scripts\env-check.ps1            # exit 0 = pronto
.\scripts\test-all.ps1             # gates host
.\scripts\build-esp32s3-devkitc.ps1 -Flash -Port COM7 -Monitor
.\scripts\build-esp32-ttgo.ps1 -OnlyBuild   # classic (sem placa ligada)
```

## Adendo 2026-10-20 (noite) — fix pareamento BLE

Diagnóstico via UART test-mode no hardware vivo (`TEST_PAIRING_OPEN` +
`TEST_LIFETIME_DUMP`, imagem `*-diag.bin` com `test-mode,debug-terminal`):
janela abria e advertising ligava, mas cada poll executava `esp_ap_stop()`
(`lt.transport.close=576` em 7s + `[WIFI] AP off.` a cada 10ms) — o `else`
do poll do AP não tinha guarda de borda, com churn no rádio durante o
bonding. Fix: `wifi_ap::ap_poll_action`/`ApPollAction` (Start/Stop/None,
edge-triggered) + teste `ap_poll_action_sem_spam_de_stop`; `main.rs` virou
`match`. Revalidado no hardware: `close=0`, zero spam, adv ativo. Bônus:
`fetch_update`→`try_update` em `lifetime.rs` (deprecation que quebrava o
gate clippy). Gates: firmware 237, core, clippy zero.

## Adendo 2026-10-20 (madrugada) — pareamento BLE validado no hardware

Com a janela aberta por UART (`TEST_PAIRING_OPEN`, sem fechar a serial para
não resetar a placa): scan acha `AegisKey` 80:65:99:DF:4B:CE com UUID
`0000fffd`, CONNECT ok, bond JustWorks ok no SO; firmware responde `link
seguro sem UP: toque no BOOT` e segura `pairing=0` (fail-closed correto —
UP físico não pode ser fakeado, então o roteiro IRL para aí por desenho).
Sem reboot loop (uptime 90s, 0 resets). Achado operacional: ABRIR QUALQUER
monitor serial reseta a placa e mata a janela de 60s — monitorar durante o
pareamento pelo app sempre falha (parece flicker/sumiço). Ritual certo:
hold BOOT 5s (LED respira azul) → parear no app em 60s → tocar BOOT no
prompt → verde sólido. `bleak` instalado no host; `ble_connect_test.py`
--self-test 14/14.

## Adendo 2026-10-20 (madrugada 2) — Wave2 resto + LED ground-truth + release

- Agents walk-away lock-only Linux (`loginctl`) e macOS (`CGSession`)
  espelhando o win: `tools/host/linux|macos/proximity_agent.py` (bleak
  opcional, fail-closed sem ele) + `test_proximity_agent.py` 21/21 cada
  + README + `--self-test`/`--simulate`.
- LED: `TEST_LED_STATE` (tela+pairing+bond+efeito ativo) e
  `TEST_LED_{RED,GREEN,BLUE,OFF}` + `TEST_LED_RELEASE` na diag
  (test-mode only, latch reaplicado todo poll; release byte-idêntica —
  2.646.512 B antes e depois). Firmware manda o efeito certo
  (`IdleStandby`→CYAN breathing); `Locked`→RED sólido + rádio mudo
  (explica app vazio fora da janela). `tools/led_probe.py` pronto p/
  olhos do usuário; hipótese driver (IRQ durante bit-bang) só se as
  primárias falharem — ver `docs/led-diagnostico.md`.
- Killswitch `--emit-*` confirmado funcionando com `--dry-run` (sem bug).
- Docs: `docs/seis-produtos.md` (Step 6), `docs/led-diagnostico.md`,
  `docs/validacao-usb-telas.md` §3 revalidada.
- Branch `fd-integracao-unificada` criada em `4b28aa4` (rastreio).
- Release rebuildada `71FDF318…` 2.646.512 B; flash travou: COM7 sumiu
  (só COM3/COM4 BT) — placa desplugada ou USB caiu; reflash pendente
  ao reconectar: `build-esp32s3-devkitc.ps1 -Flash -Port COM7`.
- Gates: 406 cargo + clippy zero + test-all + 8/8 + killswitch 13 +
  ota + 20/21/21 proximity + live 10 + app_sim 15 + guard secureboot.
