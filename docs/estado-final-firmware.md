# Estado final — firmware FreeRTOS test-mode serial (ESP32-S3)

Fechamento 23/10/2026: firmware `98D386E0` no ar, NVS preservada,
proveniencia `C:\t\aegis-app-a7a17691.bin`.

Variante: `crates/aegis-fido-firmware`, features `board-devkitc,freertos,proximity`,
target `xtensa-esp32s3-espidf`. Transporte validado: CTAPHID sobre serial
UART0 + linhas `TEST_*` (test-mode). Placa trabalho: MAC `3c:84:27:c7:17:78`.

## Resultado da bateria (fases seguras)

Fonte: `tools/e2e_user_test.py` via `scripts/battery-serial.ps1`, estado
retomavel em `docs/teste-ponta-a-ponta.md`.

Bateria final full 23/10
(log `C:\t\battery-serial-20261023-112330.log`):

- `offline`: `tools/app_simulator.py --self-test` 17/17.
- `host-win`: PASS; `host-win-tests`: 34 OK.
- `base`: 12/0/0.
- `all-safe`: 27/0/0 — zero FAIL, zero divergente.
- `bench`: 6/0/0.
- T05 `0x01`, T06 `0x05`, T06b `0x05`, T13 `0x00` slot=9 — todos PASS.

Bateria anterior pos-fix do gate de pareamento
(log `C:/t/battery-serial-20261023-003114.log`), superada:

- `base`: 11/0/0 (T01-T10, sem UP, sem janela).
- `all-safe`: 24/2/0 — 24 PASS, 2 DIVERGENTE conhecidos, 0 FAIL
  (fail 1 para 0 em relacao a rodada anterior).
- `bench`: 5/5/0 (B01 PING, B02 GetInfo 480 B, B02b janela, B03 MC ~743 B,
  B04 GA ~170 B).
- `offline`: `tools/app_simulator.py --self-test` 17/17 + agentes host
  `--self-test` verdes (porta de entrada, sem HW).
- T13 (`KEY_GEN`): saiu de `0x05` (gate) para `0x04` (execucao alcancada,
  `BadEnvelope` fail-closed). Gate corrigido; rotulo segue "divergente"
  por estriteza do harness (espera `0x00`). Trace no fio prova:
  `[VENDOR] op=0x20 pairing=1 up=1` -> resposta 1 pkt -> status `04`.
  Sonda isolada confirma `0x04` nos slots 41 e 200 (ambos >=
  `MAX_KEY_SLOTS=32`, logo `BadEnvelope` correto — slots validos no e2e
  sao 5..9). Ver `docs/bateria-serial.md` ("Residuo entre fases") e diario
  em `docs/teste-ponta-a-ponta.md`.
- T05 (`KEY_LIST` sem UP): persiste `0x01` na base e `0x00`+89 B na
  all-safe sem `TEST_UP` previo — latch residual inter-fases (RAM sem
  reset entre fases), nao bug de gate. Pendente: harness afirmar estado
  limpo no open (`up_pending=0`) ou EN-reset entre fases.

## O que esta pronto

- CTAPHID serial completo: INIT/PING/GetInfo/MC/GA + vendor `0x20-0x27`,
  bind-mgmt `0x28-0x2D`, wallet `0x35-0x37`, fw-log `0x38` (`EV=`),
  rescue/killswitch `0x2E`, trigger de pareamento `0x2F`.
  Despacho em `src/freertos.rs::dispatch_serial_vendor_msg` (espelho da
  secao D legada); gates binding -> UP -> PIN preservados, fail-closed.
- LED ok: `TEST_LED_STATE` + `TEST_LED_{RED,GREEN,BLUE,OFF}` + `TEST_LED_RELEASE`
  via UART (test-mode only, sem persistencia). Mapa: idle ciano respirando,
  pairing azul, bonded verde solido, locked vermelho solido.
  Ver `docs/led-diagnostico.md`.
- NVS preservada: `PlatformFlashBackend` NVS-device/RAM-host; CLAIM, PIN
  `1234`, recovery `1234`, vendor keys/OATH sobrevivem a EN e reboot.
  Wallet store e sessao PIN sao RAM (somem no reboot, por desenho).
- Main stack 65536: `CONFIG_ESP_MAIN_TASK_STACK_SIZE=65536` em
  `sdkconfig.defaults` (workspace root, aplicado via
  `ESP_IDF_SDKCONFIG_DEFAULTS` em `scripts/common.ps1`). Antes 32768.
  Marca d'agua por etapa via `uxTaskGetStackHighWaterMark`
  (`[STACK] ... bytes`; rotulo corrigido de words para bytes).
- Proibicoes respeitadas (sempre): nenhuma operacao de eFuse (burn/write),
  nenhum secure boot, nenhuma flash encryption. Guard em
  `scripts/ci-guard-secureboot.ps1`. Chave-dev test-mode em flash NVS
  (`aegisdev`, sem burn).
- Gate de pareamento ao vivo: `pairing_open` lido AO VIVO
  (`pairing_mgr` + `freertos_test`) no momento do despacho, com gate
  cfg test-mode/non-test-mode, em `src/main.rs`. Antes era cache
  `pairing_open_now` atualizado so 1x/s no Tick, que devolvia `0x05`
  indevido no mesmo segundo da abertura. 2 testes de regressao host
  novos em `freertos.rs` (janela fresca passa sem Tick; janela fechada
  nega `0x05` sem consumir latch). Host: 277 passed / 0 failed no crate
  firmware.
- Firmware `98D386E0` flashado e verificado em COM7 (verify OK),
  NVS preservada, proveniencia `C:\t\aegis-app-a7a17691.bin`.
  Boot readback estrito OK: `backend online` -> `[STACK] apos storage:
  232432 bytes` -> `Binding loaded (claimed=false)` -> `managers ok` ->
  `ONLINE & ACTIVE!` -> 75 ticks sem TWDT/panic/reboot. Hang anterior era
  binario de proveniencia desconhecida (`e65ad669`, stack 116 B); causa:
  `store("boot_state")` com envelope 545 B na stack + main sem yield.
- Fixes no build: envelope no heap (zeroize), `boot_state` pos-yield na
  housekeeping (1x/boot), teto `key_slots` 512->4096 (restaurado apos
  checkout acidental — com teste de regressao), `TEST_PAIRING_CLOSE` +
  setup limpo (janela+latch, touch= no `LED_STATE`), gate vendor ao vivo,
  gate BLE atras de preinit.

## Limitacoes conhecidas (por desenho nesta variante)

- USB-OTG nativo (TinyUSB) DESLIGADO: `tinyusb_driver_install` da
  `LoadProhibited` no HW durante o dump do descritor (o legado em QEMU
  nunca exercitou o periferico real). CTAPHID segue 100% pela serial.
  Ver comentario em `src/main.rs` ("USB-OTG nativo (TinyUSB): DESLIGADO").
  Sem root-cause confirmado no HW; reativacao apos diagnostico dedicado.
  Sem eFuse/secure/NVS tocados pelo gap.
- BLE sem validacao no ar: init preguicoso (lazy) — `esp_ble_preinit` no
  boot trava neste HW (`LoadProhibited` no `esp_intr_alloc` do controller,
  em investigacao); boot segue sem BLE (`[INIT] BLE init lazy ...`),
  preinit sob demanda via `TEST_BLE_PREINIT`, advertising ligado por gate
  no loop (`esp_ble_start` -> `ensure_init`). Contrato de fio congelado em
  `docs/ble-protocol.md`; radio real (`aegis_ble_nimble.c`, GATT 0xFFFD,
  bonding NVS) documentado em `docs/ble-nimble.md`, pendente de prova fim
  a fim no ar (scan, bond, walk-away).

## O que falta (pendente / nao feito)

1. `destructive`/`wipe` com slots ocupados ainda valido (fases
   destrutivas executadas antes com PIN `1234`; `wipe` nunca executou por
   falha de handshake na epoca). Nunca automaticos; exigem `-Force` +
   `--confirm` (`--confirm-release` p/ wipe) + ordem explicita do usuario.
2. BLE fim-a-fim no ar (over-the-air): scan `AegisKey` na janela, bond
   JustWorks + UP, walk-away lock-only, USB ativo veta anuncio. Hoje so
   politica host-testavel + shims + gate atras de preinit.
3. USB reativar pos-root-cause: diagnosticar `tinyusb_driver_install`
   no HW real, depois repetir U1-U3 (`docs/teste-ponta-a-ponta.md`).
4. Commit do WIP: decisao do usuario.
5. T05/T13 estriteza do harness: RESOLVIDO na bateria final full 23/10
   (T05 `0x01`, T06 `0x05`, T06b `0x05`, T13 `0x00` slot=9, todos PASS;
   zero FAIL, zero divergente). Item anterior com `BadEnvelope`/latch
   residual superado pelos fixes de gate, setup limpo e teto key_slots.

## Como reproduzir

Build (device ESP32-S3 FreeRTOS test-mode):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-freertos-s3.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-freertos-s3-testmode.ps1
```

Flash via esptool sem BOOT (download-mode por software via `TEST_DOWNLOAD`;
fallback manual BOOT+EN so se o app nao responder):

```powershell
.\scripts\flash.ps1 -BinPath C:\t\aegis-app-freertos-s3.bin -Chip esp32s3 -Port COM7 -Baud 921600 -Monitor
```

Se a placa nao bootar sozinha, apertar EN. Revalidar a placa pelo MAC do
chip (`esptool read_mac`), nunca so pela COM (portas trocam ao reconectar).

Bateria serial (fases seguras; log em `C:\t\battery-serial-<data-hora>.log`):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/battery-serial.ps1 -Port COM7 -Phase all
```

`-Phase base|all-safe|bench|offline` = recorte focado. `-Phase
destructive|wipe` = SO com `-Force` + ordem explicita do usuario no turno.
Nenhum teste manual avulso conta como evidencia; log em arquivo sempre.
Playbook completo em `docs/bateria-serial.md`; mapa e diario em
`docs/teste-ponta-a-ponta.md`.
