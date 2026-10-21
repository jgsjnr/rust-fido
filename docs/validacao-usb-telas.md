# Validacao USB + telas — matriz e modificacoes necessarias

**Data:** 2026-10-19/20 · **Topic:** validacao-usb-telas · **Status:** COM7
revalidada em 20/10 (diag test-mode); COM8 pendente reflash.

## 1. Emulador (sem hardware) — 22/22 PASS

Todas as telas abrem sem crash e sem FATAL; sem device mostram vazio/erro
amigável. Permissão BT negada: abre normal, sem SecurityException.
FLAG_SECURE confirmado (screenshots pretos são proteção, não bug).

## 2. Serial E2E COM8 (classic, UART0 115200 8N1) — pendente reflash

- Build de bandas pronto (`aegis-app-esp32.bin` 1.987.136 B); falta
  flashar na COM8 e validar fim do OOM + bateria serial.

## 3. Serial E2E COM7 (S3) — VALIDADA 20/10 (diag test-mode)

- Flash `aegis-app-esp32s3-diag.bin` 2.656.320 B, hash verified, boot
  `ONLINE & ACTIVE` (VID 0x303A/PID 0xAE61, heartbeat 3s).
- Serial CTAPHID 64B vivo: PING 64B → resposta `BF` 199B (roteamento
  serial→CTAP implementado desde Wave anterior; doc antigo §3 superado).
- `TEST_PAIRING_OPEN` → `pairing_open window_s=60 source=software` +
  `[LT][pairing] arming software` + `adv on (pairing=1)`; dumps em
  uptime 16s/26s com `lt.pairing.arming=1`; scan BLE achou `AegisKey`
  no MAC do device (over-the-air OK).
- Release (sem test-mode) corretamente NÃO responde `TEST_PAIRING_OPEN`
  (sondado: só heartbeat) — sem gatilho de pareamento por software.
- `USB Mounted: false` com UART aberta (esperado; função FIDO2 é na
  porta NATIVA USB-OTG, não na COM).
- LED: ver `docs/led-diagnostico.md` (ground-truth via `TEST_LED_STATE`
  + primárias `TEST_LED_{RED,GREEN,BLUE,OFF}`; aguardando olhos do usuário).

## 4. Ponte ADB→proxy→serial — VEREDITO: VIÁVEL

Emulador alcança host via `http://10.0.2.2:8888` (sem `adb forward`; app
já tem base URL configurável). Proxy = `http.server` + framing 64B de
`app_simulator.py`. Firmware: zero mudanças. Checar cleartext policy
antes do PoC.

## 5. Qual USB usar na S3

- **UART** (CP210x, COM7): logs, monitor, flash via esptool.
- **NATIVA USB-OTG**: função FIDO2 HID (VID 0x303A/PID 0xAE61) +
  JTAG-serial + download.
- Uso no PC/celular como chave = porta NATIVA. Monitor/teste = UART.
- **Armadilha DTR (20/10, real)**: abrir a COM com `pyserial` + `setDTR(True)`
  (ou o default DTR=True do open) dá transição que **reseta a placa**, e
  fechar com DTR preso **segura o chip em reset** (silêncio total nas
  próximas sessões — parecia "crash espontâneo"/"wedge pós-BLE", não era).
  Regra: `app_simulator.SerialLink` (Win32 cru, sem DTR/RTS) ou raw com
  `setDTR(False)+setRTS(False)` no open E no close. Uptime monotônico
  por 144s com connect BLE no meio prova estabilidade sem isso.

## 6. Modificacoes necessarias (por prioridade)

1. [ ] Flash classic com build de bandas + validar fim do OOM (COM8).
2. [x] Bateria COM7 completa (20/10, diag) — este doc §3.
3. [ ] PoC ponte `10.0.2.2:8888` (checar cleartext no manifest).
4. [ ] Olhos do usuário nas primárias do LED (§3 + led-diagnostico).
5. [ ] Tela preta no emulador: já explicado (FLAG_SECURE); sem ação.
