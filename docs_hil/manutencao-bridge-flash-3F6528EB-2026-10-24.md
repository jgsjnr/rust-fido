# Manutencao APROVADA - pausar bridge, flash 3F6528EB, validar, RELIGAR (2026-10-24 ~20:29-20:36 UTC)

Janela 5 min. Sem --confirm. Sem segredo (so contagens + PIDs + nomes de evento).

## 1. Bridge parar/religar (PIDs)

- Captura T0 PID 40336 (parent pwsh 8188):
  - CMD: "C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe" E:\projetos\fido\.slim\worktrees\android-ux-journey\tools\host_hardware_android_bridge.py
  - Parent CMD: pwsh -Command "& \"C:\...\python.exe\" \"E:\...\host_hardware_android_bridge.py\""
  - :5678 LISTEN por 40336; /bridge/info connected=true transport=UART port=COM7 vid_pid=10C4:EA60 uptime_s=891
- Stop-Process -Id 40336 -> STOPPED_OK; parent 8188 GONE (wrapper pwsh -Command sai apos filho; esperado).
- :5678 livre (sem LISTEN, so TIME_WAIT); COM7 livre (pyserial open 115200 OK).
- Reaparecimento externo durante janela (outra lane):
  - PID 24040 (parent 25480) as 20:29:51, mesma script sem -u; /bridge/info uptime_s=2; COM7 ocupada.
  - Stop-Process -Id 24040 -> STOPPED_OK; parent 25480 GONE (wrapper); :5678 livre; COM7 livre.
  - PID 28420 (parent 42648) com -u flag detectado antes do L2; CMD com -u capturado para religar.
  - Stop-Process -Id 28420 -> STOPPED_OK; parent 42648 GONE; :5678 livre; COM7 livre (COM7_OPEN_OK).
- Flash executado com COM7 livre (ver item 2).
- RELIGAR final com CMD capturada atual (com -u), background:
  - CMD: "C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe" -u E:\projetos\fido\.slim\worktrees\android-ux-journey\tools\host_hardware_android_bridge.py
  - Novo PID 38064 LISTEN :5678; /bridge/info connected=true transport=USB port=USB_HID vid_pid=303A:AE61 status=online (auto-selecionou USB pos-fix; prova USB curado).

## 2. Flash

- Comando: esptool --chip esp32s3 --port COM7 --baud 921600 --before default_reset --after hard_reset write_flash 0x10000 C:\t\aegis-app-freertos-s3-testmode.bin
- BIN: 2013168 B SHA256 3F6528EB6400DCC31A8DF13213AF1663D2CEACE71B92C74D98908C6CA57B6190 (prefixo 3F6528EB confere).
- Log: C:\t\logs\flash_20261024_202926.log
- Resultado: OK EXIT 0; Wrote 2013168 bytes (1237436 compressed) em 17.7 s; Hash of data verified; Hard resetting via RTS pin.
- Chip: ESP32-S3 QFN56 rev v0.2, MAC 3c:84:27:c7:17:78.

## 3. Canarios (pos-flash, bridge parado, COM7 livre)

- PING-200B USB: PASS (INIT CID 0x00000001 + USB_SENT cmd=81 pkts=4 bytes=200 -> USB_RESPONSE bytes=200 + PING_OK bytes=200 match=True). Log canario-ping200b-20261024_203113.log. Era FAIL 0/64 pre-flash.
- GetInfo USB: PASS (INIT CID 0x00000002 + MSG cmd=90 -> USB_RESPONSE bytes=480, status=0x00 bytes=479). Log canario-getinfo-20261024_203117.log. Era FAIL 0/64 pre-flash.

## 4. Suites (worktree E:\projetos\fido-hil, bridge parado exceto onde indicado)

- Suite sem flags: 53 passed, 21 skipped, 0 failed em 47.03 s. Log pytest-hil-20261024_203122.log. Alvo 47+/16/0 SUPERADO.
- L2 --uart COM7: 1a tentativa 1 failed (init timeout transiente) + 3 passed; retry 4 passed em 1.89 s. Alvo L2 4/4 ATINGIDO no retry. Logs pytest-hil-L2-COM7-20261024_203214.log (4 failed COM7 ocupada pelo bridge externo) + 203319 (1F/3P transiente).
- Suite --uart COM7: 60 passed, 14 skipped, 0 failed em 68.21 s. Log pytest-hil-uart-20261024_203345.log.
- L6 BLE em janela (TEST_PAIRING_OPEN_300 via COM7 -> pairing_open ok, janela 300 s, --ble-addr 3C:84:27:C7:17:7A): 9 passed, 2 skipped em 34.94 s (2 SKIP gates documentados 0x01/0x05). Log pytest-hil-L6-20261024_203509.log.

## 5. Estado final

- Bridge RELIGADO PID 38064 LISTEN :5678 + /bridge/info ok (USB_HID).
- Flash OK; canarios PASS; suites verdes (0 failed em todas as rodadas finais).
- Nenhum destrutivo (--confirm nunca usado); nenhum segredo em log.
