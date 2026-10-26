# QEMU ESP32-S3 — bancada virtual (receita)

Bancada rápida sem ciclo de flash. Os ESPs físicos seguem nas COMs
(COM14 trabalho, COM7 bench 16MB); o QEMU **nunca** toca nas COMs —
UART virtual é TCP `127.0.0.1:5678` + espelho em arquivo.

## Pré-requisitos

- `C:\qemu-esp\qemu\bin\qemu-system-xtensa.exe` (binário já instalado).
- Artefatos do dia: bootloader 16MB (`scripts/common.ps1` build),
  `crates/aegis-fido-firmware/partitions.csv` (16MB),
  `C:\t\aegis-app-freertos-s3-testmode.bin`.

## Subir

```powershell
# 1) (uma vez por build) monta a imagem flash 16MB dos artefatos do dia
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/qemu-s3.ps1 -BuildImage

# 2) sobe o QEMU (UART em TCP 127.0.0.1:5678 + log em C:\t\qemu-s3-boot.log)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/qemu-s3.ps1
```

## Provar o caminho virtual

```powershell
python tools/sim_ctap_init.py            # INIT/PING/TEST via TCP
python tools/app_simulator.py --self-test   # 17/17 sintético (sem HW)
```

`Session.connect("tcp://127.0.0.1:5678", 115200)` — `SerialLink` abre
socket (`tcp://`), resto do protocolo byte-idêntico ao COM.

## Bateria na simulação

1. `sim_ctap_init.py` — handshake TEST/UP.
2. `e2e_user_test.py --phase base/pairing/all-safe` com porta TCP
   (onde o gate for só-física, registra `SIM-COVERED` + motivo).
3. Host agents `tools/host/{win,linux,macos}` — mesmos testes, sem rádio.

## O que fica só p/ o HW (gate final, COM7; COM14 por último)

- USB nativo (TinyUSB/AE61, WUDF no Windows) — QEMU não emula USB.
- BLE real/RSSI (trava, walk-away RF) — sem rádio no QEMU.
- BOOT físico/LED/timing de flash — só bancada.
- e2e destrutivo/wipe — só com backup íntegro em `C:/t`.

## Limites conhecidos do QEMU esp32s3

- Sem BLE/WiFi/RF; `aegis_ble_*` responde fail-closed (sem init).
- Sem USB nativo; CTAPHID só via UART (TCP).
- Timing de tick acelerado/diferente — asserts de latência usam folga.
