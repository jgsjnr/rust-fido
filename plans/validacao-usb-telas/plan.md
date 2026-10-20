# Plan: Validação USB + telas

## Wave 0
- [ ] Step 0: Reset-para-estado-conhecido nos dois devices (unclaimed, config default, anotar hashes dos firmwares) (traces: R-01, R-07) — files: [COM7, COM8]

## Wave 1
- [ ] Step 1: Emulador — 22 telas, permissão negada, fallbacks, LogScreen sem device (traces: R-02, R-05) — files: [emulador]
- [ ] Step 2: Self-tests offline simulador + monitor (traces: R-05) — files: [tools/app_simulator.py, tools/live_monitor.py]

## Wave 2
- [ ] Step 3: Serial E2E COM7 S3 (USB/UART, GetInfo/MakeCred/PIN/OATH/keys + destrutivas + dump + live capture) (traces: R-01, R-05, R-07) — files: [COM7]
- [ ] Step 4: Serial E2E COM8 classic (mesmo + jornada display) (traces: R-01, R-03, R-07) — files: [COM8]

## Wave 3
- [ ] Step 5: Sonda ADB→proxy→serial, veredito viável/adiado (traces: R-06) — files: [tools/proxy (novo, condicional)]

## Wave 4
- [ ] Step 6: Escrever docs/validacao-usb-telas.md + avisar aqui (traces: R-04) — files: [docs/validacao-usb-telas.md]
