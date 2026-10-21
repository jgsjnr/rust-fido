# Affect Analysis
Generated: 2026-10-19

## Affected Files
- create docs/validacao-usb-telas.md
- modify tools/app_simulator.py
- modify tools/live_monitor.py

## Affected Systems
- Emulador Android: fluxos sem hardware
- Serial/COM: E2E nos dois devices
- Monitor/debug: cross-check

## Risk Level
medium

## Parallel Safety
### Can Parallel
- Track A (emulador): [app-android/**]
- Track B (serial devices): [tools/app_simulator.py, COM7, COM8]
### Must Sequential
- Track C (sonda ADB, depende de B): [tools/*, proxy]
- Track D (arquivo final + aviso, depende de A,B,C): [docs/validacao-usb-telas.md]
