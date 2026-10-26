# Affect Analysis
Generated: 2026-10-19T19:45:00Z

## Affected Files
- create tools/ota_server.py
- create tools/ota_registry.json.example
- create tools/ota_simulator_test.py
- modify tools/factory_provision.py
- create crates/aegis-fido-firmware/src/ota.rs
- modify crates/aegis-fido-firmware/src/lib.rs
- modify crates/aegis-fido-firmware/src/main.rs
- modify crates/aegis-fido-firmware/src/persistence.rs
- create app-android/app/src/main/java/dev/aegiskey/app/net/OtaApi.kt
- create app-android/app/src/main/java/dev/aegiskey/app/usb/OtaTransfer.kt

## Affected Systems
- OTA server/API: novo servico + contrato /api/ota/*.
- Firmware update path: novo estado + swap atomico (risco brick se mal feito -> mitigado por staged+rollback).
- App transporte: novo fluxo USB, sem tocar Auth/Vault/BLE existentes.
- Producao/registro: extensao compativel do provisionamento.

## Risk Level
high

## Parallel Safety
### Can Parallel
- Task S: servidor Python + registry [tools/ota_server.py, tools/ota_registry.json.example]
- Task F: modulo firmware ota.rs + lib export [crates/aegis-fido-firmware/src/ota.rs, crates/aegis-fido-firmware/src/lib.rs]
- Task A: app transporte OtaApi + OtaTransfer [app-android/app/src/main/java/dev/aegiskey/app/net/OtaApi.kt, app-android/app/src/main/java/dev/aegiskey/app/usb/OtaTransfer.kt]
### Must Sequential
- Task W (depends on F): wiring main.rs + preservacao persistence.rs [crates/aegis-fido-firmware/src/main.rs, crates/aegis-fido-firmware/src/persistence.rs]
- Task P (depends on S+F): extensao factory_provision.py + simulador integracao fim-a-fim [tools/factory_provision.py, tools/ota_simulator_test.py]
