# Affect Analysis
Generated: 2026-10-19T22:00:00Z

## Affected Files
- modify docs/carteira-cripto.md
- modify docs/nvs_schema.md
- create crates/aegis-fido-usb/src/piv.rs
- modify crates/aegis-fido-usb/src/ccid.rs
- modify crates/aegis-fido-usb/src/lib.rs
- create crates/aegis-fido-firmware/src/proximity.rs
- modify crates/aegis-fido-firmware/src/lib.rs
- modify crates/aegis-fido-firmware/Cargo.toml
- create crates/aegis-fido-firmware/src/ota.rs
- create crates/aegis-fido-firmware/src/migrations/vault_v7.rs
- modify crates/aegis-fido-firmware/src/migrations/mod.rs
- create app-android/app/src/main/java/dev/aegiskey/app/net/OtaApi.kt
- create app-android/app/src/main/java/dev/aegiskey/app/usb/OtaTransfer.kt
- create tools/ota_server.py
- create tools/ota_registry.json.example
- create tools/test_ota_server_smoke.py

## Notes
Integracao read-only nas origens; reconciliacao (fiação `mod` em `lib.rs`/`mod.rs`, namespaces NVS `wallet_*` x `vault/`, opcodes OTA `0x30+`) acontece so na branch propria `fd-integracao-unificada`.

## Affected Systems
- firmware-storage (vault/migracoes/NVS): envelope AEGN, dual-slot, idempotencia.
- usb-ccid (piv hook, applet PIV, paridade APDU).
- firmware-features (proximity/ota feature-gates, coexistencia BLE/WiFi).
- android-transporte (OtaApi/OtaTransfer via CTAPHID 64B).
- tooling (ota_server, factory_provision, rastreio baseline).

## Risk Level
high

## Parallel Safety
### Can Parallel
- Task A (rastreio baseline, so leitura): [baseline 4b28aa4]
### Must Sequential
- Task B (base + integra carteira + vault + piv + ota + paridade, sob demanda): [docs/carteira-cripto.md, docs/nvs_schema.md, crates/aegis-fido-usb/src/piv.rs, crates/aegis-fido-usb/src/ccid.rs, crates/aegis-fido-usb/src/lib.rs, crates/aegis-fido-firmware/src/proximity.rs, crates/aegis-fido-firmware/src/lib.rs, crates/aegis-fido-firmware/Cargo.toml, crates/aegis-fido-firmware/src/ota.rs, crates/aegis-fido-firmware/src/migrations/vault_v7.rs, crates/aegis-fido-firmware/src/migrations/mod.rs, app-android/app/src/main/java/dev/aegiskey/app/net/OtaApi.kt, app-android/app/src/main/java/dev/aegiskey/app/usb/OtaTransfer.kt, tools/ota_server.py, tools/ota_registry.json.example, tools/test_ota_server_smoke.py]
