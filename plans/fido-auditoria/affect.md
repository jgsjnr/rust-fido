# affect.md — arquivos tocados por fase (leitura fd-task, escrita futura em worktree)

## Fase 0 (P0 invasao)
- crates/aegis-fido-firmware/src/main.rs:182,191,193,229-233 (boot MockEfuse/MockFlash/nonce/TOTP)
- crates/aegis-fido-firmware/src/efuse.rs:103-175 (MockEfuseStorage -> RealEfuse)
- crates/aegis-fido-firmware/src/persistence.rs (SecureStorage nonce monotônico)
- crates/aegis-fido-core/src/otp/rescue.rs:6,23,44-99 (RESC gate UP+PIN)
- crates/aegis-fido-core/src/ctap/client_pin.rs:42-60,154-161,244-457 (retries persistido + constant_time + powerCycleState)
- crates/aegis-fido-core/src/credential/store.rs + ctap/get_assertion.rs:168-198 (sign_count atomico)
- crates/aegis-fido-core/src/crypto/pin_protocol.rs:26,34,54 (IV/salt TRNG)

## Fase 1 (L0-L5)
- novo: core/src/policy/up_policy.rs, core/src/transport.rs, core/src/crypto_core.rs, core/src/error.rs
- refator: core/src/vault/* (split), firmware/src/main_loop.rs (watchdog, sem alloc)

## Fase 2 (config P0-P3)
- novo: crates/*/src/config.rs, migrations/aegn_v1_to_v2.rs, tools/factory_provision.py
- docs: AAGUID/VID-PID/serial por unidade

## Fase 3 (BLE+menu, default-off)
- novo: firmware/src/ble/gatt_fffd.rs, firmware/src/ble/bonding.rs, firmware/src/menu/state.rs, firmware/src/coex.rs

## Fase 4 (app Android)
- novo: app-android/** (6 telas Kotlin), crates/uniffi-bridge/src/lib.rs

## NUNCA TOCAR sem gate
- usb_descriptors bytes, CTAP dispatch/status codes, ordem canonica COSE, AAGUID sem bump, build/ sem backup, esptool --verify (v5.6 nao tem)

- Wave0 novo: snapshots/ctap_golden.json, usb_desc.sha256, nvs_schema.md, excecoes-paridade.md, features ble/menu/wifi
