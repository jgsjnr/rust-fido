# Standalone Crates

- aegis-secure-guard: leaf, KEEP
- aegis-fido-core: 58 files, KEEP
- aegis-fido-usb: 12 files, KEEP
- aegis-fido-firmware: 108 files, SPLIT-phased
- universal-device-sdk: facade, KEEP, never-depends-on-core
- uniffi-bridge: 1286 lines, KEEP

Deps: firmware->core ~80 hits, firmware->usb, bridge->core+sdk, core->secure-guard re-export, zero core->sdk code deps.
