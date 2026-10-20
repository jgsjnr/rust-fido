# Affect Analysis
Generated: 2026-10-19

## Affected Files
- create crates/aegis-fido-usb/src/piv.rs
- modify crates/aegis-fido-usb/src/ccid.rs
- modify crates/aegis-fido-usb/src/lib.rs
- create crates/aegis-fido-firmware/src/proximity.rs
- modify crates/aegis-fido-firmware/src/ble_nimble.rs
- modify crates/aegis-fido-firmware/src/ble_gatt.rs
- modify crates/aegis-fido-firmware/Cargo.toml
- create tools/host/win/agent.rs
- create tools/host/linux/agent.rs
- create tools/host/macos/agent.rs
- create docs/piv-ble-proximity.md

### File Notes
1. crates/aegis-fido-usb/src/piv.rs — novo applet PIV (SELECT/GET DATA/VERIFY/AUTHENTICATE)
2. crates/aegis-fido-usb/src/ccid.rs — rota APDU PIV via handle_piv_apdu
3. crates/aegis-fido-usb/src/lib.rs — export do modulo PIV
4. crates/aegis-fido-firmware/src/proximity.rs — config/histerese de proximidade BLE
5. crates/aegis-fido-firmware/src/ble_nimble.rs — expor rssi() sem tocar CTAP-BLE
6. crates/aegis-fido-firmware/src/ble_gatt.rs — novo char notify proximidade em 0xFFFD
7. crates/aegis-fido-firmware/Cargo.toml — deps/features para proximity
8. tools/host/win/agent.rs — agent Windows (poll + LockWorkStation); troca de glob tools/host/win/* por path concreto para o parser
9. tools/host/linux/agent.rs — agent Linux; troca de glob tools/host/linux/* por path concreto para o parser
10. tools/host/macos/agent.rs — agent macOS; troca de glob tools/host/macos/* por path concreto para o parser
11. docs/piv-ble-proximity.md — guia de pairing e operacao

## Affected Systems
1. CCID/PC-SC + Windows Logon (BaseCSP/minidriver interop): PIV real pela 1ª vez
2. BLE NimBLE + GATT 0xFFFD: novo char notify + leitura RSSI (sem tocar CTAP-BLE)
3. NVS cifrada / PIN policy: retry counters + chaves 9A/9C/9D/9E
4. Hosts Windows/Linux/macOS: agents novos, fora do firmware

## Risk Level
high

## Parallel Safety
### Can Parallel
- Task PIV-applet: [crates/aegis-fido-usb/src/piv.rs, crates/aegis-fido-usb/src/lib.rs]
- Task Proximity-firmware: [crates/aegis-fido-firmware/src/proximity.rs, ble_nimble.rs, ble_gatt.rs, firmware Cargo.toml]
- Task Hosts: [tools/host/win/*, tools/host/linux/*, tools/host/macos/*]
- Task Docs: [docs/piv-ble-proximity.md]
### Must Sequential
- Task CCID-route (depends on PIV-applet): [crates/aegis-fido-usb/src/ccid.rs]
- Task Merge-final (depends on all): worktree → main, após fd-verify + aval humano
