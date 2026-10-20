# Plan: piv-ble-proximity

## Wave 1
- [ ] Step 1: Esqueleto `piv.rs` + SELECT/GET DATA (CHUID/CCC) + testes NIST (traces: R-01) — files: [crates/aegis-fido-usb/src/piv.rs]
- [ ] Step 2: Esqueleto `proximity.rs` + config/histerese + testes host-side puros (traces: R-04) — files: [crates/aegis-fido-firmware/src/proximity.rs]
- [ ] Step 3: Agent Windows mínimo (poll + LockWorkStation) + doc de pairing (traces: R-05) — files: [tools/host/win/*]
- [ ] Step 4: Guia `docs/piv-ble-proximity.md` parte 1 (traces: R-07) — files: [docs/piv-ble-proximity.md]

## Wave 2
- [ ] Step 5: VERIFY/CHANGE/RESET + retry counters NVS + zeroize (traces: R-02) — files: [crates/aegis-fido-usb/src/piv.rs]
- [ ] Step 6: GENERAL AUTHENTICATE 9A/9E (p256) + GENERATE PAIR (traces: R-01) — files: [crates/aegis-fido-usb/src/piv.rs]
- [ ] Step 7: Expor `rssi()` + char notify proximidade, GATT 0xFFFD intacto (traces: R-04) — files: [ble_nimble.rs, ble_gatt.rs, Cargo.toml]
- [ ] Step 8: Agents Linux + macOS (traces: R-05) — files: [tools/host/linux/*, tools/host/macos/*]

## Wave 3
- [ ] Step 9: Slots 9C/9D + PUT DATA + X.509 `5F C1 05` + `mscp` containers (traces: R-01, R-03) — files: [crates/aegis-fido-usb/src/piv.rs]
- [ ] Step 10: Ligar `ccid.rs` → `handle_piv_apdu` + export `lib.rs` (traces: R-06) — files: [crates/aegis-fido-usb/src/ccid.rs, lib.rs]
- [ ] Step 11: End-to-end: `certutil -scinfo` + logon lab + walk-away ≤15s, sem auto-unlock (traces: R-03, R-04, R-05) — files: [tools/host/*, docs/piv-ble-proximity.md]
