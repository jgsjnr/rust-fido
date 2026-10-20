# Plan: Seis implementações do produto

## Wave 1
- [ ] Step 1: PIV seguro — VERIFY/AUTH/PUT/GEN + PIN/PUK NVS + zeroize (traces: R-02) — files: [piv.rs, ccid.rs]
- [ ] Step 2: Dongle Ed25519 — challenge via WinUSB + envelope + verify (traces: R-06) — files: [winusb.rs, challenge_response.rs]
- [ ] Step 1b: Auditoria thin ficar-vs-mover, sem código (traces: R-09) — files: [docs/firmware-fina.md]

## Wave 2
- [ ] Step 3: Killswitch — opcode CDC/HID + 2 gatilhos + scripts SO (traces: R-05) — files: [rescue.rs, tools/killswitch.py]
- [ ] Step 4: Proximidade BLE real + agents (traces: R-03) — files: [proximity.rs, ble_gatt.rs]
- [ ] Step 4b: App controle pós-pareamento + menus por operação (traces: R-08) — files: [AegisBleClient.kt, app UI menus]
- [ ] Step 4c: Mover computação pública p/ bridge + getters mínimos + medir SIZE (traces: R-09) — files: [uniffi-bridge, totp_view.rs, wallet/address.rs]

## Wave 3
- [ ] Step 5: Carteira fim-a-fim — ops BLE + NVS + UI + web (traces: R-07) — files: [wallet/store.rs, ble_gatt.rs]
- [ ] Step 5b: Telas Bitcoin + jornada final (traces: R-08) — files: [app UI Bitcoin, jornada]
- [ ] Step 6: Regressão FIDO2/cofre + doc seis-produtos (traces: R-01, R-04) — files: [suite, docs/seis-produtos.md]
