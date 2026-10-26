# Plan: Conexão BLE fim-a-fim

## Wave 1
- [ ] Step 1: Script base + scan/discover/ler FFF4 (traces: R-01, R-04) — files: [tools/ble_connect_test.py]
- [ ] Step 2: Mapear LED vs estados IRL (traces: R-02) — files: [pairing_led.rs leitura]

## Wave 2
- [ ] Step 3: Connect+bond+subscribe+write até acesso total (traces: R-01) — files: [tools/ble_connect_test.py]
- [ ] Step 4: Ops privilegiadas com UP físico (traces: R-03) — files: [COM7]

## Wave 3
- [ ] Step 5: Fix causa raiz + re-teste (traces: R-05) — files: [ble_nimble.rs, pairing.rs]
- [ ] Step 6: Limpar estado + documentar (traces: R-04) — files: [tools/ble_connect_test.py]
