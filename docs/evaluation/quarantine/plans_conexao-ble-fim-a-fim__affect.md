# Affect Analysis
Generated: 2026-10-19

## Affected Files
- tools/ble_connect_test.py (create)
- crates/aegis-fido-firmware/src/ble_nimble.rs (modify)
- crates/aegis-fido-firmware/src/pairing.rs (modify)
- crates/aegis-fido-firmware/src/pairing_led.rs (modify)

## Affected Systems
- Transporte BLE (conexão/bond/GATT)
- Pareamento + LED (jornada física)
- Gates (vínculo/UP pós-conexão)

## Risk Level
medium

## Parallel Safety
### Can Parallel
- Task A (script + scan/discover): [tools/ble_connect_test.py]
- Task B (mapeamento LED): [pairing_led.rs leitura]
### Must Sequential
- Task C (connect+bond+write, depende de A): [tools/ble_connect_test.py]
- Task D (fix firmware, depende de C): [ble_nimble.rs, pairing.rs]
