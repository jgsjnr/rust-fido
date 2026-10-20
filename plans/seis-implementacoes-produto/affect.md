# Affect Analysis
Generated: 2026-10-19

## Affected Files
- crates/aegis-fido-usb/src/piv.rs (modify)
- crates/aegis-fido-firmware/src/proximity.rs (modify)
- crates/aegis-fido-core/src/otp/rescue.rs (modify)
- crates/aegis-fido-core/src/otp/challenge_response.rs (modify)
- crates/aegis-fido-usb/src/winusb.rs (modify)
- crates/aegis-fido-firmware/src/ble_gatt.rs (modify)
- crates/aegis-fido-core/src/wallet/store.rs (modify)
- crates/uniffi-bridge/src/lib.rs (modify)
- crates/aegis-fido-core/src/wallet/address.rs (modify)
- app-android/app/src/main/java/dev/aegiskey/app/ble/AegisBleClient.kt (modify)
- app-android/app/src/main/java/dev/aegiskey/app/ui/AccountsScreen.kt (modify)
- tools/killswitch.py (create)
- docs/seis-produtos.md (create)
- docs/firmware-fina.md (create)

## Affected Systems
- FIDO2/CTAP (regressão) · PIV/CCID · BLE proximidade · wipe/erase · WinUSB dongle · wallet NVS/UI · app Android · bridge Rust · SIZE firmware

## Risk Level
high

## Parallel Safety
### Can Parallel
- Track PIV: [piv.rs, ccid.rs]
- Track dongle: [winusb.rs, challenge_response.rs]
- Track killswitch: [rescue.rs, tools/killswitch.py]
- Track app-controle: [AegisBleClient.kt, menus]
- Track thin-audit: [docs/firmware-fina.md]
### Must Sequential
- Track proximidade: [proximity.rs, ble_gatt.rs]
- Track wallet+telas: [wallet/store.rs, ble_gatt.rs, app UI]
- Track thin-move (depende da auditoria): [uniffi-bridge, totp_view.rs, wallet/address.rs]
