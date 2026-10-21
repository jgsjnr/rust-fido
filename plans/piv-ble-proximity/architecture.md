# Architecture: piv-ble-proximity

## Approach
Estender sem quebrar. O CCID atual só roteia OATH/FIDO e responde SELECT PIV com stub. Vamos plugar um `PivApplet` real atrás do mesmo `CcidTransport`, e um `ProximityLock` isolado no firmware que só observa RSSI e sinaliza — quem trava é o host. Cada lado em arquivo disjunto para ondas paralelas e commits atômicos. Tudo default-off até o merge final.

## Components
- `piv.rs` (novo, `aegis-fido-usb`): `PivApplet` — SELECT/VERIFY/CHANGE/RESET/AUTHENTICATE/GET/PUT/GENERATE. Slots 9A/9C/9D/9E sobre curvas existentes do core, persistidas no envelope NVS cifrado. Trait `CcidApduHandler::handle_piv_apdu` (default retorna `6D 00`).
- `ccid.rs` (modify mínimo): rotear `SelectedApplet::Piv` para `handle_piv_apdu`. ATR mantido.
- `proximity.rs` (novo, firmware, feature `proximity`): `ProximityConfig` + `ProximityState` (NEAR/AWAY/LOCKED). Lê RSSI do NimBLE, nunca decide unlock. Status via GATT notify dedicado + `ltrace!`.
- `ble_nimble.rs` / `ble_gatt.rs` (modify mínimo): expor `rssi()` + char proximidade; GATT `0xFFFD` e opcodes intactos.
- `tools/host/{win,linux,macos}/` (novo): agents de lock nativo por OS. Windows: BT pareado + `LockWorkStation()`. Linux: BlueZ + `loginctl`. macOS: melhor API + doc.
- `docs/piv-ble-proximity.md` (novo): guia em PT-BR.

## Data Flow
PC/SC → CCID Bulk → `CcidTransport::process_ccid_message` → `handle_apdu` (SELECT AID) → `PivApplet::dispatch` → core crypto → NVS cifrada → `ResponseApdu` → Bulk-IN. Logon: `lsass` → BaseCSP/minidriver → slot 9A + cert `5F C1 05`. Proximidade: phone/fob BLE ↔ NimBLE (RSSI) → `proximity.rs` (histerese) → notify GATT → host agent (poll 2s) → lock nativo quando AWAY >= lock_secs.

## Alternatives Considered
- Reusar char FFF1 para proximidade — rejected porque mistura CTAP-BLE com lock (quebra apêndice BLE).
- PIV em crate separada `aegis-piv` — rejected porque duplica `CommandApdu`/`ResponseApdu`; estender `aegis-fido-usb` reutiliza.
- Auto-unlock por RSSI — rejected: inseguro (spoofing RSSI); lock-only.
- RSA onboard no S3 — adiado: priorizar p256 (9A/9E); RSA via import PUT DATA nesta fase.
