# Lifetime Debug Terminal (Wave7)

Allocation-free lifecycle tracing behind the `debug-terminal` Cargo feature
(default OFF). Release builds compile every `ltrace!` to nothing (zero cost,
zero timing change — same rule as `kprintln!`/`StaticBuf`).

Canonical counters live in `crates/aegis-fido-core/src/lifetime.rs` (core cannot
depend on firmware, so the single implementation lives there);
`crates/aegis-fido-firmware/src/lifetime_trace.rs` re-exports it and adds the
monitor printing plus the `test-mode` serial dump.

## Enable (dev only, never release)

```sh
cargo test -p aegis-fido-firmware --features debug-terminal
cargo run -p aegis-fido-firmware --features debug-terminal  # host monitor
```

Release / audit builds use default features: no lines, no counters moving.

## Event table: evento -> quando -> exemplo de linha

Details are metadata only (slot id, OATH label, retries left, transport name,
monotonic clock). NEVER a secret, key, PIN or code — details are printed, never
stored; `TEST_LIFETIME_DUMP` only carries counts.

| evento | quando (call site, 1 linha) | exemplo de linha |
|---|---|---|
| `key_slot.create` | `KeyManager::generate` / `import` OK (slot id) | `[LT][key_slot] create detail=3` |
| `key_slot.use` | `KeyManager::sign` OK (slot id) | `[LT][key_slot] use detail=3` |
| `key_slot.delete` | `KeyManager::delete` OK (slot id) | `[LT][key_slot] delete detail=3` |
| `key_slot.wipe` | `KeyManager::drop` (slots zeroized) | `[LT][key_slot] wipe detail=1` |
| `oath.put` | `OathApplet::device_put` / `oath_store_put` OK (label) | `[LT][oath] put detail=GitHub:alice` |
| `oath.code` | `OathApplet::device_code` / `oath_store_get` OK (label) | `[LT][oath] code detail=GitHub:alice` |
| `oath.delete` | `OathApplet::device_delete` / `oath_store_delete` OK (label) | `[LT][oath] delete detail=GitHub:alice` |
| `pairing.arming` | `PairingManager::on_button_level` Idle/Locked -> Arming | `[LT][pairing] arming detail=6000` |
| `pairing.pairing` | `PairingManager::complete_pairing` OK (UP+bonding) | `[LT][pairing] pairing detail=6120` |
| `pairing.timeout` | `PairingManager::tick` expira a janela de 60s | `[LT][pairing] timeout detail=66000` |
| `pin.retry` | `ClientPinState::decrement_pin_retries` (retries left) | `[LT][pin] retry detail=7` |
| `pin.blocked` | retry chega a 0 (detail 0, nunca o PIN) | `[LT][pin] blocked detail=0` |
| `transport.open` | `BleGattServer::control_write` nova transacao / `WifiApManager::update` liga AP | `[LT][transport] open detail=ble` |
| `transport.close` | mensagem completa / CANCEL / AP expira / `shutdown_after_config` | `[LT][transport] close detail=wifi` |
| `transport.erro` | `feed` invalido / USB send fail / `Protocol error` | `[LT][transport] erro detail=usb` |

## TEST_LIFETIME_DUMP (`test-mode`, default OFF)

```sh
cargo test -p aegis-fido-firmware --features test-mode
```

With `test-mode` the firmware answers the serial line `TEST_LIFETIME_DUMP`
with counters + caller states and no secrets:

```
lt_dump v=1
lt.key_slot.create=3
...
lt.pin.retry=7
lt.state uptime_s=42
lt_end
```

Without the feature the command does not exist (`dispatch_test_command` is not
compiled). On host the `main.rs` test-mode pump reads stdin lines and prints
the dump; on ESP-IDF wire UART RX -> `dispatch_test_command` -> UART TX.

## Simulator test mode

```sh
python tools/app_simulator.py --port COM7 --test-mode   # menu 10 = dump
python tools/app_simulator.py --self-test               # offline, no hardware
```

With `--test-mode` the simulator verifies on connect that the device answers
`TEST_LIFETIME_DUMP` (i.e. it really runs `test-mode` firmware). Without the
flag it behaves exactly like the app.
