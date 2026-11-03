# ROBOT_RUN — WebAuthn host robot (fd/finalizacao-linux)

Owner lane files: `tools/webauthn_robot.py` (new), this report (new). No other
files touched. No flash/hardware: board unplugged, everything emulated on host.
Stdlib + subprocess only (`argparse, ctypes, hashlib, hmac, json, os, shutil,
struct, subprocess, sys, time`). No Mock/Fake/Stub providers anywhere.

Run: `python tools/webauthn_robot.py` (add `--only a,b`, `--json-out <file>`).
Full run: **26/26 PASS, exit 0** (15.4 s, 2026-11-02).

## Results table

| # | Step | Result | Evidence |
|---|------|--------|----------|
| 1 | bridge: cargo test -p uniffi-bridge vectors | PASS | exit=0, 36 passed / 0 failed (ble split/reassemble, AEGN seal/open, cose parse-only, oath parse, app-lock PBKDF2, wallet KATs, secure-guard roundtrip) |
| 2 | bridge: direct cdylib calls (ctypes) | PASS | `C:/t/debug\aegis_bridge.dll` v1.0.0; `encode_unlock("1111")` rc=0 CBOR `{action:unlock, pin:b'1111'}`; provision rc=0; envelope seal/open roundtrip ok, bad-magic rc=-4; 300 B BLE payload -> 2 fragments (244 B first) |
| 3 | firmware: provision/unlock/lock/wipe/keepassxc | PASS | exit=0, 22 passed / 0 failed (`secure_guard` filter, RAM-backed store via harness) |
| 4 | firmware: makeCredential→getAssertion signCount | PASS | exit=0, 1 passed (`interop_make_then_two_assertions_bump_counter`: 0→1→2, monotonic) |
| 5 | firmware: ctap makeCredential/getAssertion gates | PASS | exit=0, 7 passed (`ctap_cmd`: counters + allowList/UV gates) |
| 6 | firmware: PIN/UV verify | PASS | exit=0, 8 passed (wrong+right, retries, block) |
| 7 | firmware: RFC vectors | PASS | exit=0, 2 passed |
| 8 | firmware: serial framing + manager parity | PASS | exit=0, 26 passed |
| 9 | firmware: BLE GATT reassemble | PASS | exit=0, 58 passed (bind/OTA fragments, rescue/reserved rejected) |
| 10-15 | ctaphid fragment/reassemble 0/1/57/58/200/7609 B | PASS | protocol-level framer/deframer mirrored from `crates/aegis-fido-usb/src/ctaphid.rs` (INIT 57 B, CONT 59 B, max 7609 B); boundary sizes exact |
| 16 | ctaphid overrun rejected | PASS | 7610 B → ERR_INVALID_LEN (fail-closed, mirrors firmware) |
| 17 | ctaphid bad seq rejected | PASS | mutated seq → ERR_INVALID_SEQ |
| 18 | ctaphid error codes incl. 0x06 diet | PASS | 0x06 = ERR_CHANNEL_BUSY on CTAPHID wire; 0x06 = UNSUPPORTED_FEATURE under cap diets (`crates/aegis-fido-firmware/src/lib.rs:42`) |
| 19 | ctaphid: cargo test -p aegis-fido-usb | PASS | exit=0, 92 passed / 0 failed |
| 20 | totp: HOTP RFC 4226 | PASS | 10/10 match (secret `12345678901234567890`; device: `totp.rs:160`) |
| 21 | totp: TOTP RFC 6238 | PASS | 9/9 spot checks SHA1/SHA256/SHA512 (device table `totp.rs:171`) |
| 22 | totp: 30 s window | PASS | t=59→1 s, t=60→30 s (mirrors `oath_remaining_seconds`) |
| 23 | emulators inventory | PASS | qemu-xtensa ABSENT (no download per rules); `sdkconfig.defaults.esp32s3` present; host sims `app_simulator.py`, `host_hardware_android_bridge.py`, `sim_ctap_init.py` noted but NOT executed as evidence → protocol-level emulation; physical-device acceptance NOT claimed |
| 24 | diagnosis UNLOCK | PASS | see below |
| 25 | diagnosis FLICKER | PASS | see below (read-only) |
| 26 | diagnosis KEYPASS | PASS | see below |

Validation: `cargo test -p uniffi-bridge -p aegis-fido-firmware --features
freertos,proximity` → exit 0 (585 lib + 36 bridge + integration suites, 0 failed).
`./gradlew :app:assembleDebug` skipped: no app code touched.

## UNLOCK FAILURE — root cause (bridge path reproduced, NO FIX)

Live repro through the bridge: `aegis_secure_guard_encode_unlock(b"1111")`
→ rc=0, CBOR `{action:"unlock", pin:Bytes("1111")}`. Firmware accepts exactly
this shape: `secure_guard_exec/dispatch.rs:58` (`Value::Bytes(b) => …`,
`Value::Text` also accepted) → `unlock.rs:617`
`engine.unlock_with_pin(&pin, now_ms)`. Engine gates verified green by the
harness (22 passed): `engine.rs:395` ErrorLocked deny, `:403` NotProvisioned,
`:411` RecoveryRequired cooldown, `:471` BleProximityLocked,
`engine.rs:338` InvalidStateForOperation. PIN policy `policy.rs:46-52`
(min 4 / max 16, trivial PINs allowed unless configured) — `1111`-style test
PIN valid in-memory.

**Root cause is NOT in bridge or firmware — it is app-layer:**
1. Multi-transport short-circuit in
   `SecureGuardRepositoryImpl.kt:326-402` — a USB failure throws
   `SecurityException` (line 346) *before* BLE/bridge are tried, and a BLE
   failure throws (line 366) *even when USB already succeeded*. Transports can
   legitimately disagree (hardware vs host-bridge emulator state).
2. Optimistic forge in `SecureGuardViewModel.kt:245-264` — `unlock()` hardcodes
   `state=UNLOCKED, isUnlocked=true, session 300_000L` instead of surfacing the
   device's actual status, so the UI shows unlocked while the device is locked
   and the next vault op fails ("unlock failure").

**Fixed? NO.** Fix would be Kotlin + gradle test proof, out of lane scope
(app lane owns it); bridge/firmware need no change. Not device-only/flash, so
not BLOCKED — redirected with file:line + proposed patch direction (OR-across-
transports instead of throw-on-first-failure; surface `unlockRes`/status
instead of forging UNLOCKED).

## FLICKERING — read-only inspection (NO FIX, UI untouched)

- `KeyVaultHubScreen.kt:159` — `secureGuardViewModel.uiState.collectAsState()`
  **inside** a `LazyColumn item {}` scope, while the same flow is collected a
  second time at `:510`. Every guard emission recomposes the whole list.
- `KeyVaultHubScreen.kt:511` — `LaunchedEffect(sgState.status.isUnlocked,
  sgState.status.state)` calls `dismissUnlockPrompt()` + `viewModel.refreshVault()`,
  which flips `isLoading` true→false (extra frames per unlock transition).
- `KeyVaultHubScreen.kt:109-113` — auto-reload effect; terminates (keys don't
  change) — not a loop. `:94-106` snackbar/clearMessage pairs fire twice then
  self-resolve — not a loop.
- `ConnectedKeysRepositoryScreen.kt:75` — `LaunchedEffect(Unit)` doing network
  (`fetchProximityStatus` + BLE register); runs once, not a recomposition loop.
- No state writes during composition found; no unstable-key/derivedStateOf
  misuse beyond the duplicate collector.

**Fixed? NO.** The duplicate-collector hoist is the textbook trivially-safe fix
(and matches the hoisted pattern at `:510`), but the flicker was not reproduced
on host (no device, no Compose runtime), so per lane rules UI code is left
untouched. Recommended to the app lane: hoist to a single top-level
`val sgState`, keep `:159` item stateless.

## KEYPASS / WebAuthn — break point

- getAssertion path green in firmware: signCount 0→1→2 interop test, allowList +
  PIN/UV gates in `ctap_cmd`/`ctap_state` harnesses (steps 4–6).
- Bridge carries **no** getAssertion/keepassxc encode fns (verified by source
  scan) — by design the passkey flow reaches the device as CTAPHID `CMD_CBOR`
  via the app's own Kotlin CBOR (`SecureGuardCbor`/`UsbCtaphid`).
- `keepassxc_challenge` additionally requires guard UNLOCKED
  (`unlock.rs:507-513`); firmware keepass proof:
  `secure_guard_exec/tests.rs:720` green.
- **Break point if keypass fails in the field: app Kotlin transport/parse layer
  or a locked guard — NOT bridge parse, NOT firmware assertion.**

## What would need hardware (not claimed)

Real USB CTAPHID against the S3, BLE PING/MSG roundtrip, qemu-s3 headless run
(no qemu binary present, no downloads), OLED-UPN presence ceremony, radio
proximity gating. None executed; nothing above is presented as device evidence.

## SHAs

- HEAD at run: `bd47042ebc77adc159bedfd0a32df810f4f030ab` (`bd47042`)
- New files (uncommitted, to be committed by this lane only):
  `tools/webauthn_robot.py`, `reports/testing/ROBOT_RUN.md`
- Pre-existing uncommitted files left untouched (other lanes):
  `M reports/refactoring/dep-track.json`, `?? docs/*.md`
