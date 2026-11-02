# Hardware Journey — ESP32-S3 physical board (COM7) + full wipe

- Date (UTC): 2026-11-02 (approx 15:45-17:30 UTC)
- Operator: subagent sdk-mcu lane (reports only)
- Worktree: `E:\projetos\standalone-architecture-worktree`, branch `refactor/standalone-architecture-cleanup`
- HEAD flashed (provenance): `a379cf5 fix(esp32): portable atomics + macro scope for Xtensa`
  (`ae68a77 feat(security): expire BLE bonds after 30d with NimBLE store wipe`,
  `4d5e614 feat(security): SNTP time source with NVS anchor and fail-closed TOTP clock`)
- Pre-existing uncommitted files (OTHER lanes — recorded, never staged/committed/touched):
  `M crates/aegis-secure-guard/src/crypto.rs`, `engine.rs`, `glitch_guard.rs`,
  `lib.rs`, `resource.rs`, `state.rs`
- Owner authorization on file: full journey + FULL WIPE of the physical board LAST, PIN `1111`.
  Flashing the freshly built v5.3.1 release firmware is part of the journey (implied).
- Transport: UART COM7 @115200 (CTAPHID framing = USB), repo host tools
  (`tools/app_simulator.py` Session/SerialLink, CBOR codec mirror of `tools/e2e_harness.py`
  PinClient/cbor helpers). No code/config edited. No push/merge. No buttons pressed
  (all UP/pairing via software trigger `0x2F`; UART = physical possession).
- Secrets policy: device PIN / pinUv token / credential IDs never logged (lengths only).
  TOTP used the public RFC 4226/6238 test vector (name + expected codes only).

## 1. Detect (PASS)

- `Get-CimInstance Win32_SerialPort` + `SerialPort.GetPortNames()`:
  `COM7 Silicon Labs CP210x USB to UART Bridge (USB\VID_10C4&PID_EA60\0001)`,
  plus `COM3/COM4` Bluetooth std-serial, plus native USB
  `USB\VID_303A&PID_AE61\AEGIS-S3-0002` (Espressif VID, Aegis PID). Board visible -> continue.
- READ-ONLY `esptool --chip esp32s3 --port COM7 flash_id`:
  `ESP32-S3 (QFN56) revision v0.2, Dual Core + LP Core, 240MHz, 8MB PSRAM (AP_3v3),
  40MHz crystal, MAC 3c:84:27:c7:17:78, 16MB flash (ef4018), quad 3.3V`. No writes.

## 2. Provenance (PASS) + build (PASS)

- `git status --short` / `git log --oneline -3` recorded above (6 dirty files belong to
  `aegis-secure-guard` lanes; this report is the only file added by this lane).
- Release ELF: `C:\t\xtensa-esp32s3-espidf\release\aegis-fido-firmware`
  (2000088 B, 2026-11-02 15:41:01, `.d` proves sources from THIS worktree),
  ELF-SHA256 `96E9B213FDB5F8FE80F8B688C746FA7EAE04134921F28F3D76A2BDFDBE0A55DA`.
- `elf2image` per repo pattern (`scripts/common.ps1:Invoke-FirmwareElf2Image`,
  `esptool --chip esp32s3 elf2image --flash_size 4MB`):
  `C:\t\aegis-app-esp32s3-devkitc-journey-a379cf5.bin` —
  1899056 B, first byte `0xE9`, SHA256 `535C4AAA4B6DB5C1C056DBF27BC753954011C9A57C534707101051D327A158D`,
  sidecar `.sha256` written, fits factory `0x300000` (3145728 B, `partitions.csv`).
  Distinct `-journey-` name so no shared artifact was clobbered.

## 3. Flash + boot (PASS)

- `esptool --chip esp32s3 --port COM7 --baud 921600 --before default_reset --after
  hard_reset write_flash 0x10000 <bin>`: `Wrote 1899056 bytes (1162629 compressed)
  at 0x00010000 in 16.7s ... Hash of data verified. Hard resetting via RTS pin.`
  No buttons (auto-reset via DTR/RTS).
- UART boot log (120 lines captured): ROM -> `ESP-IDF v5.3.1 2nd stage bootloader` ->
  partition table (nvs `0x9000`, factory `0x10000` len `0x300000`, storage `0x310000`) ->
  `Loaded app from partition at offset 0x10000`, app `Nov 1 2026 20:31:04`,
  `ELF file SHA256: 96e9b213f...` (matches flashed ELF), 8MB PSRAM OK,
  `AegisKey S3 Authenticator`, `VID 0x303A / PID 0xAE61 / Serial AEGIS-S3-0002`,
  `TinyUSB FIDO2 ...`, `Serial CTAPHID channel online on UART0 (115200 8N1)`,
  display init. Then `[HEARTBEAT] ... USB Mounted: true` every 3 s.
  **No panic, SecureGuard engine up (barrier enforced, see section 5), USB stack init.**
  (This release runs the legacy run loop — default `board-devkitc`, no `freertos` feature.)

## 4. Journey via UART/USB with repo host tools (final run: 51 PASS / 0 BLOCKED / 2 FAIL-quirk, 53 steps)

- Baseline (P0): CTAPHID INIT `CID=0x00060201`; GetInfo FIDO_2_0/2_1/2_1_PRE+U2F_V2,
  AAGUID `00010203...0f`, `rk=True, clientPin=False, credMgmt=8, maxMsg=2048`;
  getRetries `0x35 PIN_NOT_SET`; vault empty; OATH empty; fw-log readable (12 entries).
  `0x2F` software pairing+UP trigger `0x00` (used before every UP/pairing-gated op;
  legacy latch is 1-shot, ~10 s window, 60 s pairing window).
- Claim/binding (P1-P2): `0x21`-empty oracle read `0x05 NEED_BINDING` (unclaimed) ->
  `0x28 CLAIM` (fresh P-256 host key + random 16 B id, UP+pairing via software) `0x00` +
  id echo -> oracle `0x02 NEED_PIN` (claimed, PIN gate governs). Full gate matrix proven:
  unclaimed->`0x05`, claimed-no-PIN->`0x02`, claimed+UP+pin-session->`0x04` (bad envelope).
- PIN/lock-unlock + attempts (P3, budget max 2 wrong — used exactly 1):
  keyAgreement `0x00` (note: this build returns the COSE_Key under map key `0x01`,
  not spec `0x03`); getRetries unset `0x35`; setPin `1111` `0x00` (owner PIN provisioned);
  **wrong getPinToken (`0000`) -> `0x31 PIN_INVALID` (rejected, 1 attempt)**;
  getPinToken `1111` -> `0x00` + live device pinUv session (unlock-equivalent; RAM).
  Correct PIN accepted immediately after the wrong one -> **no lockout**.
  Quirk (2 FAIL lines, same root cause): `getRetries` once a PIN is set answers
  `0x14 MissingParameter` instead of the retry map (3 independent reproductions;
  pre-set it correctly answers `0x35`). Attempt counter 8->7 therefore not directly
  readable; rejection (`0x31`) + acceptance (`0x00`) + no-lockout is evidenced.
  No 5-attempt wipe risked (SecureGuard 5-fail path untouched; recovery `0x2D` never tried).
- Create/get/delete (P4): `0x20 GEN` slot 7 ES256 `0x00` -> `0x22 LIST` contains
  `journey-t7` -> `0x23 DELETE` `0x00` (device pinUv plumbing works) -> LIST absent.
  PASS (create/get/delete over the vendor interface with binding+UP+PIN gates).
- TOTP vs host RFC vectors (P5, clock-independent by design — device computes
  `HMAC-SHA1(secret, challenge)` for a HOST-supplied 8 B counter):
  `0x24 PUT` (`JourneyRFC:alice`, `0x21`=TOTP/SHA1, 6 digits, RFC 6238 secret
  `12345678901234567890`) `0x00` -> `0x26 CODE` counter 0 -> `755224`,
  counter 1 -> `287082`; host-computed (own DT-HMAC implementation) identical;
  RFC 4226 Appendix D expects exactly `755224`/`287082`. **device=host=RFC.**
  `0x27 DELETE` `0x00` -> LIST empty. PASS.
- CTAP FIDO2 (P6): makeCredential resident ES256 (`journey4.local`) `0x00`
  (authData 148 B, credId 16 B, signCount 0) -> getAssertion #1 signCount 1 (71 B sig) ->
  #2 signCount 2 (**counter+1**, stateful assert). PASS.
- SecureGuard lock/unlock/wipe over UART/USB (P7): `0x3A/0x3B/0x3C/0x3E` all answer
  `0x01 CTAP INVALID_CMD`. Root cause: this release runs the **legacy run loop**
  (`run_loop_legacy.rs`), whose serial/USB dispatch has NO `0x3A-0x3E` branch (SG
  dispatch exists only in `freertos_route.rs` -> `dispatch_serial_vendor_msg`, feature
  `freertos`, not enabled in this build); unknown ops fall through to the generic CTAP
  engine -> `0x01`. **SG-over-UART/USB steps are BLOCKED by firmware composition.**
  Missing piece for a follow-up: rebuild/flash with `--features freertos`
  (or backport the SG branch to the legacy loop) — explicitly NOT done here
  (assigned artifact is the default release build; no code/build changes in this lane).
  Reachable equivalents performed instead: CTAP pinUv session lifecycle (P3),
  vendor PIN-gated ops (P4/P5), CTAP reset wipe (P8).

## 5. LAST: full wipe with PIN 1111 (PASS) + final device state

- Pre-wipe inventory: journey artifacts already deleted in P4/P5 (reconfirmed empty).
  `0x2B RELEASE` (empty+UP) `0x00` -> oracle `0x05` (unclaimed, RAM). Hard reset
  (esptool `chip_id`, **no flash write**) -> re-INIT -> `0x07 CTAP authenticatorReset`
  (UP latched post-boot) `0x00` -> getRetries `0x35 PIN_NOT_SET` (**PIN 1111 destroyed**)
  -> oracle `0x05` (**release persisted = UNCLAIMED**) -> getAssertion (journey cred)
  `0x2E NO_CREDENTIALS` (**resident credential destroyed**) -> LIST empty, OATH LIST empty.
- Final passive check: GetInfo `0x00`, getRetries `0x35`, LIST `0x00` empty,
  oracle `0x05`, 4 heartbeats/14 s, **zero panic/Guru/abort lines**.
- Final device state: **UNCLAIMED, PIN unset, vault empty (0 slots), OATH empty
  (0 accounts), all journey FIDO credentials destroyed, app alive on UART+USB.**
  Factory state for every NVS-backed subsystem this build exposes over UART/USB
  (binding NVS, `pin/*`, `key_slots_v1`, `oath_creds_v1`, CTAP store).

## Observations for follow-up (not blockers for the wipe)

- (a) Single-occurrence anomaly: in one earlier run the binding claim reappeared
  after a release+reset cycle (oracle `0x02` post-reboot despite `0x05` pre-reboot).
  The next full cycle proved durability twice (pre+post-reboot oracles `0x05`,
  this run included, plus post-reset oracle `0x05`). Hypothesis: intermittent
  NVS-delete/dual-slot restore race; not reproduced since. If binding durability
  matters, re-test with NVS dumps.
- (b) `getRetries` -> `0x14 MissingParameter` whenever a PIN is set (this build);
  pre-set it correctly returns `0x35`. Cosmetic/diagnostic only (fail-closed).
- (c) `getKeyAgreement` returns the COSE_Key under map key `0x01` (not spec `0x03`).

## Evidence artifacts (host TEMP, not committed)

- `journey4_results.txt` (53 lines), `journey4.py` (procedure), `bootlog.txt`
  (120-line boot), `bootlog2.txt` (heartbeats), `final*.py` probes.
  Flash artifact + `.sha256` in `C:\t` (build cache, not repo).

## Verdict

- Steps 1-4 (detect/provenance/build/flash/boot): **PASS** with hashes above.
- Journey: create/get/delete **PASS**; TOTP vs RFC vectors **PASS** (755224/287082);
  assert/counter+1 **PASS**; lock/unlock+PIN attempts **PASS** (1 wrong -> `0x31`,
  correct -> `0x00`, no lockout); SG lock/unlock/wipe over UART/USB **BLOCKED**
  (no `0x3A-0x3E` dispatch in this legacy-loop release; exact missing piece stated).
- LAST full wipe with PIN 1111: **PASS**, final state verified factory-clean.
- No sensor values fabricated; no unsupported-hardware claims; no flashing beyond the
  authorized release image; no serial measurement beyond the authorized journey.
- Target config + memory constraints preserved (no code/config touched).
