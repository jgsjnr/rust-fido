# Release 1.0.0-wave — closeout pack (RED: NO-GO)

- Version: 1.0.0-wave
- Date (UTC): 2026-11-03
- Branch: fd/finalizacao-linux
- Verdict: **NO-GO (RED)** — blocker: `dep-track` gate FAIL (exit 2) in the
  final clean run. See GO_NOGO.md. Nothing in this pack weakens any gate.

## What is in this release

- Firmware (full preset, devkitc): measurements recorded in
  `scripts/capability-catalog.json` and `reports/refactoring/CAPABILITY_DIET.md`
  (2026-11-02, elf2image `--flash_size 4MB`):
  - full `aegis-app-esp32s3-devkitc.bin`: 1902288 B, SHA256
    `747691BCA6D67CAB40FF2AADDECAFB2AB5BA5CAA1A12C1E14411E50769F86F40`
    (OVERFLOW vs 2 MB factory 0x180000 — diet motivation).
  - fido-only `aegis-app-esp32s3-devkitc-fido-only.bin`: 1128144 B, SHA256
    `36CA330DC23CEF56D7716BFE08871D5A0CE562666716D13C555A9B2DCFD188AE`
    (PASS <= factory).
  - fido-totp `aegis-app-esp32s3-devkitc-fido-totp.bin`: 1251632 B, SHA256
    `55AC03BC49C18C2DB09175BE0D5246B0103CAE369EDB554F79D800F0B0AE9FDC`
    (PASS <= factory).
  - Repo `.bin` on disk: `dist/aegis-firmware-esp32s3.bin`, 2091408 B,
    2026-11-02, SHA256
    `13C894FB1FDB3981AA717BBB6D4BF23B0259E405CB85AACB7D793FE808DF0580`.
- Expected full-preset prefix `620D611E…`: **NOT FOUND** — no file in the repo
  matches that prefix (searched reports, docs, scripts, dist). The hashes above
  are the only ones evidenced. Treated as an open mismatch (GO_NOGO item 3).
- App APK (fresh build-only rebuild, no source edits):
  `app-android/app/build/outputs/apk/debug/app-debug.apk`, 61912002 bytes,
  built 2026-11-03 14:56:11 (local), SHA256
  `D487E29276350D0547D377AE839ACD6DE2FAB0707F986A878396274BDD451035`.
  Build: `./gradlew.bat :app:clean :app:assembleDebug` from `app-android/`,
  BUILD SUCCESSFUL (40 tasks). First attempt failed environmentally
  (`:app:clean` file lock from a concurrent Gradle daemon, not a code failure);
  rebuilt after the daemon went idle. Tree had uncommitted app-android edits at
  build time (other lanes) — recorded, not hidden.
- Capability presets + sizes: full / fido-only / fido-totp, table above
  (source: `scripts/capability-catalog.json`, `reports/refactoring/CAPABILITY_DIET.md`).
- GET_CAPS: vendor read-only command `0x3F`, no auth, CBOR response
  `(0x00, {fw_version, preset, caps, unsupported_count})`; routed through
  transport funnels (commit `bd47042`), Android capabilities screen
  (commit `747648a`). Full contract in CAPABILITY_DIET.md section 7.
- RMT LED: WS2812 driven via RMT, jitter-free (commit `5c2cdbb`, `led.rs`).
- Recovery envelope: device-key-independent envelope persisted outside
  SecureStorage (commit `a37051f`); recovery works across DEV reboot via
  wrapped KEK (commit `3a9a3de`). Envelope: magic `AEGSGR01`, version 1,
  146 bytes (`crates/aegis-secure-guard/src/recovery.rs`).
- Recent firmware/app commits in this wave: `eeb3e93` SIGN opcode `0x41`,
  `b4f9077` SET_UP_POLICY `0x40` funnels, `db8a120` per-credential UP policy,
  `cd22b80` bridge NEED_UP propagation, `0301b20` SG over USB-HID in legacy
  loop + error flash, `f253008`/`a88bc70` bridge-first status and recovery UX.

## Gate history (both runs reported honestly)

- Run 1 (2026-11-03T17:21:54Z, HEAD `cd22b80`): 7 PASS + `dep-track` FAIL
  exit 2 (NEW god `secure_guard_exec/tests.rs` 26.30) + `fmt` advisory FAIL.
  RESULT: FAIL. **Marked potentially contaminated** (firmware lane editing
  credential/CTAP sources mid-run). NOT used for the verdict.
- Run 2 final (2026-11-03T18:14:09Z, HEAD `eeb3e93` frozen after 5-min
  stability): 8 PASS + `dep-track` FAIL exit 2
  (NEW gods: `secure_guard_exec/tests.rs` 27.92 lines=1442;
  `universal-device-sdk/src/providers/oath.rs` 25.90).
  `fmt` advisory: PASS. RESULT: FAIL. This run is the verdict of record.
  Caveat: working tree held ~60 uncommitted files from other active lanes at
  run time (full list in GO_NOGO.md); HEAD was stable, tree was not pristine.

## Known limitations

- `fmt` advisory: FAIL in run 1 (pre-existing drift, e.g. `curves.rs`,
  `ecdh.rs`, `extensions_ctap21.rs`, `shamir.rs`); PASS in run 2 only because
  the working tree carried uncommitted formatting changes. Committed code is
  still unformatted — formatting is a parent decision, not taken here.
- ESP-IDF pinned v5.3.1 (esp-idf-sys 0.36.1 / hal 0.45.2 / svc 0.50.1);
  v6.1/v6.0.3-compat not validated (see `reports/refactoring/esp-idf-version-inventory.md`).
- No FIDO certification yet.
- DEV eFuse caveat: development boards stay unburned
  (`EFUSE_WRITE_HARD_LOCKED = true`, burn feature locked); secure-guard
  recovery uses wrapped KEK so provision survives DEV reboot, otherwise the
  cycle is reboot -> reprovision.
- Hardware proofs cited (HARDWARE_JOURNEY 2026-11-02, ROBOT_RUN 26/26,
  capability measurements) were recorded at older HEADs and are restated as
  provenance, not re-validated here — no device interaction in this lane
  (board untouched, no flash, no PIN attempts).
- No binaries committed: this pack is files-only (`reports/release/` text +
  `run_all` text outputs). APK and `.bin` hashes are recorded, artifacts stay
  in build/dist directories.