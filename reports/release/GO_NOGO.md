# GO / NO-GO -- 1.0.0-wave (verdict of record: run 2026-11-04T11:14:53Z)

- HEAD at verdict: `0e957fc` (`0e957fc41b662aa99b4e63e0c15c2493acc0b6d7`,
  2026-11-04 08:14:28 -0300, branch `fd/finalizacao-linux`):
  "app-android: SecureGuard detached sem transporte vivo -> LOCKED fail-closed
  (bridge UNPROVISIONED nao vence lock)".
- Verdict: **CONDITIONAL GO (GREEN with 3 documented gaps)**. All 9 release
  gates PASS at HEAD; no gate was weakened to make anything pass. The 3 gaps
  below are known, bounded, and assigned -- none blocks wave shipment per
  parent scope, but each stays recorded until closed.
- No code, config, firmware, or other report was edited in this lane to reach
  the verdict. No push performed (parent order).

## Per-gate verdicts -- final run (2026-11-04T11:14:53Z, release=on, selector=all)

Evidence: `reports/testing/consolidated-result.json`
(generated_by `tools/run_all.py`, timestamp_utc `2026-11-04T11:14:53Z`,
summary passed=9 failed=0 advisory_failures=0 skipped=0 exit=0).
Full per-leg tails in `reports/testing/CONSOLIDATED_RUN.md`
(run `2026-11-04T11:14:53Z` section).

| leg | advisory | status | exit | duration_s |
|---|---|---|---|---|
| test-debug | no | PASS | 0 | 13.5 |
| test-firmware-features | no | PASS | 0 | 30.1 |
| clippy | no | PASS | 0 | 2.6 |
| fmt | yes | PASS | 0 | 1.2 |
| deny | no | PASS | 0 | 2.9 |
| dep-track | no | PASS | 0 | 0.4 |
| docs | no | PASS | 0 | 0.4 |
| scripts | no | PASS | 0 | 11.0 |
| test-release | no | PASS | 0 | 47.7 |

- `fmt` is advisory (record-only); this run reports `(no output)`, exit 0.
- `dep-track`: `wrote reports/refactoring/dep-track.json (265 files, 22 gods)`,
  `check ok: no new god-files beyond 24 allowlisted`.
- `docs`: `reports-scan checked=1 broken=0` (STYLE-HINT lines only, non-blocking).
- Prior history (superseded, kept in CONSOLIDATED_RUN.md): red runs with the
  `oath` duplicate-module E0761 breakage (2026-11-03T23:04:03Z,
  2026-11-04T00:36:54Z) and god-file FAILs (`bench.rs` 30.88 on
  2026-11-04T03:00:54Z), all resolved before this green run (oath dedup fix
  lineage `2ca44af`, bench split `0dea539`). NOT reused for the verdict.

## App suite -- 189/189 (handoff-provided, not re-run here)

- Android unit suite: **189/189 PASS**, value provided by parent handoff
  2026-11-04. Not re-executed in this lane (no Gradle run here); no local
  evidence file for the count exists in this repo snapshot, so it is recorded
  as reported, not as locally re-validated.
- Bench/badge coverage present in-tree: `BenchSessionBadgeTest`
  (`bench_active` contract, `bench_active=true/false` cases),
  `SecureGuardRepositoryAndCborTest`, `SecureGuardJourneyTest`,
  `OobPairingTest` under `app-android/app/src/test`.

## Hardware proofs (provenance, not re-validated here -- no device in this lane)

- 5 curvas provadas: hub inventory shows 5/5 slots
  (`hw-p256` #0 / `hw-ed25519` #1 / `hw-es384` #2 / `hw-es512` #3 /
  `hw-es256k` #4, `reports/testing/HW_MATRIX.md` S9-1, dumps `hw9_hub*.xml`);
  Generate dialog offers 8 key types + 5 curves
  (Ed25519/ES256/ES384/ES512/ES256K, HW_MATRIX S9-4, `hw9_gen.xml`).
  Detail-screen caveat is gap 1 below; it does not erase the inventory proof.
- TOTP ok: TOTP vs RFC vectors PASS (755224/287082,
  `reports/testing/HARDWARE_JOURNEY.md`); TOTP RFC 6238 9/9 + HOTP RFC 4226
  10/10 (`reports/testing/ROBOT_RUN.md`, SESSION_HANDOFF). Live-app TOTP-add
  enroll correctly SKIPped (mutation, HW_MATRIX S9-6, zero submits).
- K3 presence PASS (`User Presence Button operational`, monotonic 1,420 ops,
  HW_MATRIX S9-3). ROBOT_RUN 26/26 PASS (2026-11-02, host-emulated).

## Known gaps (accepted, assigned -- not ship-blockers for wave)

1. Detalhe ES256 default: all 5 slot detail screens display `ES256 (P-256)`,
   including the 4 slots created under other curve chips (HW_MATRIX S9-2).
   Hypotheses recorded there, undecided: (a) creations fell back to ES256
   default (chip-tap did not stick); (b) detail screen renders a fixed/default
   curve instead of the real one. No `touch required on/off` toggle, no UP
   `0x40` policy switch, no `resident` selector exists in the UI (contract
   fixed: touch SEMPRE required, resident SEMPRE discoverable). Follow-up
   (parent): revalidate the real per-slot curve via signature/CTAP before
   claiming per-curve issuance.
2. Badge so com bench_active: the bench badge is asserted only when status
   `0x3A` carries `bench_active=true` (firmware `54a54f9` exposes it in
   `crates/aegis-fido-firmware/src/secure_guard_exec/status.rs:133-134` via
   `bench/policy::is_bench_active()`; app rule in
   `app-android/.../benchmode/BenchSession.kt` + `BenchSessionBadgeTest`;
   release contract `bench_active=false`, bench contract `=true` in
   `bench/tests.rs`). HW_MATRIX S9-7 therefore correctly records badge
   AUSENTE (zero `bancada/bench` hits in S9 dumps; APK `0.1.0-wave5` without
   bench authority) -- nothing forged. Expected behavior; stays a known gap
   until a bench-authorized run stamps the badge.
3. 2 fails test-mode pre-existentes (oob/sign): the firmware `test-mode`-only
   surface -- OOB arming op `0x42` (`crates/aegis-fido-firmware/src/ble/oob.rs`)
   and the SIGN opcode `0x41` path -- carries 2 pre-existing failures outside
   the release gate scope (release gates run default + `freertos,proximity`
   features, never `test-mode`; GAP-04 `prod_strict_guard` keeps `test-mode`
   out of production by `compile_error!`). Handoff-provided counts, not
   reproduced in this lane (no `test-mode` run here). Tracked as
   pre-existing; fix lane to confirm and close.

## Residual risks

- Verdict rendered while the tree is dirty (uncommitted edits from other
  active lanes at write time -- list below). The gate evidence file itself
  (`consolidated-result.json` 11:14:53Z) is also an uncommitted working-tree
  file. A clean-tree re-run is recommended before final ship if the tree
  changed semantically since the run.
- Hardware proofs are provenance from older HEADs/lanes (HARDWARE_JOURNEY
  2026-11-02, ROBOT_RUN 26/26, HW_MATRIX S9); restated, not re-validated
  here -- board untouched, no flash, no PIN attempts in this lane.
- No FIDO certification; ESP-IDF pinned v5.3.1 (v6.x not validated); DEV
  eFuse caveat stands (unburned boards, wrapped-KEK recovery, else
  reboot -> reprovision).
- Prior `.bin` identity mismatch (`620D611E...` prefix, 2026-11-03 GO_NOGO
  item 3) is SUPERSEDED by the current hashes in `SHA256SUMS.txt`; old values
  retained there under History.

## Acceptance criteria (wave ship)

- [x] 9/9 release gates PASS at HEAD `0e957fc`
      (`consolidated-result.json` 2026-11-04T11:14:53Z).
- [x] App suite 189/189 PASS (handoff statement 2026-11-04).
- [x] 5-curve inventory evidenced (HW_MATRIX S9-1/S9-2/S9-4).
- [x] TOTP vectors ok (HARDWARE_JOURNEY + ROBOT_RUN).
- [x] 3 known gaps recorded with follow-up owner (this file).
- [ ] Clean-tree gate re-run if parent requires zero-dirt attestation
      (recommended, not done here).
- [x] Sem push (honored -- nothing pushed in this lane).

## Evidence quality

- Directly observed in-repo this lane: HEAD/branch/dates via `git`;
  gate table via `reports/testing/consolidated-result.json` + tails in
  `reports/testing/CONSOLIDATED_RUN.md`; `bench_active` contract via
  `secure_guard_exec/status.rs` + `bench/policy.rs` + `bench/tests.rs` +
  `BenchSessionBadgeTest.kt`; ES256-display + badge-absent + TOTP/HOTP
  vectors via `HW_MATRIX.md`, `HARDWARE_JOURNEY.md`, `ROBOT_RUN.md`.
- Handoff-provided, NOT re-validated here: the new APK/firmware SHA256 pair;
  the app 189/189 count; the 2 test-mode oob/sign fails. Recorded as
  reported; no REAL_VERIFIED claim is made for them in this lane.
- No device touched, no suite executed, no hash recomputed in this lane.

## Working-tree state at write time (HEAD `0e957fc`, uncommitted, other lanes)

M crates/aegis-fido-core/src/crypto/curves.rs
M crates/aegis-fido-core/src/crypto/ecdh.rs
M crates/aegis-fido-core/src/ctap/extensions_ctap21.rs
M crates/aegis-fido-core/src/ctap/get_assertion.rs
M crates/aegis-fido-core/src/lib.rs
M crates/aegis-fido-core/src/otp/challenge_response.rs
M crates/aegis-fido-core/src/otp/legacy_otp_compat.rs
M crates/aegis-fido-core/src/otp/mod.rs
M crates/aegis-fido-core/src/vault/mod.rs
M crates/aegis-fido-core/src/wallet/clear_signing.rs
M crates/aegis-fido-core/src/wallet/shamir_slip39.rs
M crates/aegis-fido-firmware/src/ota_store.rs
M crates/aegis-secure-guard/src/crypto.rs
M crates/aegis-secure-guard/src/glitch_guard.rs
M crates/aegis-secure-guard/src/resource.rs
M crates/uniffi-bridge/src/ffi.rs
M crates/uniffi-bridge/src/lib.rs
M crates/universal-device-sdk/src/clear_signing.rs
M crates/universal-device-sdk/src/ctap21.rs
M crates/universal-device-sdk/src/lib.rs
M crates/universal-device-sdk/src/secure_channel.rs
M crates/universal-device-sdk/src/secure_guard.rs
M crates/universal-device-sdk/src/shamir.rs
M docs/manual/img/01_open_locked.png
M docs/manual/img/02_unlock_pin.png
M docs/manual/img/03_vault_list.png
M reports/refactoring/dep-track.json
M reports/testing/CONSOLIDATED_RUN.md
M reports/testing/consolidated-result.json
?? STDOUT
?? docs/bench-destructive.md
?? docs/bench-freertos-s3.md
?? docs/finalizacao-freertos-rust.md
?? docs/freertos-rust.md
?? docs/proximity-worktree-handoff.md
?? reports/testing/HW_MATRIX.md
?? tools/app_path_replay.py
