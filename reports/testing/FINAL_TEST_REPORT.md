# Final Test Report -- BASELINE ONLY (full gate pending later phases)

Status: BASELINE ONLY. This file records the clean-tree regression baseline at HEAD 30680ff on 2026-11-02.
It is not a full PR gate verdict. The full gate (fmt clean, workspace clippy, workspace check, minimal plus full plus external-consumer presets) remains pending for later phases.

- Worktree: `E:\projetos\standalone-architecture-worktree`, HEAD `30680ff`, clean, no code changes.
- Toolchain: `cargo 1.99.1` / `rustc 1.99.1`.
- Scope: host-only Windows x86_64. No ESP-IDF target, no NDK .so matrix, no hardware.

## Section verdicts (evidence-backed only)

## Post-fix full validation (2026-11-02 UTC, HEAD `e683979`)

Scheduler fix `e683979` ("stabilize freertos_sched demo end-to-end tick
assertion", 2026-11-01) resolved the sole pre-existing failure without
weakening any assertion: the demo now waits for the `EVT_TICK_10MS` bit
(non-destructive) before `request_stop`, guaranteeing `ticks >= 1`
(`crates/aegis-fido-firmware/src/freertos_sched.rs`, +11/-1).

### `cargo test --workspace` — PASS (exit 0, VERIFIED)

- Toolchain: `cargo 1.99.1` / `rustc 1.99.1` (unchanged from baseline).
- Full log: host-local `$env:TEMP\postfix-workspace-test.log`.
- Prior baseline: 648 passed / 1 failed. Now: **927 passed, 0 failed**,
  1 ignored (firmware doc-test, pre-existing ignore).
- Per-crate results (all `ok`):
  - `aegis-fido-core` lib: 124 passed, 0 failed (VERIFIED).
  - `ctap_tests` integration: 9 passed, 0 failed (VERIFIED).
  - `e2e_vectors` integration: 1 passed, 0 failed (VERIFIED).
  - `aegis-fido-firmware` lib: **515 passed, 0 failed (VERIFIED, FIXED)** —
    includes `freertos_sched demo_freertos_end_to_end` now passing.
  - firmware bins/integration: `applets_t9` 12, `freertos_tasks` 2,
    `migration_tests` 3, `namespaced_store_t5` 14, `netwifi_t10` 16,
    `otakey_provider_t6` 8, `proximity_freertos` 0, `secure_guard_integration` 2.
  - `aegis-fido-usb` lib: 92 passed, 0 failed (VERIFIED).
  - `aegis-secure-guard` lib: 39 passed, 0 failed (VERIFIED).
  - `aegis-bridge` lib (`aegis_bridge`): 26 passed, 0 failed (VERIFIED).
  - `universal-device-sdk` lib: 64 passed, 0 failed (VERIFIED).
  - Doc-tests: all `ok` (1 ignored, pre-existing).
- Scope: host-only Windows x86_64. No ESP-IDF target, no NDK matrix,
  no physical-device acceptance. Mocked traffic/ports/screenshots/emulators/
  handshakes are not device acceptance.

### `cargo clippy --workspace --all-targets -- -D warnings` — PASS (exit 0, VERIFIED)

- Full log: host-local `$env:TEMP\postfix-workspace-clippy.log`.
- Output: `Finished dev profile [unoptimized + debuginfo]` in 3.86s.

### Standalone consumer reuse — VERIFIED desktop-only (`$env:TEMP` consumer, 4/4)

- External crate `standalone-consumer` (host-local `$env:TEMP`, NOT part of
  this repo) depends on `universal-device-sdk`, `aegis-secure-guard`, and
  `aegis-fido-usb` via path dependencies: `cargo test -- --test-threads=1`
  exit 0, **4 passed / 0 failed** (log: `$env:TEMP\standalone-consumer-test.log`).
  Tests: SDK envelope seal→open roundtrip; SecureGuard provision→unlock
  roundtrip; wrong-PIN denied fail-closed; USB CTAPHID frame via crate-root
  re-export (`CtapHidFramer::frame_message`, `CtapHidError::to_packet`).
- Findings (gaps/caveats, still open):
  - SDK `auth`/`envelope` modules are private (`mod auth; mod envelope;`);
    external consumers MUST use root re-exports
    (`universal_device_sdk::AuthContext`, `::seal_envelope`, ...). Works, but
    module paths do not resolve — documented, not changed (out of lane).
  - USB root re-export gap: `CtapHidMessage` has no `to_packet`; framing goes
    through `CtapHidFramer`. Root re-exports exist but the message type is not
    directly frameable — noted for the standalone-reuse lane.
  - `no_std` caveat: SDK (`cfg_attr(not(test), no_std)` + `alloc`) and
    SecureGuard (`#![no_std]` + `alloc`) declare `no_std`, but `aegis-fido-usb`
    has no `no_std` attribute (std-only). All reuse evidence here is
    desktop std host-only; no embedded/ESP target build was run in this lane —
    bare-metal reuse remains UNVALIDATED.

### License / `cargo deny` evidence — BLOCKED (tool absent)

- `cargo deny` binary: ABSENT on host (`Get-Command cargo-deny` → not found).
  No `cargo deny check` run exists in this lane → deny verdict BLOCKED.
- Per repo `deny.toml` `[licenses]`: allow-list is MIT, Apache-2.0,
  BSD-2-Clause, BSD-3-Clause, ISC, Zlib (+ per-crate GPL-3.0-only exceptions).
  CC0-1.0 / MPL-2.0 / Unlicense are NOT allow-listed → any dependency under
  those licenses would be denied (BLOCKED pending a real `cargo deny` run).
- First-party crates are all `GPL-3.0-only` (covered by exceptions);
  `reports/compliance/license-inventory.json` shows no CC0/MPL/Unlicense
  entries, but without the tool run this is UNVERIFIED.

### Updated verdict

- `cargo check --workspace`: PASS (baseline, unchanged).
- `cargo clippy --workspace --all-targets -- -D warnings`: PASS (exit 0, re-verified).
- `cargo test --workspace`: **PASS (exit 0, 927 passed / 0 failed) — pre-existing fail FIXED by `e683979`.**
- Standalone consumer (SDK/secure-guard/usb): VERIFIED desktop-only, 4/4.
- `cargo deny`: BLOCKED (binary absent).
- `cargo fmt --check`: still BLOCKED (28 files pre-existing; not re-run in this lane, parent-noted).
- Physical-device acceptance: not performed (out of scope, all lanes).
