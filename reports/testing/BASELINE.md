# Baseline validation - standalone-architecture worktree

- Worktree: E:/projetos/standalone-architecture-worktree
- HEAD: 30680ff (refactor/standalone-architecture-cleanup)
- Date (UTC): 2026-11-02
- Mode: read-only baseline, no code modifications.

## Toolchain
- cargo 1.99.1 (5f94df478 2026-08-27) - VERIFIED
- rustc 1.99.1 (58cf8f9c3 2026-10-13) - VERIFIED

## rustfmt
- Status: pre-existing FAIL noted (28 files), not re-run in this lane - BLOCKED (pre-existing, parent-noted)

## cargo check --workspace
- Exit code: 0 - VERIFIED (PASS)

## cargo test --workspace
- Exit code: 101 - BLOCKED (1 failing test)
- Full log: TEMP baseline-test.log (host-local)
- aegis-fido-core lib: ok, 124 passed, 0 failed - VERIFIED
- ctap_tests integration: ok, 9 passed, 0 failed - VERIFIED
- e2e_vectors integration: ok, 1 passed, 0 failed - VERIFIED
- aegis-fido-firmware lib: FAILED, 514 passed, 1 failed - BLOCKED
- Totals: 648 passed, 1 failed, 0 ignored
- Sole failure: freertos_sched demo_freertos_end_to_end, assertion ticks greater-equal 1 at freertos_sched.rs:924

## cargo clippy --workspace --all-targets -- -D warnings
- Exit code: 0 - VERIFIED (PASS)
- Output: Finished dev profile in 1.00s
- Full log: TEMP baseline-clippy.log (host-local)

## Host-only note
- Host-only validation (Windows host, cargo test/clippy/check). No physical-device acceptance.
- Mocked traffic, ports, screenshots, emulators, handshakes are not device acceptance.

## Verdict
- Toolchain: VERIFIED
- check: VERIFIED
- clippy: VERIFIED
- test workspace: BLOCKED (firmware demo_freertos_end_to_end fails; rest pass)
- fmt: BLOCKED (pre-existing, parent-noted)
- Overall baseline: BLOCKED by 1 test failure plus pre-existing fmt fail.
