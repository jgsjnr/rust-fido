# Regression Report -- preservation-first baseline (zero moves)

- Worktree: `E:\projetos\standalone-architecture-worktree`
- Branch: `refactor/standalone-architecture-cleanup`
- HEAD: `e683979`
- Date (UTC): 2026-11-02
- Mode: preservation-first, zero file moves executed. Scheduler fix `e683979`
  (crates-only, sibling lane) re-validated here; no test-file or report-scope
  changes beyond owned report files.
- Scope: host-only Windows x86_64 (`cargo check` / `cargo clippy` / `cargo test`).
  No ESP-IDF target build, no hardware acceptance.

## Baseline (from reports/testing/BASELINE.md, HEAD 30680ff)

| Gate | Result | Evidence |
| ---- | ------ | -------- |
| `cargo check --workspace` | PASS | exit 0, VERIFIED |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS | exit 0, VERIFIED |
| `cargo test --workspace` | BLOCKED (pre-existing fail) | 648 passed / 1 failed, 0 ignored |
| `cargo fmt --check` | BLOCKED (pre-existing fail) | 28 files, parent-noted, not re-run in this lane |
| `tools/architecture-analyzer` `cargo check` | PASS | exit 0, re-verified in final integration |

Sole test failure (pre-existing, not introduced here):

- `aegis-fido-firmware` lib: 514 passed, 1 failed.
- Failing test: `freertos_sched demo_freertos_end_to_end`,
  assertion `ticks >= 1` at `freertos_sched.rs:924`.
- `aegis-fido-core` lib: 124 passed, 0 failed (VERIFIED).
- `ctap_tests` integration: 9 passed, 0 failed (VERIFIED).
- `e2e_vectors` integration: 1 passed, 0 failed (VERIFIED).

## Why zero new regressions

- `reports/refactoring/moved-files.md`: NONE, zero moves executed.
- `reports/refactoring/dependency-graph-after.json` is identical to
  `dependency-graph-before.json` (zero moves, no dependency changed).
- `reports/refactoring/migration-plan.json`: `moves_executed: 0`,
  KEEP verdicts plus 3 PROPOSED items only, nothing executed.
- No files under `crates/`, `tools/`, or `app-*` were modified in this lane.
  Untracked additions are reports, `deny.toml`, `THIRD_PARTY_NOTICES.md`,
  and `tools/architecture-analyzer/` only.
- With no code delta, no new regression is possible by construction.
  The one failing test and the fmt failures pre-date this lane.

## Verdict

- **PASS at HEAD `e683979` — pre-existing failure FIXED, not merely BLOCKED.**
- `cargo check`: PASS. `cargo clippy --workspace --all-targets -- -D warnings`: PASS (exit 0, re-verified 2026-11-02).
- `cargo test --workspace`: PASS (exit 0; 927 passed / 0 failed / 1 pre-existing
  doc-test ignore). The `freertos_sched demo_freertos_end_to_end` failure
  (`ticks >= 1`) is FIXED by `e683979`, which waits for `EVT_TICK_10MS`
  (non-destructive) before `request_stop` — assertion not weakened.
- External standalone consumer (`$env:TEMP`, SDK + secure-guard + usb path
  deps): 4/4 PASS desktop-only; usb root re-export gap + `no_std` caveat noted.
- `cargo deny`: BLOCKED (binary absent; CC0/MPL/Unlicense not allow-listed).
- `cargo fmt`: still BLOCKED (28 files, pre-existing, not re-run in this lane).
- Zero moves, therefore zero new regressions introduced by this lane; the only
  code delta since `30680ff` is the sibling-lane scheduler fix, which turned
  the one red test green.
- Remediation owner: firmware scheduler test owner — closed by `e683979`.
  Do NOT weaken any gate to make a red build pass.
