# Consolidated Run

Unified orchestrator: `python tools/run_all.py` (stdlib only: argparse,
subprocess, json, pathlib; no third-party imports). Portable across
Windows and Linux (pathlib + `sys.executable`, no hardcoded machine
paths). Deterministic emoji-free output. Never destructive: no
flash / monitor / esptool / adb / cargo-update invocations; the
orchestrator refuses such commands before execution. No network calls.
No secrets printed or persisted (only exit codes, durations, tails).

Machine-readable counterpart (overwritten each run):
`reports/testing/consolidated-result.json`.
Human sections below are appended per run with a UTC timestamp.

## Suite list (execution order)

| # | leg | command(s) | kind |
| --- | --- | --- | --- |
| 1 | test-debug | `cargo test --workspace` | gate |
| 2 | test-firmware-features | `cargo test -p aegis-fido-firmware --features freertos,proximity` | gate |
| 3 | clippy | `cargo clippy --workspace --all-targets -- -D warnings` | gate |
| 4 | fmt | `cargo fmt --all -- --check` | advisory (record-only) |
| 5 | deny | `cargo deny check licenses advisories bans sources` | gate |
| 6 | dep-track | `python tools/dep_track.py --check` | gate |
| 7 | docs | `python tools/docs-lint/docs_lint.py --root reports` + `python tools/docs-lint/docs_lint.py --root docs` (two invocations: the docs-lint CLI accepts a single `--root`) + in-process broken internal-path scan of `reports/**` | gate |
| 8 | scripts | existence of every `scripts/*.ps1` + `pwsh -NoProfile -Command` `Parser::ParseFile` syntax check per file (parse only, device scripts are never executed) | gate |
| 9 | test-release | `cargo test --workspace --release` | opt-in gate (only with `--release`; SKIP otherwise) |

Docs/tests/scripts coverage: tests via legs 1-2 (+9 opt-in); docs via
leg 7 (docs-lint for `reports` and `docs` roots plus the `reports/**`
internal-path scan); scripts via leg 8 (existence + parse check).

## Gates

- Hard gates (fail the run): test-debug, test-firmware-features, clippy,
  deny, dep-track, docs, scripts, test-release (when enabled).
- Advisory (record-only, never fails the run alone): fmt
  (`cargo fmt --check`; pre-existing violations are recorded, not enforced).
- test-release is SKIP unless `--release` is passed; SKIP never affects
  the exit code. Explicit `--leg test-release` runs it even without
  `--release`.

## Exit-code contract

- Orchestrator exit 0 only if every non-advisory executed leg passes.
- Advisory failures never change the exit code alone.
- SKIP legs never change the exit code.
- Usage errors (unknown `--leg`, safety refusal) exit 2.
- docs-lint exit semantics (per `tools/docs-lint/README.md`): 0 = no
  broken local links (warnings may still print); 1 = broken links found
  (or brand hits under `--strict`); 2 = usage error. Non-strict
  invocation here, so exit 1 fails the `docs` leg. Exit semantics
  match the gate expectation, so the `docs` leg is a hard gate
  (not record-only).

## CLI

- `python tools/run_all.py --dry-run` — list legs/commands, execute nothing.
- `python tools/run_all.py --leg <name>` — run one leg only.
- `python tools/run_all.py --release` — include the release leg.
- `python tools/run_all.py --json-only` — print JSON to stdout, skip
  markdown append (JSON file is still written).

## Results

PENDING until the post-godfiles execution. Another lane is editing
`crates/**`; heavy suites would race, so no real legs were executed yet.
Each leg captures exit code, tail (last 15 lines), and duration.

| timestamp_utc | leg | advisory | status | exit | duration_s | notes |
| --- | --- | --- | --- | --- | --- | --- |
| PENDING | test-debug | no | PENDING | PENDING | PENDING | post-godfiles execution |
| PENDING | test-firmware-features | no | PENDING | PENDING | PENDING | post-godfiles execution |
| PENDING | clippy | no | PENDING | PENDING | PENDING | post-godfiles execution |
| PENDING | fmt | yes | PENDING | PENDING | PENDING | post-godfiles execution (advisory) |
| PENDING | deny | no | PENDING | PENDING | PENDING | post-godfiles execution |
| PENDING | dep-track | no | PENDING | PENDING | PENDING | post-godfiles execution |
| PENDING | docs | no | PENDING | PENDING | PENDING | post-godfiles execution |
| PENDING | scripts | no | PENDING | PENDING | PENDING | post-godfiles execution |
| PENDING | test-release | no | PENDING | PENDING | PENDING | post-godfiles execution (needs --release) |
