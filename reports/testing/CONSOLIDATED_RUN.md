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
## Run 2026-11-02T15:57:30Z (release=on, selector=all)

| leg | advisory | status | exit | duration_s | notes |
| --- | --- | --- | --- | --- | --- |
| test-debug | no | PASS | 0 | 20.4 |  |
| test-firmware-features | no | PASS | 0 | 24.3 |  |
| clippy | no | PASS | 0 | 26.5 |  |
| fmt | yes | FAIL | 1 | 2.2 |  |
| deny | no | PASS | 0 | 35.9 |  |
| dep-track | no | FAIL | 2 | 0.7 |  |
| docs | no | FAIL | 1 | 0.8 | reports-scan checked=0 broken=0 |
| scripts | no | PASS | 0 | 14.6 |  |
| test-release | no | PASS | 0 | 91.6 |  |

### Tails (last 15 lines per leg)

#### `test-debug` - PASS (exit 0, 20.4s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=20.4
```

#### `test-firmware-features` - PASS (exit 0, 24.3s)

```
     Running tests\secure_guard_integration.rs (C:/t\debug\deps\secure_guard_integration-0f24304cdbfecac5.exe)

running 2 tests
test test_secure_guard_full_lifecycle_and_enforcement ... ok
test test_five_failures_trigger_scoped_wipe_preserving_fido2 ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

   Doc-tests aegis_fido_firmware

running 1 test
test crates\aegis-fido-firmware\src\freertos.rs - freertos (line 57) ... ignored

test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=24.3
```

#### `clippy` - PASS (exit 0, 26.5s)

```
$ cargo clippy --workspace --all-targets -- -D warnings
    Checking aegis-secure-guard v1.0.0 (E:\projetos\standalone-architecture-worktree\crates\aegis-secure-guard)
    Checking aegis-fido-usb v1.0.0 (E:\projetos\standalone-architecture-worktree\crates\aegis-fido-usb)
   Compiling aegis-fido-firmware v1.0.0 (E:\projetos\standalone-architecture-worktree\crates\aegis-fido-firmware)
    Checking aegis-fido-core v1.0.0 (E:\projetos\standalone-architecture-worktree\crates\aegis-fido-core)
    Checking uniffi-bridge v1.0.0 (E:\projetos\standalone-architecture-worktree\crates\uniffi-bridge)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 25.15s
exit=0 duration_s=26.5
```

#### `fmt` - FAIL (exit 1, 2.2s)

```
     }
 }
Diff in \\?\E:\projetos\standalone-architecture-worktree\crates\universal-device-sdk\src\shamir.rs:82:
             Value::Text("data".into()),
             Value::Bytes(share.data.to_vec()),
         ),
[31m-        (
[0m[31m-            Value::Text("crc32".into()),
[0m[31m-            Value::from(share.crc32 as u64),
[0m[31m-        ),
[0m[32m+        (Value::Text("crc32".into()), Value::from(share.crc32 as u64)),
[0m     ];
     Value::Map(map)
 }
exit=1 duration_s=2.2
```

#### `deny` - PASS (exit 0, 35.9s)

```
      ├── rustix v1.1.5 (*)
      ├── tempfile v3.27.0 (*)
      └── winapi-util v0.1.11
          ├── ignore v0.4.33
          │   └── globwalk v0.8.1
          │       └── embuild v0.33.5 (*)
          ├── same-file v1.0.6
          │   ├── ignore v0.4.33 (*)
          │   └── walkdir v2.5.0
          │       ├── globwalk v0.8.1 (*)
          │       └── ignore v0.4.33 (*)
          └── walkdir v2.5.0 (*)

advisories ok, bans ok, licenses ok, sources ok
exit=0 duration_s=35.9
```

#### `dep-track` - FAIL (exit 2, 0.7s)

```
$ C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe tools/dep_track.py --check
wrote reports/refactoring/dep-track.json (228 files, 23 gods)
NEW god-files (score>25, not in allowlist):
  25.45 crates/aegis-fido-firmware/src/secure_guard_exec/mod.rs (lines=1195 fan_in=0 fan_out=9)
exit=2 duration_s=0.7
```

#### `docs` - FAIL (exit 1, 0.8s)

```
STYLE-HINT: docs\evaluation\EVALUATION.md:250 (26 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:295 (42 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:301 (42 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:368 (27 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:376 (42 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:413 (26 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:413 (31 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:421 (28 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:430 (34 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:431 (30 words)
STYLE-HINT: docs\plans\PLANS.md:45 (29 words)
STYLE-HINT: docs\plans\PLANS.md:48 (26 words)
STYLE-HINT: docs\plans\PLANS.md:50 (35 words)
exit=1 duration_s=0.3
REPORTS-SCAN: links checked=0 broken=0
```

#### `scripts` - PASS (exit 0, 14.6s)

```
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\standalone-architecture-worktree\scripts\menu.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.7
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\standalone-architecture-worktree\scripts\pipeline.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.6
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\standalone-architecture-worktree\scripts\qemu-s3.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.7
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\standalone-architecture-worktree\scripts\sync-master.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\standalone-architecture-worktree\scripts\test-all.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.6
```

#### `test-release` - PASS (exit 0, 91.6s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=91.6
```

