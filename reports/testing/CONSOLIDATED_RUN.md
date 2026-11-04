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

## Run 2026-11-02T16:09:32Z (release=on, selector=all)

| leg | advisory | status | exit | duration_s | notes |
| --- | --- | --- | --- | --- | --- |
| test-debug | no | PASS | 0 | 22.8 |  |
| test-firmware-features | no | PASS | 0 | 8.5 |  |
| clippy | no | PASS | 0 | 4.1 |  |
| fmt | yes | FAIL | 1 | 1.4 |  |
| deny | no | PASS | 0 | 12.9 |  |
| dep-track | no | PASS | 0 | 0.3 |  |
| docs | no | PASS | 0 | 0.2 | reports-scan checked=0 broken=0 |
| scripts | no | PASS | 0 | 9.8 |  |
| test-release | no | PASS | 0 | 37.0 |  |

### Tails (last 15 lines per leg)

#### `test-debug` - PASS (exit 0, 22.8s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=22.8
```

#### `test-firmware-features` - PASS (exit 0, 8.5s)

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
exit=0 duration_s=8.5
```

#### `clippy` - PASS (exit 0, 4.1s)

```
$ cargo clippy --workspace --all-targets -- -D warnings
   Compiling aegis-fido-firmware v1.0.0 (E:\projetos\standalone-architecture-worktree\crates\aegis-fido-firmware)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.84s
exit=0 duration_s=4.1
```

#### `fmt` - FAIL (exit 1, 1.4s)

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
exit=1 duration_s=1.4
```

#### `deny` - PASS (exit 0, 12.9s)

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
exit=0 duration_s=12.9
```

#### `dep-track` - PASS (exit 0, 0.3s)

```
$ C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe tools/dep_track.py --check
wrote reports/refactoring/dep-track.json (230 files, 22 gods)
check ok: no new god-files beyond 24 allowlisted
exit=0 duration_s=0.3
```

#### `docs` - PASS (exit 0, 0.2s)

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
exit=0 duration_s=0.1
REPORTS-SCAN: links checked=0 broken=0
```

#### `scripts` - PASS (exit 0, 9.8s)

```
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\standalone-architecture-worktree\scripts\menu.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\standalone-architecture-worktree\scripts\pipeline.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\standalone-architecture-worktree\scripts\qemu-s3.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\standalone-architecture-worktree\scripts\sync-master.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\standalone-architecture-worktree\scripts\test-all.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
```

#### `test-release` - PASS (exit 0, 37.0s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=37.0
```

## Run 2026-11-03T00:48:10Z (release=on, selector=all)

| leg | advisory | status | exit | duration_s | notes |
| --- | --- | --- | --- | --- | --- |
| test-debug | no | PASS | 0 | 26.4 |  |
| test-firmware-features | no | PASS | 0 | 22.2 |  |
| clippy | no | PASS | 0 | 4.1 |  |
| fmt | yes | FAIL | 1 | 1.2 |  |
| deny | no | PASS | 0 | 33.8 |  |
| dep-track | no | FAIL | 2 | 0.3 |  |
| docs | no | FAIL | 1 | 0.2 | reports-scan checked=1 broken=1 |
| scripts | no | PASS | 0 | 9.2 |  |
| test-release | no | PASS | 0 | 56.2 |  |

### Tails (last 15 lines per leg)

#### `test-debug` - PASS (exit 0, 26.4s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=26.4
```

#### `test-firmware-features` - PASS (exit 0, 22.2s)

```
     Running tests\secure_guard_integration.rs (C:/t\debug\deps\secure_guard_integration-eb5fb21692977e35.exe)

running 2 tests
test test_secure_guard_full_lifecycle_and_enforcement ... ok
test test_five_failures_trigger_scoped_wipe_preserving_fido2 ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_fido_firmware

running 1 test
test crates\aegis-fido-firmware\src\freertos.rs - freertos (line 57) ... ignored

test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=22.2
```

#### `clippy` - PASS (exit 0, 4.1s)

```
$ cargo clippy --workspace --all-targets -- -D warnings
    Checking aegis-fido-usb v1.0.0 (E:\projetos\fido\crates\aegis-fido-usb)
    Checking aegis-secure-guard v1.0.0 (E:\projetos\fido\crates\aegis-secure-guard)
    Checking aegis-fido-core v1.0.0 (E:\projetos\fido\crates\aegis-fido-core)
    Checking uniffi-bridge v1.0.0 (E:\projetos\fido\crates\uniffi-bridge)
   Compiling aegis-fido-firmware v1.0.0 (E:\projetos\fido\crates\aegis-fido-firmware)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.87s
exit=0 duration_s=4.1
```

#### `fmt` - FAIL (exit 1, 1.2s)

```
     }
 }
Diff in \\?\E:\projetos\fido\crates\universal-device-sdk\src\shamir.rs:82:
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
exit=1 duration_s=1.2
```

#### `deny` - PASS (exit 0, 33.8s)

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
exit=0 duration_s=33.8
```

#### `dep-track` - FAIL (exit 2, 0.3s)

```
$ C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe tools/dep_track.py --check
wrote reports/refactoring/dep-track.json (232 files, 26 gods)
NEW god-files (score>25, not in allowlist):
  38.11 crates/aegis-fido-firmware/src/run/legacy_sg_dispatch.rs (lines=361 fan_in=0 fan_out=23)
  27.85 crates/aegis-fido-firmware/src/vendor_exec.rs (lines=835 fan_in=0 fan_out=13)
  27.54 crates/aegis-fido-firmware/src/pairing.rs (lines=604 fan_in=10 fan_out=11)
  25.16 crates/aegis-fido-firmware/src/ble_gatt.rs (lines=416 fan_in=9 fan_out=11)
exit=2 duration_s=0.3
```

#### `docs` - FAIL (exit 1, 0.2s)

```
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
exit=0 duration_s=0.1
REPORTS-SCAN: links checked=1 broken=1
BROKEN-PATH: reports/refactoring/CLOSED_MODEL_PLAN.md -> LICENSE
```

#### `scripts` - PASS (exit 0, 9.2s)

```
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\pipeline.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\qemu-s3.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\select-capability.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\sync-master.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\test-all.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
```

#### `test-release` - PASS (exit 0, 56.2s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=56.2
```

## Run 2026-11-03T01:06:10Z (release=on, selector=all)

| leg | advisory | status | exit | duration_s | notes |
| --- | --- | --- | --- | --- | --- |
| test-debug | no | PASS | 0 | 19.8 |  |
| test-firmware-features | no | PASS | 0 | 6.3 |  |
| clippy | no | PASS | 0 | 0.7 |  |
| fmt | yes | FAIL | 1 | 1.2 |  |
| deny | no | PASS | 0 | 12.6 |  |
| dep-track | no | PASS | 0 | 0.3 |  |
| docs | no | PASS | 0 | 0.4 | reports-scan checked=1 broken=0 |
| scripts | no | PASS | 0 | 9.0 |  |
| test-release | no | PASS | 0 | 32.8 |  |

### Tails (last 15 lines per leg)

#### `test-debug` - PASS (exit 0, 19.8s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=19.8
```

#### `test-firmware-features` - PASS (exit 0, 6.3s)

```
     Running tests\secure_guard_integration.rs (C:/t\debug\deps\secure_guard_integration-eb5fb21692977e35.exe)

running 2 tests
test test_secure_guard_full_lifecycle_and_enforcement ... ok
test test_five_failures_trigger_scoped_wipe_preserving_fido2 ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_fido_firmware

running 1 test
test crates\aegis-fido-firmware\src\freertos.rs - freertos (line 57) ... ignored

test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=6.3
```

#### `clippy` - PASS (exit 0, 0.7s)

```
$ cargo clippy --workspace --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.52s
exit=0 duration_s=0.7
```

#### `fmt` - FAIL (exit 1, 1.2s)

```
     }
 }
Diff in \\?\E:\projetos\fido\crates\universal-device-sdk\src\shamir.rs:82:
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
exit=1 duration_s=1.2
```

#### `deny` - PASS (exit 0, 12.6s)

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
exit=0 duration_s=12.6
```

#### `dep-track` - PASS (exit 0, 0.3s)

```
$ C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe tools/dep_track.py --check
wrote reports/refactoring/dep-track.json (245 files, 22 gods)
check ok: no new god-files beyond 24 allowlisted
exit=0 duration_s=0.3
```

#### `docs` - PASS (exit 0, 0.4s)

```
STYLE-HINT: docs\evaluation\EVALUATION.md:178 (38 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:213 (44 words)
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
exit=0 duration_s=0.1
REPORTS-SCAN: links checked=1 broken=0
```

#### `scripts` - PASS (exit 0, 9.0s)

```
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\pipeline.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\qemu-s3.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\select-capability.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\sync-master.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\test-all.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
```

#### `test-release` - PASS (exit 0, 32.8s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=32.8
```

## Run 2026-11-03T17:21:54Z (release=on, selector=all)

| leg | advisory | status | exit | duration_s | notes |
| --- | --- | --- | --- | --- | --- |
| test-debug | no | PASS | 0 | 27.6 |  |
| test-firmware-features | no | PASS | 0 | 15.7 |  |
| clippy | no | PASS | 0 | 3.9 |  |
| fmt | yes | FAIL | 1 | 1.5 |  |
| deny | no | PASS | 0 | 31.4 |  |
| dep-track | no | FAIL | 2 | 0.3 |  |
| docs | no | PASS | 0 | 0.2 | reports-scan checked=1 broken=0 |
| scripts | no | PASS | 0 | 8.8 |  |
| test-release | no | PASS | 0 | 53.4 |  |

### Tails (last 15 lines per leg)

#### `test-debug` - PASS (exit 0, 27.6s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=27.6
```

#### `test-firmware-features` - PASS (exit 0, 15.7s)

```
     Running tests\secure_guard_integration.rs (C:/t\debug\deps\secure_guard_integration-eb5fb21692977e35.exe)

running 2 tests
test test_secure_guard_full_lifecycle_and_enforcement ... ok
test test_five_failures_trigger_scoped_wipe_preserving_fido2 ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

   Doc-tests aegis_fido_firmware

running 1 test
test crates\aegis-fido-firmware\src\freertos.rs - freertos (line 57) ... ignored

test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=15.7
```

#### `clippy` - PASS (exit 0, 3.9s)

```
$ cargo clippy --workspace --all-targets -- -D warnings
    Checking aegis-secure-guard v1.0.0 (E:\projetos\fido\crates\aegis-secure-guard)
    Checking aegis-fido-core v1.0.0 (E:\projetos\fido\crates\aegis-fido-core)
    Checking uniffi-bridge v1.0.0 (E:\projetos\fido\crates\uniffi-bridge)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.68s
exit=0 duration_s=3.9
```

#### `fmt` - FAIL (exit 1, 1.5s)

```
     }
 }
Diff in \\?\E:\projetos\fido\crates\universal-device-sdk\src\shamir.rs:82:
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
exit=1 duration_s=1.5
```

#### `deny` - PASS (exit 0, 31.4s)

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
exit=0 duration_s=31.4
```

#### `dep-track` - FAIL (exit 2, 0.3s)

```
$ C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe tools/dep_track.py --check
wrote reports/refactoring/dep-track.json (251 files, 23 gods)
NEW god-files (score>25, not in allowlist):
  26.30 crates/aegis-fido-firmware/src/secure_guard_exec/tests.rs (lines=1280 fan_in=0 fan_out=9)
exit=2 duration_s=0.3
```

#### `docs` - PASS (exit 0, 0.2s)

```
STYLE-HINT: docs\evaluation\EVALUATION.md:178 (38 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:213 (44 words)
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
exit=0 duration_s=0.1
REPORTS-SCAN: links checked=1 broken=0
```

#### `scripts` - PASS (exit 0, 8.8s)

```
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\pipeline.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\qemu-s3.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\select-capability.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\sync-master.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\test-all.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.3
```

#### `test-release` - PASS (exit 0, 53.4s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=53.4
```

## Run 2026-11-03T18:14:09Z (release=on, selector=all)

| leg | advisory | status | exit | duration_s | notes |
| --- | --- | --- | --- | --- | --- |
| test-debug | no | PASS | 0 | 21.7 |  |
| test-firmware-features | no | PASS | 0 | 26.0 |  |
| clippy | no | PASS | 0 | 0.9 |  |
| fmt | yes | PASS | 0 | 1.3 |  |
| deny | no | PASS | 0 | 30.4 |  |
| dep-track | no | FAIL | 2 | 0.4 |  |
| docs | no | PASS | 0 | 0.2 | reports-scan checked=1 broken=0 |
| scripts | no | PASS | 0 | 11.7 |  |
| test-release | no | PASS | 0 | 63.9 |  |

### Tails (last 15 lines per leg)

#### `test-debug` - PASS (exit 0, 21.7s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=21.7
```

#### `test-firmware-features` - PASS (exit 0, 26.0s)

```
     Running tests\secure_guard_integration.rs (C:/t\debug\deps\secure_guard_integration-eb5fb21692977e35.exe)

running 2 tests
test test_secure_guard_full_lifecycle_and_enforcement ... ok
test test_five_failures_trigger_scoped_wipe_preserving_fido2 ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

   Doc-tests aegis_fido_firmware

running 1 test
test crates\aegis-fido-firmware\src\freertos.rs - freertos (line 57) ... ignored

test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=26.0
```

#### `clippy` - PASS (exit 0, 0.9s)

```
$ cargo clippy --workspace --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.64s
exit=0 duration_s=0.9
```

#### `fmt` - PASS (exit 0, 1.3s)

```
$ cargo fmt --all -- --check
(no output)
exit=0 duration_s=1.3
```

#### `deny` - PASS (exit 0, 30.4s)

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
exit=0 duration_s=30.4
```

#### `dep-track` - FAIL (exit 2, 0.4s)

```
$ C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe tools/dep_track.py --check
wrote reports/refactoring/dep-track.json (252 files, 24 gods)
NEW god-files (score>25, not in allowlist):
  27.92 crates/aegis-fido-firmware/src/secure_guard_exec/tests.rs (lines=1442 fan_in=0 fan_out=9)
  25.90 crates/universal-device-sdk/src/providers/oath.rs (lines=40 fan_in=30 fan_out=7)
exit=2 duration_s=0.4
```

#### `docs` - PASS (exit 0, 0.2s)

```
STYLE-HINT: docs\evaluation\EVALUATION.md:178 (38 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:213 (44 words)
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
exit=0 duration_s=0.1
REPORTS-SCAN: links checked=1 broken=0
```

#### `scripts` - PASS (exit 0, 11.7s)

```
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\pipeline.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\qemu-s3.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\select-capability.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\sync-master.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.6
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\test-all.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
```

#### `test-release` - PASS (exit 0, 63.9s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=63.9
```

## Run 2026-11-03T23:04:03Z (release=on, selector=all)

| leg | advisory | status | exit | duration_s | notes |
| --- | --- | --- | --- | --- | --- |
| test-debug | no | FAIL | 101 | 23.2 |  |
| test-firmware-features | no | FAIL | 101 | 3.1 |  |
| clippy | no | FAIL | 101 | 3.2 |  |
| fmt | yes | FAIL | 1 | 1.5 |  |
| deny | no | PASS | 0 | 17.2 |  |
| dep-track | no | FAIL | 2 | 0.3 |  |
| docs | no | PASS | 0 | 0.7 | reports-scan checked=1 broken=0 |
| scripts | no | PASS | 0 | 8.6 |  |
| test-release | no | FAIL | 101 | 26.8 |  |

### Tails (last 15 lines per leg)

#### `test-debug` - FAIL (exit 101, 23.2s)

```
   Compiling aegis-fido-core v1.0.0 (E:\projetos\fido\crates\aegis-fido-core)
   Compiling uniffi-bridge v1.0.0 (E:\projetos\fido\crates\uniffi-bridge)
   Compiling aegis-fido-firmware v1.0.0 (E:\projetos\fido\crates\aegis-fido-firmware)
error[E0761]: file for module `oath` found at both "crates\universal-device-sdk\src\providers\oath.rs" and "crates\universal-device-sdk\src\providers\oath\mod.rs"
  --> crates\universal-device-sdk\src\providers\mod.rs:26:1
   |
26 | mod oath;
   | ^^^^^^^^^
   |
   = help: delete or rename one of them to remove the ambiguity

For more information about this error, try `rustc --explain E0761`.
error: could not compile `universal-device-sdk` (lib test) due to 1 previous error
warning: build failed, waiting for other jobs to finish...
exit=101 duration_s=23.2
```

#### `test-firmware-features` - FAIL (exit 101, 3.1s)

```
637 |     fn storage() -> SecureStorage<MockFlashBackend> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ `crate::openpgp_cmd::tests::storage`: not accessible
    |
   ::: crates\aegis-fido-firmware\src\proximity.rs:249:5
    |
249 |     fn storage() -> SecureStorage<MockFlashBackend> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ `crate::proximity::rolling_tests::storage`: not accessible
    |
   ::: crates\aegis-fido-firmware\src\time_sync.rs:352:5
    |
352 |     fn storage() -> SecureStorage<MockFlashBackend> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ `crate::time_sync::tests::storage`: not accessible

error: could not compile `aegis-fido-firmware` (lib test) due to 1 previous error
exit=101 duration_s=3.1
```

#### `clippy` - FAIL (exit 101, 3.2s)

```
    Checking aegis-fido-core v1.0.0 (E:\projetos\fido\crates\aegis-fido-core)
    Checking aegis-secure-guard v1.0.0 (E:\projetos\fido\crates\aegis-secure-guard)
error[E0761]: file for module `oath` found at both "crates\universal-device-sdk\src\providers\oath.rs" and "crates\universal-device-sdk\src\providers\oath\mod.rs"
  --> crates\universal-device-sdk\src\providers\mod.rs:26:1
   |
26 | mod oath;
   | ^^^^^^^^^
   |
   = help: delete or rename one of them to remove the ambiguity

For more information about this error, try `rustc --explain E0761`.
error: could not compile `universal-device-sdk` (lib) due to 1 previous error
warning: build failed, waiting for other jobs to finish...
error: could not compile `universal-device-sdk` (lib test) due to 1 previous error
exit=101 duration_s=3.2
```

#### `fmt` - FAIL (exit 1, 1.5s)

```
$ cargo fmt --all -- --check
Error writing files: failed to resolve mod `oath`: file for module found at both "\\\\?\\E:\\projetos\\fido\\crates\\universal-device-sdk\\src\\providers\\oath.rs" and "\\\\?\\E:\\projetos\\fido\\crates\\universal-device-sdk\\src\\providers\\oath\\mod.rs"
exit=1 duration_s=1.5
```

#### `deny` - PASS (exit 0, 17.2s)

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
exit=0 duration_s=17.2
```

#### `dep-track` - FAIL (exit 2, 0.3s)

```
$ C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe tools/dep_track.py --check
wrote reports/refactoring/dep-track.json (261 files, 23 gods)
NEW god-files (score>25, not in allowlist):
  27.40 crates/universal-device-sdk/src/providers/oath.rs (lines=40 fan_in=33 fan_out=7)
exit=2 duration_s=0.3
```

#### `docs` - PASS (exit 0, 0.7s)

```
STYLE-HINT: docs\evaluation\EVALUATION.md:178 (38 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:213 (44 words)
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
exit=0 duration_s=0.2
REPORTS-SCAN: links checked=1 broken=0
```

#### `scripts` - PASS (exit 0, 8.6s)

```
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\pipeline.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.3
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\qemu-s3.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\select-capability.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\sync-master.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\test-all.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
```

#### `test-release` - FAIL (exit 101, 26.8s)

```
error[E0761]: file for module `oath` found at both "crates\universal-device-sdk\src\providers\oath.rs" and "crates\universal-device-sdk\src\providers\oath\mod.rs"
  --> crates\universal-device-sdk\src\providers\mod.rs:26:1
   |
26 | mod oath;
   | ^^^^^^^^^
   |
   = help: delete or rename one of them to remove the ambiguity

   Compiling aegis-fido-firmware v1.0.0 (E:\projetos\fido\crates\aegis-fido-firmware)
   Compiling aegis-fido-core v1.0.0 (E:\projetos\fido\crates\aegis-fido-core)
For more information about this error, try `rustc --explain E0761`.
error: could not compile `universal-device-sdk` (lib) due to 1 previous error
warning: build failed, waiting for other jobs to finish...
error: could not compile `universal-device-sdk` (lib test) due to 1 previous error
exit=101 duration_s=26.8
```

## Run 2026-11-04T00:36:54Z (release=on, selector=all)

| leg | advisory | status | exit | duration_s | notes |
| --- | --- | --- | --- | --- | --- |
| test-debug | no | FAIL | 101 | 3.5 |  |
| test-firmware-features | no | FAIL | 101 | 4.9 |  |
| clippy | no | FAIL | 101 | 3.5 |  |
| fmt | yes | FAIL | 1 | 1.8 |  |
| deny | no | PASS | 0 | 28.7 |  |
| dep-track | no | FAIL | 2 | 0.8 |  |
| docs | no | PASS | 0 | 0.5 | reports-scan checked=1 broken=0 |
| scripts | no | PASS | 0 | 14.7 |  |
| test-release | no | FAIL | 101 | 52.2 |  |

### Tails (last 15 lines per leg)

#### `test-debug` - FAIL (exit 101, 3.5s)

```
$ cargo test --workspace
   Compiling universal-device-sdk v1.0.0 (E:\projetos\fido\crates\universal-device-sdk)
error[E0761]: file for module `oath` found at both "crates\universal-device-sdk\src\providers\oath.rs" and "crates\universal-device-sdk\src\providers\oath\mod.rs"
  --> crates\universal-device-sdk\src\providers\mod.rs:26:1
   |
26 | mod oath;
   | ^^^^^^^^^
   |
   = help: delete or rename one of them to remove the ambiguity

For more information about this error, try `rustc --explain E0761`.
error: could not compile `universal-device-sdk` (lib test) due to 1 previous error
exit=101 duration_s=3.5
```

#### `test-firmware-features` - FAIL (exit 101, 4.9s)

```
   ::: crates\aegis-fido-firmware\src\proximity.rs:249:5
    |
249 |     fn storage() -> SecureStorage<MockFlashBackend> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ `crate::proximity::rolling_tests::storage`: not accessible
    |
   ::: crates\aegis-fido-firmware\src\time_sync.rs:352:5
    |
352 |     fn storage() -> SecureStorage<MockFlashBackend> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ `crate::time_sync::tests::storage`: not accessible

For more information about this error, try `rustc --explain E0425`.
error: could not compile `aegis-fido-firmware` (lib) due to 1 previous error
warning: build failed, waiting for other jobs to finish...
error: could not compile `aegis-fido-firmware` (lib test) due to 1 previous error
exit=101 duration_s=4.9
```

#### `clippy` - FAIL (exit 101, 3.5s)

```
$ cargo clippy --workspace --all-targets -- -D warnings
    Checking universal-device-sdk v1.0.0 (E:\projetos\fido\crates\universal-device-sdk)
error[E0761]: file for module `oath` found at both "crates\universal-device-sdk\src\providers\oath.rs" and "crates\universal-device-sdk\src\providers\oath\mod.rs"
  --> crates\universal-device-sdk\src\providers\mod.rs:26:1
   |
26 | mod oath;
   | ^^^^^^^^^
   |
   = help: delete or rename one of them to remove the ambiguity

For more information about this error, try `rustc --explain E0761`.
error: could not compile `universal-device-sdk` (lib) due to 1 previous error
warning: build failed, waiting for other jobs to finish...
error: could not compile `universal-device-sdk` (lib test) due to 1 previous error
exit=101 duration_s=3.5
```

#### `fmt` - FAIL (exit 1, 1.8s)

```
[0m         assert_eq!(st, OTA_STATUS_OK);
         assert!(consumed);
         assert_eq!(body, OTA_NEXT.to_be_bytes().to_vec());
Diff in \\?\E:\projetos\fido\crates\aegis-fido-firmware\src\run\run_loop_freertos.rs:345:
     // `ota_efuse_mgr` vive no loop p/ o gate provisionado por pacote (legado);
     // versao corrente 1 == `run::FIRMWARE_VERSION` (u32 monotonia OTA).
     #[cfg(target_os = "espidf")]
[31m-    let ota_efuse_mgr =
[0m[31m-        crate::efuse::EfuseManager::new(crate::efuse::RamEfuseStorage::new());
[0m[32m+    let ota_efuse_mgr = crate::efuse::EfuseManager::new(crate::efuse::RamEfuseStorage::new());
[0m     #[cfg(target_os = "espidf")]
     let mut ota_state = crate::ota::OtaState::new(1);
     #[cfg(target_os = "espidf")]
Error writing files: failed to resolve mod `oath`: file for module found at both "\\\\?\\E:\\projetos\\fido\\crates\\universal-device-sdk\\src\\providers\\oath.rs" and "\\\\?\\E:\\projetos\\fido\\crates\\universal-device-sdk\\src\\providers\\oath\\mod.rs"
exit=1 duration_s=1.8
```

#### `deny` - PASS (exit 0, 28.7s)

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
exit=0 duration_s=28.7
```

#### `dep-track` - FAIL (exit 2, 0.8s)

```
$ C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe tools/dep_track.py --check
wrote reports/refactoring/dep-track.json (261 files, 23 gods)
NEW god-files (score>25, not in allowlist):
  27.40 crates/universal-device-sdk/src/providers/oath.rs (lines=40 fan_in=33 fan_out=7)
exit=2 duration_s=0.8
```

#### `docs` - PASS (exit 0, 0.5s)

```
STYLE-HINT: docs\evaluation\EVALUATION.md:178 (38 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:213 (44 words)
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
exit=0 duration_s=0.2
REPORTS-SCAN: links checked=1 broken=0
```

#### `scripts` - PASS (exit 0, 14.7s)

```
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\pipeline.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\qemu-s3.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\select-capability.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\sync-master.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\test-all.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
```

#### `test-release` - FAIL (exit 101, 52.2s)

```
   Compiling aegis-fido-core v1.0.0 (E:\projetos\fido\crates\aegis-fido-core)
   Compiling aegis-fido-firmware v1.0.0 (E:\projetos\fido\crates\aegis-fido-firmware)
error[E0761]: file for module `oath` found at both "crates\universal-device-sdk\src\providers\oath.rs" and "crates\universal-device-sdk\src\providers\oath\mod.rs"
  --> crates\universal-device-sdk\src\providers\mod.rs:26:1
   |
26 | mod oath;
   | ^^^^^^^^^
   |
   = help: delete or rename one of them to remove the ambiguity

For more information about this error, try `rustc --explain E0761`.
error: could not compile `universal-device-sdk` (lib) due to 1 previous error
warning: build failed, waiting for other jobs to finish...
error: could not compile `universal-device-sdk` (lib test) due to 1 previous error
exit=101 duration_s=52.2
```

## Run 2026-11-04T00:42:26Z (release=on, selector=all)

| leg | advisory | status | exit | duration_s | notes |
| --- | --- | --- | --- | --- | --- |
| test-debug | no | PASS | 0 | 28.1 |  |
| test-firmware-features | no | PASS | 0 | 16.8 |  |
| clippy | no | PASS | 0 | 4.4 |  |
| fmt | yes | PASS | 0 | 1.4 |  |
| deny | no | PASS | 0 | 4.6 |  |
| dep-track | no | PASS | 0 | 0.4 |  |
| docs | no | PASS | 0 | 0.5 | reports-scan checked=1 broken=0 |
| scripts | no | PASS | 0 | 11.4 |  |
| test-release | no | PASS | 0 | 44.3 |  |

### Tails (last 15 lines per leg)

#### `test-debug` - PASS (exit 0, 28.1s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=28.1
```

#### `test-firmware-features` - PASS (exit 0, 16.8s)

```
     Running tests\secure_guard_integration.rs (C:/t\debug\deps\secure_guard_integration-eb5fb21692977e35.exe)

running 2 tests
test test_secure_guard_full_lifecycle_and_enforcement ... ok
test test_five_failures_trigger_scoped_wipe_preserving_fido2 ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

   Doc-tests aegis_fido_firmware

running 1 test
test crates\aegis-fido-firmware\src\freertos.rs - freertos (line 57) ... ignored

test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=16.8
```

#### `clippy` - PASS (exit 0, 4.4s)

```
$ cargo clippy --workspace --all-targets -- -D warnings
    Checking universal-device-sdk v1.0.0 (E:\projetos\fido\crates\universal-device-sdk)
   Compiling aegis-fido-firmware v1.0.0 (E:\projetos\fido\crates\aegis-fido-firmware)
    Checking uniffi-bridge v1.0.0 (E:\projetos\fido\crates\uniffi-bridge)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.11s
exit=0 duration_s=4.4
```

#### `fmt` - PASS (exit 0, 1.4s)

```
$ cargo fmt --all -- --check
(no output)
exit=0 duration_s=1.4
```

#### `deny` - PASS (exit 0, 4.6s)

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
exit=0 duration_s=4.6
```

#### `dep-track` - PASS (exit 0, 0.4s)

```
$ C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe tools/dep_track.py --check
wrote reports/refactoring/dep-track.json (260 files, 22 gods)
check ok: no new god-files beyond 24 allowlisted
exit=0 duration_s=0.4
```

#### `docs` - PASS (exit 0, 0.5s)

```
STYLE-HINT: docs\evaluation\EVALUATION.md:178 (38 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:213 (44 words)
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
exit=0 duration_s=0.1
REPORTS-SCAN: links checked=1 broken=0
```

#### `scripts` - PASS (exit 0, 11.4s)

```
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\pipeline.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\qemu-s3.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\select-capability.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\sync-master.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\test-all.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
```

#### `test-release` - PASS (exit 0, 44.3s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=44.3
```

## Run 2026-11-04T03:00:54Z (release=on, selector=all)

| leg | advisory | status | exit | duration_s | notes |
| --- | --- | --- | --- | --- | --- |
| test-debug | no | PASS | 0 | 25.4 |  |
| test-firmware-features | no | PASS | 0 | 16.9 |  |
| clippy | no | PASS | 0 | 9.7 |  |
| fmt | yes | FAIL | 1 | 1.4 |  |
| deny | no | PASS | 0 | 9.5 |  |
| dep-track | no | FAIL | 2 | 0.4 |  |
| docs | no | PASS | 0 | 0.2 | reports-scan checked=1 broken=0 |
| scripts | no | PASS | 0 | 10.2 |  |
| test-release | no | PASS | 0 | 38.1 |  |

### Tails (last 15 lines per leg)

#### `test-debug` - PASS (exit 0, 25.4s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=25.4
```

#### `test-firmware-features` - PASS (exit 0, 16.9s)

```
     Running tests\secure_guard_integration.rs (C:/t\debug\deps\secure_guard_integration-eb5fb21692977e35.exe)

running 2 tests
test test_secure_guard_full_lifecycle_and_enforcement ... ok
test test_five_failures_trigger_scoped_wipe_preserving_fido2 ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

   Doc-tests aegis_fido_firmware

running 1 test
test crates\aegis-fido-firmware\src\freertos.rs - freertos (line 57) ... ignored

test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=16.9
```

#### `clippy` - PASS (exit 0, 9.7s)

```
$ cargo clippy --workspace --all-targets -- -D warnings
    Checking aegis-fido-core v1.0.0 (E:\projetos\fido\crates\aegis-fido-core)
   Compiling aegis-fido-firmware v1.0.0 (E:\projetos\fido\crates\aegis-fido-firmware)
    Checking uniffi-bridge v1.0.0 (E:\projetos\fido\crates\uniffi-bridge)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 9.45s
exit=0 duration_s=9.7
```

#### `fmt` - FAIL (exit 1, 1.4s)

```
[0m /// Re-export da op explicita de bancada (gated `test-mode`; release = `None`).
 #[cfg(feature = "test-mode")]
 pub use crate::secure_guard_exec::bench::dispatch_serial_bench_line;
Diff in \\?\E:\projetos\fido\crates\aegis-fido-firmware\src\serial_ctaphid.rs:303:
 #[cfg(not(feature = "test-mode"))]
 pub use crate::secure_guard_exec::bench::dispatch_serial_bench_line;
[32m+#[cfg(feature = "test-mode")]
[0m[32m+pub use crate::serial_text::dispatch_serial_pairing_line;
[0m[32m+#[cfg(not(feature = "test-mode"))]
[0m[32m+pub use crate::serial_text::dispatch_serial_pairing_line;
[0m[32m+pub use crate::serial_text::dispatch_serial_text_line;
[0m 
 pub use crate::serial_vendor::{
     dispatch_serial_bind_mgmt, dispatch_serial_rescue, dispatch_serial_vendor,
exit=1 duration_s=1.4
```

#### `deny` - PASS (exit 0, 9.5s)

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
exit=0 duration_s=9.5
```

#### `dep-track` - FAIL (exit 2, 0.4s)

```
$ C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe tools/dep_track.py --check
wrote reports/refactoring/dep-track.json (262 files, 23 gods)
NEW god-files (score>25, not in allowlist):
  30.88 crates/aegis-fido-firmware/src/secure_guard_exec/bench.rs (lines=388 fan_in=0 fan_out=18)
exit=2 duration_s=0.4
```

#### `docs` - PASS (exit 0, 0.2s)

```
STYLE-HINT: docs\evaluation\EVALUATION.md:178 (38 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:213 (44 words)
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
exit=0 duration_s=0.1
REPORTS-SCAN: links checked=1 broken=0
```

#### `scripts` - PASS (exit 0, 10.2s)

```
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\pipeline.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\qemu-s3.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\select-capability.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\sync-master.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\test-all.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
```

#### `test-release` - PASS (exit 0, 38.1s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=38.1
```

## Run 2026-11-04T03:05:48Z (release=on, selector=all)

| leg | advisory | status | exit | duration_s | notes |
| --- | --- | --- | --- | --- | --- |
| test-debug | no | PASS | 0 | 10.5 |  |
| test-firmware-features | no | PASS | 0 | 15.3 |  |
| clippy | no | PASS | 0 | 3.7 |  |
| fmt | yes | PASS | 0 | 1.1 |  |
| deny | no | PASS | 0 | 2.2 |  |
| dep-track | no | PASS | 0 | 0.3 |  |
| docs | no | PASS | 0 | 0.4 | reports-scan checked=1 broken=0 |
| scripts | no | PASS | 0 | 10.0 |  |
| test-release | no | PASS | 0 | 38.9 |  |

### Tails (last 15 lines per leg)

#### `test-debug` - PASS (exit 0, 10.5s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=10.5
```

#### `test-firmware-features` - PASS (exit 0, 15.3s)

```
     Running tests\secure_guard_integration.rs (C:/t\debug\deps\secure_guard_integration-eb5fb21692977e35.exe)

running 2 tests
test test_secure_guard_full_lifecycle_and_enforcement ... ok
test test_five_failures_trigger_scoped_wipe_preserving_fido2 ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_fido_firmware

running 1 test
test crates\aegis-fido-firmware\src\freertos.rs - freertos (line 57) ... ignored

test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=15.3
```

#### `clippy` - PASS (exit 0, 3.7s)

```
$ cargo clippy --workspace --all-targets -- -D warnings
   Compiling aegis-fido-firmware v1.0.0 (E:\projetos\fido\crates\aegis-fido-firmware)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.37s
exit=0 duration_s=3.7
```

#### `fmt` - PASS (exit 0, 1.1s)

```
$ cargo fmt --all -- --check
(no output)
exit=0 duration_s=1.1
```

#### `deny` - PASS (exit 0, 2.2s)

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
exit=0 duration_s=2.2
```

#### `dep-track` - PASS (exit 0, 0.3s)

```
$ C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe tools/dep_track.py --check
wrote reports/refactoring/dep-track.json (265 files, 22 gods)
check ok: no new god-files beyond 24 allowlisted
exit=0 duration_s=0.3
```

#### `docs` - PASS (exit 0, 0.4s)

```
STYLE-HINT: docs\evaluation\EVALUATION.md:178 (38 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:213 (44 words)
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
exit=0 duration_s=0.1
REPORTS-SCAN: links checked=1 broken=0
```

#### `scripts` - PASS (exit 0, 10.0s)

```
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\pipeline.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\qemu-s3.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\select-capability.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\sync-master.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\test-all.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
```

#### `test-release` - PASS (exit 0, 38.9s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=38.9
```

## Run 2026-11-04T10:27:22Z (release=on, selector=all)

| leg | advisory | status | exit | duration_s | notes |
| --- | --- | --- | --- | --- | --- |
| test-debug | no | PASS | 0 | 47.1 |  |
| test-firmware-features | no | PASS | 0 | 25.2 |  |
| clippy | no | PASS | 0 | 6.1 |  |
| fmt | yes | FAIL | 1 | 1.4 |  |
| deny | no | PASS | 0 | 20.9 |  |
| dep-track | no | PASS | 0 | 0.3 |  |
| docs | no | PASS | 0 | 1.0 | reports-scan checked=1 broken=0 |
| scripts | no | PASS | 0 | 10.6 |  |
| test-release | no | PASS | 0 | 50.4 |  |

### Tails (last 15 lines per leg)

#### `test-debug` - PASS (exit 0, 47.1s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=47.1
```

#### `test-firmware-features` - PASS (exit 0, 25.2s)

```
     Running tests\secure_guard_integration.rs (C:/t\debug\deps\secure_guard_integration-eb5fb21692977e35.exe)

running 2 tests
test test_secure_guard_full_lifecycle_and_enforcement ... ok
test test_five_failures_trigger_scoped_wipe_preserving_fido2 ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_fido_firmware

running 1 test
test crates\aegis-fido-firmware\src\freertos.rs - freertos (line 57) ... ignored

test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=25.2
```

#### `clippy` - PASS (exit 0, 6.1s)

```
$ cargo clippy --workspace --all-targets -- -D warnings
    Checking aegis-fido-usb v1.0.0 (E:\projetos\fido\crates\aegis-fido-usb)
   Compiling aegis-fido-firmware v1.0.0 (E:\projetos\fido\crates\aegis-fido-firmware)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.81s
exit=0 duration_s=6.1
```

#### `fmt` - FAIL (exit 1, 1.4s)

```
[0m[32m+    let val: ciborium::value::Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
[0m     if let ciborium::value::Value::Map(entries) = val {
         let got = entries.iter().find_map(|(k, v)| {
             if matches!(k, ciborium::value::Value::Text(s) if s == "bench_active") {
Diff in \\?\E:\projetos\fido\crates\aegis-fido-firmware\src\secure_guard_exec\bench\tests.rs:376:
     assert!(super::policy::is_bench_active());
     let (st, body) = crate::secure_guard_exec::status::handle_status(&mut engine, 3_000);
     assert_eq!(st, 0x00);
[31m-    let val: ciborium::value::Value =
[0m[31m-        ciborium::from_reader(body.as_slice()).expect("cbor parse");
[0m[32m+    let val: ciborium::value::Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
[0m     if let ciborium::value::Value::Map(entries) = val {
         let got = entries.iter().find_map(|(k, v)| {
             if matches!(k, ciborium::value::Value::Text(s) if s == "bench_active") {
exit=1 duration_s=1.4
```

#### `deny` - PASS (exit 0, 20.9s)

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
exit=0 duration_s=20.9
```

#### `dep-track` - PASS (exit 0, 0.3s)

```
$ C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe tools/dep_track.py --check
wrote reports/refactoring/dep-track.json (265 files, 22 gods)
check ok: no new god-files beyond 24 allowlisted
exit=0 duration_s=0.3
```

#### `docs` - PASS (exit 0, 1.0s)

```
STYLE-HINT: docs\evaluation\EVALUATION.md:178 (38 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:213 (44 words)
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
exit=0 duration_s=0.2
REPORTS-SCAN: links checked=1 broken=0
```

#### `scripts` - PASS (exit 0, 10.6s)

```
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\pipeline.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\qemu-s3.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\select-capability.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\sync-master.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\test-all.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.8
```

#### `test-release` - PASS (exit 0, 50.4s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=50.4
```

## Run 2026-11-04T11:14:53Z (release=on, selector=all)

| leg | advisory | status | exit | duration_s | notes |
| --- | --- | --- | --- | --- | --- |
| test-debug | no | PASS | 0 | 13.5 |  |
| test-firmware-features | no | PASS | 0 | 30.1 |  |
| clippy | no | PASS | 0 | 2.6 |  |
| fmt | yes | PASS | 0 | 1.2 |  |
| deny | no | PASS | 0 | 2.9 |  |
| dep-track | no | PASS | 0 | 0.4 |  |
| docs | no | PASS | 0 | 0.4 | reports-scan checked=1 broken=0 |
| scripts | no | PASS | 0 | 11.0 |  |
| test-release | no | PASS | 0 | 47.7 |  |

### Tails (last 15 lines per leg)

#### `test-debug` - PASS (exit 0, 13.5s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=13.5
```

#### `test-firmware-features` - PASS (exit 0, 30.1s)

```
     Running tests\secure_guard_integration.rs (C:/t\debug\deps\secure_guard_integration-eb5fb21692977e35.exe)

running 2 tests
test test_secure_guard_full_lifecycle_and_enforcement ... ok
test test_five_failures_trigger_scoped_wipe_preserving_fido2 ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_fido_firmware

running 1 test
test crates\aegis-fido-firmware\src\freertos.rs - freertos (line 57) ... ignored

test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=30.1
```

#### `clippy` - PASS (exit 0, 2.6s)

```
$ cargo clippy --workspace --all-targets -- -D warnings
    Checking aegis-fido-core v1.0.0 (E:\projetos\fido\crates\aegis-fido-core)
    Checking uniffi-bridge v1.0.0 (E:\projetos\fido\crates\uniffi-bridge)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.37s
exit=0 duration_s=2.6
```

#### `fmt` - PASS (exit 0, 1.2s)

```
$ cargo fmt --all -- --check
(no output)
exit=0 duration_s=1.2
```

#### `deny` - PASS (exit 0, 2.9s)

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
exit=0 duration_s=2.9
```

#### `dep-track` - PASS (exit 0, 0.4s)

```
$ C:\Users\junior\AppData\Local\Programs\Python\Python312\python.exe tools/dep_track.py --check
wrote reports/refactoring/dep-track.json (265 files, 22 gods)
check ok: no new god-files beyond 24 allowlisted
exit=0 duration_s=0.4
```

#### `docs` - PASS (exit 0, 0.4s)

```
STYLE-HINT: docs\evaluation\EVALUATION.md:178 (38 words)
STYLE-HINT: docs\evaluation\EVALUATION.md:213 (44 words)
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
exit=0 duration_s=0.1
REPORTS-SCAN: links checked=1 broken=0
```

#### `scripts` - PASS (exit 0, 11.0s)

```
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\pipeline.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\qemu-s3.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\select-capability.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\sync-master.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.5
$ C:\Program Files\PowerShell\7\pwsh.EXE -NoProfile -Command $tokens=$null; $errs=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile('E:\projetos\fido\scripts\test-all.ps1',[ref]$tokens,[ref]$errs); if ($errs.Count -gt 0) { $errs | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'SYNTAX-OK'; exit 0 }
SYNTAX-OK
exit=0 duration_s=0.4
```

#### `test-release` - PASS (exit 0, 47.7s)

```

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aegis_bridge

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests universal_device_sdk

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0 duration_s=47.7
```

