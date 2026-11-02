# SCRIPT_TEST_MIGRATION_REPORT

## Baseline
- metadata: pass
- fmt: fail, 28 files pre-existing
- check: pass, 0 warnings
- binaries: 17
- tests: 1018 (648 passed / 1 failed pre-existing freertos_sched ticks>=1), host-only
- clippy: pass

## Git
- HEAD 30680ff, orig branch fd/finalizacao-linux ahead 25, worktree branch refactor/standalone-architecture-cleanup clean; original has 1 modified file app-android/app/build.gradle.kts NOT in worktree; stash freertos-wip untouched.

## Migration
- Zero moves executed; dependency-graph-after.json same as before.
- KEEP + 3 PROPOSED only. moved-files.md: NONE.
- ESP-IDF v5.3.1 pinned (esp-idf-sys 0.36.1/hal 0.45.2/svc 0.50.1); v6.1 BLOCKED unvalidated; host has v5.3.1 inactive + v6.0.3 active.

## Verdict
- UNVERIFIED/BLOCKED where noted. No crate/tool/app code touched.
