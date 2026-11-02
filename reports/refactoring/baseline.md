# Baseline — Standalone Architecture Cleanup

> Status: metadata pass. fmt / check / tests as recorded below. Mark UNVERIFIED/BLOCKED honestly.

## Git state
- HEAD 30680ff
- orig branch fd/finalizacao-linux ahead 25
- worktree branch refactor/standalone-architecture-cleanup clean
- original has 1 modified file app-android/app/build.gradle.kts NOT in worktree
- stash freertos-wip untouched

## Quality gates (baseline)
- metadata: pass
- fmt: fail — 28 files pre-existing
- check: pass, 0 warnings
- binaries: 17
- tests: 1018 total (648 passed / 1 failed pre-existing freertos_sched ticks>=1), host-only
- clippy: pass

## Scope of this report batch
- ONLY reports/refactoring/* files (10 files)
- Do NOT touch crates/, tools/, app-*, reports/compliance/, reports/testing/
- dependency-graph-after.json: same, zero moves
- moved-files.md: NONE
- migration-plan.json: KEEP + 3 PROPOSED (no moves executed)
