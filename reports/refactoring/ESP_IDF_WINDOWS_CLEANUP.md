# ESP-IDF Windows Cleanup -- host record (NO removal performed)

- Worktree: `E:\projetos\standalone-architecture-worktree`
- Branch: `refactor/standalone-architecture-cleanup`
- HEAD: `30680ff`
- Date (UTC): 2026-11-02
- Mode: record only. **NO removal performed. NO uninstall performed.**
  BLOCKED pending validation. Never uninstall ESP-IDF on parent instruction.

## Host state (observed, not modified)

| Slot | Location | State | Evidence |
| ---- | -------- | ----- | -------- |
| Pinned v5.3.1 | `C:\.embuild\espressif\esp-idf\v5.3.1` | Present, INACTIVE | directory present; `C:\.embuild` also holds `dist`, `python_env`, `tools`, constraints `v5.3` + `v6.0` |
| Active v6.0.3 | `C:\esp\v6.0.3\esp-idf` | Present, ACTIVE via EIM | `IDF_PATH=C:\esp\v6.0.3\esp-idf` in environment |
| v6.1 | absent | NOT INSTALLED | no `C:\esp\v6.1*`, no embuild v6.1 slot |

## Compat note (UNVALIDATED)

- Firmware pins `esp-idf-sys 0.36.1` / `hal 0.45.2` / `svc 0.50.1`
  (ESP-IDF v5.3.x line) in `crates/aegis-fido-firmware/Cargo.toml` + `Cargo.lock`.
- Whether `esp-idf-sys` 0.36 builds against the ACTIVE v6.0.3 toolchain is
  UNVALIDATED. Host-only lane: no ESP-IDF target build was attempted.
- v6.0.3 compat: UNVALIDATED, BLOCKED pending a trial device build.
- v6.1 target: absent from host, UNVALIDATED, BLOCKED (see companion
  `ESP_IDF_MIGRATION_REPORT.md`).

## Stale pointer (parent-noted, not changed)

- A stale VS Code ESP-IDF pointer referencing v5.5.1 was noted by the parent.
  No `.vscode/settings.json` exists in this worktree, so there is nothing to
  fix here. If the pointer lives in editor user settings or another checkout,
  it is out of scope for this lane: record only, do not retarget toolchains
  from this lane.

## What was NOT done (explicit)

- NO ESP-IDF version installed, uninstalled, activated, or deactivated.
- NO environment variables changed (`IDF_PATH` untouched).
- NO VS Code settings created, modified, or deleted.
- NO firmware manifest or lockfile entries changed.

## Next steps (require parent approval + validation)

1. Parent decides the canonical host toolchain (keep v5.3.1 pinned line,
   adopt v6.0.3, or evaluate v6.1 later). This lane makes no recommendation
   beyond recording current state.
2. Before ANY removal: successful device build + flash + functional smoke on
   the surviving toolchain, recorded with exact commands and exit codes.
3. Only then, with written parent approval stating the reason, remove the
   superseded slot. Until then: BLOCKED.
