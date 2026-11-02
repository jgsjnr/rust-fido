# ESP-IDF Windows Cleanup -- host record (NO removal performed)

- Worktree: `E:\projetos\standalone-architecture-worktree`
- Branch: `refactor/standalone-architecture-cleanup`
- HEAD: `89e0bd0`
- Date (UTC): 2026-11-02
- Mode: record only. **NO removal performed. NO uninstall performed.**
  BLOCKED (v6 migration red) -> owner-authorized legacy removal NOT executed.
  Never uninstall ESP-IDF on parent instruction.

## Host state (observed, not modified)

| Slot | Location | State | Evidence |
| ---- | -------- | ----- | -------- |
| Pinned v5.3.1 | `C:\.embuild\espressif\esp-idf\v5.3.1` | Present, INACTIVE (superseded in repo config, still on disk) | directory present; legacy venv `C:\.embuild\espressif\python_env\idf5.3_py3.12_env`; constraints `espidf.constraints.v5.3.txt`; old dist zips + old extracted tool versions (cmake 3.24.0, ninja 1.11.1, xtensa 13.2.0, rom-elfs 20240305, esp-clang 16.0.1) |
| Adopted v6.0.3 | `C:\esp\v6.0.3\esp-idf` | Present, ACTIVE via EIM | `IDF_PATH=C:\esp\v6.0.3\esp-idf` in environment; `eim_idf.json` at `C:\Espressif\tools\eim_idf.json`; venv `C:\Espressif\tools\python\v6.0.3\venv`; tools `C:\Espressif\tools` (cmake 4.0.3, xtensa 15.2.0, rom-elfs 20260528, clang 20.1.1; ninja via Strawberry PATH); managed-component storage has `esp_tinyusb 2.4.0`, `tinyusb 0.19.0`3/0.21.0`2`, `usb 1.6.0` |
| v6.1 | absent | NOT INSTALLED | no `C:\esp\v6.1*`, no embuild v6.1 slot |
| Stray embuild v6.0 venv | `C:\.embuild\espressif\python_env\idf6.0_py3.12_env` | Present, purpose unknown (predates this lane; build uses EIM venv) | left untouched; parent decides |
| VS Code extension slot | `C:\Users\junior\esp\v5.5.1` + `C:\Users\junior\.espressif` | v5.5.1 dir ABSENT (stale pointer), `.espressif` present | user settings point at nonexistent v5.5.1 path (see below); NOT fixed (fix was removal-phase-gated) |

## Removal: NOT executed (migration BLOCKED)

The owner-authorized legacy removal (delete v5.3.1 checkout + idf5.3 venv +
v5.3-only caches, clean env/PATH/VS Code pointer, set persistent v6.0.3 env,
re-verify) was gated on a GREEN migration. The migration is RED (TinyUSB
v1->v2 C-API break, see companion `ESP_IDF_MIGRATION_REPORT.md`), so per the
directive NO host deletion, NO env change, and NO VS Code edit were performed.
Deletion candidates (for the follow-up lane, after GREEN): v5.3.1 checkout,
idf5.3 venv, `espidf.constraints.v5.3.txt`, old-version dist zips + old
extracted tool dirs. Keep: everything v6.0 needs (EIM install, venv, tools,
managed-component storage) + the stray embuild idf6.0 venv until parent rules.

## Compat note (validated to C-compile boundary)

- Firmware pins `esp-idf-sys 0.38.1` / `hal 0.47.0` / `svc 0.53.0`
  (ESP-IDF v6.0 line) in `crates/aegis-fido-firmware/Cargo.toml` + `Cargo.lock`.
- Toolchain + manager + sdkconfig plumbing proven: full IDF C tree (1236
  objects) configures and compiles; only the two product C shims fail
  (TinyUSB v2 API). Rust-side bump NOT validated on-device.
- v6.0.3 compat: RED at product C-API, BLOCKED pending C-shim adaptation.
- v6.1 target: absent from host, UNVALIDATED, BLOCKED (see companion report).

## Stale pointers (recorded, not changed)

- VS Code user settings (`%APPDATA%\Code\User\settings.json`) still point at the
  nonexistent `C:\Users\junior\esp\v5.5.1\esp-idf` (`idf.espIdfPathWin`; tools at
  `C:\Users\junior\.espressif`). Fix (backup first, repoint at
  `C:\esp\v6.0.3\esp-idf`) stays gated on GREEN + explicit approval.
- Persistent env already clean: Machine `IDF_PATH=C:\esp\v6.0.3\esp-idf`;
  no stale `.embuild`/`Espressif` entries in User/Machine PATH (only Strawberry,
  which supplies `ninja.exe`). No changes made.
- Repo live v5.3.1 refs remain in UNOWNED scripts (`bench-freertos.ps1`,
  `qemu-s3.ps1`, `linux-bringup.sh`); owned files keep only commented fallbacks.

## What was NOT done (explicit)

- NO ESP-IDF version installed, uninstalled, activated, or deactivated.
- NO environment variables changed (persistent or shell-global).
- NO VS Code settings created, modified, or deleted.
- NO host files or directories deleted.
- NO firmware manifest or lockfile entries changed in this step (changed only
  during the migration attempt itself; kept, zero reverts).

## Next steps (require parent routing + GREEN build)

1. After the TinyUSB v2 C-shim fix lands and `cargo +esp check` goes green,
   execute the authorized removal exactly as scoped above, then re-verify:
   fresh-shell `idf.py --version`, xtensa check, repo grep for v5.3.1 refs.
2. Only then, with written parent approval stating the reason, remove the
   superseded slot. Until then: BLOCKED.