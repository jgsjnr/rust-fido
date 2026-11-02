# ESP-IDF Windows Cleanup -- host record (NO removal performed)

- Worktree: `E:\projetos\standalone-architecture-worktree`
- Branch: `refactor/standalone-architecture-cleanup`
- HEAD: `d6dfbbe` (this report committed on top; see return SHA)
- Date (UTC): 2026-11-02
- Mode: record only. **NO removal performed. NO uninstall performed.**
  (a) migration RED at sys-bindgen vs esp_tinyusb v2 (no released fix) and
  (b) product shims now v2-clean but unlinked -> removal NOT executed.
  Never uninstall ESP-IDF on parent instruction.

## Host state (observed, not modified)

| Slot | Location | State | Evidence |
| ---- | -------- | ----- | -------- |
| Pinned v5.3.1 | `C:\.embuild\espressif\esp-idf\v5.3.1` | Present, INACTIVE (superseded in repo config, still on disk) | directory present; legacy venv `idf5.3_py3.12_env`; constraints `espidf.constraints.v5.3.txt`; old dist zips + old extracted tool versions (cmake 3.24.0, ninja 1.11.1, xtensa 13.2.0, rom-elfs 20240305, esp-clang 16.0.1) |
| Adopted v6.0.3 | `C:\esp\v6.0.3\esp-idf` | Present, ACTIVE via EIM | `IDF_PATH` in environment; `eim_idf.json` at `C:\Espressif\tools\eim_idf.json`; venv `C:\Espressif\tools\python\v6.0.3\venv`; tools `C:\Espressif\tools` (cmake 4.0.3, xtensa 15.2.0, rom-elfs 20260528, clang 20.1.1; ninja via Strawberry PATH); managed storage has `esp_tinyusb 2.4.0`, `tinyusb 0.19/0.21`, `usb 1.6.0` |
| v6.1 | absent | NOT INSTALLED | no `C:\esp\v6.1*`, no embuild v6.1 slot |
| Stray embuild v6.0 venv | `C:\.embuild\espressif\python_env\idf6.0_py3.12_env` | Present, purpose unknown (predates this lane; build uses EIM venv) | left untouched; parent decides |
| VS Code extension slot | `C:\Users\junior\esp\v5.5.1` + `C:\Users\junior\.espressif` | v5.5.1 dir ABSENT (stale pointer), `.espressif` present | user settings point at nonexistent v5.5.1 path (see below); NOT fixed (fix was GREEN-gated) |

## Removal: NOT executed (migration RED)

The owner-authorized legacy removal (delete v5.3.1 checkout + idf5.3 venv +
v5.3-only caches, clean env/PATH/VS Code pointer, set persistent v6.0.3 env,
re-verify) was gated on GREEN. The build is RED at a third-party bindgen gap
(`esp-idf-sys 0.38.1` vs managed v2 headers; our shims compile clean), so per
the directive NO host deletion, NO env change, and NO VS Code edit were
performed. Deletion candidates (for the post-GREEN follow-up): v5.3.1 checkout,
idf5.3 venv, `espidf.constraints.v5.3.txt`, old-version dist zips + old
extracted tool dirs. Keep: everything v6.0 needs (EIM install, venv, tools,
managed-component storage) + the stray embuild idf6.0 venv until parent rules.

## Compat note (validated to bindgen boundary)

- Firmware pins `esp-idf-sys 0.38.1` / `hal 0.47.0` / `svc 0.53.0` / `embuild 0.33.7`
  (lock) in manifest + `Cargo.lock`.
- Toolchain + manager + sdkconfig + product C shims proven: full IDF C tree
  (1236 objects incl. `aegis_usb`, `aegis_ble`, `aegis_wifi` against v2 TinyUSB)
  configures and compiles; only sys bindgen fails (v1-only headers).
- v6.0.3 compat: RED at third-party bindgen, BLOCKED pending sys release with
  the unreleased v2-bindings fix (or sanctioned patch path).
- v6.1 target: absent from host, UNVALIDATED, BLOCKED (see companion report).

## Stale pointers (recorded, not changed)

- VS Code user settings (`%APPDATA%\Code\User\settings.json`) still point at the
  nonexistent `C:\Users\junior\esp\v5.5.1\esp-idf` (`idf.espIdfPathWin`; tools at
  `C:\Users\junior\.espressif`). Fix (backup first, repoint at
  `C:\esp\v6.0.3\esp-idf`) stays GREEN-gated.
- Persistent env already clean: Machine `IDF_PATH=C:\esp\v6.0.3\esp-idf`;
  no stale `.embuild`/`Espressif` entries in User/Machine PATH (only Strawberry,
  which supplies `ninja.exe`). No changes made.
- Repo live v5.3.1 refs remain in UNOWNED scripts (`bench-freertos.ps1`,
  `qemu-s3.ps1`, `linux-bringup.sh`); owned files keep only commented fallbacks.
- `components_esp32s3.lock` (repo root, untracked): pins managed 2.4.0/0.21.0`2.
  Post-GREEN follow-up decides: commit it or gitignore it.

## What was NOT done (explicit)

- NO ESP-IDF version installed, uninstalled, activated, or deactivated.
- NO environment variables changed (persistent or shell-global).
- NO VS Code settings created, modified, or deleted.
- NO host files or directories deleted.
- NO firmware manifest/lockfile entries changed in this step (changed only as
  minimal enablers: embuild lock bump for the bindgen-flags fix).

## Next steps (require parent routing + GREEN build)

1. After the sys v2-bindings fix lands and `cargo +esp check` goes green,
   release-build + ELF-verify, then execute the authorized removal exactly as
   scoped above, and re-verify (fresh-shell `idf.py --version`, xtensa check,
   repo grep for v5.3.1 refs).
2. Only then, with written parent approval stating the reason, remove the
   superseded slot. Until then: BLOCKED.