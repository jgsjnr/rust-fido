# ESP-IDF Migration Report -- preservation-first (no migration executed)

- Worktree: `E:\projetos\standalone-architecture-worktree`
- Branch: `refactor/standalone-architecture-cleanup`
- HEAD: `30680ff`
- Date (UTC): 2026-11-02
- Mode: preservation-first. No migration executed. No legacy code removed.

## Pinned everywhere (v5.3.1 line)

| Artifact | Value | Evidence |
| -------- | ----- | -------- |
| `crates/aegis-fido-firmware/Cargo.toml` | `esp-idf-sys 0.36`, `esp-idf-svc 0.50`, `esp-idf-hal 0.45` | manifest lines 49-51, `[package.metadata.esp-idf-sys] esp_idf_component_manager = false` |
| `Cargo.lock` | `esp-idf-sys 0.36.1`, `esp-idf-svc 0.50.1`, `esp-idf-hal 0.45.2` | `registry+https://github.com/rust-lang/crates.io-index` |
| `reports/refactoring/esp-idf-version-inventory.md` | Pinned v5.3.1 recorded | inventory file |

The `esp-idf-sys 0.36` / `hal 0.45` / `svc 0.50` line corresponds to
ESP-IDF v5.3.x. This mapping is by upstream release correspondence, host-only
recorded, UNVERIFIED on-device in this lane.

## v6.1 target: UNVALIDATED, BLOCKED

- ESP-IDF v6.1 as a migration target is UNVALIDATED and BLOCKED.
- No v6.1 toolchain is installed on this host (see companion
  `ESP_IDF_WINDOWS_CLEANUP.md`: `C:\.embuild` v5.3.1 inactive pinned,
  `C:\esp\v6.0.3` active via EIM, v6.1 absent).
- No `esp-idf-sys` release supporting v6.1 has been validated against this
  firmware in this lane.
- Do NOT bump `esp-idf-sys` / `esp-idf-hal` / `esp-idf-svc` to any v6.1 line
  without on-device validation (build + flash + functional smoke on ESP32-S3).

## What was NOT done (explicit)

- No migration executed: manifests, lockfile, and build config unchanged.
- No legacy code removed: `run_loop_legacy.rs` (2067 lines) untouched.
- No `binstart` / component-manager settings changed.
- No ESP-IDF installation added, removed, or modified on the host.
- No on-device build, flash, or hardware test performed (host-only lane).

## Next steps (require parent approval + validation)

1. Validate the CURRENT v5.3.1 line on-device first (baseline device build).
2. Only then evaluate v6.0.3 compat (`esp-idf-sys` 0.36 against installed
   v6.0.3): UNVALIDATED, BLOCKED pending a trial device build.
3. Treat v6.1 as a separate future proposal: new toolchain install,
   dependency-line bump, full device regression, then report.
4. Keep this preservation-first stance: record, do not migrate, until asked.
