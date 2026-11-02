# ESP-IDF Migration Report -- reverted: pinned v5.3.1 kept (v6.0.3 blocked upstream)

- Worktree: `E:\projetos\standalone-architecture-worktree`
- Branch: `refactor/standalone-architecture-cleanup`
- HEAD: `f136e48` (this report committed on top; see return SHA)
- Date (UTC): 2026-11-02
- Mode: owner-ordered revert. The v6.0.3 attempt (sys 0.38/hal 0.47/svc 0.53)
  is rolled back to the proven-green v5.3.1 line and re-verified green.
  No flash/hardware. No product `.rs` touched.

## Revert method per file (exact pre-migration bytes restored)

Base: `89e0bd0` (last state before the migration lane; verified to contain only
this lane's changes since -- no other lane touched these paths).
Method: `git checkout 89e0bd0 -- <paths>` (no hand-editing).

| File | Method | Result |
| ---- | ------ | ------ |
| `.cargo/config.toml` | checkout | `IDF_PATH=C:\.embuild\espressif\esp-idf\v5.3.1`, `ESP_IDF_VERSION=v5.3.1`; EIM block + `IDF_PYTHON_ENV_PATH` gone |
| `Cargo.lock` | checkout | sys 0.36.1 / hal 0.45.2 / svc 0.50.1 / embuild 0.33.5 |
| `crates/aegis-fido-firmware/Cargo.toml` | checkout | sys `0.36`, svc `0.50`, hal `0.45`; manager `false`; remote component entry gone |
| `components/aegis_usb/CMakeLists.txt` | checkout | v1 triple `PRIV_REQUIRES espressif__esp_tinyusb tinyusb usb` |
| `components/aegis_usb/aegis_usb.c` | checkout | v1 `tinyusb_config_t` flat fields, no `tinyusb_default_config.h` |
| `components/aegis_usb/ccid_device.c` | checkout | 4-arg `usbd_edpt_xfer` |
| `scripts/common.ps1`, `scripts/env-check.ps1` | checkout | version strings back to `C:\.embuild` v5.3.1 (EIM block gone) |
| `sdkconfig.defaults.esp32s3` | checkout | header pin back to IDF v5.3.1 |
| `components_esp32s3.lock` | deleted (was untracked) | v5 + manager-off needs no manager lock |
| This report + cleanup report | rewritten (not restored) | history preserved below |

## Proof results: v5.3.1 GREEN (shell-local .embuild env, no global changes)

- `idf.py --version` -> `ESP-IDF v5.3.1`, exit 0 (venv
  `C:\.embuild\espressif\python_env\idf5.3_py3.12_env`, era tools cmake 3.24.0 /
  ninja 1.11.1 / xtensa 13.2.0 / rom-elfs 20240305).
- `cargo +esp check -p aegis-fido-firmware --target xtensa-esp32s3-espidf
  --no-default-features --features board-devkitc -Zbuild-std=std,panic_abort`:
  exit 0.
- `cargo +esp build` (same target/features, `--release`): exit 0.
- ELF `C:/t/xtensa-esp32s3-espidf/release/aegis-fido-firmware`: freshly linked
  (2026-11-02 14:48:05, 1985384 B), magic `7f454c46`, `e_machine 0x5E`
  (Xtensa), embeds `v5.3.1` marker, no `v6.0.3` marker.
- Host `cargo test --workspace`: exit 0 (unaffected by the revert).
- Checkout-copy sanity: `C:\.embuild\...\v5.3.1\components\aegis_usb` holds v1
  code (never polluted by v2 shims) -- no re-sync needed.

## v6.0.3 status: BLOCKED upstream (attempt preserved in history)

- Commits `dbc292d` (migration attempt) and `3378633` (v2 shims + bindgen
  diagnosis) remain in history; nothing was rewritten.
- Blocker: `esp-idf-sys 0.38.1` `bindings.h:876-891` includes v1-only
  `tinyusb_types.h` + `tusb_tasks.h`; managed `esp_tinyusb 2.4.0` ships neither.
  Upstream fix is unreleased (crates.io latest still 0.38.1). Our shims are
  v2-clean and compile; full IDF C tree builds under v6.0.3.
- Retry trigger: sys release with the v2-bindings fix (warm v6 cache in `C:/t`
  + EIM install intact). Then re-apply the documented v6 config on top of
  this green base.

## Removal: CANCELLED per owner order

- Both installs stay: `C:\.embuild\...v5.3.1` (pinned, verified) and
  `C:\esp\v6.0.3` (EIM, available for future retry). No host deletion, no env
  or VS Code changes performed in this lane.
- v5.3.1 references restored in all owned files; live refs in UNOWNED scripts
  (`bench-freertos.ps1`, `qemu-s3.ps1`, `linux-bringup.sh`) were never changed
  (ownership) and match the pinned line again.

## Next steps

1. Stay on v5.3.1 until the upstream sys v2-bindings release lands.
2. Retry = re-apply v6 config (see `dbc292d`/`3378633` for the exact recipe:
   manifest bump, manager ON + remote esp_tinyusb, CMakeLists name, v2 shims,
   embuild >=0.33.6) on this green base, prove, then execute removal.
3. On-device build + flash + functional smoke on ESP32-S3 still required
   before any production claim for either line.