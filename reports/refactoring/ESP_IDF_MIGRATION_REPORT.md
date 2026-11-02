# ESP-IDF Migration Report -- v6.0.3 attempt BLOCKED (product C-API break)

- Worktree: `E:\projetos\standalone-architecture-worktree`
- Branch: `refactor/standalone-architecture-cleanup`
- HEAD: `89e0bd0`
- Date (UTC): 2026-11-02
- Mode: migration attempted against installed v6.0.3, BLOCKED at C compile by
  TinyUSB v1.x to v2.x API break in product C shims. No removal performed.
  No flash/hardware. No product `.rs` touched.

## Compat matrix (verified 2026-11-02, crates.io + upstream changelogs)

Minimal v6.0-capable line is `esp-idf-sys 0.38` (`0.38.0` changelog: `Basic
compatibility for ESP-IDF release 6.0`; `0.38.1` latest). No 0.37.x or earlier
supports IDF v6.0 (`0.37.0` added only v5.4/v5.5).

| Crate | v5.3.1 line (was) | v6.0.3 line (now) |
| ----- | ----------------- | ----------------- |
| `esp-idf-sys` | 0.36.1 | **0.38.1** | 0.38.0 = first v6.0-compatible |
| `esp-idf-hal` | 0.45.2 | **0.47.0** | 0.47.0 = first v6.0-compatible |
| `esp-idf-svc` | 0.50.1 | **0.53.0** | 0.53.0 = first v6.0-compatible |
| `embuild` | 0.33.5 | 0.33.5 (unchanged; satisfies sys 0.38 need `>=0.33.5`) |
| IDF toolchain | `C:\.embuild\espressif\esp-idf\v5.3.1` | `C:\esp\v6.0.3\esp-idf` via EIM (`C:\Espressif\tools`, venv `C:\Espressif\tools\python\v6.0.3\venv`) |

## Changes made (owned files only, zero product `.rs` changes)

- `crates/aegis-fido-firmware/Cargo.toml`: sys `0.36->0.38`, svc `0.50->0.53`,
  hal `0.45->0.47`; `esp_idf_component_manager false->true`; added
  `remote_component espressif/esp_tinyusb 2.*` (managed; EIM local storage:
  `C:\Espressif\tools\components\espressif\esp_tinyusb\2.4.0`, targets esp32s3).
- `Cargo.lock`: minimal `cargo update -p esp-idf-sys -p esp-idf-hal -p esp-idf-svc`
  cascade (sys 0.38.1, hal 0.47.0, svc 0.53.0 + dep closure). No blind update.
- `.cargo/config.toml`: `IDF_PATH`/`IDF_TOOLS_PATH`/`ESP_IDF_VERSION` point at the
  v6.0.3 EIM install (+`IDF_PYTHON_ENV_PATH`); v5.3.1 paths kept as commented
  fallback. Target linker/runner/rustflags and target-dir untouched.
- `scripts/common.ps1`, `scripts/env-check.ps1`: version strings point at the
  v6.0.3 EIM install; v5.3.1 paths kept as comments/fallback candidates.
- `sdkconfig.defaults.esp32s3`: header pin points at v6.0.3 (EIM path + legacy note).
- `crates/.../components/aegis_usb/CMakeLists.txt`: dropped `usb` from
  `PRIV_REQUIRES` (host stack, unused by device-only `tud_*`/`usbd_*` code;
  gone from v6.0.3 in-tree). v5 names kept as comment.

## Proof results (shell-local EIM env, no global env changes)

- `idf.py --version` -> `ESP-IDF v6.0.3`, exit 0. QUIRK: v6.0.3 `idf.py`
  component-manager crashes when `ESP_IDF_VERSION` carries a `v` prefix
  (`Version string lacks a numerical component: v6.0.3`); EIM profile sets
  unprefixed `6.0`/`6.0.3`. Repo files keep the `v6.0.3` tag for cargo
  (cargo-scoped, never reaches interactive `idf.py`).
- Host `cargo check -p aegis-fido-firmware` (host triple): exit 0.
- `cargo +esp check -p aegis-fido-firmware --target xtensa-esp32s3-espidf
  --no-default-features --features board-devkitc -Zbuild-std=std,panic_abort`:
  - Attempt 1: exit 101, cmake `Failed to resolve component
    espressif__esp_tinyusb required by component aegis_usb: unknown name.`
    (TinyUSB moved out-of-tree in v6.0; in-tree now only `esp_hal_usb`,
    `esp_usb_cdc_rom_console`, `esp_driver_usb_serial_jtag`.)
  - Fix (build-config): manager ON + `remote_component esp_tinyusb 2.*`.
    Attempt 2: exit 101, `Failed to resolve component usb: unknown name.`
    Manager had resolved `espressif/esp_tinyusb 2.4.0` +
    `espressif/tinyusb 0.21.0`2` from LOCAL EIM storage (offline) and written
    `components_esp32s3.lock` (untracked, left for follow-up to decide).
  - Fix (build-config, component names): dropped `usb` from `PRIV_REQUIRES`.
    Attempt 3: exit 101, full IDF C tree (1236 objects) compiles EXCEPT our two
    product C shims -> BLOCKED (exact errors below).
- Release build: not attempted (debug C compile already red; identical failure
  expected). No ELF produced. No flash/hardware attempted (no approval).

## BLOCKED: exact errors (product C-API break, follow-up lane)

v5.3.1 bundled esp_tinyusb 1.4.5 (has `tusb_tasks.c`); v6.0.3 resolves managed
`espressif/esp_tinyusb 2.4.0`. Our shims were written against the v1 API:

1. `aegis_usb.c` (`aegis_usb_init`, lines `300-306`): v2 `tinyusb_config_t` has
   no `device_descriptor`, `string_descriptor`, `string_descriptor_count`,
   `external_phy`, `configuration_descriptor`, `self_powered`,
   `vbus_monitor_io` (also `vbus_monitor_io = -1` int-to-pointer).
2. `ccid_device.c` (lines 94, 102, 304): `usbd_edpt_xfer` now takes 5 args
   (added `bool is_isr`); our calls pass 4.

Both require adapting product C code to the TinyUSB v2 API (a follow-up lane;
this lane owns only configs + CMakeLists component names, no product code).
Note: compile got all the way to our shims (aegis_ble/aegis_wifi objects built
OK), so names, manager, venv, toolchain, and sdkconfig plumbing are proven.

## Residual notes for follow-up

- `ESP_ROM_ELF_DIR` was unset in the proof shell -> non-fatal gdbinit warning
  (`gen_gdbinit.py`); EIM profile sets it. Add to proof env next time.
- `sdkconfig.defaults.esp32s3` under v6.0.3 reports unknown symbols: `TINYUSB*`
  (moved into managed-component Kconfig), `BTDM_CTRL_MODE_*` (S3-ignored,
  pre-existing), `SPIRAM_OCCUPY_NO_HOST`, and `BT_ALLOCATION_FROM_SPIRAM_FIRST`
  (invisible dependency). Remap against v6/managed Kconfig after C fixes.
- `components_esp32s3.lock` (repo root, untracked): pins managed 2.4.0/0.21.0`2.
  Follow-up decides: commit it (reproducible builds) or gitignore it.
- v5.3.1 references remaining: intentional commented fallbacks in owned files;
  live refs in UNOWNED scripts (`bench-freertos.ps1`, `qemu-s3.ps1`,
  `linux-bringup.sh`) still point at `C:\.embuild` v5.3.1 paths -- not touched
  (ownership). They will need retargeting once the C-API break is fixed.

## Next steps (require parent routing)

1. Follow-up lane adapts `aegis_usb.c` + `ccid_device.c` to the TinyUSB v2 API
   (esp_tinyusb 2.x migration guide), re-runs this exact proof, then owns the
   authorized legacy removal (host v5.3.1 checkout/venv/caches + env/VS Code).
2. This lane performed NO removal (BLOCKED -> removal forbidden) and changed
   NO host state: installs, persistent env, PATH, and VS Code settings untouched.
3. Do NOT treat the Rust-side bump (sys/hal/svc 0.38/0.47/0.53) as validated
   until an on-device build + flash + functional smoke passes on ESP32-S3.