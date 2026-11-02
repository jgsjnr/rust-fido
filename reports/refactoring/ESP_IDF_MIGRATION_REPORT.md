# ESP-IDF Migration Report -- v6.0.3 attempt BLOCKED (third-party bindgen gap)

- Worktree: `E:\projetos\standalone-architecture-worktree`
- Branch: `refactor/standalone-architecture-cleanup`
- HEAD: `d6dfbbe` (this report committed on top; see return SHA)
- Date (UTC): 2026-11-02
- Mode: v6.0.3 migration attempted; product C shims adapted to TinyUSB v2 and
  compile clean, but `esp-idf-sys 0.38.1` bindgen cannot handle managed
  `esp_tinyusb v2.x` headers (no released fix). NO removal. No flash/hardware.

## Compat matrix (verified 2026-11-02, crates.io + upstream changelogs)

Minimal v6.0-capable line is `esp-idf-sys 0.38` (`0.38.0` changelog: `Basic
compatibility for ESP-IDF release 6.0`; `0.38.1` latest on crates.io).

| Crate | v5.3.1 line (was) | v6.0.3 line (now) |
| ----- | ----------------- | ----------------- |
| `esp-idf-sys` | 0.36.1 | **0.38.1** | latest; see BLOCKED note below |
| `esp-idf-hal` | 0.45.2 | **0.47.0** | |
| `esp-idf-svc` | 0.50.1 | **0.53.0** | |
| `embuild` | 0.33.5 | **0.33.7** (lock; manifest range `0.33` unchanged) | 0.33.6+ required so managed-component defines reach bindgen (else `FreeRTOS.h` not found) |
| IDF toolchain | `C:\.embuild\espressif\esp-idf\v5.3.1` | `C:\esp\v6.0.3\esp-idf` via EIM | venv `C:\Espressif\tools\python\v6.0.3\venv`, managed storage has `esp_tinyusb 2.4.0` + `tinyusb 0.21.0`2` |

## Changes made (owned files only, zero product `.rs` changes)

Config lane (previous commit `dbc292d`): manifest sys/hal/svc bump, minimal
lock cascade, `.cargo/config.toml` + `common.ps1`/`env-check.ps1` + sdkconfig
header retargeted at EIM v6.0.3 (v5.3.1 as commented fallback), manager ON +
`remote_component espressif/esp_tinyusb 2.*`, CMakeLists dropped dead `usb` name.

This lane (`aegis_usb/` only):
- `aegis_usb.c`: v1->v2 `tinyusb_config_t` mapping (sub-structs `port/phy/task/`
  `descriptor` + `pm_lock_enable/event_cb/event_arg`; `TINYUSB_TASK_DEFAULT()`
  4096/5/CPU1 == v1 Kconfig 4096/5; v1 no-affinity not expressible, v2
  validates `xCoreID <= SOC_CPU_CORES_NUM`). Same descriptors/endpoints/PHY.
- `ccid_device.c`: 3x `usbd_edpt_xfer(..., false)` (all call sites run in task
  context; class struct sets `.xfer_isr = NULL`; FFI poll path is task ctx).
- `Cargo.lock`: `embuild 0.33.5->0.33.7` (+ `bindgen 0.71.1->0.72.1` cascade).

## Proof results (shell-local EIM env, no global env changes)

- `idf.py --version` -> `ESP-IDF v6.0.3`, exit 0 (quirk: `v`-prefixed
  `ESP_IDF_VERSION` crashes v6.0.3 component-manager; EIM uses unprefixed).
- Host `cargo check -p aegis-fido-firmware`: exit 0.
- `cargo +esp check -p aegis-fido-firmware --target xtensa-esp32s3-espidf
  --no-default-features --features board-devkitc -Zbuild-std=std,panic_abort`:
  - Attempt 1-3: cmake component resolution (fixed via manager+remote+CMakeLists).
  - Attempt 4: exit 101, v1 `tinyusb_config_t` fields + 4-arg `usbd_edpt_xfer`
    (fixed by this lane, verified compiling in attempt 5).
  - Attempt 5: exit 101, bindgen `FreeRTOS.h` not found (fixed by embuild 0.33.7).
  - Attempt 6: exit 101, bindgen ``fatal error: tinyusb_types.h file not found``
    at `esp-idf-sys 0.38.1` `src/include/esp-idf/bindings.h:880` -> BLOCKED.
- Release build: not attempted (check red at bindgen; same failure certain).
  No ELF from v6 (the `C:/t` release ELF present is a stale v5.3.1 artifact:
  embeds the `v5.3.1` marker, predates this lane -- must not be cited as proof).

## BLOCKED: exact gap (third-party, no released fix)

`esp-idf-sys 0.38.1` `bindings.h:876-891` does, under
``ESP_IDF_COMP_ESPRESSIF__ESP_TINYUSB_ENABLED``:

    #include "tinyusb.h"
    #include "tinyusb_net.h"
    #include "tinyusb_types.h"   // v1-only: absent from esp_tinyusb 2.x
    #include "tusb_config.h"
    #include "tusb_console.h"
    #include "tusb_tasks.h"      // v1-only: absent from esp_tinyusb 2.x

Managed `espressif/esp_tinyusb 2.4.0` (only version in EIM local storage) ships
neither header (v1 1.4.5 had both). The upstream fix (``support the esp_tinyusb
v2.x remote component...``) sits in the monorepo ``Unreleased`` section -- no
crates.io release contains it (latest still 0.38.1, re-verified 2026-11-02).
Our shims and the full IDF C tree compile; only sys bindgen fails. Remedies
outside this lane: (a) wait for the sys release carrying the fix, then re-run
(warm C cache); (b) parent-sanctioned vendored-source patch (fragile, not done).
Rejected: downgrading managed esp_tinyusb to 1.x (wrong direction -- 2.x is the
upstream v6 path; 1.x targets pre-v6 IDF and is not in local storage).
No behavioral USB changes were needed or made: descriptors, endpoints, polling
semantics, and task config are preserved 1:1.

## Residual notes for follow-up

- `ESP_ROM_ELF_DIR` unset in proof shells -> non-fatal gdbinit warning; EIM
  profile sets it (`C:\Espressif\tools\esp-rom-elfs\20260528`). Export it in the
  next proof run (proof scripts live in `%TEMP%\aegis-esp-proof\`).
- `sdkconfig.defaults.esp32s3` under v6.0.3 reports unknown symbols (`TINYUSB*`
  moved into managed-component Kconfig, `BTDM_CTRL_MODE_*`,
  `SPIRAM_OCCUPY_NO_HOST`, invisible `BT_ALLOCATION_FROM_SPIRAM_FIRST`).
  Remap after bindgen goes green; values are NOT validated on-device yet.
- `components_esp32s3.lock` (repo root, untracked): pins managed 2.4.0/0.21.0`2.
  Follow-up decides: commit it (reproducible builds) or gitignore it.
- v5.3.1 references remaining: intentional commented fallbacks in owned files;
  live refs in UNOWNED scripts (`bench-freertos.ps1`, `qemu-s3.ps1`,
  `linux-bringup.sh`) still point at `C:\.embuild` -- not touched (ownership).

## Next steps (require parent routing + sys release or sanctioned patch)

1. Unblock trigger: `esp-idf-sys` release containing the v2-bindings fix (or
   parent-sanctioned patch path). Then re-run the exact proof (config + shims
   already in tree; C cache warm) -> release build -> ELF verify.
2. Only after GREEN: execute the authorized legacy removal (host v5.3.1
   checkout/venv/caches + env/VS Code), re-verify, commit migration + removal.
3. This lane performed NO removal (BLOCKED -> forbidden) and changed NO host
   state. Do NOT treat the Rust-side bump as validated until on-device
   build + flash + functional smoke passes on ESP32-S3.