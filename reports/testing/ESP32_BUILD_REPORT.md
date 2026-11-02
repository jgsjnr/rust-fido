# ESP32-S3 Firmware Build Report — board-devkitc

- **Worktree:** `E:\projetos\standalone-architecture-worktree`
- **Branch:** `refactor/standalone-architecture-cleanup` — **HEAD:** `b21c821`
- **Date (UTC):** 2026-11-02
- **Scope:** read-only on repo code; build artifacts only in `C:\t` (repo `target-dir`,
  gitignored). No flash, no esptool write, no hardware commands, no env changes outside
  the shell, no push/merge.
- **Verdict:** **VERIFIED** (release ELF for `xtensa-esp32s3-espidf` built, exit 0,
  Xtensa ELF header confirmed). No `elf2image`/flash attempted — requires hardware +
  explicit approval.

## 1. Inventory (all in-worktree shell, no changes)

| Item | Result |
|---|---|
| `rustup toolchain list` | `stable-x86_64-pc-windows-msvc (active, default)`, `esp` |
| `rustup target list --toolchain esp` | **fails:** `error: invalid value 'esp' for '--toolchain <TOOLCHAIN>'` (exit 1). The `esp` toolchain is an espup-installed nightly, not a rustup-distributed toolchain, so rustup target management does not apply to it. |
| `rustup +esp target list --installed` | empty output, exit 0 (no rustup-managed targets; Xtensa std is built from source via `-Zbuild-std`) |
| `rustup run esp rustc --version` | `rustc 1.97.0-nightly (8ea53bcd7 2026-07-08) (1.97.0.0)` |
| `.../toolchains/esp/lib/rustlib/` | only `x86_64-pc-windows-msvc` (+ `etc`, `src`) — confirms `-Zbuild-std` path |
| pre-existing `$env:IDF_PATH` | `C:\esp\v6.0.3\esp-idf` (wrong version for this repo; overridden per bootstrap below) |
| `C:\.embuild\espressif\esp-idf\v5.3.1\tools\idf.py` | exists (`Test-Path` = True) |
| `scripts/build*` | `build-all.ps1`, `build-android-so.ps1`, `build-esp32-ttgo.ps1`, `build-esp32s3-devkitc.ps1`, `build-esp32s3-tdisplay.ps1`, `build-freertos-s3-testmode.ps1`, `build-freertos-s3.ps1`, `build-matrix.ps1` |
| Canonical repo build (`common.ps1` `Invoke-FirmwareBuild`) | `cargo +esp build -p aegis-fido-firmware --target <t> --release --no-default-features --features <f> -Zbuild-std=std,panic_abort`, `target-dir = "C:/t"` from `.cargo/config.toml` |
| `.cargo/config.toml` env (preserved, untouched) | `IDF_PATH=C:\.embuild\espressif\esp-idf\v5.3.1`, `ESP_IDF_VERSION=v5.3.1`, `IDF_TOOLS_PATH=C:\.embuild\espressif`, `LIBCLANG_PATH=<esp toolchain>\xtensa-esp32-elf-clang\esp-clang\bin\libclang.dll`, linker `ldproxy` for `xtensa-*-espidf` |

## 2. Environment bootstrap (shell-local only, per `scripts/common.ps1`)

Sourced `./scripts/common.ps1` + `Initialize-EspEnvironment` in each shell (never persisted):

- `IDF_PATH=C:\.embuild\espressif\esp-idf\v5.3.1`
- `ESP_IDF_VERSION=v5.3.1`, `IDF_TOOLS_PATH=C:\.embuild\espressif`
- `ESP_IDF_SDKCONFIG_DEFAULTS=<repo>\sdkconfig.defaults.esp32s3`
- `export-esp.ps1` applied (xtensa gcc/clang, cmake, ninja, IDF tools on PATH)

Verification:

| Command | Exit | Output |
|---|---|---|
| `idf.py --version` (v5.3.1 embuild python env) | 0 | `ESP-IDF v5.3.1` (plus harmless `WARNING: The IDF_PYTHON_ENV_PATH is missing`) |
| `cargo --version` | 0 | `cargo 1.99.1` (stable) / `cargo 1.97.0-nightly` under `+esp` |
| `rustc --version` | 0 | `rustc 1.99.1` (stable) / `1.97.0-nightly` under `esp` |
| `Get-Command ldproxy` | found | `C:\Users\junior\.cargo\bin\ldproxy.exe` |

Note: `Sync-IdfLocalComponents` (repo `components/*` into `$IDF_PATH/components`, part of
`Invoke-FirmwareBuild`) was **deliberately skipped**: it writes outside the shell into the
shared IDF install, which this task forbids. The build used the component copies already
present in `C:\.embuild\espressif\esp-idf\v5.3.1\components`.

## 3. Commands + exits (honest record)

### 3a. Literal task check (stable toolchain, no `+esp`, no `-Zbuild-std`) — RED (expected)

```powershell
cargo check -p aegis-fido-firmware --target xtensa-esp32s3-espidf --features board-devkitc
```

- **Exit:** `101`
- Error excerpt (toolchain usage, not a code defect):

```text
'esp32s3' is not a recognized processor for this target (ignoring processor)  (x12)
error[E0463]: can't find crate for `core`
  |
  = note: the `xtensa-esp32s3-espidf` target may not be installed
  = help: consider building the standard library from source with `cargo build -Zbuild-std`
error: could not compile `const-oid` (lib) due to 1 previous error
warning: build failed, waiting for other jobs to finish...
error: could not compile `cfg-if` (lib) due to 1 previous error
error: could not compile `rand_core` (lib) due to 1 previous error
error: could not compile `cmov` (lib) due to 1 previous error
error: could not compile `subtle` (lib) due to 1 previous error
error: could not compile `typenum` (lib) due to 1 previous error
```

- Interpretation: stable `1.99.1` has no `xtensa-esp32s3-espidf` std. The repo script never
  uses this form — it always builds with `cargo +esp ... -Zbuild-std=std,panic_abort`.

### 3b. Repo-canonical check (`+esp`, `-Zbuild-std`) — GREEN

```powershell
cargo +esp check -p aegis-fido-firmware --target xtensa-esp32s3-espidf --no-default-features --features board-devkitc -Zbuild-std=std,panic_abort
```

- **Exit:** `0` — `Finished 'dev' profile [unoptimized + debuginfo] target(s) in 3m 12s`
- Tail: `Checking aegis-secure-guard`, `Checking aegis-fido-core`,
  `Compiling esp-idf-hal v0.45.2`, `Compiling esp-idf-svc v0.50.1`. Zero warnings/errors.
- Full log: `C:\Users\junior\AppData\Local\Temp\opencode\esp32s3-check.log` (63 lines)

### 3c. Repo-canonical release build (run only because §3b was green) — GREEN

```powershell
cargo +esp build -p aegis-fido-firmware --target xtensa-esp32s3-espidf --release --no-default-features --features board-devkitc -Zbuild-std=std,panic_abort
```

- **Exit:** `0` — `Finished 'release' profile [optimized] target(s) in 1m 39s`
  (esp-idf-sys C objects were cached in `C:\t` from a prior configure; no recompile needed)
- Full log: `C:\Users\junior\AppData\Local\Temp\opencode\esp32s3-build.log` (63 lines)
- The literal shape `cargo build -p aegis-fido-firmware --target xtensa-esp32s3-espidf`
  (stable, no `+esp`/`-Zbuild-std`) was **not** run: §3a proved that shape cannot resolve
  `core` for this target on any code; it would only reproduce E0463.

## 4. Artifacts

| Path | Size | Verification |
|---|---|---|
| `C:\t\xtensa-esp32s3-espidf\release\aegis-fido-firmware` (ELF) | 1,985,052 bytes | header `7F 45 4C 46 01 01 01 00`, `e_machine = 0x5E` (94 = Xtensa). Valid 32-bit Xtensa ELF |
| `C:\t\xtensa-esp32s3-espidf\release\aegis-fido-firmware.d` | 16,623 bytes | dep-info sidecar |

No `.bin` produced (`elf2image` not run — its only purpose is flashing, left for the
hardware step). `git status --porcelain` after build: clean (zero repo modifications;
this report is the single new file).

## 5. Forbidden commands — none run

`esptool.py write_flash`, `espflash`, `idf.py flash/monitor/erase`, `cargo run` on hardware,
`adb`: **none executed**. No serial ports probed, no device touched.

## 6. What remains for flash/hardware

1. Connect an ESP32-S3 DevKitC-1 via USB and confirm the serial port (repo helper:
   `Select-TargetPort` in `common.ps1`; requires a human at the machine).
2. (Recommended) Run the repo full path once on a machine allowed to touch the IDF install:
   `.\scripts\build-esp32s3-devkitc.ps1` (build-only; runs `Sync-IdfLocalComponents` +
   `elf2image` to `C:\t\aegis-app-esp32s3-devkitc.bin`).
3. Flash only with explicit approval: `.\scripts\build-esp32s3-devkitc.ps1 -Flash [-Monitor]`
   (software TEST_DOWNLOAD reboot; physical BOOT/RST buttons are the fallback).
4. Current status maps to `REAL_IMPLEMENTED_NOT_RUN` for the on-device side: firmware ELF is
   built and verified, but no flash/serial measurement has been performed.

## 7. Target-only defect fixes (this change) - GREEN

- **Commit scope (this change only):**
  `crates/aegis-fido-firmware/src/secure_guard_exec/unlock.rs`,
  `crates/aegis-fido-firmware/src/time_sync.rs`, this report. No eFuse/flash paths touched.
- **Defect 1 - `unlock.rs` `AtomicU64` (Xtensa LX7 has no 64-bit atomics, lines 10/25):**
  `CHANGE_PIN_BACKOFF_UNTIL_MS` moved from `AtomicU64` to `std::sync::Mutex<u64>`
  (same `u64` ms F-05 backoff deadline, same accessor values on host).
  `critical-section` was checked in `Cargo.lock` first: it only arrives via
  `esp-idf-hal -> embassy-sync` under `cfg(target_os = "espidf")` - outside the
  direct deps of this crate and unavailable on host - so adopting it would be a
  new dependency; `std` is already used in this file. No `AtomicU32` truncation
  (keeps full ms precision, no ~49.7-day ceiling).
- **Defect 2 - `time_sync.rs` `crate::kprintln!` (textually scoped to `run`, lines 292/295/299):**
  added a local `#[cfg(target_os = "espidf")]`-gated `kprintln!` mirroring the exact
  body `run` uses (`StaticBuf`, no alloc -> `esp_rom_printf`; `println!` on host);
  3 call sites rerouted, message text and `cfg` gating unchanged. `#[macro_export]`
  would have required editing `run/mod.rs` (outside this task file scope); the
  `ltrace!` precedent (`#[macro_export]` + `crate::` path) was confirmed but not usable here.
- **Host:** `cargo test -p aegis-fido-firmware --features freertos,proximity` - exit 0,
  642 passed / 0 failed (574 + 12 + 2 + 3 + 14 + 16 + 8 + 11 + 2), identical totals to
  the pre-change baseline (verified via stash: same 642/0). No behavior change on host.
- **Clippy:** `cargo clippy -p aegis-fido-firmware --features freertos,proximity --all-targets` -
  exit 0; 2 warnings, both pre-existing in `run/run_loop_freertos.rs:454` (untouched file).
- **Target check (repo-canonical, shell-local v5.3.1 env, `+esp`, `-Zbuild-std=std,panic_abort`):**
  `cargo +esp check -p aegis-fido-firmware --target xtensa-esp32s3-espidf --no-default-features --features board-devkitc` - exit 0.
- **Target release:** same shape with `build --release` - exit 0 (`Finished release in 1m 35s`).
- **ELF:** `C:\t\xtensa-esp32s3-espidf\release\aegis-fido-firmware`, 2,000,088 bytes,
  header `7F 45 4C 46`, class 32-bit, `e_machine = 0x5E` (94 = Xtensa). Verified from header bytes.
- **Forbidden commands:** none run (no flash, no serial, no `elf2image`). On-device status
  stays `REAL_IMPLEMENTED_NOT_RUN`: ELF built + verified, no hardware touched.
