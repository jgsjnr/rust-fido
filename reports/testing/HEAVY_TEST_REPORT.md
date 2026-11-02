# Heavy Test Battery — standalone-architecture worktree

- Worktree: `E:\projetos\standalone-architecture-worktree`
- Branch: `refactor/standalone-architecture-cleanup`, HEAD `b1a10b3` (unchanged, no product-code edits in this lane).
- Date (UTC): 2026-11-02. Lane owner: testing-reports only (`reports/testing/*`).
- Toolchain: `cargo 1.99.1` / `rustc 1.99.1`. `PATH += $env:USERPROFILE\.cargo\bin`.
- Scope: host-only Windows x86_64. No flash, no device, no `esptool`/`adb push`
  (none run). Builds, mocked traffic, ports, screenshots, emulators and
  handshakes are not physical-device acceptance.
- Rule check: no `Mock`/`Fake`/`Stub` providers added anywhere in this lane;
  existing doubles reviewed (see §6).

## 1. Baseline — VERIFIED

| Command | Exit | Result |
|---|---|---|
| `cargo test --workspace` | 0 | **941 passed, 0 failed, 1 ignored** (firmware doc-test, pre-existing ignore) |

Per-suite `test result: ok` lines (all `0 failed`):
`aegis-fido-core` lib 124; `ctap_tests` 9; `e2e_vectors` 1;
`aegis-fido-firmware` lib 517; bin `main` 0; `applets_t9` 12;
`freertos_tasks` 2; `migration_tests` 3; `namespaced_store_t5` 14;
`netwifi_t10` 16; `otakey_provider_t6` 8; `proximity_freertos` 0 (default
features — populated only under `freertos,proximity`, see §3);
`secure_guard_integration` 2; `aegis-fido-usb` lib 92;
`aegis-secure-guard` lib 41; `aegis-bridge` lib 36;
`universal-device-sdk` lib 64; doc-tests all `ok` (1 ignored).
Sum: 124+9+1+517+12+2+3+14+16+8+2+92+41+36+64 = **941**.

## 2. Feature matrix

| Combo | Exit | Verdict | Evidence / first error |
|---|---|---|---|
| `cargo check --workspace --all-features` | 101 | BLOCKED **by design** | `compile_error!` GAP-04 guard: `SECURITY VIOLATION (GAP-04): Cannot enable 'test-mode' when building with 'prod-strict'. Software touch simulation hooks are strictly forbidden in production.` (`crates/aegis-fido-firmware`, `test-mode` + `prod-strict` are mutually exclusive; `--all-features` enables both, so failure is the intended guard, not a regression). Incidental: 2 pre-existing-style warnings in `run_loop_freertos.rs:443` (`unused_mut`/`unused_variables` on `pin_verified`) — warnings only, check of that crate otherwise proceeds. |
| `cargo test -p aegis-fido-firmware --features freertos,proximity` | 0 | VERIFIED | lib **562 passed, 0 failed, 4 ignored**; integration: `applets_t9` 12, `freertos_tasks` 2, `migration_tests` 3, `namespaced_store_t5` 14, `netwifi_t10` 16, `otakey_provider_t6` 8, `proximity_freertos` **11**, `secure_guard_integration` 2 — all `ok`, no `FAILED`/`failures:` lines. |
| `cargo check -p aegis-fido-firmware --features prod-strict` | 0 | VERIFIED | `Finished dev profile` in 2.46s. |
| `cargo check -p aegis-fido-firmware --features test-mode` | 0 | VERIFIED (check-only) | `Finished dev profile` in 2.51s. Read-only CLI invocation; **test-mode was NOT enabled in any committed code** (no file edits outside `reports/testing/`). |

## 3. Stress (flake hunt) — VERIFIED, no flakes

| Command | Runs | Result |
|---|---|---|
| `cargo test -p aegis-fido-firmware --lib freertos_sched` | 5 consecutive | **5/5 PASS**, `18 passed; 0 failed` every run (499 filtered out each time). |
| `cargo test -p aegis-fido-firmware --test proximity_freertos` (default features) | 3 consecutive | **3/3 PASS (exit 0)**, `0 passed; 0 failed` — target compiles and runs empty under default features (tests are feature-gated). |
| `cargo test -p aegis-fido-firmware --features freertos,proximity --test proximity_freertos` (extra) | 3 consecutive | **3/3 PASS**, `11 passed; 0 failed` every run. |

Zero failures across 11 stress invocations — no flake report, no seed/excerpt needed.

## 4. Release — VERIFIED

| Command | Exit | Result |
|---|---|---|
| `cargo test --workspace --release` | 0 | **941 passed, 0 failed, 1 ignored** — identical per-suite counts to debug baseline (§1), completed within budget (single invocation, no timeout). |

## 5. Target probes (no flash, no device) — all read-only

- `rustup target list --installed`: `aarch64-linux-android`,
  `armv7-linux-androideabi`, `i686-linux-android`, `x86_64-linux-android`,
  `riscv32imac/imafc/imc-unknown-none-elf`, `thumbv8m.main-none-eabihf`,
  `x86_64-pc-windows-msvc`, `x86_64/aarch64-unknown-linux-gnu`.
  **No `xtensa` / `esp32` / `espidf` target installed** (grep for
  `xtensa|esp32|espidf` returned nothing). Toolchain: only
  `stable-x86_64-pc-windows-msvc` (active, default) plus `esp` (rustup
  toolchain entry named `esp` present; not activated for the check below).
- `cargo check -p aegis-fido-firmware --target xtensa-esp32s3-espidf` →
  **exit 1, BLOCKED (expected, env limitation, no hardware involved)**.
  First/exact errors: `error[E0463]: can't find crate for 'core'` (host
  stable toolchain has no xtensa `core`; needs the ESP Rust toolchain),
  cascading `could not compile cfg-if / const-oid / subtle / rand_core /
  cmov / typenum`, plus repeated `'esp32s3' is not a recognized processor
  for this target (ignoring processor)`. No flash attempted.
- `$env:IDF_PATH` = `C:\esp\v6.0.3\esp-idf`; `Test-Path
  $env:IDF_PATH\tools\idf.py` = **True**. (Only existence checked;
  `idf.py` never executed.)
- Android: `$env:ANDROID_HOME` = `$env:ANDROID_SDK_ROOT` =
  `C:\Users\junior\AppData\Local\Android\Sdk`;
  `platform-tools\adb.exe` present (**True**) — **never invoked**
  (no `adb push`, no destructive/hardware command run in this lane).
  `sdkmanager`: not found on `PATH`; `cmdline-tools` recursive listing
  timed out (>120s, abandoned) and top-level listing returned no entries —
  recorded as NOT VERIFIED (presence unknown), not as absent.
- No `.so`/NDK matrix build attempted (out of lane/time); no physical-device
  acceptance claimed.

## 6. Doubles-boundary review (read-only grep, no edits)

- `TStubCrypto` (`crates/aegis-fido-usb/src/ccid.rs:580`) and `StubCrypto`
  (`crates/aegis-fido-usb/src/piv/piv_cmd.rs:635`): both inside
  `mod tests` — compliant.
- `MockFlashBackend` (`crates/aegis-fido-firmware/src/persistence.rs:503`):
  `pub` in a production file BUT gated
  `#[cfg(any(test, not(target_os = "espidf")))]`, documented
  `CI-GREP: MOCK-ONLY-IN-TEST`, absent on device (prod uses NVS via
  `PlatformFlashBackend`); integration tests import it from the crate root
  (e.g. `tests/applets_t9.rs`). Deliberate, documented host-simulation shim —
  **no change made** (product code out of lane); flagged here for the owning
  lane's awareness only.

## 7. New tests — none added

No genuine uncovered edge was found while running (feature-guard behavior is
by design and already covered; stress runs were flake-free; the
`proximity_freertos`-empty-under-default-features shape is feature-gating,
not a behavior gap). Per lane rules, no `#[test]` additions and no new files.

## Verdicts per leg

| Leg | Verdict |
|---|---|
| 1. Baseline `cargo test --workspace` | VERIFIED (941/0/1, exit 0) |
| 2a. `check --workspace --all-features` | BLOCKED by design (GAP-04 guard, exit 101) |
| 2b. `test -p firmware --features freertos,proximity` | VERIFIED (562+68, exit 0) |
| 2c. `check --features prod-strict` | VERIFIED (exit 0) |
| 2d. `check --features test-mode` (read-only) | VERIFIED (exit 0) |
| 3. Stress 5× sched + 3×/3× proximity | VERIFIED (11/11 pass, no flakes) |
| 4. Release `cargo test --workspace --release` | VERIFIED (941/0/1, exit 0) |
| 5a. ESP target check | BLOCKED (E0463, no xtensa std; env limitation) |
| 5b. IDF/Android existence probes | VERIFIED as probes (idf.py True, SDK dirs set, adb present-but-unused; sdkmanager NOT VERIFIED) |
| 6. New tests | NOT APPLICABLE (no genuine gap found) |

Overall: host-only battery fully green; device/ESP-matrix legs remain
BLOCKED/NOT VERIFIED for environmental reasons. No physical-device
acceptance performed or claimed.
