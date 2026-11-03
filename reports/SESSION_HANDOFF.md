# SESSION HANDOFF — fd/finalizacao-linux (single onboarding doc)

- Date (UTC): 2026-11-03
- Branch: `fd/finalizacao-linux`
- HEAD at handoff creation: `cd22b80` (`fix(bridge): propagate NEED_UP instead of empty lists`)
- Worktree root in examples: relative paths only (no machine paths recorded here).
- Scope of this doc: thorough onboarding from repo evidence only (git log + reports + tools + scripts). No code/config/other-report edits by this handoff.
- Secrets policy: this file contains NO PINs, recovery codes, key material, or passphrases. Where a procedure needs them, it says `<owner-held>`.

---

## 1. Where we are: branch, HEAD, merge history, committed vs dirty

### 1.1 Branch / HEAD

- Current branch: `fd/finalizacao-linux` (checked: `git branch --show-current`).
- HEAD: `cd22b80453e71b933c2362657319d119f02d6a1b` — `fix(bridge): propagate NEED_UP instead of empty lists` (2026-11-03).
- Last 40 commits (newest first, from `git log --oneline -n 40`):

| # | SHA (short) | Subject |
|---|---|---|
| 1 | `cd22b80` | fix(bridge): propagate NEED_UP instead of empty lists |
| 2 | `a37051f` | feat(firmware): persist recovery envelope outside SecureStorage |
| 3 | `3a9a3de` | fix(security): recovery works across DEV reboot (wrapped KEK) |
| 4 | `f253008` | fix(android): bridge-first status, confirmed provision, BLE unlock opcode |
| 5 | `a88bc70` | fix(android): true transport label + ErrorLocked recovery UX |
| 6 | `5c2cdbb` | fix(led): drive WS2812 via RMT (jitter-free) |
| 7 | `0301b20` | feat(firmware): SG over USB-HID in legacy loop + error flash |
| 8 | `3f24bd0` | fix(tools): depcheck resolves compile db at runtime; close sweep findings |
| 9 | `811ec0d` | fix: resolve download_mode release finding (whitelisted) |
| 10 | `44b7570` | refactor(god): slim vendor_tests below threshold |
| 11 | `e6acab9` | test: host-only sweep (no hardware) |
| 12 | `aa3fa67` | fix(android): transport fallback, honest unlock state, hoisted collector |
| 13 | `33fe5dc` | test: webauthn robot + unlock/flicker diagnosis |
| 14 | `bd47042` | feat(firmware): route GET_CAPS through transport funnels |
| 15 | `747648a` | feat(android): capabilities screen via GET_CAPS |
| 16 | `7e572d7` | feat(firmware): GET_CAPS capability advertisement |
| 17 | `f44d27d` | test: sealing full run (all green) |
| 18 | `62c1f9b` | refactor(god): slim legacy_sg_dispatch, vendor_exec, pairing, ble_gatt below threshold |
| 19 | `37e38cf` | docs: fix CLOSED_MODEL_PLAN link |
| 20 | `537ff30` | test: final validation on main (post-merge+diet) |
| 21 | `c393b3c` | feat(firmware): capability presets fido-only/totp (2MB diet) |
| 22 | `f3b9cfe` | merge(refactor): standalone architecture, zero-MPL, RUSTSEC fix, audits + product updates |
| 23 | `7b784ac` | fix(android): scoped cleartext + wired OTA hook |
| 24 | `9bd8e79` | feat(firmware): SG serial dispatch in legacy loop (parity with freertos) |
| 25 | `d9dfe80` | test(hardware): physical journey + final wipe |
| 26 | `a379cf5` | fix(esp32): portable atomics + macro scope for Xtensa |
| 27 | `ae68a77` | feat(security): expire BLE bonds after 30d with NimBLE store wipe |
| 28 | `4d5e614` | feat(security): SNTP time source with NVS anchor and fail-closed TOTP clock |
| 29 | `52782ca` | fix(security): change_pin backoff mirrors unlock policy (F-05) |
| 30 | `11efc2a` | fix(security): require BLE MITM via LESC+bonding, reject JustWorks (F-01) |
| 31 | `0d83f7c` | refactor(usb): optional no_std (std default) |
| 32 | `167fbbf` | feat(android): offline firmware.bin OTA engine (unwired hook) |
| 33 | `199e134` | refactor(android): split god files (no UI change) |
| 34 | `aa3afe2` | refactor(android): strings i18n + de-emoji |
| 35 | `81edd8b` | docs: ANDROID_AUDIT.md |
| 36 | `4f81df0` | revert(esp-idf): keep pinned v5.3.1, v6 blocked upstream |
| 37 | `f136e48` | fix(security): bind SecureChannel session keys into tag AD (F-02) |
| 38 | `7d3c7b9` | docs(security): adversarial audit (read-only) |
| 39 | `3378633` | docs(esp-idf): v6 migration BLOCKED - sys 0.38.1 bindgen vs esp_tinyusb v2 headers (shims adapted, pending upstream) |
| 40 | `d6dfbbe` | docs(closed-model): draft proprietary pack (not effective) |

### 1.2 Merge history (worktree merged)

- `f3b9cfe` is the integration merge: `merge(refactor): standalone architecture, zero-MPL, RUSTSEC fix, audits + product updates`. It brought the standalone-architecture worktree lane (preservation refactor P0-P7, analyzer, UniFFI removal `915ebf3`, RUSTSEC `33df2ea`, audits, product updates) into `fd/finalizacao-linux`.
- Merge-base with `main`: `20ffc71`. `main` HEAD is also `20ffc71` at read time (this branch is ahead; `main...HEAD` diff is large).
- Recent merges (`git log --merges --oneline -n 20`, newest first) include `f3b9cfe`, plus older android/product merges: `bad191d` (fido2 PIN sync + WebAuthn presence), `0832edf` (10 product commits into standalone-architecture), `608ff24`, `7509db5`, `cffe8f2`, `57d03c2`, `a942843`, `2e52fa4`, `f9b84bb`, `f81811b`, `f9e8c23`, `9556340`, `d6dfbbe`-era lanes, and older FIDO/vault/PIV/wallet/OTA merges. The operative merge for this handoff is `f3b9cfe`.
- Note: `f3b9cfe` message states the standalone lane itself was NOT merged / never pushed at report time — that refers to the worktree-local state before integration. The integration into this branch exists as `f3b9cfe` on this branch.

### 1.3 Committed vs dirty (at handoff creation)

Committed: everything in 1.1 up to `cd22b80`.

Dirty / untracked at read time (`git status --porcelain`):

- Modified (DO NOT assume committed — owner decides):
  - `app-android/app/src/main/java/dev/aegiskey/app/data/local/EncryptedKeysStore.kt`
  - `app-android/.../data/repository/KeyVaultRepositoryImpl.kt`
  - `app-android/.../data/repository/TotpRepositoryImpl.kt`
  - `app-android/.../data/transport/HostUsbUartBridgeClient.kt`
  - `app-android/.../di/AppContainer.kt`
  - `app-android/.../domain/model/TotpModels.kt`
  - `app-android/.../domain/repository/TotpRepository.kt`
  - `app-android/.../ui/atomic/molecules/TotpCodeCardMolecule.kt`
  - `app-android/.../ui/atomic/organisms/AddTotpAccountDialogOrganism.kt`
  - `app-android/.../ui/atomic/organisms/KeyGenerationDialogOrganism.kt`
  - `app-android/.../ui/screens/KeyVaultHubScreen.kt`
  - `app-android/.../ui/screens/TotpDedicatedScreen.kt`
  - `app-android/.../ui/viewmodel/KeyVaultViewModel.kt`
  - `app-android/.../ui/viewmodel/TotpAuthenticatorViewModel.kt`
  - `app-android/.../res/values-pt/strings.xml`, `res/values/strings.xml`
  - `crates/aegis-fido-core/src/credential/non_resident.rs`
  - `crates/aegis-fido-core/src/credential/record.rs`
  - `crates/aegis-fido-core/src/credential/store.rs` (large rewrite in working tree)
  - `crates/aegis-fido-core/src/ctap/make_cred.rs` (1 line)
  - `crates/aegis-fido-firmware/src/cred_store.rs`
  - `crates/aegis-fido-firmware/src/ctap_cmd.rs`
  - `reports/refactoring/dep-track.json` (side effect of `dep-track --check`; owner: godfiles lane)
  - `reports/testing/CONSOLIDATED_RUN.md` + `consolidated-result.json` (side effect of `run_all.py`; owner: testing lane)
- Untracked (DO NOT assume committed):
  - `STDOUT` (stray capture file at repo root — remove or ignore; not part of any lane)
  - `app-android/.../ble/DevicePresence.kt`
  - `app-android/.../ui/viewmodel/PresenceRequest.kt`
  - `app-android/.../NeedUpPresenceTest.kt`
  - `docs/bench-destructive.md`, `docs/bench-freertos-s3.md`, `docs/finalizacao-freertos-rust.md`, `docs/freertos-rust.md`, `docs/proximity-worktree-handoff.md`
  - `tools/app_path_replay.py`
- Interpretation: the working tree contains an in-flight per-credential UP / presence-request change (credential store + firmware cred/ctap + app TOTP/vault/presence files + new presence test). It is NOT committed at `cd22b80`. See section 7.

This handoff commit adds ONLY `reports/SESSION_HANDOFF.md`. It does not stage or commit any of the above dirty/untracked files.

---

## 2. Architecture map: 6 crates + bridge + firmware + app + tools

### 2.1 Workspace (root `Cargo.toml`)

- Workspace members (6):
  1. `crates/aegis-secure-guard` — SecureGuard engine (PIN policy, lock/unlock, backoff, recovery, scoped wipe, session expiry, BLE proximity lock, ECDH handshake).
  2. `crates/aegis-fido-core` — FIDO2/CTAP core (credentials, CTAP makeCred/getAssertion, PIN/UV, crypto curves, wallet/OATH/TOTP domains).
  3. `crates/aegis-fido-usb` — USB/CTAPHID framing, CCID/PIV/OpenPGP dispatch, descriptors (VID/PID/serial), WinUSB.
  4. `crates/aegis-fido-firmware` — ESP32-S3 firmware (run loops legacy + freertos, SG dispatch, vendor exec, BLE GATT/NimBLE, Wi-Fi/SNTP, OTA key provider, display, proximity, NVS stores, capability gates).
  5. `crates/universal-device-sdk` — host SDK envelope/AEGN, SecureGuard DTOs, CTAP21 helpers, Shamir, wallet helpers.
  6. `crates/uniffi-bridge` — cdylib `aegis_bridge` (post-UniFFI: manual `extern "C"` C-ABI `aegis_*`, two-call buffer protocol, JSON only at JNI edge). Name retained for `System.loadLibrary("aegis_bridge")`.
- Excluded: `tools/uniffi-gen` (workspace exclude).
- Workspace package: `version 1.0.0`, `edition 2021`, `license GPL-3.0-only`, `publish = false` (private path-deps; `cargo-deny [bans] allow-wildcard-paths` relies on it).
- First-party license: all six members `GPL-3.0-only` (deny exceptions). No per-file SPDX headers (verified zero hits; decision recorded in `license-inventory.json:63`).

### 2.2 Ownership boundaries (lane convention)

- `crates/**` — Rust owners (firmware / core / usb / secure-guard / SDK / bridge-FFI lanes).
- `app-android/**` — Android lane (Kotlin/Compose, transports, OTA hook, i18n, god splits).
- `tools/*.py` + `tools/host_sdk/**` + `tools/docs-lint/**` + `tools/architecture-analyzer/**` — tooling lanes (stdlib-only, no network, deterministic emoji-free output).
- `scripts/*.ps1` + `scripts/*.sh` + `scripts/capability-catalog.json` — flashing/capability/build scripts (parse-only in CI; device scripts never executed by gates).
- `.github/workflows/ci.yml` — bootstrap only (checkout + Python + Rust + cargo-deny + invoke `run_all.py`). No check commands duplicated (DRY by construction).
- `reports/<area>/**` — per-area evidence ownership: refactoring (godfiles/diet/architecture), testing (run_all/robot/sweeps/journeys), compliance (licenses/SBOM/trademark/security). Each lane owns its reports; other lanes do not edit them.
- `docs/**` — product docs (evaluation/plans/project). `docs-lint` checks `--root docs` and `--root reports` separately plus a `reports/**` internal-path scan.

### 2.3 Key files (entry points)

- Firmware: `crates/aegis-fido-firmware/src/lib.rs` (capability `compile_error!` gates), `run_loop_legacy.rs`, `run_loop_freertos.rs`, `run/legacy_sg_dispatch.rs`, `vendor_exec.rs` (+ `vendor_exec/vendor_caps.rs` for GET_CAPS `0x3F`, `vendor_tests/` split), `cred_store.rs`, `ctap_cmd.rs`, `ble_gatt.rs`, `pairing.rs`, `freertos_route.rs`, `partitions.csv` (16 MB) + `partitions-2m.csv` (2 MB), `sdkconfig.defaults.esp32s3`.
- Core: `crates/aegis-fido-core/src/credential/{store,record,non_resident}.rs`, `ctap/make_cred.rs`, `crypto/curves.rs`, `crypto/ecdh.rs`, `ctap/extensions_ctap21.rs`.
- USB: `crates/aegis-fido-usb/src/ctaphid.rs` (INIT 57 B / CONT 59 B / max 7609 B), `usb_descriptors.rs` (VID `0x303A` / PID `0xAE61` / serial), `ccid_dispatch.rs`, `piv_cmd.rs`.
- SecureGuard: `crates/aegis-secure-guard/src/{engine,policy,secure_channel,persistence,efuse,glitch_guard,resource,state,crypto}.rs`.
- SDK: `crates/universal-device-sdk/src/{envelope,auth,shamir,ctap21,hardwallet}.rs` (note: `auth`/`envelope` modules private; external consumers use root re-exports).
- Bridge FFI: `crates/uniffi-bridge/src/{lib,ffi}.rs` (22 domain fns byte-identical + `aegis_*` C-ABI; UDL frozen as reference in `UNIFFI_REMOVAL_PLAN.md`).
- App: `app-android/.../{MainActivity,AegisApplication.kt}`; `bridge/AegisBridge.kt`; `caps/{CapsConstants,CapsModels,CapsParser,CapsRepository,CapsScreen}.kt`; `ota2/{Ota2Engine,Ota2Manifest,Ota2FileStore,Ota2Transport,Ota2Verifier,Ota2Keys,Ota2Screen,Ota2Session}.kt`; `data/transport/{BleKeyTransport,UsbKeyTransport,HostUsbUartBridgeClient,SimulatedRenodeTransport}.kt`; `security/{AppLock,BiometricGate,BindingKey,SdkGate,RecoveryBackup,FeatureFlags}.kt`; `res/values/strings.xml` + `res/values-pt/strings.xml` + `ota_strings.xml`.
- Tools: `tools/run_all.py`, `tools/dep_track.py`, `tools/docs-lint/docs_lint.py`, `tools/webauthn_robot.py`, `tools/host_hardware_android_bridge.py`, `tools/host_sdk/cli.py`, `tools/architecture-analyzer/`, `tools/depcheck.py`, `tools/e2e_harness.py`, `tools/validate_aegiskey.py`.
- Scripts: `scripts/select-capability.{ps1,sh}`, `scripts/capability-catalog.json`, `scripts/build-esp32s3-devkitc.ps1`, `scripts/build-esp32s3-tdisplay.ps1`, `scripts/build-esp32-ttgo.ps1`, `scripts/build-freertos-s3{,-testmode}.ps1`, `scripts/flash.ps1`, `scripts/common.ps1` (`Invoke-FirmwareElf2Image`), `scripts/env-check.ps1`, `scripts/{menu,pipeline,test-all,qemu-s3,sync-master}.ps1`.
- CI: `.github/workflows/ci.yml` (validate + validate-release jobs).

---
## 3. What was done (by area, with commit SHAs)

### 3.1 Preservation refactor (standalone architecture, P0-P7) — `f3b9cfe` merge, evidence `FINAL_REFACTOR_REPORT.md`

- Worktree: standalone-architecture worktree (see report), branch `refactor/standalone-architecture-cleanup`, HEAD `915ebf3` at report time.
- P0 PRESERVED (inventory): `repository-inventory.json`, `standalone-crates.md`, `baseline.md`, `moved-files.md` — zero moves (`moves_executed: 0`).
- P1 UNDERSTOOD (graph): `dependency-graph-before.json` / `-after.json` identical; `god-files.md` lists split candidates, no split executed in that lane.
- P2 RELOCATE (plan only): `migration-plan.json` — KEEP verdicts + 3 PROPOSED, none executed.
- P3 DECOUPLE: NOT EXECUTED (envelope triplication, SecureGuard quad, BLE opcode contract risks recorded as-is).
- P4 Analyzer built: `tools/architecture-analyzer/` (real `cargo_metadata` + `syn`, no mocks; `cargo check` exit 0).
- P5 Compliance baseline: `reports/compliance/` (7 files) — license inventory (23 APPROVED-by-owner 2026-11-02), compatibility audit, SBOM SPDX, trademark audit, documentation audit, third-party notices source + `cargo-deny-final.log` (post-`33df2ea` snapshot, exit 0). `deny.toml` + `THIRD_PARTY_NOTICES.md` at root. `cargo-deny-output.log` preserved from prior owner (NOT modified).
- P6 Validation (post-JNI): `BASELINE.md` + `FINAL_TEST_REPORT.md` — test 937/0, clippy exit 0, deny exit 0, zero-MPL.
- P7 Docs heuristic: `documentation-audit.md` — coherence by inspection; ASD-STE100 style observed, NOT certified (no controlled-language tool run).
- Scheduler fix `e683979` re-validated (post-JNI full workspace run 937/0 + bridge 36/36 + SDK 64/64 + focused `--test-threads=1` 36/0).

### 3.2 Analyzer — `tools/architecture-analyzer/`

- Real parsing (`cargo_metadata` + `syn`), no mocks. `cargo check` exit 0. No further action in this handoff.

### 3.3 God splits (firmware + android)

Firmware (dep-track gods driven below threshold 25):

- `62c1f9b` — `refactor(god): slim legacy_sg_dispatch, vendor_exec, pairing, ble_gatt below threshold`.
- `44b7570` — `refactor(god): slim vendor_tests below threshold` (split `vendor_tests/` into `{pin,piv,store,caps}.rs`; closed HOST_SWEEP finding `vendor_tests` 26.21).
- Report baseline `god-files.md` listed: `run_loop_legacy.rs` 2067, `secure_guard_exec.rs` 1743, `run_loop_freertos.rs` 1456, `usb piv_cmd.rs` 1371, bridge `lib.rs` 1286 (KEEP). Status at that time: UNVERIFIED — no split executed (splits came later as above).
- `dep-track.json` is rewritten by `dep-track --check` itself (side effect; owner: godfiles lane). Do not hand-edit.

Android (move-only, no UI change):

- `199e134` — `refactor(android): split god files (no UI change)`: `FriendlySettingsAndThemeScreen.kt` (1764) to `FriendlySettingsDialogs.kt` (1360); `KeyDetailManagementScreen.kt` (309) to `KeyDetailSections.kt` (896); `FriendlyOnboardingWizardScreen.kt` (284) to `FriendlyOnboardingSteps.kt` (659). Same package; moved fns `private` to `internal`; no signature/body change.
- KEEP (verified, cohesive or generated): `KeyVaultRepositoryImpl.kt` (~750), `bridge/AegisBridge.kt` (1491), generated `uniffi/aegis_bridge/aegis_bridge.kt` (1961), `HostUsbUartBridgeClient.kt` (1131), `UsbCtaphid.kt` (696), `KeyVaultHubScreen.kt` (699), `AegisBleClient.kt` (649).

### 3.4 Elliptic 0.14 migration (RUSTSEC-2026-0387) — `33df2ea` (via `f3b9cfe`)

- `p256/k256/p384/p521 0.13 to 0.14` + `ecdsa 0.17`, `elliptic-curve 0.14`, `signature 3.0`, `ed25519-dalek 3.0`, `crypto-bigint 0.7.10`. Wire-preserving (Sec1Point alias, same bytes; `try_sign` propagates error).
- `cargo deny check licenses advisories bans sources`: exit 0 (`advisories/bans/licenses/sources ok`). RUSTSEC-2026-0387 RESOLVED.
- Pre-existing staleness note: 26 stale pre-0.14 elliptic rows still listed in old inventory; 36 unlisted 0.14-stack packages — left for owning lane; deny still PASS.

### 3.5 UniFFI removal (zero MPL-2.0) — `915ebf3` (via `f3b9cfe`), plan `UNIFFI_REMOVAL_PLAN.md`

- `crates/uniffi-bridge`: removed `uniffi` from `[dependencies]` + `[build-dependencies]` + deleted `build.rs` (`generate_scaffolding`). Deleted waiver `allow(clippy::empty_line_after_doc_comments)` for scaffolding.
- UDL `src/aegis_bridge.udl` FROZEN as reference doc (body untouched; content archived in commit message).
- 22 domain `pub fn` kept byte-for-byte (BLE frag, AEGN seal/open, COSE parse-only, OATH, app-lock PBKDF2, wallet, SecureGuard passthrough, mini JSON parser). Same bytes-on-wire, same semantics.
- New stable `extern "C"` ABI `aegis_*` (mapping in plan section 4): `-> i32` status (`0` ok, negative `-BridgeError`), caller-buffer outputs `(out, out_cap, out_len)` two-call protocol (`NULL` queries length), scalars via out-slots, UTF-8 `(ptr,len)` pairs, JSON only at JNI edge. `aegis_bridge_version()` returns static `"1.0.0"`. `unsafe` blocks each carry `SAFETY:` comments.
- Why not `jni` crate: Android consumes via JNA plain C symbols; `jni` would add registry packages for zero functional gain.
- Lock: 34 packages pruned, 0 added. `cargo tree -i uniffi` empty. Notices/inventory `273 to 239`, SBOM `280 to 246`. `deny.toml` MPL-2.0 entry removed. Deny PASS.
- Kotlin impact: `AegisBridge.kt` calls only generated `uniffi.aegis_bridge.*` wrappers, each with 100 percent pure-Kotlin/JVM fallback below (`splitFragmentsFallback`, `envelopeSealFallback`, `MiniCbor`, keccak/RIPEMD-160/bech32/PBKDF2). After removal, JNA lookup throws at call time, caught, deterministic fallback. No Kotlin edit required; no BLOCKED. Follow-ups for Android owner: hand-write JNA against new C ABI, refresh `proguard-rules.pro` (`-keep class uniffi.**` stale), refresh checked-in generated `uniffi/aegis_bridge/aegis_bridge.kt`.

### 3.6 RUSTSEC / deny / licenses (23 approved)

- Deny gate: `cargo deny check licenses advisories bans sources` — PASS (exit 0) in sealing runs (`62c1f9b` head: 12.6 s; earlier run: 33.8 s). Pinned `cargo-deny 0.20.2` in CI (`taiki-e/install-action@v2`).
- Allow list (`deny.toml [licenses] allow`): MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, CC0-1.0 (bip39, bitcoin_hashes, hex-conservative), Unlicense (aho-corasick, byteorder, globset, ignore, memchr, winapi-util, same-file, walkdir), Unicode-3.0 (unicode-ident, unicode-normalization as ANDed alternative), BSL-1.0 (ryu Apache-2.0 OR BSL-1.0 alternative). All non-permissive-class entries stay `REVIEW-HUMANO-PENDENTE` until legal review — factual/technical record only, no legal determination.
- Exceptions: six first-party `GPL-3.0-only` (`aegis-secure-guard`, `aegis-fido-core`, `aegis-fido-usb`, `aegis-fido-firmware`, `universal-device-sdk`, `uniffi-bridge`).
- 23 licenses APPROVED-by-owner (technical acceptance 2026-11-02; NOT legal certification). Post-UniFFI: MPL x9 clause has no object (9 uniffi removed); remaining CC0-1.0 x3 / Unlicense x8 / BSL-1.0 alt x1 / Unicode-3.0 x2 keep technical acceptance.
- `r-efi 6.0.0` (MIT OR Apache-2.0 OR LGPL-2.1-or-later, transitive via `getrandom 0.4.3` UEFI path): effective license taken via MIT/Apache-2.0 alternative; any use under LGPL alternative stays BLOCKED pending legal review.
- SBOM: `reports/compliance/sbom.spdx.json` (280 to 246 packages/relationships post-UniFFI). Inventory `license-inventory.json`, `third-party-notices.md`, root `THIRD_PARTY_NOTICES.md` (recount verified).

### 3.7 Trademarks — `reports/compliance/trademark-audit.md` (audit ONLY, no removals performed)

- 8 low KEEP rows (functional protocol references stay factual, no branding change): FIDO2/FIDO Alliance/CTAP 2.1/2.3, W3C WebAuthn, NIST P-256 / SP 800-73-4 / PIV, BIP-32/39/SLIP-0039, YKOATH/OATH/RFC 6238, OpenSSH/sk-ssh-ed25519, Microsoft OS 2.0 Descriptors / Windows Hello CDF / Named Pipe, Espressif/ESP32-S3/ESP32 classic/VID `0x303A` (do not present VID as owned).
- 3 medium REVIEW rows (no change performed; owner: docs + web UI): Google Authenticator compatibility wording (prefer generic OATH application text or keep only with permission), `dev.aegiskey.app` reverse-DNS app id (confirm ownership + store registration), FIDO certification status (no claim found — KEEP absence; never claim certification until process completes).
- So neutralized here means: audit recorded + absence-of-claim verified, NOT renamed/removed. Any rewording is an open thread (see section 7).

### 3.8 ESP-IDF v5.3.1 pinned + v6 BLOCKED — `4f81df0`, `3378633`

- `4f81df0` — `revert(esp-idf): keep pinned v5.3.1, v6 blocked upstream` (touches `.cargo/config.toml`, `Cargo.lock`, firmware `Cargo.toml`, `components/aegis_usb/*`, `ESP_IDF_MIGRATION_REPORT.md`, `ESP_IDF_WINDOWS_CLEANUP.md`, `scripts/common.ps1`, `scripts/env-check.ps1`, `sdkconfig.defaults.esp32s3`).
- `3378633` — `docs(esp-idf): v6 migration BLOCKED - sys 0.38.1 bindgen vs esp_tinyusb v2 headers (shims adapted, pending upstream)`.
- Meaning: on-device target stays v5.3.1. v6.0.3 / `esp-idf-sys` 0.36 compat UNVALIDATED. v6.1 target UNVALIDATED, BLOCKED until physical validation. Two host installations maintained; no removal executed. No migration executed; no legacy code removed.
- ESP32 build evidence: `reports/testing/ESP32_BUILD_REPORT.md`.

### 3.9 RMT LED — `5c2cdbb`

- `fix(led): drive WS2812 via RMT (jitter-free)`. Pairing/LED docs: `ble_gatt.rs`/`pairing_led`, WS2812 specs + journeys J1-J8 in master plan docs.

### 3.10 SG dispatch legacy + USB-HID — `9bd8e79`, `0301b20`

- `9bd8e79` — `feat(firmware): SG serial dispatch in legacy loop (parity with freertos)`.
- `0301b20` — `feat(firmware): SG over USB-HID in legacy loop + error flash`.
- Context from HARDWARE_JOURNEY: the default release runs the legacy run loop (`board-devkitc`, no `freertos` feature). SG `0x3A-0x3E` dispatch exists in `freertos_route.rs` to `dispatch_serial_vendor_msg` (feature `freertos`); legacy loop previously had no `0x3A-0x3E` branch (unknown ops fell through to CTAP `0x01`). These commits backport/extend SG coverage to legacy serial + USB-HID paths. `62c1f9b` then slims `legacy_sg_dispatch.rs` below god threshold.

### 3.11 Recovery envelopes — `a37051f`, `3a9a3de`

- `a37051f` — `feat(firmware): persist recovery envelope outside SecureStorage`.
- `3a9a3de` — `fix(security): recovery works across DEV reboot (wrapped KEK)`.
- No secret material is recorded in this handoff. Recovery procedure uses `<owner-held>` placeholders.

### 3.12 BLE MITM (F-01) — `11efc2a`

- `fix(security): require BLE MITM via LESC+bonding, reject JustWorks (F-01)`.
- Prior audit state (F-01 MEDIUM): `sm_io_cap = NO_INPUT_OUTPUT`, `sm_bonding = 1`, `sm_mitm = 0`, `sm_sc = 1` with acknowledged no-MITM comment. Compensating controls: SC + bonding ENC keys, app-layer ECDSA binding claim/challenge, UP-per-operation, pairing window gate. Fix direction: require MITM via LESC + bonding; reject JustWorks. Follow-ups remain (numeric-comparison/OOB evaluation, window shortening) — see section 7.

### 3.13 Backoff (F-05) — `52782ca`

- `fix(security): change_pin backoff mirrors unlock policy (F-05)`. `change_pin` now applies `compute_backoff_ms` + RateLimited transition exactly as unlock path (was: increment `failed_attempts` + `InvalidPin` with no backoff).

### 3.14 TOTP time — `4d5e614`

- `feat(security): SNTP time source with NVS anchor and fail-closed TOTP clock`. TOTP clock fails closed when time is untrusted; NVS anchor persists across reboot.

### 3.15 Bond expiry — `ae68a77`

- `feat(security): expire BLE bonds after 30d with NimBLE store wipe`.

### 3.16 Per-credential UP — IN-FLIGHT (NOT committed at `cd22b80`)

- `git log` on this branch contains NO committed per-credential UP commit. HEAD `cd22b80` is bridge NEED_UP propagation only.
- Working tree (dirty, uncommitted) contains the per-credential UP work: `crates/aegis-fido-core/src/credential/{store,record,non_resident}.rs` + `ctap/make_cred.rs` + `crates/aegis-fido-firmware/src/{cred_store,ctap_cmd}.rs` + app `Totp*/KeyVault*/Presence*` + new `NeedUpPresenceTest.kt` + `DevicePresence.kt` + `PresenceRequest.kt`. Treat as in-flight; app toggle side is an open thread (see section 7).
- If a later `git log` shows a per-credential UP commit, update this section; until then it is NOT done.

### 3.17 Capability presets + picker + catalog — `c393b3c`

- `c393b3c` — `feat(firmware): capability presets fido-only/totp (2MB diet)`. See section 5 for presets/table/pools/budgets.
- Picker: `scripts/select-capability.ps1` / `.sh` (parity; never writes flash). Catalog: `scripts/capability-catalog.json` (machine-readable source of truth).

### 3.18 GET_CAPS + caps screen — `7e572d7`, `747648a`, `bd47042`

- `7e572d7` — `feat(firmware): GET_CAPS capability advertisement` (vendor read-only `0x3F`; request must be empty or fail-closed `0x04`; response `(0x00, CBOR map)` with `fw_version` / `preset` / `caps` / `unsupported_count`; no auth; executed in `exec_vendor_op` BEFORE binding/UP/PIN gates).
- `bd47042` — `feat(firmware): route GET_CAPS through transport funnels` (serial/legacy + BLE dispatch + reassembler accept `0x3F`).
- `747648a` — `feat(android): capabilities screen via GET_CAPS` (`caps/` package: constants/models/parser/repository/screen).

### 3.19 App: i18n / emoji / god splits / OTA engine / transport fix / ErrorLocked UX / NEED_UP

- `aa3afe2` — `refactor(android): strings i18n + de-emoji`: 10 emoji removed (SecureGuard card, rate-limit popup, onboarding); backspace glyph U+232B kept (text glyph, not emoji); about 230 new `strings.xml` EN + PT-BR keys (now 614 EN + 614 PT entries + 24+24 `ota_strings.xml`); ASD-STE100 glossary comment; composable-layer literals to `stringResource`; `BiometricGate`/`BindingKey` via passed `Activity`; in-app language switch (`LocalePreferencesStore` + `LocaleHelper` + `MainActivity.attachBaseContext` + settings FilterChip + `recreate()`; no appcompat dep). VM/repo/transport runtime messages DEFERRED (unit tests pin exact message content; needs `UiText`-key migration).
- `199e134` — android god splits (see 3.3).
- `167fbbf` — `feat(android): offline firmware.bin OTA engine (unwired hook)` (`ota2/` engine: `Ota2Engine/Manifest/FileStore/Transport/Verifier/Keys/Screen/Session/Failure`; no `0x33` COMMIT by design).
- `7b784ac` — `fix(android): scoped cleartext + wired OTA hook`: A-01 fix — replace global `usesCleartextTraffic="true"` with `networkSecurityConfig` (`base-config false`; allow-list `192.168.4.1` / `10.0.2.2` / `127.0.0.1` / `localhost`); OTA_HOOK.md 3-line wiring (`AegisApplication` + `BuildConfig.OTA_RELEASE_PUBKEY_HEX` denied all-zeros placeholder fail-closed + settings row + `composable("ota2")` with BLE-preferred/USB-fallback transport + device-reported `firmwareRevision` as `currentVersion`).
- `aa3fa67` — `fix(android): transport fallback, honest unlock state, hoisted collector` (addresses ROBOT_RUN unlock/flicker diagnosis: OR-across-transports instead of throw-on-first-failure; surface device status instead of forging UNLOCKED; hoist duplicate `collectAsState` to top level).
- `a88bc70` — `fix(android): true transport label + ErrorLocked recovery UX`.
- `f253008` — `fix(android): bridge-first status, confirmed provision, BLE unlock opcode`.
- `cd22b80` — `fix(bridge): propagate NEED_UP instead of empty lists` (bridge surfaces NEED_UP; app must NOT render empty lists as success).

### 3.20 CI workflow — `.github/workflows/ci.yml`

- The ONLY CI workflow. Bootstrap only. Jobs: `validate` (default legs, push/PR + manual) + `validate-release` (manual dispatch with `release=true`). Windows-latest (pwsh + ESP-IDF paths are Windows-oriented). No `dependabot.yml` by decision (deny `advisories` gate covers vuln tracking). Action pins with tag + comment. Uploads `consolidated-result.json` + `CONSOLIDATED_RUN.md` as artifact.

### 3.21 Python trackers + robot + run_all

- `tools/run_all.py` — unified orchestrator (stdlib only; portable Windows/Linux via `pathlib` + `sys.executable`; deterministic emoji-free; refuses destructive commands; no network; no secrets). Legs: test-debug, test-firmware-features, clippy, fmt (advisory), deny, dep-track, docs, scripts, test-release (opt-in `--release`). See section 4.
- `tools/dep_track.py --check` — gate: exit 2 on NEW god-file (score over 25) outside allowlist. Rewrites `reports/refactoring/dep-track.json` as side effect (owner: godfiles lane).
- `tools/docs-lint/docs_lint.py` — heuristic markdown link + terminology checker (stub; NOT certified; ASD-STE100 heuristic only). `--root DIR` single-root invocations; `--strict` turns brand hits into exit 1.
- `tools/webauthn_robot.py` — WebAuthn host robot (stdlib + `ctypes` only; no Mock/Fake/Stub). Full run 26/26 PASS (2026-11-02). Covers bridge vectors (36/0), direct cdylib calls via `ctypes`, firmware provision/unlock/lock/wipe/keepassxc, makeCred to getAssertion signCount, CTAP gates, PIN/UV, RFC vectors, serial framing + manager parity, BLE GATT reassemble, CTAPHID fragment sizes 0/1/57/58/200/7609 B + overrun/seq/error codes incl. diet `0x06`, `cargo test -p aegis-fido-usb` 92/0, HOTP RFC 4226 10/10, TOTP RFC 6238 9/9, 30 s window, emulator inventory, UNLOCK/FLICKER/KEYPASS diagnoses.
- `tools/host_sdk/cli.py` — host SDK CLI (stdlib-only): `--help` / `--self-test` (offline) / `--demo` (frozen vectors) / `--port PORT` (default `AEGIS_PORT` or `COM7`).

### 3.22 Hardware journeys + wipes

- `d9dfe80` — `test(hardware): physical journey + final wipe`. Evidence: `reports/testing/HARDWARE_JOURNEY.md` (ESP32-S3 physical board, UART COM7 at 115200 CTAPHID framing; provenance `a379cf5`; ELF-SHA + `.bin` + `.sha256` sidecar; flash `0x10000`; boot log 120 lines ESP-IDF v5.3.1; journey 51 PASS / 0 BLOCKED / 2 FAIL-quirk over 53 steps; CTAP FIDO2 makeCred/getAssertion signCount 0 to 1 to 2; TOTP vs RFC vectors match; SG lock/unlock/wipe over UART/USB BLOCKED at that build — legacy loop had no `0x3A-0x3E` branch — since addressed by `9bd8e79`/`0301b20`; final full wipe with owner-held PIN verified factory-clean: UNCLAIMED, PIN unset, vault empty, OATH empty, resident credentials destroyed, app alive, zero panic/Guru lines).

### 3.23 APK locations + SHAs (at read time)

- `dist/android-apk/AegisKey-debug.apk` — SHA256 `8275F6F1FD4108A6723E30DD2A6C423C48B09E7368E8D1E133F5EBFE8D4EE979`.
- `dist/android-apk/AegisKey-release-unsigned.apk` — SHA256 `7DE50C9463EE2A09AF60A0E1B638C0DE22322A467931EE1ADDA630FE3DC5D9A2`.
- Also present under ignored worktree build outputs (`app-debug.apk`, `app-release-unsigned.apk` under `.slim/worktrees/android-ux-journey/.../build/outputs/apk/`). These are build caches, not release evidence.
- Note: SHAs are build artifacts; rebuilds change them. Record date + commit when promoting any APK.

---
## 4. How to use the bridge

### 4.1 `tools/host_hardware_android_bridge.py` endpoints (HTTP `:5678` + binary TCP + `adb reverse`)

Purpose: bridge physical hardware (USB VID `0x303A`/PID `0xAE61` or UART Serial CP210x, e.g. `COM7`) to Android emulator/device on port `5678`. Stdlib + optional `cryptography` package; no secrets logged.

Mapping to Android:

- `adb -s emulator-5554 reverse tcp:5678 tcp:5678` (enables `127.0.0.1:5678` inside emulator), or direct `10.0.2.2:5678` from emulator.

Exposed surface (dual HTTP REST + binary TCP on `0.0.0.0:5678`):

| Endpoint | Method | Input | Behavior |
|---|---|---|---|
| `/bridge/info` | GET | — | JSON with connected, transport UART or USB, port, vid_pid, deviceName |
| `/bridge/vendor` | POST | opcode + payload_hex | Wrap into CTAPHID `CMD_MSG (0x83)`, send to hardware, read `[status] + resp_payload`, return ok/status/payload_hex/response_hex |
| `/bridge/ctap` | POST | CTAP/CBOR or PING | Send CTAP/CBOR (`0x90`) or PING (`0x81`), return response bytes |
| `/bridge/pairing_open` | POST | — | Trigger `TEST_PAIRING_OPEN` on hardware; open 60 s host pairing window |
| `/bridge/touch_up` | POST | — | Trigger `TEST_UP` on hardware (software UP touch latch) |
| `/bridge/dump` | GET | — | Read `TEST_LIFETIME_DUMP` from hardware |
| Binary TCP stream | TCP | `[opcode:1B][len:2B BE][payload]` | Renode-compatible: return `[respOp:1B][len:2B BE][status:1B + resp_payload]` |

HEAD `cd22b80` behavior: bridge propagates `NEED_UP` instead of empty lists (callers must surface UP prompt, not success-with-empty).

### 4.2 `tools/host_sdk/cli.py` (host SDK CLI)

- `python tools/host_sdk/cli.py --help` — usage; options `--self-test --demo --port PORT` (default `AEGIS_PORT` or `COM7`); stdlib-only; no hardware touched by help.
- `python tools/host_sdk/cli.py --self-test` — offline checks, no hardware (`framing_roundtrip`, `gates_order`, `tlv_*`, `ota_vectors`, `f3_vectors`, `no_hardcoded_secrets`).
- `python tools/host_sdk/cli.py --demo` — frozen vectors only (wallet_gen op, tlv bytes/hex, ctaphid pkts, port).

### 4.3 E2E harness

- `tools/e2e_harness.py` — needs live device + app/bridge stream (HW-NEEDED; SKIP in host sweeps).
- `tools/e2e_zero_press.py` — needs physical device for zero-press flow (HW-NEEDED).
- `tools/sim_ctap_init.py`, `tools/app_simulator.py` (Session/SerialLink, CBOR codec mirror of harness PinClient/cbor helpers) — host sims; noted in robot as protocol-level emulation, NOT device acceptance.
- `tools/t_display_simulator.py`, `tools/app_path_replay.py` — sims/replay helpers (see tools dir for usage).

### 4.4 Robot

- `python tools/webauthn_robot.py` (add `--only a,b`, `--json-out <file>`). Subsets: `bridge,firmware,ctaphid,totp,emu,unlock,flicker,keypass`.
- Full run: 26/26 PASS, exit 0 (about 15-19 s host-only). No flash/hardware: board treated as unplugged; everything emulated on host.
- Diagnoses inside (read-only, NO FIX by robot lane): UNLOCK root cause = app-layer multi-transport short-circuit + optimistic forge (fixed later by `aa3fa67`); FLICKER = duplicate `collectAsState` inside `LazyColumn` + `LaunchedEffect` reload (fixed later by `aa3fa67` hoist); KEYPASS break point = app Kotlin transport/parse layer or locked guard, NOT bridge parse or firmware assertion.

### 4.5 `run_all` legs

- `python tools/run_all.py --dry-run` — list legs/commands, execute nothing.
- `python tools/run_all.py --leg <name>` — single leg.
- `python tools/run_all.py` — default legs (no release).
- `python tools/run_all.py --release` — include `test-release`.
- `python tools/run_all.py --json-only` — JSON to stdout, skip markdown append (JSON file still written).
- Legs in order: `test-debug` (`cargo test --workspace`), `test-firmware-features` (`-p aegis-fido-firmware --features freertos,proximity`), `clippy` (`--workspace --all-targets -- -D warnings`), `fmt` (advisory, record-only), `deny` (`licenses advisories bans sources`), `dep-track` (`dep_track.py --check`), `docs` (two `docs_lint.py --root` invocations + `reports/**` broken-path scan), `scripts` (every `scripts/*.ps1` existence + `pwsh Parser::ParseFile` SYNTAX-OK, parse only), `test-release` (opt-in).
- Gates: hard = all except fmt (advisory) and SKIP (test-release without `--release`). Usage/safety errors exit 2. `docs-lint` non-strict exit 1 = broken links = docs leg FAIL (hard gate).
- Sealing run (HEAD `62c1f9b`, `2026-11-03T01:06:10Z`, `--release`, exit 0): 8 passed / 0 failed / 1 advisory (fmt) / 0 skipped. Latest dirty-tree run (`2026-11-03T17:21:54Z`, exit 1) fails ONLY on `dep-track` (NEW god `secure_guard_exec/tests.rs` 26.21 from dirty changes) — expected while per-credential UP work is uncommitted; code/test/clippy/deny/docs/scripts/release legs all PASS.
- Machine counterpart: `reports/testing/consolidated-result.json` (overwritten each run). Human sections appended in `CONSOLIDATED_RUN.md` with UTC timestamp.

### 4.6 `dep_track --check`

- `python tools/dep_track.py --check` — exit 2 if NEW god-file (score over 25) outside allowlist exists. Options: `--root ROOT` (default `.`), `--out OUT` (relative to root).
- Rewrites `reports/refactoring/dep-track.json` (owner: godfiles lane; leave as-found if dirty from another lane run).

### 4.7 Capability picker usage

- Interactive: `./scripts/select-capability.ps1` / `./scripts/select-capability.sh` (menu shows includes/excludes + budget, asks confirmation).
- Non-interactive (CI): `./scripts/select-capability.ps1 --cap fido-only --board devkitc --release` (same for `.sh` with `fido-totp`).
- Catalog: `--list-caps` / `--list-pools` (both scripts; generated from same JSON).
- Behavior: builds `cargo +esp build ... --no-default-features --features <board>[,<cap>]` (ttgo preserves release OPT_LEVEL=z), picks board partition layout, converts ELF to `.bin` via esptool, writes `.sha256` sidecar, compares with factory budget (PASS exit 0; overflow FAIL exit 1). Also warns (not blocks) on NVS resident vs storage pools and on OTA staging transient in 2 MB layout. Flash stays manual via `scripts/build-*.ps1 -Flash` (needs board + approval); picker NEVER writes flash. Without toolchain/IDF: exit 2 naming missing piece (`EXTERNAL_BLOCKED`).
- Note: direct `--help` of the `.ps1` in this environment hit a parser quoting issue in the harness invocation, not a gate failure — the `scripts` leg (`Parser::ParseFile` SYNTAX-OK) PASSES. If help text is needed, read the script header or run the `.sh --help` on Linux.

### 4.8 Flashing pattern (scripts), `elf2image`, partition layouts (4 MB vs 2 MB)

- Pattern (per `scripts/common.ps1:Invoke-FirmwareElf2Image` + HARDWARE_JOURNEY): build release ELF, then `esptool --chip esp32s3 elf2image --flash_size 4MB` to `.bin` + `.sha256` sidecar (distinct `-journey-` name for one-off artifacts so shared artifacts are never clobbered), then `esptool --chip esp32s3 --port <PORT> --baud 921600 --before default_reset --after hard_reset write_flash 0x10000 <bin>` (auto-reset via DTR/RTS; no buttons). UART boot log then shows ESP-IDF v5.3.1 2nd-stage bootloader + partition table + `Loaded app from partition at offset 0x10000` + ELF-SHA match + heartbeat USB mounted.
- Layouts:
  - 2 MB physical (devkitc, `crates/aegis-fido-firmware/partitions-2m.csv`): `nvs 0x9000 0x6000`, `phy_init 0xf000 0x1000`, `factory 0x10000 0x180000` (1.50 MiB budget), `storage 0x190000 0x070000` (458752 B / 448 KiB).
  - 16 MB (tdisplay/classic, `partitions.csv`): `nvs 0x9000 0x6000`, `phy_init 0xf000 0x1000`, `factory 0x10000 0x300000` (3 MiB), `storage 0x310000 0x0e0000` (917504 B / 896 KiB).
- `elf2image --flash_size 4MB` is the measurement invocation recorded in `CAPABILITY_DIET.md` (shell-local v5.3.1 toolchain, 2026-11-02).

---

## 5. Capabilities and pools (summary of `CAPABILITY_DIET.md`)

Source of truth: `scripts/capability-catalog.json` (this section mirrors it; costs are estimates except preset totals which are MEASURED).

### 5.1 Presets (alternative roots)

`full` = `default` as today. `cap-*` require `--no-default-features`, are mutually exclusive with each other and with `default` (`compile_error!` in `lib.rs`). Diet refuses `proximity`, `debug-terminal`, `test-mode`, `has-display`, `board-t-display`, `board-ttgo-classic`, `wifi` — diet is devkitc/2MB only.

| Preset | Cargo features | Boards | Measured `.bin` | Factory budget | Status |
|---|---|---|---|---|---|
| full (default) | `board-devkitc` (default) | devkitc | 1.81 MiB (1902288 B) | 1.50 MiB (`0x180000`, 2 MB layout) | OVERFLOW (over 1.5 MB) |
| cap-fido-only (CTAP2/HID pure) | `board-devkitc,cap-fido-only` | devkitc | 1.08 MiB (1128144 B) | 1.50 MiB | PASS within factory |
| cap-fido-totp (+OATH/TOTP) | `board-devkitc,cap-fido-totp` | devkitc | 1.19 MiB (1251632 B) | 1.50 MiB | PASS within factory |

Goal fido-only within 1.4 MB: PASS. tdisplay/ttgo-classic use 16 MB layout (factory `0x300000` = 3 MiB), not measured here.

### 5.2 Caps table (flash costs ESTIMATES: module-source proportional, calibrated on 1902288 B full build; shared modules counted per-cap: DO NOT SUM)

| ID | Feature | Presets | Flash est. | Deps |
|---|---|---|---|---|
| ctap-makecred | always on | full,fido-only,fido-totp | about 141.5 KiB | — |
| ctap-getassert | always on | full,fido-only,fido-totp | about 141.5 KiB | — |
| ctap-clientpin | always on | full,fido-only,fido-totp | about 141.5 KiB | — |
| ccid | always on | full,fido-only,fido-totp | about 7.0 KiB | — |
| piv | always on | full,fido-only,fido-totp | about 62.5 KiB | ccid |
| openpgp | always on | full,fido-only,fido-totp | about 64.6 KiB | ccid |
| oath-totp | `cap-fido-totp` (or full) | full,fido-totp | about 71.4 KiB | wifi-sntp (SNTP optional) |
| oath-hotp | `cap-fido-totp` (or full) | full,fido-totp | shared | oath-totp |
| otp-challenge-response | `cap-fido-totp` (or full) | full,fido-totp | shared | oath-hotp |
| wallet | full only (gated out of `cap-*`) | full | about 24.4 KiB | — |
| vault | full only (gated out of `cap-*`) | full | about 45.8 KiB | — |
| ble | `ble` (off in diet) | full | about 94.9 KiB | vendor-mgmt |
| wifi-sntp | `wifi` (forbidden with `cap-*`) | full | about 76.7 KiB | — |
| display | `has-display` via board-t-display/board-ttgo-classic (forbidden with `cap-*`) | full | about 85.3 KiB | — |
| proximity | `proximity` (forbidden with `cap-*`) | full | about 51.5 KiB | ble |
| vendor-mgmt | always on | full,fido-only,fido-totp | about 42.3 KiB | — |
| debug-terminal | `debug-terminal` (forbidden with `cap-*`) | full | about 6.8 KiB | — |
| test-hooks | `test-mode` (forbidden with `cap-*`) | full | about 2.5 KiB | — |

Rules: fido-only INCLUDES ctap-makecred/getassert/clientpin, ccid, piv, openpgp, vendor-mgmt (wallet/OATH arms answer `0x06`). EXCLUDES oath-totp/hotp, otp-challenge-response, wallet, vault, ble (radio inert), wifi-sntp, display, proximity, debug-terminal, test-hooks. fido-totp = fido-only + oath-totp/hotp + otp-challenge-response (includes NVS time anchor; OATH over USB/BLE real). full = all + wallet + vault + ble + wifi-sntp + display + proximity + debug-terminal + test-hooks. Out-of-preset command returns `UNSUPPORTED_FEATURE` (`0x06`, vendor namespace), fail-closed, never silent drop. TOTP screens show NO_ACCOUNTS, never fake codes.

### 5.3 Pools (NVS resident vs transient)

| ID | Namespaces | Limit | Est. total | Consumed by |
|---|---|---|---|---|
| credential-slots [resident] | `cred/`, `cred/index` | 32 slots x 1024 B | about 34.2 KiB | ctap-makecred |
| oath6 [resident] | `oath6/` | 64 slots x 512 B (no quota index) | about 32.2 KiB | oath-totp, oath-hotp |
| oath6ctr [resident] | `oath6ctr/` | 8 B blobs, label 64 max | about 4.9 KiB | oath-hotp, otp-challenge-response |
| vault-store [resident] | `vault/`, `vault/index` | default 32 slots x 512 B (bound 64) | about 17.6 KiB | vault |
| wallet-stores [resident] | `key_slots_v1`, `keys6/` | 32 slots max | about 7.8 KiB | wallet |
| secureguard-slots [resident] | `sg_record_v1` | 1 record | about 512 B | vendor-mgmt |
| bonding-store [resident] | `ble_store` (controller NVS) | 1 bond | about 2.0 KiB | ble |
| wifi-creds [resident] | `wifi_sta_ssid`, `wifi_sta_pass`, `wifi_ap_pass` | 3 keys | about 512 B | wifi-sntp |
| binding-keys [resident] | `app_bind_pub`, `app_bind_id` | 2 keys | about 128 B | vendor-mgmt, ble |
| ota-staging [transient] | `ota_staging`, `ota_stage_len`, `ota_c*`, `ota_manifest`, `ota_committed` | 8 KiB chunks, budget const 896 KiB | about 896.0 KiB | transient/always |

Budgets: 2 MB layout storage `0x190000 len 0x070000` = 458752 B (448 KiB); 16 MB layout storage `0x310000 len 0x0e0000` = 917504 B (896 KiB). Resident fido-only about 35 KiB (7.8 percent) PASS; full about 102 KiB PASS. OTA staging is TRANSIENT (never added to resident): 917504 B does NOT fit 2 MB storage (WARN: that board needs streaming flow); fits 16 MB.

### 5.4 Evidence (measured, `elf2image --flash_size 4MB`)

| Preset | Bin | Bytes | SHA256 | Date |
|---|---|---|---|---|
| full | `aegis-app-esp32s3-devkitc.bin` | 1902288 | `747691BCA6D67CAB40FF2AADDECAFB2AB5BA5CAA1A12C1E14411E50769F86F40` | 2026-11-02 |
| fido-only | `aegis-app-esp32s3-devkitc-fido-only.bin` | 1128144 | `36CA330DC23CEF56D7716BFE08871D5A0CE562666716D13C555A9B2DCFD188AE` | 2026-11-02 |
| fido-totp | `aegis-app-esp32s3-devkitc-fido-totp.bin` | 1251632 | `55AC03BC49C18C2DB09175BE0D5246B0103CAE369EDB554F79D800F0B0AE9FDC` | 2026-11-02 |

See also header of `partitions-2m.csv` (fido-only size + preset served).

### 5.5 GET_CAPS wire (`0x3F`)

Host discovers preset without guessing: vendor read-only `0x3F` (first free byte after SG `0x3A-0x3E`; full audit in `vendor_exec/vendor_caps.rs` header; machine contract in `capability-catalog.json#wire_contract`). Request empty (non-empty to fail-closed `0x04`). Response `(0x00, CBOR map)`: `fw_version` (text, crate version), `preset` (text `full`/`fido-only`/`fido-totp` via cfg), `caps` (array of text, EXACTLY `presets.<preset>.includes` same IDs/order), `unsupported_count` (uint, vendor ops outside diet answering `0x06`; `0` on full). No auth (read-only, no secrets; same visibility class as `0x38` fw-log over serial). Executed in `exec_vendor_op` BEFORE `authorize_vendor_op` (binding/UP/PIN never consulted). Neighbors (`0x2E`/`0x2F`/`0x3E`/`0x40`) stay `0x04` fail-closed.

| Preset | Caps advertised | `unsupported_count` |
|---|---|---|
| full | 18 (all) | 0 |
| fido-only | 7 (ctap-makecred, ctap-getassert, ctap-clientpin, ccid, piv, openpgp, vendor-mgmt) | 7 (`0x24`-`0x27` OATH + `0x35`-`0x37` wallet) |
| fido-totp | 10 (fido-only + oath-totp, oath-hotp, otp-challenge-response) | 3 (`0x35`-`0x37` wallet) |

Funnel wiring (for transport owners; shared `exec_vendor_op` already serves `0x3F` without auth): serial/legacy include predicate + branch before pairing/UP gate (like `0x38`); BLE dispatch new armless branch (like fw-log with bonded); BLE reassembler accepts `0x3F` as fragment opcode (today only PING/MSG/bind `0x28`-`0x2D`/OTA `0x30`-`0x34`).

---
## 6. Known limitations and BLOCKED items

1. `cargo fmt --check`: BLOCKED pre-existing (28 files at refactor report time; current `run_all` tails show the representative diff in `crates/universal-device-sdk/src/shamir.rs:82` plus, in host sweep, `crypto/curves.rs:106`, `crypto/ecdh.rs:1`, `ctap/extensions_ctap21.rs:42`). Advisory-only in `run_all.py` (record-only, never fails the run alone). Code edits out of scope for tooling/testing lanes — do not fix by reformatting unrelated files.
2. ESP-IDF v6 upstream `bindgen` vs `esp_tinyusb` v2 headers: v6 migration BLOCKED (`sys 0.38.1` bindgen; shims adapted, pending upstream). v5.3.1 pinned. v6.0.3 / `esp-idf-sys` 0.36 compat UNVALIDATED. On-device v6.1 target UNVALIDATED, BLOCKED until physical validation.
3. FIDO certification: PENDING / NOT CLAIMED. Never claim certification until process completes (trademark audit medium REVIEW; absence-of-claim is correct).
4. eFuse: FORBIDDEN to burn without explicit owner order. `EfuseStorage` exposes `is_write_protected` only (no read-protect API; F-03). `efuse_plan.rs` mandates write-protect + operator ack + no-reprovision but has NO `RD_DIS` step. Prod uses keyless `RamEfuseStorage` + loader; `MockEfuseStorage::with_default_keys` is `cfg(test)`-only. NVS holds only AEGN envelopes (AES-256-GCM, HKDF master/salt). Flash dump alone = ciphertext only; physical eFuse readout without read-protect would recover master+salt (documented failure mode).
5. DEV-mode reboot to `ErrorLocked` cycle + recovery-code workflow: recovery envelope now persists outside SecureStorage (`a37051f`) and works across DEV reboot via wrapped KEK (`3a9a3de`). App surfaces true transport label + ErrorLocked recovery UX (`a88bc70`). Recovery uses `<owner-held>` codes — never log, print, or persist them. If device reports `ErrorLocked`, follow recovery UX (provision-confirmed status first, then recovery flow), do not wipe without order.
6. COM7 DTR reboot caveat: flashing/auto-reset uses DTR/RTS (`--before default_reset --after hard_reset`); `esptool chip_id` is read-only (no flash write). UART COM7 at 115200 is CTAPHID-over-serial in legacy builds. DTR-triggered reboots can disturb open sessions — re-INIT after reset; UP latch is 1-shot about 10 s; pairing window 60 s via software `0x2F`.
7. Bridge wedging history: robot diagnosis found app-layer short-circuit (USB throw before BLE/bridge tried; BLE throw even when USB succeeded) + optimistic UNLOCKED forge. Fixed by `aa3fa67` (OR-across-transports, honest state, hoisted collector) + `cd22b80` (NEED_UP propagation). If bridge appears wedged: check transport disagreement (hardware vs host-bridge emulator state), confirm provision status bridge-first (`f253008`), use `touch_up`/`pairing_open` endpoints, and surface `NEED_UP` — do not retry blindly.
8. Emulator limits: `qemu-system-xtensa` NOT on PATH; repo script `scripts/qemu-s3.ps1` is interactive (opens QEMU window, ends on close), no headless flag; binary exists only at fixed path outside repo (not portable) — lane condition (on-PATH + headless repo script, no downloads) not met, so NOT-AVAILABLE. Emulators/sims (`app_simulator.py`, `sim_ctap_init.py`, Renode transport, AVD smoke) are protocol-level emulation, NEVER device acceptance. `validate_aegiskey.py` drops straight into USB CTAPHID battery (needs physical S3 native USB) — HW-NEEDED. Gradle assemble skipped when no app code touched.
9. Trademark leftovers (3 medium REVIEW, no removal performed): VID attribution (present VID as identifier, never authenticator/owned), `dev.aegiskey.app` namespace ownership/store registration, FIDO naming (no certification claim). Plus `Google Authenticator` compatibility wording to prefer generic OATH application text. Owner: docs + web UI maintainers.
10. Other audit residuals (informational, not gates): A-02 exception-message logging (cap/strip to class names), A-03 clipboard envelope export (ciphertext-only; auto-clear + confirm follow-up), F-04 static USB serial identical on all units (derive per-device serial at provisioning; descriptors are identifiers, never authenticators), A-04 simulator transport in main source set (gated; move to debug set follow-up), A-05 pure-Kotlin crypto fallbacks (confirm callers go through `SdkGate`; zeroize transient buffers), J-01 JNI two-call verified robust (trusts caller for pointer/len), F-06 default failure policy is recovery not wipe (high-assurance deployments opt into `wipe_on_5_failures` + `reject_trivial_pins`).
11. Standalone reuse caveats (informational): USB root re-export gap (`CtapHidMessage` has no `to_packet`; framing via `CtapHidFramer`), `no_std` caveat (SDK plus SecureGuard declare `no_std` but `aegis-fido-usb` std-only; bare-metal/ESP reuse UNVALIDATED; evidence desktop std host-only 4/4), SDK `auth`/`envelope` modules private (use root re-exports).
12. `depcheck.py` rewritten to resolve `compile_commands.json` at runtime (`--compile-db` override; exit 2 BLOCKED with guidance when absent). Re-run RC=0. `check-release-clean.py download_mode` false positive proven (rlib metadata only; ack anchored) — re-run exit 0, commit `811ec0d`.

---

## 7. Open threads / next steps

1. Per-credential UP app toggle (UI side) — firmware/working-tree side in-flight (dirty `credential/*`, `cred_store.rs`, `ctap_cmd.rs` + app presence files + `NeedUpPresenceTest.kt`); NOT committed at `cd22b80`. Next: review dirty diff, run affected gates (`cargo test --workspace`, `cargo test -p aegis-fido-firmware --features freertos,proximity`, `cargo test -p aegis-secure-guard -- --test-threads=1`, `python tools/run_all.py`, `python tools/webauthn_robot.py`), then commit per-credential UP as its own commit with report update. App must add/toggle presence UI (`DevicePresence.kt`/`PresenceRequest.kt`) and honor bridge `NEED_UP` (no empty-list success). Do NOT weaken PIN/UP gates to make tests pass.
2. F-01 follow-ups: shorten/lock pairing window; evaluate numeric-comparison or OOB pairing; never claim MITM protection in user docs until implemented + hardware-validated.
3. TOTP dongle gaps: battery behavior and SSD1306 display path (2 MB diet forbids `has-display`; `has-display` only via board-t-display/ttgo-classic). Define expected behavior for display-less presets (NO_ACCOUNTS, no fake codes) + power-loss/NVS anchor cases.
4. Closed-model switch checklist + `orquestrador` identity question — `CLOSED_MODEL_PLAN.md` is DRAFT, NOT EFFECTIVE. Preconditions (all required before any edit): explicit written owner order naming plan + commit range; `orquestrador` identity confirmation recorded (who/when/where); copyright ownership 100 percent or written consent from every external contributor. GPL grants already made are irrevocable for copies conveyed (prospective-only switch). Atomic single-commit switch items 1.1-1.9 (LICENSE swap + `Cargo.toml:17` simultaneity + README spots + ARCHITECTURE-MAP + `deny.toml` re-point + CI deny KEEP + SPDX decision + reports refresh + repo-wide grep sweep) + per-binary attribution bundles + post-commit verification. Do NOT start without preconditions.
5. Physical-device acceptance gaps (NOT claimed by any host lane): real USB CTAPHID against S3, BLE PING/MSG roundtrip, qemu-s3 headless run, OLED/UPN presence ceremony, radio proximity gating, side channels (power/EM/RF), fault injection (voltage/clock/EMFI), brownout/BOD config (no evidence in worktree), eFuse real burn/write-protect/read-protect, OTA BLE MITM during pairing, flash torn-write/NVS wear/rollback beyond mocks, StrongBox/TEE fleet presence, Play Integrity server-side verdict handling.
6. Trademark rewording (docs + web UI owner): Google Authenticator to generic OATH wording (or keep only with permission); confirm `dev.aegiskey.app` ownership/registration; keep FIDO-cert absence until certified.
7. `SimulatedRenodeTransport` move to debug source set; `UiText`-key i18n migration for VM/repo/transport messages; `BiometricGate` KeyStore-bound `CryptoObject` TODO; per-session encryption for `/oath/code` over Wi-Fi; per-device USB serial derivation; clipboard auto-clear + confirm; exception-log capping.
8. Stray `STDOUT` file at repo root + untracked `docs/bench-*.md`, `docs/*freertos*.md`, `docs/proximity-worktree-handoff.md`, `tools/app_path_replay.py` — triage (adopt, move to owned reports, or delete) in owning lanes; this handoff leaves them untouched.
9. `dep-track.json` + `CONSOLIDATED_RUN.md` / `consolidated-result.json` are currently dirty from runs (expected side effects). Owning lanes should commit or revert them deliberately — not as part of this handoff.

---

## 8. Do-not-break rules

- KEEP default: `full` = `default` as today. `cap-*` require `--no-default-features`, are mutually exclusive (`compile_error!`). Never silently change the default preset.
- No eFuse burns without explicit owner order + ack + no-reprovision ritual. No `RD_DIS`/read-protect invention without plan + host test with protect-bit mock + hardware validation.
- No NVS wipe without owner order. Scoped wipe preserves FIDO2 (integration test `test_five_failures_trigger_scoped_wipe_preserving_fido2` must stay green). Full wipe only as authorized last step with verified factory-clean state (UNCLAIMED, PIN unset, vault/OATH empty, resident credentials destroyed, app alive, zero panic lines).
- PIN budget discipline: max 2 wrong in live journeys; 5th failure routes to RecoveryRequired + 15 s rate limit (default `wipe_on_5_failures = false`). Never risk the 5-attempt wipe path casually; `change_pin`/`unlock` backoff must mirror (`compute_backoff_ms` + RateLimited).
- No Mock weakening: no Mock/Fake/Stub in production code (only tests/`cfg(test)`). Bridge/Kotlin fallbacks are deterministic fail-closed paths via `SdkGate` (`ExternalBlocked`, never faked Success); `sanitizeErrorMessage` never leaks JNI internals. Do not weaken gates to make a red build pass — fix the code or record BLOCKED with missing piece.
- Wire-format preservation: elliptic 0.14 migration, UniFFI to C-ABI switch, god splits, and capability diets keep bytes-on-wire identical (Sec1Point same bytes, 22 domain fns byte-identical, CTAPHID 7609 B limits, CBOR shapes). Unknown ops fail closed (`0x01` CTAP / `0x04` vendor / `0x06` diet UNSUPPORTED). Out-of-capability never masks as success.
- Report ownership per area: only touch your lane reports. `dep-track.json` (godfiles lane), `CONSOLIDATED_RUN.md`/`consolidated-result.json` (testing lane), compliance files (compliance lane), `ANDROID_AUDIT.md` (android lane). This handoff adds only `reports/SESSION_HANDOFF.md`.
- After any gate change: run the affected python gate + full `python tools/run_all.py` (and `--release` when promoting), and report both with exact command evidence. There is no `ci/run.py` in this tree — do not invent that path. Keep gates fast with no network calls unless the gate exists for that. Never hardcode machine paths. Never print or persist secrets/keys/tokens/passphrases (patterns only, values never).
- Scripts stay portable (Windows + Linux) with deterministic emoji-free output. Baselines change only with parent approval + written reason. Never weaken a hard gate to make a red build pass.

---

## Appendix A — Commands referenced (copy-paste)

- `git branch --show-current; git rev-parse HEAD; git log --oneline -n 40`
- `git status --porcelain`
- `git log --merges --oneline -n 20; git branch -a`
- `python tools/run_all.py --dry-run`
- `python tools/run_all.py --leg <name>`
- `python tools/run_all.py`
- `python tools/run_all.py --release`
- `python tools/dep_track.py --check`
- `python tools/docs-lint/docs_lint.py --help`
- `python tools/webauthn_robot.py` (subsets bridge,firmware,ctaphid,totp,emu,unlock,flicker,keypass; `--json-out <file>`)
- `python tools/host_sdk/cli.py --help; python tools/host_sdk/cli.py --self-test; python tools/host_sdk/cli.py --demo`
- `adb -s emulator-5554 reverse tcp:5678 tcp:5678`
- `cargo test --workspace`
- `cargo test -p aegis-fido-firmware --features freertos,proximity`
- `cargo test -p aegis-secure-guard -- --test-threads=1`
- `cargo test -p uniffi-bridge -- --test-threads=1`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo deny check licenses advisories bans sources`
- `cargo tree -i uniffi` (must print nothing)
- Capability picker: `./scripts/select-capability.ps1 --cap fido-only --board devkitc --release` (or `.sh --cap fido-totp --board devkitc --release`)

## Appendix B — Report index (read, do not invent)

- `reports/refactoring/FINAL_REFACTOR_REPORT.md` (P0-P7 preservation + post-JNI verdict)
- `reports/testing/FINAL_TEST_REPORT.md` (plus `HEAVY_TEST_REPORT.md`, `ESP32_BUILD_REPORT.md`, `BASELINE.md`)
- `reports/testing/CONSOLIDATED_RUN.md` + `consolidated-result.json` (machine-readable counterpart)
- `reports/testing/ROBOT_RUN.md` (26/26 + UNLOCK/FLICKER/KEYPASS diagnoses)
- `reports/testing/HOST_SWEEP.md` (18 rows + follow-up closures)
- `reports/testing/HARDWARE_JOURNEY.md` (51 PASS / 0 BLOCKED / 2 FAIL-quirk + full wipe)
- `reports/compliance/SECURITY_AUDIT.md` (adversarial audit: 0 critical/high, 4 medium, 4 low, 4 info)
- `reports/compliance/trademark-audit.md`, `license-compatibility.md`, `license-inventory.json`, `sbom.spdx.json`, `third-party-notices.md`, `documentation-audit.md`, `cargo-deny-final.log` (log preserved; `cargo-deny-output.log` NOT modified)
- `reports/refactoring/CAPABILITY_DIET.md` (presets/caps/pools/budgets/GET_CAPS) + `scripts/capability-catalog.json`
- `reports/refactoring/god-files.md`, `UNIFFI_REMOVAL_PLAN.md`, `CLOSED_MODEL_PLAN.md` (DRAFT), `ANDROID_AUDIT.md` (in `reports/refactoring/`)
- `tools/` READMEs (`architecture-analyzer/README.md`, `docs-lint/README.md`) + `--help` outputs (section 4)
- App audit: `reports/refactoring/ANDROID_AUDIT.md`