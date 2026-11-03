# GO / NO-GO — 1.0.0-wave (verdict of record: run 2)

- HEAD at verdict: `eeb3e93 feat(firmware): dedicated SIGN opcode 0x41`
  (frozen after HEAD unchanged for 5+ min; lane commits observed before freeze:
  `cd22b80` -> `db8a120` -> `b4f9077` -> `eeb3e93`).
- Verdict: **NO-GO (RED)**. Blocker: `dep-track` gate FAIL, exit 2.
- No gate was weakened to make anything pass. No code, config, firmware, or
  other report was edited in this lane.

## Per-gate verdicts — final run (2026-11-03T18:14:09Z, release=on)

| leg | advisory | status | exit | duration_s |
|---|---|---|---|---|
| test-debug | no | PASS | 0 | 21.7 |
| test-firmware-features | no | PASS | 0 | 26.0 |
| clippy | no | PASS | 0 | 0.9 |
| fmt | yes | PASS | 0 | 1.3 |
| deny | no | PASS | 0 | 30.4 |
| dep-track | no | FAIL | 2 | 0.4 |
| docs | no | PASS | 0 | 0.2 |
| scripts | no | PASS | 0 | 11.7 |
| test-release | no | PASS | 0 | 63.9 |

- Summary: passed=8 failed=1 advisory_failures=0 skipped=0, RESULT: FAIL.
- `dep-track` evidence: `wrote reports/refactoring/dep-track.json
  (252 files, 24 gods)`; NEW god-files (score>25, not in allowlist):
  `27.92 crates/aegis-fido-firmware/src/secure_guard_exec/tests.rs
  (lines=1442 fan_in=0 fan_out=9)` and
  `25.90 crates/universal-device-sdk/src/providers/oath.rs
  (lines=40 fan_in=30 fan_out=7)`.
- Prior run for the record (2026-11-03T17:21:54Z, HEAD `cd22b80`,
  MARKED POTENTIALLY CONTAMINATED — firmware lane editing mid-run, not used
  for the verdict): 7 PASS + `dep-track` FAIL exit 2 (`tests.rs` 26.30,
  lines=1280) + `fmt` advisory FAIL. Note god growth across runs
  (26.30 -> 27.92, lines 1280 -> 1442) tracks active lane development.

## Hardware proofs (provenance, not re-validated here — no device in this lane)

- HARDWARE_JOURNEY 2026-11-02 (HEAD `a379cf5`): detect PASS (COM7 + native
  USB VID 0x303A/PID 0xAE61); release ELF build PASS; elf2image PASS
  (1899056 B, SHA256 `535C4AAA…`); flash+boot PASS (ESP-IDF v5.3.1,
  no panic, SecureGuard up); journey create/get/delete PASS, TOTP vs RFC
  vectors PASS (755224/287082), assert counter+1 PASS, PIN attempts PASS
  (1 wrong -> `0x31`, correct -> `0x00`, no lockout); SG lock/unlock/wipe over
  UART BLOCKED by composition (legacy loop lacks `0x3A-0x3E` dispatch);
  LAST full wipe with PIN `1111` PASS, verified factory-clean. Quirks:
  `getRetries` -> `0x14` once PIN set; keyAgreement COSE_Key under map `0x01`.
- ROBOT_RUN 26/26 PASS (host-emulated, `fd/finalizacao-linux`, 2026-11-02).
- HOST_SWEEP follow-ups closed: depcheck rewritten (runtime compile-db
  resolution), `download_mode` release finding proven false positive,
  `vendor_tests` god split (commits `3f24bd0`, `811ec0d`, `44b7570`).
- Fresh APK rebuild (this lane, build-only): BUILD SUCCESSFUL, SHA256
  `D487E292…` (see RELEASE_NOTES.md).

## Residual risks

- Verdict rendered with the tree dirty (below): all green legs also ran on
  uncommitted code. A clean-tree re-run is required before any GO.
- `fmt` PASS in run 2 rode on uncommitted formatting changes; committed code
  remains unformatted (advisory only, but honest state).
- Hardware proofs are stale (older HEADs) and SG-over-UART remains
  composition-blocked in the legacy loop.
- No FIDO certification; ESP-IDF beyond v5.3.1 unvalidated; DEV eFuse caveat
  (unburned boards, wrapped-KEK recovery, else reboot -> reprovision).

## Explicit NO-GO items

1. `dep-track` GATE FAIL (exit 2): two NEW god-files above the 25-point
   allowlist bar. Needs allowlist update with written reason (parent) or god
   split (code lane) — neither is this lane to do.
2. Verdict-on-dirty-tree: 63 uncommitted entries from other active lanes at
   run time (list below). Re-verify on a clean tree before any GO.
3. Firmware `.bin` identity unresolved: expected prefix `620D611E…` matches
   nothing in the repo; on-disk `dist` bin (`13C894FB…`) vs catalog full
   (`747691BC…`) provenance unconfirmed.
4. Committed code unformatted (`fmt` run-2 PASS is tree-dirt, not HEAD state).
5. No FIDO cert; ESP-IDF v5.3.1-only validation; DEV eFuse caveat stands.

## Working-tree state at verdict freeze (HEAD `eeb3e93`, uncommitted, other lanes)

M crates/aegis-fido-core/src/crypto/curves.rs
M crates/aegis-fido-core/src/crypto/ecdh.rs
M crates/aegis-fido-core/src/ctap/extensions_ctap21.rs
M crates/aegis-fido-core/src/ctap/get_assertion.rs
M crates/aegis-fido-core/src/lib.rs
M crates/aegis-fido-core/src/otp/challenge_response.rs
M crates/aegis-fido-core/src/otp/legacy_otp_compat.rs
M crates/aegis-fido-core/src/otp/mod.rs
M crates/aegis-fido-core/src/vault/mod.rs
M crates/aegis-fido-core/src/wallet/clear_signing.rs
M crates/aegis-fido-core/src/wallet/shamir_slip39.rs
M crates/aegis-fido-firmware/src/binding.rs
M crates/aegis-fido-firmware/src/ble/nimble_backend.rs
M crates/aegis-fido-firmware/src/ble_nimble.rs
M crates/aegis-fido-firmware/src/crypto_aead.rs
M crates/aegis-fido-firmware/src/crypto_rsa.rs
M crates/aegis-fido-firmware/src/efuse_safety_lock.rs
M crates/aegis-fido-firmware/src/freertos_route.rs
M crates/aegis-fido-firmware/src/freertos_sched.rs
M crates/aegis-fido-firmware/src/hmac_cr_compat_layer.rs
M crates/aegis-fido-firmware/src/lib.rs
M crates/aegis-fido-firmware/src/migrations/mod.rs
M crates/aegis-fido-firmware/src/net/ap_core.rs
M crates/aegis-fido-firmware/src/net/http_front.rs
M crates/aegis-fido-firmware/src/net/mdns.rs
M crates/aegis-fido-firmware/src/net/station.rs
M crates/aegis-fido-firmware/src/oled_ssd1306_code_only.rs
M crates/aegis-fido-firmware/src/pairing_led.rs
M crates/aegis-fido-firmware/src/prod_strict_guard.rs
M crates/aegis-fido-firmware/src/psram_public_alloc.rs
M crates/aegis-fido-firmware/src/run/common.rs
M crates/aegis-fido-firmware/src/run/mod.rs
M crates/aegis-fido-firmware/src/run/run_loop_freertos.rs
M crates/aegis-fido-firmware/src/run/run_loop_legacy.rs
M crates/aegis-fido-firmware/src/secure_guard_exec/config.rs
M crates/aegis-fido-firmware/src/secure_guard_exec/dispatch.rs
M crates/aegis-fido-firmware/src/secure_guard_exec/lock.rs
M crates/aegis-fido-firmware/src/secure_guard_exec/mod.rs
M crates/aegis-fido-firmware/src/secure_guard_exec/status.rs
M crates/aegis-fido-firmware/src/secure_guard_exec/tests.rs
M crates/aegis-fido-firmware/src/secure_guard_exec/unlock.rs
M crates/aegis-fido-firmware/src/secure_guard_exec/wipe.rs
M crates/aegis-fido-firmware/src/secure_guard_storage.rs
M crates/aegis-fido-firmware/src/time_sync.rs
M crates/aegis-fido-firmware/src/totp_view.rs
M crates/aegis-fido-firmware/src/vendor_exec.rs
M crates/aegis-fido-firmware/tests/applets_t9.rs
M crates/aegis-fido-firmware/tests/migration_tests.rs
M crates/aegis-fido-firmware/tests/namespaced_store_t5.rs
M crates/aegis-fido-firmware/tests/secure_guard_integration.rs
M crates/aegis-secure-guard/src/crypto.rs
M crates/aegis-secure-guard/src/engine.rs
M crates/aegis-secure-guard/src/glitch_guard.rs
M crates/aegis-secure-guard/src/resource.rs
M crates/uniffi-bridge/src/ffi.rs
M crates/uniffi-bridge/src/lib.rs
M crates/universal-device-sdk/src/clear_signing.rs
M crates/universal-device-sdk/src/ctap21.rs
M crates/universal-device-sdk/src/lib.rs
M crates/universal-device-sdk/src/secure_channel.rs
M crates/universal-device-sdk/src/secure_guard.rs
M crates/universal-device-sdk/src/shamir.rs
M tools/e2e_harness.py
M tools/host_hardware_android_bridge.py
?? tools/app_path_replay.py