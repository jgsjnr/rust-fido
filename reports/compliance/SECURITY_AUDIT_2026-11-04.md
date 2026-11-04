# Security Audit — 2026-11-04 (READ-ONLY, host-verifiable only)

- Branch: `fd/finalizacao-linux`
- SHA: `0e957fc41b662aa99b4e63e0c15c2493acc0b6d7` (worktree, 141 modified files uncommitted at audit time)
- Date (UTC): 2026-11-04
- Method: read-only source review (`git grep` / file reads). No code changed, no commit,
  no flash/NVS/wipe/eFuse/secure-boot, no device unlock, no PIN submitted.
- Baseline: `reports/compliance/SECURITY_AUDIT.md` (2026-11-02, SHA `3378633`). This report
  records what changed since, what stayed open, and what is new on this branch.
- Live reads: bridge `http://127.0.0.1:5678/bridge/info` UNREACHABLE (connection refused,
  no device attached). All `0x3A`/`0x38`/`GET_CAPS` evidence below is static (code + tests).
  NENHUM unlock/PIN executado contra hardware.
- Secrets policy: this report echoes NO user secret values. Only hardcoded fallback
  constants that ARE the vulnerability are cited by file:line (never reproduced in full).

## Verdict summary

- CRITICAL: 2 (C-01 shamir deterministic fallback `success=true`; C-02 key-gen synthetic success + default-PIN guess)
- HIGH: 3 (H-01 USB auto-provision after failed unlock; H-02 session-PIN memory lifetime; H-03 eFuse read-protect still absent)
- MEDIUM: 6 (M-01 bench 24 h session; M-02 SoftAP HTTP residual; M-03 BLE MITM C-mirror unverified in-checkout;
  M-04 secure-channel counter-0 on fresh channel; M-05 exception-message logging; M-06 dual change-PIN backoff source)
- LOW: 5 (L-01 simulator in main set; L-02 static USB descriptors; L-03 clipboard exports; L-04 emoji-policy violations; L-05 stale deny-output/SBOM snapshot)
- INFO / verified robust: F-02 fixed, F-05 fixed, A-01 platform fixed, F-01 MITM-required, prod-strict/test-mode exclusion,
  Mock/Fake/Stub production registration PASS (release no-ops), auto-provision gated on confirmed UNPROVISIONED.

## Top 3 risks

1. C-01 Shamir fallback reports `success=true` with compiled-in deterministic shares when the bridge is down.
2. C-02 Key-gen fabricates a success frame and guesses a default PIN when the device denies.
3. H-01 USB transport auto-provisions the Secure Guard after a FAILED unlock attempt.

## 1. Mock / Fake / Stub production registration (AUDIT requirement)

| Provider | Location | Production behavior | Verdict |
|---|---|---|---|
| `DebugHardwareChipMock` (debug) | `app-android/app/src/debug/.../data/debug/DebugHardwareChipMock.kt:22-24` (`IS_MOCK_ENABLED=false` default, `object` debug-only) | Debug source set only, default off | PASS |
| `DebugHardwareChipMock` (release) | `app-android/app/src/release/.../data/debug/DebugHardwareChipMock.kt:15-18` (`const IS_MOCK_ENABLED=false`, all candidates `null`, all ops no-op) | Compiled-out, `isMockCandidate()=false`, `seed/inject/purge` no-ops | PASS |
| `DebugChipControlHooksCard` (release) | `app-android/app/src/release/.../DebugChipControlHooksCard.kt:12-22` | Zero UI, no-op | PASS |
| `SecureGuardRepositoryImpl.mockRoutingEnabled` | `.../data/repository/SecureGuardRepositoryImpl.kt:57-71` (`mockRoutingActive = flag && simulatedTransport != null && BuildConfig.DEBUG`) | Release (`DEBUG=false`) always false; test `tearDown` resets it (`SecureGuardBridgeFirstAndWipeRiskTest.kt`, `TransportSessionLockTest.kt`) | PASS |
| `SimulatedRenodeTransport` | `.../data/transport/SimulatedRenodeTransport.kt:24-59` (main set, deterministic `mockKeys`/`mockOathAccounts`/SG mock `:61-80`) | Instantiated in `AppContainer.kt:103` (lazy) but only ROUTED when mock flag active; never consulted on release path | PASS with residual L-01 (compiled into release APK) |
| `FakeKeyTransport`, `MockSecureGuardRepository`, `StubBridgeServer` | `app/src/test/...` (`CapsQueryTest.kt:41`, `KeyVaultLockCascadeAndCacheTest.kt:111`, `SecureGuardBridgeFirstAndWipeRiskTest.kt`) | Test source set only | PASS |
| `vendorOverride` seam | `KeyVaultRepositoryImpl.kt:73,135-137` (`internal var`, deterministic answers when set) | `internal` test seam; production leaves it `null` per KDoc | PASS (code), ATTENTION: combines with C-02 dummy-success branch below |
| `BindingKey`/`BiometricGate` "Stub"/"Fake" mentions | `BiometricGate.kt:24`, `RecoveryBackup.kt:33` | Comments only ("Stub CryptoObject: null until release binds"; "Fakes so em teste") | PASS (no provider) |
| No-mock baseline | No new `Mock/Fake/Stub/Simulated` provider registered in production routing vs 2026-11-02 baseline; uncommitted diff touches only formatting in `uniffi-bridge` plus core/crypto/ota/store logic, no new mock wiring | No baseline increase | PASS |

## 2. Secrets hygiene (values NOT echoed)

- `git grep -n 'private.?key|BEGIN PRIVATE|AKIA|sk-live|api[_-]?key\s*=\s*["'']'`: hits are field/type names
  (`credential/record.rs:15`, `vault/mod.rs:109`, `crypto/curves.rs:135-182`), test vectors (`[0x5A]`/`[0xA5]`
  in `#[cfg(test)]`), marketing strings, and `MockEfuseStorage::with_default_keys` (`efuse.rs:214-223`,
  `#[cfg(test)]`-only). Production uses keyless `RamEfuseStorage` + loader. No live secret material in repo.
- PIN literals appear ONLY in `#[cfg(test)]`/host-test code (`engine.rs` tests, `transport_lock.rs:325` test,
  `bench/tests.rs`) and in `tools/app_path_replay.py` (`PIN = b"1111"`, host-only replay harness with a comment
  naming it the test PIN). Not echoed further here.
- Recovery codes: `reports/testing/HW_MATRIX.md` redacts (`palavra NN #NNNN`, wordlist `null`, dumps only in
  `%TEMP%`); `SESSION_HANDBOX` states `<owner-held>` policy; `CLICKTHROUGH.md:15,29` records zero-PIN-attempt rule
  and RFC 6238 test vector only. PASS.
- `authToken` memory-only (`@Volatile var`, `HostUsbUartBridgeClient.kt:98-105`); no EncryptedKeysStore persistence found.
- EXCEPTION (is the finding, not a leak): hardcoded deterministic Shamir shares + fixed hex constants in the
  production fallback path — cited by location only, see C-01. No user secret is involved.

## 3. Generated-token drift

- D-01 DRIFT/BYPASS (Critical, = C-01): offline `shamirSplit`/`shamirRecover` return deterministic constants with
  `success=true`, so the app can NEVER distinguish "device quorum" from "fallback fiction". Any stored/displayed
  share set from this path drifts permanently from device truth. Fix with C-01.
- D-02 DRIFT (Medium): app hardcodes `sessionRemainingMs/sessionDurationMs = 300_000L` on unlock/provision
  (`SecureGuardRepositoryImpl.kt:407,573`) while firmware bench extends the session to 24 h
  (`BENCH_SESSION_DURATION_MS = 86_400_000`, `bench/policy.rs:11-14`) and advertises `bench_active` in `0x3A`
  (`secure_guard_exec/status.rs:133-134`). The app badge reads live `benchActive` (`BenchSession.kt:55`), but any
  timeout math using the local constant drifts under bench. Fix: adopt device `session_duration_ms` /
  `session_remaining_ms` from the `0x3A` map instead of the constant when `benchActive=true`.
- D-03 NO DRIFT: `vendor_caps.rs:85-120` capability IDs claim EXACT mirror of `scripts/capability-catalog.json`
  presets; `0x3F` rejects non-empty payload fail-closed (`vendor_caps.rs:26-37`).
- D-04 NO DRIFT: `secure_channel.rs:218-253` binds both ephemeral SEC1 keys into the tag AD; cross-session replay
  test pins rejection (`test_cross_session_replay_rejected_f02`, `:443-470`). Residual M-04 only.

## 4. Zero-emoji scan (policy: none in code, logs, docs, CLI text)

`git grep -n -P '[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}]'` hits (all FAIL vs zero-emoji rule, severity LOW, fix = strip):

- `app-tray/aegis_tray.py:358` (`[check] badge`), `:368` (`[lock] badge`), `:451` (`[fire] wipe btn`), `:466` (`[cycle] reset btn`)
- `app-tray/i18n.py:51,167` (`[lock] vault_locked_banner` EN + PT)
- `app-tray/README.md:62` (`[lock]` in docs)
- `README.md:61` (`[point] ARCHITECTURE-MAP` link)
- `crates/aegis-fido-firmware/src/display/ui.rs:646` (`[point] Pressione BOOT` OLED string — ships in firmware binary)
- `tools/t_display_simulator.py` (17 hits, `:4,:116,:200,:233,:260,:274,:283,:292,:301,:329,:594,:629,:636` — CLI/simulator text)
- `reports/refactoring/ANDROID_AUDIT.md:197-206` (audit table QUOTING the emoji it reports — historical record, keep or reword)

## 5. Findings detail

### C-01 CRITICAL — Shamir fallback fabricates success with deterministic shares

- Evidence: `app-android/.../data/transport/HostUsbUartBridgeClient.kt:900-918` (`shamirSplit`: empty-share or
  HTTP-error path returns `ShamirSplitResult(success=true, shares=generateFallbackShamirShares(), message="...Dev
  deterministic fallback")`); `:921-962` (`shamirRecover`: offline path returns `success=(shares>=2)` with a FIXED
  hex constant); `:1150-1154` (`generateFallbackShamirShares()` deterministic 3-share wordlist).
- Violated invariant: security-result APIs must be fail-closed; `success=true` must imply device authority.
- Failure mode: user backs up / restores from fiction; displayed shares never reconstruct the device seed; silent
  catastrophic backup loss discovered only at recovery time.
- Smallest fix: offline/error path returns `success=false, shares=emptyList()` (+ `recoveredMasterSeedHex=null`);
  delete the deterministic constants from the main source set (move to debug/test if needed for UI previews).

### C-02 CRITICAL — Key-gen fabricates success frame + default-PIN guess

- Evidence: `app-android/.../data/repository/KeyVaultRepositoryImpl.kt:372-376` (on `PIN_REQUIRED`, falls back to
  `lastVerifiedSessionPin ?: "000000"` and sends an unlock attempt with a hardcoded guess); `:411-415`
  (on `PIN_REQUIRED/NEED_PIN/NEED_BINDING/OPERATION_DENIED/null` with any session PIN in memory, returns
  `byteArrayOf(OP, 0x00, slot)` — a SYNTHETIC `STATUS_OK` without touching hardware).
- Violated invariant: never synthesize `STATUS_OK`; never guess PINs; deny fail-closed with a typed presence/PIN error
  (the file itself states this rule at `:396-401` for NEED_UP).
- Failure mode: UI reports key creation that does not exist on device; each auto-guess burns a device retry against
  the 5-attempt wipe/recovery policy; masks binding/presence denials.
- Smallest fix: delete the `:412-415` dummy branch (throw `IllegalStateException`/typed PIN exception instead);
  delete `?: "000000"` (require non-null session PIN or throw `NeedPin`); keep the NEED_UP typed throw as the pattern.

### H-01 HIGH — USB transport auto-provisions after FAILED unlock

- Evidence: `app-android/.../usb/UsbCtaphid.kt:609-628` (Rito 0: on `NEED_PIN/PIN_REQUIRED` with a session PIN,
  sends `0x3B` unlock; if `unlockSt != 0x00` sends `encodeProvisionRequest(pinBytes, null, null)` — provisioning a
  device that just REJECTED the PIN — then fires `0x2F` pairing-open and retries); `:630-668` (Ritos 1-2 auto-fire
  `0x2F TRIGGER_PAIRING_OPEN` on `NEED_BINDING/OPERATION_DENIED/NEED_UP` and poll up to 15 s).
- Contrast (correct pattern): `SecureGuardRepositoryImpl.kt:467-475` auto-provisions ONLY on round-trip-confirmed
  `UNPROVISIONED` via real `0x3A`, never after a failed unlock.
- Failure mode: accidental provisioning/recovery-code rotation on a wrong-PIN device; retry loops mask explicit
  binding/presence denials and burn attempts.
- Smallest fix: remove the `:619-620` provision attempt from the unlock-failure path (provision only via the
  confirmed-UNPROVISIONED flow); require explicit user action before any `0x2F` auto-retry; cap Rito 2 polling.

### H-02 HIGH — Session PIN lives in app memory with device-independent lifetime

- Evidence: `SecureGuardRepositoryImpl.kt:61` (`@Volatile var lastVerifiedSessionPin`), set `:388,553`, cleared on
  lock/detach/transport-loss (`:96-106,113-120,582,739` — good); auto-replayed by `UsbCtaphid.kt:611-612,671-672`
  and `BleKeyTransport.kt:84,133`, and gates vault-cache decryption (`KeyVaultRepositoryImpl.kt:79,106` — good).
- Residual: no app-side expiry bound to `session_remaining_ms`/`inactivity_timeout_ms`; under bench (24 h) the
  in-memory PIN outlives the operator's 5-minute mental model.
- Smallest fix: timestamp the in-memory PIN at unlock and drop it at `min(device session_remaining, inactivity)`;
  single auto-retry per denial (no Rito 0 + Rito 3 double attempt).

### H-03 HIGH — No eFuse read-protect path (F-03 carryover, still open)

- Evidence: `crates/aegis-fido-firmware/src/efuse.rs:23-32` exposes `is_write_protected` only, no read-protect API;
  `efuse_plan.rs:38-51,80-90` mandates write-protect + operator ack + no-reprovision (good) but has no `RD_DIS` step.
  Compensating (verified): NVS holds only AEGN envelopes (AES-256-GCM, key = HKDF(master, salt),
  `persistence.rs:37-53`); `efuse_safety_lock.rs:20` hard-locks ALL writes (`EFUSE_WRITE_HARD_LOCKED=true`, every
  `burn()` fails, host-tested `:396-444`).
- Failure mode: unchanged from baseline — flash dump alone is ciphertext-only; WITH physical eFuse readout,
  master+salt recovery decrypts credentials at rest.
- Smallest fix: add explicit read-protect (`RD_DIS`-equivalent) step to `EfusePlan`/provisioning ritual + host test
  with a mock protect bit (same recipe as the 2026-11-02 recommendation).

### M-01 MEDIUM — Bench 24 h session + WiFi-edge suppression (test-mode-gated, documented)

- Evidence: `secure_guard_exec/bench/policy.rs:11-14,84-88` (24 h `BENCH_SESSION_DURATION_MS` /
  `BENCH_INACTIVITY_TIMEOUT_MS`, RAM-only, NVS untouched, restores on `bench_disable`); `transport_lock.rs:155-212`
  (WiFi active->inactive edge suppressed + 24 h quiescence ONLY when `bench_active`; USB still locks);
  `bench/mod.rs:10-11` (release = no-ops; `prod-strict`+`test-mode` fails compile via `prod_strict_guard.rs`).
  `0x3A` advertises `bench_active` (`status.rs:133-134`) and the app badges it (`BenchSession.kt:55`,
  `guard_bench_badge` = `MODO BANCADA/TESTE`).
- Residual: a bench left ON is a 24 h unlocked window with no WiFi-loss lock and no auto-expiry.
- Smallest fix: auto-expire bench (e.g. require re-arm per unlock or a max-ON timer) + keep `EV_BENCH` audit.

### M-02 MEDIUM — SoftAP HTTP residual (platform layer FIXED since baseline)

- Evidence (fixed): `app-android/app/src/main/res/xml/network_security_config.xml:9-15` (`base-config
  cleartextTrafficPermitted="false"` + allowlist `192.168.4.1/10.0.2.2/127.0.0.1/localhost`); `WifiApi.kt:279-337`
  (`DevicePinning.guard`, HTTPS fail-closed without pins). Prior global `usesCleartextTraffic="true"` is GONE from
  the manifest (now `allowBackup=false`, `exported=true` launcher-only + USB filter, `AndroidManifest.xml:45-67`).
- Residual: SoftAP JSON (`POST /ctap`, `POST /config/wifi`, `GET /oath/code`, `WifiApi.kt:43-155`) still rides HTTP;
  compensating: WPA2 + AES-GCM envelope (`net/ap_core.rs:11`), AP-password change requires UP+PIN
  (`wifi_ap.rs:230-248` test). Keep documented; consider per-session encryption for `/oath/code` over WiFi.

### M-03 MEDIUM — BLE MITM-required mirror not verifiable in this checkout

- Evidence (mirror fixed): `ble/nimble_backend.rs:167-194` (`BLE_SM_MITM_REQUIRED=true`, SC+bonding, no-JustWorks
  fallback, `mitm_repair_notice()`), `ble_nimble.rs:289-301` (host test pins the contract), `ble/oob.rs` (OOB TK
  via `0x42`, MITM never downgraded).
- Residual: the C source (`components/aegis_ble/aegis_ble_nimble.c` `sm_mitm/sm_sc/sm_bonding`) is ABSENT from this
  checkout (`components/` has no `aegis_ble` dir), so the mirror claim is unverified here — confirm `sm_mitm=1` on
  the ESP-IDF lane before closing F-01.

### M-04 MEDIUM — Secure-channel zero-counter acceptance on fresh channel (F-02 fixed, edge remains)

- Evidence (fixed): tag AD binds both ephemeral SEC1 keys (`secure_channel.rs:218-253`), cross-session replay test
  green (`:443-470`).
- Residual: `seal`/`open` (`:275,:310`: `if counter <= last_seen && last_seen != 0`) accept counter `0` on a FRESH
  channel (`last_seen==0` bypass). Smallest fix: require `counter >= 1` (reject `0` even when `last_seen==0`).

### M-05 MEDIUM — Exception-message logging on transport/bridge paths (A-02 carryover, wider surface)

- Evidence: `HostUsbUartBridgeClient.kt:135,220,313,700,720,909,954,1022,1072` (`${t.message}` / `${e.message}` into
  logcat + `DeviceLog` on probe/vendor/HTTP paths); positive: vendor calls log opcode+size only (`:310`), fw-log
  format is `SEQ EV= ARG= T=` with no PII (`fw_log.rs:112-140`).
- Failure mode: host/URL fragments land in `DeviceLog.snapshotText()` (`DeviceLog.kt:47-51`), copyable from Settings
  (`FriendlySettingsAndThemeScreen.kt:1530-1531`, `FriendlySettingsDialogs.kt:1054`).
- Smallest fix: log exception CLASS only (+ `.take(64)`), matching the SanitizedLog fixed-token rule.

### M-06 MEDIUM — Dual change-PIN backoff source (F-05 fixed, desync risk)

- Evidence (fixed): `secure_guard_exec/unlock.rs:18-110,271-321` (own `CHANGE_PIN_BACKOFF_UNTIL_MS` pre-gate reusing
  `compute_backoff_ms`, responds `0x36`+`remaining_ms` like unlock).
- Residual: engine `rate_limit_until_ms` and the static window are TWO sources (static is RAM-only, lost on reboot
  while engine record persists). Smallest fix: persist/arm both from the same event or derive the static window from
  the engine record on boot path (`engine.rs:95-118` restore).

### L-01 LOW — Deterministic simulator ships in main source set (A-04 residual)

- Evidence: `SimulatedRenodeTransport.kt:44-80` demo keys/accounts + SG mock compiled into release APK; routing is
  correctly gated (see table §1). Smallest fix: move to the debug source set (no behavior change).

### L-02 LOW — Static USB descriptors (F-04 carryover)

- Evidence: `usb_descriptors.rs:17-24` VID `0x303A`/PID `0xAE61`, `SERIAL_NUMBER_STRING="AEGIS-S3-0002"` identical per
  unit; `device_filter.xml` allowlists three VID/PID pairs (AegisKey + OTG PHY + CP2102 bridge). Smallest fix:
  per-device serial from eFuse/salt at provisioning; document descriptors as identifiers, never authenticators.

### L-03 LOW — Clipboard exports of sensitive-equivalent material

- Evidence: `KeyDetailSections.kt:883` (`onCopy(exportedEnvelope)` AEGN hex); `FriendlySettingsAndThemeScreen.kt:941-942,
  1618-1619` + `EfuseSafetyNoticeMolecule.kt:362-364` (Shamir share copy); `strings.xml:704`
  (`set_phrase_copied` recovery-phrase copy); compensating: envelope is ciphertext, shares are quorum-gated.
  Smallest fix: auto-clear clipboard after timeout + confirm dialog noting sensitivity.

### L-04 LOW — Emoji-policy violations (§4 table; smallest fix = strip to text glyphs)

### L-05 LOW — Compliance snapshots stale vs current worktree

- Evidence: `reports/compliance/cargo-deny-final.log` = PASS exit 0 post-RUSTSEC-2026-0387 (p256/k256 0.13->0.14,
  uniffi removal pruned 34 pkgs, zero MPL, only duplicate-version warnings) BUT the committed
  `cargo-deny-output.log` is the PRE-migration snapshot (wildcard errors + RUSTSEC-2026-0387 vuln text);
  `sbom.spdx.json` predates the lane deltas (26 stale pre-0.14 elliptic rows noted in final.log); human legal
  review still pending (14 crates). Smallest fix: regenerate output.log + SBOM at release cut; keep legal-review
  gate (no PASS claim).

## 6. Verified robust (checked, no finding)

- PIN retry/lockout/wipe/rate-limit enforced device-side (`aegis-secure-guard/src/engine.rs:438-577,698-739`;
  5th failure -> RecoveryRequired + 15 s rate limit or wipe per policy; `MAX_ATTEMPTS=5`); reboot restores
  `failed_attempts` + rate-limit (`:95-118`); `change_pin` backoff added (M-06 residual only).
- `prod-strict` + `test-mode` mutually exclusive at compile time (`prod_strict_guard.rs:12-16`); TEST commands
  (`TEST_UP/DOWNLOAD/USB_RECONNECT/PAIRING_OPEN/.../BENCH_ON/OFF/OTA_COMMIT_HOOK`, `test_hooks.rs:19-44`) and
  `TEST_BENCH`/`TEST_PAIRING`/`TEST_OTA` handlers all `#[cfg(feature="test-mode")]` (`serial_text.rs`,
  `pairing.rs:238-319`, `ota.rs:511-589`, `nvs_backend.rs:181-186` dev-keys); tripwire test pins manifest<->docs.
- `GET_CAPS 0x3F` + `fw-log 0x38` read-only pre-gate, no auth, no secrets (`vendor_caps.rs:33-35`, `fw_log.rs:4-5`,
  `dispatch_bind.rs:128-141`); serial physical possession = free is documented and consistent.
- Gates canonical binding->UP->PIN: usage (LIST/CODE) UP-only (`dispatch_bind.rs:83-88`); config GEN/IMPORT/DELETE/PUT
  binding+UP+PIN as applicable (`:89-102`, `vendor_op_requires_pin`); wallet binding+UP (`:109-126`); PIV enroll
  `0x39` binding+UP no PIN on virgin device (`vendor_dispatch.rs:38-51`, `vendor_piv.rs`); recovery SET `0x2C` UP,
  UNLOCK `0x2D` UP+PIN->wipe+reclaim (`dispatch_bind.rs:247-264`); OATH atomic increment-before-use + torn-write
  fail-closed (`oath_cmd.rs:4-24,134-155`); PIV 6-8B PIN/8B PUK, 3 tries each, salted SHA-256, zeroized
  (`piv_cmd.rs:230-342`).
- UP bound to operation hash with window + replay/wrong-op/expiry denial (`up_policy.rs:49-103`).
- Transport lock fail-closed with RAM-only session wipe, no secret in log (`transport_lock.rs:251-304`,
  `EV_TRANSPORT_LOCK` channel-only arg); BLE disconnect/USB detach force LOCKED app-side
  (`SecureGuardRepositoryImpl.kt:76-120`, `TransportSessionLock.kt:71-84`).
- Zeroize on all reviewer paths: engine verifiers/salts (`engine.rs:461,512,633,675,903,957,1060,1200,1238-1271`),
  binding RAM (`binding.rs:237-248`), vault seal keys + nonces (`EncryptedKeysStore.kt:195,232`), sealed cache
  bound to `hardwareBinding` + AAD (`:185-238`), memory vault cleared on lock/detach (`KeyVaultRepositoryImpl.kt:100-133`).
- `allowBackup=false`, no WebView/JS bridge, `MainActivity` exported launcher + USB-attach only, no deep links/intent
  parsing; BLE permissions minimal (SCAN neverForLocation + CONNECT, no LOCATION/ADVERTISE, manifest header comment);
  `PendingIntent.FLAG_MUTABLE` remains the documented platform requirement (prior audit, unchanged).
- `0x2F`/`0x40` opcode-collision guards intact (`vendor_caps.rs:26-37`).

## 7. NOT VERIFIED (needs hardware/lab)

1. Side channels (power/EM/RF) of AES/P-256/PBKDF2 on ESP32-S3. 2. Real fault injection / BOD config (no BOD evidence
   in checkout). 3. eFuse real burn/write-protect/read-protect (H-03). 4. OTA link MITM during SoftAP leg (M-02).
5. Flash torn-write wear/rollback beyond host mocks. 6. StrongBox/TEE + server-side Play Integrity verdict handling.
7. `sm_mitm=1` in the C NimBLE source (M-03 — source absent here).

## 8. Supply chain

- `deny.toml` (GPL-3.0-only + explicit CC0/Unlicense/Unicode/BSL allows, `REVIEW-HUMANO-PENDENTE`, bans/wildcard-deny,
  unknown-registry/git deny): unchanged and sound. `cargo-deny-final.log` (this lane): PASS exit 0,
  licenses+advisories+bans+sources. Committed `cargo-deny-output.log`: STALE pre-migration snapshot — regenerate.
- `sbom.spdx.json` (SPDX 2.3) + `license-inventory.json` + `third-party-notices.md` present; SBOM deltas (uniffi -34,
  0.14-stack +36) noted but not yet regenerated — L-05.
- `Cargo.lock` + `reports/refactoring/dep-track.json` modified in worktree (uncommitted); no new external registry.

## 9. Live-read annex (read-only, no unlock)

- `GET http://127.0.0.1:5678/bridge/info` -> connection refused (no bridge/device). No `0x3A`/`0x38`/caps bytes
  captured this lane; no PIN/unlock/recovery operation attempted. All transport claims above are code-evidence with
  file:line, not device observations.

## Counts

- CRITICAL 2 | HIGH 3 | MEDIUM 6 | LOW 5 | INFO 0. Worktree SHA `0e957fc`.
- Prior baseline deltas: FIXED since 2026-11-02: F-02 (session-bound tags), F-05 (change-PIN backoff), A-01 platform
  (scoped networkSecurityConfig), F-01 mirror (MITM-required + OOB). STILL OPEN: F-03/H-03 (read-protect), A-02/M-05
  (exception logging), A-03/L-03 (clipboard), F-04/L-02 (descriptors), A-04/L-01 (simulator in main).
- NEW on this branch: C-01, C-02, H-01, H-02, M-06, L-04 (emoji scan), D-02 (bench/app session drift).
