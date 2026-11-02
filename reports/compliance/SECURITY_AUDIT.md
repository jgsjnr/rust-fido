# Adversarial Security Audit (read-only, host-verifiable only)

- Branch: refactor/standalone-architecture-cleanup
- SHA: 337863349de241807bba1ffde86461db9e815c22
- Date (UTC): 2026-11-02
- Method: read-only review plus host-run test suites. No hardware, no flash,
  no device, no network attacks, no destructive commands, no secret material.
- Report file only: reports/compliance/SECURITY_AUDIT.md
## Host test evidence (commands run in worktree, all passed)

1. cargo test -p aegis-secure-guard => 41 passed, 0 failed.
   Covers: PIN provision/verify, 5-failure wipe and recovery paths,
   persistence + reboot restore, session absolute/inactivity expiry,
   lock/transport-disconnect, critical-action PIN gate, BLE proximity lock,
   ECDH handshake roundtrip, tampered-tag reject, replay-counter reject,
   glitch-guard patterns.
2. cargo test -p aegis-fido-firmware --features freertos,proximity
   => lib 562 passed / 0 failed / 4 ignored; integration suites
   12 + 2 + 3 + 14 + 16 + 8 + 11 + 2 passed, 0 failed.
   Covers: secure-guard lifecycle + scoped wipe preserving FIDO2, proximity
   replay/ctr/interop truth tables, namespaced store, ota/key provider,
   freertos tasks, migration, applets.
3. Grep sweeps: secrets/keys/URLs, Log.*, WebView/JS bridges,
   manifest/exported, unsafe/SAFETY, mitm/JustWorks/bond, BROWNOUT/BOD,
   with_default_keys, IS_MOCK_ENABLED, authToken, BLE SM flags.

## Findings detail

### A-01 MEDIUM - Cleartext HTTP transport, global opt-out (host proximity, no physical)
- Violated invariant: sensitive traffic (CTAP envelopes, TOTP codes,
  PIN-authenticated sessions, WiFi password PUT) must not cross an
  unencrypted L3 in a globally-enabled way.
- Evidence: AndroidManifest.xml:50 `usesCleartextTraffic="true"`;
  WifiApi.kt:30 `DEFAULT_BASE_URL = "http://192.168.4.1"`, :35 fallbacks
  `http://10.0.2.2:5678`, :243-255 `open()` only pins HTTPS, plain HTTP
  passes with no extra protection; OtaApi.kt:85 `isHttp` accepts `http://`,
  :229/:487 absolute-URL passthrough; HostUsbUartBridgeClient.kt:37
  candidate hosts are `http://` loopback/emulator URLs.
- Compensating controls (verified): SoftAP is WPA2 + AES-GCM envelope
  (firmware `net/ap_core.rs:11`); AP password change requires UP + PIN
  (`wifi_ap.rs:230-248` test); HTTPS is fail-closed without pins
  (WifiApi.kt:289-293); OTA image has sha256 + device-side Ed25519 check.
- Failure mode: anyone holding the AP credential (or during an open
  provisioning window) can passively sniff CTAP/TOTP/PIN-session traffic
  or MITM the OTA manifest leg (image substitution still fails at the
  device signature check; DoS/downgrade-attempt remains).
- Fix (smallest): replace global `usesCleartextTraffic="true"` with a
  `networkSecurityConfig` that cleartext-permits only `192.168.4.1`,
  `10.0.2.2`, `127.0.0.1`; document AP-credential provisioning; consider
  per-session encryption for `/oath/code` over WiFi.

### F-01 MEDIUM - BLE pairing is JustWorks, MITM flag off (proximity + pairing window)
- Violated invariant: link-layer pairing should resist active MITM, or the
  gap must be explicit with compensating controls.
- Evidence: components/aegis_ble/aegis_ble_nimble.c:545-552 -
  `sm_io_cap = NO_INPUT_OUTPUT`, `sm_bonding = 1`, `sm_mitm = 0`,
  `sm_sc = 1`, ENC key distribution both ways; comment states
  "Sem MITM/passkey ... nesta etapa" (acknowledged, not accidental).
- Compensating controls (verified): Secure Connections + bonding with ENC
  keys; app-layer ECDSA binding claim/challenge (`ble_gatt.rs:266-319`
  tests); UP-per-operation; pairing window gate
  (`ble_nimble.rs:120-264` tests).
- Failure mode: active attacker present inside the pairing window can MITM
  the GATT link (read/inject). Cannot forge binding signatures without the
  app private key, but can relay traffic and DoS pairing.
- Fix (smallest): keep as documented known limitation; shorten/lock the
  pairing window, and evaluate numeric-comparison or OOB pairing in a
  follow-up; do NOT claim MITM protection in user-facing docs.

### F-02 MEDIUM - SecureChannel counter resets per handshake, cross-session replay (protocol, no physical)
- Violated invariant: an authenticated frame captured in session N must not
  verify in session N+1.
- Evidence: secure_channel.rs:138-166 `complete_handshake` resets
  `last_seen_counter = 0`; seal (:215-219) and open (:250-252) enforce
  `counter <= last_seen && last_seen != 0`, so a FRESH channel
  (`last_seen == 0`) accepts any counter including a replayed one.
- Failure mode: captured (ciphertext, tag, nonce, counter) sealed-PIN frame
  from an old ECDH session is accepted after a re-handshake if the
  attacker can trigger one and the counter is not already consumed.
- Fix (smallest): bind the session into the tag AD (e.g. hash of both
  ephemeral public keys) or start `last_seen_counter` from a fresh TRNG
  base per handshake and require strictly-greater counters.
### F-03 MEDIUM - No eFuse read-protect path (needs physical)
- Violated invariant: the hardware root that decrypts a flash dump must be
  locked against readout, not just against rewrite.
- Evidence: efuse.rs:24-33 `EfuseStorage` exposes `is_write_protected`
  only, no read-protect API; efuse_plan.rs:43-90 mandates write-protect +
  operator ack + no-reprovision (good) but has no RD_DIS step.
- Compensating controls (verified): NVS holds only AEGN envelopes
  (AES-256-GCM, key = HKDF(master, salt), persistence.rs:37-53); envelope
  framing + zero-nonce + oversize rejects are host-tested.
- Failure mode: flash dump alone yields ciphertext only (safe). With
  physical eFuse readout (no read-protect enforced in code), master + salt
  recovery decrypts all stored credentials at rest.
- Fix (smallest): add an explicit read-protect (`RD_DIS`-equivalent) step
  to `EfusePlan` / provisioning ritual and assert it in a host test with a
  mock that models the protect bit.

### A-02 LOW - Exception-message logging on transport paths (host, no physical)
- Violated invariant: logs must carry fixed tokens only, never peer- or
  transport-influenced strings.
- Evidence: HostUsbUartBridgeClient.kt:135 logs `${t.message}` from probe
  failures; :673/:693 same pattern on SecureGuard HTTP paths. (Positive:
  OtaApi/DeviceLog/SanitizedLog otherwise log codes/sizes/names only.)
- Failure mode: low-sensitivity host/URL fragments can land in DeviceLog,
  which is copyable from Settings via `snapshotText` (DeviceLog.kt:47-51).
- Fix (smallest): cap with `.take(64)` and strip to exception class names,
  matching the SanitizedLog fixed-token rule.

### A-03 LOW - Clipboard export of AEGN envelope hex (host, no physical)
- Violated invariant: export flows must minimize cleartext-equivalent
  lifetime on shared surfaces.
- Evidence: KeyDetailManagementScreen.kt:1089-1114 `onCopy(exportedEnvelope)`
  copies the exported envelope hex to the clipboard.
- Compensating: envelope is ciphertext (key never leaves device/vault
  flow), so exposure is ciphertext-only.
- Fix (smallest): auto-clear the clipboard after a timeout + add a confirm
  dialog noting the envelope is sensitive ciphertext.

### F-04 LOW - Static shared USB serial + Espressif VID (host, no physical)
- Violated invariant: descriptors should not make every unit trivially
  trackable/cloneable by VID/PID/serial alone.
- Evidence: usb_descriptors.rs:17-18 VID 0x303A / PID 0xAE61; :24
  `SERIAL_NUMBER_STRING = "AEGIS-S3-0002"` identical on all units.
- Failure mode: cross-host tracking of the device; counterfeit hardware can
  clone descriptors byte-for-byte, so host allow-listing by VID/PID/serial
  is not authentication (binding/auth is, and is enforced app-side).
- Fix (smallest): derive per-device serial from eFuse/device salt at
  provisioning time; document that descriptors are identifiers, never
  authenticators.

### F-05 LOW - change_pin failure path has no backoff (protocol, no physical)
- Violated invariant: every PIN oracle must apply the same failure policy.
- Evidence: engine.rs:880-886 increments `failed_attempts` and returns
  `InvalidPin` with no backoff/RateLimited, unlike unlock (:507-562) and
  critical-action (:670-727) paths.
- Compensating: the shared counter still feeds the 5-attempt
  wipe/recovery policy on the unlock path.
- Fix (smallest): apply `compute_backoff_ms` + RateLimited transition in
  `change_pin` exactly as the unlock path does.
### A-04 INFO - Simulator transport ships in main source set (gated, defense in depth)
- Evidence: SimulatedRenodeTransport.kt:17-53 (main set) seeds
  deterministic demo keys/OATH accounts; release mock is a const-false
  no-op (release/.../DebugHardwareChipMock.kt:15-23); SIMULATOR connect
  throws in production when mocks are off
  (PairingWizardRepositoryImpl.kt:258-263); single-touch/hold helpers are
  mock-gated (:205-227).
- Residual: deterministic mock key material is compiled into the release
  APK even though unreachable. Fix: move `SimulatedRenodeTransport` to the
  debug source set. No behavioral change implied.

### A-05 INFO - Pure-Kotlin crypto fallbacks when native lib is absent
- Evidence: AegisBridge.kt:56-80 `nativeLoaded` + per-call fallbacks
  (constants, envelope seal/open, PBKDF2 app-lock). SdkGate correctly maps
  missing native lib to `ExternalBlocked` (SdkGate.kt:70-82), never a
  faked Success.
- Residual: confirm every security-relevant caller goes through SdkGate and
  that fallback paths zeroize transient buffers (`wipe`, :326) as the Rust
  side does. No change implied by this audit.

### J-01 INFO - JNI two-call protocol verified robust (checked, no finding)
- Evidence: ffi.rs:88-157 - NULL/len discipline (`len == 0` = empty),
  `BUFFER_TOO_SMALL` with required size, UTF-8/JSON rejection, caps
  `MAX_FRAGMENT_BYTES`/`MAX_PLAINTEXT_BYTES`/`MAX_ENVELOPE_BYTES`
  (lib.rs:35-98), all-zero-nonce reject (:269-273); SAFETY rationale
  present at all 5 unsafe sites (:99,:114,:126,:138,:152).
- Residual (inherent to any C ABI): trusts the JNI caller for
  `ptr..ptr+len` readability; documented in the contract header (:12-41).
  No change.

### F-06 INFO - Default failure policy is recovery, not wipe (documented behavior)
- Evidence: policy.rs:39-54 defaults `wipe_on_5_failures = false`,
  `reject_trivial_pins = false`, min 4 / max 16; 5th failure routes to
  RecoveryRequired + 15 s rate limit (engine.rs:519-540); unprovisioned
  engine accepts FIDO-standard flow without PIN by design (:736-738).
- Action: high-assurance deployments should opt into
  `wipe_on_5_failures` + `reject_trivial_pins`. No code change implied.

## Verified robust (checked, no finding)

- No hardcoded secrets/keys/URLs in app or crates: grep for
  api_key/secret/privateKey/BEGIN PRIVATE/AKIA/sk-live found only
  res/strings marketing copy, `secretBase32` field names, and test
  fixtures (`[0x5A]`/`[0xA5]` patterns in `#[cfg(test)]` code);
  `MockEfuseStorage::with_default_keys` is `#[cfg(test)]`-only
  (efuse.rs:214-223); prod uses keyless `RamEfuseStorage` + loader.
- No WebView / JS bridge in app (grep: zero hits).
- `MainActivity` exported=true is launcher + USB_DEVICE_ATTACHED only
  (AndroidManifest.xml:51-66); `onNewIntent` is inert (`setIntent`);
  no deep links, no intent data parsing => no intent-spoofing surface.
- `allowBackup="false"` + `fullBackupContent="false"` (manifest :46-47);
  secrets live in EncryptedSharedPreferences / device NVS, never backup.
- PIN retry/lockout/wipe path enforced device-side (engine.rs) and
  host-tested (41 secure-guard + 2 integration tests, all green).
- `PendingIntent.FLAG_MUTABLE` (UsbCtaphid.kt:272-278) is the documented
  platform requirement for `UsbManager.requestPermission` on API 31+
  and the intent is explicit via `setPackage` => checked, not a finding.
- Global screenshot shield via FLAG_SECURE (AppSecurity.kt:127-134),
  disabled only in debug/QA by design.
- `NotCompiled` vs `Unavailable` kept honest: capability-bit gate
  (SdkGate.kt:70-82), bridge errors mapped without synthetic success
  (:110-125), unknown wire status => Unsupported fail-closed (:134-142).
- `HMAC-CR` compat FFI (hmac_cr_compat_layer.rs:149-153) null-checks all raw
  pointers and caps challenge at 64 B.
- PlayIntegrity polling loop is bounded (15 s timeout, 100 ms delay,
  fail-closed to `Failed("timeout")`, AppSecurity.kt:200-224).
- `authToken` is memory-only (`@Volatile var`, HostUsbUartBridgeClient
  :97-105); no persistence found in EncryptedKeysStore grep.

## NOT VERIFIED (cannot be checked from host; needs hardware/lab)

1. Side channels: power/EM/RF leakage of AES/P-256/PBKDF2 on ESP32-S3.
2. Real fault injection: voltage/clock/EMFI behavior; brownout (BOD)
   configuration - no BOD/brownout evidence found anywhere in worktree.
3. eFuse real burn, write-protect fusing, and any read-protect (F-03).
4. Over-the-air BLE MITM during pairing (F-01 compensating controls
   assume the app-layer binding runs before sensitive ops).
5. Flash power-loss torn-write behavior and NVS wear/rollback resistance
   beyond host mocks.
6. StrongBox/TEE presence on the actual device fleet; server-side Play
   Integrity verdict handling.

## Counts, top risks, audit SHA

- CRITICAL: 0 | HIGH: 0 | MEDIUM: 4 (A-01, F-01, F-02, F-03)
  | LOW: 4 (A-02, A-03, F-04, F-05) | INFO: 4 (A-04, A-05, J-01, F-06)
- Top 3 risks:
  1. A-01 cleartext HTTP inside the SoftAP (proximity sniffer/MITM).
  2. F-01 BLE JustWorks pairing, MITM flag off (pairing-window MITM).
  3. F-02 secure-channel cross-session frame replay (counter reset).
- Worktree SHA: 337863349de241807bba1ffde86461db9e815c22

