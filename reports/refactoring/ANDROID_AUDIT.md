# ANDROID_AUDIT.md — app-android audit (2026-11-02)

Scope: `app-android/**` only. Branch: `refactor/standalone-architecture-cleanup`.
Method: static read + `TODO/FIXME/stub/mock/fake/NotImplemented/Hardcoded` grep,
emoji grep, `Text("` inventory, UniFFI symbol cross-check
(`crates/uniffi-bridge/src/ffi.rs` read-only, no bridge edits).

Conventions used below:
- WORKS = real path, hardware-backed, fail-closed.
- PARTIAL = real path with degraded/canned branch or compile flag OFF.
- MOCK = debug-only mock (release source set is a no-op).
- MISSING = TODO / stub / unwired.

## 1. Screen / feature map

### Navigation shell — WORKS
- `app/src/main/java/dev/aegiskey/app/MainActivity.kt:41` — `MainActivity`
  (ComponentActivity, screenshot protection, BLE release on destroy).
- `MainActivity.kt:70` — `AegisApp`: 4-tab hub
  (`MainHubScaffoldTemplate` + `NavHost`: VAULT / CODES / KEYS / SETTINGS,
  `onboarding-wizard` route). Transport label via `stringResource`
  (`MainActivity.kt:129-135`). Screen-change logging only (`DeviceLog`).

### Vault tab — WORKS (hardware-backed; debug mock injection available)
- `ui/screens/KeyVaultHubScreen.kt` — list, filter, generate, sign,
  AEGN envelope export, PIV PIN/PUK, diagnostics, quick health check.
- `ui/viewmodel/KeyVaultViewModel.kt` — `WORKS`, except:
  - PARTIAL `KeyVaultViewModel.kt:254` `injectMockKeysForDebug()` — debug only,
    gated by `DebugHardwareChipMock.IS_MOCK_ENABLED`, early-return otherwise
    (`:453`).
  - PARTIAL `KeyVaultViewModel.kt:477` user message mentions "Chip Mock".
- `data/repository/KeyVaultRepositoryImpl.kt` — WORKS; mock branch
  `KeyVaultRepositoryImpl.kt:145,168` gated by `IS_MOCK_ENABLED`.
- `data/transport/{Ble,Usb}KeyTransport.kt`, `usb/UsbCtaphid.kt`,
  `ble/AegisBleClient.kt` — WORKS (fail-closed `Result`s).

### TOTP tab — WORKS (hardware-backed; debug mock injection available)
- `ui/screens/TotpDedicatedScreen.kt` — WORKS.
- `ui/viewmodel/TotpAuthenticatorViewModel.kt` — WORKS, except PARTIAL
  `:221-226` mock sync (`IS_MOCK_ENABLED` gate).
- `data/repository/TotpRepositoryImpl.kt:89-106` — mock fallback branches,
  all gated by `IS_MOCK_ENABLED`.

### Devices tab — WORKS
- `ui/screens/ConnectedKeysRepositoryScreen.kt` — list, rename, unbind,
  select-active, connect-new. WORKS.
- `ui/viewmodel/ConnectedKeysViewModel.kt` — WORKS (feedback strings are
  code-side PT literals — see §5 i18n debt).
- `domain/usecase/GetAppStartDestinationUseCase.kt` — WORKS.

### Onboarding / pairing wizard — WORKS (+ debug mock branches)
- `ui/screens/FriendlyOnboardingWizardScreen.kt` — WORKS; used by both
  first-run and `onboarding-wizard` route (`MainActivity.kt:101,213`).
- `ui/screens/OnboardingWizardScreen.kt:11` — thin wrapper delegating to
  the friendly screen (not dead, not a duplicate flow).
- `ui/viewmodel/OnboardingWizardViewModel.kt:184,197-198,210-211,242` —
  simulator/emulator auto-candidate + hold simulation, all gated by
  `IS_MOCK_ENABLED` / `isDebugMode`. WORKS on hardware.
- `data/repository/PairingWizardRepositoryImpl.kt:81-84,148-150,175-188,206-242,290-394`
  — mock candidate injection + mock connect paths, all gated. WORKS on hardware.

### Secure Guard — WORKS (fail-closed) + one MISSING crypto binding
- `ui/atomic/organisms/SecureGuardCardOrganism.kt` — provision / unlock /
  lock / change-PIN / recover / policy / selective wipe dialogs. WORKS.
- `ui/viewmodel/SecureGuardViewModel.kt` — WORKS; `sanitizeErrorMessage`
  (`:83`) never leaks JNA/JNI internals (pinned by
  `SecureGuardRepositoryAndCborTest.kt:110-144`).
- `data/repository/SecureGuardRepositoryImpl.kt`, `data/cbor/SecureGuardCbor.kt`,
  `bridge/AegisBridge.kt` secure-guard encoders + `MiniCbor` — WORKS.
- Error code `"PinAuthInvalid"` (`SecureGuardCbor`, asserted at
  `SecureGuardRepositoryAndCborTest.kt:106`) is a protocol code, not prose.

### Settings tab — WORKS except two PARTIAL canned OTA paths
- `ui/screens/FriendlySettingsAndThemeScreen.kt` (2771 lines, see §6):
  - WORKS: theme (persisted), biometrics toggle, walk-away lock, HW PIN
    dialog, KeePassXC card, Wi-Fi config/test/TOTP-read, backup phrase +
    DKEK quorum, Shamir 2-of-3, eFuse notice, rescue self-test + logs,
    ownership/reset, PIV PIN.
  - PARTIAL `FriendlySettingsAndThemeScreen.kt:175`
    `otaStatusMessage` initial canned value
    `"Firmware v3.4.0-esp32s3 signed and verified."`.
  - PARTIAL `:958-971` "Check for Updates" uses `delay(600)` then a canned
    success string — no manifest fetch on this button (real OTA validate
    lives in `net/OtaApi.kt` + `usb/OtaTransfer.kt`, WORKS).
  - PARTIAL `:199-207` diagnostics defaults (`1420L`, `"v0.2.1-esp32s3"`,
    `"Auto-teste 0x2E concluído"`) used until BLE/hardware answers.
- Language switch: MISSING (added by this change — see §5).

### Biometrics — PARTIAL (stub)
- `security/BiometricGate.kt:27` `stubCryptoObject()` returns null;
  `available()` is false in stub (`:30-31`). Callers fall back to password.
- MISSING `BiometricGate.kt:24` `TODO(release)`: bind AndroidKeyStore
  user-auth key + `CryptoObject`. Only TODO in main source set.
- `security/BindingKey.kt:226` biometric sign negative button hardcodes
  `"Cancelar"` (Activity context available — localizable, see §5).

### App lock — PARTIAL (implemented, flag OFF, unwired UI)
- `security/AppLock.kt` (PBKDF2 verifier via `AegisBridge.appLockDerive`) —
  implemented but `FeatureFlags.kt:22` `ENABLE_APP_LOCK = false` and no
  LockScreen is wired in `MainActivity.kt`. Dead path in release.
- `FeatureFlags.kt:23` `ENABLE_DEVICE_PRESS = false`; `ui/GateBanner.kt:29`
  defined but never called (SdkGate banner unwired).

### Transports / protocols — WORKS
- `ble/{AegisBleClient,BleContract,BindingOps,VendorOps}.kt`,
  `usb/{UsbCtaphid,OtaTransfer}.kt`, `net/{OtaApi,WifiApi,WifiDiscovery}.kt`,
  `data/transport/HostUsbUartBridgeClient.kt` — WORKS, fail-closed.
- `net/WifiApi.kt:109` user-visible fallback message is a code-side PT
  literal (see §5 i18n debt).
- `usb/UsbCtaphid.kt:171,234,257,280,284,294,303,328,343,385,400` user-visible
  PT status strings are code-side literals (see §5 i18n debt).

### Backup / crypto helpers — WORKS
- `security/{RecoveryBackup,SdkGate,AppSecurity,BlePermissions}.kt`,
  `data/system/SystemSecurityService.kt`, `log/DeviceLog.kt` — WORKS.
- `security/AppSecurity.kt:137` Play Integrity path is real (no stub).

### Debug-only mocks — MOCK (release source set is a no-op)
- `app/src/debug/.../DebugHardwareChipMock.kt` (`:22`, `:159`, `:193`,
  `:207` mock TOTP/MACs, `:246-262` purge list) vs
  `app/src/release/.../DebugHardwareChipMock.kt:15` pure no-op.
- `app/src/debug/.../DebugChipControlHooksCard.kt:52,66` debug-only card.
- `data/transport/SimulatedRenodeTransport.kt:44-52` canned keys/accounts
  (`"Passkey Google"`, `"GitHub:developer"` …), reachable only when
  `IS_MOCK_ENABLED`.
- `data/local/EncryptedKeysStore.kt:45` purges residual mock data.

### Unit tests (5 files, `app/src/test/...`) — WORKS
- `AndroidUiFeaturesAndRescueTest.kt`, `CleanJourneyArchitectureTest.kt`
  (pins `"Hardware Conectado"` health text at `:304,310`),
  `KeyVaultLockCascadeAndCacheTest.kt` (`MockSecureGuardRepository` is a
  test fake, `:111`), `SecureGuardJourneyTest.kt`,
  `SecureGuardRepositoryAndCborTest.kt` (pins sanitized message content at
  `:143` — constrains i18n of VM messages, see §5).

## 2. Tally

- WORKS: 23 areas (nav, vault, totp, devices, wizard wrapper+friendly flow,
  pairing repo, secure-guard card+VM+repo+CBOR+bridge, settings
  theme/security/wifi/backup/shamir/efuse/rescue/piv/logs, transports BLE +
  USB + Wi-Fi + bridge-client, OTA validate/transfer, backup/SDK-gate/
  integrity/permissions, CBOR codec, AppContainer DI, 5 test files).
- PARTIAL: 9 (OTA canned status + canned check, diagnostics defaults,
  KeyVault/TOTP mock injectors, wizard mock branches, repo mock branches,
  BiometricGate stub, AppLock flag-off/unwired, GateBanner unwired).
- MOCK: 4 debug-only (chip mock, debug hooks card, renode transport,
  mock purge).
- MISSING: 2 (KeyStore-bound `CryptoObject` TODO `BiometricGate.kt:24`;
  in-app language switch — implemented by this change).

## 3. AegisBridge JNA symbols vs `crates/uniffi-bridge/src/ffi.rs` (read-only)

`ffi.rs` publishes (snake_case, `pub fn`): `ble_constants`,
`ble_split_fragments`, `envelope_validate`, `envelope_seal`,
`envelope_open`, `cose_key_info`, `oath_code_valid`,
`oath_remaining_seconds`, `totp_format_display`, `app_lock_derive`,
`wifi_password_valid`, `oath_account_from_path`, `oath_parse_response`,
`otpauth_extract_label_and_secret`, `wallet_address`,
`secure_guard_parse_status`, `secure_guard_encode_provision`,
`secure_guard_encode_unlock`, `secure_guard_encode_change_pin`,
`secure_guard_encode_recover`, `secure_guard_encode_lock`,
`secure_guard_encode_config`, `secure_guard_encode_wipe`.

`AegisBridge.kt` calls (camelCase UniFFI): `bleConstants`,
`bleSplitFragments`, `envelopeValidate`, `oathParseResponse`,
`appLockDerive`, `totpFormatDisplay`, `otpauthExtractLabelAndSecret`,
`envelopeSeal`, `walletAddress`, `envelopeOpen`,
`secureGuardParseStatus`, `secureGuardEncodeProvision/Unlock/ChangePin/`
`Recover/Lock/Config/Wipe`. Every called symbol exists in `ffi.rs` —
**no mismatches**. Deliberately local (not called over JNI):
`cose_key_info` (unused), `oath_code_valid`/`oath_remaining_seconds`/
`wifi_password_valid`/`oath_account_from_path` (pure-Kotlin mirrors in
`AegisBridge.kt:164-180`). No bridge edit made or needed.

## 4. Emoji hits (user-visible, removed by this change)

| File:line | Emoji | Context |
|---|---|---|
| `ui/atomic/organisms/SecureGuardCardOrganism.kt:122` | 🛡️ | title prefix |
| `SecureGuardCardOrganism.kt:201` | ⚠️ | error prefix |
| `SecureGuardCardOrganism.kt:209` | ✅ | success prefix |
| `SecureGuardCardOrganism.kt:300` | 🔒 | lock button prefix |
| `SecureGuardCardOrganism.kt:308` | ⚙️ | policies button prefix |
| `SecureGuardCardOrganism.kt:311` | 🔥 | wipe button prefix |
| `ui/atomic/organisms/HardwareSessionPinPopupDialog.kt:211` | ⏳ | rate-limit prefix |
| `ui/atomic/organisms/HardwareSessionPinPopupDialog.kt:221` | ⚠️ | error prefix |
| `ui/screens/FriendlyOnboardingWizardScreen.kt:183` | ⚡ | quick-open USB card |
| `res/values*/strings.xml` `pin_keypad_backspace` = `⌫` | — | kept: U+232B text glyph, not an emoji; no replacement needed |

Total removed: 10 emoji in 3 Kotlin files (6 SecureGuard + 1 rate-limit + 1 popup + 1 title + 1 onboarding + 1 max-attempts = recount: 122, 201, 209, 300, 308, 311, 325, popup 211, 221, onboarding 183). `⌫` retained (symbol, renders as
text, no emoji presentation).

## 5. Hardcoded user-visible literals → `strings.xml` (EN) + `strings-pt` (PT-BR)

Already resourced: 226 EN entries (171 `stringResource` call sites).
Extracted by this change (new keys, ASD-STE100 short style, one concept per
string; glossary comment at top of `strings.xml`):

- Composables — `TotpCodeCardMolecule.kt:203` (1),
  `AddTotpAccountDialogOrganism.kt:203-259` (10),
  `KeyGenerationDialogOrganism.kt:195,332,377-378` (4),
  `ConnectedKeysRepositoryScreen.kt:309,328,370,375` (3 + reuse),
  `FriendlyOnboardingWizardScreen.kt:183,194,306-310,377,398,724-738`
  (12), `FriendlySettingsAndThemeScreen.kt` (~70: section titles, Wi-Fi
  card, OTA channel/status/buttons, PIN dialog, Shamir placeholders,
  power/channel labels, rescue/log/transfer dialogs, `"Fechar"`→reuse),
  `KeyDetailManagementScreen.kt:296,301,623,791,799,817,946,1002` (8),
  `TotpDedicatedScreen.kt:364,369` (2, reuse Delete/Cancel).
- `BiometricGate.kt:51-53` prompt title/subtitle/negative button +
  `BindingKey.kt:226` negative button — resolved via passed `Activity`
  (`activity.getString`), no API change.
- Language preference: new `LocalePreferencesStore` (SharedPreferences
  `aegis_locale_preferences`, mirrors `ThemePreferencesStore`), applied in
  `MainActivity.attachBaseContext` + manual `recreate()`; no new
  dependency (appcompat absent — `activity-compose:1.9.2` only — so
  `AppCompatDelegate` per-app locales are intentionally not used).
  Settings section follows the OTA `FilterChip` channel pattern (no redesign).

Deferred with rationale (NOT extracted; still code-side literals):
- ViewModel/Repos/Transports runtime messages (e.g.
  `KeyVaultViewModel.kt:210,226,232,267,274,298,303,323,328,346,350,370,377,437,458,466,477`;
  `SecureGuardViewModel.kt:84-…` sanitize fallbacks;
  `TotpAuthenticatorViewModel.kt:138,158,162,180,184,200,202,214,216,226`;
  `ConnectedKeysViewModel.kt:87,101,114,134`;
  `OnboardingWizardViewModel.kt:203,226,301,339`;
  `UsbCtaphid.kt:171,234,257,280,284,294,303,328,343,385,400`;
  `BleContract.kt:89-92`/`VendorOps.kt:76-79`/`BindingOps.kt:62-110`
  status labels; `WifiApi.kt:109`; `HostUsbUartBridgeClient.kt:878,890,923,934,1041`;
  `FriendlySettingsAndThemeScreen.kt` BLE-fallback diagnostics defaults).
  Reason: ViewModels/repos are constructed without `Context` in unit tests
  (`SecureGuardRepositoryAndCborTest.kt:106,143` and
  `CleanJourneyArchitectureTest.kt:304,310` pin exact message content);
  localizing them needs a `UiText`-key architecture migration, which is
  out of scope for a no-UI-change pass. Follow-up: emit string-key events
  and resolve with `stringResource` at the call site.

## 6. God files (lines, same-package move-only splits by this change)

| File | Lines | Action |
|---|---|---|
| `ui/screens/FriendlySettingsAndThemeScreen.kt` | 2771 | split (dialogs → same-package files) |
| `bridge/AegisBridge.kt` | 1381 | KEEP (cohesive facade + fallbacks; split would scatter crypto) |
| `ui/uniffi/aegis_bridge/aegis_bridge.kt` | 1664 | KEEP (generated bindings, never hand-edit) |
| `data/transport/HostUsbUartBridgeClient.kt` | 1061 | split only if clean boundary (shamir/efuse/clear-signing sections) |
| `ui/screens/KeyDetailManagementScreen.kt` | 1071 | split only if clean boundary |
| `ui/screens/FriendlyOnboardingWizardScreen.kt` | 823 | KEEP (single flow, cohesive) |
| `usb/UsbCtaphid.kt` | 696 | KEEP |
| `ui/screens/KeyVaultHubScreen.kt` | 687 | KEEP |
| `ble/AegisBleClient.kt` | 649 | KEEP |

Rule applied: extract whole top-level `@Composable`/helper functions to a
new file in the same package, no signature or behavior change, imports
carried with the moved code. Public APIs used elsewhere preserved.

## 7. Change log (this workstream)

- `docs: ANDROID_AUDIT.md` — this file.
- `refactor(android): strings i18n + de-emoji` —
  10 emoji removed (neutral text, no new icons); ~230 new `strings.xml`
  (EN) / `strings-pt` (PT-BR) keys with ASD-STE100 glossary comment;
  every composable-layer literal now `stringResource` (event
  handlers/coroutines use `resources.getString`, since `stringResource`
  is composable-only); `BiometricGate`/`BindingKey` prompts resolved via
  passed `Activity`; in-app language switch (`LocalePreferencesStore`
  SharedPreferences + `LocaleHelper` + `MainActivity.attachBaseContext`
  + settings FilterChip section + `recreate()`; no appcompat dep);
  VM/repo/transport runtime messages deferred with rationale (§5).
- `refactor(android): split god files (no UI change)` —
  `FriendlySettingsAndThemeScreen.kt` → `FriendlySettingsDialogs.kt`;
  `KeyDetailManagementScreen.kt` → `KeyDetailSections.kt`;
  `FriendlyOnboardingWizardScreen.kt` → `FriendlyOnboardingSteps.kt`
  (same package; moved functions widened `private` → `internal`, no
  signature/body change; `HostUsbUartBridgeClient`/`AegisBridge`/
  generated UniFFI bindings kept whole).
- Validation: `./gradlew :app:assembleDebug` + `:app:testDebugUnitTest`
  (offline, SDK 34 present) — recorded per commit.
