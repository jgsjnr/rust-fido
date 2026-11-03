# CLICKTHROUGH — Full UI Walk (Emulator Only)

- **Date (UTC):** 2026-11-03 ~17:55–18:20
- **Branch:** `fd/finalizacao-linux`
- **HEAD at build time:** `db8a120` (`feat(firmware): per-credential UP policy (default require-touch)`); HEAD at report time: `4187829` (`refactor(god): slim oath provider below threshold`). Parent lane is actively committing — HEAD moved mid-run.
- **Working tree:** DIRTY at build and test time (100+ unmodified-by-me files from the parent lane, e.g. `BleContract.kt`, `EncryptedKeysStore.kt`, `KeyVaultRepositoryImpl.kt`, `TotpRepositoryImpl.kt`, `TouchPolicy*`, `values/strings.xml`, `values-pt/strings.xml`). The APK under test includes those uncommitted changes. I made **zero source edits** (read-only + `adb` + one created report file).
- **APK under test:** `app-android/app/build/outputs/apk/debug/app-debug.apk`
  - `versionCode=1`, `versionName=0.1.0-wave5`, `application-label=AegisKey`, `compileSdk=34`
  - Built 2026-11-03 14:56:11 (local), SHA256 `D487E29276350D0547D377AE839AC6DE2FAB0707F986A878396BDD451035`
  - `adb -s emulator-5554 install -r` → `Success` (re-install over snapshot residue, then `pm clear` for a deterministic first-run)
  - First `assembleDebug` attempt failed on a transient Windows file lock (`mergeDebugJavaResource` zip-cache `FileSystemException`); retry succeeded (`BUILD SUCCESSFUL in 19s`). No source change involved.
- **Emulator:** AVD `Telemetry_AVD_S24` (snapshot `default_boot`), booted headless (`-no-window -no-audio -no-boot-anim -snapshot default_boot -no-snapshot-save -read-only`), Android 16 (`sdk_gphone64_x86_64`, `boot_completed=1`). Home launcher unlocked, no setup wizard blocking.
- **adb rule:** every invocation used `-s emulator-5554` explicitly. Two physical phones (`moto_g_60_`, `192.168.15.17:38071` + TLS entry) are on the same adb server via another lane — **never targeted, never touched**.
- **Screenshots:** `%TEMP%\clickthru\*.png` (+ paired `*.xml` uiautomator dumps). `FLAG_SECURE` is cleared in debug builds (`applyScreenshotProtection` no-ops when `!BuildConfig.DEBUG`), so `screencap` works.
- **Secrets:** no real PIN/password/recovery material used or stored. TOTP enrolment used RFC 6238 test vector secret `JBSWY3DPEHPK3PXP` + throwaway labels (`TestService`, `Test Key Alpha`). Recovery-phrase dialog renders index placeholders only (`palavra NN #NNNN`, wordlist `null`).

## Safety box — LIVE host bridge to another lane's physical board

Mid-walk (step 14) the app surfaced candidate **`AegisKey BLE (Hardware Real)`** (`BLE-BRIDGE`, rssi −42) and the header flipped to **`Connection · Connected`** (green). Passive `logcat` confirms why — the host bridge at `10.0.2.2:5678` is ONLINE with a real provisioned board attached:

```
AegisBridge: "deviceName": "AegisKey Hardware Real (USB HID 303A:AE61)", "status": "online",
             "usb_native_present": true, "was_usb_native_seen": true
AegisBridge: Host http://10.0.2.2:5678 respondeu code=200
```

That board belongs to the concurrent lane driving the physical phone. Consequences applied for the rest of the run:

- **Zero PIN/password attempts** (not even the allowed single wrong-PIN: `unlock()`/`provision()` dispatch `sendVendor(0x3B/…)` over USB → BLE → host bridge, i.e. straight to the other lane's board; one wrong PIN would burn a real attempt counter).
- **No provision / lock / generate-key / sign / export / enroll-PIV-PIN / delete / health-check / diagnostics(0x2E) / audit-log(0x38) / check-for-updates / refresh-status taps** — all dispatch vendor opcodes via the live bridge.
- **Caps screen NOT opened**: `CapsScreen` fires `CapsRepository.query(transport)` (GET_CAPS `0x3F`) in `LaunchedEffect(transport)` (`caps/CapsScreen.kt:51,56`) — merely opening the screen transmits to the board.
- **OTA panel opened, nothing staged/sent** (`Ota2Screen` has no auto-transmit; `Send to key` stays disabled with no staged image). No file picked, no COMMIT, no flash.
- **PIV card tapped once (navigation only, no transport).** Destructive entries (`Release Ownership or Reset Key (0x2B)`, factory reset, unbind, selective wipe) never tapped.
- Ambient read-only status polling by the app itself (vault card/diagnostics/rescue section showing live `Counter: 1,420 ops`, `v2.4.1-rc1`, PIV slots) could not be suppressed — it is the app's own rendering path, not an action I initiated.

Net effect: every flow that needs the provisioned board is **BLOCKED (board owned by concurrent lane — functionally HW-NEEDED for this lane)**, all fail-closed rendering paths verified.

## Flow matrix

| # | Flow | Verdict | Screenshot(s) | Notes / exact step |
|---|------|---------|---------------|--------------------|
| 0 | Boot, unlock, dismiss setup | **PASS** | `00-lockstate.png` | Launcher, no setup wizard. |
| 1 | Fresh install → onboarding step 1 (transport select) | **PASS** | `01-onboarding-step1-transport.png` | After `pm clear`: "Select Connection Method" (BLE/USB/Wi-Fi) + "I have a configured key — Go to Vault" + Next. (Pre-clear state showed residual bound key `Minha Chave Principal` from snapshot residue — `02-vault-hub-initial.png` — proving the snapshot ships app data; `pm clear` was required for determinism.) |
| 2 | BLE runtime permission | **PASS** | `02a-ble-permission.png` | System prompt on Next; tapped Allow. |
| 3 | Onboarding step 2 (hold button) | **PASS** | `03-onboarding-step2-holdbutton.png` | GPIO0 guidance renders. |
| 4 | Onboarding step 3 (discover) empty | **PASS** | `04-onboarding-step3-discover.png` | "Scanning for security keys…" + Refresh scan, zero results on isolated emulator. |
| 5 | Refresh scan, still empty | **PASS** (fail-closed) | (dump `04b-step3-refresh.xml`) | No devices, no crash. |
| 6 | Next with no selection | **PASS** (fail-closed, locale bug F1) | `05-onboarding-step3-no-selection-error.png` | Wizard refuses to advance; error banner hardcoded PT on EN UI: "Nenhuma chave selecionada. Escolha sua AegisKey na lista abaixo." |
| 7 | Skip to Vault ("I have a configured key") | **PASS** | `06-vault-hub-fresh.png` | 1-touch skip works; hub shows SecureGuard LOCKED `[5/5]`, "Security Key Disconnected", Generate disabled (greyed) pre-bridge. |
| 8 | TOTP empty state | **PASS** | `07-totp-list.png` | "No codes registered" + Add/Scan buttons. |
| 9 | Add TOTP dialog (manual entry) | **PASS** (render) | `08-totp-add-dialog.png` | TOTP/HOTP + 6/8-digit chips, 3 fields, disabled-until-valid Save. |
| 10 | Fill TOTP fields | **PASS w/ tooling note** | `09-totp-add-filled.png` | Direct coordinate taps land on the scrim when the keyboard is up and dismiss the dialog (no data loss — nothing saved yet); TAB-key (`keyevent 61`) navigation fills all three fields reliably. |
| 11 | Save TOTP without hardware | **PASS** (fail-closed, locale bug F1) | `10-totp-after-save.png` | Save closes dialog, list unchanged, snackbar (PT, hardcoded): "Não foi possível cadastrar o código: Sem resposta da chave para cadastro OATH" (`TotpRepositoryImpl.kt:312`). |
| 12 | Devices list | **PASS** | `11-devices-list.png` | Bound key `Minha Chave Aegis`/`CONFIGURED-VAULT`, Active, `Wireless BLE · Disconnected`, Rename/Unbind, Connect New. Proximity card claims `NEAR (-32 dBm)` + `Proximity Watch: ACTIVE` for a remembered `Galaxy S24 Ultra (3C:84:27:C7:17:7A)` with no board attached — emulator-only reading, needs HW verification (F5). |
| 13 | Rename key → `Test Key Alpha` | **PASS** | `12-devices-rename.png`, `12b-devices-rename-filled.png`, `13-devices-renamed.png` | Local-only rename persists across list/header. |
| 14 | Connect New Security Key → wizard (in-hub) | **PASS** (render) / **BLOCKED** (pair) | `14-connect-new-wizard.png` | Navigates to `onboarding-wizard` route; scan now shows `AegisKey BLE (Hardware Real)` (bridge online) pre-selected; header `Connection · Connected`. Did NOT tap Next — pairing would claim the other lane's board. Steps 4–5 (touch/bind, name/finish) unreachable → HW-NEEDED. |
| 15 | Wizard Back navigation | **PASS** | (dumps `15*.xml`) | Step-by-step Back to step 1; bottom-tab taps are swallowed while the wizard route is on top; system Back pops to Devices. Step 2 showed "Activation signal received. Tap Next to continue." with no hardware attached — hold-detection source unverified on emulator (F6). |
| 16 | Settings render (top) | **PASS** | `16-settings-top.png` | Theme / Language / Security+HW PIN / KeePassXC / Wi-Fi / Recovery sections. |
| 17 | Language EN→PT | **PASS** | `17-settings-pt.png` | "Theme and Appearance"→"Tema e Aparência", nav `Vault/Devices/Settings`→`Cofre/TOTP/Dispositivos/Configurações`. |
| 18 | Language PT→EN | **PASS** | (dump `18-en.xml`) | Back to EN, applies immediately, no restart. |
| 19 | 24-word recovery phrase dialog | **PASS** | `19-recovery-phrase.png` | Local generation; renders index placeholders (`palavra NN #NNNN`, 18 visible + scroll), Copy/Complete. No secret material on screen by construction. |
| 20 | Settings bottom (rescue/ownership/PIV/OTA-nav/caps-nav/footer) | **PASS** | `20-settings-bottom.png` | Self-test chips (`NVS OK … Counter: 1,420 ops` — live board data via bridge), ownership `0x2B`, PIV card, OTA + caps nav cards, footer `AegisKey App · v0.1.0`. |
| 21 | OTA panel | **PASS** (render) / **BLOCKED** (send) | `21-ota-panel.png` | "Firmware update / Choose firmware.bin / Send to key (disabled)". No pick, no send, no COMMIT, no flash. |
| 22 | Smart Card (PIV) card | **FAIL** (dead navigation, F2) | `23-piv-after-tap.png` | Tap leaves Settings unchanged; no `piv` route exists. |
| 23 | Vault hardware diagnostics expander | **PASS** | `24-vault-diagnostics.png` | Live board data (curves/PIV slots/KEK status, badge `v2.4.1-rc1`, `Slots: 0 used, 32 available`). "Run Quick Health Check" NOT tapped (board traffic). |
| 24 | Vault category filter (Crypto Wallets) | **PASS** (moot) | `27-vault-crypto-filter.png` (`33-vault-final.png`) | Chip selects; locked gate dominates with zero entries — filter effect unobservable without hardware. |
| 25 | Unlock Session → PIN pad dialog | **PASS** (render) / **BLOCKED** (submit) | `25-unlock-pin-dialog.png` | `Hardware Session Authentication`, numeric pad, Min 4 digits, Unlock disabled until valid, Cancel. Dialog opened (local state `openUnlockPrompt`) and Cancelled — **zero digits entered, zero submits**. |
| 26 | Emergency Recovery panel | **PASS** (render) / **BLOCKED** (submit) | `26-emergency-recovery.png` | Recovery Code + New PIN fields, `Recover and Save` disabled until filled. Viewed then Cancelled — nothing submitted. |
| 27 | Theme toggle (header) | **PASS** | `28-theme-dark.png` | SYSTEM→LIGHT (no visible change)→DARK (full dark vault) →back to SYSTEM/light. `cycleThemeMode()` works. |
| 28 | QR scan → camera permission → deny | **PASS** (fail-closed, misleading text F4) | `29-totp-qrscan.png`, `29b-totp-qr-denied.png` | Deny → external ZXing activity: "Sorry, the Android camera encountered a problem…" + OK; app itself doesn't crash; Back returns to Vault. |
| 29 | Wi-Fi Test Connection (no AP) | **INCONCLUSIVE** (F3) | `30-wifi-test.png`, `30b-wifi-test-result.png` | No visible result, no app log within 8s; result line (`wifiTestResult`, `FriendlySettingsAndThemeScreen.kt:663,685-699`) never surfaced. No board traffic (plain HTTP to `192.168.4.1`). |
| 30 | DKEK Quorum dialog | **PASS** (render) | `31-dkek-quorum.png` | N=3/M=2 steppers + summary; Closed without saving. |
| 31 | Backup Central chooser | **PASS** (render) | `32-backup-central.png` | BIP-39 / DKEK / SLIP-39 rows; Cancelled. Did not enter Shamir share generation (hardware-gated). |
| 32 | Caps screen | **BLOCKED** (deliberately not opened) | — | `LaunchedEffect(transport)` auto-fires GET_CAPS `0x3F` (`caps/CapsScreen.kt:51,56`) → opening = transmitting to another lane's board. |
| 33 | Unlock/PIN submit, provision, lock, key-gen/sign, PIV ops, per-key touch toggle, OTA send, caps query, refresh/diagnostics/audit, check-for-updates, reset/unbind/wipe | **BLOCKED** | — | All dispatch vendor opcodes through the live host bridge to a board owned by the concurrent lane. `KeyDetailManagementScreen` (incl. `TouchPolicyCard` toggle, `KeyDetailManagementScreen.kt:167-171`) unreachable: zero vault entries without hardware (guard locked gate). |
| 34 | Final vault state | **PASS** | `33-vault-final.png` | Guard still LOCKED `[5/5]`, no mutations persisted (rename excepted — local label). |

## Failure / BLOCKED list with root-cause hypotheses (no fixes)

- **F1 — Hardcoded PT user-facing strings on EN UI (fail-closed paths still correct).**
  - `OnboardingWizardViewModel.kt:203` — `"Nenhuma chave selecionada. …"` literal instead of `R.string.*` (seen in `05-…png`).
  - `TotpRepositoryImpl.kt:312` — `"Sem resposta da chave para cadastro OATH"` literal (seen in `10-…png` snackbar).
  - `SecureGuardViewModel.kt:222,258` — `"Secure Guard provisionado com sucesso!"` / `"Cofre desbloqueado com sucesso!"` literals (same pattern, not exercised — would also bypass locale).
  - Hypothesis: error/success strings written inline during Waves 5–7; `values-pt` exists but these call sites never reference resources.
- **F2 — PIV settings card is dead navigation (this build).**
  - `FriendlySettingsAndThemeScreen.kt:146` (`onNavigateToPiv … = {}`) + `:1370` (`onClick = onNavigateToPiv`); `MainActivity.kt:228-237` never passes the callback; NavHost has no `"piv"` route (only `vault/codes/keys/settings/ota2/caps/onboarding-wizard`). Tap = no-op (evidence `23-piv-after-tap.png`).
- **F3 — Wi-Fi "Test Connection" gives no observable result on emulator.**
  - Test path exists (`FriendlySettingsAndThemeScreen.kt:685-699`, `WifiApi.testConnection("http://192.168.4.1")`, result line `:663`) but within 8s: no text change, no snackbar, no app log. Hypothesis: HTTP to the absent AP hangs past the observation window (long/no timeout surfaced), or `wifiTestResult` recomposition missed; needs a failure-path timeout assertion on-device.
- **F4 — QR-scan denial shows a misleading third-party error.**
  - After denying camera permission, the external ZXing `CaptureActivity` reports "the Android camera encountered a problem. You may need to restart the device" (`29b-…png`). Not an app crash (Back recovers cleanly), but the message misattributes a permission denial to broken hardware; app-side pre-check/rationale could intercept `SecurityException`/permission state before delegating.
- **F5 — Proximity claims ACTIVE/NEAR with no board attached.**
  - Devices card: `NEAR (-32 dBm)`, `Galaxy S24 Ultra (3C:84:27:C7:17:7A)`, `Proximity Watch: ACTIVE` (`11-devices-list.png`). On emulator this MAC/RSSI cannot come from a real scan; likely remembered BT state or emulator BT passthrough. Needs physical-device verification that ACTIVE only reflects a live bonded key.
- **F6 — Button-hold auto-detected without hardware.**
  - Wizard step 2 showed "Activation signal received. Tap Next to continue." on emulator. Suspect `simulatedRenodeTransport.buttonHoldSimulated` / bridge-probed state leaking into `_buttonHoldSimulatedOrDetected` (`PairingWizardRepositoryImpl.kt:101-104`, `OnboardingWizardViewModel.kt:184`). Needs HW-gated assertion.
- **F7 — Firmware version + slot-count drift across screens.**
  - Vault card (isolated): `v0.2.1-esp32s3`, `Slots: 0 used, 16 available` (`06-vault.xml`); vault card (bridge live): badge `v2.4.1-rc1`, `Slots: 0 used, 32 available` (`24-vault2b.xml`); Settings OTA card: `Firmware v3.4.0-esp32s3` (`20-settings-bottom.png`). Hypothesis: stale compiled default vs live `GET_STATUS` vs OTA-channel metadata shown side-by-side with no source label; slot total changing 16→32 suggests mixed default/live data. Reconcile or label provenance.
- **F8 — "Generate Key in Security Key" enables on connection alone.**
  - Greyed while disconnected (`06-…png`), enabled once the bridge reported Connected (`24-…png`) while SecureGuard is still LOCKED. Not tapped (would emit to the other lane's board); enablement gating on transport rather than guard-unlocked deserves a fail-closed review (expected: disabled until `isGuardUnlocked`, or tap → explicit guard prompt, never silent hardware dispatch).

## Evidence states / extension boundaries (read-only notes)

- Test doubles live **only** in `src/debug` + `src/test` (+ release no-op): `src/debug/…/DebugHardwareChipMock.kt:22` (`IS_MOCK_ENABLED=false` default) vs `src/release/…/DebugHardwareChipMock.kt:15` (const false, all no-ops). `main` references resolve per-variant — boundary respected. Consequently this debug APK had **no mock candidates** (mock never enabled outside tests): every hardware-gated list was honestly empty until the *real* host bridge appeared.
- `res/values-pt/strings.xml:15` mojibake check: `Configura��es`/`Seguran�a` in raw dump reads are extraction-encoding artifacts — on-screen PT (`17-settings-pt.png`) renders `Configurações`, `Segurança`, `Claro/Escuro` correctly. Not an app bug.
- TOTP add-field dismissal (matrix #10): coordinate taps with the IME up land outside the moved dialog and dismiss it — test-harness artifact, not app behavior (dialog has no `onDismiss` data loss: nothing was staged yet).

## Logcat excerpt (redacted — no PINs/secrets; indices only, wordlist null)

```
# install + first run (pid 18420→18744 after pm clear)
AegisBridge: Tentando conectar em http://127.0.0.1:5678/bridge/info...
AegisBridge: Host http://127.0.0.1:5678 falhou: ConnectException: Failed to connect to /127.0.0.1:5678
AegisBridge: Tentando conectar em http://10.0.2.2:5678/bridge/info...
AegisBridge: Host http://10.0.2.2:5678 respondeu code=200
AegisBridge: "deviceName": "AegisKey Hardware Real (USB HID 303A:AE61)", "status": "online",
             "cid": "0x60201", "usb_native_present": true, "was_usb_native_seen": true
AegisBridge: Bridge USB/UART detectada com sucesso: AegisKey Hardware Real (USB HID 303A:AE61) em USB_HID
# TOTP save w/o hardware: dialog closed, snackbar shown, no exception in app log (only system MDD/SurfaceSync noise)
```

## Verdict

Emulator click-through: **33 screens/dialogs rendered, all reachable local flows PASS, all hardware-mutating flows correctly fail-closed or were deliberately not exercised** (other lane's live board on the host bridge). Findings F1–F8 are hypotheses with `file:line` pointers — **no fixes applied, no code committed**.
This run is **not physical-device acceptance**: builds, mocked traffic absence, emulator, screenshots and the shared-bridge handshake observe contracts only. Physical-device acceptance still requires: provisioned-board pairing (steps 4–5), PIN provision/unlock/lock + the single wrong-PIN path, key detail + per-key touch toggle, TOTP enrolment + live codes, OTA send/verify, caps query, diagnostics/audit opcodes — on a dedicated board with no concurrent session.
