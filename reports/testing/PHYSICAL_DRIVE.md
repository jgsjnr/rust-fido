# PHYSICAL DRIVE — Full UI Matrix (Physical Device Acceptance)

- **Date (local/host, UTC-3):** 2026-11-03 21:02–21:30 (≈ 2026-11-04 00:02–00:30 UTC)
- **Branch:** `fd/finalizacao-linux`
- **Drive-time HEAD:** `79d39fb` (`docs(manual): full click-through tour`)
- **Working tree:** DIRTY at drive time (parent lane uncommitted changes, e.g. `crates/aegis-fido-*`, `app-android` sources). **Zero source edits by this drive** (read-only `adb` + `uiautomator` + two `%TEMP%` capture helpers; one created report file).
- **APK under test (on phone):** `dev.aegiskey.app`, `versionCode=1`, `versionName=0.1.0-wave5` (`firstInstallTime=2026-11-03 12:40:33`). Installed build **predates** some working-tree fixes (see F-A).
- **Phone:** Motorola moto_g_60_ (`hanoip`), via `adb -s 192.168.15.17:38071` (every invocation pinned with `-s`; the second TLS transport entry was never targeted).
- **Board:** ESP32-S3 (`USB HID 303A:AE61`, `UART COM7` Silicon Labs CP210x), firmware app `v1` (ESP-IDF v5.3.1, ELF 2026-11-01) per UART boot log.
- **Bridge:** `tools/host_hardware_android_bridge.py` on host port `5678`, transport **USB HID** at drive start → **UART COM7** at drive end (see §4).
- **PIN policy:** correct PIN `1111` used ONLY where a flow required unlock/provision; **zero wrong-PIN attempts** (attempts counter `[5/5]` at every checkpoint). No wipe / eFuse / NVS-erase / change-PIN / factory-reset / reset / unbind / delete touched.

## Safety box — what was NOT done

- No source edits, no push/merge (report committed locally only, see §8).
- No `Delete Key from Physical Chip (0x23)`, no `Release Ownership or Reset Key (0x2B)`, no `Pair New Security Key`, no `Unbind`, no `Change Security Key PIN`, no `Selective Wipe`, no Shamir share generate/recover, no OTA `Send to key` / file pick / COMMIT, no `Check for Updates`, no `Sign on Chip Now`, no AEGN export, no PIV PIN enroll, no TOTP Add/Scan or `Delete code`, no `Clear Logs`, no recovery `Recover and Save` submit, no vault entry deletion (user slots untouched; only `tst-drive1` created).
- Recovery codes shown on screen are **redacted** in this report (`[REDACTED]`); screenshots/dumps stay in `%TEMP%`, never committed.

## 1. Pre-flight (all three present, else STOP)

| Piece | Result |
|---|---|
| Working dir + branch `E:\projetos\fido` / `fd/finalizacao-linux` | OK |
| Phone via ADB (`192.168.15.17:38071`, `device`) + app `dev.aegiskey.app` in foreground | OK |
| Bridge alive (PIDs 10408/21488, `--probe` → `USB HID 303A:AE61`, `status=online`) | OK (degraded later, see §4) |
| Board on USB (`COM7` CP210x + `USB HID 303A:AE61`) | OK |
| `adb logcat -c` + host capture `app_log.log` + UART capture `board_errors.log` (DTR/RTS suppressed) started | OK 21:02:03 |

## 2. Flow matrix

| # | Button / screen | Verdict | Evidence / notes |
|---|---|---|---|
| 1 | Unlock flow (PIN `1111`) | **PASS** | 1st unlock: `Hardware Session Authentication` dialog (initial-setup variant, `4/16` after entry) → `Unlock` → transient `POST /api/secure-guard/unlock timeout` (§4) → `Refresh` → **UNLOCKED, Session Active, `[5/5]`**. Re-unlock after each 5-min expiry with `1111`: PASS every time (dialog `LOCKED` variant, `Unlock PIN` label). 3 provisions + 2 re-unlocks total, attempts `[5/5]` at every checkpoint. |
| 2 | Vault create (`tst-drive1`) | **PASS** | `Generate Key in Security Key` → label `tst-drive1` → `Generate Key` → dialog closes, **Slots: 1 used, 31 available**, `All (1)`. On-board keygen end-to-end (no app error in logcat). |
| 3 | Vault list | **PASS** | After scroll: row `tst-drive1` / `Passkey` / `Credencial WebAuthn / Passkey (P-256 (recomendada)) [Slot #0]` / `fido2/resident-key/0` / `Manage`. Locked-state list shows `0 used` (fail-closed display; `31 available` stays live — see §5/F-G). |
| 4 | Key detail + touch policy (view-only) | **PASS** | `Manage` → `Physical Key Management`, `Hardware Slot #0 · tst-drive1`, badge **Touch Required** (per-key UP default ON), CTAP 2.1 / P-256 / resident / UV rows. `Sign on Chip Now`, AEGN export, `Delete Key (0x23)` **viewed, never tapped**. No `TouchPolicyCard` switch rendered in installed build (source has it at `KeyDetailManagementScreen.kt:167`) — nothing to toggle, nothing changed. |
| 5 | TOTP view codes | **PASS** | Pre-existing `e2e-test` entry (other lane's; untouched) rendered a live rotating 6-digit code (`XXX XXX` format) + countdown + `Copy code`. `Add Code` / `Scan QR Code` / `Delete code` never tapped. |
| 6 | Caps screen (preset/caps) | **PASS** | `Board capabilities` card → `GET_CAPS 0x3F` (authorized read): **Firmware 1.0.0**, **Preset `full`**, 17 features (`Passkey create/assert`, `Client PIN`, `Smartcard USB`, `PIV slots`, `OpenPGP`, `TOTP/HOTP`, `Challenge response`, `Crypto wallet`, `Vault items`, `Bluetooth`, `Wi-Fi clock`, `Display`, `Proximity lock`, `Device control`, `Debug lines`, `Test hooks`), `0 not on this preset`, `Missing commands answer 0x06`. **Version drift (F7 repro):** caps `1.0.0` vs vault card `v2.4.1-rc1` vs OTA card `v3.4.0-esp32s3`. |
| 7 | OTA card | **PASS (view-only)** | `Offline firmware update` card → `OTA2` panel: `Firmware update`, `Choose firmware.bin`, `Send to key` (disabled, nothing staged). No pick, no send, no COMMIT. `Check for Updates` deliberately not tapped (SKIPPED-WHY: out of view-only scope). |
| 8 | Settings language EN→PT→EN | **PASS** | `Português (Brasil)` → `Theme and Appearance`→`Tema e Aparência`, tabs `Vault`→`Cofre`, `Devices`→`Dispositivos`; back to `English` restores EN immediately, no restart. |
| 9 | Touch-toggle (per-key) | **PASS (view-only)** | Policy visible as `Touch Required` badge (require-touch ON, hardware default). No toggle control exists in installed build; zero policy changes. |
| 10 | 24-word recovery phrase (view-only) | **PASS** | `24-Word Recovery Phrase` → `Recovery Phrase (24 Words)` dialog, 16 index placeholders (`palavra NN #NNNN` format) + `Copy`/`Complete`; dismissed via Back. No Copy, no submit. |
| 11 | Emergency Recovery panel (view-only) | **PASS** | Locked-provisioned state shows `Unlock Session` + `Emergency Recovery`; panel expands inline: `Emergency Recovery with Recovery Code`, `Recovery Code (XXXX-XXXX-XXXX-XXXX)` + `New PIN (4 to 16 digits)` fields, `Recover and Save` (disabled). **Nothing entered, nothing submitted**; collapsed after. |
| 12 | Recovery-code display section | **PASS (view-only)** | Unlocked hub shows `Emergency Recovery Code:` + code (redacted) + storage guidance. Viewed only. |
| 13 | PIV screens | **FAIL** | `Smart Card (PIV / Certificates)` card tap (2 attempts, settled UI) → **no navigation**, no logcat line. Installed APK predates the fix; source now wires `onNavigateToPiv = { nav.navigate(AppRoutes.PIV) }` (`MainActivity.kt:248`), route `AppRoutes.PIV` + `PivScreen` exist. Hypothesis: stale APK on phone (F2 persists in installed build). |
| 14 | Diagnostics expander (vault) | **PASS** | `Show Hardware Diagnostics` → live board data: `Health status: Hardware Conectado · Verificação Básica OK`, PIV slots 9A/9C, KeePassXC READY. `Run Quick Health Check` viewed, not tapped (covered by 0x2E below). |
| 15 | Rescue Diagnostics (0x2E) | **PASS** | `Diagnostics (0x2E)` → `Rescue Diagnostics (0x2E)` screen, verdict `Hardware Conectado · Verificação Básica OK`, NVS / TRNG (FIPS 140-2 pass) / Crypto HW (P-256, AES-256) / UP button / monotonic counter rows. Read-only query, no mutation. |
| 16 | Audit Logs (0x38) | **PASS (view)** | `Audit Logs (0x38)` → `Security Audit Logs (0x38)` live trace (`Bridge sendVendor(0x25/0x22/0x83/0x36)…`, timestamps). `Copy All` / `Clear Logs` / `Fw 0x38` viewed, never tapped. Closed after. |
| 17 | Rescue `Refresh` | **PASS** | Re-queries status; read-only. |
| 18 | Devices tab | **PASS** | Bound key `Minha Chave Principal`, `Active`, `Serial: BRIDGE:USB_HID`, `USB / UART Cable · Connected`, proximity `NEAR (-32 dBm)`, `Proximity Watch: ACTIVE`. `Rename`/`Unbind`/`Connect New` never tapped. |
| 19 | Sign/Auth/Delete/Export/Change-PIN/Wipe/Ownership/Shamir/DKEK/Backup-Central | **SKIPPED-WHY** | Out of task scope or destructive; screens containing them viewed only (deletion zone text recorded: purge opcode `0x23`). |
| 20 | Final 0x3A read-only | **PASS** | §6. |

## 3. Logcat app errors/warnings (redacted; PINs/codes never appear in logs)

10 app (pid 10425) `W` lines total, zero `E`, zero `FATAL`, zero app crashes:

```
21:06:40.279 SecureGuard: HTTP POST /api/secure-guard/unlock falhou: timeout        # §4 wedge
21:08:06–21:08:15 AegisBridge: Host http://127.0.0.1:5678 falhou: SocketTimeoutException: timeout   # x3, expected: phone has no loopback bridge
21:08:07–21:08:15 AegisBridge: Host http://10.0.2.2:5678 falhou: failed to connect … after 1500ms  # x3, expected: emulator gateway unreachable from physical phone
21:05:04 ViewRootImpl[MainActivity]: frameCompleteCallback/frameDrawingCallback timeout 5001/5003ms # x2, dialog render jank, benign
21:09:56 IInputConnectionWrapper: requestCursorAnchorInfo on inactive InputConnection               # benign IME noise
```

App falls through `127.0.0.1 → 10.0.2.2 → <host-LAN-IP>:5678`; only the LAN leg succeeds on a physical phone (Connected + live data throughout except the §4 window).

## 4. Bridge incident (resolved, no board mutation)

- 21:06:40 `unlock` POST timed out while **two** bridge instances (PIDs 10408/21488, both `LISTEN` on `0.0.0.0:5678` via `SO_REUSEADDR`) contended for the single USB HID handle; HTTP `/bridge/info` and CLI `--probe` then went `offline`.
- Per task instruction ("restart it if dead"): killed 10408+21488, started ONE instance → CLI probe + HTTP 200 `USB HID 303A:AE61 online`; phone `Refresh` → `Connected`.
- At 21:08:52 a second instance (PID 25260, other lane's supervisor) appeared on `:5678`; bridge transport later settled to **UART COM7** (`vid_pid 10C4:EA60`). My instance was removed (only the removal, restoring single-server state) — never touched the other lane's process. Phone path stayed healthy via the remaining instance.
- Hypothesis (`tools/host_hardware_android_bridge.py:703-781`): `detect_and_connect` prefers UART (holds COM7 ~seconds per scan); dual instances serial-scan + HID-contend → wedge. Single instance = stable for the rest of the drive.

## 5. UART capture + board log (redacted excerpts)

- Capture `board_errors.log` ran 21:02:03–21:07:39 (5.6 min), then the holder died during the §4 contention window; resilient retry loop kept `SERIAL-OPEN-ERR (Acesso negado)` notes since COM7 became the other bridge's active UART transport (left untouched deliberately).
- Opening COM7 emits a DTR pulse despite `dtr=False/rts=False`: board `POWERON` boot ROM at 21:02:03 (capture-induced reboot #1, documented).
- Board boot state: ESP-IDF v5.3.1, ESP32-S3 r0.2, 16 MB flash, PSRAM 8 MB, `FIDO2 / WebAuthn ready on native USB (HID Usage Page 0xF1D0)`.
- Warnings (no panic, no `E`, no Guru, no brownout in 5.6 min):
  - `[WARN] eFuse nao provisionado (Unprovisioned); usando chaves efemeras TRNG (modo DEV…)` → `tools/factory_provision.py` never run on this board.
  - `[WARN] PIN NVS inconsistente; sem PIN.` → board-side PIN store empty at every boot.
  - Legacy-driver warnings (`pcnt`, `i2c`, `timer_group`) — informational.
- Live traffic sample: `[CTAPHID] … [USB][SG] op 0x3A (status 0x00). [CTAPHID] Sent SG response (583 bytes)` + 3 s heartbeats (`USB Mounted: true`).
- Uptime readings imply reboots ~21:10:46 and ~21:14:22 (bridge serial-scan windows); slot data survived (1 used at end). No reboot was initiated by this drive after 21:02:03.

## 6. Board final state (0x3A read-only, 21:29:44)

`GET /bridge/info` (read-only): `connected=true`, `transport=UART`, `port=COM7`, `vid_pid=10C4:EA60`, `status=online`, `cid=0xa0201`, `uptime_s=922`, `usb_native_present=true`.
App final: `UNLOCKED`, `Session Active`, `[5/5]`, `Connection · Connected`, `Slots: 1 used, 31 available`, `All (1)` with `tst-drive1` listed. No deletes, no user-slot changes, no PIN/ownership/NVS mutations.

## 7. Failure / observation list with root-cause hypotheses

- **F-A — PIV card dead navigation in installed APK.** Tap = no-op, no log. Source wires it correctly now (`MainActivity.kt:236-249`, `AppRoutes.PIV`, `PivScreen.kt:69`). Hypothesis: phone APK predates the F2 fix (`FriendlySettingsAndThemeScreen.kt:1385 onClick = onNavigateToPiv` + default `{}` in old build). Needs rebuilt-APK retest.
- **F-B — PIN does not persist across session end on this board.** After each 5-min session expiry, status reverts to `UNPROVISIONED` (no reboot); re-provision with `1111` restores unlock. Consistent with boot `[WARN] PIN NVS inconsistente; sem PIN`. Slot data persists; PIN/session does not. Hypothesis: NVS PIN store unprovisioned/broken on this unit; app honestly mirrors device state (`SecureGuardViewModel.kt:262-264` "Estado honesto… nunca forja UNLOCKED").
- **F-C — Dual-bridge wedge (§4).** Transient; resolved. Recommendation: single bridge per host (or log a clear "duplicate server" error instead of silent HID contention).
- **F-D — UART capture contention.** COM7 held persistently by the other lane's bridge (active UART transport). Captured 21:02–21:07 + contention notes; no board-side evidence gap for verdicts (all flows verified via HID path + app + bridge reads).
- **F-E — Board rebooted during bridge contention windows** (uptime math: ~21:10:46, ~21:14:22; plus capture-induced 21:02:03). No data loss observed for slots.
- **F-F — Concurrent-lane interference on the shared phone.** Motorola Camera forced itself to foreground twice (first-run tutorial + full UI; exited without touching shutter/settings/gallery); vault↔detail screens flipped without my input once; `/sdcard` holds other-lane dumps (`probe*`, `ble_ui*`, `tour_uidump`, `ui*`). All matrix verdicts re-verified with a dump immediately after my own tap.
- **F-G — Locked-state list shows `0 used` while `31 available` stays live.** Fail-closed display artifact (enumeration gated, free-slots live). Reappears correctly (`1 used`) on unlock.
- **F-1 (repeat) — PT success string on EN UI:** `Cofre desbloqueado com sucesso!` snackbar after unlock (`SecureGuardViewModel.kt` success path uses literal or untranslated res — same pattern as `ClickThroughFindingsTest` F1).
- **F7 (repeat) — version drift across screens:** vault `v2.4.1-rc1` vs caps `Firmware 1.0.0` vs OTA `Firmware v3.4.0-esp32s3` (`KeyVaultHubScreen.kt:643-645` single-source comment exists; OTA card still shows its own metadata).

## 8. Evidence states / extension boundaries (read-only notes)

- Test doubles live only in `src/debug` + `src/test` (release no-ops); this release-APK drive used zero mocks — every PASS above is live board traffic or local read-only UI.
- `values-pt/strings.xml` mojibake is an extraction artifact only; on-screen PT renders correctly (verified visually in dumps: `Tema e Aparência`, `Segurança e PIN de Hardware`, `Cofre`).
- TOTP `e2e-test` entry and bound key `Minha Chave Principal` predate this drive (other lane's); untouched.
- Committed with this report: nothing else. Parent-lane dirty files left exactly as found.
