# TASKS — Executable tasks, HIL, batteries, checklists, handoffs, rites

> Style: ASD-STE100. Use short sentences. Use active voice. Use one instruction per sentence.
> Scope: consolidates executable tasks T0-T20, HIL L0-L4, serial battery, test hooks, user checklist,
> bonding walk-away, handoffs, rites, bench, emulators, QEMU, and desktop system tray verification.
> Sources: MASTER_EXECUTION_PLAN.md, docs/plano-testes-hil, bateria-serial, test-hooks, checklist-usuario, bonding-walkaway,
> HANDOFF-*, secure-guard/04-06+09, bench-*, emuladores, qemu, sessao-20-10, linux-bringup,
> GUIA_RITOS, lifetime-debug, live-monitor, MACHINE, REGRAS-automacao.

---

> [!CAUTION]
> ### CRITICAL HARDWARE SAFETY POLICY — eFuse OTP Protection (`DO NOT EXECUTE`)
> **NEVER EXECUTE COMMANDS TO BURN eFuses ON HARDWARE (`esptool.py burn_efuse`, `BLOCK7`, `SPI_BOOT_CRYPT_CNT`, `SECURE_VERSION`).**  
> eFuse burning in the ESP32-S3 is permanent, irreversible, and locks hardware against reprogramming.  
> All eFuse modules (`efuse_safety_lock.rs`, `GAP-01`, `GAP-03`, `GAP-07`) are guarded by `EFUSE_WRITE_HARD_LOCKED = true` and `feature = "burn-efuse-irreversible-do-not-enable"`. Development boards on `COM7` remain unburned to preserve flashing and test capabilities.

---

## 1. Task list T0-T20 (executable)

| Task | Owner | Command | Gate |
|---|---|---|---|
| T0 Freeze rules plus COM7 matrix | orchestration | `powershell scripts/env-check.ps1` | MACHINE revalidated |
| T1 Zero-touch orchestrator | host | `python tools/aegis_auto.py full --port COM7` | R6 plus R11 green on device |
| T2 Simulator as full remote | host | `python tools/app_simulator.py --port COM7 --demo` | Privileged op needs 60 s window plus UP plus PIN |
| T3 Doc sync | firmware | `cargo test -p aegis-fido-firmware` | Display stub drift closed |
| T4 Wire freeze | firmware | Review opcodes plus manifest | Wire change needs major plus migration |
| T5 BLE bond plus wallet gates | firmware plus app | Bond, run GEN/LIST/ADDR | `NEED_BINDING` outside window |
| T6 OATH on device | firmware | PUT/LIST/CODE/DELETE | NVS persists after EN |
| T7 PIV enroll `0x39` | firmware | Enroll plus GEN/AUTH | OpenSC handshake passes |
| T8 OTA stage and apply | firmware | Stage plus apply with `--confirm` | Manifest 104 B verified |
| T9 Provision load | factory | `factory_provision load --confirm` | Pins plus integrity verified |
| T10 Killswitch and rescue | firmware | `wipe --confirm`, `0x2E` rescue | Deny probes pass |
| T11 Size plus release clean | release | `check-release-clean.py` | No `TEST_*` in release |
| T12 Nightly plus pre-release | release | Nightly pipeline | Tag plus SHA256 plus rollback rehearsed |
| T13 Release | release | Release pipeline | Real tag plus push with approval |
| T14 Desktop Companion Tray App | desktop | `dotnet build app-tray/dotnet/AegisKeyTray/` | C# .NET 9 tray builds clean |
| T15 Native OpenSSH Agent Provider | desktop | `python -m unittest app-tray/test_tray_and_ssh_guard.py` | Named Pipe and sk-ssh-ed25519 pass |
| T16 OS Login Companion | desktop | `python -m unittest app-tray/test_tray_and_ssh_guard.py` | Windows Hello CDF & PAM logic pass |
| T17 ECDH Channel & Glitch Guard | core | `cargo test -p aegis-fido-core secure_channel glitch_guard` | Vector tests pass, zero leak |
| T18 CTAP 2.1 Extensions & Shamir | core | `cargo test -p aegis-fido-core extensions_ctap21 shamir_slip39` | 2-of-3 quórum & hmac-secret pass |
| T19 Clear Signing & OLED Buffer | core + fw | `cargo test -p aegis-fido-core clear_signing` | Framebuffer 128x64 unit tests pass |
| T20 eFuse Safety Lock Audit | firmware | `cargo test -p aegis-fido-firmware efuse_safety_lock` | Confirm zero-brick lock active |

- Use default port COM7. Override with `%AEGIS_PORT%` or `--port COMx`. Use baud 115200.
- Require `--confirm` for wipe, OTA, provision, erase, burn. Deny without it.
- Keep Rust code out of planning lanes. Record commands, do not execute them there.

## 2. HIL matrix L0-L4

| Level | Name | Setup | Proof |
|---|---|---|---|
| L0 | Host offline, no device | `cargo test`, clippy | Suite green, zero warnings |
| L1 | Simulator: dummy plus QEMU plus Renode | Dummy first, skip Renode if absent | Smoke only, never RealVerified |
| L2 | Serial E2E classic UART0 115200 8N1 | COM8 plus reflash | Pending reflash |
| L3 | S3 E2E plus test-mode diag | COM7 plus test-mode fw | Validated 20/10 & 01/11 |
| L4 | Destructive plus factory | COM13 plus `--confirm` | Erase plus reflash. eFuse burn requires explicit factory sign. |

- Run L0 before any L1. Run L1 before any L2. Run L2-L3 before L4.
- Treat F2 QEMU interactive as smoke. Treat F3 D08a as blocked on bad-sig end-to-end (FINISH denies).
- Record HIL map: current state with verifiable evidence, what F2 lacks, what F3 lacks.

## 3. Batteries and benches

### 3.1 Serial battery (standard playbook)

- Use Python tools only. Automate every step.
- Run single command. Invent no custom command.
- Run order: env-check, `cargo test`, clippy, ESP build, flash, boot check, `app_simulator --demo`, `test_aegiskey_rust.py`, `e2e_user_test.py`, `e2e_zero_press.py`, gate probes, `validate_aegiskey.py`.
- Report PASS or FAIL plus SHA256 artifact.

### 3.2 Bench FreeRTOS S3 (hardware)

- Prepare environment plus hardware first.
- Flash S3 on COM7. Expect correct boot plus serial monitor logs.
- Run 7/7 bench: chip_id, boot tasks, high-water, USB VID/PID, suite 8/8, killswitch dry-run, factory dry-run.
- Record bundle name `bench-freertos-<date>`. Keep 8272 B high-water reference.

### 3.3 Bench destructive (COM13, freertos plus proximity)

- Erase full flash first. Reflash clean at factory offset.
- Treat erase as destructive with no return. Require explicit approval.
- Verify hash after flash. Verify USB composite after boot.

### 3.4 Pre-flash emulators (memory protocol)

- Run host first, always.
- Run tscircuit dummy if Renode is absent. Skip Renode safely.
- Map fast table: host, dummy, QEMU, Renode.

### 3.5 QEMU S3 virtual bench (recipe)

- Mount 16 MB flash image from day artifacts once per build.
- Boot QEMU S3. Treat boot as smoke.
- Never claim hardware verification from QEMU.

### 3.6 Linux bring-up

- Prepare machine once: install ESP toolchain.
- Map Windows to Linux ports.
- Reuse same battery commands on Linux.

## 4. Checklists

### 4.1 User checklist (physical H1-H7 plus lock plus WUDF)

- [ ] Phase 0: prepare 5 min, touch nothing.
- [ ] Phase 1: install APK or launch Desktop Companion System Tray.
- [ ] Phase 2: run gestures H1-H4, confirm LED order.
- [ ] Phase 3: run H5-H7, confirm UP plus PIN.
- [ ] Phase 4: test lock plus walk-away.
- [ ] Phase 5: confirm WUDF behavior on Windows.
- [ ] Phase 6: test Native OpenSSH Agent with `ssh -T git@github.com`.

### 4.2 Bonding plus walk-away runbook (turnkey)

1. Meet prerequisites: charged board, bonded host, test-mode fw if inbox needed.
2. Bond device. Open 60 s window with 5 s BOOT hold.
3. Run privileged op with UP plus PIN. Confirm `0x00`.
4. Walk away 15 s. Confirm lock.
5. Return. Confirm stay-locked (manual unlock only).
6. Send USB traffic. Confirm BLE silences.

- Diagnose failures by symptom: no bond means pairing lost, `0x05` means window closed, `0x02` means PIN missing, silence means USB veto active.

### 4.3 Desktop Companion & OpenSSH Agent Runbook

1. Launch Desktop Companion: `python app-tray/aegis_tray.py` or execute `AegisKeyTray.exe`.
2. Insert AegisKey into USB port. Confirm native OS notification: "AegisKey Connected".
3. Check OpenSSH Pipe: Windows Named Pipe `\\.\pipe\openssh-ssh-agent` active.
4. Set environment variable: `$env:SSH_AUTH_SOCK = "\\.\pipe\openssh-ssh-agent"`.
5. Execute `ssh-add -l`. Verify AegisKey resident `sk-ssh-ed25519` key listed.
6. Trigger SSH connection. Confirm blinking LED on AegisKey requesting User Presence (UP).
7. Touch physical button GPIO 0. Confirm authentication succeeds.

## 5. Test hooks and rites

- Read text hooks only on D1/UART in test-mode. Keep them off in release.
- Audit hooks by manifest. Audit bypasses by `cfg!` at compile time.
- Enforce `prod_strict_guard.rs` (GAP-04): `compile_error!` when `prod-strict` and `test-mode` are both defined.
- Run `TEST_LIFETIME_DUMP` only with test-mode, default OFF.
- Run lifetime debug terminal only in dev. Never enable it in release.
- Run live monitor only in dev. Never enable it in release.
- Follow rites guide: GPIOs, USB connect, BLE pair, LED colors, wallet and key management.

## 6. Handoffs (consolidated, no separate files)

| Handoff | Done | Evidence | Pending with reason |
|---|---|---|---|
| 2026-10-20 Wave2 Step3 plus HW | F4 proof, RSSI lock | Observed logs, 8/8 suite | RF bonded test needs second radio |
| Proximity worktree RSSI lock | Near/Away/Locked plus beacon | 34 plus 34/33/33 green on origin | FFI MAC plus factory `K_prox` flow |
| Secure Guard 06 canonical | File map per layer | 147 core tests pass | Port remaining gates to FreeRTOS scheduler |
| 2026-11-01 Master Plan Hardening | 7 Gaps closed, 6 Opportunities delivered | Unit tests in core, fw, app-tray | Physical eFuse burn blocked by policy in lab dev |

- Write each handoff with scope, contract, risks, tests, acceptance, evidence quality, external blockers.
- Mark evidence as observed, simulated, or blocked. Never claim `REAL_VERIFIED` without adjacent metadata.
- List external blockers explicitly: second device, RF chamber, factory approval, COM port access.

## 7. Validation results (summary)

- Rust core `secure_guard` suite: 147 tests PASS on host workspace.
- New cryptographic modules:
  - `secure_channel.rs` (GAP-02 ECDH P-256 + HKDF + AEAD): Verified.
  - `glitch_guard.rs` (GAP-06 GlitchResistantBool + TRNG jitter): Verified.
  - `crypto.rs` (GAP-03 Hardware HMAC-anchored KDF): Verified.
  - `extensions_ctap21.rs` (OPP-02 hmac-secret & largeBlobKey): Verified.
  - `shamir_slip39.rs` (OPP-03/05 Shamir 2-of-3 in GF(256)): Verified.
  - `clear_signing.rs` (OPP-06 Web3 Clear Signing parser): Verified.
- Firmware suite:
  - `efuse_safety_lock.rs` (GAP-01/03/07): Zero-brick policy verified, writes hard-locked.
  - `prod_strict_guard.rs` (GAP-04): Isolation between test-mode and prod-strict verified.
  - `oled_ssd1306_code_only.rs` (OPP-06): Code-only 128x64 virtual framebuffer verified with hardware attach = false.
- Desktop Companion App:
  - `app-tray/test_tray_and_ssh_guard.py`: All tests PASS (System tray state, OpenSSH Agent Named Pipe, OS Login Companion).
- Hardware: 8/8 Rust suite twice on different bins, bench 7/7, killswitch dry-run plus 13 unit PASS, factory dry-run PASS.
- Blocked by design: physical eFuse permanent burn (blocked by Zero-Brick Policy to preserve COM7 dev boards).

---

## 8. Verification Checklists: WS2812 LED States and User Journeys (J1 to J8)

### 8.1 WS2812 RGB LED States Verification (`GPIO 48`)

- [ ] **L1 Soft Cyan (`#00283C`)**: Connect unprovisioned key to USB. Confirm steady Soft Cyan glow. Confirm zero keys in vault.
- [ ] **L2 Amber / Orange (`#3C1900`)**: Confirm steady Amber glow on boot of provisioned key or after clicking *Lock Now*. Confirm vault opcodes return `0x36 / 403`.
- [ ] **L3 Emerald Green (`#003C0F`)**: Authenticate with master PIN. Confirm steady Emerald Green glow. Confirm vault opcodes return `0x00 OK`.
- [ ] **L4 Fast Blinking Cyan/White (5 Hz)**: Trigger FIDO2 MakeCredential or SSH signature. Confirm rapid 5 Hz blinking until `GPIO 0` button is touched.
- [ ] **L5 Breathing Blue (1 Hz)**: Hold `BOOT` button for 5 seconds to open pairing window. Confirm smooth 60-second breathing pattern.
- [ ] **L6 Alternating Red / Amber**: Enter incorrect PIN (attempts 3 and 4). Confirm alternating warning pattern and backoff delays (2s and 5s).
- [ ] **L7 Intense Red Solid / Pulse (`#5A0000`)**: Enter 5 consecutive incorrect PINs. Confirm intense red alert. Confirm standard keypad is disabled and Recovery Code is required.
- [ ] **L8 Locate Key (Wink)**: Send CTAPHID `0x88` wink command. Confirm rapid multi-color identification flashes.

### 8.2 End-to-End User Journeys Verification (J1 to J8)

- [ ] **Journey 1 (Clean Slate Baseline)**:
  - Connect key. Trigger factory reset via opcode `0x2B`.
  - Hold `GPIO 0` for 5 seconds. Confirm NVS format.
  - Verify storage partition contains 0 keys and LED turns Soft Cyan.
- [ ] **Journey 2 (Secure Guard Provisioning)**:
  - Submit new PIN over ECDH P-256 channel (`GAP-02`).
  - Verify PBKDF2-HMAC-SHA256 derivation and 256B NVS record write.
  - Verify 16-character Recovery Code generation and LED transition to Emerald Green.
- [ ] **Journey 3 (Silicon Keys, Clear Signing & Shamir)**:
  - Register WebAuthn passkey with touch confirmation on `GPIO 0`.
  - Submit EIP-1559 Ethereum transaction. Verify 128x64 display buffer formatting and clear parameters before signing.
  - Split master seed into Shamir 2-of-3 shares. Verify quórum reconstruction.
- [ ] **Journey 4 (Lock/Unlock Vault Gatekeeper)**:
  - Click *Lock Now* or disconnect USB. Confirm LED turns Amber.
  - Verify vault keys are hidden (`0x36 / 403`) while standard WebAuthn logins still function.
  - Unlock with PIN. Confirm LED turns Emerald Green and vault restores.
- [ ] **Journey 5 (Desktop System Tray & OpenSSH SshGuard)**:
  - Insert key into USB. Verify OS native connection notification.
  - Start OpenSSH Named Pipe server (`\\.\pipe\openssh-ssh-agent`).
  - Execute `git push` or `ssh-add -l`. Verify physical touch confirmation on `GPIO 0`.
  - Disconnect key. Verify `ssh-add -D` auto-purges identities from agent memory.
- [ ] **Journey 6 (BLE Proximity Walk-Away Lock)**:
  - Monitor BLE beacon RSSI. Simulate walking away (> 3 m for > 10 s, RSSI < -80 dBm).
  - Verify workstation lock (`LockWorkStation()` or PAM lock).
  - Return to workstation (RSSI > -65 dBm). Verify single-touch unlock via Windows Hello CDF / PAM without typing passwords.
- [ ] **Journey 7 (Emergency Recovery)**:
  - Enter incorrect PINs to trigger rate limiting and 5th failure lockout.
  - Verify LED illuminates Intense Red.
  - Submit 16-character Recovery Code over opcode `0x3E`. Verify access restoration and PIN counter reset.
- [ ] **Journey 8 (Silicon Security & eFuse Safety Lock)**:
  - Audit `crates/aegis-fido-firmware/src/efuse_safety_lock.rs`.
  - Confirm `EFUSE_WRITE_HARD_LOCKED = true`.
  - Verify that no permanent OTP burns can execute on `COM7` development boards.

