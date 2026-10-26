# TASKS — Executable tasks, HIL, batteries, checklists, handoffs, rites

> Style: ASD-STE100. Use short sentences. Use active voice. Use one instruction per sentence.
> Scope: consolidates executable tasks, HIL L0-L4, serial battery, test hooks, user checklist,
> bonding walk-away, handoffs, rites, bench, emulators, QEMU.
> Sources: docs/plano-testes-hil, bateria-serial, test-hooks, checklist-usuario, bonding-walkaway,
> HANDOFF-*, secure-guard/04-06+09, bench-*, emuladores, qemu, sessao-20-10, linux-bringup,
> GUIA_RITOS, lifetime-debug, live-monitor, MACHINE, REGRAS-automacao.

## 1. Task list T0-T13 (executable)

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

- Use default port COM7. Override with `%AEGIS_PORT%` or `--port COMx`. Use baud 115200.
- Require `--confirm` for wipe, OTA, provision, erase, burn. Deny without it.
- Keep Rust code out of planning lanes. Record commands, do not execute them there.

## 2. HIL matrix L0-L4

| Level | Name | Setup | Proof |
|---|---|---|---|
| L0 | Host offline, no device | `cargo test`, clippy | Suite green, zero warnings |
| L1 | Simulator: dummy plus QEMU plus Renode | Dummy first, skip Renode if absent | Smoke only, never RealVerified |
| L2 | Serial E2E classic UART0 115200 8N1 | COM8 plus reflash | Pending reflash |
| L3 | S3 E2E plus test-mode diag | COM7 plus test-mode fw | Validated 20/10 |
| L4 | Destructive plus factory | COM13 plus `--confirm` | Erase plus reflash plus burn with approval |

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
- [ ] Phase 1: install APK.
- [ ] Phase 2: run gestures H1-H4, confirm LED order.
- [ ] Phase 3: run H5-H7, confirm UP plus PIN.
- [ ] Phase 4: test lock plus walk-away.
- [ ] Phase 5: confirm WUDF behavior on Windows.

### 4.2 Bonding plus walk-away runbook (turnkey)

1. Meet prerequisites: charged board, bonded host, test-mode fw if inbox needed.
2. Bond device. Open 60 s window with 5 s BOOT hold.
3. Run privileged op with UP plus PIN. Confirm `0x00`.
4. Walk away 15 s. Confirm lock.
5. Return. Confirm stay-locked (manual unlock only).
6. Send USB traffic. Confirm BLE silences.

- Diagnose failures by symptom: no bond means pairing lost, `0x05` means window closed, `0x02` means PIN missing, silence means USB veto active.

### 4.3 Release checklist entry

- Run `RELEASE-checklist.md` pipeline (quarantined, summarized in PLANS.md section 5).
- Confirm scope, contract, executable pipeline, clean proof, tag, SHA256, rollback rehearsal.
- Block on R6, R7, R11, R12, R13, R14.

## 5. Test hooks and rites

- Read text hooks only on D1/UART in test-mode. Keep them off in release.
- Audit hooks by manifest. Audit bypasses by `cfg!` at compile time.
- Run `TEST_LIFETIME_DUMP` only with test-mode, default OFF.
- Run lifetime debug terminal only in dev. Never enable it in release.
- Run live monitor only in dev. Never enable it in release.
- Follow rites guide: GPIOs, USB connect, BLE pair, LED colors, wallet and key management.
- Follow screen journey: map each LCD screen to LED, require UP before vault OATH.

## 6. Handoffs (consolidated, no separate files)

| Handoff | Done | Evidence | Pending with reason |
|---|---|---|---|
| 2026-10-20 Wave2 Step3 plus HW | F4 proof, RSSI lock | Observed logs, 8/8 suite | RF bonded test needs second radio |
| Proximity worktree RSSI lock | Near/Away/Locked plus beacon | 34 plus 34/33/33 green on origin | FFI MAC plus factory `K_prox` flow |
| Secure Guard 06 canonical | File map per layer | 147 core tests pass | Port remaining gates to FreeRTOS scheduler |

- Write each handoff with scope, contract, risks, tests, acceptance, evidence quality, external blockers.
- Mark evidence as observed, simulated, or blocked. Never claim `REAL_VERIFIED` without adjacent metadata (port, bin SHA, date, command).
- List external blockers explicitly: second device, RF chamber, factory approval, COM port access.

## 7. Validation results (summary of 09)

- Rust core `secure_guard` suite: 147 tests PASS on host workspace.
- Firmware suite: 250 plus USB 72 plus proximity 34 on host, clippy zero, release clean.
- FreeRTOS host: 303 lib plus 11 bin plus 2 plus 3 plus 11 integration, clippy clean on 4 configs.
- Hardware: 8/8 Rust suite twice on different bins, bench 7/7, killswitch dry-run plus 13 unit PASS, factory dry-run PASS.
- Blocked: e2e base and all-safe without test-mode inbox, walk-away air loop by design, physical UP, bonded RF, eFuse burn.
