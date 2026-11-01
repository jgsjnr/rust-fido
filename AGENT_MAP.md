# AGENT_MAP - Master map for agents (where to find, where to put new work)

Keep AGENTS.md intact. This file routes agents. It changes rarely.
Style: ASD-STE100. Use short sentences. Use active voice.

## 1. Where to find what

| Need | Open this file | Section |
|---|---|---|
| Vision, hardware, crates, transports, app, firmware, security, system tray | docs/project/PROJECT.md | 1-10 |
| Interactive topology, cards, wire opcodes, source files | docs/project/ARCHITECTURE-MAP.html | all |
| Master execution plan, 7 security gaps, 6 product opportunities, eFuse policy | MASTER_EXECUTION_PLAN.md (root) | 1-6 |
| Roadmap, TODO, follow-ups, features, master plan integration, session history | docs/plans/PLANS.md | 1-7 |
| Executable tasks T0-T20, HIL, batteries, checklists, handoffs, rites | docs/tasks/TASKS.md | 1-7 |
| Quarantine index, security gap evaluations, product opportunity analysis | docs/evaluation/EVALUATION.md | 1-5 |
| Firmware test tripwire hooks (do not move or delete) | docs/test-hooks.md | all |
| Build, lint, conventions, context rules | AGENTS.md (root, untouched) | all |
| Product overview, badges, quick start, directory layout | README.md (root) | all |
| Desktop Companion App, System Tray, OpenSSH Agent, OS Login | app-tray/ | all |

## 2. Canonical documentation structure

The project enforces exactly 4 canonical documentation folders in `docs/`:
- `docs/project/`: System design, architecture specifications, and interactive map (`PROJECT.md`, `ARCHITECTURE-MAP.html`).
- `docs/plans/`: Execution roadmaps, sprint records, and integrated master execution plans (`PLANS.md`).
- `docs/tasks/`: Executable task matrices, HIL verification, batteries, and release checklists (`TASKS.md`).
- `docs/evaluation/`: Benchmark results, evaluation of security gaps and opportunities, legacy quarantine index (`EVALUATION.md`).
- `docs/test-hooks.md`: Preserved intact for Rust firmware tripwire tests.

Never create loose markdown files outside these 4 canonical locations.

## 3. Tree (ASCII)

```text
E:/projetos/fido-tray-guard (feat/responsive-guard-tray-ssh)
|-- AGENTS.md                  (rules, intact)
|-- AGENT_MAP.md               (this master routing map)
|-- MASTER_EXECUTION_PLAN.md   (master execution plan phases 0-5, 7 gaps, 6 opportunities)
|-- README.md                  (product overview, architecture, quick start)
|-- docs/
|   |-- project/PROJECT.md     (vision + arch + modules + security)
|   |-- project/ARCHITECTURE-MAP.html (interactive visual architecture map)
|   |-- plans/PLANS.md         (roadmap + TODO + features + master plan integration)
|   |-- tasks/TASKS.md         (executable + HIL + batteries + rites + T0-T20)
|   |-- evaluation/EVALUATION.md (quarantine index + security gaps & product opportunities)
|   |-- test-hooks.md          (tripwire test hooks, preserved intact)
|-- crates/
|   |-- aegis-secure-guard/    (pure #![no_std] Zero-Trust 10-state security authority, PBKDF2 verifiers, ECDH channel)
|   |-- aegis-fido-core/       (pure #![no_std] cryptographic engines, FIDO2/CTAP2.3 core, Shamir, Clear Signing)
|   |-- aegis-fido-firmware/   (ESP32-S3 FreeRTOS, router, eFuse safety lock, SSD1306 code-only, prod-strict)
|   |-- aegis-fido-usb/        (CTAPHID 64B framer, channel locks)
|   |-- universal-device-sdk/  (cross-platform CBOR DTOs)
|   |-- uniffi-bridge/         (UniFFI C-ABI/JNI bindings for Android)
|-- app-tray/                  (Desktop Companion App: C# .NET 9 WPF/WinForms + Python multiplatform)
|   |-- dotnet/AegisKeyTray/   (C# .NET 9 System Tray App, OpenSshAgentPipeServer, HardwareBridgeClient)
|   |-- openssh_native_agent.py (OPP-01 native OpenSSH agent for sk-ssh-ed25519 keys)
|   |-- os_login_companion.py  (OPP-04 Windows Hello CDF & Linux PAM companion)
|   |-- aegis_tray.py          (Python cross-platform system tray implementation)
|-- app-android/               (Android companion app in Kotlin Jetpack Compose)
|-- tools/                     (host hardware bridge, web dashboard, simulators)
|-- scripts/                   (CI/CD automation, release cleanliness verification)
```

## 4. Where to put new work

- Put vision, architecture, module, transport, app, firmware, system tray, or security changes in `docs/project/PROJECT.md`.
- Put interactive cards, wires, or topology nodes in `docs/project/ARCHITECTURE-MAP.html`.
- Put roadmap, TODO, follow-up, feature plan, or session notes in `docs/plans/PLANS.md` (cross-referencing `MASTER_EXECUTION_PLAN.md`).
- Put executable tasks, HIL proofs, battery results, checklist ticks, handoffs, or rites in `docs/tasks/TASKS.md`.
- Put legacy notes or evaluations of gaps and opportunities in `docs/evaluation/EVALUATION.md`.
- Do not create markdown files outside these canonical locations.

## 5. Critical Safety Invariant (eFuse Zero-Brick Policy)

> [!CAUTION]
> **DO NOT EXECUTE EFUSE WRITE COMMANDS IN DEVELOPMENT (`COM7`)**
> Writing OTP eFuses (`BLOCK7`, `SPI_BOOT_CRYPT_CNT`, `SECURE_VERSION`) irreversibly locks ESP32-S3 boards.
> All eFuse code is maintained as static audit specifications protected by `burn-efuse-irreversible-do-not-enable` feature locks.
> Any automated script or command attempting to burn eFuses without explicit factory authorization is strictly blocked.
