# AGENT_MAP - Master map for agents (where to find, where to put new work)

Keep AGENTS.md intact. This file routes agents. It changes rarely.
Style: ASD-STE100. Use short sentences. Use active voice.

## 1. Where to find what

| Need | Open this file | Section |
|---|---|---|
| Vision, hardware, crates, transports, app, firmware, security | docs/project/PROJECT.md | 1-9 |
| Roadmap, TODO, follow-ups, features, session history | docs/plans/PLANS.md | 1-6 |
| Executable tasks, HIL, batteries, checklists, handoffs, rites | docs/tasks/TASKS.md | 1-7 |
| Quarantine index, old-to-new table, pending decisions | docs/evaluation/EVALUATION.md | 1-4 |
| Build, lint, conventions, context rules | AGENTS.md (root, untouched) | all |
| Product overview, badges, quick start | README.md (root, kept) | all |

## 2. Old-to-new table (condensed)

| Old location | New location |
|---|---|
| docs secure-guard 00-03 plus 07-08, capacidades-modulos, ble files, COMMS-map, binding, APP and app files, freertos files, display, matriz files, wifi, DESACOPLAMENTO, nvs schema, MACHINE, interop matrix | docs/project/PROJECT.md |
| plans STATE, MATRIZ-TODO, TASKS-microdetalhe, F2-F3-HIL-MAP, RELEASE-checklist, risk-acceptance, SIMULACAO-final, plans family files, docs plano files, finalizacoes, firmware-fina, estado-final, seis-produtos, proximos-passos, sessao-20-10, unificacao files | docs/plans/PLANS.md |
| docs plano-testes-hil, bateria-serial, test-hooks, checklist-usuario, bonding-walkaway, HANDOFF files, secure-guard 04-06 plus 09, bench files, emuladores, qemu, GUIA RITOS, lifetime files, live-monitor | docs/tasks/TASKS.md |
| Every other own markdown | docs/evaluation/quarantine files, indexed in EVALUATION.md |

## 3. Tree (ASCII)

```text
E:/projetos/fido-hygiene
|-- AGENTS.md                  (rules, intact)
|-- AGENT_MAP.md               (this master)
|-- README.md                  (product overview, kept)
|-- docs/
|   |-- project/PROJECT.md     (vision + arch + modules + security)
|   |-- plans/PLANS.md         (roadmap + TODO + features + history)
|   |-- tasks/TASKS.md         (executable + HIL + batteries + rites)
|   |-- evaluation/
|       |-- EVALUATION.md      (quarantine index)
|       |-- quarantine/        (all legacy .md, flattened names)
|-- crates/                   (Rust code, do not touch in doc lanes)
|-- tools/host_sdk/           (simulator + transport)
|-- tools/host agents         (proximity agents win linux macos)
|-- tools/app_simulator.py    (telecommand)
|-- scripts/                  (build, bench, sync)
|-- app-android/              (Android app + UniFFI)
```

## 4. Where to put new work

- Put vision, architecture, module, transport, app, firmware, or security change in docs/project/PROJECT.md.
- Put roadmap, TODO, follow-up, feature plan, or session note in docs/plans/PLANS.md.
- Put executable task, HIL proof, battery result, checklist tick, handoff, or rite in docs/tasks/TASKS.md.
- Put legacy or superseded note in docs/evaluation/quarantine/ and index it in EVALUATION.md.
- Create no new markdown outside these 4 files plus quarantine without a decision entry in EVALUATION.md.
- Keep one file per folder. Break this rule only for quarantine.

## 5. Validation lane (run before close)

1. Run git status --short. Confirm only intended moves plus new files.
2. Count markdown outside quarantine. Expect 7 files.
3. Open all 4 files. Confirm headings, tables, and diagrams render.
4. Run cargo test for full suite when code changed. Run cargo clippy with -D warnings for lint.
5. Write handoff with scope, contract, risks, tests, acceptance, evidence quality, external blockers.
6. Never claim REAL_VERIFIED without adjacent metadata: port, bin SHA, date, command.
7. Never write secrets, tokens, credentials, signing material, invitation codes, or external-host details.
