# PLANS — Roadmap, TODO matrix, follow-ups, features, session history

> Style: ASD-STE100. Use short sentences. Use active voice. Use one instruction per sentence.
> Scope: consolidates roadmap, TODO, follow-ups, yellow items, next steps, features, dated sessions as history.
> Sources: plans/STATE, MATRIZ-TODO, TASKS-microdetalhe, F2-F3-HIL-MAP, RELEASE-checklist,
> risk-acceptance, SIMULACAO-final, plans/*/plan|architecture|affect, docs/plano-*, finalizacoes,
> firmware-fina, estado-final, seis-produtos, proximos-passos, sessao-20-10, unificacao-worktrees.

## 1. Roadmap

| Phase | Goal | Gate |
|---|---|---|
| Fase 0-1 SDK | Freeze capabilities and providers | 38 SDK tests green |
| Fase 1 crypto | Add P-256, AEAD, hash, RSA, extra curves, HRNG | Vectors plus clippy clean per module |
| Fase 2 FIDO | Prove CTAP machine over transport | Host plus device roundtrips |
| Fase 2 OTA | Own `ota.rs` plus `nvs_backend.rs` | Manifest 104 B verified |
| Fase 3 PIV/proximity | Finish transfer plus walk-away | Bonded RF test |
| Fase 4 wallet/OATH | Persist GEN-LIST-CODE-DELETE | NVS post-EN roundtrip |
| Fase 5 release | Run dev to HIL to nightly to pre-release to release | Checklist section 3 green |
| Loop FreeRTOS | Stabilize native tasks plus proximity scheduler | 7/7 bench plus 8/8 suite on HW |

- Run phases in order T0, T1, T2, then T3-T12, then T13.
- Close no phase without doc plus build plus flash plus battery on large change.
- Freeze wire from T4. Treat wire change as major plus migration plus HIL.

## 2. TODO matrix (condensed from MATRIZ-TODO)

| ID | Item | Status | Owner |
|---|---|---|---|
| F0-01 | SDK capabilities and providers | Ready | sdk |
| T-CR-01..06 | P-256, AEAD, hash, RSA, extra, HRNG | Ready | firmware-crypto |
| T-FIDO | CTAP machine over CTAPHID and serial | Partial, transport ready | firmware-ctap |
| T-OTA | Manifest, stage, apply, rollback | In progress | firmware-ota |
| T-PIV | CCID driver plus applet persist | Partial, handshake done | firmware-piv |
| T-PROX | Beacon, verifier, tick, bonded gates | Ready on host, RF pending | firmware-prox |
| T-WALLET | Store-only slots plus ADDR | Ready | firmware-wallet |
| T-OATH | PUT/LIST/CODE/DELETE on device | Ready | firmware-oath |
| T-BLE | GATT 0xFFFD plus FFF1 plus bonding | Ready | firmware-ble |
| T-WIFI | AP plus station plus mDNS | Ready as C component | firmware-wifi |
| T-DISP | LCD plus headless plus LED table | Ready | firmware-ui |

- Apply generation rules: GEN-DEVICE generates on device, GEN-APP-STORE generates in app and stores as envelope, GEN-NA never generates.
- Apply standard gate: `cargo test -p <crate>` plus `cargo clippy -p <crate> --all-targets -- -D warnings` plus section 9 criteria.
- Roll back with `git revert <commit>` or `git checkout -- <scope>`. Never touch outside scope.

## 3. Follow-ups F1-F4 plus yellows plus next steps (single list)

| Item | Severity | Status | Acceptance |
|---|---|---|---|
| F1 PIN plumbing in vendor ops | Medium | Done 20/10, live | PUT with PIN `0x00`, without PIN `0x02` |
| F2 vendor keys and OATH executor | Large | Done 20/10, live | Real GEN-LIST-CODE-DELETE plus NVS post-EN |
| F3 persist `pin_hash` plus retries in NVS | Small | Done 20/10, live | setPIN, EN, token works after reboot |
| F4 CCID/PIV on USB | Large | Enumerated 20/10, handshake 100 percent, transfer pending | OpenSC sees card plus GEN/AUTH P-256 end-to-end |
| Yellow: LED eyes check | User | Open | Confirm order, flicker, green |
| Yellow: BLE bond plus privileged ops with UP | User plus agent | Open | Bond, open 60 s window, run op, close |
| Yellow: walk-away air test | Hardware | Blocked, needs RF bonded | Lock at 15 s away, stay locked on return |
| Yellow: burn eFuse | Factory | Blocked, explicit approval | Dry-run passes first |
| P0 hardware immediate | Hardware | Open | Needs board on bench |
| P1 end-to-end pairing in app | App | Open | Pair through app screens |
| P2 pending code | Code | Open | Port fob_id FFI plus factory `K_prox` flow |

- Merge the 6 pending lists here. Keep no separate yellow, follow-up, or next-step file.
- Merge the 3 handoffs here as history (see section 6). Keep no separate handoff file.

## 4. Features (one row per plan family)

| Feature | Plan waves | Affect scope | Status |
|---|---|---|---|
| Carteira cripto store | W1 store, W2 policy | Firmware vault plus app screens | Ready, slot policy enforced |
| Conexao BLE fim-a-fim | W1 GATT, W2 bond, W3 app | NimBLE plus Windows agent plus app | Ready on host, RF pending |
| Fido auditoria (NASA) | W0 gates, W1 P0, W2 L0-L5 | Mocks audit plus AEGN v1-v2 | Done, contained mocks, zero hardcoded secrets |
| Fido UX conex | Stage A BLE real | App transport | Approved, in execution |
| PIV BLE proximity | W1 skeleton, W2 beacon, W3 multi-OS | `proximity.rs`, `ble_nimble.rs`, 3 host agents | W1 verified, tick wired, RF pending |
| Seis implementacoes produto | W1 FIDO/PIV/prox, W2 wallet/OATH/OTA | Six product tracks | FIDO ready, PIV partial, prox host-complete |
| Sistema OTA | W1 parallel, W2 sequential | `ota.rs`, `nvs_backend.rs`, server | In progress |
| Unificacao worktrees | W0 base, W1 one-by-one, W2 consolidate | Branches `fd-*` into one | Base recorded, merge rehearsal read-only |
| Validacao USB telas | W0 emulator, W1 serial, W2 screens | Simulator, COM7/COM8, 22 screens | Emulator 22/22 pass, COM7 validated, COM8 pending reflash |
| Vault cofre flash seguro | W1 parallel, W2 sequential, W3 verify | Migration from `main@4b28aa4` | Planned |
| F2 QEMU plus F3 D08a | F2 smoke, F3 USB | QEMU plus D08a via USB | F2 smoke only, F3 denies bad-sig end-to-end |
| SIMULACAO final F5 plus F4 remainder | Merge rehearsal, zero-press | `git merge-tree`, no second device | Read-only done, zero-press externally blocked |

- Keep each `task.md` as requirements plus out-of-scope plus acceptance.
- Keep each `architecture.md` as approach plus components plus data flow.
- Keep each `affect.md` as files plus systems plus risk.
- Keep each `plan.md` as dated waves. Treat them as history after merge.

## 5. Release path and risk

- Follow pipeline: dev, HIL, nightly, pre-release, release.
- Run orchestrator: env-check, test, clippy, ESP build, flash, boot `ONLINE and ACTIVE`, simulator demo, Rust suite, e2e, probes, validate, report SHA256.
- Require `--confirm` for destructive steps: wipe, OTA apply, provision load, erase flash, eFuse burn.
- Freeze contract: opcode `0x05 NEED_BINDING` never on USB, `6D 00` honest, `0x2E` rescue, `0x39` PIV enroll, OTA manifest 104 B, PIV slots 24-27, canonical TLV.
- Prove `TEST_*` absence in release with `check-release-clean.py`.
- Treat QEMU-S3 as smoke only. Never count QEMU as hardware verification.
- Accept formal risk: no Secure Boot and no Flash Encryption in automatic path. Burn requires explicit factory approval.
- Record SIZE Wave1 offline: keep C baseline 2026-10-18, measure S3 bins, report bytes against factory max 3145728.

## 6. History (dated sessions, summarized)

- 2026-10-19 validacao-usb-telas Step 4: web assisted tab, docs reconciled, store rollback fix, 87/87 crate tests.
- 2026-10-19 Waves 1-2: wallet 17 tests, PIV skeleton plus proximity plus win agent, 291/291 workspace, clippy clean.
- 2026-10-20 F4 session: CCID C driver plus composite descriptor plus FFI plus Rust applet persist, USB 72 plus firmware 250 tests, clippy zero.
- 2026-10-20 finalizacoes: F4 E2E on Linux, RSSI lock integrated, board loop closed.
- 2026-10-20 HANDOFF Wave2 Step3: work done, observed evidence, pending items with reasons.
- 2026-10-20 proximity handoff: Near/Away/Locked plus beacon plus 3 host agents, origin green 34 plus 34/33/33.
- 2026-10-20 FreeRTOS loops 1-4: native tasks, scheduler wiring, FFI MAC, S3 release builds 483936 B then 821808 B, bench 7/7, suite 8/8 on HW.
- 2026-10-21 vigilance: no `entendendo o projeto` branch or lane found, fetch clean, 3-to-5 retry rule set.
- SIMULACAO-final: `git merge-tree` rehearsal done read-only, zero-press externally blocked without second device.
- Unificacao: base record Wave 0 at `4b28aa4`, merge on demand, consolidate after 4 joins.
