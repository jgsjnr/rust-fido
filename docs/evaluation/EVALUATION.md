# EVALUATION — Quarantine index (what moved, why, pending decision)

> Scope: index of every legacy markdown moved to `docs/evaluation/quarantine/`.
> Rule: quarantine is the only exception to one-file-per-folder.
> Status convention: SUPERSEDED (content merged), HISTORICAL (keep for audit), PENDING (needs decision).

## 1. Rule

- Keep 3 consolidated files plus this index plus root files only.
- Move every other own markdown to quarantine with a flattened name.
- Delete emptied legacy folders after move. Touch no code file.
- Touch no `.slim/`, `target/`, `*.apk`, vendored crates, `.opencode/node_modules`.

## 2. Quarantine table (old path → quarantine name → fate)

| Old path | Quarantine name | Fate | Pending decision |
|---|---|---|---|
| `docs/APP_ANDROID_KEY_LIFECYCLE.md` | `docs_APP_ANDROID_KEY_LIFECYCLE.md` | SUPERSEDED by PROJECT.md sec 7 | None |
| `docs/APP_ANDROID_UX_ARCHITECTURE.md` | `docs_APP_ANDROID_UX_ARCHITECTURE.md` | SUPERSEDED by PROJECT.md sec 7 | None |
| `docs/app-android-clean-atomic-architecture.md` | `docs_app-android-clean-atomic-architecture.md` | SUPERSEDED by PROJECT.md sec 7 | None |
| `docs/APP-INTEGRACAO.md` | `docs_APP-INTEGRACAO.md` | SUPERSEDED by PROJECT.md sec 6-7 | None |
| `docs/app-journey.md` | `docs_app-journey.md` | SUPERSEDED by PROJECT.md sec 7 | None |
| `docs/app-mapa.md` | `docs_app-mapa.md` | SUPERSEDED by PROJECT.md sec 7 | None |
| `docs/APP-PLANO-NOVOS-MODULOS.md` | `docs_APP-PLANO-NOVOS-MODULOS.md` | SUPERSEDED by PLANS.md sec 4 | Confirm lane ownership |
| `docs/auditoria-mocks.md` | `docs_auditoria-mocks.md` | HISTORICAL, summarized PLANS.md sec 4 | None |
| `docs/bateria-serial.md` | `docs_bateria-serial.md` | SUPERSEDED by TASKS.md sec 3.1 | None |
| `docs/bench-destructive.md` | `docs_bench-destructive.md` | SUPERSEDED by TASKS.md sec 3.3 | Needs factory approval for live run |
| `docs/bench-freertos-s3.md` | `docs_bench-freertos-s3.md` | SUPERSEDED by TASKS.md sec 3.2 | None |
| `docs/binding.md` | `docs_binding.md` | SUPERSEDED by PROJECT.md sec 6.2 | None |
| `docs/ble-nimble.md` | `docs_ble-nimble.md` | SUPERSEDED by PROJECT.md sec 6.1 | None |
| `docs/ble-protocol.md` | `docs_ble-protocol.md` | SUPERSEDED by PROJECT.md sec 6.1 | Frozen contract, no change without major |
| `docs/bonding-walkaway.md` | `docs_bonding-walkaway.md` | SUPERSEDED by TASKS.md sec 4.2 | RF test pending |
| `docs/capacidades-modulos.md` | `docs_capacidades-modulos.md` | SUPERSEDED by PROJECT.md sec 5 | None |
| `docs/carteira-cripto.md` | `docs_carteira-cripto.md` | SUPERSEDED by PLANS.md sec 4 | None |
| `docs/checklist-usuario.md` | `docs_checklist-usuario.md` | SUPERSEDED by TASKS.md sec 4.1 | None |
| `docs/COMMS-map.md` | `docs_COMMS-map.md` | SUPERSEDED by PROJECT.md sec 6 | Section 8 validation stays normative |
| `docs/DESACOPLAMENTO.md` | `docs_DESACOPLAMENTO.md` | SUPERSEDED by PROJECT.md sec 4.3 | None |
| `docs/emuladores-pre-flash.md` | `docs_emuladores-pre-flash.md` | SUPERSEDED by TASKS.md sec 3.4 | None |
| `docs/estado-final-firmware.md` | `docs_estado-final-firmware.md` | HISTORICAL, summarized PLANS.md sec 6 | Confirm test-mode inbox state |
| `docs/excecoes-paridade.md` | `docs_excecoes-paridade.md` | SUPERSEDED by PROJECT.md sec 5 | None |
| `docs/finalizacao-freertos-rust.md` | `docs_finalizacao-freertos-rust.md` | HISTORICAL, summarized PLANS.md sec 6 | None |
| `docs/finalizacoes.md` | `docs_finalizacoes.md` | HISTORICAL, merged PLANS.md sec 6 | None, one of 4 finals |
| `docs/firmware-fina.md` | `docs_firmware-fina.md` | HISTORICAL, merged PLANS.md sec 6 | None, one of 4 finals |
| `docs/freertos-rust.md` | `docs_freertos-rust.md` | SUPERSEDED by PROJECT.md sec 4.2 | None |
| `docs/GUIA_DISPLAY_LCD_RUST_C.md` | `docs_GUIA_DISPLAY_LCD_RUST_C.md` | SUPERSEDED by PROJECT.md sec 8 | None |
| `docs/GUIA_RITOS_CONEXAO_USB_BLE_LED_E_WALLETS.md` | `docs_GUIA_RITOS_CONEXAO_USB_BLE_LED_E_WALLETS.md` | SUPERSEDED by TASKS.md sec 5 | None |
| `docs/HANDOFF-2026-10-20.md` | `docs_HANDOFF-2026-10-20.md` | HISTORICAL, merged TASKS.md sec 6 | None, one of 3 handoffs |
| `docs/interop-matrix.md` | `docs_interop-matrix.md` | SUPERSEDED by PROJECT.md sec 5 | Never claim without vector |
| `docs/jornada-onboarding-totp-simulacao-renode.md` | `docs_jornada-onboarding-totp-simulacao-renode.md` | SUPERSEDED by PROJECT.md sec 7-8 | None |
| `docs/led-diagnostico.md` | `docs_led-diagnostico.md` | HISTORICAL, needs eyes | User must confirm LED order |
| `docs/lifetime-debug.md` | `docs_lifetime-debug.md` | SUPERSEDED by TASKS.md sec 5 | Keep OFF in release |
| `docs/linux-bringup.md` | `docs_linux-bringup.md` | SUPERSEDED by TASKS.md sec 3.6 | None |
| `docs/live-monitor.md` | `docs_live-monitor.md` | SUPERSEDED by TASKS.md sec 5 | Keep OFF in release |
| `docs/MACHINE.md` | `docs_MACHINE.md` | HISTORICAL, normative for ports | Revalidate on bench change |
| `docs/matriz-funcionalidades-esp32s3.md` | `docs_matriz-funcionalidades-esp32s3.md` | SUPERSEDED by PROJECT.md sec 5 | None |
| `docs/nvs_schema.md` | `docs_nvs_schema.md` | SUPERSEDED by PROJECT.md sec 6.3 | None |
| `docs/piv-ble-proximity.md` | `docs_piv-ble-proximity.md` | SUPERSEDED by PLANS.md sec 4 | None |
| `docs/plano-amarelos.md` | `docs_plano-amarelos.md` | SUPERSEDED by PLANS.md sec 3 | None, one of 6 pending lists |
| `docs/plano-followups.md` | `docs_plano-followups.md` | SUPERSEDED by PLANS.md sec 3 | None, one of 6 pending lists |
| `docs/plano-hw.md` | `docs_plano-hw.md` | SUPERSEDED by PROJECT.md sec 3 | None |
| `docs/plano-testes-hil.md` | `docs_plano-testes-hil.md` | SUPERSEDED by TASKS.md sec 2 | None |
| `docs/provisionamento-pins-integrity.md` | `docs_provisionamento-pins-integrity.md` | SUPERSEDED by PROJECT.md sec 9 | Confirm server pins |
| `docs/proximity-worktree-handoff.md` | `docs_proximity-worktree-handoff.md` | HISTORICAL, merged TASKS.md sec 6 | None, one of 3 handoffs |
| `docs/proximos-passos.md` | `docs_proximos-passos.md` | SUPERSEDED by PLANS.md sec 3 | None, one of 6 pending lists |
| `docs/qemu-s3.md` | `docs_qemu-s3.md` | SUPERSEDED by TASKS.md sec 3.5 | Smoke only |
| `docs/REGRAS-automacao.md` | `docs_REGRAS-automacao.md` | HISTORICAL, normative R1-R14 | Violation aborts lane |
| `docs/screen-journey.md` | `docs_screen-journey.md` | SUPERSEDED by TASKS.md sec 5 | None |
| `docs/secure-guard/00-BASELINE.md` | `docs_secure-guard__00-BASELINE.md` | SUPERSEDED by PROJECT.md sec 3-4 | None |
| `docs/secure-guard/01-ARCHITECTURE.md` | `docs_secure-guard__01-ARCHITECTURE.md` | SUPERSEDED by PROJECT.md sec 4 | None |
| `docs/secure-guard/02-THREAT-MODEL.md` | `docs_secure-guard__02-THREAT-MODEL.md` | SUPERSEDED by PROJECT.md sec 9 | None |
| `docs/secure-guard/03-PROTOCOL.md` | `docs_secure-guard__03-PROTOCOL.md` | SUPERSEDED by PROJECT.md sec 6 | None |
| `docs/secure-guard/04-TEST-PLAN.md` | `docs_secure-guard__04-TEST-PLAN.md` | SUPERSEDED by TASKS.md sec 2-3 | None |
| `docs/secure-guard/05-IMPLEMENTATION-STATUS.md` | `docs_secure-guard__05-IMPLEMENTATION-STATUS.md` | HISTORICAL, summarized PLANS.md | Reconcile with current code |
| `docs/secure-guard/06-HANDOFF.md` | `docs_secure-guard__06-HANDOFF.md` | HISTORICAL, merged TASKS.md sec 6 | None, one of 3 handoffs |
| `docs/secure-guard/07-DESIGN-INDUSTRIAL.md` | `docs_secure-guard__07-DESIGN-INDUSTRIAL.md` | SUPERSEDED by PROJECT.md sec 3 | Confirm keyfob dimensions |
| `docs/secure-guard/08-SECURITY-REVIEW.md` | `docs_secure-guard__08-SECURITY-REVIEW.md` | SUPERSEDED by PROJECT.md sec 9 | Enforce 20 rules plus 6 criteria |
| `docs/secure-guard/09-VALIDATION-RESULTS.md` | `docs_secure-guard__09-VALIDATION-RESULTS.md` | SUPERSEDED by TASKS.md sec 7 | Refresh after next HW run |
| `docs/seis-produtos.md` | `docs_seis-produtos.md` | SUPERSEDED by PLANS.md sec 4 | None |
| `docs/sessao-20-10-f4-ccid-opensc.md` | `docs_sessao-20-10-f4-ccid-opensc.md` | HISTORICAL, summarized PLANS.md sec 6 | None |
| `docs/size-wave1.md` | `docs_size-wave1.md` | HISTORICAL, summarized PLANS.md sec 5 | Re-measure on next S3 build |
| `docs/test-hooks.md` | `docs_test-hooks.md` | SUPERSEDED by TASKS.md sec 5 | Gate test-mode |
| `docs/teste-ponta-a-ponta.md` | `docs_teste-ponta-a-ponta.md` | HISTORICAL diary, map merged to TASKS.md | Keep as audit diary only |
| `docs/validacao-usb-telas.md` | `docs_validacao-usb-telas.md` | SUPERSEDED by PLANS.md sec 4 | COM8 reflash pending |
| `docs/wifi.md` | `docs_wifi.md` | SUPERSEDED by PROJECT.md sec 6 | None |
| `plans/carteira-cripto-store/*` (5) | `plans_carteira-cripto-store__*.md` | SUPERSEDED by PLANS.md sec 4 | None |
| `plans/conexao-ble-fim-a-fim/*` (4) | `plans_conexao-ble-fim-a-fim__*.md` | SUPERSEDED by PLANS.md sec 4 | RF pending |
| `plans/F2-F3-HIL-MAP.md` | `plans_F2-F3-HIL-MAP.md` | SUPERSEDED by TASKS.md sec 2 | F3 blocked on bad-sig |
| `plans/fido-auditoria/*` (3) | `plans_fido-auditoria__*.md` | HISTORICAL, summarized PLANS.md sec 4 | None |
| `plans/fido-ux-conex/plan.md` | `plans_fido-ux-conex__plan.md` | SUPERSEDED by PLANS.md sec 4 | One-line plan, keep |
| `plans/MATRIZ-TODO.md` | `plans_MATRIZ-TODO.md` | SUPERSEDED by PLANS.md sec 2 | Reconcile T-FIDO partial |
| `plans/piv-ble-proximity/*` (4) | `plans_piv-ble-proximity__*.md` | SUPERSEDED by PLANS.md sec 4 | RF pending |
| `plans/RELEASE-checklist.md` | `plans_RELEASE-checklist.md` | HISTORICAL normative, summarized PLANS.md sec 5 | Keep pipeline exact |
| `plans/risk-acceptance-secureboot.md` | `plans_risk-acceptance-secureboot.md` | HISTORICAL normative | Needs factory sign |
| `plans/seis-implementacoes-produto/*` (4) | `plans_seis-implementacoes-produto__*.md` | SUPERSEDED by PLANS.md sec 4 | None |
| `plans/SIMULACAO-final.md` | `plans_SIMULACAO-final.md` | HISTORICAL, summarized PLANS.md sec 6 | Zero-press blocked |
| `plans/sistema-ota/*` (4) | `plans_sistema-ota__*.md` | SUPERSEDED by PLANS.md sec 4 | OTA in progress |
| `plans/STATE.md` | `plans_STATE.md` | HISTORICAL, summarized PLANS.md sec 6 | Session log closed |
| `plans/TASKS-microdetalhe.md` | `plans_TASKS-microdetalhe.md` | SUPERSEDED by TASKS.md sec 1 | Keep T0-T13 order |
| `plans/unificacao-worktrees/*` (5) | `plans_unificacao-worktrees__*.md` | HISTORICAL, summarized PLANS.md sec 4-6 | Merge on demand |
| `plans/validacao-usb-telas/*` (4) | `plans_validacao-usb-telas__*.md` | SUPERSEDED by PLANS.md sec 4 | COM8 pending |
| `plans/vault-cofre-flash-seguro/*` (4) | `plans_vault-cofre-flash-seguro__*.md` | SUPERSEDED by PLANS.md sec 4 | Planned |
| `app-android/CHECKLIST.md` | `app-android_CHECKLIST.md` | SUPERSEDED by PROJECT.md sec 7 | Confirm UniFFI path |
| `scripts/README.md` | `scripts_README.md` | SUPERSEDED by TASKS.md sec 1 | Confirm PS1 names |
| `tools/host/linux/README.md` | `tools_host_linux_README.md` | SUPERSEDED by PROJECT.md sec 6.1 | Agent autostart pending |
| `tools/host/macos/README.md` | `tools_host_macos_README.md` | SUPERSEDED by PROJECT.md sec 6.1 | Agent autostart pending |
| `tools/host/win/README.md` | `tools_host_win_README.md` | SUPERSEDED by PROJECT.md sec 6.1 | Pairing steps pending |
| 15 single-use probes (`tools/*.py`: `bond_*`, `pair_*`, `usb_*`, `ble_hold_bond`, `need_hands`, `fw_rebuild`, `take_all_wave11c`, `audit_final_screenshots`) | same names in `quarantine/` | QUARANTINED, logic untouched | Indexed in `tools/_QUARANTINE_MANIFEST.txt` |
| `scripts/aegis_auto.py` | `tools/aegis_auto.py` (moved, not quarantined) | RELOCATED, zero changes | Update callers to `tools/` path |
| `scripts/build-diag.ps1` + `scripts/flash-diag.ps1` | `scripts/diag.ps1` (merged stubs) | CONSOLIDATED | None |
| `tools/e2e_user_test.py` + `tools/emulate_app_session.py` + `tools/hil_emulate_full_app_on_board.py` | `tools/e2e_harness.py` (subcommands user/session/onboard/bridge, 113/113 defs preserved, 0 dupes) + originals in `quarantine/` | FUSED, logic preserved | Callers rewired: `tools/aegis_auto.py` + `scripts/battery-serial.ps1` now use `e2e_harness.py user`; `host_hardware_android_bridge.py` kept (live import in `hil_test_ds_and_proximity_lock.py`) |

## 3. Consolidation decisions

- Merge 4 finals (`finalizacoes`, `firmware-fina`, `estado-final-firmware`, `finalizacao-freertos-rust`) into PLANS.md section 6. Keep originals as HISTORICAL.
- Merge 6 pending lists (`plano-amarelos`, `plano-followups`, `proximos-passos`, plus MATRIZ-TODO yellows, STATE next actions, TASKS-microdetalhe T-gates) into PLANS.md section 3.
- Merge 3 handoffs (`HANDOFF-2026-10-20`, `proximity-worktree-handoff`, `secure-guard/06-HANDOFF`) into TASKS.md section 6.
- Merge 8 app docs into PROJECT.md section 7.
- Merge 4 BLE/comms docs into PROJECT.md section 6.1.
- Merge 2 wallet docs into PLANS.md section 4.
- Merge 2 USB validation docs into PLANS.md section 4.

## 4. Pending external blockers

- Second device for zero-press and bonded RF walk-away.
- Factory approval for eFuse burn and destructive erase.
- User eyes for LED order and flicker.
- COM8 reflash for classic-path validation.
- Server pins for OTA and WiFi provision.
