# SIMULACAO-final — F5+F4-restante (READ-ONLY, sem flash/COM7)

> Worktree: `E:/projetos/fido/.slim/worktrees/modular-solid-atomic` (branch `omos/modular-solid-atomic`). Nenhum edit/flash/worktree add-remove/tag/push executado. Unica escrita: este arquivo novo.

## 1) Merge rehearsal via `git merge-tree` (sem tocar working tree/branches)

- `git merge-base main omos/modular-solid-atomic` = `20ffc7144e05e9f73f56c7d89731137e67e39606`
- `git rev-parse main` = `20ffc7144e05e9f73f56c7d89731137e67e39606`
- `git rev-parse omos/modular-solid-atomic` = `20ffc7144e05e9f73f56c7d89731137e67e39606`
- Comandos (git 2.56.0.windows.2, sintaxe moderna, opcoes antes dos branches):
  - `git merge-tree --name-only main omos/modular-solid-atomic` => `67ee46da8fb49d515c968d8c757d37f039122b30` (EXIT 0)
  - `git merge-tree --write-tree --messages --name-only main omos/modular-solid-atomic` => mesmo tree (EXIT 0)
  - `git rev-parse 'main^{tree}'` = `67ee46...`; `'omos/...^{tree}'` = `67ee46...` (identicos ao merged tree)
  - `git diff --stat 'main^{tree}' 67ee46...` => vazio (EXIT 0)
- Resultado: **merge limpo (0 conflitos)** no nivel committado.
- Lista de conflitos (arquivo:linha): **limpo — nenhum**.
- Diffstat committado: **vazio**.

### Ressalva dirty-work (fora do alcance do merge-tree) — FATO
- O merge-tree acima cobre SOMENTE refs committadas (identicas). O risco real de merge esta no trabalho NAO committado, que o merge-tree nao avalia.
- `git status --short`: ~43 modified + untracked. Amostra (verificacao 23/10):
  - Modified: `Cargo.toml`, `Cargo.lock`, `crates/aegis-fido-core/src/ctap/{cbor,info}.rs`, `lib.rs`, `oath/tlv.rs`, `wallet/store.rs`, `tests/ctap_tests.rs`, `crates/aegis-fido-firmware/src/{binding,ble_gatt,ble_nimble,ccid_dispatch,freertos,main,mdns,nvs_backend,oath_store,ota,pairing,pairing_flow,pairing_led,persistence,piv_store,proximity,recovery,serial_ctaphid,test_hooks,totp_view,vault_store,vendor_exec,wifi_ap,wifi_station}.rs`, `crates/aegis-fido-usb/src/{ctaphid,keyboard}.rs`, `docs/{capacidades-modulos,size-wave1,test-hooks,teste-ponta-a-ponta}.md`, `scripts/battery-serial.ps1`, `tools/{app_simulator,device_ops,ota_deny_probe,wallet_gate_probe}.py`
  - Untracked: `crates/aegis-fido-firmware/tests/{applets_t9,namespaced_store_t5,netwifi_t10,otakey_provider_t6}.rs`, `crates/universal-device-sdk/`, `docs/{APP-INTEGRACAO,COMMS-map,REGRAS-automacao}.md`, `plans/{RELEASE-checklist,TASKS-microdetalhe}.md`, `scripts/aegis_auto.py`, `tools/host_sdk/`
  - `git diff --stat` (uncommitted): 43 files, +4521/-931 (maiores: `persistence.rs`, `nvs_backend.rs`, `wifi_ap.rs`, `binding.rs`).
- INFERENCIA marcada: merge real dara conflito aparente zero no committado, mas exigira `git add/commit` + revisao do dirty acima antes de qualquer merge true; sem isso, `git merge` apos commit pode conflitar (nao simulado aqui por READ-ONLY).
- Nao resolvido: conteudo linha-a-linha do dirty nao foi diffado aqui (escopo: rehearsal de refs).

## 2) zero_press sem 2o device — veredito: EXTERNAL_BLOCKED

- Alvo: `tools/e2e_zero_press.py` — evidencia (leitura direta):
  - L14 `MAC = "80:65:99:DF:4B:CE"` (peer BLE hardcoded, 1 device fisico especifico).
  - L19 `sess.connect("COM7", 115200)` (exige serial real; proibido nesta sessao).
  - L34 `from bleak import BleakClient` (import direto, sem injecao/mock).
  - L37 `async with BleakClient(MAC, timeout=30.0)` + L40 `await client.pair()` (bond GATT real, sem shim).
- Bleak precisa de radio real? FATO (fonte: `tools/host/win/proximity_agent.py`):
  - L414-420 `_bleak_scan`: `from bleak import BleakScanner` + docstring "Requer adaptador BT ligado + fob pareado/bonded (endereco/IRK resolvido pelo Windows)"; sem bleak => `OSError`; falha de scan => `OSError` (fail-closed).
  - Mock/shim existente? NAO para o path GATT/bond: `grep -r "mock.*bleak|FakeBleak|SimulatedBleak"` => 0 matches; `SimulatedSource` (L131-141) + `scanner=lambda` (L566,578; testes L150,171,179,195,281,291,301) cobrem SOMENTE o path scan/RSSI do proximity_agent, nunca `BleakClient.connect/pair` do `e2e_zero_press.py`.
- Oraculo `proximity_freertos.rs` cobre o que? FATO (header L1-17 + 11 `#[test]`):
  - `aes_oraculo_confere_vetor_fips197`, `interop_tag_vector_k42_ctr7_eq_660d4941`, `interop_tag_rejeita_chave_fob_ctr_divergentes`, `beacon_0xfffe_valido_parse_e_accept_alimenta_near`, `beacon_invalido_e_fail_closed_away`, `replay_ctr_repetido_rejeitado_sem_avancar`, `salto_maior_que_1000_marca_reverify`, `beacon_tick_cadencia_1s_sem_wrap`, `gate_bonding_usb_e_adv_truth_table`, `scheduler_freertos_usb_montado_veta_beacon`, `monitor_lock_exige_confirmacao_e_unlock_presenca_pin`.
  - Tudo host-side, sem hardware/radio: contrato cripto (TAG=660d4941 via oraculo AES-ECB independente), beacon 0xFFFE vs 0xFFFD/VER-curto fail-closed, anti-replay, reverify, gates USB/bonding, scheduler FreeRTOS, lock com confirmacao. NAO cobre bond GATT real nem `TEST_UP` serial.
- Cobertura alternativa EXISTENTE (sem 2o device / sem radio):
  - `crates/aegis-fido-firmware/tests/proximity_freertos.rs` (11 tests, host).
  - `tools/host/{win,linux,macos}/proximity_agent.py --self-test` + `test_proximity_agent.py` (SimulatedSource/lambda, offline).
  - `tools/ble_connect_test.py::run_self_test` L447-448 "sem hardware, sem bleak" (fragments/framing/parsers UUID/FFF2/FFF3).
  - INFERENCIA marcada: suficientes para logica/contrato, insuficientes para prova over-air fim-a-fim (bond + UP na mesma sessao).
- Veredito: **EXTERNAL_BLOCKED** — sem peer BLE fisico (MAC 80:65:99:DF:4B:CE) + radio BT host + COM7, `e2e_zero_press.py` nao e simulavel; nao inventar estado de device; nao converter observacao de software em evidencia fisica.

## 3) Checklist de aprovacao humana p/ merge real (pos-simulacao)

1. [ ] Humano decide destino do dirty-work: committar em `omos/modular-solid-atomic` (ou split) antes de merge; `git status` limpo confirmado.
2. [ ] Re-rodar `git merge-tree` APOS o commit (base pode mudar) + `git diff --stat main...branch` revisado.
3. [ ] Validacao: `cargo test` + `cargo clippy --all-targets -- -D warnings` verdes (AGENTS.md); `proximity_freertos.rs` 11 passed + host self-tests.
4. [ ] HIL real fora desta sessao: flash + bateria COM7 (`app_simulator --demo`, `test_aegiskey_rust`, `e2e_user_test`, `e2e_zero_press --port COM7`, probes wallet/ota/killswitch) com operador presente; `e2e_zero_press` segue EXTERNAL_BLOCKED ate la.
5. [ ] Merge real somente por humano (`git merge` + resolucao + push/tag); rollback boundary: se merge committado quebrar CI/HIL, `git reset --hard ORIG_HEAD` / `git revert -m 1 <merge-sha>` antes do push; apos push, revert dedicado (sem force-push em main).
6. [ ] Sem QEMU-S3 como `RealVerified` (cf. `docs/REGRAS-automacao.md`); gaps conhecidos (`e2e_zero_press` hardcoded, OTA-COMMIT so USB) aceitos ou mitigados em `plans/TASKS-microdetalhe.md`.

---
*Simulacao F5+F4-restante concluida READ-ONLY em 23/10/2026. Sem logs extensos por instrucao.*
