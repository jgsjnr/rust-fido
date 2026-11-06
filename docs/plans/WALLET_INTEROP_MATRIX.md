# WALLET_INTEROP_MATRIX — Fase 8: matriz de interop F1-F7

> Natureza: planejamento + registro de estado. Nenhuma alteracao de codigo neste documento.
> Branch: `fd/finalizacao-linux`. HEAD observado: `d594f83` (`feat(wallet): F7 wallet companion`).
> Plano de referencia: `docs/plans/HW_WALLET_COMPAT_PLAN.md` (secoes 8 e 9, fases F1-F8).
> Regra transversal: consumidores falam com o dispositivo somente pela fachada `universal-device-sdk` (facade-first). Transporte (`uniffi-bridge`) e passthrough puro.
> Vocabulario: apenas termos genericos — "carteiras hardware populares", "carteiras software", "companion de mesa", "companion movel", "placa com display", "placa sem display". Nenhum nome comercial de produto.
> Proibicoes mantidas: sem dado sintetico de fallback, sem sucesso forjado, sem mock de producao, nenhuma etapa exige gravacao OTP.

---

## 1. Escopo (scope)

Esta matriz cobre as fases F1-F7 do plano de compatibilidade de carteira, uma linha por fase/camada. Colunas separam o que foi observado em host do que depende de hardware fisico.

Fases cobertas:

- F1 — Reserva de opcodes + gates (`0x48`-`0x4B`, `check_compiled`, `CapabilitySet` aditivo).
- F2 — Derivacao hierarquica no nucleo (RAM, sem fio, sem NVS).
- F3 — Exportacao de chave publica estendida por conta + borda estavel + vetores.
- F4 — Envelope parcial de transacao + opcode de assinatura ligado a `WalletStore::sign` com gate de exibicao-antes-de-assinar.
- F5 — Cerimonia de semente + persistencia (gerar/mostrar/importar com confirmacao fisica, snapshot + rollback + verify-after-write).
- F6 — Confirmacao fisica por placa (pre-visualizacao obrigatoria antes do UP de assinatura; politica explicita por variante sem display).
- F7 — Companion (mesa + movel) via fachada (fluxos chave-estendida/watch-only e round-trip de envelope parcial, sem logica cripto no app).

Fora de escopo deste documento: alteracao de codigo, gravacao em placa, fluxo de eFuse, pareamento real com carteiras de terceiros, qualquer execucao em hardware.

## 2. Contrato (contract)

### 2.1 Fachada e fio

- Pedido: `{ opcode: u8, payload: TLV }`. TLV segue o padrao existente (`0x01` slot, `0x02` etiqueta, `0x07` endereco na resposta, `0x08` rede no pedido GEN). Novas etiquetas somente acima das reservadas; decoders antigos ignoram etiquetas desconhecidas, nunca falham.
- Resposta: `SdkResponse { status: u8, payload: Vec<u8> }`. Conjunto fechado: `0x00` ok, `0x01` need-UP, `0x02` need-PIN, `0x03` no-slot, `0x04` bad-envelope, `0x05` need-binding. `is_ok()` e verdadeiro somente para `0x00`.
- Faixa congelada `0x35`-`0x37` inalterada. Reserva F1/F6: `0x48` derivacao, `0x49` chave estendida, `0x4A` envelope parcial/assinatura, `0x4B` pre-visualizacao pendente. Conferido em `crates/aegis-fido-firmware/src/ble/gatt_core.rs` (`OP_WALLET_DERIVE/XPUB/PSBT/PENDING`) e `crates/aegis-fido-firmware/src/vendor_exec/vendor_caps.rs` (contagem diet: full 0, fido-only 11, fido-totp 7).
- `NotCompiled` aparece SOMENTE na coluna "compilado fora". Nenhuma outra coluna mapeia para ele. Nenhum caminho retorna endereco, chave estendida ou assinatura de exemplo.

### 2.2 Gates por operacao

| Operacao | Gate canonico | Negacao fio |
|---|---|---|
| `Wallet GEN/LIST/ADDR` | binding -> UP (+PIN no import) | sem UP `0x01`, rede invalida `0x04`, slot inexistente `0x03` |
| Derivacao (F2) | sem fio; nucleo RAM + isolamento de slots | caminho fora do padrao `0x04` (quando exposto via F1) |
| Chave estendida (F3) | binding -> UP | rede/caminho invalido `0x04` |
| Assinatura envelope parcial (F4+F6) | pre-visualizacao `0x4B` intacta + recibo + binding -> UP -> PIN | sem exibicao previa `0x01`/`0x04`, sem UP `0x01`, sem PIN `0x02` |
| Backup/restore semente (F5) | UP + PIN, confirmacao fisica | frase invalida/checksum `0x04` |
| Pre-visualizacao (F6) | binding -> UP; `0x4B` expoe preview, nunca autentica sozinho | display ausente = variante headless responde DTO sem framebuffer |
| Companion (F7) | fachada tipada + `require_hardwallet()`; sem logica cripto no app | sem `hardwallet` = `SdkError::NotCompiled` |

Ordem canonica de negacao observada no codigo: binding, depois UP, depois PIN. Conferido em `crates/aegis-fido-firmware/src/ble/dispatch_bind.rs` (`authorize_wallet_op`, `authorize_wallet_sign_op`) e `crates/aegis-fido-firmware/src/serial_ctaphid.rs` (gates `dispatch_serial_wallet`).

### 2.3 Feature gating

- `hardwallet` (ligado por padrao no perfil full): `Wallet` + `WalletSign` compilam; desligado rende `SdkError::NotCompiled` via `require_hardwallet()` em `check_compiled()`. Conferido em `crates/universal-device-sdk/src/error.rs` e `crates/universal-device-sdk/src/request.rs`.
- Perfis diet `cap-fido-only` / `cap-fido-totp`: sem wallet/vault/radio/display; qualquer opcode de carteira responde `0x06` fora-da-capability no fio e `NotCompiled` no SDK. Combinacao invalida falha em `compile_error!`. Contagem registrada em `scripts/capability-catalog.json` (`wire_contract.get_caps.unsupported_count_rule`).
- `has-display` / placas com e sem display: mesmo contrato `DisplayManager`; variante sem display usa stub (mesmo contrato, sem framebuffer dedicado). Plano nao presume tela.
- `prod-strict`: sem ganchos de teste, sem toque simulado, sem bypass.
- `test-mode` (nunca em `default`): unica superficie de testes de laboratorio.

## 3. Estado implementado observado no codigo (implemented state)

Verificacao por leitura de fontes no HEAD `d594f83`, sem execucao de suite neste lane. Caminhos citados existem na arvore.

| Fase | Arquivos observados | Estado em host |
|---|---|---|
| F1 | `crates/universal-device-sdk/src/request.rs`, `src/capabilities.rs`, `src/providers/wallet.rs`, `tests/wallet_compat_f1.rs`, `examples/wallet_compat_f1.rs`; `crates/aegis-fido-firmware/src/wallet_exec.rs`, `src/ble/gatt_core.rs`, `src/ble/dispatch_bind.rs`, `src/vendor_exec/vendor_caps.rs`; `scripts/capability-catalog.json` | Presente: fachada, bits de capability aditivos, gates diet. Commit `18c6d1d`. |
| F2 | `crates/aegis-fido-core/src/wallet/hd.rs`, `hd_paths.rs`, `hd_codec.rs`, `mod.rs`; `crates/aegis-fido-core/tests/hd_bip32_vectors.rs` | Presente: derivacao hierarquica no nucleo (RAM), vetores de derivacao. Commit `01efee0`. |
| F3 | `crates/aegis-fido-core/src/wallet/xpub.rs`; `crates/aegis-fido-core/tests/xpub_export_vectors.rs`; `crates/uniffi-bridge/src/lib.rs`, `src/ffi.rs`, `examples/xpub_export.rs`; `crates/universal-device-sdk/src/hardwallet.rs`, `tests/xpub_request_f3.rs` | Presente: exportacao por conta, borda estavel two-call, rejeicao fail-closed de rede/caminho. Commit `84d1f77`. |
| F4 | `crates/aegis-fido-core/src/wallet/psbt.rs`; `crates/aegis-fido-core/tests/psbt_sign_vectors.rs`; `crates/aegis-fido-firmware/src/wallet_sign.rs`, `src/wallet_exec.rs`, `src/freertos_route.rs`, `src/run/ble_dispatch.rs`, `src/run/run_loop_legacy.rs`, `src/serial_vendor.rs`, `src/serial_ctaphid.rs` | Presente: parser de envelope parcial, sighash por rede, opcode ligado a `WalletStore::sign` com gate exibicao-antes-de-assinar. Commit `39e9e46`. |
| F5 | `crates/aegis-fido-core/src/wallet/seed_ceremony.rs`; `crates/aegis-fido-core/tests/seed_ceremony_vectors.rs`; `crates/aegis-fido-firmware/src/wallet_seed_store.rs`, `examples/wallet_seed_provision.rs`, `tests/wallet_seed_f5.rs` | Presente: cerimonia gerar/mostrar/importar no nucleo + armazenamento com envelope e rollback no firmware. Commit `d3fafcc`. |
| F6 | `crates/aegis-fido-firmware/src/wallet_approval.rs` (`WalletPendingApproval`, uso unico, limpeza anti-tamper), `src/wallet_sign.rs` (gate recibo + preview intacta + UP + PIN), `tests/wallet_approval_f6.rs`, `examples/wallet_approval_f6.rs`; `crates/universal-device-sdk/src/wallet_approval.rs`, `tests/wallet_approval_f6.rs`; camada movel `WalletApprovalGate` + testes | Presente: preview `0x4B` + assinatura `0x4A` com gate binding -> UP -> PIN. Commit `ff61538`. |
| F7 | `crates/universal-device-sdk/src/wallet_companion.rs`, `tests/wallet_companion_f7.rs`, `examples/wallet_companion_f7.rs`; `crates/uniffi-bridge/src/wallet_companion.rs`, `src/ffi.rs`, `examples/wallet_companion_passthrough.rs`; `app-tray/wallet_companion.py`, `app-tray/test_wallet_companion.py`; camada movel `WalletCompanion` + testes | Presente: fluxos chave-estendida/watch-only e round-trip de envelope via fachada, passthrough sem logica cripto. Commit `d594f83`. |

Nenhuma fase acima foi observada executando em hardware neste lane. O campo "Estado em host" significa apenas "fonte presente na arvore".

## 4. Matriz de interop F1-F7 (plans)

Legenda de celula:

- `HOST PRESENTE + GATE PASS` — fonte presente na arvore + ultimo gate consolidado PASS (ver secao 6). Nao e afirmacao de hardware.
- `EXTERNAL BLOCKED` — depende de hardware fisico, bancada, ou pareamento com terceiros; nao executado neste lane; nunca lido como "ok".
- `NA` — nao aplicavel por desenho (ex.: F2 sem fio, sem NVS).

| Fase / camada | host-test (testes unitarios + gate em maquina de desenvolvimento) | device-variant com display (confirmacao visual obrigatoria) | device-variant sem display (politica explicita, sem garantia visual) | companion round-trip (mesa + movel via fachada, com placa) |
|---|---|---|---|---|
| F1 reserva + gates | HOST PRESENTE + GATE PASS. Evidencia: `tests/wallet_compat_f1.rs`, `vendor_caps.rs` (contagem diet), catalogo `wire_contract.get_caps`; gate 9/9 PASS em `2026-11-06T03:52:34Z` (ver secao 6). | EXTERNAL BLOCKED. Motivo: sem placa presente; sem execucao `GET_CAPS 0x3F` em placa. | EXTERNAL BLOCKED. Motivo: idem; stub headless nao validado em placa. | EXTERNAL BLOCKED. Motivo: sem bancada; sem round-trip app->placa. |
| F2 derivacao nucleo | HOST PRESENTE + GATE PASS. Evidencia: `tests/hd_bip32_vectors.rs` (vetores de derivacao padrao); isolamento de slots no nucleo. | EXTERNAL BLOCKED. Motivo: F2 e RAM-only por desenho; sem HIL aplicavel alem do nucleo. | EXTERNAL BLOCKED. Motivo: idem. | NA por desenho (sem fio, sem NVS nesta fase). |
| F3 chave estendida + borda | HOST PRESENTE + GATE PASS. Evidencia: `tests/xpub_export_vectors.rs` (vetores cruzados), `tests/xpub_request_f3.rs`, exemplo `xpub_export.rs`; borda two-call com rejeicao fail-closed. | EXTERNAL BLOCKED. Motivo: sem exportacao real em placa; sem verificacao cruzada off-device contra placa. | EXTERNAL BLOCKED. Motivo: idem. | EXTERNAL BLOCKED. Motivo: sem fluxo xpub/watch-only com placa. |
| F4 envelope parcial + assinatura | HOST PRESENTE + GATE PASS. Evidencia: `tests/psbt_sign_vectors.rs` (parse + `sign_psbt` com gate de sessao; negacoes sem sessao, envelope invalido, slot desconhecido); `wallet_sign.rs` + funis BLE/serial. | EXTERNAL BLOCKED. Motivo: sem envelope de teste assinado em placa; sem verificacao off-device de assinatura vinda de placa. | EXTERNAL BLOCKED. Motivo: idem + sem politica anti-blind-signing validada em placa sem display. | EXTERNAL BLOCKED. Motivo: sem round-trip de envelope com placa. |
| F5 cerimonia + persistencia | HOST PRESENTE + GATE PASS. Evidencia: `tests/seed_ceremony_vectors.rs`, `tests/wallet_seed_f5.rs` (inclui queda no meio do save: parcial = corrompido, nunca meio-estado). | EXTERNAL BLOCKED. Motivo: sem cerimonia gerar/mostrar/importar executada em placa; sem confirmacao fisica observada. | EXTERNAL BLOCKED. Motivo: idem; sem rollback NVS observado em placa. | EXTERNAL BLOCKED. Motivo: sem backup/restore assistido por companion com placa. |
| F6 confirmacao fisica | HOST PRESENTE + GATE PASS. Evidencia: `tests/wallet_approval_f6.rs` (firmware + SDK: preview `0x4B` uso unico, negacao sem preview, tamper-clear; assinatura exige recibo + UP + PIN). | EXTERNAL BLOCKED. Motivo: sem HIL por variante com display; sem pre-visualizacao de 4 linhas + banner observada em placa. | EXTERNAL BLOCKED. Motivo: sem politica explicita validada em placa sem display (assinatura assistida com hash nos dois lados). | EXTERNAL BLOCKED. Motivo: sem fluxo mediado pelo app com placa (anuncio `0x4B` -> aprovacao -> `0x4A`). |
| F7 companion fachada | HOST PRESENTE + GATE PASS. Evidencia: `tests/wallet_companion_f7.rs` (SDK), `test_wallet_companion.py` (mesa), testes da camada movel `WalletCompanionTest`; passthrough sem logica cripto (`wallet_companion_passthrough.rs`). | EXTERNAL BLOCKED. Motivo: sem integracao app->placa em bancada. | EXTERNAL BLOCKED. Motivo: idem. | EXTERNAL BLOCKED. Motivo: sem pareamento xpub nem round-trip de envelope com placa. |
| F8 interop com ecossistema (esta fase) | HOST PRESENTE (este documento; sem bateria de terceiros em host). | EXTERNAL BLOCKED. Motivo: sem bateria contra carteiras hardware populares; sem placa. | EXTERNAL BLOCKED. Motivo: idem. | EXTERNAL BLOCKED. Motivo: sem bateria contra carteiras software; sem bancada. |

Regra da matriz: celula nao executada = `EXTERNAL BLOCKED`, nunca "ok". Nenhuma celula de hardware desta matriz esta marcada como aprovada.

## 5. Testes de aceitacao (criterios de saida, sem placa neste plano)

1. `cargo test` passa no workspace (nucleo + firmware host + SDK + ponte).
2. `cargo clippy --all-targets -- -D warnings` limpo.
3. Vetores: gerador secp256k1 (enderecos), frase oficial de entropia zero, derivacao hierarquica padrao, chave estendida padrao, envelope parcial de teste — todos cruzados com implementacao independente (arquivos `*_vectors.rs` citados na secao 3).
4. Negacoes: sem UP, sem PIN, sem binding, opcode/etiqueta invalidos, NVS parcial, feature desligada (`NotCompiled`), transporte ausente (`external blocked`) — cada uma com teste dedicado na arvore.
5. HIL por variante de placa (com/sem display) antes de qualquer declaracao de verificacao real para assinatura. Nao executado neste lane.
6. Politica de eFuse inalterada: nenhuma etapa exige gravacao OTP.

## 6. Evidencia e qualidade da evidencia (evidence quality)

- Ultimo gate consolidado registrado em `reports/testing/consolidated-result.json`: `timestamp_utc 2026-11-06T03:52:34Z`, pernas `test-debug PASS`, `test-firmware-features PASS`, `clippy PASS`, `fmt PASS (advisory)`, legs restantes registradas no JSON. Evidencia adjacente: comandos `cargo test --workspace` e `cargo test -p aegis-fido-firmware --features freertos,proximity` com `exit 0` no JSON.
- Evidencia por fase: arquivos de teste listados na secao 3 existem na arvore no HEAD `d594f83` (observado por listagem e historico de commits `18c6d1d`, `01efee0`, `84d1f77`, `39e9e46`, `d3fafcc`, `ff61538`, `d594f83`). Este lane nao re-executou a suite (zero edicoes de fonte neste lane; re-execucao seria redundante sem alteracao de codigo).
- Qualidade declarada: MEDIA para host (fonte observada + gate consolidado recente, mas sem re-execucao dedicada neste lane). Nenhuma afirmacao de hardware e feita. Nenhum selo de verificacao real e reivindicado neste documento porque nao ha metadado adjacente de execucao em placa.
- Deriva codigo-docs: cruzado nesta data — opcodes `0x48`-`0x4B` conferem entre `gatt_core.rs`, `vendor_caps.rs`, `serial_ctaphid.rs` e `capability-catalog.json`; contagem diet confere (full 0, fido-only 11, fido-totp 7); `require_hardwallet` confere entre `error.rs`, `request.rs` e `lib.rs`. Nenhuma divergencia encontrada.

## 7. Riscos e limites declarados (risks)

- Sem tela fisica nao ha garantia visual contra assinatura cega; F6 torna isso explicito por variante em vez de presumir.
- Compatibilidade plena com o ecossistema exige F1+F2+F3; o restante e seguranca e UX, nao interop.
- Transporte HID generico de carteira (enquadramento especifico de carteira popular) e opcional para o MVP: os transportes existentes (serial vendor, BLE vendor, CTAPHID) carregam os fluxos.
- Matriz de hardware anterior (`reports/testing/HW_MATRIX.md`, sessoes S1-S7) registra bancada instavel e divergencia UI x silicio em sessoes de outubro/novembro; nenhuma conclusao de hardware e reusada aqui como prova.
- Confusao entre lista vazia de UI e lista real do silicio ja foi observada em historico de bancada; por isso a fonte de verdade para slots e o opcode direto de lista, nunca o espelho.

## 8. Bloqueadores externos (external blockers)

1. Placa fisica presente e estavel (sem reboot espurio, sessao valida) — necessario para qualquer celula device-variant sair de `EXTERNAL BLOCKED`.
2. Bancada com ponte serial ativa e transporte confirmado — necessario para `GET_CAPS 0x3F`, lista direta e probes read-only.
3. Variante com display e variante sem display disponiveis separadamente — necessario para F6 HIL por variante.
4. Companion de mesa e companion movel instalados e vinculados — necessario para F7 round-trip com placa.
5. Bateria de interop com terceiros (carteiras hardware populares + carteiras software: parear chave estendida, verificar endereco, assinar envelope parcial) — necessario para F8 sair de `EXTERNAL BLOCKED`. Requer aprovacao explicita; nada destrutivo sem confirmacao.
6. Aprovacao de fabrica para qualquer etapa OTP — fora de escopo; nenhuma etapa deste plano a exige.

## 9. Historico (history)

- `18c6d1d` — F1: fachada wallet-compat + caps + gates.
- `01efee0` — F2: carteira HD hierarquica (nucleo + vetores).
- `84d1f77` — F3: exportacao de chave estendida por conta (nucleo + borda + SDK).
- `39e9e46` — F4: assinatura de envelope parcial (nucleo + fio firmware).
- `d3fafcc` — F5: cerimonia de semente + persistencia com rollback.
- `ff61538` — F6: preview `0x4B` + gate de assinatura binding-UP-PIN.
- `d594f83` — F7: companion via fachada (SDK + passthrough + mesa + movel).
- Este documento — F8: matriz de interop (planejamento; sem execucao em hardware).

---

## Handoff

- Escopo: escrever somente `docs/plans/WALLET_INTEROP_MATRIX.md` (Fase 8). Sem alteracao de codigo, sem push.
- Contrato: fio `0x35`-`0x37` congelado + reserva `0x48`-`0x4B`; status fechado `0x00`-`0x05`; `NotCompiled` somente em coluna compilado-fora; ordem binding -> UP -> PIN.
- Riscos: sem display nao ha garantia visual; interop plena exige F1+F2+F3; historico de bancada instavel nao e reusado como prova.
- Testes: arquivos `*_vectors.rs` / `wallet_*_f*.rs` / `test_wallet_companion.py` presentes na arvore; ultimo gate consolidado PASS em `2026-11-06T03:52:34Z` (`consolidated-result.json`); sem re-execucao neste lane (zero diff de fonte).
- Criterios de aceitacao: secao 5, itens 1-6; item 5 (HIL por variante) explicitamente nao executado.
- Qualidade da evidencia: MEDIA para host (fonte observada + gate recente, sem re-run dedicado); NULA para hardware (todas as celulas de hardware = `EXTERNAL BLOCKED`).
- Bloqueadores externos: placa estavel, ponte ativa, duas variantes de placa, companions vinculados, bateria com terceiros, aprovacao OTP (fora de escopo).
