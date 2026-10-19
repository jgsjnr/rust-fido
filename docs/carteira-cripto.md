# Carteira Cripto — storage-only (DRAFT, Fase 1)

> DRAFT — reconciliar com wallet/* no Step 4

Fonte (quando o modulo pousar): `wallet/*.rs` sobre `KeyManager`.
Este documento descreve a intençao; o codigo e a fonte final (Step 4 reconcilia).

## Objetivo

Storage-only de segredos BTC / EVM / SOL sobre o `KeyManager` existente.
Nenhuma transaçao e assinada ou transmitida nesta fase — apenas guarda e leitura
mediante gates. Sem OTP, sem lock dedicado (reuso dos gates ja existentes).

## Mapa de reuso

| Capacidade | Reuso | Nota |
| --- | --- | --- |
| Gates UP / UP+PIN | `KeyManager` | nenhuma logica nova de gate; matriz abaixo |
| Envelope | AEGN v1 byte-identico | nenhum byte de envelope muda (ver `nvs_schema.md`) |
| Seed | BIP-39 | seed unica; slots derivam/apontam para ela |
| Persistencia | NVS cifrada | chaves `wallet_slot_*` (§ NVS abaixo) |
| Auditoria | padrao `binding`/`recovery` | segredo nunca em claro no log |

## Politica de alocaçao de slots

Definida no codigo — reconciliada no Step 4.

(Placeholder intencional: um slot por rede — `btc`, `evm`, `sol`.
Detalhe de indice/formato do payload vive em `wallet/*`, nao aqui.)

## Matriz de gates

| Operaçao | Gate | Nota |
| --- | --- | --- |
| Listar slots / metadados | UP | presença apenas, nunca segredo |
| Gravar slot (`wallet_slot_*`) | UP+PIN | verify-after-write, padrao `binding` |
| Ler / exportar segredo do slot | UP+PIN | segredo nunca logado |
| Apagar slot | UP+PIN | wipe com zeroize |
| OTP / lock dedicado | — | FORA DE ESCOPO: nao existe nesta fase |

Sem OTP. Sem lock proprio — o gate UP+PIN do `KeyManager` e o unico cadeado.

## Chaves NVS

Envelope inalterado (AEGN v1, TRNG interno, zeroize). Detalhe formal em `nvs_schema.md` (§ Carteira).

| Chave | Conteudo | Gate | Nota |
| --- | --- | --- | --- |
| `wallet_slot_btc` | envelope AEGN do segredo BTC | UP+PIN | storage-only; ver Step 4 p/ formato |
| `wallet_slot_evm` | envelope AEGN do segredo EVM | UP+PIN | storage-only; ver Step 4 p/ formato |
| `wallet_slot_sol` | envelope AEGN do segredo SOL | UP+PIN | storage-only; ver Step 4 p/ formato |

Seed BIP-39 mora no `KeyManager`; os slots referenciam-na (detalhe no codigo, Step 4).

## Plano da aba web

Leitura/listagem de slots na aba web existente (padrao das abas `wifi`/`binding`):

- Listar slots sem exibir segredos (UP).
- Gravar / apagar slot sob UP+PIN.
- Nunca exibir seed ou segredo em claro no log ou na resposta sem gate.
- Layout exato reconciliado no Step 4 apos o modulo pousar.

## Fora de escopo

- Assinar ou transmitir transaçoes (qualquer rede).
- BIP-32 / derivaçao HD (follow-up futuro, apos storage-only estabilizar).
- OTP, lock dedicado, ou qualquer byte novo no envelope AEGN v1.
- USB/CTAP tocando nas chaves `wallet_slot_*`.

## Pendencias abertas (Step 4)

- [ ] Reconciliar formato exato do payload de cada slot com `wallet/*`.
- [ ] Confirmar politica de alocaçao de slots contra o codigo.
- [ ] Confirmar plano da aba web contra o modulo.
