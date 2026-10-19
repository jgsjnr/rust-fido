# Carteira Cripto — storage-only (Fase 1)

Fonte: `crates/aegis-fido-core/src/wallet/*` sobre `KeyManager`
(`store.rs`, `types.rs`, `address.rs`, `mod.rs`).
Este documento espelha o codigo; divergencia se resolve a favor do codigo.

## Objetivo

Storage-only de segredos BTC / EVM / SOL sobre o `KeyManager` existente.
Nenhuma transaçao e assinada ou transmitida nesta fase — apenas guarda e leitura
mediante gates. Sem OTP, sem lock dedicado (reuso dos gates ja existentes).

## Mapa de reuso

| Capacidade | Reuso | Nota |
| --- | --- | --- |
| Gates UP / UP+PIN | `KeyManager` | nenhuma logica nova de gate; matriz abaixo |
| Envelope | AEGN v1 byte-identico | nenhum byte de envelope muda (ver `nvs_schema.md`) |
| Seed | BIP-39 | seed unica; sem derivaçao HD nesta fase (fora de escopo) |
| Persistencia | NVS cifrada | chaves `wallet_slot_*` (§ NVS abaixo) |
| Auditoria | padrao `binding`/`recovery` | segredo nunca em claro no log |

## Politica de alocaçao de slots

B1 (ver `wallet/mod.rs`): o `WalletStore` detem um `KeyManager` dedicado e
privado (sem acessor, sem `&mut` vazado) mais uma tabela de roteamento em
memoria `slot_id -> CryptoNetwork`. Alternativas descartadas: faixa reservada
(coordenaçao entre consumidores, desperdicio, estado compartilhado) e prefixo
de rotulo sozinho (convenção nao aplicada). O prefixo `wallet:` e aplicado em
todo slot criado como defesa em profundidade para auditoria de LIST.

- Namespace: 32 slots, ids `0..=31` (id `32` rejeitado como `BadEnvelope`;
  exaustao retorna `NoSlot`; apos `delete` o slot e reutilizavel).
- Rotulo: prefixo `wallet:` (7B) + rotulo do chamador, limite total 32B —
  rotulo util ate 25 caracteres, acima disso `BadEnvelope`.
- Curvas (reuso, sem motor novo): BTC e EVM usam ES256K (secp256k1);
  SOL usa EdDSA. Como ES256K e ambiguo entre BTC e EVM, a rede nao e
  recuperavel do alg COSE — dai a tabela de roteamento.
- `import` declara o `alg` e recusa (`BadEnvelope`, slot intocado) quando ele
  diverge da curva da rede: o host nao reinterpreta bytes de envelope sob a
  curva errada.
- Robustez de roteamento: a entrada de roteamento e desfeita se `record_for`
  falhar em `generate`/`import` — nunca resta entrada orfa.

## Formato do payload de cada slot

- Conteudo: envelope AEGN v1 (`AegisVault::seal_envelope` / open) dos bytes do
  segredo; `import` abre o envelope com a chave vinculada ao PIN
  (`pin_token` + `AegisVault` emprestada por chamada, sem lock global).
- Em RAM, o segredo vive no `KeyManager` dedicado (zeroize on drop); o
  `WalletStore` guarda so metadados de roteamento.
- `WalletRecord` e so metadados por construçao: `slot_id`, `network`,
  `address`, `label` — nenhum campo de bytes privados, de modo que clones de
  LIST nunca vazam material de chave.
- Endereços derivados somente de chaves publicas: BTC = P2WPKH bech32 v0
  (BIP-173, `bc1q...`); EVM = EIP-55 checksummed (`0x...`); SOL = base58 da
  pubkey Ed25519 de 32B. Curva errada para a rede mapeia para `BadEnvelope`
  (conjunto fechado 9.5, sem status novo).

## Matriz de gates

| Operaçao | Gate | Nota |
| --- | --- | --- |
| Listar slots / metadados (`list`, `get`, `address`, `public_cose`) | UP | presença apenas, nunca segredo; `public_cose` so CBOR publica |
| Gerar slot (`generate`) | UP | sob a curva da rede |
| Assinar mensagem (`sign`) | UP | storage + message-sign; nenhuma transaçao construida aqui |
| Gravar slot (`wallet_slot_*`) | UP+PIN | verify-after-write, padrao `binding` |
| Ler / exportar segredo do slot | UP+PIN | segredo nunca logado |
| Apagar slot (`delete`) | UP+PIN | wipe com zeroize; libera o slot e a entrada de roteamento |
| OTP / lock dedicado | — | FORA DE ESCOPO: nao existe nesta fase |

Sem OTP. Sem lock proprio — o gate UP+PIN do `KeyManager` e o unico cadeado.

## Chaves NVS

Envelope inalterado (AEGN v1, TRNG interno, zeroize). Detalhe formal em `nvs_schema.md` (§ Carteira).

| Chave | Conteudo | Gate | Nota |
| --- | --- | --- | --- |
| `wallet_slot_btc` | envelope AEGN do segredo BTC | UP+PIN | storage-only; segredo BTC sob ES256K |
| `wallet_slot_evm` | envelope AEGN do segredo EVM | UP+PIN | storage-only; segredo EVM sob ES256K |
| `wallet_slot_sol` | envelope AEGN do segredo SOL | UP+PIN | storage-only; segredo SOL sob EdDSA |

Sem derivaçao HD nesta fase: cada slot guarda seu proprio segredo (gerado no
dispositivo ou importado via envelope).

## Plano da aba web

Aba `Carteira Cripto` em `web/index.html` + `web/app.js`, isolada (nao toca o
codigo das demais abas). Painel **assistido**: `tools/server.py` nao expoe
`GET/POST /api/wallet` (verificado) — portanto a aba nao busca o firmware:

- **Vivo:** navegaçao, tabela de slots em forma de `WalletRecord`
  (rede, slot/NVS, rotulo, endereço, gate), botao Atualizar, passos guiados
  (gerar sob UP, importar sob UP+PIN, ver endereço sob UP, apagar sob UP+PIN)
  e matriz de escopo; tudo sem tocar em outro fluxo.
- **Stub (aguarda firmware):** endereços exibidos como
  "— (provisionar no firmware)"; gerar/importar/listar reais acontecem no
  firmware sob UP / UP+PIN.
- Nunca exibe seed ou segredo em claro; nenhum byte privado ou OTP existe no JS.

## Fora de escopo

- Assinar ou transmitir transaçoes (qualquer rede).
- BIP-32 / derivaçao HD (follow-up futuro, apos storage-only estabilizar).
- OTP, lock dedicado, ou qualquer byte novo no envelope AEGN v1.
- USB/CTAP tocando nas chaves `wallet_slot_*`.

## Pendencias abertas (Step 4) — resolvidas

- [x] Reconciliar formato exato do payload de cada slot com `wallet/*`.
- [x] Confirmar politica de alocaçao de slots contra o codigo.
- [x] Confirmar plano da aba web contra o modulo.
