# HW_WALLET_COMPAT_PLAN — AegisKey como hardware wallet

> Natureza: avaliacao + planejamento. Nenhuma implementacao neste documento.
> Branch: `fd/finalizacao-linux`. Regra transversal: consumidores falam com o
> dispositivo somente pela fachada `universal-device-sdk` (facade-first).
> Nomes de protocolo e camada usados de forma generica: BIP-32/39/44,
> PSBT/BIP-174, USB HID, xpub. Referencias de interoperabilidade usam apenas
> o termo "carteiras hardware populares" e "carteiras software".

---

## 1. Objetivo e escopo

Avaliar o que falta para a AegisKey operar como hardware wallet
interoperavel com carteiras hardware populares e carteiras software,
sem quebrar o modelo de seguranca existente (gates binding -> UP -> PIN,
conjunto fechado de status de fio, feature gating com `NotCompiled`).

Fora de escopo deste plano: alteracao de codigo, gravacao em placa,
fluxos de eFuse, e qualquer dado sintetico de fallback (proibido em
todas as fases: sem sucesso forjado, sem mock de producao).

## 2. Fachada publica (contrato, nao implementacao)

### 2.1 Chamada de fachada

Toda operacao de carteira passa por tipos fechados do
`universal-device-sdk`; o transporte (`uniffi-bridge`) permanece
passthrough puro (sem logica de negocio). Proposta de superficie
aditiva (nomes indicativos, sem quebrar o existente):

- `SdkRequest::Wallet(WalletRequest { opcode, payload })` — GEN / LIST / ADDR (existente).
- `SdkRequest::WalletSign(WalletSignRequest { opcode, payload })` — assinatura (existente como carrier opaco; execucao pendente no firmware).
- Novos opcodes futuros na faixa livre (nunca `0x20`-`0x27`, nunca `0x30`-`0x34`, nunca `0x2E`/`0x2F`/`0x38`/`0x39`): exemplo de alocacao a reservar — derivacao hierarquica, exportacao de chave publica estendida (xpub), PSBT/BIP-174. Valores exatos definidos na fase F1; a faixa `0x35`-`0x37` existente e congelada.

### 2.2 Semantica tipada de request/response

- Request: `{ opcode: u8, payload: TLV }`. TLV segue o padrao existente
  (`0x01` slot, `0x02` label, `0x07` address na resposta, `0x08` rede no
  pedido GEN). Novas tags somente acima das reservadas e ignoradas por
  decoders antigos (regra 9.6: desconhecido e ignorado, nunca falha).
- Response: `SdkResponse { status: u8, payload: Vec<u8> }`. O byte de
  status preserva o conjunto fechado 9.5 (`0x00` ok, `0x01` need-UP,
  `0x02` need-PIN, `0x03` no-slot, `0x04` bad-envelope, `0x05`
  need-binding). `is_ok()` e verdadeiro somente para `0x00`.
- `AddressRequest { coin, account, change, index }` (tipos em
  `hardwallet.rs`) e DTO de exibicao: nenhuma criptografia ocorre no SDK;
  derivacao e assinatura executam no firmware, em RAM.
- `ClearSignSummaryDto { network, action, to_address, amount, tx_hash_hex }`
  e `OledPreviewDto { line1..line4, framebuffer_1024_bytes? }` ja existem
  como DTOs CBOR no SDK (veiculo, sem logica).

### 2.3 Estados por operacao (sem fallback sintetico)

| Estado | Significado | Quando ocorre |
|---|---|---|
| `success` (`0x00`) | Operacao real verificada no dispositivo | Chave gerada/assinatura produzida com gates aprovados |
| `unsupported` | Operacao nao suportada por este build/dispositivo | Opcode fora da faixa, rede desconhecida, PSBT antes de F4 |
| `unavailable` | Temporariamente indisponivel | Transporte ocupado, sessao expirada, NVS em rollback |
| `permission denied` | Gate fail-closed (`0x05`/`0x01`/`0x02`) | Sem binding, sem UP fisica, sem PIN |
| `compiled out` (`NotCompiled`) | Familia fora da build | Feature `hardwallet` desligada ou build diet `cap-fido-only` / `cap-fido-totp` (UNICA origem legitima de `NotCompiled`; nunca erro de runtime) |
| `external blocked` | Dependencia externa bloqueia | Sem hardware presente, host sem transporte, dependencia de laboratorio desligada |
| `real verified` | Evidencia, nao estado de fio | Vetor conhecido + teste executado (secao 9); nenhum caminho retorna dado forjado |

## 3. Feature-gated behavior

- `hardwallet` (default ON): `Wallet` + `WalletSign` compilam; OFF rende
  `SdkError::NotCompiled` via `require_hardwallet()` em `check_compiled()`.
- `cap-fido-only` / `cap-fido-totp` (raizes alternativas, mutuamente
  exclusivas com `default`): dieta sem wallet/vault/radio/display; qualquer
  opcode de carteira responde `unsupported`/`NotCompiled` conforme a
  camada (fio = status fechado; SDK = `NotCompiled`). Combinacao errada
  falha em `compile_error!`.
- `has-display` / `board-t-display` / `board-ttgo-classic`: LCD presente
  ou stub headless (mesmo contrato de `DisplayManager`, sem framebuffer
  de ~106 KiB e sem dependencia grafica). Plano nao pode presumir tela.
- `prod-strict`: sem ganchos de teste, sem toque simulado, sem bypass.
- `test-mode` (nunca em `default`/release): unica superficie de testes
  de laboratorio; sem comportamento de firmware fora dela.

## 4. Traducao FFI/JNI

- Borda C estavel (`aegis_*`): `i32` (`0` ok, negativos `AEGIS_ERR_*`
  `-1..-13`), padrao two-call `(out, out_cap, out_len)`, NULL com
  `len > 0` = `NULL_POINTER`, UTF-8 obrigatorio, sem segredo em erro.
- Valores estruturados cruzam a borda como JSON somente (dentro = structs
  tipadas; JSON nunca e formato de fio). `aegis_wallet_address`
  (rede + pubkey_hex -> endereco, off-device puro, com vetores conhecidos)
  e o precedente a seguir para `xpub` e resumo de exibicao.
- A fachada Kotlin Android opera com fallbacks ate vincular os simbolos;
  nenhuma mudanca Kotlin decorre da superficie nova ate F7.
- JNI/PM existente (`pm_jni`) e ortogonal; nada de carteira passa por ele.

## 5. Persistencia

- Hoje: `WalletStore` e sessao de boot em RAM (por desenho). Codec pronto:
  `export_routing` / `import_routing` (`[slot, discriminante]` ordenado,
  atomico, fail-closed: comprimento impar, discriminante zerado/
  desconhecido, slot >= 32 ou duplicado = `BadEnvelope` sem tocar a
  tabela anterior) + chaves `wallet_slot_btc` / `wallet_slot_evm` /
  `wallet_slot_sol` (envelope-por-slot).
- Padrao a reutilizar: `SecureStorage` NVS cifrada + snapshot com rollback
  se o save falhar (precedente do executor vendor) e `verify-after-write`
  (precedente do binding). NVS parcial = corrompido, nunca meio-estado.
- Novas chaves (semente, xpub cache, contador anti-replay de PSBT) seguem
  o mesmo envelope-por-slot; nenhum byte privado em label, log ou TLV de
  resposta. Cache de xpub e derivado e re-derivavel: perda = re-derivar,
  nunca perda de fundos.

## 6. O que ja existe (verificado no codigo)

| Camada | Estado | Evidencia |
|---|---|---|
| Curvas | Pronto | `p256`, `p384`, `p521`, `k256` (secp256k1), `ed25519-dalek` no workspace; `CryptoNetwork` mapeia BTC/EVM -> ES256K, rede ed25519 -> EdDSA |
| Wallet store | Pronto (sessao) | `WalletStore` com `KeyManager` dedicado (isolamento B1), GEN/IMPORT/SIGN/LIST/DELETE/GET/ADDR/public_cose, gates UP e UP+PIN herdados, 32 slots, prefixo `wallet:`, zeroizacao no drop |
| Enderecos | Pronto | P2WPKH bech32 (BIP-173), EIP-55 com checksum, base58 ed25519; vetores: gerador G -> `bc1qw508...f3t4` e `0x7E5F...Bdf` |
| BIP-39 / semente | Pronto (core) | `Mnemonic24` 24 palavras, PBKDF2-HMAC-SHA512 2048 iteracoes, `to_seed` 64 B, vetor oficial (entropia zero -> frase `abandon...art`, seed `bda8...fcc8` com passphrase de teste); `AegisVault::from_master_seed` via HKDF-SHA256; envelope de semente via chave derivada de hardware + Shamir 2-de-3 em GF(256) com CRC32 |
| hmac-secret / largeBlob | Pronto | Extensoes CTAP 2.1 no core (base para fluxos de desafio-resposta de carteira software) |
| Challenge-Response simetrico | Pronto (camada generica) | HMAC-SHA1 por slot no companion desktop (caminho siexistente e testado; nao e assinatura de carteira) |
| Clear signing (parse) | Parcial | RLP EIP-1559/legacy + seletor `transfer` ERC-20, transacao crua de rede principal (saidas P2WPKH/P2PKH), mensagem de rede ed25519 (transferencia de programa de sistema); framebuffer 128x64 de 1024 B com fonte 5x7 + `render_transaction_preview` (4 linhas + banner de confirmacao) — tudo testavel sem hardware |
| Display | Pronto (condicional) | `DisplayManager` unificado; placas com LCD usam `has-display`; placa sem display usa stub (mesmo contrato, LED + espelho serial) |
| UP fisica | Pronto | Botao fisico (GPIO 0) com debounce; guarda `prod-strict` contra toque simulado |
| Transportes | Pronto | CTAPHID (pacotes 64 B, remontagem ate 7609 B), USB HID + CCID/PIV + teclado HID no firmware USB, BLE GATT com ops wallet `0x35`-`0x37`, serial |
| Fio wallet GEN/LIST/ADDR | Pronto (sessao) | `wallet_exec` TLV + status fechado 9.5; negacao sem UP (`0x01`), rede invalida (`0x04`), slot inexistente (`0x03`) |
| SDK facade / erros / capabilities | Pronto | `SdkRequest::check_compiled`, `SdkError` (5 variantes), `CapabilitySet::HARDWALLET` const, DTOs CBOR de exibicao, `AddressRequest` tipado sem logica |
| FFI endereco | Pronto | `aegis_wallet_address` com vetores conhecidos e rejeicao de entradas invalidas |
| Companions | Pronto (outros fluxos) | Desktop tray + agente SSH + login SO; app Android Kotlin — nenhum com fluxo de carteira |

## 7. Gaps por camada (com veredito curto)

| # | Camada | Gap | Veredito |
|---|---|---|---|
| G1 | Derivacao hierarquica | Sem BIP-32/44/84: chaves avulsas por slot, sem caminho conta/troca/indice, sem controle de domanda | NAO PRONTO — nucleo da compatibilidade; sem isso nao ha interoperabilidade com carteiras software |
| G2 | xpub export | Sem chave publica estendida, sem descritor de conta, sem FFI/JNI correspondente | NAO PRONTO — bloqueia watch-only e pareamento com carteiras software |
| G3 | PSBT/BIP-174 | Parser cobre transacao crua; PSBT (entradas, scripts, sighash, multi-parte) ausente; sem opcode de assinatura ligado ao transporte (`WalletStore::sign` existe, sem fio) | NAO PRONTO — bloqueia fluxo padrao de assinatura |
| G4 | Semente e backup (cerimonia) | Primitivas prontas (BIP-39, Shamir, envelope); falta cerimonia no firmware: gerar/mostrar/importar frase com confirmacao fisica + persistencia com rollback | PARCIAL — criptografia pronta, UX de custodia ausente |
| G5 | Confirmacao fisica sem display | Placa sem display = LED + espelho serial apenas; framebuffer de pre-visualizacao existe mas sem amarracao ao fluxo de assinatura wallet no headless | PARCIAL — seguro para teste, insuficiente como garantia anti-blind-signing sem tela |
| G6 | App companion (fluxo wallet) | Nenhum fluxo xpub/PSBT no desktop ou Android; FFI de endereco e o unico precedente | NAO PRONTO — pareamento depende de F7 |
| G7 | USB HID generico de carteira | Existem CTAPHID + CCID/PIV + BLE vendor; sem framing HID generico de carteira (mensagens de Sutton de carteira popular) | NAO PRONTO — transporte alternativo; BLE/USB existentes cobrem MVP sem ele |
| G8 | Politica anti-blind-signing | Parse exibe, mas nada impoe exibicao-antes-de-assinar no firmware (sem gate `mostrou -> assinou`) | NAO PRONTO — requisito de seguranca para qualquer assinatura real |

## 8. Tabela de contrato (fases futuras; sem dado sintetico)

| Operacao (fachada) | success | unsupported | unavailable | permission denied | compiled out | external blocked | real verified |
|---|---|---|---|---|---|---|---|
| `Wallet GEN/LIST/ADDR` | `0x00` + TLV | opcode/rede invalida `0x04` | sessao expirada | sem UP `0x01` (+PIN no import `0x02`) | sem `hardwallet` / diet | sem hardware | vetores G + roundtrip sessao (testes atuais) |
| Derivacao (BIP-32/44/84) | `0x00` + pubkey encadeada | caminho fora do padrao `0x04` | NVS em rollback | sem UP `0x01` | idem | idem | vetor hierarquico padrao (teste F2) |
| xpub export | `0x00` + xpub conta | rede sem curva wallet `0x04` | idem | sem UP `0x01` | idem | idem | xpub contra vetor padrao (teste F3) |
| PSBT sign | `0x00` + PSBT parcial | PSBT malformado `0x04` / contrato nao suportado | idem | sem UP `0x01` + exibicao previa obrigatoria | idem | idem | PSBT de teste assinado + verificado off-device (teste F4) |
| Backup/restore semente | `0x00` metadados | frase invalida/checksum `0x04` | idem | UP+PIN `0x01`/`0x02` | idem | idem | roundtrip BIP-39 + Shamir 2-de-3 (testes atuais + F5) |
| Clear-sign preview | `0x00` DTO + framebuffer | tipo de envelope nao coberto `0x04` | display ausente (headless = DTO sem framebuffer) | sem UP `0x01` | sem `hardwallet` | sem tela fisica | parse dos 3 formatos + render 4 linhas (testes atuais) |

`NotCompiled` aparece SOMENTE na coluna "compiled out". Nenhuma outra
coluna pode mapear para ele. Nenhum caminho retorna endereco, xpub ou
assinatura de exemplo/placeholder.

## 9. Ordem atomica de implementacao (backward-compat + evidencia)

Ordem estrita; cada fase e atomicamente reversivel e nao altera bytes
de fio existentes (faixa `0x35`-`0x37` e tags TLV congeladas; decoders
antigos ignoram tags novas).

- **F1 — Reserva de opcodes + gates.** Reservar faixas livres para
  derivacao/xpub/PSBT; estender `WALLET_OP_*`, `check_compiled`,
  `CapabilitySet` de forma aditiva (nunca renumerar bits). Evidencia:
  testes de gate (on/off de feature) + `capabilities()` const.
- **F2 — Derivacao hierarquica no core (RAM).** BIP-32/44/84 sobre
  secp256k1 com testes contra vetores padrao; sem fio, sem NVS.
  Evidencia: vetores de derivacao + teste de isolamento de slots.
- **F3 — xpub + FFI/JNI.** Exportacao de chave estendida por conta,
  `aegis_xpub_*` na borda C seguindo o padrao two-call + vetores;
  rejeicao fail-closed de rede/caminho invalido. Evidencia: testes FFI
  + vetores cruzados com implementacao independente.
- **F4 — PSBT/BIP-174 + fio de assinatura.** Parser PSBT, sighash por
  rede, opcode de assinatura ligado a `WalletStore::sign` com gate
  exibicao-antes-de-assinar (G8). Evidencia: PSBT de teste assinado e
  verificado off-device; teste de negacao sem exibicao previa.
- **F5 — Cerimonia de semente + persistencia.** Gerar/mostrar/importar
  frase com confirmacao fisica; persistir routing + envelopes com
  snapshot/rollback + verify-after-write; NVS parcial = corrompido.
  Evidencia: teste de queda no meio do save + roundtrip Shamir.
- **F6 — Confirmacao fisica por placa.** Com display: pre-visualizacao
  obrigatoria (4 linhas + banner) antes do UP de assinatura; sem
  display: politica explicita documentada (ex.: assinatura assistida
  pelo companion com hash exibido nos dois lados) — nunca silenciosa.
  Evidencia: testes HIL por variante de placa.
- **F7 — Companion (desktop + Android) via fachada.** Fluxos
  xpub/watch-only e PSBT round-trip chamando apenas `universal-device-sdk`
  (passthrough preservado); sem logica cripto no app. Evidencia: teste
  de integracao app->firmware em bancada.
- **F8 — Interop matriz.** Bateria contra carteiras hardware populares e
  carteiras software (parear xpub, assinar PSBT, verificar endereco).
  Evidencia: matriz de interop preenchida somente com execucoes reais;
  celula nao executada = `external blocked`, nunca "ok".

Compatibilidade retroativa: nenhuma fase remove opcode, tag TLV, bit de
capability ou codigo de erro; builds diet continuam respondendo o
conjunto fechado; SDK sem a feature nova rende `NotCompiled`.

## 10. Testes de aceitacao (criterios de saida, sem placa neste plano)

1. `cargo test` passa no workspace (core + firmware host + SDK + bridge).
2. `cargo clippy --all-targets -- -D warnings` limpo.
3. Vetores: G secp256k1 (enderecos), BIP-39 oficial (entropia zero),
   derivacao hierarquica padrao, xpub padrao, PSBT de teste — todos
   cruzados com implementacao independente.
4. Negacoes: sem UP, sem PIN, sem binding, opcode/tag invalidos,
   NVS parcial, feature desligada (`NotCompiled`), transporte ausente
   (`external blocked`) — cada uma com teste dedicado.
5. HIL por variante de placa (com/sem display) antes de qualquer
   declaracao de "real verificado" para assinatura.
6. Politica de eFuse inalterada: nenhuma etapa exige gravacao OTP.

## 11. Riscos e limites declarados

- Sem tela fisica nao ha garantia visual contra blind signing; F6 torna
  isso explicito por variante em vez de presumir.
- Compatibilidade plena com o ecossistema exige G1+G2+G3; o restante e
  seguranca e UX, nao interop.
- Transporte HID generico de carteira (G7) e opcional para o MVP: os
  transportes existentes (USB CTAPHID/CCID, BLE) carregam os fluxos.