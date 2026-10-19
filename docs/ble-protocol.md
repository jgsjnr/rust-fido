# BLE Protocol — Contrato Congelado (Wave4)

App Android implementa este contrato. USB/CTAP bytes intactos; BLE so encapsula.

## 1. GATT 0xFFFD

| Handle | UUID | Props | Uso |
|--------|------|-------|-----|
| Service | `0xFFFD` | — | Servico AegisKey |
| FFF1 | `0xFFF1` | Write | Control-point: request fragmentado |
| FFF2 | `0xFFF2` | Notify | Status/keepalive (`0=idle,1=processing,2=up-needed`) |
| FFF3 | `0xFFF3` | Read | `u16 LE`: tamanho pendente do reassemble (0=idle) |
| FFF4 | `0xFFF4` | Read/Write | Revisao (`0x01`; escrita so aceita `0x01`) |

Constantes em `firmware/src/ble_gatt.rs`: `BLE_SERVICE_UUID`, `CHAR_*_UUID`, `GATT_REVISION`.

## 2. Opcodes CTAP2-BLE

| Op | Nome | Delega para |
|----|------|-------------|
| `0x81` | PING | Eco (sem `CtapEngine`) |
| `0x83` | MSG | `CtapEngine::process_packet` (`[cmd, CBOR...]` -> `[status, CBOR...]`) |
| `0xBE` | CANCEL | Aborta transacao ativa, retorna vazio |

## 3. Framing (FFF1)

- Primeiro fragmento: `[opcode:1, len_hi:1, len_lo:1, data..]`, `len` = total do payload.
- Continuacao: `[seq:1, data..]` (seq ignorado no stub, so concatena).
- Max fragmento: `244B` (`MAX_FRAGMENT_BYTES`); limite total: `512B` (`CONTROL_POINT_LENGTH`, == envelope MAX-ESP).
- Colisao: novo `start` com transacao ativa -> `TransactionBusy`; host deve `CANCEL (0xBE)` primeiro.
- `CANCEL` como primeiro byte aborta e retorna `{opcode:0xBE, payload:[]}`.

Exemplo MSG 10B em 2 fragmentos:

```
-> [0x83, 0x00, 0x0A, 01 02 03 04]   (primeiro, 4/10B)
<- (FFF3=10, FFF2=[0x01])
-> [0x00, 05 06 07 08 09 0A]         (continuacao, completa)
<- (FFF2=[0x00], resposta CTAP via notify/read)
```

## 4. Auth (bonding + UP)

- Bonding obrigatorio (`requires_bonding()=true`, JustWorks+bonding+UP).
- UP por operacao: `control_write` exige `presence_confirmed=true` (latch uso unico pelo chamador, via `UpPolicy::UpOnly`).
- PIN/UV continuam no `CtapEngine` (ClientPIN); transporte nao decide PIN.
- Pareamento: hold 5s GPIO0 -> advertising com flag pairing, janela 60s (`PAIRING_WINDOW_SECS`).

## 5. Envelope WiFi `POST /ctap`

Mesmo `SecureStorage` (AES-256-GCM, magic `AEGN`, versao `0x01`):

```
envelope = MAGIC[4]=41 45 47 4E | VER[1]=01 | NONCE[12] | CT+TAG[...]
min_len = 4+1+12+16 = 33B
```

`validate_ctap_envelope` checa magic/versao/tamanho; conteudo delega ao `CtapService`.

## 6. `POST /config/wifi` (troca de senha)

- Body: nova senha ASCII `8..63` chars.
- Exige UP+PIN (`UpAndPin::check_up`); sem auth -> `Unauthorized`, NVS intacta.
- Grava em `NVS key wifi_ap_pass` via `SecureStorage::store` (TRNG interno, zeroize apos uso).

## 7. `GET /oath/code?account=<nome>` (TOTP no device)

- Exige `presence_confirmed=true`; secret nunca sai.
- Resposta JSON (app parseia):

```json
{"account":"GitHub:alice","code":"287082","remaining_seconds":28}
```

- `code`: 6-8 digitos, zero-padded, janela 30s (`T=t/30`, RFC6238).
- Query: `parse_oath_account_query("/oath/code?account=X") -> Some("X")`.

## 8. Prioridades e keys

- Prioridade: `USB > BLE > WiFi` (decisao congelada).
- Keys nunca saem do device (master em eFuse BLOCK7, salt BLOCK8; AP/BLE so transportam envelopes/codigos).
- Revisao GATT `0x01`; mudancas futuras bumpam FFF4 e este doc juntos.
## 9. Apendice Fase 6 — Keys/OATH sobre BLE (aditivo, sem quebra)

Aditivo ao contrato Wave4 (§1-§8 intactos). GATT inalterado, revisao permanece
`0x01`. Framing §3 reutilizado sem mudanca: `[opcode:1, len_hi:1, len_lo:1, data..]`
+ continuacao `[seq:1, data..]`, fragmento max `244B`, total max `512B`,
`CANCEL (0xBE)` e `TransactionBusy` como antes. `0x81/0x83/0xBE` inalterados.
Inner payload dos ops abaixo e TLV (`tag:1, len:BER, value`), mesmo codec de
`crates/aegis-fido-core/src/oath/tlv.rs` (`parse_tlv_records`/`write_tlv`/`find_tlv`:
len `<0x80` direto, `0x81`+1B, `0x82`+2B).

### 9.1 Opcodes (faixa vendor `0x20-0x27`, FFF1 control-point)

| Op | Nome | Gate normativo |
|----|------|----------------|
| `0x20` | `KEY_GEN_ONDEVICE` | UP |
| `0x21` | `KEY_IMPORT_ENVELOPE` | UP+PIN |
| `0x22` | `KEY_LIST` | UP |
| `0x23` | `KEY_DELETE` | UP+PIN |
| `0x24` | `OATH_PUT` | UP+PIN |
| `0x25` | `OATH_LIST` | UP |
| `0x26` | `OATH_CODE` | UP |
| `0x27` | `OATH_DELETE` | UP+PIN |

Request wire: `[op:1, len_hi:1, len_lo:1, TLV...]` fragmentado per §3.
Response wire: `[op:1, status:1, TLV...]` (status §9.5), fragmentado igual.

### 9.2 Tags inner

- `KEY_*`: `0x01` slot_id (1B) | `0x02` label (utf8, 1..32B) |
  `0x03` pubkey_or_handle (so metadados, nunca privada) |
  `0x04` envelope opaco (bytes AEGN §5). Faixa `0x01-0x04` nao colide com OATH.
- `OATH_*`: reutiliza `oath/types.rs` sem novos tags —
  `0x71` NAME | `0x73` KEY (`type_algo||secret`) | `0x74` CHALLENGE (8B) |
  `0x75` RESPONSE | `0x76` TRUNCATED | `0x78` PROPERTY | `0x7A` IMF |
  `0x7B` ALGORITHM | `0x7C` TOUCH. Semantica identica ao `OathApplet`.

### 9.3 Request/Response TLV por op

| Op | Request TLV | Response OK (`status=0x00`) |
|----|-------------|------------------------------|
| `0x20` GEN | `0x01` slot + `0x02` label | `0x01` slot + `0x02` label + `0x03` pubkey/handle |
| `0x21` IMPORT | `0x01` slot + `0x04` envelope | `0x01` slot (echo) |
| `0x22` LIST | vazio (0B) | repeticao de (`0x01` slot + `0x02` label) por slot ocupado; vazio = 0B |
| `0x23` DELETE | `0x01` slot | `0x01` slot (echo) |
| `0x24` PUT | `0x71` name + `0x73` key + opt `0x78`/`0x7A` | vazio (0B) |
| `0x25` LIST | vazio (0B) | repeticao de `0x71` name (prefixo 1B type/algo, igual `handle_list`) |
| `0x26` CODE | `0x71` name + opt `0x74` challenge (zeros = TOTP now) | `0x75`/`0x76` codigo + opt `0x7C` |
| `0x27` DELETE | `0x71` name | vazio (0B) |

Limites: `MAX_CREDENTIALS=64`; label `1..32B` utf8; TLV total `<=512B` (fragmentacao §3 vale para todos).

### 9.4 Gates UP/PIN (normativo)

- UP = `presence_confirmed=true`, latch uso unico via `UpPolicy::UpOnly` (§4). Sem UP -> `NEED_UP`.
- PIN = sessao ClientPIN/`CtapEngine` ja verificada (§4); transporte nao decide PIN, so exige (igual §6). Sem PIN onde exigido -> `NEED_PIN`.
- GEN/LIST/CODE = UP; IMPORT/PUT/DELETE = UP+PIN. Desvio e bug de seguranca.

### 9.5 Erros (conjunto fechado)

`status: 0x00=OK | 0x01=NEED_UP | 0x02=NEED_PIN | 0x03=NO_SLOT | 0x04=BAD_ENVELOPE`. Payload erro = 0B.

| Status | Quando |
|--------|--------|
| `NEED_UP` | UP ausente/expirado em qualquer op |
| `NEED_PIN` | PIN ausente em `0x21/0x23/0x24/0x27` |
| `NO_SLOT` | slot/nome inexistente (`0x23/0x26/0x27`), slot ocupado/invalido (`0x20`), cheio (`0x24` mapeia `FILE_FULL` -> `NO_SLOT`) |
| `BAD_ENVELOPE` | TLV malformado, label/nome fora do limite, `0x04` que falha `validate_ctap_envelope` (magic `AEGN`/ver `0x01`/min `33B` per §5) |

Framing (`TransactionBusy`, overflow, `CANCEL`) continua em §3. Status desconhecido = falha generica, sem retry e sem fallback para `0x83` MSG.

### 9.6 Forward-compat (normativo)

Decoders Wave4 que nao conhecem `0x20-0x27` DEVEM ignorar/descartar sem NACK que quebre §3 e sem responder. Remetente novo NAO reenvia como `0x83` MSG. Tags TLV desconhecidos em op conhecido DEVEM ser ignorados. Mantem decoders atuais intactos e §1-§8 congelado.

### 9.7 Direcao de dados (o que sai vs o que entra)

- SAI: so metadados e codigos — (`0x01`/`0x02`/`0x03`, nomes OATH + type/algo, `0x75`/`0x76` 6-8 digitos janela 30s per §7). NUNCA: privada, secret OATH, envelope desencapsulado, NONCE/CT em claro.
- ENTRA: so envelopes opacos via `0x21` (device so valida magic/ver/tamanho, delega conteudo). Unica excecao: `0x24` transporta `0x73` secret para dentro (exige bonding §4 + UP+PIN); secret NUNCA sai (so `0x26` retorna codigo). `GET /oath/code` (§7) segue valido; `0x26` e o equivalente BLE com mesmo gate UP.

### 9.8 O que NAO muda

GATT `0xFFFD`/`FFF1-FFF4`, bonding, pareamento hold-5s/janela-60s, prioridade `USB > BLE > WiFi`, `POST /ctap` e `POST /config/wifi`, TOTP RFC6238 — todos per §1-§8. Este apendice so adiciona opcodes.
