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
