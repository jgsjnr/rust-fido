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

## 10. Apendice Phase8 - UX-conex (mDNS + station + pairing_flow)

Aditivo ao contrato Wave4 (§1-§9 intactos). USB/CTAP bytes intactos; este apendice so conecta transporte + UX.

### 10.1 Hold BOOT: TOTP 2s vs pareamento 5s (`pairing_flow.rs`)

| Hold | `pairing_open=false` | `pairing_open=true` |
|------|----------------------|---------------------|
| `<2000ms` | `None` (sem acao) | `None` |
| `[2000ms,5000ms)` | `Totp` (CALCULATE no device) | `None` (suprimido) |
| `>=5000ms` | `PairingReady` (vence TOTP) | `PairingReady` |

`classify_hold(held_ms, pairing_open)`: `>=5000 => PairingReady` sempre; `>=2000 && <5000 && !pairing_open => Totp`; resto `None`. `held_ms_from_ticks(start, now) = (now-start)*10` (base 10ms do `main.rs`). Corrige `PairingManager` orfao comido pelo branch OATH 2s: o loop agora alimenta `on_button_level + tick` todo poll e so exibe TOTP quando `HoldAction::Totp`.

### 10.2 mDNS `aegiskey-XXXX.local` (`mdns.rs`)

```
hostname = "aegiskey-" + lowercase(ultimos 4 alfanumericos do serial) + ".local"
fallback = "aegiskey-0001.local" (serial sem 4 alfanumericos)
ex.: "AEGIS-S3-00AF" -> "aegiskey-00af.local"
```

`is_valid_mdns_hostname`: prefixo `aegiskey-`, sufixo `.local`, `<=64B`, meio `[0-9a-z-]`. `MdnsManager::update(pairing_open, station_up)`: ativo SOMENTE quando `!pairing_open && station_up`; durante pareamento ou sem station -> `Off` (fallback AP assume). Stub ESP `start_mdns_esp(hostname)`.

### 10.3 WiFi station (`wifi_station.rs`)

| Chave NVS | Conteudo | Gate |
|-----------|----------|------|
| `wifi_sta_ssid` | SSID `1..32` ascii | UP+PIN no save/clear |
| `wifi_sta_pass` | senha WPA2 `8..63` ascii | UP+PIN no save/clear |

`save_station_credentials`: `UpAndPin::check_up` primeiro (sem auth -> `Unauthorized`, NVS intacta); valida bounds; grava par via `SecureStorage::store` (TRNG interno, zeroize). `has_station_credentials`: ambos existem. `WifiStationManager`: `Off -> Connecting (15s) -> Connected`; `update(pairing_open, has_credentials, now)`: conecta SO quando `!pairing_open && has_credentials`; `pairing_open` desliga na hora; `Connecting` expira em `WIFI_STA_CONNECT_TIMEOUT_MS=15000` (fallback AP). Stub ESP `start_station_esp(ssid)`.

### 10.4 Regra de transporte (main loop)

```
pairing_open = pairing_mgr.is_pairing_window_open(now_ms)   // alimentado todo poll
wifi_ap_mgr.update(pairing_open, menu_request=false, now_ms) // fallback AP durante pareamento
sta_mgr.update(pairing_open, has_creds=false(host stub), now_ms)
mdns_mgr.update(pairing_open, sta_mgr.is_up())
TOTP exibido SOMENTE quando classify_hold==Totp (suprimido com pairing_open)
```

Prioridade mantida `USB > BLE > WiFi` (§8); AP/BLE seguem §1-§6; TOTP segue §7 (codigo so sai com UP, secret nunca sai). Gates: `UpOnly` (BLE control_write, OATH display) e `UpAndPin` (troca senha AP §6, save/clear station §10.3).

## 11. Apendice Binding + Recovery sobre GATT (0x28-0x2D, aditivo)

Aditivo ao contrato Wave4 (§1-§10 intactos). GATT inalterado, revisao permanece
`0x01`. Framing §3 reutilizado sem mudanca. USB/CTAP bytes intactos e sempre
livres (binding nunca toca neste caminho). Implementacao:
`firmware/src/binding.rs` (`BindingManager`), `firmware/src/recovery.rs`
(`RecoveryManager` PIN), `firmware/src/ble_gatt.rs` (despacho 0x28-0x2D),
fiação minima em `firmware/src/main.rs` (`binding_mgr.tick` todo poll).

### 11.1 Opcodes (faixa binding mgmt `0x28-0x2D`, FFF1 control-point)

| Op | Nome | Req | Resp OK | Gate |
|----|------|-----|---------|------|
| `0x28` | `BIND_CLAIM` | `app_pub(65)\|\|binding_id(16)` = 81B | `binding_id(16)` echo | Unclaimed+pareamento+UP (nunca PIN) |
| `0x29` | `BIND_CHALLENGE` | vazio (0B) | `challenge(32)` TRNG | Claimed (senao NEED_BINDING) |
| `0x2A` | `BIND_VERIFY` | `op(1)\|\|challenge(32)\|\|payload_hash(32)\|\|sig(var)` | vazio | Claimed+prova valida (helper teste) |
| `0x2B` | `BIND_RELEASE` | `challenge(32)\|\|payload_hash(32)\|\|sig(var)` | vazio (wipe) | Claimed+prova+UP (teste: so UP com bypass) |
| `0x2C` | `RECOVERY_SET` | `pin_ascii(4..6)` | vazio | UP (nunca vinculo; fisico e raiz) |
| `0x2D` | `RECOVERY_UNLOCK` | `pin_ascii(4..6)` | vazio (wipe vinculo) | UP+PIN certo (8 tentativas NVS) |

`payload_hash = SHA-256(payload)`; `sig` P-256 DER ou raw sobre
`challenge||op||payload_hash` (para RELEASE, `op=0x52 BIND_OP_RELEASE` e
`payload_hash=SHA-256(binding_id)`). Request wire:
`[op:1, len_hi:1, len_lo:1, payload...]` fragmentado per §3. Response wire:
`[op:1, status:1, payload...]` (status §9.5+0x05).

### 11.2 Split uso/config (normativo)

- USO (`0x22` KEY_LIST, `0x25` OATH_LIST, `0x26` OATH_CODE, `0x83` MSG
  GetAssertion, `GET /oath/code`, display TOTP): nunca exige vinculo, so UP
  fisico via `UpPolicy::UpOnly` (latch uso unico). Senao keypass nao funciona.
- CONFIGURAR (`0x20` GEN, `0x21` IMPORT, `0x23` KEY_DELETE, `0x24` OATH_PUT,
  `0x27` OATH_DELETE, `POST /config/wifi`, `/wifi/creds` save/clear,
  `0x28-0x2B` claim-mgmt): release exige vinculo+UP(+PIN onde `vendor_op_requires_pin`);
  teste (`test-mode` ON) exige so UP(+PIN) com `ltrace` (cripto app/chave
  DESABILITADA em teste). Ordem canonica: binding -> UP -> PIN (app alheio
  sempre ve NEED_BINDING primeiro).
- `GET /oath/code` e `oath_store_get` sao USO (vinculo ignorado de proposito;
  assinatura preservada para compat). `POST /config/wifi`, station save/clear,
  `oath_store_put/delete` sao CONFIG (vinculo em release, bypass em teste).

### 11.3 Bypass test-mode (normativo)

Com `test-mode` ON (`cfg(feature="test-mode")`), `binding_bypass_enabled()==true`:
gates CONFIG ignoram `binding_ok` e retornam `Ok` com
`ltrace!(Transport, TpOpen, "binding-bypass")` (zero custo sem `debug-terminal`).
Cripto P-256 do app segue valida em `BindingManager::verify` (testes de curva
passam nos dois modos); o bypass e so na barreira do transporte. Release
(feature OFF) = vinculo OBRIGATORIO para CONFIGURAR. USO nunca e afetado
(sempre so UP, nos dois modos).

### 11.4 Recovery PIN (normativo)

- Formato: 4-6 digitos ASCII (`is_valid_recovery_pin`); definido no claim via
  `0x2C` com UP fisico (sobrescreve anterior; novo dono deve definir outro
  apos re-claim). NVS: `rec_pin_hash` (32B SHA-256(salt||pin)), `rec_pin_salt`
  (16B TRNG), `rec_pin_retries` (1B, inicia em 8), envelope AEGN v1 com
  verify-after-write e zeroize. Segredo nunca sai (so hash+salt; codigo nunca
  loga o PIN; `ltrace` so conta `PinRetry`/`PinBlocked` com retries restantes).
- Verify no device (`0x2D` + `verify_recovery_pin`): exige UP; compara em tempo
  constante; sucesso reseta para 8; falha decrementa na NVS (persistida contra
  queda); 0 restantes => `Locked` (so `factory_reset` fisico com hold 5s+UP
  recupera). `recovery_unlock` = verify ok + `binding.wipe` (volta a Unclaimed,
  NVS de binding limpa, RAM zerada; PIN preservado ate ser sobrescrito).
- Status: `PresenceRequired->0x01`, `BadPin/Locked->0x02`, resto `->0x04`.
  Recovery nunca emite `0x05` (nao e gate de dono; e resgate fisico+PIN).

### 11.5 Erros (conjunto fechado, §9.5+0x05)

`status: 0x00=OK | 0x01=NEED_UP | 0x02=NEED_PIN | 0x03=NO_SLOT | 0x04=BAD_ENVELOPE | 0x05=NEED_BINDING`.
`0x00-0x04` preservados (§9.5 golden); `0x05` e a unica adicao (so BLE/WiFi,
nunca USB). `AlreadyClaimed/Corrupted/Storage->0x04`; `PairingRequired->0x01`;
`NotClaimed/BadSignature/ChallengeMismatch/Replay/BadPubkey->0x05`.
Framing (§3) inalterado; status desconhecido = falha generica sem retry.

### 11.6 Forward-compat e o que NAO muda

Decoders Wave4 que nao conhecem `0x28-0x2D` DEVEM ignorar/descartar sem NACK
que quebre §3 (igual §9.6). GATT `0xFFFD`/`FFF1-FFF4`, bonding, pareamento
hold-5s/janela-60s, prioridade `USB > BLE > WiFi`, `POST /ctap`, TOTP RFC6238 —
todos per §1-§10. Este apendice so adiciona opcodes + split + recovery.
USB/CTAP (`aegis-fido-usb`, `CtapEngine`) zero mudanca (golden em
`usb_ctap_bytes_untouched_golden`).
