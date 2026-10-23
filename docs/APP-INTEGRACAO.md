# APP-INTEGRACAO -- Guia de atualizacao do app

> Fonte unica de verdade do wire: `docs/COMMS-map.md` (secoes 0-8).
> Este documento e um guia de consumo para o app. Em caso de conflito,
> vale o COMMS-map + o codigo-fonte citado. Sem segredos, PINs ou labels
> reais no texto. ASCII puro por regra de transporte.

Fontes lidas (somente leitura):
`docs/COMMS-map.md`, `docs/capacidades-modulos.md`,
`tools/host_sdk/{tlv,ops,transport,gates,cli}.py`,
`tools/app_simulator.py` (menus 0-11, `Session`, `VENDOR_OPS`),
`crates/aegis-fido-firmware/src/ble_gatt.rs` (servico `0xFFFD`),
`wifi_ap.rs` (`POST /ctap`, `POST /config/wifi`, `GET /oath/code`),
`serial_ctaphid.rs`, `ctap/info.rs` (GetInfo canonico),
`binding.rs`, `pairing*.rs`, `proximity.rs`, `recovery.rs`,
`credential/key_manager.rs` + `ctap/status_code.rs` (status),
`ble_nimble.rs` (coex `USB > WiFi > BLE`).

Validacao da dona: somente leitura + consistencia (toda opcode citada
existe nas fontes; sem links quebrados). Rollback: deletar este arquivo.

______________________________________________________________________

## 0. Mapa rapido (o que o app precisa suportar)

| Dominio | Transporte | Opcode / rota | Gate | Resposta util |
|---|---|---|---|---|
| Descoberta/identificacao | BLE / USB / serial / WiFi | scan, `CMD_INIT 0x86`, GetInfo `0x04`, `read-mac` | nenhum | MAC, CID, CBOR GetInfo, SSID, mDNS |
| Pareamento serial | serial 115200 | hold BOOT 5 s, janela 60 s, menu 9 | fisico | janela local `pairing_until` |
| Vinculo BLE/WiFi | BLE `FFF1` | `0x28` claim, `0x29` challenge, `0x2A` verify, `0x2B` release | janela + UP + prova | NVS `app_bind_pub` + `app_bind_id` |
| Ciclo de vida | BLE `FFF1` | `0x2C` set, `0x2D` unlock (8 tentativas) | UP + PIN 4-6 | wipe + re-claim livre |
| FIDO CTAP | todos via `CMD_CBOR 0x90` / `MSG 0x83` / `POST /ctap` | `0x01` MC, `0x02` GA, `0x04` GI, `0x06` PIN | pairing / UP / PIN | `0x00 + CBOR` |
| Wallet | todos via `CMD_MSG 0x83` | `0x35` GEN, `0x36` LIST, `0x37` ADDR | binding + UP | TLV `01/02/07/08` |
| OATH | BLE/serial/USB + HTTP | `0x24-0x27` + `GET /oath/code` | escrita: binding+UP+PIN; leitura: so UP | codigo 6-8 digitos; segredo nunca sai |
| Vendor KEY | todos via `CMD_MSG 0x83` | `0x20` GEN, `0x21` IMPORT, `0x22` LIST, `0x23` DELETE | leitura: UP; escrita: binding+UP+PIN | `0x00 + TLV` |
| PIV enroll | BLE `FFF1` | `0x39` | pairing + UP, sem PIN | enroll inicial |
| Rescue | todos via `CMD_MSG 0x83` | `0x2E` + frame `RESC` | UP + PIN-UV por comando | frame `RESC 01 cmd len payload` |
| fw-log | todos via `CMD_MSG 0x83` | `0x38` | serial fisico livre; BLE: vinculo | `0x00 + ASCII`, max 512 B |
| WiFi mgmt | HTTP AP | `POST /config/wifi` | binding + UP + PIN | `200` ok, senha 8-63 ASCII |
| OTA | -- | `0x30-0x34` + `0x2F` reservado | NAO USAR (UNMAPPED secao 8) | -- |

Ordem canonica de gates (sempre): `binding -> UP -> PIN`.
O app deve exibir o primeiro gate que falhar nessa ordem.

______________________________________________________________________

## 1. Descoberta e conexao por transporte

### 1.1 BLE (principal para o app movel)

- Scan: procurar Service UUID `0xFFFD`. Advertising carrega
  `[len=2][type=0x01][0x06]` + `[03 03 FD FF]` + svc-data com flag de
  pairing (`ble_nimble.rs`): `0x01` = janela aberta, `0x00` = fechada.
- Servico FIDO: `0xFFFD`. Chars:
  `FFF1` control/write, `FFF2` status/notify (`0` idle, `1` processing,
  `2` up-needed), `FFF3` len/read (`u16 BE`, `0` = idle),
  `FFF4` revision/read-write (so aceita `0x01`, `GATT_REVISION`).
- Framing FFF1: primeiro frag
  `[opcode:1 | len_hi:1 | len_lo:1 | dados...]`,
  continuacao `[seq:1 | dados...]`.
  `MAX_FRAGMENT_BYTES 244`, `CONTROL_POINT_LENGTH 512` (teto BLE).
  Colisao = `TransactionBusy`; envie `CANCEL 0xBE` (`[BE 00 00]`) primeiro.
- Proximidade usa servico separado `0xFFFE` (nunca `FFF1-FFF4`).
- Identificacao: apos conectar, ler `FFF4` (esperar `0x01`), assinar
  `FFF2` notify, fazer `PING 0x81` (`81 len_hi len_lo <bytes>`) e
  conferir eco. Depois GetInfo via `MSG 0x83` (secao 3).

### 1.2 USB HID nativo (VID 0x303A / PID 0xAE61)

- Report de 64 B com Report ID `0x00` prefixado no `hidapi` (65 B no fio).
- Sem texto entrelacado: troca binaria direta.
- `CMD_INIT 0x86` com nonce de 8 B aloca CID (`connect_usb()` ->
  `CID_ALLOCATED`). Usage `0xF1D0`.
- Mesmo framing e mesmos comandos do serial (secao 1.3), mais
  `CMD_LOCK 0x84` e `CMD_ERROR 0xBF`.
  Erros: `0x01` invalid-cmd, `0x02` invalid-par, `0x03` invalid-len,
  `0x04` invalid-seq, `0x05` timeout, `0x06` busy, `0x0A` lock,
  `0x0B` invalid-channel, `0x7F` other.
- Faixa CTAPHID vendor `0xC0-0xFF` e reservada do transporte, nao
  confundir com app `0x20-0x27`.
- Diferenca critica: `0x05 NEED_BINDING` NUNCA aparece no USB
  (posse do cabo = vinculo). Nao pedir claim no USB.

### 1.3 Serial UART (115200, lab e debug)

- 115200 bps. Framing CTAPHID 64 B identico ao USB:
  `INIT [CID:4 BE | CMD:1 (bit7=1) | LEN:2 BE | 57 B]`
  + `CONT [CID:4 BE | SEQ:1 | 59 B]`. Teto `7609 B` (`57 + 128x59`).
- Texto (heartbeat/log `\n`) e drenado por `SerialStreamReader`;
  binario com CID errado dispara resync ancorado no CID
  (`RESYNC_SCAN_MAX 4096 B`). Porta padrao `COM7` ou `AEGIS_PORT`.
- Fluxo: menu 0 scan, menu 1 connect, `cmd_init()` guarda `cid`.
  Keepalive `0xBB`: `0x01` processing, `0x02` up-needed
  (toast "pressione BOOT ate 25 s").
- `CMD_CBOR 0x90` + CTAP `0x04/0x01/0x02/0x06` (secao 3).
- `CMD_MSG 0x83` + `0x20-0x27/0x35-0x37/0x2E/0x38/0x28-0x2D/0x39`.

### 1.4 WiFi AP + mDNS

- Base `http://192.168.4.1`. SSID `AegisKey-XXXX` (sufixo do serial).
  mDNS `aegiskey-XXXX.local` (fora do pareamento, com fallback AP).
- Senha AP: 8-63 ASCII (`wifi_password_valid`). Validar no app antes
  de enviar (curta/longa/nao-ASCII = erro local).
- Rotas (unicas): `POST /ctap`, `POST /config/wifi`,
  `GET /oath/code?account=<nome>`.
- `POST /ctap`: `Content-Type: application/octet-stream`, envelope
  AEGN v1 `AEGN(4) | 01(1) | nonce(12) | ct+tag` (min 33 B).
  Envelope ruim = `InvalidEnvelope`. Resposta = CBOR/CTAP pelo
  `CtapService` conforme op interno.
- Identificacao: apos associar, chamar `GET /oath/code` conhecido ou
  `POST /ctap` com GetInfo para confirmar o device antes de mgmt.

### 1.5 Identificacao (todos os transportes)

1. MAC (somente leitura, runtime): `esptool --port <porta> read_mac`
   (`transport.resolve_mac()`). Nunca hardcodar.
2. USB: VID/PID + `CMD_INIT` -> CID.
3. BLE: `FFF4 == 0x01` + `PING` eco.
4. GetInfo canonico (`ctap/info.rs`): `CMD_CBOR 0x90` + `0x04` vazio.
   Resposta `0x00 + CBOR` com:
   `1` versions `["FIDO_2_0","FIDO_2_1","FIDO_2_1_PRE","U2F_V2"]`,
   `2` extensions `["credProtect","hmac-secret","credBlob","largeBlobs",...]`,
   `4` options (`uv`, `pinUvAuthToken`, `largeBlobs=true`,
   `credMgmt=true`, ...), `6` pinUvProtocols `[1,2]`,
   `9` transports `["usb","nfc"]`, mais `pin_set`, `min_pin_length`,
   `force_pin_change`.
5. Capabilities: derivar do GetInfo + gates locais. Nao exibir opcao
   que o transporte nao suporta (ex.: claim no USB).

______________________________________________________________________

## 2. Pareamento e ciclo de vida do vinculo

### 2.1 Pareamento serial/USB (posse do cabo)

- Segurar BOOT 5 s (`LONG_PRESS_MS=5000`) abre 60 s
  (`PAIRING_WINDOW_SECS`). Host rastreia localmente (menu 9,
  `Session.confirm_pairing()` -> `pairing_until`).
- Expirou = `PermissionError` / `GATE_PAIRING_DENIED` no host.
- Afeta (serial): `make_credential`, `pin_set`/`pin_change`,
  vendor escrita `0x20/0x21/0x23/0x24/0x27`
  (`serial_requires_pairing`). Leitura (`0x22/0x25/0x26`,
  GetInfo, GetAssertion) nao exige pairing.
- Lab (nunca em release): `TEST_PAIRING_OPEN` abre 60 s locais
  (`source=software`), `TEST_UP` injeta 1 tap, `TEST_LIFETIME_DUMP`
  retorna contadores. So com firmware `test-mode`.

### 2.2 Vinculo BLE/WiFi (claim / challenge / verify, 0x28-0x2D)

| Op | Nome | Payload | Gate | Resposta |
|---|---|---|---|---|
| `0x28` | BIND_CLAIM | `app_pub SEC1 65 B + binding_id 16 B` = 81 B | `Unclaimed` + janela pairing + UP + pubkey valida; persiste NVS + verify-after-write | primeiro dono ok; segundo claim nega |
| `0x29` | BIND_CHALLENGE | req 0 B | `Claimed` (senao `0x05`) | 32 B TRNG; invalida o anterior (so ultimo vale) |
| `0x2A` | BIND_VERIFY | `op(1) + challenge(32) + payload_hash(32) + sig(var)` | prova cripto, uso unico | helper de diagnostico |
| `0x2B` | BIND_RELEASE | `challenge(32) + payload_hash(32) + sig(var)` | UP + prova (`challenge + 0x52 + sha256(binding_id)`); `test-mode` = bypass + wipe direto | wipe NVS+RAM, re-claim livre |
| `0x2C` | RECOVERY_SET | ASCII 4-6 digitos | UP (+ PIN valido) | define PIN de resgate |
| `0x2D` | RECOVERY_UNLOCK | ASCII 4-6 digitos | UP + PIN | wipe do vinculo + re-claim |

Fluxo do app (BLE):
1. Checar `Unclaimed` (qualquer op retorna `0x05 NEED_BINDING`).
2. Pedir hold 5 s no BOOT (ou janela aberta no advertising).
3. `0x28` claim com pubkey gerada no app + `binding_id` aleatorio 16 B.
4. Para ops sensiveis futuras: `0x29` -> assinar -> `0x2A` (quando exigido).
5. Definir recovery logo apos o claim (`0x2C`), com UP.

### 2.3 Ciclo de vida e recovery (8 tentativas / wipe)

- Recovery PIN: 4-6 digitos ASCII (`RECOVERY_PIN_MIN_LEN/MAX_LEN`).
  Hash `SHA-256(salt || pin)` + salt 16 B TRNG em NVS
  (`rec_pin_hash/salt/retries`), verify-after-write. Segredo nunca sai.
- 8 tentativas persistidas (`RECOVERY_MAX_RETRIES`,
  `rec_pin_retries`). Erro consome 1; sucesso reseta para 8.
  Esgotou = `Locked` (so `factory_reset` fisico recupera).
- `RECOVERY_UNLOCK` com UP + PIN certo = wipe do `BindingManager`
  (volta a `Unclaimed`, NVS de binding limpa, RAM zerada) e libera
  re-claim. PIN de recovery e preservado ate o novo dono definir outro.
- `BIND_RELEASE` com prova = mesmo wipe. `recovery.wipe_recovery_pin`
  apaga a tripla (troca de dono com wipe completo).
- `recovery.rs` nunca emite `0x05` (resgate fisico+PIN, nao gate de dono).
- App deve: mostrar tentativas restantes, exigir UP antes do PIN,
  apos unlock guiar para novo claim + novo `0x2C`.

______________________________________________________________________

## 3. Controle: matriz operacao -> transporte -> opcode -> payload -> gate

Canonica: `binding -> UP -> PIN`. USO nunca exige vinculo.
`USB/CTAP nunca ve NEED_BINDING`.
UP fisico: latch 1,5 s, single-shot, um por operacao.

### 3.1 FIDO CTAP (todos os transportes)

| Operacao | Transporte/endpoint | Opcode | Payload | Gate | Resposta / retry |
|---|---|---|---|---|---|
| GetInfo | serial/USB `CMD_CBOR 0x90`; BLE `FFF1+MSG 0x83`; HTTP `POST /ctap` | CTAP `0x04` | CBOR vazio (`04`) | nenhum | `0x00 + CBOR`; erro de envelope = corrigir e reenviar 1x |
| MakeCredential | mesmos | CTAP `0x01` | `01 + CBOR` (rp/user) | serial: pairing 60 s + UP device; BLE: binding+UP | keepalive `0x02` = pedir UP (ate 25 s); timeout = nova operacao |
| GetAssertion | mesmos | CTAP `0x02` | `02 + CBOR` (allowList) | UP device | mesmo retry do MC |
| ClientPIN getRetries | mesmos | CTAP `0x06` | `06 A2 01 01` (`{1:1,2:1}`) | verify sem pairing; `pin_set/pin_change` exigem pairing | retries esgotados = trocar PIN, nao retry cego |
| Cancel | serial/USB CTAPHID; BLE `FFF1` | `0xBE` (`CMD_CANCEL 0xBE|0x80` no fio) | vazio / `[BE 00 00]` no BLE | nenhum | aborta transacao; reopen seavel |

### 3.2 Wallet 0x35-0x37 (GEN/LIST/ADDR)

TLV: `0x01` slot, `0x02` label 1-32 B, `0x08` network, `0x07` address (resp).

| Op | Transporte | Payload | Gate | Resposta / retry |
|---|---|---|---|---|
| `0x35` WALLET_GEN | `CMD_MSG 0x83` / `FFF1+MSG` | `[35 + TLV(01 slot, 02 label, 08 network)]`; builder `ops.wallet_gen(slot,label,network)`; vetor congelado `01 01 03 02 03 627463 08 01 01` | binding + UP (sem PIN) | `0x00` ok; `0x01` = pedir UP; `0x03` = slot ocupado (escolher outro, nao retry) |
| `0x36` WALLET_LIST | mesmos | `[36]` (`ops.wallet_list_req()` = vazio) | binding + UP; so metadados `wallet:` | `0x00 + TLV`; `0x05` = fazer claim |
| `0x37` WALLET_ADDR | mesmos | `[37 + TLV(01 slot)]` (`ops.wallet_addr_req(s)`) | binding + UP | `0x00 + TLV(07 address)`; so pubkey/address sai |

### 3.3 OATH (0x24-0x27 + HTTP)

| Op | Transporte | Payload | Gate | Resposta / retry |
|---|---|---|---|---|
| `0x24` OATH_PUT | `CMD_MSG 0x83` / `FFF1+MSG` | `[24 + TLV(71 name, ...secret)]` | CONFIG + PIN: binding+UP+PIN | `0x00`; `0x02` = pedir PIN |
| `0x25` OATH_LIST | mesmos | `[25]` vazio | USO: so UP | `0x00 + TLV(71 names)` |
| `0x26` OATH_CODE | mesmos + `GET /oath/code?account=<nome>` | `[26 + TLV(71 name)]` / query URL-encoded, `<=128`, nao-vazio | USO: so UP; HTTP `401` = sem UP, `404` = conta desconhecida | codigo 6-8 digitos + `remaining_seconds`; segredo nunca sai |
| `0x27` OATH_DELETE | mesmos | `[27 + TLV(71 name)]` | CONFIG + PIN: binding+UP+PIN | `0x00` |
| WiFi code | `GET /oath/code` | query `account=` | so UP (binding ignorado de proposito) | mesmo da linha 0x26 |

### 3.4 Vendor KEY 0x20-0x23

| Op | Payload | Gate |
|---|---|---|
| `0x20` KEY_GEN | `[20 + TLV(01 slot, 02 label<=32B, 05 alg i32BE, 06 usage!=0)]`; `ops.vendor_key_gen(s,label,alg,usage)`; vetor `01 01 08 02 06 <6B> 05 04 <i32BE> 06 01 <u>` | CONFIG: binding+UP (bypass `test-mode`+ltrace; release exige vinculo) |
| `0x21` KEY_IMPORT | `[21 + envelope AEGN + vault]` | CONFIG + PIN: binding+UP+PIN; gate ok = `0x04` (executor on-device = follow-up) |
| `0x22` KEY_LIST | `[22]` vazio | USO: so UP, nunca vinculo |
| `0x23` KEY_DELETE | `[23 + TLV(01 slot)]` (`ops.vendor_slot_only(s)`) | CONFIG + PIN: binding+UP+PIN |

### 3.5 Vendor OATH repetido para clareza (0x24-0x27)

Mesmo da secao 3.3. Privilegiadas `0x21/0x23/0x24/0x27` exigem PIN;
`0x20/0x22/0x25/0x26` exigem binding+UP (GEN/LIST/CODE sem PIN).

### 3.6 PIV 0x39 (enroll inicial)

- `[39 + pin_len(1) + pin(6-8) + puk(8)]` via `FFF1+MSG 0x83`.
- Gate: pairing + UP, sem PIN (PIN ainda nao existe). Fora da faixa
  `0x20-0x27`. PIV CCID/APDU completo e UNMAPPED (secao 8).

### 3.7 Rescue 0x2E

- Frame `RESC|01|cmd|lenBE|payload` (`ops.rescue_frame(cmd,payload)`),
  ex.: `rescue_frame(0x06, b"\x01\x02")` = `52455343 01 06 0002 0102`.
- Viaja como payload de `OP_MSG`, nunca como opcode de fragmento.
- Gate: UP do latch + PIN-UV conforme comando rescue interno.
- Killswitch `cmd 0x06` / wipe token existe no firmware mas sem comando
  de app alem do builder (UNMAPPED parcial).

### 3.8 fw-log 0x38 + diagnostico

- Req `[38]` vazio (`ops.fw_log_req()`). Resp `0x00 + ASCII`,
  `FW_LOG_MAX_BYTES 512`, anel `64x16 B` em RAM (perde no reboot,
  `EV_BOOT` marca o zero). So codigos, sem PII.
- Gates: serial fisico = livre (posse do cabo); BLE = vinculo, sem
  UP/PIN (`NeedBinding 0x05` sem bond).
- Eventos: `01` boot, `02/03` adv start/stop, `04/05` pair open/close,
  `06` bond-ok, `09/0A` op-rx/resp, `0B/0C` up-needed/ok, `0D` wallet,
  `0E` rescue, `0F` OTA, `10` err, `11` adv-nomem.

### 3.9 OTA 0x30-0x34 -- NAO USAR

Sem builder em `host_sdk/ops.py`, sem menu no simulador.
App nao deve enviar. Ver secao 8.

______________________________________________________________________

## 4. Geracao e uso (MC/GA, wallet addr, CODE)

- MC/GA com UP latch: ao receber keepalive `0x01` processing mostre
  progresso; ao receber `0x02` up-needed mostre "pressione BOOT ate
  25 s". Latch e single-shot: um UP vale uma operacao; nova operacao
  = novo UP. `control_write` exige `presence_confirmed`.
- Wallet: GEN cria sob a curva da rede; ADDR retorna so TLV `0x07`
  (address/pubkey). Nenhuma chave privada sai do device. LIST retorna
  so metadados `wallet:` (slot/label/network), nunca segredo.
- OATH CODE: calculo no device; so o codigo 6-8 digitos sai
  (HTTP JSON `{"account","code","remaining_seconds"}` ou TLV `0x75`).
  Validar formato no app: so digitos, 6-8 chars. Secret nunca sai.
- Segredo nunca sai: OATH secret, chave privada wallet/vendor, salt/hash
  de recovery, `SecureStorage` e telas seguem a regra
  "codigo/metadado sai, segredo nao". Log sanitizado: so nomes de
  evento + contagens/bytes (`SanitizedLog` / `log_event`).
- Display-only: `CODE` e `address` sao para exibir/copiar, nao para
  editar no app. Label 1-32 B validado antes do fio
  (`_check_label`); senha WiFi 8-63 ASCII validada antes do fio.

______________________________________________________________________

## 5. Erros fail-closed e politica de retry

### 5.1 Status vendor (-byte, `to_vendor_status`, `key_manager.rs`)

| Byte | Nome | Significado | Politica do app |
|---|---|---|---|
| `0x00` | OK | sucesso | consumir resposta |
| `0x01` | NEED_UP | UP ausente | pedir 1 tap BOOT (latch 1,5 s), reenviar 1x |
| `0x02` | NEED_PIN | PIN ausente/errado | pedir PIN, reenviar 1x; recovery consome 1 de 8 por erro |
| `0x03` | NO_SLOT | sem slot / ocupado | NAO retry; pedir outro slot ou LIST primeiro |
| `0x04` | BAD_ENVELOPE | falha generica (envelope, coex `CoexBlocked`, notify excedente, executor follow-up) | NAO retry cego; corrigir envelope/coex e tentar 1x |
| `0x05` | NEED_BINDING | sem vinculo (so BLE/WiFi, nunca USB) | guiar para claim (secao 2.2); nunca no USB |

### 5.2 CTAP1/CTAPHID (nao confundir com vendor)

- CTAP (`ctap/status_code.rs`): `0x00` Success, `0x01` InvalidCommand,
  `0x02` InvalidParameter, `0x03` InvalidLength, `0x04` InvalidSeq
  (erro CTAPHID `ERR_INVALID_SEQ`, nao vendor `0x04`), `0x05` Timeout,
  `0x06` ChannelBusy. Timeout = nova operacao, nao replay cego.
- CTAPHID keepalive (`transport.py`/`serial_ctaphid.rs`): os mesmos
  `0x01/0x02` da secao 4.
- Fail-closed: zeros negam (chave OTA zerada em release),
  `None` sem stack, `Locked` so via `confirm_lock`,
  `6D 00` honesto fora do escopo CCID, notify excedente vira
  `[op, 0x04]` sem vazar prefixo truncado.
- Regra de retry: so `0x01` (UP) e `0x02` (PIN) tem retry 1x apos acao
  do usuario. `0x03/0x04/0x05`, CTAP `0x01-0x04/0x06`, HTTP
  `400/404` nao tem retry. HTTP `401` = pedir UP/PIN e reenviar 1x.
  Expirou pairing = reabrir janela, nao repetir o POST.

______________________________________________________________________

## 6. Regras de sessao (1 sessao / fase, coex, tetos)

- 1 sessao/fase: `Session` tem um `link` + um `cid` por vez.
  `close()` (menu 1 trocar) + `connect()` zeram estado.
  Reopen = reset: novo `CMD_INIT 0x86` -> novo CID; `CANCEL 0xBE`
  antes de abandonar transacao BLE; `Reassembler.reset()` no host.
- Coex `USB > WiFi > BLE`: USB ativo veta BLE-proximidade
  (`CoexBlocked -> 0x04`); WiFi ativo desacelera advertising BLE.
  App: se USB conectado, nao oferecer fluxo BLE; se AP ativo, avisar
  que scan BLE fica lento.
- Tetos: CTAPHID/USB/serial ate `7609 B`; BLE control-point `512 B`.
  `notify_frame` acima de 512 vira `[op, 0x04]`. Fatiar em frags
  `<=244 B`. TLV usa BER short/long (`<0x80` direto, `0x81`+1B,
  `0x82`+2B; `0x80`/reservados rejeitados; overrun/truncacao = erro).
- Janela pairing 60 s rastreada no host (`pairing_until`); UP latch
  1,5 s single-shot por operacao; challenge BLE 32 B so ultimo vale.
- Sessao HTTP e stateless por rota, mas gates sao por operacao:
  cada `POST /config/wifi` e `GET /oath/code` reavalia
  binding/UP/PIN. Nao cachear "autenticado".

______________________________________________________________________

## 7. Mapeamento host_sdk + menus do simulador

### 7.1 Qual funcao para cada chamada

| Chamada do app | host_sdk | Simulador |
|---|---|---|
| Scan serial | -- (pyserial no app) | menu 0 |
| Connect serial 115200 | `transport.resolve_port()` + `SerialLink` | menu 1 (`Session.connect(port,baud)`) |
| Connect USB HID | `HidLink(VID 0x303A, PID 0xAE61)` | `Session.connect_usb()` |
| Alocar CID | `transport.frame_message(cid, CMD_INIT 0x86, nonce8)` | `Session.cmd_init()` |
| GetInfo | `transport.exchange_ctaphid(link,cid,CMD_CBOR 0x90,b"\x04",op="get_info")` | menu 2 |
| MakeCredential | mesmo com `b"\x01"+cbor`, `op="make_credential"` + `gates.check_pairing_window()` | menu 3 (priv) |
| GetAssertion | mesmo com `b"\x02"+cbor`, `op="get_assertion"` | menu 4 |
| ClientPIN | mesmo com `b"\x06"+cbor`, `op` conforme `pin_set/pin_change/verify` | menu 5 |
| Vendor KEY/OATH raw | `ops.wrap_op(op, body)` + `tlv.write_tlv/parse_tlv` + `exchange_ctaphid(CMD_MSG 0x83)` | menu 7 (priv p/ escrita) |
| KEY_GEN body | `ops.vendor_key_gen(slot,label,alg,usage)` | menu 7 `KEY_GEN` |
| KEY_LIST/DELETE | `ops.wallet_list_req()`-like vazio / `ops.vendor_slot_only(s)` | menu 7 |
| Wallet GEN/ADDR | `ops.wallet_gen / wallet_addr_req / wallet_list_req` + `wrap_op(0x35/0x36/0x37)` | menu 7 (via raw; sem menu proprio) |
| OATH CODE (serial) | `wrap_op(0x26, TLV 0x71)` | menu 7; HTTP prefere menu 6 |
| OATH CODE (HTTP) | `transport.oath_code(ap_base, account)` | menu 6 (`Session.oath_code()`) |
| WiFi config | `transport.http_post(ap,"/config/wifi",senha,"text/plain")` + `gates` priv | menu 8 (`Session.wifi_config()`, valida 8-63 antes) |
| CTAP sobre HTTP | `transport.http_post(ap,"/ctap",envelope,"application/octet-stream")` | `Session.ctap_http(envelope_hex)` |
| Rescue frame | `ops.rescue_frame(cmd,payload)` + `wrap_op(0x2E, frame)` | menu 7 raw |
| fw-log | `ops.fw_log_req()` + `wrap_op(0x38, b"")` + `gates.authorize_fw_log(bonded)` | menu 7 raw |
| PIV enroll | `bytes([0x39,pin_len])+pin+puk` via `MSG 0x83` | menu 7 raw (BLE) |
| Bind claim/challenge/verify/release | `wrap_op(0x28/0x29/0x2A/0x2B, ...)` | menu 7 raw (BLE) |
| Recovery set/unlock | `wrap_op(0x2C/0x2D, pin_ascii)` | menu 7 raw (BLE) |
| Pairing confirm | `Session.confirm_pairing()` (janela local 60 s) | menu 9 |
| Diagnostico lab | `send_text_line("TEST_LIFETIME_DUMP"/"TEST_PAIRING_OPEN"/"TEST_UP")` | menus 10/11 (`--test-mode` + fw `test-mode`) |
| OTA builders | `ops.ota_begin/chunk/verify/commit/abort` + `wrap_op(0x30-0x34)` | menu 12 (COMMIT USB-only, nunca executar aqui) |
| CCID/PIV-APDU | `ops.piv_apdu/select_aid/verify_pin` (AID `A0000005272101`) | menu 13 |
| OTP typer | `ops.otp_typer_input` (6-8 digitos, fail-closed) | menu 14 (secret via getpass, nunca no log) |
| Ext rotas 6D00 | `ops.ext_route_status/deny` (`ykman/nitrokey/yubiotp`) | menu 15 |
| Proximidade FFFE | `ops.prox_walkaway/k_prox_begin` (RAM-only) | menu 16 |
| PIV-OpenSC/F4 | `ops.piv_strip_ff/gen_auth/verify_pin` | menu 17 |
| Killswitch builder | `ops.rescue_killswitch_frame("WIPE-ACK")` (exec = ExternalBlocked) | menu 18 (`--confirm WIPE-ACK`) |
| Self-test offline | `cli.py --self-test` (TLV/gates/framing/rescue/vetores) | `app_simulator.py --self-test` |

- `VENDOR_OPS` (menu 7): `0x20 KEY_GEN, 0x21 KEY_IMPORT, 0x22 KEY_LIST,`
  `0x23 KEY_DELETE, 0x24 OATH_PUT, 0x25 OATH_LIST, 0x26 OATH_CODE,`
  `0x27 OATH_DELETE`.
- `PRIVILEGED` (gates host): `make_credential, pin_set, pin_change,`
  `key_gen, key_import, key_delete, oath_put, oath_delete, wifi_config`.
- `VENDOR_PRIVILEGED` (`ops.py`, so decide PIN): subset
  `0x21/0x23/0x24/0x27`.
- Vetores congelados (`cli --self-test`, `--demo`): wallet
  `01 01 03 02 03 627463 08 01 01`; vendor
  `01 01 08 02 06 <6B ascii> 05 04 <i32BE> 06 01 <usage>`.

______________________________________________________________________

## 8. O que o app NAO deve usar ainda (UNMAPPED secao 7 do COMMS-map)

> F3: cada item abaixo tem builder + menu + vetor/gate/HIL no COMMS-map
> secao 7 (MAPPED host). O app NAO envia nada disso ao vivo nesta lane;
> COMMIT/kill/wipe reais = ExternalBlocked (jig+HSM / outra lane).

| Funcionalidade | Onde vive | Regra do app |
|---|---|---|
| OTA `0x30-0x34` + reservado `0x2F` | mapa `ble_gatt.rs` wallet; `ops.ota_*`; menu 12 | NAO enviar; COMMIT USB-only e NUNCA aqui; dono = firmware (OTA) |
| USB CCID / PIV APDUs (fora enroll `0x39`) | `usb/ccid.rs`, `piv.rs`; AID `A0000005272101`; INS `01/02/03/04/A1/A2/A3/A4`; `ops.piv_*`; menu 13 | NAO enviar APDU CCID; app so usa enroll `0x39` via BLE |
| USB keyboard HID (OTP modhex/scancodes) | `usb/keyboard.rs`; `ops.otp_typer_input`; menu 14 | NAO consumir como API; so validar digitos 6-8, sem segredo no log; dono = firmware (OTP) |
| Ykman mgmt / Nitrokey / YubiOTP | `core/otp/ykman.rs`, `nitrokey.rs`, `yubikey_otp.rs`; `ops.ext_route_*`; menu 15 | sem rota de app; responder `6D00` honesto fora de escopo |
| Proximidade `0xFFFE` (K_prox NVS, adv walkaway) | `PROXIMITY_SERVICE_UUID`, `proximity.rs`, `ble_nimble.rs`; `ops.prox_*`; menu 16 | NAO implementar fluxo walkaway; RAM-only, sem NVS aqui; outra lane |
| PIV CCID via OpenSC / F4 | `plans/`, `docs/piv-ble-proximity.md`, `docs/sessao-20-10-f4-ccid-opensc.md`; `ops.piv_strip_ff/gen_auth`; menu 17 | fora do contrato do app terminal; normalizar strip-FF; lane PIV |
| Rescue killswitch `cmd 0x06` / wipe token | `core/otp/rescue.rs` (`RESCUE_CMD_PING`, `EMERGENCY_WIPE_TOKEN`, `KILLSWITCH_ACK`); `ops.rescue_killswitch_frame`; menu 18 | builder SO com `--confirm WIPE-ACK`; kill real = ExternalBlocked (jig+HSM), nunca executar |
| Burn / eFuse / provisionamento | `persistence.rs`, `efuse.rs`, `provision.rs` | NUNCA expor; sem eFuse burn fora de provisionamento |
| `TEST_*` / `source=software` / chaves-dev | `test_hooks.rs`, `scripts/check-release-clean.py` | NUNCA em release; so lab `test-mode` |

______________________________________________________________________

## 9. Checklist de atualizacao do app (ordem sugerida)

1. Descoberta: scan `0xFFFD`, `FFF4==0x01`, `PING` eco, GetInfo, MAC via
   runtime, SSID/mDNS.
2. Sessao: 1 link/CID por vez, reopen=reset, `CANCEL` antes de trocar,
   tetos 7609/512, coex `USB > WiFi > BLE`.
3. Pairing/vinculo: hold 5 s + 60 s (serial) e claim/challenge/verify
   (BLE) + recovery `0x2C` imediato + tentativas/wipe.
4. Gates na ordem `binding -> UP -> PIN` em todo envio; USO so UP.
5. Matriz secao 3 por dominio; builders `ops.*` + `tlv.*` + `gates.*`.
6. Erros secao 5: retry so em `0x01/0x02` apos acao do usuario.
7. Segredos: nunca logar/exibir secret, PIN, chave, salt/hash.
8. Self-test: `cli.py --self-test` + `app_simulator.py --self-test`
   offline antes de plugar hardware.
