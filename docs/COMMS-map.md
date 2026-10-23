# COMMS-map — Fonte única de comunicações do app

> Escopo: mapear TODAS as comunicações que o app (Android / `tools/app_simulator.py` /
> `tools/host_sdk/`) precisa gerar, a partir de fontes só-leitura. Formato normativo:
> tabela transporte → endpoint → opcodes → payload → gate → exemplo.
> Congelado: revisão GATT `0x01`, faixas `0x20-0x27` / `0x28-0x2D` / `0x35-0x37`,
> `0x2E`, `0x38`, `0x39`, serviço `0xFFFD`, status `0x00-0x05`.

Fontes (só-leitura, sem drift):

- `tools/app_simulator.py` — Serial UART CTAPHID 64 B + HTTP AP
  (`POST /ctap`, `POST /config/wifi`, `GET /oath/code`).
- `tools/host_sdk/tlv.py` — TLV canônico (tags wallet `0x01/0x02/0x07/0x08`,
  vendor `0x20-0x27`, rescue `0x2E`, fw-log `0x38`).
- `tools/host_sdk/ops.py` — builders wallet / vendor / rescue / fw-log.
- `tools/host_sdk/transport.py` — framing CTAPHID 64 B + HTTP AP.
- `tools/host_sdk/gates.py` — gates `binding → UP → PIN`.
- `tools/host_sdk/cli.py` — vetores congelados (self-test offline).
- `crates/aegis-fido-firmware/src/ble_gatt.rs` — serviço `0xFFFD`,
  chars `FFF1-FFF4`, opcodes `0x81/0x83/0xBE`, faixas vendor/bind/wallet,
  rescue, fw-log, PIV enroll `0x39`, gates, `0x00-0x05`, coex.
- `crates/aegis-fido-firmware/src/fw_log.rs` — op `0x38`, resposta `0x00 + ASCII`.
- `crates/aegis-fido-firmware/src/wifi_ap.rs` — rotas HTTP + envelope AEGN.
- `crates/aegis-fido-firmware/src/ble_nimble.rs` — coex `USB > WiFi > BLE`.
- `crates/aegis-fido-firmware/src/binding.rs`, `pairing.rs`,
  `lifetime_trace.rs` — `test-mode`, janela 60 s, `TEST_*`.
- `crates/aegis-fido-usb/src/ctaphid.rs` — framing CTAPHID (teto 7609 B).
- `crates/aegis-fido-core/src/credential/key_manager.rs` — status `0x00-0x04`.
- `crates/aegis-fido-core/src/otp/rescue.rs` + `oath/tlv.rs` — `0x2E`.
- `scripts/check-release-clean.py` — prova de ausência `TEST_*` em release.

## 0. Convenções globais (valem para todas as tabelas)

| Assunto | Valor congelado |
|---|---|
| Ordem canônica de gates | `binding → UP → PIN` (app alheio sempre vê `NEED_BINDING` primeiro) |
| Status vendor `§9.5` | `0x00` OK · `0x01` NEED_UP · `0x02` NEED_PIN · `0x03` NO_SLOT · `0x04` BAD_ENVELOPE (falha genérica, sem retry) · `0x05` NEED_BINDING (só BLE/WiFi, **nunca USB**) |
| CTAP1 status (`ctap/status_code.rs`) | `0x00` Success · `0x01` InvalidCommand · `0x02` InvalidParameter · `0x03` InvalidLength · `0x04` InvalidSeq (erro CTAPHID `ERR_INVALID_SEQ`, não confundir com vendor `0x04`) · `0x05` Timeout · `0x06` ChannelBusy |
| CTAPHID keepalive | `0x01` processing · `0x02` up-needed (toast "pressione BOOT até 25 s") |
| CTAPHID teto | `7609 B` (`57 + 128×59`); USB/serial aceitam até aqui; **BLE control-point limita a `512 B`** (`CONTROL_POINT_LENGTH`) |
| Coexistência | `USB > WiFi > BLE`: USB ativo veta BLE-proximidade (`CoexBlocked → 0x04`); WiFi ativo desacelera advertising BLE |
| Janela pairing (serial/host) | hold físico 5 s no BOOT abre **60 s** (`PAIRING_WINDOW_SECS`); host rastreia localmente (menu 9); expirou = `PermissionError` / `GATE_PAIRING_DENIED` |
| UP físico | latch **1,5 s**, single-shot, um por operação (`control_write` exige `presence_confirmed`) |
| Log sanitizado | só nomes de evento + contagens/bytes; nunca payload, label, segredo, PIN (`SanitizedLog` / `log_event`) |
| `TEST_*` | só firmware com feature `test-mode`; **nunca em release** (`scripts/check-release-clean.py` prova ausência de `TEST_LIFETIME_DUMP`, `TEST_PAIRING_OPEN`/`pairing_open`, `TEST_UP`/`up_latched`, `source=software`, chaves-dev) |

## 1. Serial UART — CTAPHID 64 B (`tools/app_simulator.py` + `tools/host_sdk/transport.py`)

Framing: `INIT [CID:4 BE | CMD:1 (bit7=1) | LEN:2 BE | 57 B]`
+ `CONT [CID:4 BE | SEQ:1 | 59 B]`. Texto (heartbeat/log `\n`) é
drenado por `SerialStreamReader`; binário com CID errado dispara resync
ancorado no CID (`RESYNC_SCAN_MAX 4096 B`). Teto `7609 B`.

| Endpoint (cmd CTAPHID) | Opcodes / payload | Payload (bytes) | Gate (host) | Exemplo |
|---|---|---|---|---|
| `CMD_INIT 0x86` (aloca CID) | nonce `8 B` | `nonce` aleatório | nenhum | req `86 … 0008 <nonce>` → resp `[nonce-echo \| new-cid:4 \| …]`; `sess.cmd_init()` guarda `cid` |
| `CMD_PING 0x81` | eco opaco | bytes arbitrários | nenhum | `frame_message(cid, 0x81, b"ping")` → eco idêntico |
| `CMD_WINK 0x88` | — | vazio | nenhum | wink / blink |
| `CMD_CBOR 0x90` + CTAP `0x04` GetInfo | CBOR vazio | `04` | nenhum | `ctap(0x04, "", op="get_info")` → `status 0x00 + CBOR` |
| `CMD_CBOR 0x90` + CTAP `0x01` MakeCredential | CBOR relying-party/usuário | `01 ‖ CBOR` | **pairing 60 s** (`PRIVILEGED` tem `make_credential`) + UP device | `ctap(0x01, "<cbor-hex>", op="make_credential")` |
| `CMD_CBOR 0x90` + CTAP `0x02` GetAssertion | CBOR allowList | `02 ‖ CBOR` | UP device (não-privilegiado no host) | `ctap(0x02, "<cbor-hex>", op="get_assertion")` |
| `CMD_CBOR 0x90` + CTAP `0x06` ClientPIN | CBOR PIN (`{1:1,2:1}` = getRetries) | `06 ‖ CBOR` | `pin_set`/`pin_change` exigem **pairing**; verify não | getRetries dev: `06 a2010102` |
| `CMD_MSG 0x83` + vendor `0x20-0x27` | §2 (KEY/OATH) | `[op:1 ‖ TLV…]` | leitura: sem pairing; escrita: **pairing** + gates §2 | `KEY_LIST`: `83 22` (TLV vazio) |
| `CMD_MSG 0x83` + wallet `0x35/0x36/0x37` | §3 | `[op:1 ‖ TLV…]` | **pairing** + `binding→UP` (§3) | `WALLET_LIST`: `83 36` |
| `CMD_MSG 0x83` + `0x2E` rescue | frame `RESC‖01‖cmd‖len‖payload` | `[2E ‖ rescue-frame]` | UP do latch + PIN-UV conforme comando rescue | `ops.rescue_frame(0x06, b"\x01\x02")` = `52455343 01 06 0002 0102` |
| `CMD_MSG 0x83` + `0x38` fw-log | vazio | `[38]` | serial físico = **livre** (posse do cabo) | `83 38` → `00 + ASCII` (§5) |
| `CMD_CANCEL 0xBE\|0x80` | — | vazio | nenhum | aborta transação pendente |
| Linha texto `TEST_LIFETIME_DUMP\n` | diagnóstico | ASCII + `\n` | `--test-mode` + fw `test-mode` | resp `lt_dump v=1 … lt_end` (contadores, sem segredos) |
| Linha texto `TEST_PAIRING_OPEN\n` | diagnóstico | ASCII + `\n` | `--test-mode` | resp `pairing_open source=software`; host abre 60 s locais |
| Linha texto `TEST_UP\n` | diagnóstico | ASCII + `\n` | `--test-mode` | resp `up_latched source=software` (1 tap, single-shot) |

## 2. USB HID nativo (`tools/app_simulator.py` `HidLink` + `crates/aegis-fido-usb`)

Sem texto entrelaçado (troca binária direta). Report de **64 B**
com **Report ID `0x00` prefixado** no `hidapi` (`65 B` no fio).
Mesmo framing/mesmos comandos §1, mais:

| Endpoint (cmd CTAPHID) | Opcodes / payload | Payload | Gate | Exemplo |
|---|---|---|---|---|
| `CMD_INIT 0x86` | `VID 0x303A / PID 0xAE61`, usage `0xF1D0` | nonce `8 B` | nenhum | `connect_usb()` → `CID_ALLOCATED` |
| `CMD_MSG 0x83` | vendor `0x20-0x27`, wallet `0x35-0x37`, `0x2E`, `0x38`, bind `0x28-0x2D`, PIV `0x39` | `[op:1 ‖ …]` | iguais a BLE/serial, **exceto: `0x05 NEED_BINDING` nunca no USB** (posse do cabo = vínculo) | idênticos a §1/§2/§3 |
| `CMD_CBOR 0x90` | `0x01/0x02/0x04/0x06` | `ctap_cmd ‖ CBOR` | iguais a §1 | idênticos a §1 |
| `CMD_LOCK 0x84` | lock de canal | duração `1 B` | nenhum | `ERR_LOCK_REQUIRED 0x0A` se canal travado |
| `CMD_ERROR 0xBF` / erros | `0x01` invalid-cmd · `0x02` invalid-par · `0x03` invalid-len · `0x04` invalid-seq · `0x05` timeout · `0x06` busy · `0x0A` lock · `0x0B` invalid-channel · `0x7F` other | — | — | `CtapHidError { cid, code }` |
| Vendor `0xC0-0xFF` | faixa CTAPHID vendor (transporte, não confundir com app `0x20-0x27`) | — | — | reservado FIDO |

## 3. BLE GATT `0xFFFD` (`crates/aegis-fido-firmware/src/ble_gatt.rs`)

Serviço `0xFFFD` (proximidade isolada em `0xFFFE`, nunca conflita).
Chars: `FFF1` control/write · `FFF2` status/notify (`0` idle, `1` processing,
`2` up-needed) · `FFF3` len/read (pendente) · `FFF4` revision/read-write
(**só aceita `0x01`**). Framing FFF1: primeiro frag
`[opcode:1 \| len_hi:1 \| len_lo:1 \| dados…]`, continuação `[seq:1 \| dados…]`;
`MAX_FRAGMENT_BYTES 244`, `CONTROL_POINT_LENGTH 512`, colisão rejeitada
(`TransactionBusy`; `CANCEL` primeiro).

| Endpoint (char + opcode) | Opcode app (1º byte de `OP_MSG`) | Payload | Gate (ordens canônicas) | Exemplo |
|---|---|---|---|---|
| `FFF1` + `PING 0x81` | — (eco, sem `CtapEngine`) | bytes opacos ≤ 512 | **UP por operação** (`control_write` exige) | `81 00 05 hello` → notify eco `hello` |
| `FFF1` + `MSG 0x83` + CTAP | CBOR (`04/01/02/06 …`) | `ctap_cmd ‖ CBOR` | CTAP nativo (UP/PIN do engine) | mesmo CBOR do §1, fatiado em frags ≤ 244 B |
| `FFF1` + `MSG 0x83` + `0x20` KEY_GEN | `TLV(01 slot, 02 label≤32B, 05 alg i32BE, 06 usage≠0)` | `[20 ‖ TLV]` | **CONFIG**: `binding→UP` (bypass `test-mode` + ltrace; release exige vínculo) | `ops.vendor_key_gen(8, b"e2e-t1", -7, 0x03)` = `01 01 08 02 06 … 05 04 FFFF… 06 01 03` |
| `FFF1` + `MSG 0x83` + `0x21` KEY_IMPORT | envelope **AEGN** + vault (F2b) | `[21 ‖ envelope]` | **CONFIG + PIN**: `binding→UP→PIN` | gate ok → `0x04` (executor on-device = follow-up) |
| `FFF1` + `MSG 0x83` + `0x22` KEY_LIST | vazio | `[22]` | **USO: só UP**, nunca vínculo | `83-framed 22` → `00 ‖ TLV…` |
| `FFF1` + `MSG 0x83` + `0x23` KEY_DELETE | `TLV(01 slot)` | `[23 ‖ TLV(01)]` | **CONFIG + PIN**: `binding→UP→PIN` | `ops.vendor_slot_only(s)` |
| `FFF1` + `MSG 0x83` + `0x24` OATH_PUT | `TLV(71 name, …secret)` | `[24 ‖ TLV]` | **CONFIG + PIN**: `binding→UP→PIN` | put → `00` |
| `FFF1` + `MSG 0x83` + `0x25` OATH_LIST | vazio | `[25]` | **USO: só UP** | `83-framed 25` → `00 ‖ TLV(71 names…)` |
| `FFF1` + `MSG 0x83` + `0x26` OATH_CODE | `TLV(71 name)` | `[26 ‖ TLV]` | **USO: só UP** | calc no device; só o código sai |
| `FFF1` + `MSG 0x83` + `0x27` OATH_DELETE | `TLV(71 name)` | `[27 ‖ TLV]` | **CONFIG + PIN**: `binding→UP→PIN` | delete → `00` |
| `FFF1` + `MSG 0x83` + `0x35` WALLET_GEN | `TLV(01 slot, 02 label, 08 network)` | `[35 ‖ TLV]` | **binding→UP** (sem PIN nesta faixa) | `ops.wallet_gen(3, b"btc", 0x01)` = `01 01 03 02 03 627463 08 01 01` |
| `FFF1` + `MSG 0x83` + `0x36` WALLET_LIST | vazio | `[36]` | **binding→UP** (só metadados `wallet:`) | `83-framed 36` → `00 ‖ TLV…` |
| `FFF1` + `MSG 0x83` + `0x37` WALLET_ADDR | `TLV(01 slot)` | `[37 ‖ TLV(01)]` | **binding→UP** | `ops.wallet_addr_req(s)` → `00 ‖ TLV(07 address)` |
| `FFF1` + `MSG 0x83` + `0x38` FW-LOG | vazio | `[38]` | **vínculo, sem UP/PIN** (`NeedBinding 0x05` sem bond) | `00 + ASCII` (§5) |
| `FFF1` + `MSG 0x83` + `0x39` PIV_ENROLL | `pin_len(1) ‖ pin(6-8) ‖ puk(8)` | `[39 ‖ …]` | **pairing→UP, sem PIN** (PIN ainda não existe) | enroll inicial F4 |
| `FFF1` + `MSG 0x83` + `0x28` BIND_CLAIM | `app_pub SEC1 65B ‖ binding_id 16B` = 81 B | `[28 ‖ 81B]` | `Unclaimed` + janela pairing + UP + pubkey válida; persiste NVS + verify-after-write | primeiro dono; segundo claim nega |
| `FFF1` + `MSG 0x83` + `0x29` BIND_CHALLENGE | req 0 B → resp 32 B TRNG | `[29]` | `Claimed` (senão `0x05`); invalida anterior (só último vale) | `challenge = dispatch_bind_challenge(…)` |
| `FFF1` + `MSG 0x83` + `0x2A` BIND_VERIFY | `op(1) ‖ challenge(32) ‖ payload_hash(32) ‖ sig(var)` | `[2A ‖ …]` | helper de teste/diagnóstico (cripto válida nos dois modos) | `dispatch_bind_verify(…)` consome uso único |
| `FFF1` + `MSG 0x83` + `0x2B` BIND_RELEASE | `challenge(32) ‖ payload_hash(32) ‖ sig(var)` | `[2B ‖ …]` | UP + prova (`challenge‖0x52‖sha256(binding_id)`); `test-mode` = bypass + wipe direto | sucesso = wipe NVS+RAM, re-claim livre |
| `FFF1` + `MSG 0x83` + `0x2C` RECOVERY_SET | ASCII `4-6` dígitos | `[2C ‖ pin]` | **UP** (+ PIN válido) | `dispatch_recovery_set("4242")` |
| `FFF1` + `MSG 0x83` + `0x2D` RECOVERY_UNLOCK | ASCII `4-6` dígitos | `[2D ‖ pin]` | **UP + PIN** (8 tentativas NVS); sucesso = wipe + re-claim | `dispatch_recovery_unlock(…)` |
| `FFF1` + `MSG 0x83` + `0x2E` rescue | frame `RESC…` | `[2E ‖ rescue-frame]` | UP do latch + PIN-UV conforme comando; viaja como **payload de OP_MSG, nunca opcode de fragmento** | `52455343…` idêntico ao serial |
| `FFF1` + `CANCEL 0xBE` | — | `[BE 00 00]` | nenhum (aborta) | `reassembler.cancel()` + `status=0` |
| `FFF2` notify | keepalive/status | `1 B` | — | `01` processing · `02` up-needed |
| `FFF3` read | tamanho pendente | `u16 BE` (`0` idle) | — | `pending_len()` |
| `FFF4` read/write | revisão | `1 B` (`0x01`; outro valor = `InvalidFragment`) | — | `read_revision` / `write_revision` |
| Serviço `0xFFFE` (proximidade, separado) | K_prox / advertising | svc-data próprio | `bonded→UP→coex` (`usb_active` → `CoexBlocked→0x04`) | nunca usa `FFF1-FFF4` nem `0xFFFD` |

## 4. WiFi AP HTTP (`crates/aegis-fido-firmware/src/wifi_ap.rs` + simulator `Session`)

Base `http://192.168.4.1`. Senha AP `8-63` ASCII (`wifi_password_valid`).

| Endpoint (método + rota) | Content-Type / corpo | Resposta | Gate | Exemplo |
|---|---|---|---|---|
| `POST /ctap` | `application/octet-stream`; envelope **AEGN v1** `AEGN(4) ‖ 01(1) ‖ nonce(12) ‖ ct+tag` (mín. `33 B`; `validate_aegn_envelope` / `validate_ctap_envelope`) | CBOR/CTAP pelo `CtapService` | conforme op interno | `sess.ctap_http("<aegn-hex>")`; envelope ruim → `InvalidEnvelope` |
| `POST /config/wifi` | `text/plain`; senha ASCII `8-63` | `200` ok | **CONFIG mgmt: binding + UP + PIN** (`401` sem UP/PIN) | `sess.wifi_config("nova-senha-123")`; curta/longa/não-ASCII → erro local antes do fio |
| `GET /oath/code?account=<nome>` | query `account=` (≤128, não-vazio, URL-encoded) | JSON `{"account","code":"6-8 dígitos","remaining_seconds":0-30}`; `401` sem presença · `404` conta desconhecida | **USO: só UP** (nunca vínculo; **secret nunca sai**, só o código) | `sess.oath_code("GitHub:alice")` → `("GitHub:alice","287082",28)` |

## 5. TLV canônico (fio idêntico Rust ↔ Python)

BER short/long: `tag(1) ‖ len ‖ valor`; `len<0x80` direto;
`0x81` +1B; `0x82` +2B; `0x80`/reservados rejeitados; overrun/truncação = erro.

| Tag | Nome | Onde | Exemplo |
|---|---|---|---|
| `0x01` | slot (wallet **e** vendor — mesmo valor, contextos distintos: `TAG_WALLET_SLOT`/`TAG_SLOT`) | GEN/ADDR/DELETE | `01 01 03` |
| `0x02` | label (`1-32 B`) | GEN/LIST | `02 03 627463` (`"btc"`) |
| `0x05` | alg-hint (`i32 BE`) | `vendor_key_gen` | `05 04 FFFF…` (`-7`) |
| `0x06` | usage-hint (`≠0`) | `vendor_key_gen` | `06 01 03` |
| `0x07` | address (resposta) | `WALLET_ADDR` resp | `07 …` |
| `0x08` | network | `wallet_gen` req | `08 01 01` |
| `0x71` | OATH name | OATH TLV | `71 …` |
| `0x75` | OATH response | OATH TLV | `75 …` |
| op `0x2E` | rescue-transport (não é tag TLV; é 1º byte de `CMD_MSG`) | serial/BLE/USB | `[2E ‖ RESC…]` |
| op `0x38` | fw-log (idem) | serial/BLE/USB | `[38]` (+ `00+ASCII` na volta) |

Vetores congelados (`cli.py --self-test`): wallet
`01 01 03 02 03 627463 08 01 01`; vendor
`01 01 08 02 06 e2652d7431 05 04 <i32BE> 06 01 03`.

## 6. Diagnóstico fw-log `0x38` (só códigos, sem PII)

Resposta wire `0x00 + ASCII` (`FW_LOG_MAX_BYTES 512`, anel `64×16 B` em RAM,
perde-se no reboot; `EV_BOOT` marca o zero). Eventos:
`01` boot · `02/03` adv start/stop · `04/05` pair open/close · `06` bond-ok ·
`09/0A` op-rx/resp · `0B/0C` up-needed/ok · `0D` wallet · `0E` rescue ·
`0F` OTA · `10` err · `11` adv-nomem.

## 7. UNMAPPED — funcionalidade existe no firmware, sem entrada de app (dono)

> F3 status: builders + menus existem no host; "MAPPED (host)" abaixo
> significa vetor+gate+HIL documentados aqui, sem envio real nesta lane.
> Envio ao vivo so para provar denies (fail-closed); sem stage/commit/
> wipe/provision.

| Funcionalidade | Onde vive | Status | Dono |
|---|---|---|---|
| OTA `0x30-0x34` + reservado `0x2F` | mapa `ble_gatt.rs` wallet (`0x30-0x34` OTA, `0x2F` reservado); builders `tools/host_sdk/ops.py` (`ota_begin/chunk/verify/commit/abort`) | **MAPPED (host)** — builders + menu 12; vetor `ota_begin(1024, 32x00)` + `ota_chunk(0, 01020304)`; gate `binding->UP->PIN`; HIL: deny sem vinculo; **COMMIT USB-only, NUNCA executar aqui** | firmware (OTA) |
| USB CCID / PIV APDUs (fora enroll `0x39`) | `crates/aegis-fido-usb/src/ccid.rs`, `piv.rs`; `core/oath` INS `01/02/03/04/A1/A2/A3/A4`, AID `A0000005272101`; builders `piv_apdu/select_aid/verify_pin` | **MAPPED (host)** — builders + menu 13; vetor `SELECT a0000005272101` (`00A40400 07 ...`); gate `pairing->UP`; sem toque em firmware | firmware (PIV/CCID) |
| USB keyboard HID (OTP modhex/scancodes) | `crates/aegis-fido-usb/src/keyboard.rs`; entrada app `otp_typer_input` | **MAPPED (host)** — validador + menu 14; vetor `287082` ok, `12ab56` deny; so digitos 6-8, fail-closed; segredo nunca no log | firmware (OTP) |
| Ykman mgmt / Nitrokey / YubiOTP | `crates/aegis-fido-core/src/otp/ykman.rs`, `nitrokey.rs`, `yubikey_otp.rs`; `ext_route_status/deny` | **MAPPED (host)** — rotas + menu 15; resposta honesta `6D00` fora de escopo; deny `ExternalBlocked` | firmware (OTP) |
| Proximidade `0xFFFE` (K_prox NVS, adv walkaway) | `ble_gatt.rs` `PROXIMITY_SERVICE_UUID`, `proximity.rs`, `ble_nimble.rs`; builders `prox_walkaway/k_prox_begin` | **MAPPED (host)** — builders + menu 16; vetor `prox_walkaway(60)=003C`; RAM-only, sem NVS aqui; nunca usa `FFF1-FFF4`; gate `bonded->UP->coex` | proximity lane |
| PIV CCID via OpenSC / F4 | `plans/`, `docs/piv-ble-proximity.md`, `docs/sessao-20-10-f4-ccid-opensc.md`; helpers `piv_strip_ff/gen_auth/verify_pin` | **MAPPED (host)** — helpers + menu 17; norma `strip-FF` (trailing `FF` removido); VERIFY 6-8 digitos + GEN AUTH 32B; fora do contrato do app terminal | PIV lane |
| Rescue killswitch `cmd 0x06` / wipe token | `core/otp/rescue.rs` (`RESCUE_CMD_PING`, `EMERGENCY_WIPE_TOKEN`, `KILLSWITCH_ACK`); `rescue_killswitch_frame` | **MAPPED (host)** — builder + menu 18 com `--confirm WIPE-ACK`; vetor `RESC 01 06 ...`; kill real = `ExternalBlocked` (jig+HSM), nunca executar aqui | firmware (rescue) |

## 8. Validação da dona (só leitura + lint)

1. `python tools/app_simulator.py --self-test` (offline, sem hardware).
2. `python tools/host_sdk/cli.py --self-test` (vetores TLV/gates/framing + F3).
3. Markdown lint básico (tabelas com `|` de borda, sem segredos no texto; ASCII puro).
4. Sem flash/COM7 para escrita nesta lane (proibido: sem hardware).
   Leitura ao vivo permitida SO para provar denies (sem stage/commit/wipe).
5. Rollback: `git checkout -- tools/host_sdk/ops.py tools/app_simulator.py docs/COMMS-map.md docs/APP-INTEGRACAO.md`.
