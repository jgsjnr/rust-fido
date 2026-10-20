# Teste ponta-a-ponta como usuário — mapa + diário

Script: `tools/e2e_user_test.py` (finge ser o app via serial; hoje COM7/UART,
USB nativo quando plugado). Cada teste tem ID estável; este MD é o estado
retomável: se parar, continue pelo primeiro teste com status `TODO`.

Regras: sem wipe sem confirmação (`--confirm`); UP via `TEST_UP` (firmware
diag test-mode); janela via `TEST_PAIRING_OPEN` ou hold físico 5s; abrir a
serial reseta a placa (uma sessão por fase).

## Legenda de status

`TODO` não rodado · `PASS` respondeu o esperado · `DIVERGENTE` respondeu
diferente do esperado (analisar, pode ser bug ou expectativa errada) ·
`FAIL` erro de transporte/timeout · `BLOCKED` depende de algo externo ·
`MANUAL` só com dedo no hardware.

## Mapa — tudo que dá para fazer com a chave

### Fase BASE (sem UP, sem janela) — `phase=base`

| ID | Funcionalidade (como usuário) | Op | Esperado | Status |
|---|---|---|---|---|
| T01 | Conectar e alocar canal (INIT) | CTAP INIT | CID novo | PASS |
| T02 | Ping eco (link vivo?) | PING | eco igual | PASS |
| T03 | Info do autenticador (GetInfo) | MSG 0x04 | 0x00 + bytes | PASS |
| T04 | Ler log da firmware | MSG 0x38 | 0x00 + `EV=` | PASS |
| T05 | Listar chaves SEM tocar (gate deve barrar) | MSG 0x22 | 0x01 NEED_UP | PASS |
| T06 | Criar carteira SEM UP/janela (pairing barra) | MSG 0x35 | 0x05 NEED_BINDING | PASS |
| T06b | Criar carteira COM UP sem janela (pairing barra) | MSG 0x35 | 0x05 NEED_BINDING | DIVERGENTE |
| T07 | Rescue lixo sem magic (INVALID_MAGIC) | MSG 0x2E | 0x01 | PASS |
| T07b | Rescue lixo COM UP (mesmo 0x01, magic manda) | MSG 0x2E | 0x01 | DIVERGENTE |
| T07c | Killswitch frame válido sem UP/PIN (nega, sem wipe) | MSG 0x2E | 0x04 | PASS |
| T08 | OTA-BEGIN sem janela (deve negar) | MSG 0x30 | ≠0x00 (anotar) | PASS |
| T09 | Ver tentativas de PIN (leitura, CBOR `a201010201`) | PIN getRetries | 0x00 | PASS |
| T10 | Pedir challenge sem posse (deve negar) | MSG 0x29 | ≠0x00 (anotar) | PASS |

### Com janela + UP (TEST_PAIRING_OPEN + TEST_UP) — `phase=pairing`

| ID | Funcionalidade (como usuário) | Op | Esperado | Status |
|---|---|---|---|---|
| T11 | Abrir janela por software (diag) | TEST_PAIRING_OPEN | `pairing_open` | PASS |
| T12 | Abrir janela produto 0x2F (sem test-mode) | MSG 0x2F | 0x00 | PASS |
| T13 | Criar chave chamada "e2e-t1" | MSG 0x20 s90 | 0x04 (gate-ok, executor=follow-up — confirmar) | PASS |
| T14 | Listar chaves | MSG 0x22 | 0x04 vazio (sem executor — confirmar) | PASS |
| T15 | Guardar segredo OATH "e2e@test" | MSG 0x24 | 0x04 (sem executor — confirmar) | DIVERGENTE |
| T16 | Ver código OATH atual | MSG 0x26 | 0x04 (sem executor — confirmar) | PASS |
| T17 | Criar credencial WebAuthn (rp "e2e") | MC 0x01 + UP | 0x00 + attestation | DIVERGENTE |
| T18 | Entrar com a credencial (assertion) | GA 0x02 + UP | 0x00 + assertion | DIVERGENTE |
| T19 | Criar carteira BTC (slot 6) | MSG 0x35 | 0x00 + endereço | DIVERGENTE |
| T20 | Listar carteiras (tem a 6?) | MSG 0x36 | contém slot 6 | DIVERGENTE |
| T21 | Ver endereço da 6 (bate com T19?) | MSG 0x37 s6 | igual T19 | DIVERGENTE |
| T22 | Criar carteira rede inexistente | MSG 0x35 rede 0x09 | 0x04 BadEnvelope | PASS |

### Destrutivos/mudam estado — só com `--confirm` (`phase=destructive`)

| ID | Funcionalidade | Op | Esperado | Status |
|---|---|---|---|---|
| D01 | Apagar chave (UP+PIN; plumbing gap → 0x02) | MSG 0x23 s5 | 0x02 NEED_PIN | DIVERGENTE |
| D02 | Apagar OATH (UP+PIN; plumbing gap → 0x02) | MSG 0x27 | 0x02 NEED_PIN | DIVERGENTE |
| D03 | Definir PIN "1234" (muda o device!) | setPIN cripto real | 0x00 (0x33 se já tem) | PASS |
| D03b | Sessão PIN viva (getPinToken) | token | 0x00 + token oculto | PASS |
| D04a/b | Trocar PIN 1234→5678→1234 | changePIN | 0x00/0x00 | PASS |
| D05a | Recovery SET 1234 | 0x2C | 0x00 (anotar) | PASS |
| D06 | Reivindicar posse (CLAIM — muda binding!) | 0x28 | 0x00 (0x04 se já claimed) | PASS |
| D06b | Challenge pós-claim | 0x29 | 0x00 + 32B | PASS |
| D07 | Liberar posse (RELEASE = wipe!) | 0x2B | `--confirm-release` + SIM | TODO |
| D05b | Recovery UNLOCK (= wipe!) | 0x2D | `--confirm-release` + SIM | TODO |
| D08 | OTA-BEGIN com janela (stage, SEM commit) | 0x30 | anotar; COMMIT JAMAIS | PASS |

NUNCA no script: killswitch real (jig+HSM), factory_reset físico,
OTA-COMMIT, eFuse.

### Hardware com o dedo — checklist `MANUAL`

| ID | Gesto | Olho em | Status |
|---|---|---|---|
| H1 | Hold BOOT 5s | LED azul respirando + janela 60s | TODO |
| H2 | Tap BOOT | UP (operação pendente destrava) | TODO |
| H3 | Cores | idle ciano / pairing azul / bonded verde / locked vermelho | TODO |
| H4 | Scan BLE na janela | `AegisKey` aparece; fora da janela some | TODO |
| H5 | Bond pelo app no celular + wallet fim-a-fim | GEN/LIST/ADDR + menus controle | TODO |
| H6 | Walk-away (fob) | desconecta longe | TODO |
| H7 | PIV via USB nativo | CCID enumera | TODO |

### USB nativo (quando plugado) — `phase=usb`

| ID | Funcionalidade | Status |
|---|---|---|
| U1 | Enumer HID (VID/PID) | Windows PnP OK (`HID-compliant fido`, fidohid, Problem 0); hidapi cego (ambiente) | PASS |
| U2 | PING + GetInfo via USB | via WebAuthn browser (MC+GA = CTAPHID real; PING/GetInfo raw bloqueados p/ hidapi) | PASS |
| U3 | Re-rodar fases base/pairing via USB (mesmo controle?) | PARCIAL: USB serve CTAP+OTA+rescue+0x2F; vendor/carteira/bind/0x38 só serial/BLE (desenho; ver matriz) | PASS |

## Baseline atual do device (muda com destructive!)

- 20/10 após D-phase: PIN `1234` definido · recovery PIN `1234` · CLAIMED
  (binding NVS) · credencial residente `e2e` no NVS · carteiras s6-s9 na
  RAM (somem no reboot). T10 agora responde `0x00`+32B (era `0x05`).
  Wipes (D07 release, D05b unlock) NÃO executados — aguardam SIM digitado.

## Bugs / divergências

- 20/10 T07 (esclarecido, não é bug): rescue com lixo responde `0x01`
  `INVALID_MAGIC` (rescue.rs), não NEED_UP — o magic manda antes de tudo.
  O `0x04` aparece com frame válido sem UP/PIN (T07c, fail-closed).
- 20/10 T06b (esclarecido, não é bug): com UP e sem janela o esperado é
  `0x05`; se der `0x04`, uma janela residual de sessão anterior ainda está
  aberta (a placa não reseta ao abrir a serial — RAM persiste). Confirmar
  no fw-log (`EV=4` sem `EV=5` depois). Em `all-safe` a base roda antes do
  pairing, então a janela está fechada e o teste é determinístico.
- 20/10 USB (ambiente, não firmware): PnP OK + Problem 0 + WebAuthn
  funcional, mas hidapi/pywinusb não enxergam a coleção (19 outros HIDs
  listados). PING/GetInfo raw via USB ficam p/ depuração futura do host;
  prova funcional via browser vale como U2.
- 20/10 TOOLS (bug real no host, corrigido): `Reassembler` do
  app_simulator limitava resposta em 512 B (teto do BLE) — attestation
  (743 B) entrava em resync infinito e o MC "travava". Teto serial agora
  7609 B (CTAPHID) + buffer 16 KiB. Commit com o fix.
  app_simulator limitava resposta em 512 B (teto do BLE) — attestation
  (743 B) entrava em resync infinito e o MC "travava". Teto serial agora
  7609 B (CTAPHID) + buffer 16 KiB. Commit com o fix.
- 20/10 SCRIPT (bug meu, corrigido): slots 90/91 > `MAX_KEY_SLOTS=32`;
  `user.id` do MC como texto (firmware exige bytes); chave `id` do mapa
  user como inteiro (é texto `"id"`); CBOR getRetries correto
  `a201010201`; T21 sem UP; T19 com slot fixo (placa não reseta — agora
  rotaciona 6..9). Vetores MC/GA gerados pelo ciborium da firmware
  (`crates/aegis-fido-core/tests/e2e_vectors.rs`).
- 20/10 GAP (firmware follow-up, não é bug do teste): ops vendor
  privilegiadas (IMPORT/DELETE/PUT) sempre respondem `0x02` NEED_PIN no
  serial e no BLE — `main.rs`/`serial_ctaphid.rs` passam `pin_authenticated
  = false` fixo (só o rescue tem plumbing ClientPIN). D01/D02/T15 provam
  o gate; o PUT/DELETE real com PIN fica p/ o plumbing. O app vai ver
  `0x02` nessas telas até lá.
- 20/10 T09 (esclarecido, by design): ClientPIN sem subcomando
  (`a10101`) ou CBOR malformado responde `0x30` NOT_ALLOWED — o
  `client_pin_write` é fail-closed (serial_ctaphid.rs). getRetries correto
  é `{1:1, 2:1}` (`a201010201`) → `0x00` + `{3: 8}` (8 tentativas).

## Execuções

(append-only; o script acrescenta um bloco por rodada.)

### 20/10 — USB via browser (tools/usb_webauthn_test.html @ localhost:8137)

- [PASS] U2 MC via USB: `MC OK attBytes=178 credIdBytes=16` (rp localhost, UP no BOOT)
- [PASS] U2 GA via USB: `GA OK authBytes=37 sigBytes=70`
- Nota: attestation menor que no serial (742 B) — navegador negocia formato;
  CTAPHID funcional nos dois transportes.

### 20/10 12:58 — phase=base
- [PASS] T01 INIT aloca CID — cid=0x00020201
- [PASS] T02 PING eco — eco=b'ping-e2e'
- [PASS] T03 GetInfo — status=0x00 bytes=480
- [PASS] T04 FW-LOG serial livre — status=0x00 linhas=4
- [PASS] T05 KEY_LIST sem UP barra — 0x01
- [PASS] T06 WALLET_GEN sem janela barra — 0x05
- [DIVERGENTE] T07 RESCUE lixo nega — recebido=0x01 esperado=0x04
- [PASS] T08 OTA-BEGIN sem janela nega — status=0x01 bytes=0
- [DIVERGENTE] T09 PIN getRetries — status=0x30 body=
- [PASS] T10 BIND_CHALLENGE sem posse nega — status=0x05 (anotar)

### 20/10 12:59 — phase=pairing
- [FAIL] TRANSPORTE erro — pairing-open needs --test-mode (firmware must have test-mode)

### 20/10 13:00 — phase=pairing
- [PASS] T11 janela via TEST_PAIRING_OPEN — pairing_open 60s
- [PASS] T12 trigger 0x2F abre janela — 0x00
- [DIVERGENTE] T07b RESCUE lixo com UP nega 0x04 — status=0x01
- [PASS] T13 KEY_GEN e2e-t1 — status=0x04 (0x04=gate-ok sem executor)
- [PASS] T14 KEY_LIST — status=0x04 bytes=0 (anotar)
- [DIVERGENTE] T15 OATH_PUT e2e@test — status=0x02 (anotar)
- [PASS] T16 OATH_CODE — status=0x04 (anotar)
- [DIVERGENTE] T17 MakeCredential rp e2e — status=0x14 bytes=0
- [DIVERGENTE] T18 GetAssertion rp e2e — status=0x2E bytes=0
- [DIVERGENTE] T19 WALLET_GEN BTC s91 — status=0x04 addr=
- [DIVERGENTE] T20 WALLET_LIST tem s91 — status=0x01 tem91=False
- [DIVERGENTE] T21 WALLET_ADDR bate T19 — igual=
- [PASS] T22 WALLET rede invalida barra — 0x04

### 20/10 13:02 — phase=pairing
- [PASS] T11 janela via TEST_PAIRING_OPEN — pairing_open 60s
- [PASS] T12 trigger 0x2F abre janela — 0x00
- [DIVERGENTE] T07b RESCUE lixo com UP nega 0x04 — status=0x01
- [PASS] T13 KEY_GEN e2e-t1 — status=0x04 (0x04=gate-ok sem executor)
- [PASS] T14 KEY_LIST — status=0x04 bytes=0 (anotar)
- [PASS] T15 OATH_PUT sem PIN pede PIN — status=0x02 (PUT cheio fica p/ após D03)
- [PASS] T16 OATH_CODE — status=0x04 (anotar)
- [DIVERGENTE] T17 MakeCredential rp e2e — status=0x14 bytes=0
- [DIVERGENTE] T18 GetAssertion rp e2e — status=0x2E bytes=0
- [PASS] T19 WALLET_GEN BTC s6 — status=0x00 addr=wallet:e2e-btc*bc1qzsrgzte3wu6kks7
- [PASS] T20 WALLET_LIST tem s6 — status=0x00 tem6=True
- [DIVERGENTE] T21 WALLET_ADDR bate T19 — igual=
- [PASS] T22 WALLET rede invalida barra — 0x04

### 20/10 13:05 — phase=pairing
- [PASS] T11 janela via TEST_PAIRING_OPEN — pairing_open 60s
- [PASS] T12 trigger 0x2F abre janela — 0x00
- [PASS] T07b RESCUE lixo com UP dá INVALID_MAGIC — status=0x01
- [PASS] T07c killswitch sem UP/PIN nega 0x04 (sem wipe) — status=0x04
- [PASS] T13 KEY_GEN e2e-t1 — status=0x04 (0x04=gate-ok sem executor)
- [PASS] T14 KEY_LIST — status=0x04 bytes=0 (anotar)
- [PASS] T15 OATH_PUT sem PIN pede PIN — status=0x02 (PUT cheio fica p/ após D03)
- [PASS] T16 OATH_CODE — status=0x04 (anotar)
- [FAIL] TRANSPORTE erro — serial read timeout (0/1 bytes)

### 20/10 13:06 — phase=pairing only=T17
- [PASS] T11 janela via TEST_PAIRING_OPEN — pairing_open 60s
- [PASS] T12 trigger 0x2F abre janela — 0x00
- [PASS] T07b RESCUE lixo com UP dá INVALID_MAGIC — status=0x01
- [PASS] T07c killswitch sem UP/PIN nega 0x04 (sem wipe) — status=0x04
- [PASS] T13 KEY_GEN e2e-t1 — status=0x04 (0x04=gate-ok sem executor)
- [PASS] T14 KEY_LIST — status=0x04 bytes=0 (anotar)
- [PASS] T15 OATH_PUT sem PIN pede PIN — status=0x02 (PUT cheio fica p/ após D03)
- [PASS] T16 OATH_CODE — status=0x04 (anotar)
- [FAIL] TRANSPORTE erro — serial read timeout (0/1 bytes)

### 20/10 13:08 — phase=base only=T17
- [FAIL] TRANSPORTE erro — serial read timeout (0/1 bytes)

### 20/10 13:09 — phase=base only=T17
- [PASS] T17 MakeCredential rp e2e — status=0x00 bytes=742
- [PASS] T17n MC gravou residente (persiste no NVS!) — credencial e2e criada

### 20/10 13:09 — phase=pairing
- [PASS] T11 janela via TEST_PAIRING_OPEN — pairing_open 60s
- [PASS] T12 trigger 0x2F abre janela — 0x00
- [PASS] T07b RESCUE lixo com UP dá INVALID_MAGIC — status=0x01
- [PASS] T07c killswitch sem UP/PIN nega 0x04 (sem wipe) — status=0x04
- [PASS] T13 KEY_GEN e2e-t1 — status=0x04 (0x04=gate-ok sem executor)
- [PASS] T14 KEY_LIST — status=0x04 bytes=0 (anotar)
- [PASS] T15 OATH_PUT sem PIN pede PIN — status=0x02 (PUT cheio fica p/ após D03)
- [PASS] T16 OATH_CODE — status=0x04 (anotar)
- [PASS] T17 MakeCredential rp e2e — status=0x00 bytes=744
- [PASS] T17n MC gravou residente (persiste no NVS!) — credencial e2e criada
- [PASS] T18 GetAssertion rp e2e — status=0x00 bytes=171
- [DIVERGENTE] T19 WALLET_GEN BTC s6 — status=0x03 addr=
- [PASS] T20 WALLET_LIST tem s6 — status=0x00 tem6=True
- [DIVERGENTE] T21 WALLET_ADDR bate T19 — igual=False (rode T19 antes na mesma sessão: WalletStore é RAM)
- [PASS] T22 WALLET rede invalida barra — 0x04

### 20/10 13:09 — phase=pairing
- [PASS] T11 janela via TEST_PAIRING_OPEN — pairing_open 60s
- [PASS] T12 trigger 0x2F abre janela — 0x00
- [PASS] T07b RESCUE lixo com UP dá INVALID_MAGIC — status=0x01
- [PASS] T07c killswitch sem UP/PIN nega 0x04 (sem wipe) — status=0x04
- [PASS] T13 KEY_GEN e2e-t1 — status=0x04 (0x04=gate-ok sem executor)
- [PASS] T14 KEY_LIST — status=0x04 bytes=0 (anotar)
- [PASS] T15 OATH_PUT sem PIN pede PIN — status=0x02 (PUT cheio fica p/ após D03)
- [PASS] T16 OATH_CODE — status=0x04 (anotar)
- [PASS] T17 MakeCredential rp e2e — status=0x00 bytes=744
- [PASS] T17n MC gravou residente (persiste no NVS!) — credencial e2e criada
- [PASS] T18 GetAssertion rp e2e — status=0x00 bytes=170
- [PASS] T19 WALLET_GEN BTC — status=0x00 slot=7 addr=bc1qqqz02frxqjp8uwa2rua0rfy049vczzj8s6afa5
- [PASS] T20 WALLET_LIST tem s7 — status=0x00 tem=True
- [DIVERGENTE] T21 WALLET_ADDR bate T19 — igual=False
- [PASS] T22 WALLET rede invalida barra — 0x04

### 20/10 13:10 — phase=pairing
- [PASS] T11 janela via TEST_PAIRING_OPEN — pairing_open 60s
- [PASS] T12 trigger 0x2F abre janela — 0x00
- [PASS] T07b RESCUE lixo com UP dá INVALID_MAGIC — status=0x01
- [PASS] T07c killswitch sem UP/PIN nega 0x04 (sem wipe) — status=0x04
- [PASS] T13 KEY_GEN e2e-t1 — status=0x04 (0x04=gate-ok sem executor)
- [PASS] T14 KEY_LIST — status=0x04 bytes=0 (anotar)
- [PASS] T15 OATH_PUT sem PIN pede PIN — status=0x02 (PUT cheio fica p/ após D03)
- [PASS] T16 OATH_CODE — status=0x04 (anotar)
- [PASS] T17 MakeCredential rp e2e — status=0x00 bytes=743
- [PASS] T17n MC gravou residente (persiste no NVS!) — credencial e2e criada
- [PASS] T18 GetAssertion rp e2e — status=0x00 bytes=170
- [PASS] T19 WALLET_GEN BTC — status=0x00 slot=8 addr=bc1qpm6eg7jpcuq0mjdezv668dxzyzgn4kfuwa55vv
- [PASS] T20 WALLET_LIST tem s8 — status=0x00 tem=True
- [PASS] T21 WALLET_ADDR bate T19 — igual=True
- [PASS] T22 WALLET rede invalida barra — 0x04

### 20/10 13:10 — phase=base
- [PASS] T01 INIT aloca CID — cid=0x00090201
- [PASS] T02 PING eco — eco=b'ping-e2e'
- [PASS] T03 GetInfo — status=0x00 bytes=480
- [PASS] T04 FW-LOG serial livre — status=0x00 linhas=20
- [PASS] T05 KEY_LIST sem UP barra — 0x01
- [DIVERGENTE] T06 WALLET_GEN sem janela barra — recebido=0x01 esperado=0x05
- [PASS] T07 RESCUE lixo sem magic — 0x01
- [PASS] T08 OTA-BEGIN sem janela nega — status=0x01 bytes=0
- [PASS] T09 PIN getRetries — status=0x00 body=a2030804f4
- [PASS] T10 BIND_CHALLENGE sem posse nega — status=0x05 (anotar)

### 20/10 13:10 — phase=base
- [PASS] T01 INIT aloca CID — cid=0x000A0201
- [PASS] T02 PING eco — eco=b'ping-e2e'
- [PASS] T03 GetInfo — status=0x00 bytes=480
- [PASS] T04 FW-LOG serial livre — status=0x00 linhas=22
- [PASS] T05 KEY_LIST sem UP barra — 0x01
- [DIVERGENTE] T06 WALLET_GEN sem janela barra — recebido=0x01 esperado=0x05
- [PASS] T07 RESCUE lixo sem magic — 0x01
- [PASS] T08 OTA-BEGIN sem janela nega — status=0x01 bytes=0
- [PASS] T09 PIN getRetries — status=0x00 body=a2030804f4
- [PASS] T10 BIND_CHALLENGE sem posse nega — status=0x05 (anotar)

### 20/10 13:11 — phase=base only=T06b
- [DIVERGENTE] T06b WALLET_GEN com UP sem janela barra — recebido=0x04 esperado=0x05

### 20/10 13:12 — phase=all-safe
- [PASS] T01 INIT aloca CID — cid=0x000D0201
- [PASS] T02 PING eco — eco=b'ping-e2e'
- [PASS] T03 GetInfo — status=0x00 bytes=480
- [PASS] T04 FW-LOG serial livre — status=0x00 linhas=30
- [PASS] T05 KEY_LIST sem UP barra — 0x01
- [DIVERGENTE] T06 WALLET_GEN sem UP barra — recebido=0x05 esperado=0x01
- [PASS] T06b WALLET_GEN com UP sem janela barra — 0x05
- [PASS] T07 RESCUE lixo sem magic — 0x01
- [PASS] T08 OTA-BEGIN sem janela nega — status=0x01 bytes=0
- [PASS] T09 PIN getRetries — status=0x00 body=a2030804f4
- [PASS] T10 BIND_CHALLENGE sem posse nega — status=0x05 (anotar)
- [PASS] T11 janela via TEST_PAIRING_OPEN — pairing_open 60s
- [PASS] T12 trigger 0x2F abre janela — 0x00
- [PASS] T07b RESCUE lixo com UP dá INVALID_MAGIC — status=0x01
- [PASS] T07c killswitch sem UP/PIN nega 0x04 (sem wipe) — status=0x04
- [PASS] T13 KEY_GEN e2e-t1 — status=0x04 (0x04=gate-ok sem executor)
- [PASS] T14 KEY_LIST — status=0x04 bytes=0 (anotar)
- [PASS] T15 OATH_PUT sem PIN pede PIN — status=0x02 (PUT cheio fica p/ após D03)
- [PASS] T16 OATH_CODE — status=0x04 (anotar)
- [PASS] T17 MakeCredential rp e2e — status=0x00 bytes=742
- [PASS] T17n MC gravou residente (persiste no NVS!) — credencial e2e criada
- [PASS] T18 GetAssertion rp e2e — status=0x00 bytes=170
- [PASS] T19 WALLET_GEN BTC — status=0x00 slot=9 addr=bc1qpvseh20jraxgz2m3jhse73nx282eu046dyxp0d
- [PASS] T20 WALLET_LIST tem s9 — status=0x00 tem=True
- [PASS] T21 WALLET_ADDR bate T19 — igual=True
- [PASS] T22 WALLET rede invalida barra — 0x04

### 20/10 13:20 — phase=destructive
- [DIVERGENTE] D01 KEY_DELETE s5 — status=0x05
- [DIVERGENTE] D02 OATH_DELETE e2e@test — status=0x05
- [DIVERGENTE] D03 setPIN 1234 (muda o device!) — status=0x30
- [DIVERGENTE] D03b getPinToken 1234 (sessão viva) — status=0x35
- [DIVERGENTE] D04a changePIN 1234->5678 — status=0x30
- [PASS] D05a RECOVERY_SET 1234 — status=0x00
- [DIVERGENTE] D06 CLAIM posse (muda binding!) — status=0x01 id=9849210f
- [DIVERGENTE] D06b CHALLENGE pós-claim dá 32B — status=0x05 bytes=0
- [PASS] D08 OTA-BEGIN com janela (stage, SEM commit) — status=0x01 bytes=0 (serial não tem OTA — só USB; COMMIT JAMAIS)

### 20/10 13:20 — phase=destructive
- [PASS] T11 janela via TEST_PAIRING_OPEN — pairing_open 60s
- [DIVERGENTE] D01 KEY_DELETE s5 — status=0x02
- [DIVERGENTE] D02 OATH_DELETE e2e@test — status=0x02
- [PASS] D03 setPIN 1234 (muda o device!) — status=0x00
- [PASS] D03b getPinToken 1234 (sessão viva) — token 32B (oculto)
- [PASS] D04a changePIN 1234->5678 — status=0x00
- [PASS] D04b changePIN 5678->1234 (volta) — status=0x00 (device fica com 1234)
- [PASS] D05a RECOVERY_SET 1234 — status=0x00
- [PASS] D06 CLAIM posse (muda binding!) — status=0x00 id=5fa0f87d
- [PASS] D06n device agora CLAIMED (NVS) — gates de binding mudam; ver T10
- [PASS] D06b CHALLENGE pós-claim dá 32B — status=0x00 bytes=32
- [PASS] D08 OTA-BEGIN com janela (stage, SEM commit) — status=0x01 bytes=0 (serial não tem OTA — só USB; COMMIT JAMAIS)

### 20/10 13:21 — phase=base
- [PASS] T01 INIT aloca CID — cid=0x000E0201
- [PASS] T02 PING eco — eco=b'ping-e2e'
- [PASS] T03 GetInfo — status=0x00 bytes=480
- [PASS] T04 FW-LOG serial livre — status=0x00 linhas=38
- [PASS] T05 KEY_LIST sem UP barra — 0x01
- [DIVERGENTE] T06 WALLET_GEN sem UP/janela barra — recebido=0x01 (0x01=janela residual aberta)
- [DIVERGENTE] T06b WALLET_GEN com UP sem janela barra — recebido=0x04 esperado=0x05
- [PASS] T07 RESCUE lixo sem magic — 0x01
- [PASS] T08 OTA-BEGIN sem janela nega — status=0x01 bytes=0
- [PASS] T09 PIN getRetries — status=0x00 body=a2030804f4
- [PASS] T10 BIND_CHALLENGE — 0x00+32B (device CLAIMED — ver D06)

### 20/10 13:21 — phase=destructive
- [PASS] T11 janela via TEST_PAIRING_OPEN — pairing_open 60s
- [PASS] D01 KEY_DELETE s5 pede PIN (gap plumbing) — status=0x02
- [PASS] D02 OATH_DELETE pede PIN (gap plumbing) — status=0x02
- [DIVERGENTE] D03 setPIN 1234 (muda o device!) — status=0x33
- [PASS] D03b getPinToken 1234 (sessão viva) — token 32B (oculto)
- [PASS] D04a changePIN 1234->5678 — status=0x00
- [PASS] D04b changePIN 5678->1234 (volta) — status=0x00 (device fica com 1234)
- [PASS] D05a RECOVERY_SET 1234 — status=0x00
- [DIVERGENTE] D06 CLAIM posse (muda binding!) — status=0x04 id=9c443976
- [PASS] D06b CHALLENGE pós-claim dá 32B — status=0x00 bytes=32
- [PASS] D08 OTA-BEGIN com janela (stage, SEM commit) — status=0x01 bytes=0 (serial não tem OTA — só USB; COMMIT JAMAIS)

### 20/10 13:22 — phase=destructive
- [PASS] T11 janela via TEST_PAIRING_OPEN — pairing_open 60s
- [PASS] D01 KEY_DELETE s5 pede PIN (gap plumbing) — status=0x02
- [PASS] D02 OATH_DELETE pede PIN (gap plumbing) — status=0x02
- [PASS] D03 setPIN 1234 (muda o device!) — status=0x33 (já tinha PIN)
- [PASS] D03b getPinToken 1234 (sessão viva) — token 32B (oculto)
- [PASS] D04a changePIN 1234->5678 — status=0x00
- [PASS] D04b changePIN 5678->1234 (volta) — status=0x00 (device fica com 1234)
- [PASS] D05a RECOVERY_SET 1234 — status=0x00
- [PASS] D06 CLAIM posse (muda binding!) — status=0x04 id=0d13152b (já claimed)
- [PASS] D06b CHALLENGE pós-claim dá 32B — status=0x00 bytes=32
- [PASS] D08 OTA-BEGIN com janela (stage, SEM commit) — status=0x01 bytes=0 (serial não tem OTA — só USB; COMMIT JAMAIS)
