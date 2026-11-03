# CAPABILITY_DIET — presets fido-only / fido-totp (dieta 2 MB)

Fonte da verdade legivel por maquina: `scripts/capability-catalog.json`
(este doc espelha os numeros dele; tabelas geradas do mesmo JSON).
Picker: `scripts/select-capability.ps1` / `scripts/select-capability.sh`
(paridade total; nunca grava flash).

## 1. Presets (raizes alternativas)

`full` = `default` como hoje. `cap-*` exigem
`--no-default-features` e sao mutuamente exclusivas entre si e com
`default` (`compile_error!` em `lib.rs`). Diet recusa por `compile_error!`
as features `proximity`, `debug-terminal`, `test-mode`, `has-display`,
`board-t-display`, `board-ttgo-classic`, `wifi` — dieta e so devkitc/2MB.

| preset | features (cargo) | boards | medido .bin | factory (budget) | status |
|---|---|---|---|---|---|
| full (default como hoje) | board-devkitc (default) | devkitc | 1,81 MiB (1902288 B) | 1.50 MiB (0x180000, 2MB layout) | **OVERFLOW (>1.5MB)** |
| cap-fido-only (CTAP2/HID puro) | board-devkitc,cap-fido-only | devkitc | 1,08 MiB (1128144 B) | 1.50 MiB (0x180000, 2MB layout) | **PASS <= factory** |
| cap-fido-totp (+OATH/TOTP) | board-devkitc,cap-fido-totp | devkitc | 1,19 MiB (1251632 B) | 1.50 MiB (0x180000, 2MB layout) | **PASS <= factory** |

Medicao: `cargo +esp build -p aegis-fido-firmware --target
xtensa-esp32s3-espidf --release --no-default-features --features
<set> -Zbuild-std=std,panic_abort` + `esptool --chip esp32s3 elf2image
--flash_size 4MB` (v5.3.1 shell-local), 2026-11-02. Full nao cabe na
factory 2 MB (motivacao da dieta); dieta passa com margem. Meta
fido-only <= 1.4 MB: PASS (1128144 B). tdisplay/ttgo-classic usam o
layout 16 MB/4 MB (factory 0x300000 = 3 MiB) e nao foram medidos aqui.

## 2. O que entra / o que sai por preset

- fido-only INCLUI: ctap-makecred, ctap-getassert, ctap-clientpin, ccid,
  piv, openpgp, vendor-mgmt (braços wallet/OATH respondem 0x06).
  EXCLUI: oath-totp, oath-hotp, otp-challenge-response, wallet, vault,
  ble (radio inerte), wifi-sntp, display, proximity, debug-terminal,
  test-hooks (comando fora da capability = 0x06 UNSUPPORTED_FEATURE,
  fail-closed, nunca queda silenciosa).
- fido-totp = fido-only + oath-totp, oath-hotp, otp-challenge-response
  (inclui ancora de tempo NVS; OATH via USB/BLE real).
- full = tudo acima + wallet + vault + ble + wifi-sntp + display +
  proximity + debug-terminal + test-hooks.

Comandos indisponiveis num preset respondem `UNSUPPORTED_FEATURE`
(0x06, namespace vendor §9.5); telas TOTP mostram NO_ACCOUNTS sem
codigo falso.

## 3. Como selecionar (picker)

Interativo (menu mostra includes/excludes + orcamento, pede confirmacao):

```
./scripts/select-capability.ps1
./scripts/select-capability.sh
```

Nao-interativo (CI):

```
./scripts/select-capability.ps1 --cap fido-only --board devkitc --release
./scripts/select-capability.sh --cap fido-totp --board devkitc --release
```

Catalogo (gera da mesma fonte JSON):

```
./scripts/select-capability.ps1 --list-caps
./scripts/select-capability.ps1 --list-pools
./scripts/select-capability.sh --list-caps
./scripts/select-capability.sh --list-pools
```

O picker monta o `cargo +esp build` correto por preset+placa
(`--no-default-features --features <board>[,<cap>]`; ttgo preserva
`CARGO_PROFILE_RELEASE_OPT_LEVEL=z`), escolhe o layout de particoes da
placa, converte ELF->.bin via esptool, grava `.sha256` sidecar e compara
com a factory: PASS continua (exit 0), FAIL (overflow) recusa continuar
(exit 1). Tambem confere pools NVS residentes vs storage (WARN, nao
bloqueia) e avisa sobre OTA staging transiente no layout 2 MB. Flash
permanece manual via `scripts/build-*.ps1 -Flash` (exige placa +
aprovacao); o picker nunca grava hardware. Sem toolchain/IDF o picker
sai exit 2 nomeando a peca ausente (EXTERNAL_BLOCKED).
## 4. Catalogo de capabilities (gerado de capability-catalog.json)

Custos flash sao ESTIMATIVAS (modulo-fonte proporcional, calibrado no build full medido de 1902288 B); modulos compartilhados aparecem em cada capability: NAO SOMAR. Totais por preset sao MEDIDOS (secao 1).

| id | feature | presets | flash est. | deps | modulos |
|---|---|---|---|---|---|
| ctap-makecred | (always on) | full,fido-only,fido-totp | ~141,5 KiB | - | ctap_cmd.rs, ctap_state.rs, ctap_ext.rs, cred_store.rs, pin_uv.rs, apdu.rs, up_policy.rs |
| ctap-getassert | (always on) | full,fido-only,fido-totp | ~141,5 KiB | - | ctap_cmd.rs, ctap_state.rs, ctap_ext.rs, cred_store.rs, pin_uv.rs, apdu.rs, up_policy.rs |
| ctap-clientpin | (always on) | full,fido-only,fido-totp | ~141,5 KiB | - | ctap_cmd.rs, ctap_state.rs, pin_uv.rs |
| ccid | (always on) | full,fido-only,fido-totp | ~7,0 KiB | - | ccid_dispatch.rs |
| piv | (always on) | full,fido-only,fido-totp | ~62,5 KiB | ccid | piv_cmd.rs, piv_store.rs, crypto_rsa.rs |
| openpgp | (always on) | full,fido-only,fido-totp | ~64,6 KiB | ccid | openpgp_applet.rs, openpgp_cmd.rs, crypto_extra.rs |
| oath-totp | cap-fido-totp (or full) | full,fido-totp | ~71,4 KiB | wifi-sntp (sntp opcional) | oath_cmd.rs, oath_store.rs, totp.rs, totp_view.rs, time_sync.rs, migrations/keys_oath_v6.rs |
| oath-hotp | cap-fido-totp (or full) | full,fido-totp | (compartilhado) | oath-totp | oath_cmd.rs (hotp dispatcher), oath_store.rs |
| otp-challenge-response | cap-fido-totp (or full) | full,fido-totp | (compartilhado) | oath-hotp | oath_cmd.rs (hotp_resync path) |
| wallet | full only (gated out of cap-*) | full | ~24,4 KiB | - | wallet_exec.rs, hd_wallet.rs |
| vault | full only (gated out of cap-*) | full | ~45,8 KiB | - | vault_aead.rs, vault_store.rs, migrations/vault_v7.rs |
| ble | ble (off in diet builds) | full | ~94,9 KiB | vendor-mgmt | ble/, ble_gatt.rs, ble_nimble.rs |
| wifi-sntp | wifi (forbidden with cap-*) | full | ~76,7 KiB | - | wifi_ap.rs, wifi_station.rs, net/, mdns.rs |
| display | has-display via board-t-display/board-ttgo-classic (forbidden with cap-*) | full | ~85,3 KiB | - | display/, oled_ssd1306_code_only.rs, ui_journey.rs |
| proximity | proximity (forbidden with cap-*) | full | ~51,5 KiB | ble | proximity/, proximity_sched.rs, proximity_crypto.rs |
| vendor-mgmt | (always on) | full,fido-only,fido-totp | ~42,3 KiB | - | vendor_exec.rs, serial_vendor.rs, serial_text.rs |
| debug-terminal | debug-terminal (forbidden with cap-*) | full | ~6,8 KiB | - | lifetime_trace.rs |
| test-hooks | test-mode (forbidden with cap-*) | full | ~2,5 KiB | - | test_hooks.rs |

Notas: oath-hotp/otp-challenge-response pegam carona no oath (custo contado em oath-totp). ble em dieta: radio init fail-closed (-1), sem advertising. display em devkitc (todos os presets) ja usa stub headless; dieta recusa boards com display por compile_error.

## 5. Pools de chaves/storage (gerado de capability-catalog.json)

| id | namespaces | limite | est. total | consome (caps) |
|---|---|---|---|---|
| credential-slots [resident] | cred/, cred/index | 32 slots x 1024 B | ~~34,2 KiB | ctap-makecred |
| oath6 [resident] | oath6/ | 64 slots x 512 B (no quota index) | ~~32,2 KiB | oath-totp,oath-hotp |
| oath6ctr [resident] | oath6ctr/ | 8 B blobs, label <=64 | ~~4,9 KiB | oath-hotp,otp-challenge-response |
| vault-store [resident] | vault/, vault/index | default 32 slots x 512 B (bound 64) | ~~17,6 KiB | vault |
| wallet-stores [resident] | key_slots_v1, keys6/ | <=32 slots | ~~7,8 KiB | wallet |
| secureguard-slots [resident] | sg_record_v1 | 1 record | ~512 B | vendor-mgmt |
| bonding-store [resident] | ble_store (controller NVS) | 1 bond | ~~2,0 KiB | ble |
| wifi-creds [resident] | wifi_sta_ssid, wifi_sta_pass, wifi_ap_pass | 3 keys | ~512 B | wifi-sntp |
| binding-keys [resident] | app_bind_pub, app_bind_id | 2 keys | ~128 B | vendor-mgmt,ble |
| ota-staging [transient] | ota_staging, ota_stage_len, ota_c*, ota_manifest, ota_committed | 8 KiB chunks, budget const 896 KiB | ~~896,0 KiB | (transiente/sempre) |

Budgets NVS: `storage @0x190000 len 0x070000` = 458752 B (448 KiB, layout 2 MB, devkitc); `storage @0x310000 len 0x0e0000` = 917504 B (896 KiB, layout 16 MB). Residente fido-only ~35 KiB (7,8%) PASS; full ~102 KiB PASS. OTA staging e TRANSIENTE (nunca somado ao residente): 917504 B nao cabe no storage 2 MB (WARN: nessa placa o fluxo precisa transmitir por streaming); cabe no 16 MB.

## 6. Evidencia (medido, elf2image --flash_size 4MB)

| preset | bin | bytes | sha256 | data |
|---|---|---|---|---|
| full | aegis-app-esp32s3-devkitc.bin | 1902288 | 747691BCA6D67CAB40FF2AADDECAFB2AB5BA5CAA1A12C1E14411E50769F86F40 | 2026-11-02 |
| fido-only | aegis-app-esp32s3-devkitc-fido-only.bin | 1128144 | 36CA330DC23CEF56D7716BFE08871D5A0CE562666716D13C555A9B2DCFD188AE | 2026-11-02 |
| fido-totp | aegis-app-esp32s3-devkitc-fido-totp.bin | 1251632 | 55AC03BC49C18C2DB09175BE0D5246B0103CAE369EDB554F79D800F0B0AE9FDC | 2026-11-02 |

Ver tambem: header de `crates/aegis-fido-firmware/partitions-2m.csv` (tamanho fido-only medido + preset atendido).## 7. Advertisement da capability (GET_CAPS `0x3F`)

Host descobre o preset sem adivinhar: comando vendor read-only `0x3F`
(primeiro byte livre apos a faixa SG `0x3A-0x3E`; auditoria completa no
header de `crates/aegis-fido-firmware/src/vendor_exec/vendor_caps.rs`).
Contrato wire legivel por maquina em
`scripts/capability-catalog.json#wire_contract`.

- Request: vazio. Qualquer payload nao-vazio nega fail-closed (`0x04`).
- Response: `(0x00, mapa CBOR)`:

| chave | tipo | conteudo |
|---|---|---|
| `fw_version` | text | versao do crate (`env!("CARGO_PKG_VERSION")`) |
| `preset` | text | `"full"` / `"fido-only"` / `"fido-totp"` (via cfg) |
| `caps` | array de text | EXATAMENTE `presets.<preset>.includes` do catalogo (mesmos IDs, mesma ordem) |
| `unsupported_count` | uint | numero de comandos vendor fora da dieta (`0` no full) |

- Auth: nenhuma (read-only, sem segredos; mesma classe de visibilidade do
  `0x38` fw-log over serial). Executado no `exec_vendor_op` ANTES do
  `authorize_vendor_op`: binding/UP/PIN nunca consultados.
- Desconhecidos preservados: vizinhos (`0x2E`/`0x2F`/`0x3E`/`0x40`) seguem
  `0x04` fail-closed; `fido-only` segue reportando a dieta (7 caps, 7
  `unsupported`), nunca mascara capability ausente.

| preset | caps anunciadas | `unsupported_count` (ops que respondem `0x06`) |
|---|---|---|
| full | 18 (todas) | 0 |
| fido-only | 7 (ctap-makecred, ctap-getassert, ctap-clientpin, ccid, piv, openpgp, vendor-mgmt) | 7 (`0x24`-`0x27` OATH + `0x35`-`0x37` wallet) |
| fido-totp | 10 (fido-only + oath-totp, oath-hotp, otp-challenge-response) | 3 (`0x35`-`0x37` wallet) |

Fiacao dos funis (fora do escopo de `vendor_exec`; snippet para os donos
dos transportes -- o executor compartilhado `exec_vendor_op` ja atende o
`0x3F` sem auth):

```
# USB serial (freertos_route::dispatch_serial_vendor_msg + loop legado):
# incluir o predicado e desviar ANTES do gate pairing/UP (como o 0x38):
if is_vendor_keys_oath_op(op) || is_wallet_op(op) || is_piv_enroll_op(op)
    || crate::vendor_exec::is_get_caps_op(op) { /* ... exec_vendor_op ... */ }

# BLE (ble_dispatch_complete): novo braco sem gates (como fw-log com bonded):
o if crate::vendor_exec::is_get_caps_op(o) => {
    let (st, body) = crate::vendor_exec::exec_vendor_op(
        key_mgr, oath_applet, storage, o, p, false, false, false, now_secs, &mut rng);
    ble::notify_frame(o, st, &body)
}
# + BLE reassembler (is_ble_fragment_opcode em gatt_core.rs): aceitar 0x3F
#   como opcode de fragmento (hoje so PING/MSG/bind 0x28-0x2D/OTA 0x30-0x34).
```

## 8. Per-credential UP policy (default require-touch, owner-explicit)

Cada credencial residente carrega `up_required: bool` (default `TRUE`).
`true` = fluxo UP existente, inalterado (phishing resistance preservada).
`false` (opt-out explicito, pos-criacao) = pula a presenca PARA ESTA
credencial, mas continua exigindo sessao DESBLOQUEADA (PIN/UV viva).
Uso silencioso com device travado nunca e permitido (invariante
fiscalizada no executor + documentada no codigo e aqui).

### 8.1 Onde mora o flag

- Core (`aegis-fido-core`, `credential::CredentialRecord::up_required`):
  campo aditivo `#[serde(default = "default_up_required")]` (`true`).
  CBOR/JSON antigo sem o campo decodifica como require-touch (sem
  migration wipe). Non-resident wrap (AES-GCM): tail `0/1` apos
  `public_key_cose`; wrap v0 sem tail decodifica `true`; tail fora de
  `0/1` nega fail-closed.
- Firmware NVS (`cred_store.rs`): registro `FC` bump `0x01 -> 0x02`;
  v2 = layout antigo + 1 B final (`0/1`); v1 lido como `true` (promovido
  para v2 de forma transparente no proximo `cred_bump_counter`).
  `decode` estrito: tamanho exato + tail `0/1`, resto nega.
- `MakeCredential` sempre minta `true`; opt-out nasce SOMENTE via
  management op abaixo (nunca na criacao).

### 8.2 Gate (firmware `ctap_cmd.rs`)

- `get_assertion`: limites wire + UV (sem UP) -> carrega o slot ->
  confere vinculo RP/id -> se `up_required`, `check_up` vinculado
  (existente); se opt-out, exige desbloqueio
  (`(pin_auth_ok && session.is_live()) || uv_performed`), senao
  CTAP `PinRequired (0x36)`; grant NAO consumido no opt-out nem nas
  negacoes (reuso do grant continua valido). Slot ausente/corrompido
  ou cross-RP: exige toque ANTES de negar (`OperationDenied` /
  `NoCredentials` / `InvalidCredential`; sem oraculo de existencia
  sem presenca).
- U2F equivalentes: o latch de transporte (`CMD_MSG` `INS=0x01` /
  `INS=0x02,P1=0x03`) e mantido (defense in depth, sem mudanca nos
  transportes); resolvido o `cred/` label, a lane de engine DEVE
  consultar `up_required_for_label` (fail-closed `true` em
  ausente/corrompido) e aplicar a mesma invariante de desbloqueio.
- `ctap_reset`: inalterado (sempre UP).

### 8.3 Management op SET (executor `ctap_cmd::set_credential_up_policy`)

Gate fail-closed, nesta ordem: `cred_id` 1..=128 B (`MissingParameter`
/ `InvalidParameter`) -> sessao desbloqueada viva
(`pin_auth_ok && is_live`, senao `PinRequired`; `pin_auth_ok` sem RAM
viva tambem nega) -> slot existente (`NoCredentials`) / NVS integra
(`IntegrityFailure`). Sem gate UP (a autenticacao e a sessao viva);
sessao de uso unico consumida SOMENTE no sucesso (negacoes nao
consomem, retry sem novo verify). Auditoria em toda mudanca:
`FwLog::record(EV_UP_POLICY_SET = 0x12, arg = 0/1, now_ms)` — proximo
codigo livre apos `EV_ADV_NOMEM (0x11)`; `arg` carrega SO a politica,
nunca label/credId/RP/segredo.

### 8.4 Wire contract (para a app lane)

CTAP existente e wire-invisivel (mesmos status): opt-out com sucesso
retorna assertion normal; travado+opt-out = `PinRequired (0x36)`;
toque ausente no default = `OperationDenied (0x27)`.

SET via transporte (PROPOSTO — executor firmware pronto; fiacao do
dispatcher e follow-up da app lane, sem mudanca de transporte neste
commit):

- `CMD_MSG` opcode `0x40` (primeiro livre apos `GET_CAPS 0x3F`).
- Request body (apos o opcode):
  `[up_flag:1][cred_id_len:1][cred_id:cred_id_len]` com
  `up_flag in {0,1}`, `1 <= cred_id_len <= 128`; fora disso = `0x04`.
- Gates de transporte: BLE = binding valido + sessao PIN viva
  (sem latch UP); serial/USB fisico = sessao PIN viva.
- Response status-first (namespace vendor §9.5):
  `0x00` ok (+ auditoria `EV=18`) | `0x02` NEED_PIN (travado) |
  `0x03` NO_SLOT (ausente) | `0x04` falha (forma/storage).
- Invariante repetida no fio: `up_flag = 0` NUNCA autoriza uso com
  device travado; o desbloqueio e verificado no executor, nao no host.

## 9. SIGN dedicado (VENDOR_SIGN `0x41`)

Causa raiz (verificada): a app enviava sign para o GEN `0x20` com TLV
`{0x01 slot, 0x74 challenge}`, mas o GEN exige `TAG_LABEL` (`0x02`) e
negava deterministico (`0x04`). `KeyManager::sign` existia sem nenhum
braco no dispatcher que o chamasse. `VENDOR_SIGN` recebe exatamente
aquele shape e chama `KeyManager::sign`; a semantica do GEN `0x20`
fica intacta (inclusive o `0x04` sem label, com teste de regressao).

### 9.1 Prova da escolha do opcode

O `0x2F` da tarefa esta OCUPADO e foi rejeitado com prova em codigo:

- `0x2F` = `pairing::OP_HOST_PAIRING_OPEN` (trigger de pareamento
  produto no USB/serial; `is_host_pairing_msg` exige payload vazio).
  Reutilizar no executor compartilhado (USB + BLE) colidiria com o
  trigger no path serial. Teste `opcode_audit_sign_is_first_free_after_set_up_policy`
  fixa `OP_HOST_PAIRING_OPEN == 0x2F`.
- `0x40` = `ctap_cmd::OP_SET_UP_POLICY` (implementado e fiado nos 4
  funis + reassembler). Teste fixa `OP_SET_UP_POLICY == 0x40`.
- `0x41` = primeiro byte livre apos `0x40`; nenhuma outra definicao
  de opcode em arvore (só magic bytes, padding de teste e bitmaps de
  fonte). Auditoria vizinha completa no header de
  `crates/aegis-fido-firmware/src/vendor_exec/vendor_keys.rs` e no
  teste de auditoria acima (predicados de funil existentes nao
  engolem `0x41`).

### 9.2 Contrato wire (legivel por maquina em `scripts/capability-catalog.json#wire_contract.vendor_sign`)

- Request TLV: `TAG_SLOT` `0x01` (1 B, obrigatorio) + `TAG_CHALLENGE`
  `0x74` (mensagem/desafio nao-vazio, obrigatorio). Qualquer outra
  forma nega fail-closed (`0x04`, corpo vazio).
- Response: `(0x00, bytes da assinatura)` no sucesso; negacoes
  `0x01` NEED_UP (sem presenca) | `0x03` NO_SLOT (slot desconhecido) |
  `0x04` BAD_ENVELOPE (TLV malformado) | `0x05` NEED_BINDING (sem vinculo).
- Auth: classe CONFIG sem PIN, EXATAMENTE o GEN `0x20` (binding valido
  com bypass test-mode + ltrace, depois UP; ordem canonica binding ->
  UP; PIN nunca exigido, nunca mais fraco que o GEN).
  `KeyManager::sign` re-checa UP internamente (defense in depth).
- Persistencia: o bump de `sign_count` (clone detection) salva em NVS
  com rollback via snapshot se o save falhar (mesmo padrao do DELETE);
  roundtrip coberto em teste.
- Dieta: sem capability nova — pega carona em `vendor-mgmt` nos tres
  presets (`full`, `fido-only`, `fido-totp`); `unsupported_count`
  inalterado.

Fiacao dos funis (follow-up dos donos dos transportes; o executor
compartilhado `exec_vendor_op` ja atende o `0x41` com gate):

```
# USB serial (freertos_route::dispatch_serial_vendor_msg + loop legado):
# incluir o predicado e exigir binding + UP (classe GEN, sem PIN):
if is_vendor_keys_oath_op(op) || ... || crate::vendor_exec::...is_vendor_sign_op(op) { ... }

# BLE (ble_dispatch_complete): novo braco com gates (como GEN, nao como fw-log):
o if is_vendor_sign_op(o) => { binding + UP; exec_vendor_op(...) }
# + BLE reassembler (is_ble_fragment_opcode em gatt_core.rs): aceitar 0x41
#   como opcode de fragmento.
```

## 10. OOB-assisted BLE pairing (BLE_OOB_ARM `0x42`)

Causa raiz (provada no hardware): a SM NimBLE exige MITM (`sm_mitm=1`,
LESC + bonding, Sec. F-01) mas o device nao tem display/teclado
(`NO_INPUT_NO_OUTPUT`): telefone consent-only (sem metodo de
confirmacao) nao completa o bonding — JustWorks e rejeitado
fail-closed (`AUTH_REQUIREMENTS`). Sem enfraquecer o MITM, a saida e
OOB: a chave temporaria viaja pelo canal USB/serial ja confiavel
(posse fisica + sessao desbloqueada + vinculo) e o BLE completa
LESC+OOB. Sem flash nesta etapa (validacao host primeiro; placa
intacta).

### 10.1 Disponibilidade OOB no IDF v5.3.1 pinado (verificada, nao assumida)

Headers locais `C:\.embuild\espressif\esp-idf\v5.3.1` (esp-nimble
`2cf7edd`, `ble_hs.h` + `ble_sm.h`): `ble_hs_cfg.sm_oob_data_flag`,
`sm_mitm`, `sm_sc`, `sm_our_key_dist`, `sm_their_key_dist`;
`BLE_SM_IOACT_OOB` (=1, TK legado 16 B) + `BLE_SM_IOACT_OOB_SC` (=5,
`oob_sc_data.{local,remote}`), `struct ble_sm_sc_oob_data {r[16],c[16]}`,
`ble_sm_sc_oob_generate_data()` + `ble_sm_inject_io()` (guard
`NIMBLE_BLE_SM`, sempre ON com bonding). Mesmo padrao do exemplo
oficial `bleprph` v5.3.1 (`PASSKEY_ACTION` + `inject`). NAO ha gap:
nenhum downgrade para JustWorks (F-01 intacto).

### 10.2 Prova da escolha do opcode

`0x42` = primeiro byte livre apos `VENDOR_SIGN 0x41`; nenhuma
definicao de opcode na arvore (soma de auditoria: vizinhos `0x3F`
GET_CAPS, `0x40` SET_UP_POLICY, `0x41` VENDOR_SIGN travados em teste;
predicados de funil existentes nao engolem `0x42`; reassembler BLE o
rejeita `InvalidOpcode` — serial/USB only por construcao).

### 10.3 Contrato wire (legivel em `crates/.../src/ble/oob.rs`)

- Request `CMD_MSG`: `[0x42, tk0..tk15]` — opcode + EXATAMENTE 16 B
  (random OOB do peer / TK legado). Outro comprimento (incl. vazio e
  32 B) ou TK todo-zero nega fail-closed (`0x04`, corpo vazio, sem
  armar; sem vazamento).
- Response status-first: `[status]` (`0x00` ok + corpo vazio; `0x05`
  sem janela/vinculo | `0x01` sem UP | `0x02` travado | `0x04` forma
  ou radio sem latch).
- Gates (classe CONFIG sensivel, ordem canonica): janela de
  pareamento (funil serial, `0x05` fechada) -> binding (`0x05`) -> UP
  fisico por operacao (`0x01`, NUNCA pulado: o `on_link_secured`
  continua exigindo o latch no `ENC_CHANGE`) -> sessao PIN viva
  (`0x02`). Sucesso consome o latch UP; negacoes nao tocam estado.
- Transporte: SOMENTE serial/USB. O BLE nunca serve `0x42`.
- Radio (componente C `aegis_ble`): latch one-shot (consome no
  inject, limpa no disconnect, re-arm last-wins); `sm_oob_data_flag`
  levantado so com latch (lido live pelo SM; sem latch, OOB falha
  fechado e o MITM segue exigido).
- LESC-SC honesto: com 16 B o glue injeta `remote = {r: TK, c: TK}`
  + local fresco — a checagem de confirm do SM falha fechado rapido
  (`CONFIRM_MISMATCH`, sem bonding) em vez de travar em timeout.
  OOB-SC pleno (par `(r,c)` real do peer, 32 B) e follow-up
  documentado (op `0x42` estendida ou nova op); o caminho legado
  (`IOACT_OOB`) completa com os 16 B. Sem o TK OOB, MITM nao passa.
- Dieta: `0x42` valida+gates em todos os presets (`vendor-mgmt`);
  o latch de radio so existe no `full` (BLE inerte na dieta: shim
  `-1`, funil nega `0x04`). `unsupported_count` do GET_CAPS
  inalterado.

Fiacao dos funis (ramo dedicado `is_ble_oob_op`, mesma severidade do
vendor CONFIG; BLE sem braco — cai no default `0x04`):

```
# USB serial Freertos + legado (secao D): janela + binding -> UP -> sessao;
# sucesso arma via esp_ble_arm_oob e consome o latch UP:
if crate::ble::oob::is_ble_oob_op(op) { /* gates; exec_vendor_op; arm; */ }
# Executor compartilhado (vendor_dispatch.rs): braco ANTES do authorize_vendor_op
# (0x42 fora da faixa 0x20-0x27), sem efeito colateral — o funil serial arma.
```

