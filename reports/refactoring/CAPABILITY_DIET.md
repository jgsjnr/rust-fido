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

