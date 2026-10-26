# BLE Real via NimBLE — Etapa B (GATT 0xFFFD no ESP32-S3)

Etapa B liga o radio: GATT 0xFFFD real sobre NimBLE (BLE-only, sem Bluedroid),
advertising somente em modo pareamento, bonding persistido em NVS e
`complete_pairing` que desliga o advertising. USB/CTAP intactos; WiFi intocado
(usa o mesmo `PairingManager`, sem mudar AP/station).

Contrato de fio congelado: `docs/ble-protocol.md` §1–§4 + §11 (inalterado).

## 1. Por que NimBLE (e nao Bluedroid)

`esp-idf-svc` 0.50.1 nao tem feature `ble`: o modulo `bt::ble` e Bluedroid
(`BtDriver` + `EspBleGap` + `EspGatts`, exemplo oficial avisa do consumo de
memoria). NimBLE no Rust = C API via `esp-idf-svc`/`esp-idf-sys` + sdkconfig
(`CONFIG_BT_NIMBLE_ENABLED=y`), sem nenhum dep novo no `Cargo.toml`.

- Stack: NimBLE BLE-only (`BTDM_CTRL_MODE_BLE_ONLY`), 1 conexao
  (`BT_NIMBLE_MAX_CONNECTIONS=1`). Ver `sdkconfig.defaults.esp32s3`.
- Padrao de codigo: componente C fino + `extern "C"` manual no Rust, identico
  ao `components/aegis_usb/aegis_usb.c` (zero risco de bindgen).

## 2. Mapa de arquivos

| Arquivo | Papel |
|---|---|
| `crates/aegis-fido-firmware/src/ble_nimble.rs` | Politica host-testavel (`no_std`): payload adv, `should_advertise`, intervalos coex, `notify_frame`, `on_link_secured`, FFI + shims host |
| `crates/aegis-fido-firmware/components/aegis_ble/aegis_ble_nimble.c` | Radio: init NimBLE, GATT 0xFFFD, GAP, bonding NVS, API `aegis_ble_*` |
| `crates/aegis-fido-firmware/components/aegis_ble/CMakeLists.txt` | Registro do componente (`REQUIRES bt nvs_flash`) |
| espelho em IDF `components/aegis_ble` | Copia exigida pelo build neste env (esp-idf-sys ignora `extra_components` do Cargo.toml aqui); fonte da verdade = crate, manter em sync |
| `crates/aegis-fido-firmware/src/main.rs` | Fio: `PairingManager` -> start/stop adv; pump de eventos + FFF1; dispatch -> notify FFF2 |
| `crates/aegis-fido-firmware/src/ble_gatt.rs` | `BleGattServer` reutilizado sem mudanca; `start/stop_advertising` viraram shims de compat |
| sdkconfig.defaults.esp32s3 (workspace root) | Bloco BT NimBLE (padrao oficial leprph_wifi_coex); aplicado via ESP_IDF_SDKCONFIG_DEFAULTS (scripts/common.ps1); o esp-idf-sys nao resolve sdkconfig.defaults.* sozinho neste env |

## 3. GATT 0xFFFD (real)

| Char | Props | Servidor |
|---|---|---|
| FFF1 | write (+write-no-rsp) | 1 fragmento pendente por vez (backpressure = `BLE_ATT_ERR_UNLIKELY`); Rust consome via `aegis_ble_fetch_rx` e alimenta `BleGattServer::control_write` (UP por operacao, framing §3 intacto) |
| FFF2 | read + notify | Respostas `[op, status, payload...]` via `aegis_ble_notify` (CCCD automatico do NimBLE); read retorna o byte de status |
| FFF3 | read | `u16 LE` espelhado pelo Rust (`aegis_ble_set_pending_len` apos cada fragmento) |
| FFF4 | read/write | Revisao `0x01`; escrita de outro valor = `INVALID_ATTR_VALUE_LEN` |

Dispatch no `main.rs` (`ble_dispatch_complete`): PING ecoa, CANCEL confirma,
MSG delega ao `CtapEngine::process_packet` (mesmo `[cmd, CBOR...]` do USB),
bind-mgmt `0x28–0x2D` usa os helpers de `ble_gatt` (gates binding -> UP -> PIN
preservados, respostas com `to_vendor_status`), vendor `0x20–0x27` valida os
gates §9.4 e responde `0x04` (executor TLV on-device = follow-up, §7).

## 4. Ciclo de pareamento (radio)

```
hold BOOT 5s -> PairingBle (janela 60s) -> edge-trigger liga adv
   (UUID 0xFFFD + service-data flag 0x01 + nome "AegisKey", <=31B)
-> central conecta -> bonding JustWorks (sm_bonding=1, NO_IO, SC)
-> ENC_CHANGE ok (bond gravado via ble_store/NVS) -> evento SECURED
-> main: on_link_secured(janela + UP latch) -> complete_pairing
   -> stop advertising + Idle (sai do modo) + LED verde solido
   + tela "DISPOSITIVO PAREADO"
```

- Sem UP no latch: mostra prompt de UP e marca `ble_bond_pending`; conclui
  quando o usuario tocar no BOOT (dentro da janela).
- Timeout (60s), disconnect ou troca de modo: edge-trigger para o adv.
- Fluxo de envio do app: toque no BOOT -> rajada de fragmentos dentro do
  latch (1,5s cobre folgado escritas BLE de ms) -> resposta em FFF2.
  Sem toque, o fragmento e negado (UP por operacao, como no host).
- Bonding persiste entre reboots (NVS `nvs`); reconexao com bond recifra e
  reemite SECURED. O flag `bonded` do `PairingManager` continua por sessao
  (RAM), como antes.

## 5. Coexistencia (USB > WiFi > BLE)

- USB tem controlador dedicado: nunca afetado pelo BLE.
- WiFi AP fallback liga durante o pareamento; station, fora dele. Com WiFi
  ativo o advertising usa intervalo lento (250–320ms vs 100–150ms normal):
  o BLE cede airtime (`adv_intervals(true)` no Rust, mesmos valores no C).
- `PairingAp`: BLE mudo (radio com o WiFi). `Idle`/`Arming`/`Locked` ou
  janela expirada: BLE mudo (privacidade + bateria).
- Referencia oficial seguida: `examples/bluetooth/nimble/bleprph_wifi_coex`
  (IDF v5.3.1).

## 6. RAM/flash (MAX-ESP, medido no S3)

Binario `release/aegis-fido-firmware` (`xtensa-esp32s3-elf-size -B`):

| | text | data | bss |
|---|---|---|---|
| Baseline pre-Etapa B | 1679138 | 130984 | 3450685 |
| Pos-Etapa B (2026-10-19, IDF v5.3.1) | 1989606 | 198768 | 4204273 |

NimBLE BLE-only + 1 conexao e a configuracao mais leve do IDF para BLE
(Bluedroid dual-mode, que foi explicitamente desligado, custa ~2x). O grueso
do bss vinha do stack USB/LCD pre-existente; o delta (+310468 text / +67784 data / +753588 bss) e a pilha NimBLE + controller BLE (PSRAM ja em uso pelo baseline).

## 7. Testes (host)

`ble_nimble.rs` (10 testes): layout do adv travado byte a byte (flag so muda
1 byte 0x00/0x01), `<=31B`, matriz `should_advertise` (Idle/Arming mudos,
PairingBle anuncia, expirado mudo, AP mudo), coex lento > normal, moldura de
notify + teto 512B, glue UP/framing, CANCEL, matriz `on_link_secured`
(janela+UP, sem UP, pareado sai do modo, corrida com timeout), shims inertes.
Suite workspace: 242 verdes (232 baseline + 10); S3: build verde + SIZE preenchido (2026-10-19).

## 8. Follow-ups (fora desta etapa, documentados de proposito)

- Executor TLV on-device `0x20–0x27` (hoje: gates corretos + `0x04`).
- `pin_authenticated` real sobre BLE (hoje `false`; ClientPIN chega via MSG).
- `SecureStorage` do app ainda e RAM no device (`RamFlashBackend`); bonding
  BLE usa a NVS real via `ble_store` (independente).
- `enter_ap_mode` via menu (hoje o main nunca entra em `PairingAp`).

NOTA: crates/aegis-fido-firmware/sdkconfig.defaults* e legado e nao e lido pelo build cargo (o build S3 aplica o arquivo do workspace root via ESP_IDF_SDKCONFIG_DEFAULTS em scripts/common.ps1). Nao editar esperando efeito no build.
