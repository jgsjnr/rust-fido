# WiFi Real via esp-idf — Etapa B (AP + station + mDNS no ESP32-S3)

Etapa B liga o radio WiFi: AP `AegisKey-XXXX` real, station com DHCP e mDNS
`aegiskey-xxxx.local` real, com power-down total fora de uso (bateria).
USB/CTAP/BLE intactos; logica de politica (`wifi_ap.rs`, `wifi_station.rs`,
`mdns.rs`) inalterada no comportamento — so os stubs viraram FFI real.

Contrato de fio congelado: `docs/ble-protocol.md` §5–§8 + §10 (inalterado).

## 1. Por que componente C (licao da Etapa A)

`esp-idf-svc` 0.50 e usado aqui SO com `binstart` (ver `Cargo.toml` do
firmware): nenhuma feature de WiFi/BLE e assumida — licao registrada da
Etapa A (NimBLE veio por componente C, nao por feature inexistente). Todo o
radio WiFi vive no componente C `components/aegis_wifi` (esp_wifi + esp_netif
+ esp_event + sockets lwIP), chamado pelo Rust via `extern "C"` manual, sem
bindgen e sem nenhum dep novo no `Cargo.toml`.

- Credenciais nunca persistem no IDF: `esp_wifi_set_storage(WIFI_STORAGE_RAM`)
  e o Rust entrega SSID/senha a cada start (NVS cifrada `SecureStorage`,
  envelope AES-GCM AEGN v1). O C zera as senhas da RAM no `aegis_wifi_off`.
- mDNS: o IDF v5.3 nao tem mais `mdns` no core (virou componente gerenciado
  `espressif/mdns`, incompativel com `component_manager = false`); por isso o
  responder e minimo sobre sockets lwIP (so A-query `<host>.local`, TTL 120s,
  cache-flush bit). Sem HTTP ainda (follow-up §8).
- sdkconfig: SEM MUDANCA. WiFi e ligado por default no IDF e coexiste com o
  BLE-only da Etapa A (mesma referencia oficial:
  `examples/bluetooth/nimble/bleprph_wifi_coex`, IDF v5.3.1). O bloco BT do
  `sdkconfig.defaults.esp32s3` segue intocado.

## 2. Mapa de arquivos

| Arquivo | Papel |
|---|---|
| `crates/aegis-fido-firmware/components/aegis_wifi/aegis_wifi.c` | Radio: AP, station DHCP, mDNS minimo, power-down; API `aegis_wifi_*` / `aegis_mdns_*` |
| `crates/aegis-fido-firmware/components/aegis_wifi/CMakeLists.txt` | Registro (`REQUIRES esp_wifi esp_netif esp_event nvs_flash lwip freertos`) |
| espelho em `C:/.embuild/.../v5.3.1/components/aegis_wifi` | Copia exigida pelo build neste env (mesmo caso do `aegis_ble`); fonte da verdade = crate, manter em sync |
| `crates/aegis-fido-firmware/src/wifi_ap.rs` | `esp_ap_start/stop`, `esp_wifi_off`, `resolve_ap_password`, shims host |
| `crates/aegis-fido-firmware/src/wifi_station.rs` | `STA_*`, `esp_sta_start/stop/state/ip`, `sta_retry_due`, shims host |
| `crates/aegis-fido-firmware/src/mdns.rs` | `esp_mdns_start/stop`, `mdns_bare_hostname`, shims host |
| `crates/aegis-fido-firmware/src/main.rs` | Fio: edge-trigger AP/station/mDNS + backoff + power-down |
| `crates/aegis-fido-firmware/Cargo.toml` | `components/aegis_wifi` no `extra_components` |

## 3. AP `AegisKey-XXXX` (so em pareamento)

- SSID deriva do serial (`ap_ssid_for_serial`, ultimos 4 alfanumericos).
- Senha: `resolve_ap_password` le a NVS (`wifi_ap_pass`, troca exige
  binding+UP+PIN como antes). Sem senha provisionada = rede ABERTA, somente
  na janela curta de pareamento (60s, radio desliga depois). As rotas mgmt
  exigem binding+UP+PIN mesmo em rede aberta; CTAP/OATH exigem UP fisico.
- Canal 6, 4 clientes, WPA2_PSK com senha / OPEN no bootstrap.
- Edge-trigger no `main.rs`: liga quando `WifiApManager` ativa, desliga no
  timeout/pos-config (`shutdown_after_config` preservado).

## 4. Station (fora de pareamento, com fallback AP)

- Credenciais em NVS cifrada (`wifi_sta_ssid` + `wifi_sta_pass`, par, nunca em
  claro no log). Save/clear exigem UP+PIN (+binding nas variantes `_bound`).
- `main.rs`: `sta_mgr.update(pairing_open, has_creds, now)` com credenciais
  REAIS (antes era `false` fixo). Poll do radio (`STA_OFF/CONNECTING/
  CONNECTED/FAILED`) -> `on_connected` / `on_failed` do manager.
- Sem retry automatico no C (bateria): `sta_retry_due` libera 1 tentativa a
  cada 60s (`WIFI_STA_RETRY_BACKOFF_MS`); entre tentativas o radio desliga.
- Pareamento abre ou credenciais somem -> `esp_sta_stop` imediato (o AP de
  fallback assume o radio). Station e AP nunca disputam: modo APSTA quando
  ambos querem, rebaixado sem derrubar o outro.
- `WIFI_PS_MAX_MODEM` (modem-sleep) sempre que o radio liga.

## 5. mDNS `aegiskey-xxxx.local`

- Hostname deriva do serial (lowercase, fallback `0001`), como antes.
- `main.rs`: `mdns_mgr.update(pairing_open, sta_up)` inalterado; edge-trigger
  chama `esp_mdns_start` com o hostname SEM `.local` (`mdns_bare_hostname`).
- O responder anuncia o IP da station; com station fora e AP ativo, o IP do
  AP (phone provisiona na janela de pareamento). Sem IP: silencioso.
- Desliga junto com a station/AP (fallback AP assume; fora de uso, off).

## 6. Coexistencia (USB > WiFi > BLE)

- USB tem controlador dedicado: intocado.
- WiFi prefere sobre BLE: `wifi_active = ap_ativo || sta_up` continua
  alimentando `adv_intervals(true)` (BLE lento, cede airtime). `PairingAp`:
  BLE mudo (radio com o WiFi).
- Bateria: fora de uso (nem AP, nem station) o `main.rs` chama
  `esp_wifi_off` (power-down total + zero das senhas na RAM do C).

## 7. RAM/flash (MAX-ESP, medido no S3)

Binario `release/aegis-fido-firmware` (`xtensa-esp32s3-elf-size -B`):

| | text | data | bss |
|---|---|---|---|
| Baseline pre-Etapa B | 1679138 | 130984 | 3450685 |
| Pos-Etapa B BLE (2026-10-19, IDF v5.3.1) | 1989606 | 198768 | 4204273 |
| Pos-Etapa B WiFi (2026-10-19, IDF v5.3.1) | 2349223 | 250652 | 4956081 |

Delta WiFi (+359617 text / +51884 data / +751808 bss): stack WiFi do IDF
(802.11 + lwIP + esp_netif) + task mDNS 4KB. Esperado e justificado: e o
custo fixo do WiFi no IDF (mesma ordem do BLE na etapa anterior); o radio
passa a maior parte do tempo DESLIGADO (AP so 60s em pareamento, station com
backoff 60s, `WIFI_PS_MAX_MODEM`), entao o custo e flash/RAM, nao bateria.
Sem regressao funcional: USB/CTAP/BLE intactos (suite verde, build verde).

## 8. Testes (host)

+6 testes (suite workspace: 242 -> 248 verdes):

- `wifi_ap.rs`: shims inertes (`esp_ap_start/stop`, `esp_wifi_off` = 0);
  `resolve_ap_password` (None/vazia/curta/nao-utf8 -> aberta; valida -> Some,
  sem expor conteudo).
- `wifi_station.rs`: shims inertes (state OFF, IP zerado); `sta_retry_due`
  (primeira true, dentro do backoff false, borda 60s true, skew false).
- `mdns.rs`: shims inertes; `mdns_bare_hostname` (tira `.local`, idempotente).
- S3: build verde + SIZE preenchido (2026-10-19). Flash pendente (S3 desplugada).

## 9. Follow-ups (fora desta etapa, documentados de proposito)

- Servidor HTTP mgmt (`POST /ctap`, `POST /config/wifi`, `GET /oath/code`)
  sobre o AP/station (rotas e gates ja existem; falta o socket server).
- `SecureStorage` do app ainda e RAM no device (`RamFlashBackend`);
  station/AP sobrevivem ate o reboot (NVS real = follow-up, como no BLE).
- `enter_ap_mode` via menu (main ainda passa `menu_request=false`).
- Retry adaptativo da station (backoff exponencial + C-side retry em
  transientes) e WPA3_SAE transition quando o parque de roteadores permitir.
- `pin_authenticated` real sobre WiFi (hoje as rotas exigem via UP+PIN
  fisico; ClientPIN chega via CTAP USB/BLE).

NOTA: `crates/aegis-fido-firmware/sdkconfig.defaults*` e legado e nao e lido
pelo build S3 (vale o `sdkconfig.defaults.esp32s3` do workspace root via
`ESP_IDF_SDKCONFIG_DEFAULTS` em `scripts/common.ps1`). Nao editar esperando
efeito no build. Da mesma forma, apos adicionar componente C novo, o cache
cmake do esp-idf-sys precisa reconfigurar (apagar
`target/.../build/esp-idf-sys-*/` força; `cargo clean -p <crate>` NAO basta).
