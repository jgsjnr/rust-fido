# Capacidades e Módulos — Inventário do Sistema

Inventário fiel ao código atual de todas as capacidades que podem (ou já deveriam) ser módulos.
Escopo: `crates/*/src`, `components/` embutidos no firmware, `tools/` e features do Cargo.
Método: só-leitura do repo; sem compilação.

Referências de features: `crates/aegis-fido-firmware/Cargo.toml:9-24`.
Mapa de módulos do firmware: `crates/aegis-fido-firmware/src/lib.rs:11-48`.
Núcleo: `crates/aegis-fido-core/src/lib.rs:6-15`.
USB: `crates/aegis-fido-usb/src/lib.rs:4-9`.

---

## 1. Inventário por domínio

### 1.1 Transporte USB (CTAPHID / CCID / Keyboard / WinUSB)

Onde mora hoje:

- Lógica host-testável Rust: `crates/aegis-fido-usb/src/` — `lib.rs:4-9` declara
  `ccid`, `ctaphid`, `keyboard`, `piv`, `transport`, `winusb`.
- Driver C no device: `crates/aegis-fido-firmware/components/aegis_usb/aegis_usb.c`,
  `ccid_device.c`, `aegis_uart.c`, `aegis_serial.c`, headers em
  `components/aegis_usb/include/aegis_usb.h` e `aegis_serial.h`.
- Descritores USB compostos: `crates/aegis-fido-firmware/src/usb_descriptors.rs`
  (reexportado em `lib.rs:60`).
- FFI no dispatcher: `crates/aegis-fido-firmware/src/main.rs:50-82`
  (`aegis_usb_init/is_mounted/send_report/pop_packet`,
  `aegis_ccid_pop_frame/send`, variantes `aegis_serial_*` por placa).
- Roteamento FreeRTOS: `crates/aegis-fido-firmware/src/freertos.rs:1-30`
  (tarefa `usb_ctaphid` drena pacotes de 64 B para `FirmwareEvent`).

Já é módulo? Parcialmente. `aegis-fido-usb` é crate separada (bom), mas o driver C
e os descritores continuam dentro do firmware, e `main.rs` chama FFI direto.

Acoplamentos que prendem:

- `main.rs:50-82` espalha `#[cfg(board-ttgo-classic)]` entre `aegis_usb_*` e
  `aegis_serial_*`; Classic reusa o transporte UART como `aegis_usb_*`
  (`main.rs:157-185`).
- `ccid_dispatch.rs:10-17` cruza `aegis_fido_usb::ccid` + `piv_store` + `persistence`.
- Coexistência `USB > WiFi > BLE` decidida em `ble_nimble.rs:23-25` e no tick
  de proximidade (`main.rs:759-791`).

Candidato a módulo: `transport-usb` (fronteira: `Transport` trait de
`aegis-fido-usb/src/transport.rs` + drivers C atrás de `UsbBackend` trait).
Porquê: coesão alta (framing 64 B idêntico no USB/serial), acoplamento hoje
espalhado em `#[cfg]` no dispatcher.

### 1.2 Transporte serial/UART (CTAPHID sobre UART 115200)

Onde mora hoje:

- Dispatch: `crates/aegis-fido-firmware/src/serial_ctaphid.rs:1-21` — framing
  byte-idêntico ao USB via `CtapHidFramer`/`CtapHidManager`, heartbeat fora do
  framing (`is_text_line`), gates de pareamento + UP.
- FFI: `main.rs:75-82` (`aegis_serial_init/send_report/pop_packet/read_chunk`).

Já é módulo? Sim, como módulo Rust (`serial_ctaphid.rs`), mas sem trait de
backend: o Classic vs S3/S2 é decidido por `#[cfg]` em `main.rs:163-185`.

Acoplamentos: `serial_ctaphid` importa `ctap` (`CLIENT_PIN`, `MAKE_CREDENTIAL`,
`GET_ASSERTION`, `RESET` em `serial_ctaphid.rs:24-28`), `ble_gatt::authorize_vendor_op`
(`serial_ctaphid.rs:17-19`), `freertos.rs:25-29` reexporta seus gates.

Candidato a módulo: `transport-serial` (fronteira: `SerialBackend` com
`pop/send/read_chunk` + `SerialRouter` já existente).
Porquê: mesma semântica de framing do USB; isola os `#[cfg(board-*)]`.

### 1.3 Transporte BLE GATT (0xFFFD) — política e framing

Onde mora hoje:

- Política/framing host-testável: `crates/aegis-fido-firmware/src/ble_gatt.rs:1-30`
  (serviço `0xFFFD`, chars `FFF1-FFF4`, opcodes `MSG 0x83/PING 0x81/CANCEL 0xBE`,
  `CONTROL_POINT_LENGTH`, bonding obrigatório, UP por operação).
- Dispatcher BLE completo: `main.rs:212-439` (`ble_dispatch_complete` cobre
  PING/CANCEL/MSG/rescue `0x2E`/bind `0x28-0x2D`/recovery/vendor `0x20-0x27`/
  wallet/fw-log `0x38`).
- Porta serial espelha os mesmos gates (`serial_ctaphid.rs:17-19`).

Já é módulo? Sim (`ble_gatt.rs` + reuso em `ble_nimble.rs:6-8`), mas o dispatcher
que aplica os gates vive em `main.rs`, não no módulo.

Acoplamentos: `ble_gatt.rs:15` importa `policy::{UpOnly, UpPolicy}` do core;
`ble_dispatch_complete` (`main.rs:213-228`) recebe 12 dependências
(`CtapEngine`, `BindingManager`, `SecureStorage`, `RescueEngine`, `WalletStore`,
`KeyManager`, `OathApplet`, `FwLog`, ...).

Candidato a módulo: `transport-ble-gatt` (fronteira: `BleGattServer::{control_write,
read_len}` + `authorize_*` puros; dispatcher vira função injetável).
Porquê: política já é `no_std` e testável; o que falta é tirar o `match` de opcodes
de `main.rs`.

### 1.4 Backend BLE NimBLE + rádio C

Onde mora hoje:

- Política testável + shims host: `crates/aegis-fido-firmware/src/ble_nimble.rs:1-26`
  (advertising, intervalos de coexistência, moldura de notify, desfecho do bonding).
- Rádio real: `crates/aegis-fido-firmware/components/aegis_ble/aegis_ble_nimble.c`
  via `extern "C"` (`ble_nimble.rs:327`, `ble_nimble.rs:536-552`).
- Proximidade usa o mesmo rádio: `ble_nimble.rs:470-552` com gates
  `#[cfg(feature = "proximity")]`.

Já é módulo? Sim, padrão exemplar: lógica pura Rust + backend C atrás de FFI +
shims inertes no host (`ble_nimble.rs:11`).

Acoplamentos: `ble_nimble.rs:31-37` importa `ble_gatt`, `lifetime_trace`,
`pairing`; `main.rs:570-577` importa `ble_nimble::{esp_ble_proximity_start,
esp_ble_stop, should_adv_proximity}` no `prox_sched`.

Candidato a módulo: manter como está; extrair `BleRadioBackend` trait se um dia
houver segundo stack BLE.
Porquê: já separa política (testável) de rádio (C); nada a fazer além de não
regredir.

### 1.5 CTAP2 / CBOR (MakeCredential, GetAssertion, ClientPIN, Reset, ...)

Onde mora hoje:

- Núcleo: `crates/aegis-fido-core/src/ctap/` (`mod.rs`, `make_cred.rs`,
  `get_assertion.rs`, `client_pin.rs`, `cred_mgmt.rs`, `large_blobs.rs`,
  `info.rs`, `config.rs`, `reset.rs`, `cbor.rs`, `status_code.rs`, `attestation.rs`)
  reexportado como `CtapEngine` (`core/src/lib.rs:17`).
- Uso no firmware: `main.rs:13-14` (`CtapEngine`, `CTAP_CMD_*`), `main.rs:108-155`
  (`extract_rp_and_user` p/ display), `main.rs:245-272` (MSG via `process_packet`).

Já é módulo? Sim — o mais modularizado do sistema (crate `aegis-fido-core`,
submódulos por comando).

Acoplamentos: `CtapEngine.pin_state` é lido por BLE/wallet/vendor
(`main.rs:250`, `main.rs:388`) para plumbing de PIN; `cbor` é reusado pelo
display (`main.rs:113-152`). Ambos são usos legítimos via API pública.

Candidato a módulo: nenhum trabalho restante; proteger com testes de paridade
CBOR.
Porquê: coesão por comando já existe; acoplamento é só via `CtapEngine`.

### 1.6 Credenciais / KeyManager / Vault (núcleo)

Onde mora hoje:

- Núcleo: `crates/aegis-fido-core/src/credential/` (`store.rs`, `record.rs`,
  `non_resident.rs`, `key_manager.rs`, `mod.rs`) e
  `crates/aegis-fido-core/src/vault/` (`store.rs`, `secrets.rs`, `policy.rs`).
- Firmware: `crates/aegis-fido-firmware/src/vault_store.rs:1-9`
  (slots `vault/<label>`, quota via `vault/index`, verify-after-write, `alloc`-only)
  e `vendor_exec.rs:27-30` (chaves NVS `key_slots_v1`, `oath_creds_v1`, PIN hash).
- Migrações de chaves: `src/migrations/keys_oath_v6.rs`, `src/migrations/vault_v7.rs`.

Já é módulo? Núcleo sim; camada NVS (`vault_store`, `oath_store`, `piv_store`)
são três módulos finos sobre o mesmo `SecureStorage` — bom, mas com lógica
repetida de verify-after-write.

Acoplamentos: `vault_store.rs:19-23` importa `config::DeviceConfig`,
`migrations::vault_v7::VAULT_LIVE_PREFIX`, `persistence::SecureStorage`;
`vendor_exec.rs:11-16` cruza `KeyManager` + `OathApplet` + `ble_gatt` gates +
`piv_store`.

Candidato a módulo: `credential-vault-store` único (fronteira: trait
`NamespacedStore { put/get/delete }` com prefixo + quota + verify-after-write).
Porquê: `oath_store`, `vault_store`, `piv_store` repetem o mesmo padrão NVS.

### 1.7 Wallet (carteira cripto)

Onde mora hoje:

- Núcleo: `crates/aegis-fido-core/src/wallet/` (`types.rs`, `store.rs`,
  `address.rs`, `mod.rs`); deps `sha3/ripemd/bech32/bs58` só p/ wallet
  (`Cargo.toml:39-43`, comentário "wallet/* only").
- Executor firmware: `crates/aegis-fido-firmware/src/wallet_exec.rs:1-19`
  (GEN/LIST/ADDR sobre `WalletStore` em RAM; TLV `0x01/0x02/0x07/0x08`; sem NVS
  aqui, persistência é follow-up com envelope-por-slot).
- Gates: `ble_gatt::authorize_wallet_op` + `is_wallet_op`
  (`freertos.rs:25`, `main.rs:398-419`).

Já é módulo? Parcialmente: núcleo isolado, executor fino, mas despacho vive em
`main.rs:398-419` e a persistência ainda é RAM-only (documentado como follow-up).

Acoplamentos: `wallet_exec.rs:18-19` importa `oath::tlv` (TLV BER compartilhado
com OATH) + `wallet::{CryptoNetwork, WalletError, WalletStore}`; dispatcher
recebe `&mut WalletStore` junto com outros 11 argumentos.

Candidato a módulo: crate `aegis-wallet` (fronteira: `WalletStore` + codec
`export/import_routing` + `wallet_slot_*`; executor vira `WalletService`).
Porquê: deps cripto isoláveis (`sha3/ripemd/bech32/bs58`); TLV compartilhado
vira util comum em vez de import cruzado de `oath::tlv`.

### 1.8 OATH / TOTP / HOTP (incl. auto-typer e WiFi code)

Onde mora hoje:

- Núcleo: `crates/aegis-fido-core/src/oath/` (`types.rs`, `tlv.rs`, `presence.rs`,
  `crypto.rs`, `applet.rs`, `mod.rs`).
- Firmware NVS: `src/oath_store.rs:1-7` (namespaces `oath6/`, TLV total <= 512 B,
  verify-after-write, sem getter de segredo fora do envelope).
- Executor: `vendor_exec.rs:1-7` (PUT/LIST/CODE/DELETE sobre `OathApplet` + NVS,
  snapshot + rollback).
- View/UI: `src/totp_view.rs` (`collect_totp_codes`, `NO_ACCOUNTS_MSG`,
  `TOTP_SHOW_TICKS`; usado em `main.rs:26-31`), `src/wifi_ap.rs:17-19`
  (`GET /oath/code` gera só o código no device, nunca o secret).
- Keyboard: `aegis-fido-usb/src/keyboard.rs` (`OtpTyper`) + `totp_view` p/ long-press 2 s.

Já é módulo? Núcleo sim; fatiado em 3 camadas finas (store/exec/view) que poderiam
ser um módulo só.

Acoplamentos: `oath_store.rs:14-15` importa `migrations::keys_oath_v6` +
`persistence`; `wifi_ap.rs:16` importa `oath::{calculate_code, OathAlgorithm}`;
`vendor_exec.rs:16-17` importa `oath::{applet, tlv}`.

Candidato a módulo: crate `aegis-oath` (fronteira: `OathApplet` + `OathNvsStore` +
`TotpView`; TLV vira `oath::tlv` canônico).
Porquê: fluxo vertical completo (store → exec → view → WiFi/keyboard) com um
contrato de segredo claro (código sai, secret nunca).

### 1.9 PIV / CCID (F4, OpenSC)

Onde mora hoje:

- Applet/framings: `crates/aegis-fido-usb/src/piv.rs` (`PivApplet`) e
  `crates/aegis-fido-usb/src/ccid.rs` (`CcidApduHandler`, `CcidTransport`).
- Backend firmware: `src/piv_store.rs:1-10` (`PivNvsStore` sobre `SecureStorage`;
  `PivFwBackend` sobre `KeyManager` slots 24-27 p/ 9A/9C/9D/9E; EC P-256/P-384,
  RSA = `BadAlg`; resposta R||S cru).
- Dispatch: `src/ccid_dispatch.rs:1-6` (1 `CcidTransport` + `CcidPivHandler` por
  boot; OATH/FIDO sobre CCID fora do escopo v1, `6D 00` honesto).
- Enroll via BLE: `vendor_exec.rs` op `0x39` (`OP_PIV_ENROLL`, `main.rs:374-397`).

Já é módulo? Parcialmente: applet no USB + store no firmware, ligados por traits
`PivRecordStore`/`PivKeyBackend` (`piv_store.rs:16`) — bom desenho, mas em duas
crates sem crate própria.

Acoplamentos: `piv_store.rs:13-19` cruza `credential::key_manager`,
`credential::{KEY_USE_AUTH, KEY_USE_SIGN}`, `crypto::curves::CoseAlgorithm`,
`usb::piv::{PivKeyBackend, PivRecordStore, ...}`, `persistence::SecureStorage`;
colisão de slot vendor falha `NoSlot` sem sobrescrever (`piv_store.rs:5-6`).
`ccid_dispatch.rs:10-17` repete o mesmo leque.

Candidato a módulo: crate `aegis-piv` (fronteira: traits já existentes +
`PivNvsStore` + `PivFwBackend` + `process_ccid_frame`).
Porquê: traits já definem a fronteira; falta só mover os 4 arquivos para uma
crate e quebrar o import direto de `KeyManager`.

### 1.10 Rescue / OTA / Lifetime

Onde mora hoje:

- Rescue: `crates/aegis-fido-core/src/otp/rescue.rs` (`RescueEngine`,
  `RESCUE_TRANSPORT_OP = 0x2E`; `main.rs:16`, `main.rs:246-257`).
- OTA: `src/ota.rs:1-16` (máquina `Idle → Staged → Verified → Applying →
  Committed`, manifesto 104 B, streaming sem RAM de imagem, Ed25519 fail-closed)
  + `persistence.rs:18-22` (`OtaSink`, `FlashOtaSink`, `dispatch_ota_request`).
  Chave ativa em `main.rs:502-513` (`ota_active_pubkey`: zeros fail-closed em
  release, `OTA_TEST_PUBKEY` em test-mode).
- Lifetime: `core/src/lifetime.rs` + `src/lifetime_trace.rs:19`
  (reexporta `record/snapshot/write_dump`); `ltrace!` com custo zero sem
  `debug-terminal` (`Cargo.toml:20`, `binding.rs:68`).
- Diagnóstico: `TEST_LIFETIME_DUMP` (`test_hooks.rs:20-31`, `main.rs:192-202`).

Já é módulo? Sim, os três são módulos com contratos claros; OTA tem acoplamento
residual com `persistence` (sink) e com `main.rs` (chave + `FIRMWARE_VERSION`
em `main.rs:474-475`).

Acoplamentos: `persistence.rs:18-22` importa `ota::{OtaManifest, OtaSink,
OtaState, ...}` + `ed25519_dalek`; `ota_provisioned` (`main.rs:516-524`) cruza
`efuse` + `provision`.

Candidato a módulo: `update-rescue` (fronteira: `OtaState` + `OtaSink` trait +
`RescueEngine`; chave via `OtaKeyProvider` injetado em vez de constante em
`main.rs`).
Porquê: fail-closed e streaming já coesos; isolar a chave tira `#[cfg(test-mode)]`
do dispatcher.

### 1.11 Binding / Pairing / Proximidade (walkaway)

Onde mora hoje:

- Binding: `src/binding.rs:1-30` (claim/challenge/verify/release, NVS
  `app_bind_pub` + `app_bind_id`, AEGN v1, `NEED_BINDING 0x05` só BLE/WiFi).
- Pairing: `src/pairing.rs:1-12` (hold 5 s `LONG_PRESS_MS=5000`, janela 60 s,
  `no_std`, relógio injetado) + `src/pairing_flow.rs:8` + `src/pairing_led.rs`.
- Proximidade: `src/proximity.rs:1-12` (RSSI, trava < -75 dBm por 10 s, histerese
  5 dB, `Locked` só via `confirm_lock`, `no_std`, tempo injetado) + `mod prox_sched`
  em `main.rs:567-797` (tick ~1 Hz, beacon `0xFFFE`, gates
  `should_adv_proximity`, coex USB) + `#[cfg(feature = "proximity")]` em
  `lib.rs:35-36` e `ble_nimble.rs:470-552`.
- Recovery (re-claim): `src/recovery.rs:1-12` (PIN 4-6, 8 tentativas em NVS,
  wipe do vínculo com UP).

Já é módulo? Lógica pura sim (`binding`, `pairing`, `proximity`, `recovery` são
`no_std` e testáveis); fiação não (2 pontos `Paired` + `BIND_RELEASE` /
`RECOVERY_UNLOCK` vivem só no loop legado — gap documentado em `main.rs:543-564`).

Acoplamentos: `binding.rs:29-30` importa `lifetime_trace` + `persistence`;
`ble_nimble.rs:37` importa `pairing::{PairingManager, PairingState}`;
`main.rs:341-346` limpa `proximity::delete_proximity_key` no `BIND_RELEASE`.

Candidato a módulo: `trust-binding` (fronteira: `BindingManager` + `PairingManager`
+ `ProximityMonitor` + `RecoveryPolicy` atrás de um `TrustFacade`; NVS via
`SecureStorage` injetado).
Porquê: os quatro decidem "este app/dispositivo pode configurar?" — hoje cada
transporte reimplementa a ordem binding → UP → PIN.

### 1.12 WiFi AP / Station / mDNS

Onde mora hoje:

- AP: `src/wifi_ap.rs:1-30` (SSID `AegisKey-XXXX`, senha em NVS cifrada,
  AP só em pareamento/menu, `POST /ctap`, `POST /config/wifi`,
  `GET /oath/code`).
- Station: `src/wifi_station.rs` (referenciado em `binding.rs:933-935`).
- mDNS: `src/mdns.rs:1-6` (`aegiskey-XXXX.local`, só fora de pareamento com
  fallback AP, núcleo sem I/O, `start_mdns_esp` no ESP).
- Rádio C: `components/aegis_wifi/aegis_wifi.c`.
- Feature: `wifi` (`Cargo.toml:17`); coexistência `USB > WiFi > BLE`.

Já é módulo? Parcialmente: `wifi_ap`/`wifi_station`/`mdns` separados, mas HTTP
mínimo, mDNS e gates de binding dividem constantes sem facade.

Acoplamentos: `wifi_ap.rs:15-17` importa `persistence`, `oath`, `policy
{UpAndPin, UpPolicy}`; testes em `binding.rs:929-935` cruzam `wifi_ap` +
`wifi_station` + `oath`.

Candidato a módulo: `net-wifi` (fronteira: `WifiNet { ap_start/stop,
station_join, mdns_announce }` + `HttpConfig` com os 3 endpoints; rádio C atrás
de trait como no BLE).
Porquê: mesmo padrão NimBLE que já funciona; tira HTTP/mDNS do caminho do
dispatcher.

### 1.13 Display / LED / UI (exemplo de modularização pronta)

Onde mora hoje:

- Subsistema: `src/display/mod.rs:1-8` (T-Display-S3 ST7789 170x320 vs
  DevKitC-1 LED + espelho serial).
- Gate: `has-display` (`Cargo.toml:12` = `dep:embedded-graphics` optional; `:13-14` `board-t-display`/`board-ttgo-classic` implicam `has-display`
  features reais `board-devkitc` (`:11`, default `:10`) headless, `ble` (`:15`), `wifi` (`:17`), `proximity` (`:18`), `test-mode` (`:22`), `freertos` (`:24`)); `lib.rs:51-53` reexporta
  `AegisUiRenderer/DisplayBuffer` só com a feature.
- Stub: `display/mod.rs:131-175` (`#[cfg(not(feature = "has-display"))]`
  DevKitC-1 headless constrói `DisplayManager` com o mesmo contrato `new`/`init_hardware`/`set_screen`/`tick` + `apply_screen_led_effect` compartilhado, sem `todo!()` quando off).
- UI: `src/display/ui.rs` (gates `has-display` em ~20 pontos), driver
  `src/display/st7789.rs:10` (`extern "C"`, `aegis_display_st7789.c`,
  `include/aegis_display.h`), LED compartilhado `display/mod.rs:29-58`
  (`apply_screen_led_effect`). Periféricos reais (R14): LCD ST7789 (T-Display-S3 320x170 / TTGO-Classic 135x240) + WS2812 RGB + espelho serial no headless; sem mudar comportamento.
- Jornada UI: `src/ui_journey.rs`, `src/totp_view.rs`, telas via `UiScreen`
  (`display/mod.rs:21`).

Já é módulo? Sim — o modelo a copiar: feature-gate por placa/capacidade,
stub com API estável, LED sincronizado nos dois caminhos.

Acoplamentos (residuais): `button.rs:196-198` e `display/mod.rs:65-114`
espalham `#[cfg(board-ttgo-classic)]`; `main.rs:1550-1560` escolhe tela por
`board-t-display/board-ttgo-classic`.

Candidato a módulo: nenhum (referência). Próximo passo seria só extrair
`UiScreen` + `DisplayManager` trait para crate se outra placa LCD surgir.
Porquê: coesão total, stub prova o contrato sem hardware.

### 1.14 Persistência NVS / eFuse / Provisionamento

Onde mora hoje:

- Envelope: `src/persistence.rs:1-7` (AES-256-GCM, nonce único, HKDF-SHA256 de
  eFuse Master Key + Device Salt, teto fail-closed por `store`).
- Backend: `src/nvs_backend.rs:22` (`FlashStorageBackend`, `MockFlashBackend`,
  `StorageError`).
- eFuse: `src/efuse.rs:1-12` (BLOCK7 Master Key, BLOCK8 Salt, lock permanente;
  `RamEfuseStorage`/`MockEfuseStorage` p/ host).
- Provision: `src/provision.rs` (`load_device_keys`, usado em `main.rs:28`,
  `main.rs:518`), `src/identity.rs`, `src/config.rs`
  (`DeviceConfig::max_vault_slots`), `src/migrations/`.
- Regra: sem eFuse burn fora de provisionamento; `vault_store.rs:8` repete a
  regra ("no eFuse burn").

Já é módulo? Sim na prática: `SecureStorage` + `FlashStorageBackend` é a
fronteira que todos os stores usam; mocks só em `#[cfg(test)]`
(`binding.rs:21`, `recovery.rs:13`).

Acoplamentos: todos os stores importam `persistence::{FlashStorageBackend,
SecureStorage}` (`oath_store.rs:15`, `piv_store.rs:19`, `vault_store.rs:23`,
`binding.rs:30`, `nvs_backend.rs:22`); `persistence.rs:18-22` puxa `ota` para
dentro (sink) — inversão a desfazer.

Candidato a módulo: `storage-secure` (fronteira: `SecureStorage` + `OtaSink` como
trait em `ota`, não em `persistence`).
Porquê: um único ponto de envelope AEGN v1; quebra o ciclo `persistence ↔ ota`.

### 1.15 Test-hooks / test-mode

Onde mora hoje:

- Manifesto: `src/test_hooks.rs:1-14` (ÚNICA fonte de nomes `TEST_*` fora de
  `#[cfg(test)]`; regra: nome aqui + handler gated + doc + `CI-GREP: TEST-HOOK`).
- Handlers: `#[cfg(feature = "test-mode")]` em `main.rs:64-82`,
  `main.rs:192-202`, `mod freertos_test_mode` (`main.rs:989-1204`),
  `binding.rs:69` (`binding_bypass_enabled`), `lifetime_trace.rs:62-157`.
- Prova de limpeza: `scripts/check-release-clean.py` (strings do artefato).
- Docs: `docs/test-hooks.md`.

Já é módulo? Sim como disciplina (manifesto + gates + CI), não como crate —
e está certo assim: hooks são transversais por definição.

Acoplamentos: `test-mode` toca `main.rs` (reboot download, USB reconnect,
serial `read_chunk`), `binding` (bypass de vínculo), `ota` (chave de lab
`main.rs:497-500`), `freertos_test_mode` (latch UP, janela de pareamento).

Candidato a módulo: manter transversal; extrair só `TestHookRegistry`
(manifesto tipado + `classify_*` como em `main.rs:1024-1041`) se crescer.
Porquê: o valor está no gate, não no agrupamento; crate própria espalharia
`#[cfg]` em vez de concentrar.

### 1.16 Tooling / host (scripts e agentes)

Onde mora hoje:

- E2E e probes: `tools/test_aegiskey_rust.py`, `tools/e2e_user_test.py`,
  `tools/e2e_zero_press.py`, `tools/validate_aegiskey.py`,
  `tools/wallet_gate_probe.py`, `tools/ota_deny_probe.py`,
  `tools/killswitch_deny_probe.py`, `tools/wedge_hunt.py`,
  `tools/pair_trigger_probe.py`, `tools/led_probe.py`, `tools/ble_hold_bond.py`,
  `tools/ble_connect_test.py`, `tools/device_ops.py`, `tools/usb_*.py`,
  `tools/ota_server.py`, `tools/factory_provision.py`, `tools/server.py`,
  `tools/app_simulator.py`, `tools/t_display_simulator.py`.
- Agentes de proximidade por SO: `tools/host/win|linux|macos/proximity_agent.py`
  (+ testes `test_proximity_agent.py` e READMEs).
- Geração UniFFI: `tools/uniffi-gen/` (fora do workspace, `Cargo.toml:9`).
- Monitor: `tools/live_monitor.py`, `tools/stability_watch.py`, `tools/diag_now.py`.

Já é módulo? Sim por arquivo/script, sem empacotamento — adequado para tooling.

Acoplamentos: cada probe conhece opcodes/status do wire (`0x05 NEED_BINDING`,
gates binding → UP → PIN); `ota_server.py` + `ota_registry.json.example`
espelham o manifesto OTA de 104 B.

Candidato a módulo: `host-sdk` (fronteira: um cliente Python/Rust com
`VendorOps` TLV + `authorize_*` espelhados; probes viram asserções sobre o SDK).
Porquê: hoje cada script duplica framing TLV/CBOR; um SDK elimina drift
:app ↔ device.

---

## 2. Tabela-resumo por capacidade

| Capacidade | Onde mora | Já é módulo? | Acoplamentos que prendem | Fronteira proposta + porquê |
|---|---|---|---|---|
| USB CTAPHID/CCID/Keyboard/WinUSB | `aegis-fido-usb/src/`, `components/aegis_usb/`, `usb_descriptors.rs`, `main.rs:50-82` | Parcial (crate OK, C + `#[cfg]` no dispatcher) | FFI direto em `main.rs`; `board-ttgo-classic` troca backend por `#[cfg]` | `transport-usb` (`UsbBackend` trait). 1 linha: framing 64 B é idêntico, só o backend muda. |
| Serial/UART CTAPHID | `serial_ctaphid.rs`, `main.rs:157-185` | Módulo fino, sem trait | `#[cfg(board-*)` no dispatcher; importa gates do BLE | `transport-serial` (`SerialBackend`). 1 linha: isola Classic vs S3/S2 atrás de um trait. |
| BLE GATT 0xFFFD | `ble_gatt.rs`, `main.rs:212-439` | Política sim, dispatch não | `ble_dispatch_complete` com 12 args em `main.rs` | `transport-ble-gatt` (dispatch injetável). 1 linha: política já `no_std`, falta tirar o `match` do `main`. |
| NimBLE + rádio C | `ble_nimble.rs`, `components/aegis_ble/` | Sim (modelo) | Imports de `pairing/lifetime` na política | Manter; `BleRadioBackend` se houver 2o stack. 1 linha: política testável + C atrás de FFI já funciona. |
| CTAP2/CBOR | `core/src/ctap/` | Sim (nada a fazer) | Só via `CtapEngine` (saudável) | Nenhuma. 1 linha: coesão por comando, sem drift. |
| Credenciais/KeyManager/Vault core | `core/src/credential/`, `core/src/vault/` | Sim | Uso legítimo via API | Nenhuma no core. 1 linha: núcleo estável, mexer só por bug. |
| Stores NVS (oath/vault/piv) | `oath_store.rs`, `vault_store.rs`, `piv_store.rs` | Três finos repetidos | Todos importam `SecureStorage`; verify-after-write triplicado | `NamespacedStore` único. 1 linha: mesmo padrão NVS, 3 implementações. |
| Wallet | `core/src/wallet/`, `wallet_exec.rs` | Parcial (RAM-only) | Importa `oath::tlv`; dispatch em `main.rs:398-419` | Crate `aegis-wallet`. 1 linha: deps cripto isoláveis, TLV vira comum. |
| OATH/TOTP | `core/src/oath/`, `oath_store.rs`, `vendor_exec.rs`, `totp_view.rs` | Fatiado em 4 | Store/exec/view/WiFi espalham `oath::` | Crate `aegis-oath`. 1 linha: fluxo vertical com um contrato de segredo. |
| PIV/CCID | `usb/src/piv.rs`, `usb/src/ccid.rs`, `piv_store.rs`, `ccid_dispatch.rs` | Traits OK, sem crate | Cruza `KeyManager` + `usb::piv` + `SecureStorage` | Crate `aegis-piv`. 1 linha: traits já desenham a fronteira. |
| Rescue/OTA/Lifetime | `otp/rescue.rs`, `ota.rs`, `lifetime.rs` + `lifetime_trace.rs` | Sim | `persistence ↔ ota` (sink); chave OTA em `main.rs:497-513` | `OtaKeyProvider` injetado. 1 linha: tira `#[cfg(test-mode)]` do dispatcher. |
| Binding/Pairing/Proximidade/Recovery | `binding.rs`, `pairing*.rs`, `proximity.rs` + `prox_sched`, `recovery.rs` | Lógica sim, fiação não | Gaps FreeRTOS (`main.rs:543-564`); `BIND_RELEASE` só no legado | `trust-binding` (`TrustFacade`). 1 linha: 4 módulos decidem a mesma pergunta "pode configurar?". |
| WiFi AP/Station/mDNS | `wifi_ap.rs`, `wifi_station.rs`, `mdns.rs`, `components/aegis_wifi/` | Parcial | HTTP + mDNS + gates sem facade; `binding.rs:929-935` cruza os três | `net-wifi` (réplica do padrão NimBLE). 1 linha: rádio C atrás de trait tira HTTP do dispatcher. |
| Display/LED/UI | `display/`, `ui_journey.rs`, `led.rs` | Sim (referência) | `#[cfg(board-*)` residuais (`button.rs:196-198`, `display/mod.rs:65-114`) | Nenhuma. 1 linha: stub com API estável é o padrão a copiar. |
| Persistência/eFuse/Provision | `persistence.rs`, `nvs_backend.rs`, `efuse.rs`, `provision.rs` | Sim (fronteira `SecureStorage`) | `persistence` importa `ota` (inversão) | `storage-secure` (sink em `ota`). 1 linha: um ponto de envelope AEGN v1. |
| Test-hooks | `test_hooks.rs`, `#[cfg(test-mode)]` espalhado | Disciplina sim, crate não (correto) | Transversal por desenho | `TestHookRegistry` se crescer. 1 linha: o valor é o gate, não o agrupamento. |
| Tooling/host | `tools/*.py`, `tools/host/*/`, `tools/uniffi-gen/` | Scripts soltos (adequado) | Cada probe duplica TLV/CBOR/wire | `host-sdk`. 1 linha: um SDK elimina drift app ↔ device. |
| FreeRTOS scheduler | `freertos.rs`, `main.rs:446-467`, `main.rs:1438+` | Módulo, em construção | Dispatcher legado ainda dono do BLE completo | Completar migração task-a-task. 1 linha: scheduler canibaliza o super-loop aos poucos. |

---

## 3. Ordenação prática

### 3.1 Já modularizado — nada a fazer

- CTAP2/CBOR (`core/src/ctap/`), credenciais/vault core, display stub
  (`display/mod.rs:137-144`), NimBLE-policy (`ble_nimble.rs:1-26`),
  persistência (`SecureStorage`), test-hooks (manifesto + CI), lifetime
  (`lifetime.rs` + `lifetime_trace.rs:19`).

### 3.2 FÁCIL — stub com API estável (como foi o display)

- `NamespacedStore` unificando `oath_store`/`vault_store`/`piv_store`
  (mesma assinatura `put/get/delete` + verify-after-write; risco baixo, só NVS).
- `OtaKeyProvider` (tira `OTA_TEST_PUBKEY`/`OTA_RELEASE_PUBKEY` de
  `main.rs:483-513` para um provider injetado; fail-closed preservado).
- `TestHookRegistry` (só se `TEST_*` passar de ~15; hoje `test_hooks.rs:20-31`
  basta).
- `net-wifi` facade sobre `wifi_ap`/`wifi_station`/`mdns` (padrão copiado do
  `ble_nimble`; sem mexer no rádio C).

### 3.3 MÉDIO — extrair para crate

- `aegis-wallet` (`core/src/wallet/` + `wallet_exec.rs`; levar `sha3/ripemd/
  bech32/bs58` junto; TLV `0x01/0x02/0x07/0x08` documentado em
  `wallet_exec.rs:10-12`).
- `aegis-oath` (`core/src/oath/` + `oath_store.rs` + TOTP view + `vendor_exec`
  OATH; atenção ao `validate_v6_label` em `oath_store.rs:14`).
- `aegis-piv` (`usb/src/piv.rs` + `usb/src/ccid.rs` + `piv_store.rs` +
  `ccid_dispatch.rs`; slots 24-27 em `piv_store.rs:22` são o contrato a
  congelar).
- `trust-binding` (`binding` + `pairing` + `proximity` + `recovery`; fechar os
  gaps FreeRTOS listados em `main.rs:543-564` antes de mover).
- `host-sdk` (`tools/`; unificar `VendorOps` TLV hoje duplicado em
  `wallet_exec.rs`, `oath/tlv.rs` e nos probes).

### 3.4 DIFÍCIL / arriscado — desentrelaçar com cuidado

- Dispatcher `main.rs` (`ble_dispatch_complete` + `run_authenticator` +
  `run_authenticator_freertos`): 4000+ linhas, 12 dependências por função,
  `extern "C"` + `#[cfg(board-*)]` + `#[cfg(test-mode)]` entrelaçados.
  Estratégia: extrair um transporte por vez atrás de trait, nunca o `main`
  inteiro de uma vez.
- Driver BLE C (`components/aegis_ble/aegis_ble_nimble.c`): rádio real,
  bonding NVS do stack, coexistência; qualquer refator aqui exige bancada
  com analisador BLE, não só `cargo test`.
- Driver USB C + `ccid_device.c`: dono do PHY interno (GPIO19/20);
  remark em `main.rs:51` ("dono único do PHY") — mexer aqui derruba USB e
  serial juntos.
- Persistência ↔ OTA (`persistence.rs:18-22`): inversão de dependência com
  dados cifrados em campo; migração errada perde credenciais (ver
  `src/migrations/` antes de tocar).

---

## 4. Regras de módulo do projeto (deduzidas do que já funciona)

1. Feature-gate por placa/capacidade: `board-devkitc`, `board-t-display`
   (`has-display`), `board-ttgo-classic` (`has-display`), `ble`, `menu`,
   `wifi`, `proximity`, `freertos` (`Cargo.toml:10-24`); `has-display`
   implica `dep:embedded-graphics` (`Cargo.toml:12`).
2. Stub com API estável: headless compila o mesmo contrato
   (`display/mod.rs:137-144`); `not(feature)` sempre constrói, nunca `todo!()`.
3. Fail-closed por padrão: zeros negam (`OTA_RELEASE_PUBKEY` em `main.rs:483-486`),
   `None` sem stack (`prox_sched::prox_fob_id`, `main.rs:584-590`), `Locked` só
   via `confirm_lock` (`proximity.rs:5`), `6D 00` honesto fora do escopo
   (`ccid_dispatch.rs:5-6`).
4. Sem eFuse burn fora de provisionamento (`vault_store.rs:8`, `efuse.rs:1-12`;
   `RamEfuseStorage` no host).
5. `test-mode` só em `test-mode`: nomes no manifesto (`test_hooks.rs:1-14`),
   handlers atrás de `#[cfg(feature = "test-mode")]`, release provado por
   `scripts/check-release-clean.py` (`test_hooks.rs:10-11`).
6. Núcleo sem I/O: `no_std` + `alloc`-only + relógio injetado
   (`binding.rs:18-19`, `pairing.rs:6`, `proximity.rs:8`, `ota.rs:18`,
   `serial_ctaphid.rs:20`, `mdns.rs:6`); FFI (`extern "C"`) só nas bordas
   (`ble_nimble.rs:327`, `st7789.rs:10`, `mdns.rs:132`, `main.rs:50-82`).
7. Host testável: shims inertes no host (`ble_nimble.rs:11`), mocks só em
   `#[cfg(test)]` (`binding.rs:21`, `recovery.rs:13`), `cargo test` como porta
   de entrada (sem bancada para política).
8. Segredos nunca no fio/log: só metadados e códigos (`vendor_exec.rs:7`,
   `wifi_ap.rs:8`, `ota.rs` sem chaves em log, `prox_sched` em `main.rs:566`).
9. Ordem de gates congelada: binding → UP → PIN para CONFIG
   (`vendor_exec.rs:2-4`, `binding.rs:72-76`); USO nunca exige vínculo
   (`binding.rs:88-93`); USB/CTAP nunca vê `NEED_BINDING`
   (`binding.rs:16-17`).
