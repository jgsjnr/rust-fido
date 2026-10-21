# Sessão 20/10 — F4 CCID/PIV fim-a-fim + fix BLE + flash sem botão

Data: 20/10/2026. Branch: `fd/finalizacao-linux`. Objetivo: fechar o F4
(CCID/PIV no USB), destravar o F5/D08, e tornar o flash sem-botão o padrão.
Estado final: F4 device completo e provado no fio; OpenSC reconhece o cartão
e carrega o driver PIV, mas o primeiro `SCardTransmit` morre no host
(`0x45D`) sem nenhum byte no USB. Pendente: prova fim-a-fim (precisa de
USBPcap com admin ou 2º PC).

## 1. F4 lado device (firmware + C)

### C — driver CCID (`crates/.../components/aegis_usb/`)
- **CRIADO `ccid_device.c`**: class driver CCID minimalista registrado via
  hook oficial `usbd_app_driver_get_cb` (TinyUSB do IDF não tem CCID).
  Bulk OUT/IN + interrupt notify; remontagem de frames (header 10 B +
  dwLength); fila FreeRTOS de frames completos; `control_xfer_cb` dá STALL
  (class-specific não suportado no v1); `xfer_cb` trata conclusão IN/OUT e
  re-arma; logs de diagnóstico (`open itf=`, `rx frame`, `tx rpdu`, `xfer`,
  `ctrl stage`) — TEMPORÁRIOS, remover antes do release.
- **`aegis_usb.c` (ALTERADO)**: descritor de configuração COMPOSTO —
  HID FIDO2 intacto em 1º lugar (VID `0x303A`/PID `0xAE61`) + interface CCID
  classe `0x0B` em 2º com funcional de **54 B exatos** (achei e corrigi:
  faltava `dwMaxDataRate`; `wTotalLength` mentia), 3 EPs
  (bulk OUT `0x02` / bulk IN `0x82` / intr IN `0x83`).
  Valores finais: `dwProtocols`=T=1, `dwFeatures=0x000C0000`
  (APDU-level; com `0` o host falava TPDU cru), `dwDefaultClock` =
  `dwMaximumClock` = 3571 kHz (= 9600×372/1000, coerente com TA1=0x11),
  `dwDataRate` = `dwMaxDataRate` = 9600, `dwMaxCCIDMessageLength` = 2048.
  + `aegis_usb_reconnect()` (`tud_disconnect/connect`).
- **`include/aegis_usb.h` (ALTERADO)**: FFI `aegis_ccid_pop_frame`,
  `aegis_ccid_send`, `aegis_usb_reconnect` (+ doc).
- **`CMakeLists.txt` (ALTERADO)**: adicionado `ccid_device.c` ao `SRCS`.

### Rust — transporte + applet
- **`crates/aegis-fido-usb/src/ccid.rs` (ALTERADO)**:
  - `CcidTransport::process_ccid_message_store` (novo): espelha
    `process_ccid_message` mas serve o PIV via `handle_store` com
    NVS+`KeyManager` reais; applet persiste no transporte entre frames
    (bug real de estado achado e corrigido: handler recriado por frame
    perdia `pin_verified`).
  - `error_response` (novo): RPDU de erro p/ frame malformado — nunca
    silencia (silêncio travava o `SCardConnect` em hang).
  - `parameters_response_with` (novo): ecoa os parâmetros do host
    (eco fixo quebrava com BWI/CWI `0x75` vs `0x4D`).
  - `0x61`/`0x6D` (SET/RESET PARAMETERS): ecoam T=1.
  - `0x73`→`0x84` SetDataRateAndClock: ecoa clock/rate; zeros do host viram
    defaults 3571 kHz / 9600 bps (0/0 matava o Transmit seguinte).
  - SlotStatus sempre `0x00` (presente); `0x01/0x02` faziam o Windows
    concluir "sem cartão".
  - `AEGIS_ATR` final = PIVKey uTrust
    `3b:96:11:81:21:75:75:54:72:75:73:74:73` (T=1 only, TCK válido, na
    tabela do OpenSC). Tentados antes: custom (OpenSC não reconhecia),
    T=1+TCK (PROTO_MISMATCH resolvido, mas sem match), ID-One Cosmo
    (T=15 → UsbCcids aborta), Feitian E0 (Di=8 reservado → aborta).
  - Testes novos: `store_*` (5, caminho NVS), `set_reset_*`,
    `set_data_rate_and_clock_ecoam`, `set_data_rate_zero_responde_defaults`,
    `atr_tck_valido` (estrutural), `frame_malformado_responde_erro_nunca_silencio`,
    `ccid_power_select_verify_gen_auth_fim_a_fim` (no firmware).
- **`crates/aegis-fido-firmware/src/ccid_dispatch.rs` (CRIADO)**: dono do
  `CcidTransport` + `NoExtraApplets` (OATH/FIDO = `6D 00` honesto);
  `process_ccid_frame` com fallback p/ `error_response`.
- **`crates/aegis-fido-firmware/src/lib.rs`**: `pub mod ccid_dispatch`.
- **`crates/aegis-fido-firmware/src/main.rs`**: FFI CCID, `ccid_transport`
  persistente, poll C2 (USB section C), op vendor `0x39` nos gates
  BLE+serial, handler `TEST_USB_RECONNECT`, `esp_ble_preinit` no boot,
  gate `BleStartGate` no adv, `[CCID] rx/tx` debug (temporário).
- **`ble_nimble.rs`**: `BleStartGate` (backoff 5s, 3 por borda) + teste
  dedicado + `esp_ble_preinit`.
- **`ble_gatt.rs`**: `OP_PIV_ENROLL = 0x39` + `is_piv_enroll_op`.
- **`vendor_exec.rs`**: braço `0x39` (binding→UP, sem PIN;
  `pin_len||pin(6-8)||puk(8)`) + 3 testes.
- **`serial_ctaphid.rs`**: `0x39` nas listas pairing/UP/deny + `flush_input()`
  (PurgeComm/tcflush) + dreno de 0,4 s pós-match no `send_text_line`
  (corrige corrida do leitor UART que quebrava pareamento).
- **`piv_store.rs` / `key_manager.rs` / `curves.rs`** (base anterior, já
  commitada): `PivNvsStore`+`PivFwBackend`, `KeyManager::public_sec1`,
  `to_sec1_uncompressed`.
- **`components/aegis_ble/aegis_ble_nimble.c`**: `aegis_ble_preinit()` +
  log de heap no `nimble_port_init` falho.
- **`usb_descriptors.rs` + `identity.rs`**: serial `AEGIS-S3-0002`
  (re-enumeração limpa; tripwire atualizado de propósito).

### F4 lado app (lane designer, revisado e aceito)
- **CRIADO `app-android/.../ui/PivScreen.kt`**: rota `piv`, PIN+confirmação+PUK,
  validação local, status `0x00/01/04/05`, sem logar segredos (`wipe`).
- **ALTERADOS `ble/VendorOps.kt`** (`OP_PIV_ENROLL`, `pivEnrollRequest`),
  **`ble/BleContract.kt`** (`isVendorOp` até `0x39`), **`MainActivity.kt`**
  (rota), **`ui/DeviceControlScreen.kt`** (botão). `assembleDebug` verde.

## 2. Ferramentas e scripts
- **CRIADO `tools/piv_enroll_live.py`**: prova viva do `0x39`
  (0x00 na 1ª, 0x04 AlreadyProvisioned depois).
- **CRIADO `tools/raw_transmit.py`**: SCardTransmit cru via ctypes
  (isola OpenSC — falha igual: 0x45D, depois 0x54F; prova que o problema
  não é o OpenSC).
- **CRIADO `tools/need_hands.py`**: banner + bipes p/ chamar o operador.
- **`tools/flash_soft.py`** (já existia, mantido): TEST_DOWNLOAD + esptool
  `--before no-reset` — zero botões.
- **`scripts/common.ps1`**: `Invoke-FirmwareFlash` agora tenta
  TEST_DOWNLOAD por software primeiro (fallback manual só se sem ack) +
  retry de baud; `Clear-StaleIdfSysBuild` (licão aprendida: cargo NÃO
  recompila o C do `esp-idf-sys` ao mudar `.c` — apaga os build dirs p/
  forçar reconfigure; `cargo clean -p` não adianta).
- **CRIADO `tools/e2e_user_test.py::--phase bench`** (`B01-B04` + janela):
  baseline F7 (PING 21ms, GetInfo 67ms, MC ~1250ms, GA ~1359ms).

## 3. Provas no hardware (20/10, firmware diag test-mode, COM7)
- Bench 5/5, base 9/11 (2 DIVERGENTE conhecidas e documentadas: T06/T06b,
  janela residual — flake histórico, sem relação), enroll 0x39 ao vivo
  (0x00 → 0x04), **D08 6/6** (bad-sig nega, 20 KiB em CHUNKs, FINISH verify
  real, COMMIT sem UP nega / com UP grava marker, ABORT limpa).
- Host: 459 testes verdes (workspace), clippy zero, release-clean OK.

## 4. Saga OpenSC (estado: handshake 100%, XFR não sai do host)
Correções com evidência no fio: SlotStatus, TCK, T=1-only, `dwFeatures`
APDU-level (host falava TPDU: PPS `FF1111FF`, I-blocks), descritor exato
54 B, clock 3571 kHz, eco de parâmetros, `0x73`→`0x84`, ATR uTrust,
`error_response` anti-silêncio, TEST_USB_RECONNECT.
**Pendente**: primeiro XFR morre no WUDF (`0x45D`) sem byte no fio.
Próximos passos: USBPcap com admin OU 2º PC (isola driver local);
telefone com Windows limpo decide em 5 min.

## 5. Fix BLE (causa raiz real do antigo "travamento de energia")
`nimble_port_init` falhava intermitente → retry a cada poll reinicializava
por cima → leak → `Malloc failed` → panic Interrupt WDT (`emi.c:164`,
capturado no boot). NÃO era energia. Fix: `BleStartGate` + preinit no boot
+ heap no log. D08 passou em seguida. Uptime estável desde então.

## 6. Commits (branch `fd/finalizacao-linux`, pushed; ver `git log`)
Do mais antigo ao mais novo na sessao: base PIV + sync C + TEST_DOWNLOAD,
flash sem botao como padrao, SEC1 KeyManager + NVS particao storage + bench,
regras OpenCode + gitignore, F4 driver C + dispatch PIV + enroll 0x39, bench
5/5 + enroll ao vivo + fix leitor UART, tela PIV Android + auditoria CCID,
gate BLE + preinit (panic emi.c), D08 6/6, disciplina stale-object do C,
0x73/0x84 SetDataRate, ATRs ID-One/uTrust/Feitian/uTrust, TCK valido,
TEST_USB_RECONNECT, notify off/on, dump CCID, nunca-silencia (anti-hang),
dwFeatures APDU-level (TPDU cru), descritor 54B exato, clock 3571 kHz,
eco dinamico de parametros, serial 0002 + raw_transmit, docs e diario.

## 7. Pendências
1. OpenSC fim-a-fim (USBPcap ou 2º PC) — único item técnico aberto.
2. Remover logs temporários de debug (C: `rx frame`/`tx rpdu`/`xfer`/`ctrl`/`open itf`; Rust: `[CCID] rx/tx`; `is_mounted` não usado foi removido).
3. Merge p/ `main` (F6) após (1).
4. Com o usuário: H1–H7 físico, instalar APK nova, bond pelo app do celular,
   decisão do gesto hold, USB nativo plugado no PC já está.
