//! Authenticator run loops (moved from `main.rs`; single-owner audit slice).
//!
//! - `run_authenticator`: legacy poll loop (USB + serial + BLE + CCID).
//! - `run_authenticator_freertos`: FreeRTOS variant (usb + button + housekeeping).
//! - Helpers moved with the loops: FFI shims, `kprintln!`, `extract_rp_and_user`,
//!   OTA version/key helpers, `freertos_test_mode`, thin serial shims and the
//!   BLE complete-message dispatcher (thin composition, no logic fork).
//!
//! Contract (R15/R16, MATRIZ-TODO sec. 9): wire behavior preserved byte for
//! byte; time arrives via `now_ms`/`now_secs` args, never from a host clock;
//! no secrets in logs; hardware only via declared FFI + lib stores/radios.
//! `main.rs` keeps only thin `app_main` wiring over `run::*`.
#[cfg(target_os = "espidf")]
use crate::led::LedEffect;
#[cfg(all(feature = "debug-terminal", target_os = "espidf"))]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};
use crate::{
    button::{DualButtonManager, EspBootButtonInput, EspKeyButtonInput},
    display::{DisplayManager, UiScreen},
    efuse::{EfuseManager, RamEfuseStorage},
    led::{EspWs2812Output, Ws2812Controller},
    persistence::{PlatformFlashBackend, SecureStorage},
    provision::load_device_keys,
    totp_view::{collect_totp_codes, NO_ACCOUNTS_MSG, TOTP_SHOW_TICKS},
    usb_descriptors,
    watchdog::Watchdog,
};
#[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
use crate::{
    ota::{OtaState, OP_OTA_COMMIT},
    ota_store::{
        dispatch_ota_request, is_ota_op, FlashOtaSink, OtaRequestCtx, OTA_STATUS_FAIL,
        OTA_STATUS_OK,
    },
};
#[cfg(target_os = "espidf")]
use aegis_fido_core::ctap::CTAP_CMD_RESET;
use aegis_fido_core::ctap::{CtapEngine, CTAP_CMD_GET_ASSERTION, CTAP_CMD_MAKE_CREDENTIAL};
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::otp::rescue::{RescueEngine, RESCUE_TRANSPORT_OP};
use aegis_fido_core::wallet::WalletStore;
use aegis_fido_usb::ctaphid::CtapHidManager;
#[cfg(target_os = "espidf")]
use aegis_fido_usb::ctaphid::{
    CtapHidFramer, RawPacket, CAPABILITY_CBOR, CAPABILITY_WINK, CMD_CANCEL, CMD_CBOR, CMD_INIT,
    CMD_MSG, CMD_PING, CMD_WINK, PACKET_SIZE, STATUS_UPNEEDED,
};
use core::time::Duration;

#[cfg(target_os = "espidf")]
extern "C" {
    // USB-OTG (TinyUSB) ATIVO no dispatcher FreeRTOS: dono único do PHY
    // interno (GPIO19/20); console primário no UART0 (sdkconfig).
    #[allow(dead_code)]
    fn aegis_usb_init() -> esp_idf_sys::esp_err_t;
    fn aegis_usb_is_mounted() -> bool;
    fn aegis_usb_send_report(packet: *const u8, len: u16) -> bool;
    fn aegis_usb_pop_packet(out_buf: *mut u8, max_len: u16) -> u16;
    // F4: CCID bulk (driver C `ccid_device.c`; frames completos remontados).
    // `pop` devolve 0 sem frame; `send` fragmenta em 64B no bulk-IN.
    fn aegis_ccid_pop_frame(out_buf: *mut u8, max_len: u16) -> u16;
    fn aegis_ccid_send(data: *const u8, len: u16) -> bool;
    // CI-GREP: TEST-HOOK (test-mode only; absent in release).
    // Reboot p/ download ROM via RTC_CNTL (sem BOOT/DTR/RTS).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    fn aegis_reboot_to_download();
    // CI-GREP: TEST-HOOK (test-mode only; absent in release).
    // Drop + re-enumera o USB nativo (dispensa replug físico).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    fn aegis_usb_reconnect() -> bool;
    // Serial CTAPHID (UART 115200, framing identical to USB). Classic reuses
    // the UART-backed aegis_usb_* symbols; S3/S2 use aegis_serial_* (UART0
    // diagnostic channel alongside native USB-OTG).
    #[cfg(all(feature = "board-ttgo-classic", feature = "test-mode"))]
    fn aegis_usb_read_chunk(out_buf: *mut u8, max_len: u16) -> u16;
    #[cfg(not(feature = "board-ttgo-classic"))]
    fn aegis_serial_init() -> esp_idf_sys::esp_err_t;
    #[cfg(not(feature = "board-ttgo-classic"))]
    fn aegis_serial_send_report(packet: *const u8, len: u16) -> bool;
    #[cfg(not(feature = "board-ttgo-classic"))]
    fn aegis_serial_pop_packet(out_buf: *mut u8, max_len: u16) -> u16;
    #[cfg(all(not(feature = "board-ttgo-classic"), feature = "test-mode"))]
    fn aegis_serial_read_chunk(out_buf: *mut u8, max_len: u16) -> u16;
}

macro_rules! kprintln {
    () => {
        kprintln!("");
    };
    ($($arg:tt)*) => {{
        let mut raw: [u8; 256] = [0u8; 256];
        let mut w = crate::watchdog::StaticBuf::new(&mut raw);
        let _ = core::fmt::Write::write_fmt(&mut w, format_args!($($arg)*));
        let s = w.as_str();
        #[cfg(target_os = "espidf")]
        #[allow(unused_unsafe)]
        unsafe {
            for b in s.as_bytes() {
                esp_idf_sys::esp_rom_printf(b"%c\0".as_ptr() as *const _, *b as core::ffi::c_int);
            }
            esp_idf_sys::esp_rom_printf(b"\r\n\0".as_ptr() as *const _);
        }
        #[cfg(not(target_os = "espidf"))]
        println!("{}", s);
    }};
}

/// Serial CTAPHID byte source/sink (UART 115200).
///
/// Classic (single serial port): the UART-backed `aegis_usb_*` transport IS
/// the serial link. S3/S2: `aegis_serial_*` on the UART0 diagnostic channel,
/// alongside native USB-OTG (whose section below stays untouched).
#[cfg(target_os = "espidf")]
fn serial_pop_packet(out: &mut [u8; PACKET_SIZE]) -> u16 {
    #[cfg(feature = "board-ttgo-classic")]
    unsafe {
        aegis_usb_pop_packet(out.as_mut_ptr(), PACKET_SIZE as u16)
    }
    #[cfg(not(feature = "board-ttgo-classic"))]
    unsafe {
        aegis_serial_pop_packet(out.as_mut_ptr(), PACKET_SIZE as u16)
    }
}

/// Sends raw bytes over the serial link (64B CTAPHID packets or dump text).
#[cfg(target_os = "espidf")]
fn serial_send_bytes(packet: *const u8, len: u16) -> bool {
    #[cfg(feature = "board-ttgo-classic")]
    unsafe {
        aegis_usb_send_report(packet, len)
    }
    #[cfg(not(feature = "board-ttgo-classic"))]
    unsafe {
        aegis_serial_send_report(packet, len)
    }
}

/// Non-blocking diagnostic text read.
///
/// Yields bytes ONLY while fewer than 64 are buffered, so a 64-byte CTAPHID
/// packet is never split by the dump path: binary bursts always win the wire.
/// Diagnostic-idle use (TEST_LIFETIME_DUMP with test-mode).
#[cfg(all(target_os = "espidf", feature = "test-mode"))]
fn serial_read_chunk(out: &mut [u8], max_len: u16) -> u16 {
    #[cfg(feature = "board-ttgo-classic")]
    unsafe {
        aegis_usb_read_chunk(out.as_mut_ptr(), max_len)
    }
    #[cfg(not(feature = "board-ttgo-classic"))]
    unsafe {
        aegis_serial_read_chunk(out.as_mut_ptr(), max_len)
    }
}

/// Etapa B — despacha 1 mensagem GATT completa e notifica via FFF2.
///
/// PING ecoa; CANCEL confirma vazio; MSG delega ao `CtapEngine` (mesmo
/// `[cmd, CBOR...]` do `CMD_CBOR` USB); bind-mgmt `0x28-0x2D` usa os helpers
/// de `ble_gatt` (gates binding -> UP -> PIN preservados); vendor `0x20-0x27`
/// executa de verdade via `vendor_exec` (GEN/LIST/DELETE + OATH, NVS;
/// IMPORT segue 0x04 = F2b). USB/CTAP intactos.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(feature = "freertos", allow(dead_code))]
fn ble_dispatch_complete(
    msg: crate::ble_gatt::BleCompleteMessage,
    up: bool,
    pairing_window_open: bool,
    now_secs: u64,
    ctap_engine: &mut CtapEngine,
    binding_mgr: &mut crate::binding::BindingManager,
    storage: &mut SecureStorage<PlatformFlashBackend>,
    rescue: &mut RescueEngine,
    wallet: &mut WalletStore,
    bonded: bool,
    now_ms: u64,
    fwlog: &mut crate::fw_log::FwLog,
    key_mgr: &mut aegis_fido_core::credential::key_manager::KeyManager,
    oath_applet: &mut OathApplet,
) {
    use crate::binding::{BIND_CHALLENGE_LEN, BIND_ID_LEN, BIND_PUB_LEN};
    use crate::ble_gatt as g;
    use crate::ble_nimble as ble;
    use crate::fw_log as fl;
    use crate::wallet_exec as w;

    let op = msg.opcode;
    let p = &msg.payload;
    // Log real do device: toda op recebida + UP quando presente.
    fwlog.record(fl::EV_OP_RX, op, now_ms);
    if up {
        fwlog.record(fl::EV_UP_OK, op, now_ms);
    }
    let frame: Vec<u8> = match op {
        g::OP_PING => ble::notify_frame(op, 0x00, &g::BleGattServer::dispatch_ping(p)),
        g::OP_CANCEL => ble::notify_frame(op, 0x00, &[]),
        g::OP_MSG => {
            // Rescue Wave2 Step3: OP_MSG com primeiro byte 0x2E carrega
            // um frame rescue (reassemble/framing intactos). UP do
            // latch + PIN via plumbing ClientPIN (fail-closed sem sessão).
            if p.first() == Some(&RESCUE_TRANSPORT_OP) {
                rescue.set_user_presence(up);
                // Plumbing ClientPIN: sessão pinUvAuth viva prova PIN
                // verificado (fail-closed sem ela).
                rescue.set_pin_uv_authenticated(ctap_engine.pin_state.has_valid_pin_uv_session());
                let (st, body) = crate::serial_ctaphid::dispatch_serial_rescue(rescue, &p[1..]);
                kprintln!("[BLE] rescue 0x2E (status 0x{:02X}).", st);
                ble::notify_frame(op, st, &body)
            } else {
                ctap_engine.set_user_presence(up);
                let mut rng = rand_core::OsRng;
                let resp = ctap_engine.process_packet(p, now_secs, &mut rng);
                // F3: ClientPIN (0x06) mudou estado? Persiste hash+retries.
                if p.first() == Some(&0x06)
                    && !crate::vendor_exec::save_pin_state(storage, &ctap_engine.pin_state)
                {
                    kprintln!("[WARN] NVS pin save falhou (BLE).");
                }
                ble::notify_frame(op, 0x00, &resp)
            }
        }
        g::OP_BIND_CLAIM => {
            if p.len() != BIND_PUB_LEN + BIND_ID_LEN {
                ble::notify_frame(op, g::BleGattError::InvalidFragment.to_vendor_status(), &[])
            } else {
                let mut app_pub = [0u8; BIND_PUB_LEN];
                let mut binding_id = [0u8; BIND_ID_LEN];
                app_pub.copy_from_slice(&p[..BIND_PUB_LEN]);
                binding_id.copy_from_slice(&p[BIND_PUB_LEN..]);
                match g::dispatch_bind_claim(
                    binding_mgr,
                    storage,
                    &app_pub,
                    &binding_id,
                    pairing_window_open,
                    up,
                ) {
                    Ok(()) => ble::notify_frame(op, 0x00, &binding_id),
                    Err(e) => ble::notify_frame(op, e.to_vendor_status(), &[]),
                }
            }
        }
        g::OP_BIND_CHALLENGE => {
            if !p.is_empty() {
                ble::notify_frame(op, g::BleGattError::InvalidFragment.to_vendor_status(), &[])
            } else {
                let mut rng = rand_core::OsRng;
                match g::dispatch_bind_challenge(binding_mgr, storage, &mut rng) {
                    Ok(ch) => ble::notify_frame(op, 0x00, &ch),
                    Err(e) => ble::notify_frame(op, e.to_vendor_status(), &[]),
                }
            }
        }
        g::OP_BIND_VERIFY => {
            if p.len() < 1 + BIND_CHALLENGE_LEN + 32 {
                ble::notify_frame(op, g::BleGattError::InvalidFragment.to_vendor_status(), &[])
            } else {
                let vop = p[0];
                let mut ch = [0u8; BIND_CHALLENGE_LEN];
                let mut ph = [0u8; 32];
                ch.copy_from_slice(&p[1..1 + BIND_CHALLENGE_LEN]);
                ph.copy_from_slice(&p[1 + BIND_CHALLENGE_LEN..1 + BIND_CHALLENGE_LEN + 32]);
                match g::dispatch_bind_verify(binding_mgr, &p[65..], &ch, vop, &ph) {
                    Ok(()) => ble::notify_frame(op, 0x00, &[]),
                    Err(e) => ble::notify_frame(op, e.to_vendor_status(), &[]),
                }
            }
        }
        g::OP_BIND_RELEASE => {
            if p.len() < BIND_CHALLENGE_LEN + 32 {
                ble::notify_frame(op, g::BleGattError::InvalidFragment.to_vendor_status(), &[])
            } else {
                let mut ch = [0u8; BIND_CHALLENGE_LEN];
                let mut ph = [0u8; 32];
                ch.copy_from_slice(&p[..BIND_CHALLENGE_LEN]);
                ph.copy_from_slice(&p[BIND_CHALLENGE_LEN..BIND_CHALLENGE_LEN + 32]);
                match g::dispatch_bind_release(
                    binding_mgr,
                    storage,
                    &p[BIND_CHALLENGE_LEN + 32..],
                    &ch,
                    &ph,
                    up,
                ) {
                    Ok(()) => {
                        // Wave2 proximidade: release revoga o K_prox
                        // (fail-closed; o loop limpa o cache RAM ao ver a NVS
                        // vazia). Nunca auto-unlock.
                        #[cfg(feature = "proximity")]
                        let _ = crate::proximity::delete_proximity_key(storage);
                        ble::notify_frame(op, 0x00, &[])
                    }
                    Err(e) => ble::notify_frame(op, e.to_vendor_status(), &[]),
                }
            }
        }
        g::OP_RECOVERY_SET => match core::str::from_utf8(p) {
            Ok(pin) => match g::dispatch_recovery_set(storage, pin, up) {
                Ok(()) => ble::notify_frame(op, 0x00, &[]),
                Err(e) => ble::notify_frame(op, e.to_vendor_status(), &[]),
            },
            Err(_) => {
                ble::notify_frame(op, g::BleGattError::InvalidFragment.to_vendor_status(), &[])
            }
        },
        g::OP_RECOVERY_UNLOCK => match core::str::from_utf8(p) {
            Ok(pin) => match g::dispatch_recovery_unlock(storage, binding_mgr, pin, up) {
                Ok(()) => {
                    // Wave2 proximidade: recovery revoga o K_prox
                    // (fail-closed; o loop limpa o cache RAM ao ver a NVS
                    // vazia). Nunca auto-unlock.
                    #[cfg(feature = "proximity")]
                    let _ = crate::proximity::delete_proximity_key(storage);
                    ble::notify_frame(op, 0x00, &[])
                }
                Err(e) => ble::notify_frame(op, e.to_vendor_status(), &[]),
            },
            Err(_) => {
                ble::notify_frame(op, g::BleGattError::InvalidFragment.to_vendor_status(), &[])
            }
        },
        o if g::is_vendor_keys_oath_op(o) || g::is_piv_enroll_op(o) => {
            // F2: executor real on-device (GEN/LIST/DELETE + OATH
            // PUT/LIST/CODE/DELETE, NVS persistente); IMPORT segue 0x04
            // (envelope AEGN + vault = F2b). F4: 0x39 enrollment PIV
            // (binding -> UP, sem PIN). Gates §9.4 intactos.
            let pin_ok = ctap_engine.pin_state.has_valid_pin_uv_session();
            let mut rng = rand_core::OsRng;
            let (st, body) = crate::vendor_exec::exec_vendor_op(
                key_mgr,
                oath_applet,
                storage,
                o,
                p,
                binding_mgr.is_claimed(),
                pin_ok,
                up,
                now_secs,
                &mut rng,
            );
            if st == 0x00 {
                kprintln!("[BLE] op vendor 0x{:02X} executada.", o);
            }
            ble::notify_frame(o, st, &body)
        }
        o if g::is_wallet_op(o) => {
            // Carteira Fase7 (R-07): binding + UP já aprovados; executa de
            // verdade no WalletStore de sessão (chaves TRNG no device).
            match g::authorize_wallet_op(o, binding_mgr.is_claimed(), up) {
                Ok(()) => {
                    let mut rng = rand_core::OsRng;
                    let (st, body) = match o {
                        g::OP_WALLET_GEN => w::wallet_gen(wallet, p, now_secs, true, &mut rng),
                        g::OP_WALLET_LIST => w::wallet_list(wallet, true),
                        g::OP_WALLET_ADDR => w::wallet_addr(wallet, p, true),
                        _ => (0x04, Vec::new()),
                    };
                    kprintln!(
                        "[BLE] op wallet 0x{:02X} executada (status 0x{:02X}).",
                        o,
                        st
                    );
                    ble::notify_frame(o, st, &body)
                }
                Err(e) => ble::notify_frame(o, e.to_vendor_status(), &[]),
            }
        }
        o if fl::is_fw_log_op(o) => {
            // Log da firmware (0x38): leitura sem segredos; BLE exige
            // vínculo (0x05 sem ele), nunca UP/PIN.
            match g::authorize_fw_log_op(o, bonded) {
                Ok(()) => {
                    let body = fwlog.render_ascii(fl::FW_LOG_MAX_BYTES);
                    kprintln!("[BLE] fw-log 0x38 ({} B).", body.len());
                    ble::notify_frame(o, 0x00, &body)
                }
                Err(e) => ble::notify_frame(o, e.to_vendor_status(), &[]),
            }
        }
        _ => ble::notify_frame(op, 0x04, &[]),
    };
    // Status respondido entra no log (frame = [op, status, ...]).
    if frame.len() >= 2 {
        fwlog.record(fl::EV_OP_RESP, frame[1], now_ms);
    }
    let _ = ble::esp_ble_notify(&frame);
}

#[allow(dead_code)]
fn extract_rp_and_user(cmd: u8, payload: &[u8]) -> (String, String, &'static str) {
    if payload.len() <= 1 {
        return ("Autenticador".into(), "Chave FIDO2".into(), "Autenticação");
    }
    let cbor_bytes = &payload[1..];
    if let Ok(map) = aegis_fido_core::ctap::cbor::decode_cbor_map(cbor_bytes) {
        if cmd == CTAP_CMD_MAKE_CREDENTIAL {
            let mut rp_id = String::from("localhost");
            let mut user_name = String::from("Passkey");
            if let Some(ciborium::value::Value::Map(rp_map)) =
                aegis_fido_core::ctap::cbor::get_int_key(&map, 2)
            {
                for (k, v) in rp_map {
                    if let (ciborium::value::Value::Text(key), ciborium::value::Value::Text(val)) =
                        (k, v)
                    {
                        if key == "id" {
                            rp_id = val.clone();
                        }
                    }
                }
            }
            if let Some(ciborium::value::Value::Map(user_map)) =
                aegis_fido_core::ctap::cbor::get_int_key(&map, 3)
            {
                for (k, v) in user_map {
                    if let (ciborium::value::Value::Text(key), ciborium::value::Value::Text(val)) =
                        (k, v)
                    {
                        if key == "name" || key == "displayName" {
                            user_name = val.clone();
                        }
                    }
                }
            }
            return (rp_id, user_name, "Registro de Passkey");
        } else if cmd == CTAP_CMD_GET_ASSERTION {
            let mut rp_id = String::from("localhost");
            if let Some(ciborium::value::Value::Text(s)) =
                aegis_fido_core::ctap::cbor::get_int_key(&map, 1)
            {
                rp_id = s.clone();
            }
            return (rp_id, "Credencial Residente".into(), "Autenticação FIDO2");
        }
    }
    ("WebAuthn".into(), "Chave FIDO2".into(), "Autorização FIDO2")
}

/// Running firmware version (monotonic u32; OTA manifests must exceed it).
#[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
const FIRMWARE_VERSION: u32 = 1;

/// Offline OTA pubkey via injected provider (T6/A4).
///
/// The OTA pubkeys moved out of the dispatcher into ota OtaKeyProvider.
/// Release is zeros fail-closed until the factory programs the real release
/// key. Lab key compiled only under feature = "test-mode" gate.
/// CI-GREP TEST-HOOK marker TEST-OTA-KEY.
/// scripts check-release-clean proves absence in the release artifact.
/// R12 no hard coded key in main, R13 stub only, R14 eFuse BLOCK7 plus
/// BLOCK8 salt path via ota_provisioned below.
#[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
fn ota_active_pubkey() -> [u8; 32] {
    crate::ota::OtaKeyProvider::active_pubkey_for_build()
}

/// Provisionado p/ OTA: eFuse válido, ou lab em test-mode (CI-GREP: TEST-HOOK).
#[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
fn ota_provisioned(efuse_mgr: &crate::efuse::EfuseManager<crate::efuse::RamEfuseStorage>) -> bool {
    crate::provision::load_device_keys(efuse_mgr).is_ok() || cfg!(feature = "test-mode")
}

/// Diagnóstico TEST_* no caminho FreeRTOS (device + test-mode; host inalterado).
///
/// Drena linhas de texto da serial (`aegis_serial_*` fora da classic, igual
/// ao poll USB binário) e roteia via `SerialRouter`/dispatch existentes:
/// - `TEST_UP` arma 1 latch de presença (consumo único, mesma semântica do
///   legado: vale no próximo Tick, 1,5 s via `prox.note_presence`).
/// - `TEST_PAIRING_OPEN[_300]` delega a `dispatch_serial_pairing_line`
///   (usa o ponto de pareamento `PairingManager::open_test_window[_secs]`;
///   UP/bonding seguem exigidos, sem auto-parear).
/// - `TEST_PAIRING_CLOSE` fecha a janela em `freertos_test` (via
///   `close_test_window`, test-only) e o chamador FreeRTOS fecha a janela
///   host em `pairing_mgr` (mesmo `close_test_window`); ack
///   `pairing_closed source=software`.
/// - `TEST_DOWNLOAD` responde ack e reboota p/ download ROM (`RTC_CNTL`).
/// - Demais `TEST_*` respondem status textual sem segredos ou são ignorados
///   (documentado): `TEST_LED_*` não tem pipeline LED/display no FreeRTOS
///   (o latch `led_test_hold` vive no loop legado), então é ack compatível
///   sem latch; `TEST_LIFETIME_DUMP` delega ao dump canónico (só metadados);
///   `TEST_*` desconhecido ou não-TESTE não responde (sem janela/latch).
/// - Fio continua `k=v` texto; domínio interno é tipado (`FreertosTestLine`,
///   `TestLineOutcome`); sem JSON fora de FFI.
///
/// Todo o ramo só compila com `test-mode` (release nem vê este `mod`).
#[cfg(feature = "test-mode")]
#[cfg_attr(not(target_os = "espidf"), allow(dead_code))]
mod freertos_test_mode {
    use crate::pairing::{PairingManager, PairingState};

    /// Linha TEST_* tipada (domínio interno; fio segue texto `k=v`, sem JSON).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FreertosTestLine {
        /// `TEST_UP`: 1 toque BOOT via software.
        UpLatch,
        /// `TEST_PAIRING_OPEN`: janela 60 s.
        PairingOpen,
        /// `TEST_PAIRING_OPEN_300`: janela 300 s.
        PairingOpen300,
        /// `TEST_PAIRING_CLOSE`: fecha qualquer janela aberta (determinismo).
        PairingClose,
        /// `TEST_DOWNLOAD`: reboot p/ download ROM.
        Download,
        /// `TEST_USB_RECONNECT`: re-enumera o USB nativo.
        UsbReconnect,
        /// `TEST_LED_STATE`: estado textual (sem segredos).
        LedState,
        /// `TEST_LED_{RED,GREEN,BLUE,OFF}`: ack compatível, sem latch no FreeRTOS.
        LedSet,
        /// `TEST_LED_RELEASE`: ack compatível, sem latch no FreeRTOS.
        LedRelease,
        /// `TEST_LIFETIME_DUMP`: dump canónico (só metadados).
        LifetimeDump,
        /// `TEST_*` desconhecido: ignorado (sem resposta).
        UnknownTest,
        /// Não é `TEST_*`: ignorado.
        NotTest,
    }

    /// Classifica a linha já aparada (sem alocar; sem segredos).
    pub fn classify_freertos_test_line(trimmed: &str) -> FreertosTestLine {
        match trimmed {
            "TEST_UP" => FreertosTestLine::UpLatch,
            "TEST_PAIRING_OPEN" => FreertosTestLine::PairingOpen,
            "TEST_PAIRING_OPEN_300" => FreertosTestLine::PairingOpen300,
            "TEST_PAIRING_CLOSE" => FreertosTestLine::PairingClose,
            "TEST_DOWNLOAD" => FreertosTestLine::Download,
            "TEST_USB_RECONNECT" => FreertosTestLine::UsbReconnect,
            "TEST_LED_STATE" => FreertosTestLine::LedState,
            "TEST_LED_RED" | "TEST_LED_GREEN" | "TEST_LED_BLUE" | "TEST_LED_OFF" => {
                FreertosTestLine::LedSet
            }
            "TEST_LED_RELEASE" => FreertosTestLine::LedRelease,
            "TEST_LIFETIME_DUMP" => FreertosTestLine::LifetimeDump,
            s if s.starts_with("TEST_") => FreertosTestLine::UnknownTest,
            _ => FreertosTestLine::NotTest,
        }
    }

    /// Resultado tipado de uma linha (resposta textual + efeitos FFI a cargo do device).
    pub struct TestLineOutcome {
        /// Linha de status a enviar na serial (sem segredos) ou `None` (ignorado).
        pub response: Option<String>,
        /// Sinaliza reboot p/ download ROM (FFI só no device).
        pub reboot_to_download: bool,
        /// Sinaliza re-enumeração USB (FFI só no device).
        pub usb_reconnect: bool,
    }

    /// Estado test-mode do dispatcher FreeRTOS (latch UP 1x + janela de pareamento).
    pub struct FreertosTestState {
        up_pending: bool,
        pairing: PairingManager,
    }

    impl FreertosTestState {
        /// Estado inicial: sem latch, sem janela (fail-closed).
        pub fn new() -> Self {
            Self {
                up_pending: false,
                pairing: PairingManager::new(),
            }
        }

        /// Arma 1 UP software (consumo único via [`Self::take_up`]).
        pub fn arm_up(&mut self) {
            self.up_pending = true;
        }

        /// Consome o latch 1x (semântica legado: 1 UP, uso único).
        pub fn take_up(&mut self) -> bool {
            core::mem::replace(&mut self.up_pending, false)
        }

        /// Latch armado? (só metadado p/ `extra_states` do dump).
        pub fn up_pending(&self) -> bool {
            self.up_pending
        }

        /// Janela de pareamento atual (p/ `prox.tick`; `Idle` sem `TEST_PAIRING_OPEN`).
        pub fn pairing_state(&self) -> PairingState {
            self.pairing.state()
        }

        /// `true` SOMENTE com a janela de 60 s aberta (não basta `!= Idle`:
        /// `Locked` pós-timeout NÃO é janela aberta; sem isto, a primeira
        /// janela expirada deixava `test_open` preso em `true` e os gates
        /// de pairing do dispatcher viam janela aberta para sempre).
        pub fn is_pairing_window_open(&self, now_ms: u64) -> bool {
            self.pairing.is_pairing_window_open(now_ms)
        }

        /// Fecha a janela de teste (test-only; determinismo entre sessões).
        ///
        /// Espelha `TEST_PAIRING_OPEN` (que abre via
        /// `dispatch_serial_pairing_line`): vira `Locked`, mesmo estado do
        /// timeout natural. Não toca em `bonded`.
        pub fn close_test_window(&mut self) {
            self.pairing.close_test_window();
        }

        /// Acesso ao pareamento (só via `dispatch_serial_pairing_line`).
        pub fn pairing_mut(&mut self) -> &mut PairingManager {
            &mut self.pairing
        }

        /// Avança timeouts da janela (chamar a cada `Tick10ms`).
        pub fn tick(&mut self, now_ms: u64) {
            self.pairing.tick(now_ms);
        }
    }

    impl Default for FreertosTestState {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Roteia uma linha de texto (já sem `\n`) para resposta/efeitos, sem FFI.
    ///
    /// `extra_states` carrega só metadados (uptime/latch; nunca segredos).
    /// O dreno TEST de `run_authenticator_freertos` monta `extra_states`
    /// como `uptime_s=<s> up_latched=<0|1> touch=<0|1>`, onde `touch` é o
    /// flag do dispatcher (`touch_latched`) — visível só via este texto.
    /// `TEST_LED_STATE` ignora o resto de `extra_states` e só reflete
    /// `touch=` (metadado, sem efeito no latch).
    pub fn dispatcher_touch_from_extra(extra_states: &str) -> u8 {
        for token in extra_states.split([' ', '\t', '\r', '\n', ',']) {
            if let Some(v) = token.strip_prefix("touch=") {
                return u8::from(v.starts_with('1'));
            }
        }
        0
    }

    pub fn handle_freertos_test_line(
        state: &mut FreertosTestState,
        line: &str,
        now_ms: u64,
        extra_states: &str,
    ) -> TestLineOutcome {
        let trimmed = line.trim();
        match classify_freertos_test_line(trimmed) {
            FreertosTestLine::UpLatch => {
                state.arm_up();
                TestLineOutcome {
                    response: Some(String::from("up_latched source=software\n")),
                    reboot_to_download: false,
                    usb_reconnect: false,
                }
            }
            FreertosTestLine::PairingOpen | FreertosTestLine::PairingOpen300 => {
                let resp = crate::serial_ctaphid::dispatch_serial_pairing_line(
                    line,
                    state.pairing_mut(),
                    now_ms,
                );
                TestLineOutcome {
                    response: resp,
                    reboot_to_download: false,
                    usb_reconnect: false,
                }
            }
            FreertosTestLine::PairingClose => {
                state.close_test_window();
                TestLineOutcome {
                    response: Some(String::from("pairing_closed source=software\n")),
                    reboot_to_download: false,
                    usb_reconnect: false,
                }
            }
            FreertosTestLine::Download => TestLineOutcome {
                response: Some(String::from("download_mode source=software\n")),
                reboot_to_download: true,
                usb_reconnect: false,
            },
            FreertosTestLine::UsbReconnect => TestLineOutcome {
                response: Some(String::from("usb_reconnect source=software\n")),
                reboot_to_download: false,
                usb_reconnect: true,
            },
            FreertosTestLine::LedState => {
                // Sem pipeline LED/display no FreeRTOS (o latch `led_test_hold`
                // + `display_mgr` vivem no loop legado): responde só metadados.
                // `touch=` vem do dreno TEST via `extra_states` (flag do
                // dispatcher `touch_latched`); só texto, sem efeito no latch.
                let resp = format!(
                    "led_state screen=freertos pairing={:?} up_pending={} touch={} uptime_s={}\n",
                    state.pairing_state(),
                    state.up_pending() as u8,
                    dispatcher_touch_from_extra(extra_states),
                    now_ms / 1000
                );
                TestLineOutcome {
                    response: Some(resp),
                    reboot_to_download: false,
                    usb_reconnect: false,
                }
            }
            FreertosTestLine::LedSet => {
                // Ack compatível com o legado (`led_set <CMD>`); sem latch/cor
                // no FreeRTOS (documentado: E2E não trava esperando o ack).
                let resp = format!("led_set {trimmed}\n");
                TestLineOutcome {
                    response: Some(resp),
                    reboot_to_download: false,
                    usb_reconnect: false,
                }
            }
            FreertosTestLine::LedRelease => TestLineOutcome {
                response: Some(String::from("led_set released\n")),
                reboot_to_download: false,
                usb_reconnect: false,
            },
            FreertosTestLine::LifetimeDump => {
                let resp = crate::serial_ctaphid::dispatch_serial_text_line(line, extra_states);
                TestLineOutcome {
                    response: resp,
                    reboot_to_download: false,
                    usb_reconnect: false,
                }
            }
            FreertosTestLine::UnknownTest | FreertosTestLine::NotTest => TestLineOutcome {
                response: None,
                reboot_to_download: false,
                usb_reconnect: false,
            },
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn classifica_todas_do_manifesto_sem_json() {
            assert_eq!(
                classify_freertos_test_line("TEST_UP"),
                FreertosTestLine::UpLatch
            );
            assert_eq!(
                classify_freertos_test_line("TEST_DOWNLOAD"),
                FreertosTestLine::Download
            );
            assert_eq!(
                classify_freertos_test_line("TEST_USB_RECONNECT"),
                FreertosTestLine::UsbReconnect
            );
            assert_eq!(
                classify_freertos_test_line("TEST_PAIRING_OPEN"),
                FreertosTestLine::PairingOpen
            );
            assert_eq!(
                classify_freertos_test_line("TEST_PAIRING_OPEN_300"),
                FreertosTestLine::PairingOpen300
            );
            assert_eq!(
                classify_freertos_test_line("TEST_PAIRING_CLOSE"),
                FreertosTestLine::PairingClose
            );
            assert_eq!(
                classify_freertos_test_line("TEST_LIFETIME_DUMP"),
                FreertosTestLine::LifetimeDump
            );
            assert_eq!(
                classify_freertos_test_line("TEST_LED_STATE"),
                FreertosTestLine::LedState
            );
            for cmd in [
                "TEST_LED_RED",
                "TEST_LED_GREEN",
                "TEST_LED_BLUE",
                "TEST_LED_OFF",
            ] {
                assert_eq!(classify_freertos_test_line(cmd), FreertosTestLine::LedSet);
            }
            assert_eq!(
                classify_freertos_test_line("TEST_LED_RELEASE"),
                FreertosTestLine::LedRelease
            );
            assert_eq!(
                classify_freertos_test_line("TEST_FUTURO"),
                FreertosTestLine::UnknownTest
            );
            assert_eq!(
                classify_freertos_test_line("[HEARTBEAT] oi"),
                FreertosTestLine::NotTest
            );
        }

        #[test]
        fn up_tem_consumo_unico() {
            let mut s = FreertosTestState::new();
            assert!(!s.up_pending());
            let out = handle_freertos_test_line(&mut s, "TEST_UP", 1000, "uptime_s=1 up_latched=0");
            assert_eq!(
                out.response.as_deref(),
                Some("up_latched source=software\n")
            );
            assert!(!out.reboot_to_download && !out.usb_reconnect);
            assert!(s.up_pending());
            assert!(s.take_up());
            assert!(!s.take_up());
        }

        #[test]
        fn pairing_abre_janela_60_e_300_sem_bond() {
            let mut s = FreertosTestState::new();
            let out = handle_freertos_test_line(&mut s, "TEST_PAIRING_OPEN", 5000, "");
            let resp = out.response.expect("ack 60s");
            assert!(resp.contains("pairing_open") && resp.contains("window_s=60"));
            assert!(s.pairing_state() != PairingState::Idle);
            assert!(!s.pairing_mut().is_bonded());

            let mut t = FreertosTestState::new();
            let out = handle_freertos_test_line(&mut t, "TEST_PAIRING_OPEN_300", 7000, "");
            let resp = out.response.expect("ack 300s");
            assert!(resp.contains("window_s=300"));
            // Expira: tick além da janela volta a `Locked`/fechada.
            t.tick(7000 + 300 * 1000);
            assert!(!t.pairing_mut().is_pairing_window_open(7000 + 300 * 1000));
        }

        #[test]
        fn download_e_reconnect_sinalizam_ffi_sem_executar() {
            let mut s = FreertosTestState::new();
            let out = handle_freertos_test_line(&mut s, "TEST_DOWNLOAD", 0, "");
            assert!(out.reboot_to_download && !out.usb_reconnect);
            assert!(out.response.unwrap().contains("download_mode"));
            let out = handle_freertos_test_line(&mut s, "TEST_USB_RECONNECT", 0, "");
            assert!(out.usb_reconnect && !out.reboot_to_download);
            assert!(out.response.unwrap().contains("usb_reconnect"));
        }

        #[test]
        fn led_responde_status_sem_segredo_e_sem_latch() {
            let mut s = FreertosTestState::new();
            let out = handle_freertos_test_line(&mut s, "TEST_LED_STATE", 42_000, "");
            let resp = out.response.expect("led_state");
            assert!(resp.starts_with("led_state "));
            assert!(resp.contains("screen=freertos"));
            assert!(resp.contains("up_pending=0"));
            assert!(resp.contains("touch=0"));
            assert!(resp.contains("uptime_s=42"));
            assert!(!resp.contains("SECRET"));
            let out = handle_freertos_test_line(&mut s, "TEST_LED_RED", 0, "");
            assert_eq!(out.response.as_deref(), Some("led_set TEST_LED_RED\n"));
            let out = handle_freertos_test_line(&mut s, "TEST_LED_RELEASE", 0, "");
            assert_eq!(out.response.as_deref(), Some("led_set released\n"));
        }

        #[test]
        fn led_state_expoe_touch_do_dreno() {
            // Formato do dreno TEST (`extra="uptime_s=<s> up_latched=<0|1>
            // touch=<0|1>"`): `up_pending` vem do `FreertosTestState`,
            // `touch` é o flag do dispatcher (`touch_latched`) repassado via
            // `extra_states` (só metadado textual, sem efeito no latch).
            let mut s = FreertosTestState::new();
            let out = handle_freertos_test_line(
                &mut s,
                "TEST_LED_STATE",
                42_000,
                "uptime_s=42 up_latched=1 touch=1",
            );
            let resp = out.response.expect("led_state com touch");
            assert!(resp.contains("up_pending=0"));
            assert!(resp.contains("touch=1"));
            assert_eq!(
                dispatcher_touch_from_extra("uptime_s=1 up_latched=0 touch=1"),
                1
            );
            assert_eq!(
                dispatcher_touch_from_extra("uptime_s=1 up_latched=0 touch=0"),
                0
            );
            assert_eq!(dispatcher_touch_from_extra("uptime_s=1 up_latched=0"), 0);
            assert_eq!(dispatcher_touch_from_extra(""), 0);
        }

        #[test]
        fn dump_delega_e_desconhecido_ignora() {
            let mut s = FreertosTestState::new();
            let out = handle_freertos_test_line(&mut s, "TEST_LIFETIME_DUMP", 0, "uptime_s=42");
            let dump = out.response.expect("dump");
            assert!(dump.starts_with("lt_dump v=1\n"));
            assert!(dump.contains("lt.state uptime_s=42"));
            assert!(dump.ends_with("lt_end\n"));
            let out = handle_freertos_test_line(&mut s, "TEST_FUTURO_X", 0, "");
            assert!(out.response.is_none());
            assert!(!out.reboot_to_download && !out.usb_reconnect);
            // Linha não-TESTE também ignorada.
            let out = handle_freertos_test_line(&mut s, "[HEARTBEAT] oi", 0, "");
            assert!(out.response.is_none());
        }

        #[test]
        fn pairing_close_fecha_ambas_e_reabre_sem_regressao() {
            use crate::serial_ctaphid::dispatch_serial_pairing_line;
            // Abre as duas janelas: host (`pairing_mgr`) + teste (`freertos_test`).
            let mut host = PairingManager::new();
            let mut test = FreertosTestState::new();
            host.open_test_window(5000);
            let out = handle_freertos_test_line(&mut test, "TEST_PAIRING_OPEN", 5000, "");
            assert!(out.response.expect("ack open").contains("pairing_open"));
            assert!(host.is_pairing_window_open(5000));
            assert!(test.is_pairing_window_open(5000));
            // Fecha via mesmos calls do inbox TEST.
            let ack_host = dispatch_serial_pairing_line("TEST_PAIRING_CLOSE", &mut host, 6000)
                .expect("ack close host");
            assert_eq!(ack_host, "pairing_closed source=software\n");
            let out = handle_freertos_test_line(&mut test, "TEST_PAIRING_CLOSE", 6000, "");
            assert_eq!(
                out.response.as_deref(),
                Some("pairing_closed source=software\n")
            );
            assert!(!host.is_pairing_window_open(6000));
            assert!(!test.is_pairing_window_open(6000));
            // Reaberta depois continua funcionando (sem regressão).
            host.open_test_window(7000);
            let out = handle_freertos_test_line(&mut test, "TEST_PAIRING_OPEN", 7000, "");
            assert!(out.response.expect("ack reopen").contains("pairing_open"));
            assert!(host.is_pairing_window_open(7000));
            assert!(test.is_pairing_window_open(7000));
        }
    }
}

/// Entrada da variante FreeRTOS com feature freertos, T12 parte B.
///
/// Selecao sem quebrar o legado: com freertos cai aqui, sem a feature cai
/// em run_authenticator. O dispatcher BLE completo continua no legado.
/// Roteamento CTAPHID via route_ctaphid_event com origem preservada.
/// TrustFacade fiada no boot via sync_trust_claimed. sync_from_trust e
/// open_gaps seguem para a T8. Secmon segue ExternallyBlocked.
/// Gaps restantes: 7 FreertosTrustGap, todos ExternallyBlocked.
/// Sem burn ou secure boot, HW first, R6 zero, R7 gated.
///
/// Sobe USB mais botao mais housekeeping sobre fila mais event group.
/// No host roda cerca de 2 s e sai. No ESP-IDF o loop e infinito.
#[cfg(feature = "freertos")]
pub fn run_authenticator_freertos() {
    #[cfg(target_os = "espidf")]
    use crate::button::ButtonInput;
    #[cfg(target_os = "espidf")]
    use crate::freertos::route_ctaphid_event;
    #[cfg(target_os = "espidf")]
    use crate::freertos::SerialVendorCtx;
    use crate::freertos::{FirmwareEvent, FreeRtosScheduler, PacketOrigin, DEFAULT_QUEUE_DEPTH};
    kprintln!("[FREERTOS] AegisKey FreeRTOS variant booting (usb+button+housekeeping).");
    // Sem isto, `log::*` (incl. `log_boot_info`) cai no vazio no device:
    // nenhum caminho do firmware instala logger global.
    #[cfg(target_os = "espidf")]
    esp_idf_svc::log::EspLogger::initialize_default();
    // UART limpa p/ CTAPHID: driver WiFi em WARN (o INFO dele inunda o fio
    // a cada AP start com dezenas de linhas e afoga o resync do host).
    // Erros seguem visíveis; resto do IDF mantém INFO de boot.
    #[cfg(target_os = "espidf")]
    unsafe {
        esp_idf_sys::esp_log_level_set(
            b"wifi\0".as_ptr() as *const core::ffi::c_char,
            esp_idf_sys::esp_log_level_t_ESP_LOG_WARN,
        );
    }
    #[cfg(target_os = "espidf")]
    crate::freertos::log_boot_info();
    // USB-OTG nativo (TinyUSB) no PHY interno (GPIO19 D-/GPIO20 D+):
    // console primário no UART0 (`ESP_CONSOLE_UART_DEFAULT` +
    // `ESP_CONSOLE_SECONDARY_NONE` em sdkconfig.defaults.esp32s3) libera o
    // PHY p/ o TinyUSB como dono único — com o default S3 (console
    // USB_SERIAL_JTAG), o USJ reclama o mesmo PHY e o
    // `tinyusb_driver_install` falha (`LoadProhibited` no dump do
    // descritor). USB soma como transporte; a serial (UART0 115200)
    // segue intacta p/ CTAPHID + TEST_*.
    // Ordem funcional inalterada: USB primeiro, serial em seguida (a serial
    // é requisito do `aegis_serial_pop_packet`/`read_chunk`; ver abaixo).
    // Os anúncios saem SÓ depois da serial pronta, via `log::*` (mesmo lock
    // do `ESP_LOG` do C sob `EspLogger`): `kprintln!` (`esp_rom_printf`)
    // furava o lock e intercalava byte-a-byte com a task TinyUSB no UART0
    // (`AegisUSB: TinyUSB2…` truncado). Sem mutex novo, sem tocar no TinyUSB.
    #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
    let usb_init_rc: esp_idf_sys::esp_err_t = {
        // SAFETY: sem ponteiros; só instala o driver TinyUSB e lê o retorno.
        unsafe { aegis_usb_init() }
    };
    // Serial CTAPHID UART (UART0 115200, diagnóstico + TEST_*): sem ela,
    // `aegis_serial_pop_packet`/`read_chunk` devolvem 0 para sempre
    // (`s_serial_initialized` do C). Igual ao boot legado.
    #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
    let serial_init_rc: esp_idf_sys::esp_err_t = {
        // SAFETY: init idempotente do driver UART0; só lê o código de retorno.
        unsafe { aegis_serial_init() }
    };
    #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
    {
        if usb_init_rc == esp_idf_sys::ESP_OK {
            log::info!("[INIT] TinyUSB FIDO2 HID online (USB-OTG D+/D- 19/20).");
        } else {
            log::warn!(
                "[WARN] TinyUSB init rc=0x{:04X}; CTAPHID segue na serial.",
                usb_init_rc as i32
            );
        }
        if serial_init_rc == esp_idf_sys::ESP_OK {
            log::info!("[INIT] Serial CTAPHID UART online (115200 8N1, framing = USB).");
        } else {
            log::warn!(
                "[WARN] Serial CTAPHID UART init failed (rc={}); USB segue primário.",
                serial_init_rc as i32
            );
        }
    }
    let sched = FreeRtosScheduler::new(DEFAULT_QUEUE_DEPTH);
    let poll_usb = || -> Option<([u8; 64], PacketOrigin)> {
        #[cfg(target_os = "espidf")]
        {
            let mut buf = [0u8; 64];
            // SAFETY: `buf` tem 64 B vivos na stack; o C escreve até 64 B e
            // devolve o total escrito; só aceitamos o pacote se completo (64 B).
            let n = unsafe { aegis_usb_pop_packet(buf.as_mut_ptr(), 64) };
            if n == 64 {
                return Some((buf, PacketOrigin::Usb));
            }
            #[cfg(not(feature = "board-ttgo-classic"))]
            {
                // SAFETY: mesmo `buf` válido por 64 B; drena o canal serial
                // (UART0 diagnóstico); parcial é descartado com `None`.
                let m = unsafe { aegis_serial_pop_packet(buf.as_mut_ptr(), 64) };
                if m == 64 {
                    return Some((buf, PacketOrigin::Serial));
                }
            }
            None
        }
        #[cfg(not(target_os = "espidf"))]
        {
            None
        }
    };
    #[cfg(target_os = "espidf")]
    let usb_h = sched
        .spawn_packet_task_native(poll_usb)
        .expect("spawn usb_ctaphid native");
    #[cfg(not(target_os = "espidf"))]
    let usb_h = sched.spawn_packet_task(poll_usb);
    // Botão sem bloqueio: amostragem direta `is_pressed_raw` (o helper
    // `DualButtonManager::is_boot_pressed` dorme ~1 ms e é proibido em task).
    #[cfg(target_os = "espidf")]
    let btn_h = {
        let boot_input = EspBootButtonInput::new();
        #[cfg(any(feature = "board-t-display", feature = "board-ttgo-classic"))]
        {
            let key_input = EspKeyButtonInput::new();
            sched
                .spawn_button_task_native(
                    move || boot_input.is_pressed_raw(),
                    move || key_input.is_pressed_raw(),
                )
                .expect("spawn ui_button native")
        }
        #[cfg(not(any(feature = "board-t-display", feature = "board-ttgo-classic")))]
        {
            sched
                .spawn_button_task_native(move || boot_input.is_pressed_raw(), || false)
                .expect("spawn ui_button native")
        }
    };
    #[cfg(not(target_os = "espidf"))]
    let btn_h = sched.spawn_button_task(|| false, || false);
    #[cfg(target_os = "espidf")]
    let hk_h = sched
        .spawn_housekeeping_task_native()
        .expect("spawn housekeeping native");
    #[cfg(not(target_os = "espidf"))]
    let hk_h = sched.spawn_housekeeping_task();
    #[cfg(feature = "proximity")]
    let mut prox = {
        let mut s = crate::proximity_sched::ProxSchedState::new();
        // Boot: `load` ou `rekey` SOMENTE se `bonded || claimed`. O
        // scheduler ainda não observa PairingManager/BindingManager nem
        // NVS (`prox_k`): sem vínculo, fail-closed até `note_paired`.
        s.note_boot(false);
        s
    };
    #[cfg(feature = "proximity")]
    let mut prox_now_ms: u64 = 0;
    // CI-GREP: TEST-HOOK (test-mode only; absent in release).
    // Estado TEST_* do dispatcher FreeRTOS (device + test-mode; host inalterado).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut freertos_test = freertos_test_mode::FreertosTestState::new();
    // Linha de diagnóstico (`\n`; máx 48 B como o legado; sem JSON).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut freertos_serial_line: Vec<u8> = Vec::new();
    // Guarda do fio compartilhado UART: o dreno TEST nunca consome bytes
    // no meio de um reassemble CTAPHID (o evento do pacote 1 acorda o loop
    // bem no meio do pacote 2). Assembly pendente segura o dreno (teto
    // 2 s p/ nunca travar o inbox); janela quieta cobre o pacote 1.
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut serial_assembly_since_ms: Option<u64> = None;
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut serial_quiet_until_ms: u64 = 0;
    // Relógio monotónico do dispatcher p/ janelas/testes (atualizado no Tick).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut freertos_test_now_ms: u64 = 0;
    // Roteamento CTAPHID do dispatcher (device): 1 manager por transporte
    // (como `ctaphid_mgr`/`serial_router` no legado) + `CtapEngine` real com
    // a chave do provisionamento (fallback efêmero TRNG, como o legado).
    #[cfg(target_os = "espidf")]
    let mut ctaphid_usb = CtapHidManager::new();
    #[cfg(target_os = "espidf")]
    let mut ctaphid_serial = CtapHidManager::new();
    #[cfg(target_os = "espidf")]
    let (mut ctap_engine, dev_master_key, dev_salt) = {
        use rand_core::RngCore as _;
        let efuse_mgr = EfuseManager::new(RamEfuseStorage::new());
        match load_device_keys(&efuse_mgr) {
            Ok(keys) => {
                kprintln!("[INIT] Hardware Master Key carregada (FreeRTOS CTAPHID).");
                (
                    CtapEngine::new(keys.master_key, 0),
                    keys.master_key,
                    keys.device_salt,
                )
            }
            Err(_) => {
                let mut rng = rand_core::OsRng;
                let mut mk = [0u8; 32];
                let mut salt = [0u8; 32];
                rng.fill_bytes(&mut mk);
                rng.fill_bytes(&mut salt);
                // CI-GREP: TEST-HOOK (test-mode only; absent in release).
                // Sem burn de eFuse: a chave-dev mora em flash NVS
                // (namespace "aegisdev"), reutilizada entre boots.
                #[cfg(feature = "test-mode")]
                match crate::nvs_backend::load_or_create_dev_keys() {
                    Ok((m, s)) => {
                        kprintln!("[TEST] dev-key flash persistente ativa (test-mode only).");
                        mk = m;
                        salt = s;
                    }
                    Err(_) => {
                        kprintln!(
                            "[WARN] eFuse nao provisionado; chaves efemeras TRNG (sem persistencia)."
                        );
                    }
                }
                #[cfg(not(feature = "test-mode"))]
                kprintln!(
                    "[WARN] eFuse nao provisionado; chaves efemeras TRNG (sem persistencia)."
                );
                (CtapEngine::new(mk, 0), mk, salt)
            }
        }
    };
    // USB-OTG nativo (TinyUSB): ATIVO nesta variante (init acima, antes da
    // serial; dono único do PHY interno 19/20 com console no UART0).
    // CTAPHID soma USB + serial (UART0) + TEST_*; sem eFuse/secure/NVS tocados.
    // FreeRTOS: display/LED + BLE + NVS + WiFi + CCID (paridade com o loop
    // legado; o dispatcher CTAPHID acima segue intacto). Tudo `device-only`.
    // Marca d'água da stack da main a cada etapa (caça ao overflow da main).
    #[cfg(target_os = "espidf")]
    let stack_mark = |etapa: &str| {
        // SAFETY: NULL = tarefa corrente (main); só lê o high water mark.
        // `uxTaskGetStackHighWaterMark` retorna em words; ×4 p/ bytes
        // (convenção em freertos.rs:814-825; o rótulo antigo "words" mentia).
        let words = unsafe { esp_idf_sys::uxTaskGetStackHighWaterMark(core::ptr::null_mut()) };
        let bytes = (words as usize).saturating_mul(4);
        kprintln!("[STACK] main livre após {}: {} bytes.", etapa, bytes);
    };
    #[cfg(target_os = "espidf")]
    let mut display_mgr = {
        kprintln!("[INIT] Display & LED (FreeRTOS).");
        #[cfg(feature = "board-devkitc")]
        let led_controller = {
            let mut led_output = EspWs2812Output::new(48);
            led_output.init_hardware();
            Some(Ws2812Controller::new(led_output))
        };
        #[cfg(not(feature = "board-devkitc"))]
        let led_controller: Option<Ws2812Controller<EspWs2812Output>> = None;
        let mut dm = DisplayManager::new(led_controller);
        let _ = dm.init_hardware();
        dm.set_screen(UiScreen::IdleStandby {
            status_text: "Aguardando solicitação FIDO2...".into(),
        });
        kprintln!("[INIT] UI and visual engine online (FreeRTOS).");
        dm
    };
    #[cfg(target_os = "espidf")]
    stack_mark("display");
    #[cfg(target_os = "espidf")]
    let mut storage = {
        kprintln!("[INIT] Encrypted Storage (FreeRTOS)...");
        let flash_backend = PlatformFlashBackend::new();
        if flash_backend.is_persistent() {
            kprintln!("[INIT] Flash NVS backend online (persiste entre reboots).");
        } else {
            kprintln!("[WARN] Flash NVS indisponivel; RAM volatil (sem persistencia).");
        }
        // Boot health-check `boot_state` NÃO roda aqui: AES/NVS na main
        // pré-yield estourou a stack (~116 B livres → TWDT silencioso).
        // `SecureStorage::new` (HKDF) é barato e fica; o `store` foi
        // diferido p/ após o primeiro yield do loop (ver `boot_state_pending`
        // ao fim da iteração), onde a main já cedeu ao scheduler. 1x por boot.
        SecureStorage::new(flash_backend, &dev_master_key, &dev_salt)
    };
    #[cfg(target_os = "espidf")]
    stack_mark("storage");
    #[cfg(target_os = "espidf")]
    let mut binding_mgr = match crate::binding::BindingManager::load_from_storage(&storage) {
        Ok(m) => {
            kprintln!("[INIT] Binding loaded (claimed={}).", m.is_claimed());
            m
        }
        Err(e) => {
            kprintln!("[WARN] Binding store inconsistent ({e}); starting unclaimed.");
            crate::binding::BindingManager::new()
        }
    };
    #[cfg(target_os = "espidf")]
    let mut pairing_mgr = crate::pairing::PairingManager::new();
    #[cfg(target_os = "espidf")]
    let mut ble_server = crate::ble_gatt::BleGattServer::new();
    #[cfg(target_os = "espidf")]
    let mut ble_rx = [0u8; crate::ble_nimble::BLE_RX_FRAGMENT_MAX];
    #[cfg(target_os = "espidf")]
    let mut ble_start_gate = crate::ble_nimble::BleStartGate::new();
    #[cfg(target_os = "espidf")]
    let mut ble_adv_active = false;
    // Saúde BLE provada (`esp_ble_preinit rc=0` via TEST_BLE_PREINIT): sem
    // ela, o ramo de reconexão sem janela fica mudo (fail-closed). Sem esse
    // gate, o primeiro Tick pós-claim (`claimed` + `Idle`) chamava
    // `esp_ble_start → nimble_port_init` com heap/rádio nunca validado
    // neste HW → `LoadProhibited` determinístico.
    #[cfg(target_os = "espidf")]
    #[allow(unused_mut)]
    let mut ble_preinit_ok = false;
    #[cfg(target_os = "espidf")]
    let mut ble_bond_pending = false;
    #[cfg(target_os = "espidf")]
    let mut pairing_open_prev = false;
    #[cfg(target_os = "espidf")]
    let mut pairing_open_now = false;
    #[cfg(target_os = "espidf")]
    let mut rescue_engine = RescueEngine::new();
    #[cfg(target_os = "espidf")]
    let mut wallet_store = WalletStore::new();
    #[cfg(target_os = "espidf")]
    let mut fw_log = crate::fw_log::FwLog::new();
    #[cfg(target_os = "espidf")]
    let mut key_mgr = aegis_fido_core::credential::key_manager::KeyManager::new();
    #[cfg(target_os = "espidf")]
    let mut oath_applet = OathApplet::new();
    #[cfg(target_os = "espidf")]
    {
        fw_log.record(crate::fw_log::EV_BOOT, 0, 0);
        if !crate::vendor_exec::load_states(&storage, &mut key_mgr, &mut oath_applet) {
            kprintln!("[WARN] vendor NVS inconsistente; começando vazio.");
        }
        if !crate::vendor_exec::load_pin_state(&storage, &mut ctap_engine.pin_state) {
            kprintln!("[WARN] PIN NVS inconsistente; sem PIN.");
        }
    }
    #[cfg(target_os = "espidf")]
    stack_mark("binding+managers");
    #[cfg(target_os = "espidf")]
    let mut wifi_ap_mgr = crate::wifi_ap::WifiApManager::new();
    #[cfg(target_os = "espidf")]
    let mut mdns_mgr = crate::mdns::MdnsManager::new();
    #[cfg(target_os = "espidf")]
    let mut sta_mgr = crate::wifi_station::WifiStationManager::new();
    #[cfg(target_os = "espidf")]
    let mut wifi_ap_active = false;
    #[cfg(target_os = "espidf")]
    let mut wifi_ap_last_try_ms: u64 = 0;
    #[cfg(target_os = "espidf")]
    let mut wifi_ap_fails: u32 = 0;
    #[cfg(target_os = "espidf")]
    let mut mdns_active = false;
    #[cfg(target_os = "espidf")]
    let mut wifi_radio_on = false;
    #[cfg(target_os = "espidf")]
    let mut last_sta_attempt_ms: Option<u64> = None;
    #[cfg(target_os = "espidf")]
    let mut ccid_transport = aegis_fido_usb::ccid::CcidTransport::new();
    // CI-GREP: TEST-HOOK (test-mode only; absent in release).
    // Latch de cor solida p/ diagnostico LED (TEST_LED_*).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut led_test_hold: Option<LedEffect> = None;
    // Nível do BOOT p/ `PairingManager` (hold 5s abre pareamento) e TOTP.
    #[cfg(target_os = "espidf")]
    let mut boot_held_since_ms: Option<u64> = None;
    #[cfg(target_os = "espidf")]
    let mut totp_display_until: u64 = 0;
    #[cfg(target_os = "espidf")]
    let mut totp_account_idx: usize = 0;
    // Watchdog da main task (paridade legada: `Watchdog::new(300)` + feed
    // por poll). Sem ele, trechos lentos de init/loop matam a IDLE0 no TWDT.
    #[cfg(target_os = "espidf")]
    let mut freertos_watchdog = crate::watchdog::Watchdog::new(300);
    #[cfg(all(target_os = "espidf", feature = "proximity"))]
    {
        // Boot: K_prox em RAM se vínculo prévio (fail-closed caso contrário);
        // `note_paired` no bonding gera o próximo (ctr=0).
        // T12-parte-B: fia o vínculo TrustFacade no scheduler (BindingWire):
        // `sync_trust_claimed` espelha `binding_mgr.is_claimed()`; sem ela,
        // `trusted = bonded` (fail-closed). `sync_from_trust`/`open_gaps`
        // seguem para a T8; secmon (universal-device-sdk) segue ExternallyBlocked.
        let trusted = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
        prox.note_boot(trusted);
        prox.sync_trust_claimed(binding_mgr.is_claimed());
    }
    #[cfg(target_os = "espidf")]
    {
        kprintln!("[INIT] managers ok (FreeRTOS).");
        // BLE init é preguiçoso (lazy): `esp_ble_preinit` no boot trava
        // neste HW (LoadProhibited no `esp_intr_alloc` do controller — em
        // investigação). O adv liga via gate no loop (`esp_ble_start` →
        // `ensure_init`) e o diagnóstico sob demanda vem por TEST_BLE_PREINIT.
        // Boot segue sem BLE; CTAPHID/TEST/NVS/LED vivos.
        kprintln!("[INIT] BLE init lazy (sem preinit no boot; ver TEST_BLE_PREINIT).");
        kprintln!("============================================================");
        kprintln!("   AegisKey S3 Authenticator ONLINE & ACTIVE! (FreeRTOS)");
        kprintln!("   FIDO2 / WebAuthn ready on native USB (HID Usage Page 0xF1D0)");
        kprintln!("============================================================");
    }
    // Latch UP 1x (BOOT físico ou TEST_UP), com expiração de 1,5 s.
    #[cfg(target_os = "espidf")]
    let mut touch_latched = false;
    #[cfg(target_os = "espidf")]
    let mut touch_expire_ms: u64 = 0;
    // Relógio do roteamento CTAPHID (atualizado a cada Tick10ms).
    #[cfg(target_os = "espidf")]
    let mut freertos_now_ms: u64 = 0;
    // Health-check de boot diferido: `true` até o primeiro `store` pós-yield.
    // O `receive` abaixo é o primeiro ponto onde a main cede ao scheduler;
    // só depois dele há stack folgada p/ AES/NVS. Executa 1x por boot.
    #[cfg(target_os = "espidf")]
    let mut boot_state_pending = true;
    #[cfg(not(target_os = "espidf"))]
    {
        let t0 = std::time::Instant::now();
        while t0.elapsed() < std::time::Duration::from_secs(2) {
            match sched.queue.receive(Some(100)) {
                Some(FirmwareEvent::UsbPacket(pkt)) => {
                    kprintln!("[FREERTOS] usb packet ({} B).", pkt.len());
                }
                Some(FirmwareEvent::SerialPacket(pkt)) => {
                    kprintln!("[FREERTOS] serial packet ({} B).", pkt.len());
                }
                Some(FirmwareEvent::ButtonPress { boot, key }) => {
                    kprintln!("[FREERTOS] UP latch boot={} key={}.", boot, key);
                    #[cfg(feature = "proximity")]
                    if boot {
                        prox.note_presence(prox_now_ms);
                    }
                }
                Some(FirmwareEvent::Tick10ms(t)) => {
                    if t % 100 == 0 {
                        kprintln!("[FREERTOS] tick {}.", t);
                    }
                    #[cfg(feature = "proximity")]
                    {
                        prox_now_ms = t.saturating_mul(10);
                        // USB veta o beacon; no host, sem driver: inativo.
                        #[cfg(target_os = "espidf")]
                        // SAFETY: `aegis_usb_is_mounted` só lê o estado do
                        // driver TinyUSB; sem ponteiros, sem escrita.
                        let usb_active = unsafe { aegis_usb_is_mounted() };
                        #[cfg(not(target_os = "espidf"))]
                        let usb_active = false;
                        // Sem WiFi no dispatcher: intervalo sempre normal
                        // (gap: desacelerar quando o WiFi entrar na coex
                        // `USB > WiFi > BLE`). Sem PairingManager: `Idle`
                        // (gap: ligar à janela real de pareamento).
                        prox.tick(
                            prox_now_ms,
                            usb_active,
                            false,
                            crate::pairing::PairingState::Idle,
                        );
                    }
                }
                Some(FirmwareEvent::BleFragment(_, len)) => {
                    kprintln!("[FREERTOS] ble fragment ({} B).", len);
                    // Gap PROX: sem dispatch GATT no scheduler — `note_paired`
                    // (rekey + ctr=0 dos 2 `Paired`), `erase` (`BIND_RELEASE`/
                    // `RECOVERY_UNLOCK`) e RSSI vivem no loop legado; o tick
                    // ~1 s aqui segue fail-closed (sem chave, sem adv).
                }
                Some(FirmwareEvent::Shutdown) => {
                    kprintln!("[FREERTOS] shutdown.");
                    #[cfg(feature = "proximity")]
                    {
                        prox.erase();
                        kprintln!("[PROX] K_prox zerado no shutdown.");
                    }
                    break;
                }
                None => {}
            }
        }
        sched.request_stop();
    }
    #[cfg(target_os = "espidf")]
    loop {
        // CI-GREP: TEST-HOOK (test-mode only; absent in release).
        // Drena linhas de diagnóstico sem bloquear (o `receive` abaixo dá o
        // timeout; sem `sleep`). Fora da classic usa `aegis_serial_*`
        // (igual ao poll USB binário); na classic o canal já é o USB.
        // Binário 64 B segue na task USB; aqui só texto `\n`, nunca quebra
        // reassemble (uso idle, como o D1 legado).
        #[cfg(feature = "test-mode")]
        {
            // Fio compartilhado UART: o dreno TEST só lê com o CTAPHID
            // quieto. O evento do pacote 1 acorda o loop bem no meio do
            // pacote 2; sem a guarda, o dreno comia bytes do frame e o
            // reassemble multi-pacote morria (MC/GA mudos). Assembly
            // pendente segura o dreno (teto 2 s); janela quieta cobre a
            // chegada do pacote 1.
            let pending = ctaphid_serial.has_pending_assembly();
            if pending && serial_assembly_since_ms.is_none() {
                serial_assembly_since_ms = Some(freertos_now_ms);
            } else if !pending {
                serial_assembly_since_ms = None;
            }
            let assembly_hold = pending
                && serial_assembly_since_ms
                    .is_some_and(|since| freertos_now_ms.saturating_sub(since) < 2000);
            let wire_free = !assembly_hold && freertos_now_ms >= serial_quiet_until_ms;
            let mut chunk = [0u8; 32];
            // SAFETY: `chunk` tem 32 B vivos na stack; o C escreve até 32 B e
            // devolve o total; só lemos `chunk[..n]`. Com fio ocupado (n=0),
            // nada é consumido: o frame segue intacto p/ o reassemble.
            let n = if wire_free {
                serial_read_chunk(&mut chunk, 32)
            } else {
                0
            };
            for b in chunk.iter().take(n as usize) {
                if *b == b'\n' {
                    if let Ok(line) = core::str::from_utf8(&freertos_serial_line) {
                        // TEST_UP arma o latch SINCRONAMENTE aqui (o ack já
                        // sai com latch válido). O Tick mantém o re-armo
                        // idempotente via take_up (compat); sem isso, a
                        // latência ack→tick comia a janela de 1,5 s e o MC
                        // caía em 0x27 mesmo com UP "confirmado".
                        if line.trim() == "TEST_UP" {
                            touch_latched = true;
                            touch_expire_ms = freertos_now_ms.saturating_add(1500);
                            rescue_engine.set_user_presence(true);
                            pairing_mgr.on_button_level(true, freertos_now_ms);
                            boot_held_since_ms = Some(freertos_now_ms);
                            #[cfg(feature = "proximity")]
                            prox.note_presence(prox_now_ms);
                        }
                        // CI-GREP: TEST-HOOK (test-mode only): preinit BLE sob
                        // demanda (diagnóstico do crash de boot; sem reboot).
                        #[cfg(all(target_os = "espidf", feature = "test-mode"))]
                        if line.trim() == "TEST_BLE_PREINIT" {
                            kprintln!("[TEST] ble preinit on demand...");
                            // Prova de heap p/ o `Malloc failed` (emi.c:164): livre +
                            // maior bloco contíguo antes/depois (fragmentação, não
                            // vazamento). O C (`ensure_init`) também loga via ESP_LOGI.
                            // SAFETY: só lê estatísticas do heap; sem ponteiros, sem escrita.
                            let free_before = unsafe { esp_idf_sys::esp_get_free_heap_size() };
                            // SAFETY: `MALLOC_CAP_DEFAULT` só seleciona o heap; sem
                            // ponteiros, sem escrita; devolve o maior bloco livre.
                            let largest_before = unsafe {
                                esp_idf_sys::heap_caps_get_largest_free_block(
                                    esp_idf_sys::MALLOC_CAP_DEFAULT,
                                )
                            };
                            kprintln!(
                                "[BLE] heap antes livre={} maior={}.",
                                free_before,
                                largest_before
                            );
                            let rc = crate::ble_nimble::esp_ble_preinit();
                            // SAFETY: mesma leitura pós-preinit; sem ponteiros, sem escrita.
                            let free_after = unsafe { esp_idf_sys::esp_get_free_heap_size() };
                            // SAFETY: mesma leitura do maior bloco; sem ponteiros, sem escrita.
                            let largest_after = unsafe {
                                esp_idf_sys::heap_caps_get_largest_free_block(
                                    esp_idf_sys::MALLOC_CAP_DEFAULT,
                                )
                            };
                            kprintln!(
                                "[TEST] ble preinit rc={} heap depois livre={} maior={}.",
                                rc,
                                free_after,
                                largest_after
                            );
                            if rc == 0 {
                                ble_preinit_ok = true;
                                kprintln!("[BLE] preinit ok; reconexao sem janela liberada.");
                            }
                            let resp = format!("ble_preinit rc={}\n", rc);
                            serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                            freertos_serial_line.clear();
                            continue;
                        }
                        // `touch=` expõe o flag do dispatcher (`touch_latched`)
                        // no `TEST_LED_STATE`/`TEST_LIFETIME_DUMP`: só metadado
                        // textual p/ observabilidade do harness; o latch real
                        // segue intocado (dreno TEST do device, sem cobertura
                        // host — ver teste `led_state_expoe_touch_do_dreno`).
                        let extra = format!(
                            "uptime_s={} up_latched={} touch={}",
                            freertos_test_now_ms / 1000,
                            freertos_test.up_pending() as u8,
                            touch_latched as u8
                        );
                        let outcome = freertos_test_mode::handle_freertos_test_line(
                            &mut freertos_test,
                            line,
                            freertos_test_now_ms,
                            &extra,
                        );
                        // TEST_PAIRING_CLOSE fecha também a janela host em
                        // `pairing_mgr` (placa não reseta entre sessões; uma
                        // janela de sonda anterior ainda vale aqui) e muda o
                        // radio: `shutdown_after_config` + `esp_ap_stop` se o
                        // AP estava on (sem isto o `WifiApManager` seguia
                        // `Active` ate expirar e o poll pedia Start sem heap).
                        if line.trim() == crate::pairing::TEST_PAIRING_CLOSE_CMD {
                            pairing_mgr.close_test_window();
                            wifi_ap_mgr.shutdown_after_config();
                            if wifi_ap_active {
                                let _ = crate::wifi_ap::esp_ap_stop();
                                wifi_ap_active = false;
                                kprintln!("[WIFI] AP off (pairing fechado).");
                            }
                        }
                        if let Some(resp) = outcome.response {
                            // `resp` viva até ao fim da chamada; o C só
                            // lê `len` bytes para TX serial.
                            serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                        }
                        if outcome.reboot_to_download {
                            kprintln!("[TEST] download via software (RTC_CNTL).");
                            // Reboot p/ download ROM via RTC_CNTL;
                            // nunca retorna; sem ponteiros.
                            // SAFETY: reboot via RTC_CNTL; nunca retorna.
                            unsafe {
                                aegis_reboot_to_download();
                            }
                        }
                        if outcome.usb_reconnect {
                            kprintln!("[TEST] usb reconnect via software.");
                            // SAFETY: drop + re-enumera o USB nativo; sem
                            // ponteiros, sem escrita em RAM partilhada.
                            unsafe {
                                aegis_usb_reconnect();
                            }
                        }
                        // CI-GREP: TEST-HOOK (test-mode only): espelha a cor
                        // pedida no LED físico (release devolve ao pipeline).
                        #[cfg(all(target_os = "espidf", feature = "test-mode"))]
                        {
                            use crate::led::Color as LedColor;
                            let t = line.trim();
                            if t.starts_with("TEST_LED_RED") {
                                led_test_hold = Some(LedEffect::Solid(LedColor::RED));
                            } else if t.starts_with("TEST_LED_GREEN") {
                                led_test_hold = Some(LedEffect::Solid(LedColor::GREEN));
                            } else if t.starts_with("TEST_LED_BLUE") {
                                led_test_hold = Some(LedEffect::Solid(LedColor::BLUE));
                            } else if t.starts_with("TEST_LED_OFF") {
                                led_test_hold = Some(LedEffect::Off);
                            } else if t.starts_with("TEST_LED_RELEASE") {
                                led_test_hold = None;
                            }
                            if let Some(h) = led_test_hold {
                                if let Some(ref mut led) = display_mgr.led_controller {
                                    led.set_effect(h);
                                }
                            }
                        }
                    }
                    freertos_serial_line.clear();
                } else if freertos_serial_line.len() < 48 {
                    freertos_serial_line.push(*b);
                } else {
                    freertos_serial_line.clear();
                }
            }
        }
        // FreeRTOS: bomba BLE (GAP + FFF1->dispatch->FFF2) + CCID, por
        // iteração (FFI não-bloqueante; USB segue na task dedicada).
        #[cfg(target_os = "espidf")]
        {
            // Feed do TWDT da main a cada iteração (paridade legada).
            freertos_watchdog.feed(freertos_now_ms / 10);
            use crate::ble_nimble as ble;
            match ble::esp_ble_poll_event() {
                e if e == ble::BLE_EVT_SECURED => {
                    match ble::on_link_secured(&mut pairing_mgr, touch_latched, freertos_now_ms) {
                        ble::BondOutcome::Paired => {
                            touch_latched = false;
                            ble_bond_pending = false;
                            rescue_engine.set_user_presence(true);
                            let _ = ble::esp_ble_stop();
                            ble_adv_active = false;
                            display_mgr.set_screen(UiScreen::Success {
                                title: "DISPOSITIVO PAREADO".into(),
                                subtitle: "BLE seguro ativo".into(),
                            });
                            if let Some(ref mut led) = display_mgr.led_controller {
                                led.set_effect(LedEffect::Solid(crate::led::Color::GREEN));
                            }
                            kprintln!("[BLE] bonding ok (FreeRTOS): advertising parado.");
                            fw_log.record(crate::fw_log::EV_BOND_OK, 0, freertos_now_ms);
                            #[cfg(feature = "proximity")]
                            prox.note_paired(freertos_now_ms);
                        }
                        ble::BondOutcome::DeniedNoPresence => {
                            ble_bond_pending = true;
                            kprintln!("[BLE] link seguro sem UP: toque no BOOT para confirmar.");
                            display_mgr.set_screen(UiScreen::UserPresencePrompt {
                                rp_id: "Pareamento BLE".into(),
                                user_name: "App AegisKey".into(),
                                operation: "Confirmar pareamento".into(),
                                remaining_seconds: 25,
                            });
                        }
                        ble::BondOutcome::DeniedNoWindow => {
                            kprintln!("[BLE] link seguro fora da janela: ignorado.");
                        }
                    }
                }
                e if e == ble::BLE_EVT_DISCONNECTED => {
                    kprintln!("[BLE] central desconectou.");
                    ble_adv_active = false;
                    ble_bond_pending = false;
                }
                e if e == ble::BLE_EVT_CONNECTED => {
                    kprintln!("[BLE] central conectou (aguardando bonding).");
                }
                _ => {}
            }
            // Bonding pendente: conclui quando o usuario tocar no BOOT.
            #[allow(clippy::collapsible_if)]
            if ble_bond_pending
                && touch_latched
                && pairing_mgr.is_pairing_window_open(freertos_now_ms)
            {
                if ble::on_link_secured(&mut pairing_mgr, true, freertos_now_ms)
                    == ble::BondOutcome::Paired
                {
                    touch_latched = false;
                    ble_bond_pending = false;
                    rescue_engine.set_user_presence(true);
                    let _ = ble::esp_ble_stop();
                    ble_adv_active = false;
                    display_mgr.set_screen(UiScreen::Success {
                        title: "DISPOSITIVO PAREADO".into(),
                        subtitle: "BLE seguro ativo".into(),
                    });
                    if let Some(ref mut led) = display_mgr.led_controller {
                        led.set_effect(LedEffect::Solid(crate::led::Color::GREEN));
                    }
                    kprintln!("[BLE] bonding ok (apos UP): advertising parado.");
                    fw_log.record(crate::fw_log::EV_BOND_OK, 0, freertos_now_ms);
                    #[cfg(feature = "proximity")]
                    prox.note_paired(freertos_now_ms);
                }
            }
            // Fragmentos FFF1 -> reassemble -> dispatch -> notify FFF2.
            let rx_n = ble::esp_ble_fetch_rx(&mut ble_rx);
            if rx_n > 0 {
                let up = touch_latched;
                let frag = &ble_rx[..rx_n as usize];
                match ble::feed_control_write(&mut ble_server, frag, up) {
                    Ok(Some(msg)) => {
                        touch_latched = false;
                        ble::esp_ble_set_pending_len(ble::pending_len(&ble_server));
                        let bonded = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
                        #[cfg(feature = "proximity")]
                        let prox_revoked_op = msg.opcode;
                        ble_dispatch_complete(
                            msg,
                            up,
                            pairing_open_now,
                            freertos_now_ms / 1000,
                            &mut ctap_engine,
                            &mut binding_mgr,
                            &mut storage,
                            &mut rescue_engine,
                            &mut wallet_store,
                            bonded,
                            freertos_now_ms,
                            &mut fw_log,
                            &mut key_mgr,
                            &mut oath_applet,
                        );
                        // Wave2: release/recovery apagou a NVS no dispatch;
                        // espelha no cache RAM (fail-closed até o rekey).
                        #[cfg(feature = "proximity")]
                        {
                            use crate::ble_gatt as g;
                            let revoked = prox_revoked_op == g::OP_BIND_RELEASE
                                || prox_revoked_op == g::OP_RECOVERY_UNLOCK;
                            if revoked && crate::proximity::load_proximity_key(&storage).is_err() {
                                prox.erase();
                            }
                        }
                    }
                    Ok(None) => {
                        ble::esp_ble_set_pending_len(ble::pending_len(&ble_server));
                    }
                    Err(e) => {
                        kprintln!("[BLE] fragmento rejeitado: {}", e);
                        let op = frag.first().copied().unwrap_or(0x83);
                        let frame = ble::notify_frame(op, e.to_vendor_status(), &[]);
                        let _ = ble::esp_ble_notify(&frame);
                    }
                }
            }
            // C2. Service CCID frames (F4 PIV; composite interface 2).
            #[cfg(not(feature = "board-ttgo-classic"))]
            {
                // SAFETY: só lê o estado do driver TinyUSB; sem ponteiros.
                let usb_mounted = unsafe { aegis_usb_is_mounted() };
                if usb_mounted {
                    const CCID_FRAME_MAX: usize = 2048;
                    let mut frame = [0u8; CCID_FRAME_MAX];
                    // SAFETY: `frame` tem 2048 B vivos; o C escreve até
                    // 2048 B e devolve o total; só lemos `frame[..n]`.
                    let n =
                        unsafe { aegis_ccid_pop_frame(frame.as_mut_ptr(), CCID_FRAME_MAX as u16) };
                    if n >= 10 {
                        if let Some(rpdu) = crate::ccid_dispatch::process_ccid_frame(
                            &mut ccid_transport,
                            &frame[..n as usize],
                            &mut storage,
                            &mut key_mgr,
                            freertos_now_ms / 1000,
                        ) {
                            if !unsafe { aegis_ccid_send(rpdu.as_ptr(), rpdu.len() as u16) } {
                                kprintln!("[CCID] bulk-IN send falhou ({} B).", rpdu.len());
                            }
                        }
                    }
                }
            }
        }
        match sched.queue.receive(Some(100)) {
            Some(ev @ (FirmwareEvent::UsbPacket(_) | FirmwareEvent::SerialPacket(_))) => {
                // CTAPHID com origem preservada (seção C legada, sem bloqueio):
                // acumula no manager do transporte de entrada, despacha ao
                // `CtapEngine` e responde 64 B pela MESMA origem. Vendor serial
                // (bind-mgmt/wallet/fw-log/rescue/pairing, seção D legada) vai
                // junto no contexto; U2F/OTA/desconhecido cai no engine.
                let pin_uv_session = ctap_engine.pin_state.has_valid_pin_uv_session();
                // Liveness lida NA HORA (não o cache do Tick, atualizado só
                // 1×/s): sem isto, janela recém-aberta (TEST_PAIRING_OPEN /
                // trigger 0x2F) era vista como fechada até o próximo Tick e
                // o gate devolvia 0x05 indevido no mesmo segundo da abertura.
                #[cfg(feature = "test-mode")]
                let pairing_live = pairing_mgr.is_pairing_window_open(freertos_now_ms)
                    || freertos_test.is_pairing_window_open(freertos_now_ms);
                #[cfg(not(feature = "test-mode"))]
                let pairing_live = pairing_mgr.is_pairing_window_open(freertos_now_ms);
                let mut vendor_ctx = SerialVendorCtx {
                    pairing_open: pairing_live,
                    up_latched: touch_latched,
                    now_ms: freertos_now_ms,
                    now_secs: freertos_now_ms / 1000,
                    binding: &mut binding_mgr,
                    storage: &mut storage,
                    wallet: &mut wallet_store,
                    key_mgr: &mut key_mgr,
                    oath: &mut oath_applet,
                    fwlog: &mut fw_log,
                    rescue: &mut rescue_engine,
                    pairing: &mut pairing_mgr,
                    pin_uv_session,
                };
                let out = route_ctaphid_event(
                    &mut ctaphid_usb,
                    &mut ctaphid_serial,
                    &mut ctap_engine,
                    &ev,
                    touch_latched,
                    freertos_now_ms,
                    freertos_now_ms / 1000,
                    Some(&mut vendor_ctx),
                );
                if out.consumed_up {
                    touch_latched = false;
                }
                // Fio compartilhado UART: marca janela quieta em qualquer
                // pacote serial (recebido ou respondido) p/ o dreno TEST
                // não morder o próximo frame da rajada.
                #[cfg(all(target_os = "espidf", feature = "test-mode"))]
                if matches!(ev, FirmwareEvent::SerialPacket(_))
                    || matches!(out.origin, Some(PacketOrigin::Serial))
                {
                    serial_quiet_until_ms = freertos_now_ms.saturating_add(40);
                }
                if !out.responses.is_empty() {
                    kprintln!(
                        "[FREERTOS] ctaphid resp ({} pkt, origem={:?}).",
                        out.responses.len(),
                        out.origin
                    );
                }
                for pkt in &out.responses {
                    match out.origin {
                        Some(PacketOrigin::Usb) => {
                            // SAFETY: `pkt` vive até ao fim da chamada; o C só
                            // lê 64 B para o endpoint HID de entrada.
                            unsafe {
                                aegis_usb_send_report(pkt.as_ptr(), 64);
                            }
                        }
                        Some(PacketOrigin::Serial) => {
                            // `pkt` vivo até ao fim da chamada; o C só
                            // lê 64 B para TX serial enquadrada.
                            serial_send_bytes(pkt.as_ptr(), 64);
                        }
                        None => {}
                    }
                }
            }
            Some(FirmwareEvent::ButtonPress { boot, key }) => {
                kprintln!("[FREERTOS] UP latch boot={} key={}.", boot, key);
                // UP físico arma o latch 1x do CTAPHID (expira em 1,5 s).
                if boot {
                    touch_latched = true;
                    touch_expire_ms = freertos_now_ms.saturating_add(1500);
                    rescue_engine.set_user_presence(true);
                    pairing_mgr.on_button_level(true, freertos_now_ms);
                    boot_held_since_ms = Some(freertos_now_ms);
                }
                // KEY (GPIO 14) alterna as contas TOTP reais do device.
                if key {
                    let tick10ms = freertos_now_ms / 10;
                    let entries =
                        collect_totp_codes(&mut oath_applet, freertos_now_ms / 1000, true);
                    if entries.is_empty() {
                        totp_display_until = tick10ms.saturating_add(TOTP_SHOW_TICKS);
                        display_mgr.set_screen(UiScreen::Error {
                            message: NO_ACCOUNTS_MSG.into(),
                        });
                    } else {
                        totp_account_idx = (totp_account_idx + 1) % entries.len();
                        let entry = &entries[totp_account_idx];
                        kprintln!("[KEY BUTTON] TOTP '{}' (FreeRTOS).", entry.account);
                        totp_display_until = tick10ms.saturating_add(TOTP_SHOW_TICKS);
                        display_mgr.set_screen(UiScreen::TotpCode {
                            label: entry.account.clone(),
                            code: entry.code.clone(),
                            remaining_seconds: entry.remaining_seconds,
                        });
                    }
                }
                #[cfg(feature = "proximity")]
                if boot {
                    prox.note_presence(prox_now_ms);
                }
            }
            Some(FirmwareEvent::Tick10ms(t)) => {
                if t % 100 == 0 {
                    kprintln!("[FREERTOS] tick {}.", t);
                }
                // Relógio do roteamento + expiração do latch UP (1,5 s).
                freertos_now_ms = t.saturating_mul(10);
                if touch_latched && freertos_now_ms >= touch_expire_ms {
                    touch_latched = false;
                    rescue_engine.set_user_presence(false);
                }
                // Nível do BOOT p/ hold (5s pareamento / 2s TOTP): o evento
                // é borda; 300 ms sem repetição = solto.
                if let Some(since) = boot_held_since_ms {
                    if freertos_now_ms.saturating_sub(since) > 300 {
                        boot_held_since_ms = None;
                        pairing_mgr.on_button_level(false, freertos_now_ms);
                    }
                }
                // Avança a janela TEST_PAIRING_OPEN[_300] (expira como o hold).
                #[cfg(feature = "test-mode")]
                {
                    freertos_test_now_ms = t.saturating_mul(10);
                    freertos_test.tick(freertos_test_now_ms);
                }
                // Pairing: alimenta nível + tick; borda da janela no fw-log.
                pairing_mgr.tick(freertos_now_ms);
                {
                    use crate::fw_log as fl;
                    #[cfg(feature = "test-mode")]
                    let test_open = freertos_test.is_pairing_window_open(freertos_now_ms);
                    #[cfg(not(feature = "test-mode"))]
                    let test_open = false;
                    pairing_open_now =
                        pairing_mgr.is_pairing_window_open(freertos_now_ms) || test_open;
                    if pairing_open_now && !pairing_open_prev {
                        fw_log.record(fl::EV_PAIR_OPEN, 0, freertos_now_ms);
                    } else if !pairing_open_now && pairing_open_prev {
                        fw_log.record(fl::EV_PAIR_CLOSE, 0, freertos_now_ms);
                        // Close/timeout (Locked): radio mudo no close. O
                        // `WifiApManager` so expira por tempo; sem isto ele
                        // seguia `Active` apos o close e, caido o veto BLE, o
                        // poll pedia Start sem heap -> OOM/abort do IDF.
                        wifi_ap_mgr.shutdown_after_config();
                        if wifi_ap_active {
                            let _ = crate::wifi_ap::esp_ap_stop();
                            wifi_ap_active = false;
                            kprintln!("[WIFI] AP off (pairing fechado).");
                        }
                    }
                    pairing_open_prev = pairing_open_now;
                }
                binding_mgr.tick(freertos_now_ms);
                let _ = binding_mgr.is_claimed();
                // WiFi (paridade legada): AP em pareamento, station fora dele
                // com backoff, mDNS com station up, radio off fora de uso.
                // Precedência: USB > WiFi > BLE (BLE desliga com WiFi ativo).
                wifi_ap_mgr.update(pairing_open_now, false, freertos_now_ms);
                let ap_want = wifi_ap_mgr.is_active(freertos_now_ms);
                if !ap_want {
                    wifi_ap_fails = 0;
                }
                {
                    use crate::ble_nimble as ble;
                    // Gate BLE ao vivo (Fix gate TEST): `TEST_PAIRING_OPEN`
                    // arma a janela em `freertos_test`, não em `pairing_mgr`.
                    // Sem o OR o adv nunca ligava em janela TEST (só o AP
                    // subia). Espelha o `pairing_live` do despacho vendor;
                    // `should_advertise` preserva o mute em `PairingAp`.
                    #[cfg(feature = "test-mode")]
                    let ble_pairing_now = ble::should_advertise(&pairing_mgr, freertos_now_ms)
                        || freertos_test.is_pairing_window_open(freertos_now_ms);
                    #[cfg(not(feature = "test-mode"))]
                    let ble_pairing_now = ble::should_advertise(&pairing_mgr, freertos_now_ms);
                    match crate::wifi_ap::ap_poll_action(ap_want, ble_pairing_now, wifi_ap_active) {
                        crate::wifi_ap::ApPollAction::Start => {
                            if wifi_ap_fails < 3
                                && (wifi_ap_last_try_ms == 0
                                    || freertos_now_ms.saturating_sub(wifi_ap_last_try_ms) >= 5000)
                            {
                                // Guarda de heap: sem bloco contiguo o driver
                                // aborta (OOM) em vez de retornar erro.
                                #[cfg(target_os = "espidf")]
                                // SAFETY: só lê o maior bloco livre do heap; sem ponteiros, sem escrita.
                                let largest: usize = unsafe {
                                    esp_idf_sys::heap_caps_get_largest_free_block(
                                        esp_idf_sys::MALLOC_CAP_DEFAULT,
                                    )
                                };
                                #[cfg(not(target_os = "espidf"))]
                                let largest: usize = usize::MAX;
                                if !crate::wifi_ap::wifi_ap_start_allowed(largest) {
                                    wifi_ap_last_try_ms = freertos_now_ms;
                                    kprintln!("[WIFI] AP skip (heap curto).");
                                } else {
                                    wifi_ap_last_try_ms = freertos_now_ms;
                                    let ssid = crate::wifi_ap::ap_ssid_for_serial(
                                        usb_descriptors::SERIAL_NUMBER_STRING,
                                    );
                                    let pass_bytes = storage
                                        .load(crate::wifi_ap::WIFI_PASS_NVS_KEY)
                                        .unwrap_or_default();
                                    let pass_opt = crate::wifi_ap::resolve_ap_password(
                                        if pass_bytes.is_empty() {
                                            None
                                        } else {
                                            Some(&pass_bytes)
                                        },
                                    );
                                    let pass_str = pass_opt.unwrap_or_default();
                                    let rc = crate::wifi_ap::esp_ap_start(&ssid, &pass_str);
                                    if rc == 0 {
                                        wifi_ap_active = true;
                                        wifi_ap_fails = 0;
                                        kprintln!("[WIFI] AP '{}' on (pareamento).", ssid);
                                    } else if rc == crate::wifi_ap::WIFI_AP_RC_NO_MEM {
                                        // NO_MEM terminal ate nova borda, sem retry.
                                        wifi_ap_fails = 3;
                                        kprintln!(
                                            "[WIFI] AP start rc=-4 NO_MEM (terminal ate nova borda)."
                                        );
                                    } else {
                                        wifi_ap_fails = wifi_ap_fails.saturating_add(1);
                                        if wifi_ap_fails == 1 {
                                            kprintln!("[WIFI] AP start rc={} (backoff 5s).", rc);
                                        }
                                    }
                                }
                            }
                        }
                        crate::wifi_ap::ApPollAction::Stop => {
                            let _ = crate::wifi_ap::esp_ap_stop();
                            wifi_ap_active = false;
                            kprintln!("[WIFI] AP off.");
                        }
                        crate::wifi_ap::ApPollAction::None => {}
                    }
                    let has_creds = crate::wifi_station::has_station_credentials(&storage);
                    sta_mgr.update(pairing_open_now, has_creds, freertos_now_ms);
                    let mut sta_radio = crate::wifi_station::esp_sta_state();
                    if sta_radio == crate::wifi_station::STA_CONNECTED {
                        if !sta_mgr.is_up() {
                            sta_mgr.on_connected();
                            let ip = crate::wifi_station::esp_sta_ip();
                            kprintln!(
                                "[WIFI] station conectada (DHCP {}.{}.{}.{}).",
                                ip[0],
                                ip[1],
                                ip[2],
                                ip[3]
                            );
                        }
                    } else if sta_radio == crate::wifi_station::STA_FAILED {
                        sta_mgr.on_failed();
                    }
                    if matches!(
                        sta_mgr.state(),
                        crate::wifi_station::WifiStationState::Connecting { .. }
                    ) && sta_radio == crate::wifi_station::STA_OFF
                        && !pairing_open_now
                        && !ble_pairing_now
                        && crate::wifi_station::sta_retry_due(freertos_now_ms, last_sta_attempt_ms)
                    {
                        let got = storage.load(crate::wifi_station::WIFI_STA_SSID_NVS_KEY);
                        let got_pass = storage.load(crate::wifi_station::WIFI_STA_PASS_NVS_KEY);
                        match (got, got_pass) {
                            (Ok(ssid_b), Ok(pass_b)) => {
                                match (core::str::from_utf8(&ssid_b), core::str::from_utf8(&pass_b))
                                {
                                    (Ok(ssid), Ok(pass)) => {
                                        let rc = crate::wifi_station::esp_sta_start(ssid, pass);
                                        last_sta_attempt_ms = Some(freertos_now_ms);
                                        if rc != 0 {
                                            kprintln!("[WIFI] station start rc={}.", rc);
                                            sta_mgr.on_failed();
                                        }
                                    }
                                    _ => sta_mgr.on_failed(),
                                }
                            }
                            _ => sta_mgr.on_failed(),
                        }
                    }
                    if (pairing_open_now || ble_pairing_now || !has_creds)
                        && sta_radio != crate::wifi_station::STA_OFF
                    {
                        let _ = crate::wifi_station::esp_sta_stop();
                        sta_mgr.disconnect();
                        #[allow(unused_assignments)]
                        {
                            sta_radio = crate::wifi_station::STA_OFF;
                        }
                    }
                    mdns_mgr.update(pairing_open_now || ble_pairing_now, sta_mgr.is_up());
                    let mdns_want = mdns_mgr.is_active();
                    if mdns_want != mdns_active {
                        if mdns_want {
                            let host = crate::mdns::mdns_hostname_for_serial(
                                usb_descriptors::SERIAL_NUMBER_STRING,
                            );
                            let bare = crate::mdns::mdns_bare_hostname(&host);
                            let rc = crate::mdns::esp_mdns_start(bare);
                            if rc == 0 {
                                mdns_active = true;
                                kprintln!("[WIFI] mDNS '{}' on.", host);
                            } else {
                                kprintln!("[WIFI] mDNS start rc={}.", rc);
                            }
                        } else {
                            let _ = crate::mdns::esp_mdns_stop();
                            mdns_active = false;
                        }
                    }
                    sta_radio = crate::wifi_station::esp_sta_state();
                    let radio_in_use = wifi_ap_active || sta_radio != crate::wifi_station::STA_OFF;
                    if !radio_in_use && wifi_radio_on {
                        let _ = crate::wifi_ap::esp_wifi_off();
                        wifi_radio_on = false;
                        kprintln!("[WIFI] radio off (bateria).");
                    } else if radio_in_use {
                        wifi_radio_on = true;
                    }
                    // BLE real: adv na janela de pareamento; reconexão de
                    // confiável sem janela SÓ com saúde BLE provada
                    // (`ble_preinit_ok` via TEST_BLE_PREINIT rc=0).
                    // Fail-closed: sem preinit saudável, o Tick pós-claim
                    // (claimed + Idle) fica mudo em vez de chamar
                    // `esp_ble_start → nimble_port_init` (LoadProhibited).
                    let trusted = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
                    // Mesmo gate vivo do AP/BLE acima: janela TEST
                    // (`freertos_test`) também pede adv; sem isto o Tick
                    // pós-`TEST_PAIRING_OPEN` ficava mudo (sem EV_ADV_START).
                    let ble_want_adv = ble_pairing_now
                        || (ble_preinit_ok
                            && ble::should_advertise_reconnect(pairing_mgr.state(), trusted));
                    if ble_want_adv != ble_adv_active {
                        if ble_want_adv {
                            let wifi_active =
                                wifi_ap_mgr.is_active(freertos_now_ms) || sta_mgr.is_up();
                            if ble::BleStartGate::allow(&mut ble_start_gate, true, freertos_now_ms)
                            {
                                let rc = ble::esp_ble_start(pairing_open_now, wifi_active);
                                if rc == ble::BLE_ADV_RC_NOMEM {
                                    // 519 residual: registra e NAO consome retry.
                                    ble_start_gate.on_nomem();
                                    fw_log.record(crate::fw_log::EV_ADV_NOMEM, 0, freertos_now_ms);
                                    kprintln!(
                                        "[BLE] adv start rc=519 NOMEM (residual; sem gastar retry)."
                                    );
                                } else {
                                    ble_start_gate.on_result(rc == 0);
                                    if rc == 0 {
                                        ble_adv_active = true;
                                        fw_log.record(
                                            crate::fw_log::EV_ADV_START,
                                            0,
                                            freertos_now_ms,
                                        );
                                    } else {
                                        kprintln!("[BLE] adv start rc={} (backoff 5s).", rc);
                                    }
                                }
                            }
                        } else {
                            let _ = ble::esp_ble_stop();
                            ble_adv_active = false;
                            ble_bond_pending = false;
                            ble_start_gate.allow(false, freertos_now_ms);
                            fw_log.record(crate::fw_log::EV_ADV_STOP, 0, freertos_now_ms);
                        }
                    }
                }
                #[cfg(feature = "proximity")]
                {
                    prox_now_ms = freertos_now_ms;
                    // USB veta o beacon (controlador dedicado tem prioridade).
                    // SAFETY: `aegis_usb_is_mounted` só lê o estado do
                    // driver TinyUSB; sem ponteiros, sem escrita.
                    let usb_active = unsafe { aegis_usb_is_mounted() };
                    // TEST_UP (test-mode): 1 UP software, consumo único
                    // (latch 1,5 s via `note_presence` + latch 1x do CTAPHID
                    // + presença p/ BLE/rescue).
                    #[cfg(feature = "test-mode")]
                    if freertos_test.take_up() {
                        touch_latched = true;
                        touch_expire_ms = prox_now_ms.saturating_add(1500);
                        rescue_engine.set_user_presence(true);
                        pairing_mgr.on_button_level(true, prox_now_ms);
                        boot_held_since_ms = Some(prox_now_ms);
                        prox.note_presence(prox_now_ms);
                        kprintln!("[TEST] UP via software CONFIRMED (latch 1x).");
                    }
                    let wifi_active = wifi_ap_mgr.is_active(freertos_now_ms) || sta_mgr.is_up();
                    prox.tick(prox_now_ms, usb_active, wifi_active, pairing_mgr.state());
                }
                // Display + LED (seção B legada): tick + efeito por estado.
                // TEST_LED_* (hold) vence o pipeline quando armado.
                display_mgr.tick(Duration::from_millis(freertos_now_ms));
                {
                    let bonded = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
                    if matches!(display_mgr.current_screen, UiScreen::IdleStandby { .. })
                        && (pairing_mgr.state() != crate::pairing::PairingState::Idle || bonded)
                    {
                        if let Some(ref mut led) = display_mgr.led_controller {
                            led.set_effect(crate::pairing_led::effect_for_pairing_state(
                                pairing_mgr.state(),
                                bonded,
                            ));
                        }
                    }
                }
                #[cfg(all(target_os = "espidf", feature = "test-mode"))]
                if let Some(held) = led_test_hold {
                    if let Some(ref mut led) = display_mgr.led_controller {
                        led.set_effect(held);
                    }
                }
                // Hold físico: 5s abre pareamento (via PairingManager), 2s
                // calcula TOTP no device (WAVE8, sem segredo no log).
                if let Some(since) = boot_held_since_ms {
                    use crate::pairing_flow as pf;
                    let held_ms = freertos_now_ms.saturating_sub(since);
                    let hold_action = pf::classify_hold(held_ms, pairing_open_now);
                    if hold_action == pf::HoldAction::Totp && totp_display_until <= t {
                        totp_display_until = t.saturating_add(TOTP_SHOW_TICKS);
                        let entries =
                            collect_totp_codes(&mut oath_applet, freertos_now_ms / 1000, true);
                        if entries.is_empty() {
                            display_mgr.set_screen(UiScreen::Error {
                                message: NO_ACCOUNTS_MSG.into(),
                            });
                        } else {
                            totp_account_idx %= entries.len();
                            let entry = &entries[totp_account_idx];
                            kprintln!(
                                "[TOTP] '{}' ({} conta(s), FreeRTOS).",
                                entry.account,
                                entries.len()
                            );
                            display_mgr.set_screen(UiScreen::TotpCode {
                                label: entry.account.clone(),
                                code: entry.code.clone(),
                                remaining_seconds: entry.remaining_seconds,
                            });
                        }
                    }
                }
                if totp_display_until > 0 && t >= totp_display_until {
                    totp_display_until = 0;
                    display_mgr.set_screen(UiScreen::IdleStandby {
                        status_text: "Aguardando solicitação FIDO2...".into(),
                    });
                } else if totp_display_until > t && t % 100 == 0 {
                    let entries =
                        collect_totp_codes(&mut oath_applet, freertos_now_ms / 1000, true);
                    if !entries.is_empty() {
                        totp_account_idx %= entries.len();
                        let entry = &entries[totp_account_idx];
                        display_mgr.set_screen(UiScreen::TotpCode {
                            label: entry.account.clone(),
                            code: entry.code.clone(),
                            remaining_seconds: entry.remaining_seconds,
                        });
                    }
                }
                // Sem proximidade o latch UP não tem onde ancorar: consome e
                // mantém só o ack já enviado (documentado; sem latch).
                #[cfg(all(feature = "test-mode", not(feature = "proximity")))]
                if freertos_test.take_up() {
                    kprintln!("[TEST] UP sem prox (ack já enviado, sem latch).");
                }
            }
            Some(FirmwareEvent::BleFragment(_, len)) => {
                // Via task dedicada (nenhuma ativa hoje): o poll direto
                // `esp_ble_fetch_rx` + `ble_dispatch_complete` roda a cada
                // iteração do loop acima (bonding, BIND, vendor, OATH vivos).
                kprintln!("[FREERTOS] ble fragment ({} B, via task).", len);
            }
            Some(FirmwareEvent::Shutdown) => {
                kprintln!("[FREERTOS] shutdown.");
                #[cfg(feature = "proximity")]
                {
                    prox.erase();
                    kprintln!("[PROX] K_prox zerado no shutdown.");
                }
                break;
            }
            None => {}
        }
        // Health-check de boot (1x): roda SÓ após o primeiro yield (`receive`
        // acima cedeu ao scheduler), nunca na main pré-yield onde a stack tem
        // ~116 B. Log equivalente ao health-check original.
        #[cfg(target_os = "espidf")]
        if boot_state_pending {
            boot_state_pending = false;
            let init_nonce = [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            ];
            match storage.store("boot_state", b"BOOT_SUCCESS_V1", &init_nonce) {
                Ok(()) => kprintln!("[INIT] boot_state ok (pos-yield, 1x/boot)."),
                Err(_) => kprintln!("[WARN] boot_state nao persistiu (segue sem NVS)."),
            }
        }
    }
    let _ = usb_h.join();
    let _ = btn_h.join();
    let _ = hk_h.join();
    kprintln!("[FREERTOS] scheduler stopped.");
}

#[cfg_attr(feature = "freertos", allow(dead_code))]
pub fn run_authenticator() {
    kprintln!("\r\n============================================================");
    kprintln!("   AegisKey S3 Authenticator - Firmware Booting up");
    kprintln!("   Target: ESP32-S3 (Dual-Core Xtensa LX7 @ 240MHz)");
    kprintln!(
        "   VID: 0x{:04X} | PID: 0x{:04X}",
        usb_descriptors::USB_VID,
        usb_descriptors::USB_PID
    );
    kprintln!("   Manufacturer: {}", usb_descriptors::MANUFACTURER_STRING);
    kprintln!("   Product:      {}", usb_descriptors::PRODUCT_STRING);
    kprintln!("   Serial:       {}", usb_descriptors::SERIAL_NUMBER_STRING);
    kprintln!("   AAGUID:       00010203-0405-0607-0809-0a0b0c0d0e0f");
    kprintln!("============================================================");

    // 0. Initialize Native Hardware USB-OTG Peripheral with TinyUSB HID (Usage Page 0xF1D0) FIRST
    kprintln!("[INIT] Initializing ESP32-S3 Native USB-OTG Controller as FIDO2 CTAPHID...");
    #[cfg(target_os = "espidf")]
    let usb_installed = unsafe {
        let err = aegis_usb_init();
        if err == esp_idf_sys::ESP_OK {
            kprintln!("[INIT] Native TinyUSB FIDO2 HID Driver installed successfully!");
            true
        } else {
            kprintln!("[WARN] USB driver returned code: 0x{:04X}", err);
            false
        }
    };
    #[cfg(not(target_os = "espidf"))]
    let usb_installed = true;
    #[cfg(not(target_os = "espidf"))]
    let _ = usb_installed;
    // Serial CTAPHID UART ready flag (classic reuses the UART transport above;
    // S3/S2 bring up UART0 as the diagnostic channel next to native USB).
    #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
    let serial_installed = unsafe {
        if aegis_serial_init() == esp_idf_sys::ESP_OK {
            kprintln!("[INIT] Serial CTAPHID UART online (115200 8N1, framing = USB).");
            true
        } else {
            kprintln!("[WARN] Serial CTAPHID UART init failed; USB stays primary.");
            false
        }
    };
    #[cfg(all(target_os = "espidf", feature = "board-ttgo-classic"))]
    let serial_installed = usb_installed;

    // 1. Initialize Display Subsystem (WS2812 RGB LED on DevKitC-1 + ST7789 IPS LCD on LilyGO T-Display)
    kprintln!("[INIT] Initializing Display & Visual Feedback Engine...");
    #[cfg(feature = "board-devkitc")]
    let led_controller = {
        let mut led_output = EspWs2812Output::new(48);
        led_output.init_hardware();
        Some(Ws2812Controller::new(led_output))
    };
    #[cfg(not(feature = "board-devkitc"))]
    let led_controller: Option<Ws2812Controller<EspWs2812Output>> = None;

    let mut display_mgr = DisplayManager::new(led_controller);
    let _ = display_mgr.init_hardware();

    // Boot visual self-test: Splash Screen + animation
    kprintln!("[INIT] Boot splash screen: AegisKey S3 Shield Logo...");
    #[cfg(feature = "board-ttgo-classic")]
    let chip_str = "ESP32 Classic (TTGO)".into();
    #[cfg(not(feature = "board-ttgo-classic"))]
    let chip_str = "ESP32-S3 Dual-Core".into();

    display_mgr.set_screen(UiScreen::BootSplash {
        version: "v1.0.0 (Rust)".into(),
        chip: chip_str,
    });
    for step in 0..30 {
        display_mgr.tick(Duration::from_millis(step * 33));
        std::thread::sleep(Duration::from_millis(33));
    }

    // Set to idle standby
    display_mgr.set_screen(UiScreen::IdleStandby {
        status_text: "Aguardando solicitação FIDO2...".into(),
    });
    kprintln!("[INIT] UI and visual engine online.");

    // 2. Initialize Hardware eFuse OTP (BLOCK7 Master Key, BLOCK8 Device Salt)
    // Wave3 P2: provision loader with fallback (no hardcoded 0x5A/0xA5 in prod).
    kprintln!("[INIT] Initializing eFuse OTP subsystem...");
    let efuse_storage = RamEfuseStorage::new();
    let efuse_mgr = EfuseManager::new(efuse_storage);

    let keys = match load_device_keys(&efuse_mgr) {
        Ok(keys) => {
            kprintln!("[INIT] Hardware Master Key & Salt loaded from eFuse OTP.");
            keys
        }
        Err(e) => {
            // Fail-operational: dispositivo sem provisionamento de fabrica.
            // Gera chaves efemeras via TRNG (RAM, zeradas no reboot) e segue o boot
            // com comportamento identico ao modo dev anterior. NUNCA panic no boot.
            kprintln!("[WARN] eFuse nao provisionado ({e:?}); usando chaves efemeras TRNG (modo DEV, sem persistencia entre reboots). Rode tools/factory_provision.py para provisionar.");
            use rand_core::RngCore;
            let mut rng = rand_core::OsRng;
            let mut master_key = [0u8; 32];
            let mut salt = [0u8; 32];
            rng.fill_bytes(&mut master_key);
            rng.fill_bytes(&mut salt);
            // CI-GREP: TEST-HOOK (test-mode only; absent in release).
            // Sem burn de eFuse, com persistencia p/ teste: a chave-dev mora
            // em flash NVS (namespace "aegisdev"), reutilizada entre boots.
            // Release sem test-mode NEM COMPILA este ramo (efemero puro).
            #[cfg(all(target_os = "espidf", feature = "test-mode"))]
            if let Ok((m, s)) = crate::nvs_backend::load_or_create_dev_keys() {
                kprintln!("[TEST] dev-key flash persistente ativa (test-mode only).");
                master_key = m;
                salt = s;
            }
            crate::provision::DeviceKeys {
                master_key,
                device_salt: salt,
            }
        }
    };
    let master_key = keys.master_key;
    let salt = keys.device_salt;

    // 3. Initialize Encrypted Flash / NVS Persistence
    kprintln!("[INIT] Initializing AES-256-GCM Encrypted Storage...");
    let flash_backend = PlatformFlashBackend::new();
    if flash_backend.is_persistent() {
        kprintln!("[INIT] Flash NVS backend online (persiste entre reboots).");
    } else {
        kprintln!("[WARN] Flash NVS indisponivel; RAM volatil (sem persistencia).");
    }
    let mut storage = SecureStorage::new(flash_backend, &master_key, &salt);
    // AUDIT-PREP: wiring na Wave4

    let init_nonce = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    ];
    storage
        .store("boot_state", b"BOOT_SUCCESS_V1", &init_nonce)
        .expect("Persist boot state");
    kprintln!("[INIT] Encrypted Flash / NVS storage ready.");

    // Binding: dono exclusivo de BLE vendor + WiFi mgmt (release exige vinculo
    // para CONFIGURAR; teste faz bypass com ltrace). USB/CTAP zero mudanca.
    // Carrega da NVS (par ausente = Unclaimed; parcial = Corrupted e exige reset).
    let mut binding_mgr = match crate::binding::BindingManager::load_from_storage(&storage) {
        Ok(m) => {
            kprintln!("[INIT] Binding loaded (claimed={}).", m.is_claimed());
            m
        }
        Err(e) => {
            kprintln!("[WARN] Binding store inconsistent ({e}); starting unclaimed (factory_reset recovers).");
            crate::binding::BindingManager::new()
        }
    };

    // 4. Initialize Hardware Buttons: BOOT (GPIO 0) + Optional KEY (GPIO 14 / GPIO 35)
    kprintln!("[INIT] Initializing Hardware Buttons...");
    let boot_input = EspBootButtonInput::new();
    #[cfg(any(feature = "board-t-display", feature = "board-ttgo-classic"))]
    let key_input = Some(EspKeyButtonInput::new());
    #[cfg(not(any(feature = "board-t-display", feature = "board-ttgo-classic")))]
    let key_input: Option<EspKeyButtonInput> = None;

    let button_mgr = DualButtonManager::new(boot_input, key_input);
    kprintln!("[INIT] User Presence (UP) sensor online.");

    // 5. Initialize Rust CTAPHID Manager and CTAP2 Core Engine
    #[allow(unused_mut)]
    let mut ctaphid_mgr = CtapHidManager::new();
    #[allow(unused_mut)]
    let mut ctap_engine = CtapEngine::new(master_key, 0);
    // WAVE8: OATH real no device (contas do NVS via PUT; display calcula CALCULATE no long-press).
    let mut oath_applet = OathApplet::new();
    // F2: chaves vendor on-device (NVS persistente).
    let mut key_mgr = aegis_fido_core::credential::key_manager::KeyManager::new();
    if !crate::vendor_exec::load_states(&storage, &mut key_mgr, &mut oath_applet) {
        kprintln!("[WARN] vendor NVS inconsistente; começando vazio.");
    }
    // F3: PIN persistente (hash+retries; sessão pinUvAuth morre no reboot).
    if !crate::vendor_exec::load_pin_state(&storage, &mut ctap_engine.pin_state) {
        kprintln!("[WARN] PIN NVS inconsistente; sem PIN.");
    }
    #[cfg(not(target_os = "espidf"))]
    let _ = (&ctaphid_mgr, &ctap_engine);
    // Classic serves CTAPHID through the serial section D (ctaphid_mgr stays
    // as the S3-USB manager only).
    #[cfg(all(target_os = "espidf", feature = "board-ttgo-classic"))]
    let _ = &ctaphid_mgr;
    let mut rescue_engine = RescueEngine::new();
    // Wave1: latch uso unico; PIN para RESC so apos verify_token_permission Ok.
    // Carteira Fase7: WalletStore de sessão (RAM; NVS = follow-up).
    let mut wallet_store = WalletStore::new();
    // Log real do device p/ o app (op 0x38; RAM, sem PII/segredos).
    let mut fw_log = crate::fw_log::FwLog::new();
    fw_log.record(crate::fw_log::EV_BOOT, 0, 0);

    kprintln!("============================================================");
    kprintln!("   AegisKey S3 Authenticator ONLINE & ACTIVE!");
    kprintln!("   FIDO2 / WebAuthn ready on native USB (HID Usage Page 0xF1D0)");
    kprintln!("   Dual-Board Ready: DevKitC-1 (WS2812) / LilyGO T-Display-S3");
    kprintln!("============================================================");
    // F5: pré-init BLE no boot (heap fresco). Sem anunciar; o adv liga só
    // na janela (gate com backoff no loop).
    // Saúde BLE provada (`rc=0`): libera a reconexão de confiável sem
    // janela no loop (fail-closed, mesmo gate do FreeRTOS).
    #[allow(unused_mut)]
    let mut ble_preinit_ok = false;
    #[cfg(target_os = "espidf")]
    {
        let rc = crate::ble_nimble::esp_ble_preinit();
        if rc != 0 {
            kprintln!("[BLE] preinit rc={} (retry com backoff na janela).", rc);
        } else {
            kprintln!("[BLE] nimble preinit ok.");
            ble_preinit_ok = true;
        }
    }

    // Main Event Loop
    let mut tick: u64 = 0;
    let mut touch_latched = false;
    let mut touch_expire_tick: u64 = 0;
    // OTA staged verify-before-swap session (R-04/R-06; USB section C only).
    #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
    let mut ota_state = OtaState::new(FIRMWARE_VERSION);
    // F4: transporte CCID (framing) com applet PIV persistente entre polls
    // (seleção/PIN sobrevivem a frames; NVS+chaves emprestados por frame).
    #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
    #[allow(unused_mut)]
    let mut ccid_transport = aegis_fido_usb::ccid::CcidTransport::new();

    let mut press_start_tick: Option<u64> = None;
    let mut totp_display_until: u64 = 0;
    let mut totp_account_idx: usize = 0;
    // Phase8 UX-conex: PairingManager orfao agora alimentado no loop (hold 5s vence TOTP 2s).
    let mut pairing_mgr = crate::pairing::PairingManager::new();
    // Etapa B (BLE NimBLE real): servidor GATT 0xFFFD + estado do radio.
    let mut ble_server = crate::ble_gatt::BleGattServer::new();
    let mut ble_adv_active = false;
    let mut ble_bond_pending = false;
    // Wave2 proximidade (feature proximity): beacon rolling-code 0xFFFE.
    // fob_id de 6 B derivado do serial USB (placeholder estavel p/ host e
    // testes). Follow-up: ler o MAC BLE real via FFI (ble_hs_id_copy_addr /
    // esp_read_mac) e usar os 6 B publicos como fob_short_id; nunca inventar
    // MAC aqui. Cache RAM do K_prox + flag de presenca (fail-closed sem chave).
    // Nunca auto-unlock: beacon/RSSI so sinalizam ausencia (ver proximity.rs).
    // Vetor de interop (py == rs): K=0x42*16, fob=AA:BB:CC:DD:EE:FF, ctr=7,
    // VER=0x01 => tag=660d4941 (ver proximity_tag; agents host espelham).
    #[cfg(feature = "proximity")]
    let mut prox_beacon = crate::proximity::ProximityBeacon::new();
    #[cfg(feature = "proximity")]
    let mut prox_last_ms: u64 = 0;
    #[cfg(feature = "proximity")]
    let mut prox_key: [u8; 16] = [0u8; 16];
    #[cfg(feature = "proximity")]
    let mut prox_key_present: bool = false;
    // fob_short_id = MAC BLE publico real via own_addr(), resolvido a cada
    // tick no loop (beacon_fob_id); None (stack down) => sem adv (fail-closed).
    #[cfg(feature = "proximity")]
    let mut prox_adv_active: bool = false;
    // F5: gate de tentativas do BLE start (backoff 5s, 3 por borda).
    // Sem isso, um `nimble_port_init` falho repetia a CADA poll, vazava
    // heap do controlador até `Malloc failed` e panic (Interrupt WDT).
    let mut ble_start_gate = crate::ble_nimble::BleStartGate::new();
    let mut ble_rx = [0u8; crate::ble_nimble::BLE_RX_FRAGMENT_MAX];
    // Borda da janela de pareamento p/ o fw-log (0x38).
    let mut pairing_open_prev = false;
    // Phase8 UX-conex: mDNS+station so fora de pareamento, com fallback AP.
    let mut wifi_ap_mgr = crate::wifi_ap::WifiApManager::new();
    let mut mdns_mgr = crate::mdns::MdnsManager::new();
    let mut sta_mgr = crate::wifi_station::WifiStationManager::new();
    // Etapa B (WiFi real): espelhos do radio p/ edge-trigger + backoff.
    let mut wifi_ap_active = false;
    // Backoff do AP start: sem isso, uma falha (ex. radio com BLE) repete
    // o start a CADA poll (~10ms) com NVS load + deinit + log — inunda o
    // UART, esfomeia o loop e desgasta flash. Tenta no max 1x/5s e desiste
    // apos 3 falhas ate a proxima borda de want.
    let mut wifi_ap_last_try_ms: u64 = 0;
    let mut wifi_ap_fails: u32 = 0;
    let mut mdns_active = false;
    let mut wifi_radio_on = false;
    let mut last_sta_attempt_ms: Option<u64> = None;
    // WAVE8: sem TOTP literal — o display mostra SO codigos calculados no device
    // via `OathApplet::device_code` (contas do NVS via PUT). Sem contas -> "sem contas".

    #[cfg(target_os = "espidf")]
    let mut rx_buf = [0u8; PACKET_SIZE];
    // Serial CTAPHID (UART 115200, framing identical to USB): text-tolerant
    // router plus pairing-mode + UP gates (simulator parity).
    #[cfg(target_os = "espidf")]
    let mut serial_router = crate::serial_ctaphid::SerialRouter::new();
    // Diagnostic text-line buffer (TEST_LIFETIME_DUMP with test-mode).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut serial_line: Vec<u8> = Vec::new();
    // Latch de cor solida p/ diagnostico LED (TEST_LED_*, test-mode only).
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut led_test_hold: Option<crate::led::LedEffect> = None;
    // UP por software (TEST_UP, test-mode only): injeta UM toque BOOT.
    #[cfg(all(target_os = "espidf", feature = "test-mode"))]
    let mut test_up_latch = false;

    let mut watchdog = Watchdog::new(300); // L5: feed sem mudar timing USB
                                           // Wave2 proximidade (feature proximity): carrega o K_prox da NVS cifrada.
                                           // So gera+persiste via rekey se ja houver vinculo (bonded/trusted); sem
                                           // vinculo deixa ausente fail-closed (sem adv ate o pareamento).
    #[cfg(feature = "proximity")]
    {
        match crate::proximity::load_proximity_key(&storage) {
            Ok(k) => {
                prox_key = k;
                prox_key_present = true;
                kprintln!("[PROX] K_prox carregado da NVS.");
            }
            Err(_) => {
                let bonded_now = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
                if bonded_now {
                    let mut rng = rand_core::OsRng;
                    match crate::proximity::rekey_proximity(&mut storage, &mut rng) {
                        Ok(k) => {
                            prox_key = k;
                            prox_key_present = true;
                            kprintln!("[PROX] K_prox gerado no boot (vinculo previo).");
                        }
                        Err(e) => {
                            prox_key = [0u8; 16];
                            prox_key_present = false;
                            kprintln!("[PROX] rekey falhou no boot ({e:?}); sem adv.");
                        }
                    }
                } else {
                    kprintln!("[PROX] sem K_prox (fail-closed ate parear).");
                }
            }
        }
    }

    // Wave7 test-mode: serial diagnostic inbox (host stdio; on ESP-IDF wire UART RX to dispatch_test_command).
    #[cfg(all(feature = "test-mode", not(target_os = "espidf")))]
    let diag_rx = {
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let _ = std::thread::Builder::new()
            .name("aegis_diag".into())
            .spawn(move || {
                use std::io::BufRead as _;
                let stdin = std::io::stdin();
                let mut line = String::new();
                loop {
                    line.clear();
                    match stdin.lock().read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            if tx.send(line.clone()).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        rx
    };

    loop {
        watchdog.feed(tick); // L5: feed no hot path, sem sleep
        let elapsed = Duration::from_millis(tick * 10);
        let now_ms = tick * 10;
        let now_secs = now_ms / 1000;
        #[cfg(not(target_os = "espidf"))]
        let _ = now_secs;

        // A. Check physical buttons
        // Button 1: BOOT (GPIO 0) - Confirm / UP / Long press (2s)
        // Button 2: KEY (GPIO 14 on LilyGO T-Display) - Cycle accounts / Cancel
        // TEST_UP (test-mode): UM toque via software, mesma semantica do tap
        // fisico (latch 1.5s, pairing/UP/rescue); consumo unico por comando.
        #[cfg(all(target_os = "espidf", feature = "test-mode"))]
        let test_up_once = core::mem::replace(&mut test_up_latch, false);
        #[cfg(not(all(target_os = "espidf", feature = "test-mode")))]
        let test_up_once = false;
        let is_boot_pressed = button_mgr.is_boot_pressed(std::thread::sleep) || test_up_once;
        let is_key_pressed = button_mgr.is_key_pressed(std::thread::sleep);

        // Phase8 UX-conex: alimenta PairingManager todo poll (corrige orfao).
        pairing_mgr.on_button_level(is_boot_pressed, now_ms);
        pairing_mgr.tick(now_ms);
        let pairing_open_now = pairing_mgr.is_pairing_window_open(now_ms);
        // Borda da janela -> fw-log (0x38) do app.
        {
            use crate::fw_log as fl;
            if pairing_open_now && !pairing_open_prev {
                fw_log.record(fl::EV_PAIR_OPEN, 0, now_ms);
            } else if !pairing_open_now && pairing_open_prev {
                fw_log.record(fl::EV_PAIR_CLOSE, 0, now_ms);
                // Close/timeout (Locked): radio mudo no close (mesmo fix do
                // FreeRTOS; sem isto o AP seguia `Active` e o poll pedia
                // Start sem heap -> OOM/abort).
                wifi_ap_mgr.shutdown_after_config();
                if wifi_ap_active {
                    let _ = crate::wifi_ap::esp_ap_stop();
                    wifi_ap_active = false;
                    kprintln!("[WIFI] AP off (pairing fechado).");
                }
            }
            pairing_open_prev = pairing_open_now;
        }
        // Exclusao mutua de radio (OOM BT+WiFi): BLE anuncia SOMENTE em
        // PairingBle; WiFi (AP/station/mDNS) fica desligado nesse estado.
        let ble_pairing_now = crate::ble_nimble::should_advertise(&pairing_mgr, now_ms);
        // Binding + recovery: fiação transporte GATT/main (tick todo poll; USB intacto).
        binding_mgr.tick(now_ms);
        let _ = binding_mgr.is_claimed();
        // Etapa B (WiFi real via `aegis_wifi`): AP em pareamento (SSID do
        // serial + senha da NVS, aberta no bootstrap), station fora dele com
        // backoff (bateria), mDNS com station up, power-down fora de uso.
        // Precedencia de radio: USB (controlador dedicado, intacto) > WiFi >
        // BLE. BLE e WiFi sao mutuamente exclusivos (heap do S3 nao suporta
        // os dois juntos); PairingBle desliga todo WiFi, PairingAp desliga BLE.
        wifi_ap_mgr.update(pairing_open_now, false, now_ms);
        let ap_want = wifi_ap_mgr.is_active(now_ms);
        if !ap_want {
            wifi_ap_fails = 0;
        }
        // Decisao edge-triggered (wifi_ap::ap_poll_action): cada acao
        // executa no maximo uma vez por transicao. O `else` anterior
        // chamava esp_ap_stop() a CADA poll com BLE pareando (spam de
        // close/wifi-ap no log e churn no radio durante o bonding).
        match crate::wifi_ap::ap_poll_action(ap_want, ble_pairing_now, wifi_ap_active) {
            crate::wifi_ap::ApPollAction::Start => {
                if wifi_ap_fails >= 3 {
                    // Desistiu ate a proxima borda: sem spam, sem churn.
                } else if now_ms.saturating_sub(wifi_ap_last_try_ms) < 5000
                    && wifi_ap_last_try_ms != 0
                {
                    // Backoff: aguarda 5s entre tentativas.
                } else {
                    // Guarda de heap: sem bloco contiguo o driver aborta (OOM).
                    #[cfg(target_os = "espidf")]
                    // SAFETY: só lê o maior bloco livre do heap; sem ponteiros, sem escrita.
                    let largest: usize = unsafe {
                        esp_idf_sys::heap_caps_get_largest_free_block(
                            esp_idf_sys::MALLOC_CAP_DEFAULT,
                        )
                    };
                    #[cfg(not(target_os = "espidf"))]
                    let largest: usize = usize::MAX;
                    if !crate::wifi_ap::wifi_ap_start_allowed(largest) {
                        wifi_ap_last_try_ms = now_ms;
                        kprintln!("[WIFI] AP skip (heap curto).");
                    } else {
                        wifi_ap_last_try_ms = now_ms;
                        let ssid = crate::wifi_ap::ap_ssid_for_serial(
                            usb_descriptors::SERIAL_NUMBER_STRING,
                        );
                        let pass_bytes = storage
                            .load(crate::wifi_ap::WIFI_PASS_NVS_KEY)
                            .unwrap_or_default();
                        let pass_opt =
                            crate::wifi_ap::resolve_ap_password(if pass_bytes.is_empty() {
                                None
                            } else {
                                Some(&pass_bytes)
                            });
                        let pass_str = pass_opt.unwrap_or_default();
                        // Nunca loga a senha.
                        let rc = crate::wifi_ap::esp_ap_start(&ssid, &pass_str);
                        if rc == 0 {
                            wifi_ap_active = true;
                            wifi_ap_fails = 0;
                            kprintln!("[WIFI] AP '{}' on (pareamento).", ssid);
                        } else if rc == crate::wifi_ap::WIFI_AP_RC_NO_MEM {
                            // NO_MEM terminal ate nova borda, sem retry.
                            wifi_ap_fails = 3;
                            kprintln!("[WIFI] AP start rc=-4 NO_MEM (terminal ate nova borda).");
                        } else {
                            wifi_ap_fails = wifi_ap_fails.saturating_add(1);
                            // Loga só a 1ª falha (as seguintes seriam spam a cada 5s);
                            // apos 3, desiste ate a proxima borda de want.
                            if wifi_ap_fails == 1 {
                                kprintln!(
                                    "[WIFI] AP start rc={} (backoff 5s, desiste apos 3).",
                                    rc
                                );
                            }
                        }
                    }
                }
            }
            crate::wifi_ap::ApPollAction::Stop => {
                let _ = crate::wifi_ap::esp_ap_stop();
                wifi_ap_active = false;
                kprintln!("[WIFI] AP off.");
            }
            crate::wifi_ap::ApPollAction::None => {}
        }
        // Station: so fora de pareamento, com credenciais e backoff 60s.
        let has_creds = crate::wifi_station::has_station_credentials(&storage);
        sta_mgr.update(pairing_open_now, has_creds, now_ms);
        let mut sta_radio = crate::wifi_station::esp_sta_state();
        if sta_radio == crate::wifi_station::STA_CONNECTED {
            if !sta_mgr.is_up() {
                sta_mgr.on_connected();
                let ip = crate::wifi_station::esp_sta_ip();
                kprintln!(
                    "[WIFI] station conectada (DHCP {}.{}.{}.{}).",
                    ip[0],
                    ip[1],
                    ip[2],
                    ip[3]
                );
            }
        } else if sta_radio == crate::wifi_station::STA_FAILED {
            sta_mgr.on_failed();
        }
        if matches!(
            sta_mgr.state(),
            crate::wifi_station::WifiStationState::Connecting { .. }
        ) && sta_radio == crate::wifi_station::STA_OFF
            && !pairing_open_now
            && !ble_pairing_now
            && crate::wifi_station::sta_retry_due(now_ms, last_sta_attempt_ms)
        {
            let got = storage.load(crate::wifi_station::WIFI_STA_SSID_NVS_KEY);
            let got_pass = storage.load(crate::wifi_station::WIFI_STA_PASS_NVS_KEY);
            match (got, got_pass) {
                (Ok(ssid_b), Ok(pass_b)) => {
                    match (core::str::from_utf8(&ssid_b), core::str::from_utf8(&pass_b)) {
                        (Ok(ssid), Ok(pass)) => {
                            // Credenciais nunca vao para o log.
                            let rc = crate::wifi_station::esp_sta_start(ssid, pass);
                            last_sta_attempt_ms = Some(now_ms);
                            if rc != 0 {
                                kprintln!("[WIFI] station start rc={}.", rc);
                                sta_mgr.on_failed();
                            }
                        }
                        _ => sta_mgr.on_failed(),
                    }
                }
                _ => sta_mgr.on_failed(),
            }
        }
        if (pairing_open_now || ble_pairing_now || !has_creds)
            && sta_radio != crate::wifi_station::STA_OFF
        {
            let _ = crate::wifi_station::esp_sta_stop();
            sta_mgr.disconnect();
            // Local cache update; refreshed via esp_sta_state() below. Retained for readability (no behavior change).
            #[allow(unused_assignments)]
            {
                sta_radio = crate::wifi_station::STA_OFF;
            }
        }
        mdns_mgr.update(pairing_open_now || ble_pairing_now, sta_mgr.is_up());
        let mdns_want = mdns_mgr.is_active();
        if mdns_want != mdns_active {
            if mdns_want {
                let host =
                    crate::mdns::mdns_hostname_for_serial(usb_descriptors::SERIAL_NUMBER_STRING);
                let bare = crate::mdns::mdns_bare_hostname(&host);
                let rc = crate::mdns::esp_mdns_start(bare);
                if rc == 0 {
                    mdns_active = true;
                    kprintln!("[WIFI] mDNS '{}' on.", host);
                } else {
                    kprintln!("[WIFI] mDNS start rc={}.", rc);
                }
            } else {
                let _ = crate::mdns::esp_mdns_stop();
                mdns_active = false;
            }
        }
        // Bateria: radio totalmente off fora de uso (nem AP, nem station).
        // Rele apos start/stop deste poll (evita off imediato).
        sta_radio = crate::wifi_station::esp_sta_state();
        let radio_in_use = wifi_ap_active || sta_radio != crate::wifi_station::STA_OFF;
        if !radio_in_use && wifi_radio_on {
            let _ = crate::wifi_ap::esp_wifi_off();
            wifi_radio_on = false;
            kprintln!("[WIFI] radio off (bateria).");
        } else if radio_in_use {
            wifi_radio_on = true;
        }
        // Etapa B (BLE NimBLE real): advertising na janela de pareamento
        // (flag ligada) + reconexão de confiável sem janela SÓ com saúde
        // BLE provada (`ble_preinit_ok` do preinit de boot `rc=0`).
        // Fail-closed: sem preinit saudável, claimed + Idle fica mudo em
        // vez de chamar `esp_ble_start → nimble_port_init` (LoadProhibited).
        // Coexistencia USB > WiFi > BLE: com WiFi ativo o intervalo e lento.
        let trusted = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
        let ble_want_adv = crate::ble_nimble::should_advertise(&pairing_mgr, now_ms)
            || (ble_preinit_ok
                && crate::ble_nimble::should_advertise_reconnect(pairing_mgr.state(), trusted));
        if ble_want_adv != ble_adv_active {
            if ble_want_adv {
                let wifi_active = wifi_ap_mgr.is_active(now_ms) || sta_mgr.is_up();
                // Gate: borda tenta já; falha entra em backoff 5s e desiste
                // após 3 (nunca martela `nimble_port_init` — vaza heap e
                // derruba o controlador em panic).
                if crate::ble_nimble::BleStartGate::allow(&mut ble_start_gate, true, now_ms) {
                    let rc = crate::ble_nimble::esp_ble_start(pairing_open_now, wifi_active);
                    if rc == crate::ble_nimble::BLE_ADV_RC_NOMEM {
                        // 519 residual: registra e NAO consome retry.
                        ble_start_gate.on_nomem();
                        fw_log.record(crate::fw_log::EV_ADV_NOMEM, 0, now_ms);
                        kprintln!("[BLE] adv start rc=519 NOMEM (residual; sem gastar retry).");
                    } else {
                        ble_start_gate.on_result(rc == 0);
                        if rc == 0 {
                            ble_adv_active = true;
                            fw_log.record(crate::fw_log::EV_ADV_START, 0, now_ms);
                        } else {
                            kprintln!("[BLE] adv start rc={} (backoff 5s, desiste apos 3).", rc);
                        }
                    }
                }
            } else {
                let _ = crate::ble_nimble::esp_ble_stop();
                ble_adv_active = false;
                ble_bond_pending = false;
                // Janela fechou: o gate zera na próxima borda.
                ble_start_gate.allow(false, now_ms);
                fw_log.record(crate::fw_log::EV_ADV_STOP, 0, now_ms);
            }
        }
        // Wave2 proximidade (feature proximity): adv 0xFFFE ~1 s quando Idle +
        // bonded + trusted + USB inativo + K_prox presente. USB veta o adv;
        // WiFi ativo so desacelera o intervalo (coex). Nunca auto-unlock:
        // aceitar beacon nunca destrava (unlock exige presenca + PIN).
        #[cfg(feature = "proximity")]
        {
            use crate::ble_nimble as prox_ble;
            use crate::proximity as prox_mod;
            let bonded = pairing_mgr.is_bonded();
            let trusted = bonded || binding_mgr.is_claimed();
            #[cfg(target_os = "espidf")]
            let usb_active = unsafe { aegis_usb_is_mounted() };
            #[cfg(not(target_os = "espidf"))]
            let usb_active = false;
            let wifi_active = wifi_ap_mgr.is_active(now_ms) || sta_mgr.is_up();
            // Revogado via release/recovery (dispatch apagou a NVS): limpa o
            // cache RAM na borda (fail-closed ate o proximo rekey).
            if prox_key_present && prox_mod::load_proximity_key(&storage).is_err() {
                prox_key = [0u8; 16];
                prox_key_present = false;
                if prox_adv_active {
                    let _ = prox_ble::esp_ble_stop();
                    prox_adv_active = false;
                }
                kprintln!("[PROX] K_prox revogado; adv parado.");
            }
            // Rollover (ctr travou no MAX): rekey + ctr=0; sem rekey, mudo.
            if prox_beacon.is_rollover() && prox_key_present {
                let mut rng = rand_core::OsRng;
                match prox_mod::rekey_proximity(&mut storage, &mut rng) {
                    Ok(k) => {
                        prox_key = k;
                        prox_beacon = prox_mod::ProximityBeacon::new();
                        prox_last_ms = now_ms;
                        kprintln!("[PROX] rekey pos-rollover (ctr=0).");
                    }
                    Err(e) => {
                        prox_key = [0u8; 16];
                        prox_key_present = false;
                        kprintln!("[PROX] rekey pos-rollover falhou ({e:?}).");
                    }
                }
            }
            // fob_short_id real (MAC BLE publico); None => sem adv (fail-closed).
            let prox_fob = prox_mod::beacon_fob_id();
            let want_prox = prox_ble::should_adv_proximity(
                pairing_mgr.state(),
                bonded,
                trusted,
                usb_active,
                prox_key_present,
            ) && prox_fob.is_some();
            if want_prox {
                // Radio unico: presenca 0xFFFE vence a reconexao 0xFFFD em Idle.
                if ble_adv_active {
                    let _ = prox_ble::esp_ble_stop();
                    ble_adv_active = false;
                    ble_start_gate.allow(false, now_ms);
                    fw_log.record(crate::fw_log::EV_ADV_STOP, 0, now_ms);
                }
                // So (re)anuncia no tick de ~1 s (throttle natural + backoff de
                // falha); o C e idempotente, entao para antes p/ reaplicar o
                // svc_data novo (ctr++) e o intervalo atual.
                if prox_beacon.tick_if_due(prox_last_ms, now_ms) {
                    prox_last_ms = now_ms;
                    if prox_adv_active {
                        let _ = prox_ble::esp_ble_stop();
                        prox_adv_active = false;
                    }
                    let ctr = prox_beacon.counter();
                    // Gate want_prox garante Some; o default abaixo nunca e
                    // transmitido (fail-closed sem MAC real).
                    let fob = prox_fob.unwrap_or([0u8; 6]);
                    let tag = prox_mod::proximity_tag(
                        &prox_key,
                        prox_mod::PROXIMITY_BEACON_VERSION,
                        ctr,
                        &fob,
                    );
                    let svc = prox_mod::encode_proximity_svc_data(ctr, &tag);
                    let rc = prox_ble::esp_ble_proximity_start(&svc, wifi_active);
                    if rc == 0 {
                        prox_adv_active = true;
                        fw_log.record(crate::fw_log::EV_ADV_START, 0, now_ms);
                    } else {
                        kprintln!("[PROX] adv start rc={} (retry ~1 s).", rc);
                    }
                }
            } else if prox_adv_active {
                let _ = prox_ble::esp_ble_stop();
                prox_adv_active = false;
                fw_log.record(crate::fw_log::EV_ADV_STOP, 0, now_ms);
            }
        }
        // Etapa B: bomba BLE (eventos GAP + fragmentos FFF1). USB intacto.
        {
            use crate::ble_nimble as ble;
            match ble::esp_ble_poll_event() {
                e if e == ble::BLE_EVT_SECURED => {
                    match ble::on_link_secured(&mut pairing_mgr, touch_latched, now_ms) {
                        ble::BondOutcome::Paired => {
                            touch_latched = false;
                            ble_bond_pending = false;
                            rescue_engine.set_user_presence(true);
                            let _ = ble::esp_ble_stop();
                            ble_adv_active = false;
                            display_mgr.set_screen(UiScreen::Success {
                                title: "DISPOSITIVO PAREADO".into(),
                                subtitle: "BLE seguro ativo".into(),
                            });
                            #[cfg(target_os = "espidf")]
                            if let Some(ref mut led) = display_mgr.led_controller {
                                led.set_effect(LedEffect::Solid(crate::led::Color::GREEN));
                            }
                            kprintln!(
                                "[BLE] bonding ok: advertising parado, pareamento encerrado."
                            );
                            fw_log.record(crate::fw_log::EV_BOND_OK, 0, now_ms);
                            // Wave2 proximidade: rekey do K_prox no pareamento +
                            // zera o contador do beacon (ctr=0 no proximo adv).
                            #[cfg(feature = "proximity")]
                            {
                                let mut rng = rand_core::OsRng;
                                match crate::proximity::rekey_proximity(&mut storage, &mut rng) {
                                    Ok(k) => {
                                        prox_key = k;
                                        prox_key_present = true;
                                        prox_beacon = crate::proximity::ProximityBeacon::new();
                                        prox_last_ms = now_ms;
                                        kprintln!("[PROX] rekey pos-pareamento (ctr=0).");
                                    }
                                    Err(e) => {
                                        prox_key = [0u8; 16];
                                        prox_key_present = false;
                                        kprintln!("[PROX] rekey falhou ({e:?}); sem adv.");
                                    }
                                }
                            }
                        }
                        ble::BondOutcome::DeniedNoPresence => {
                            ble_bond_pending = true;
                            kprintln!("[BLE] link seguro sem UP: toque no BOOT para confirmar.");
                            display_mgr.set_screen(UiScreen::UserPresencePrompt {
                                rp_id: "Pareamento BLE".into(),
                                user_name: "App AegisKey".into(),
                                operation: "Confirmar pareamento".into(),
                                remaining_seconds: 25,
                            });
                        }
                        ble::BondOutcome::DeniedNoWindow => {
                            kprintln!("[BLE] link seguro fora da janela: ignorado.");
                        }
                    }
                }
                e if e == ble::BLE_EVT_DISCONNECTED => {
                    kprintln!("[BLE] central desconectou.");
                    ble_adv_active = false;
                    ble_bond_pending = false;
                }
                e if e == ble::BLE_EVT_CONNECTED => {
                    kprintln!("[BLE] central conectou (aguardando bonding).");
                }
                _ => {}
            }
            // Bonding pendente: conclui quando o usuario tocar no BOOT.
            // Nested to avoid simultaneous &mut/& borrows of pairing_mgr in one condition; readability intentional.
            #[allow(clippy::collapsible_if)]
            if ble_bond_pending && touch_latched && pairing_mgr.is_pairing_window_open(now_ms) {
                if ble::on_link_secured(&mut pairing_mgr, true, now_ms) == ble::BondOutcome::Paired
                {
                    touch_latched = false;
                    ble_bond_pending = false;
                    rescue_engine.set_user_presence(true);
                    let _ = ble::esp_ble_stop();
                    ble_adv_active = false;
                    display_mgr.set_screen(UiScreen::Success {
                        title: "DISPOSITIVO PAREADO".into(),
                        subtitle: "BLE seguro ativo".into(),
                    });
                    #[cfg(target_os = "espidf")]
                    if let Some(ref mut led) = display_mgr.led_controller {
                        led.set_effect(LedEffect::Solid(crate::led::Color::GREEN));
                    }
                    kprintln!("[BLE] bonding ok (apos UP): advertising parado.");
                    fw_log.record(crate::fw_log::EV_BOND_OK, 0, now_ms);
                    // Wave2 proximidade: rekey do K_prox no pareamento +
                    // zera o contador do beacon (ctr=0 no proximo adv).
                    #[cfg(feature = "proximity")]
                    {
                        let mut rng = rand_core::OsRng;
                        match crate::proximity::rekey_proximity(&mut storage, &mut rng) {
                            Ok(k) => {
                                prox_key = k;
                                prox_key_present = true;
                                prox_beacon = crate::proximity::ProximityBeacon::new();
                                prox_last_ms = now_ms;
                                kprintln!("[PROX] rekey pos-pareamento (ctr=0).");
                            }
                            Err(e) => {
                                prox_key = [0u8; 16];
                                prox_key_present = false;
                                kprintln!("[PROX] rekey falhou ({e:?}); sem adv.");
                            }
                        }
                    }
                }
            }
            // Fragmentos FFF1 -> reassemble -> dispatch -> notify FFF2.
            let rx_n = ble::esp_ble_fetch_rx(&mut ble_rx);
            if rx_n > 0 {
                let up = touch_latched;
                let frag = &ble_rx[..rx_n as usize];
                match ble::feed_control_write(&mut ble_server, frag, up) {
                    Ok(Some(msg)) => {
                        touch_latched = false;
                        ble::esp_ble_set_pending_len(ble::pending_len(&ble_server));
                        let bonded = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
                        #[cfg(feature = "proximity")]
                        let prox_revoked_op = msg.opcode;
                        ble_dispatch_complete(
                            msg,
                            up,
                            pairing_open_now,
                            now_secs,
                            &mut ctap_engine,
                            &mut binding_mgr,
                            &mut storage,
                            &mut rescue_engine,
                            &mut wallet_store,
                            bonded,
                            now_ms,
                            &mut fw_log,
                            &mut key_mgr,
                            &mut oath_applet,
                        );
                        // Wave2 proximidade: release/recovery apagou a NVS
                        // no dispatch (so no Ok); espelha no cache RAM.
                        #[cfg(feature = "proximity")]
                        {
                            let revoked = prox_revoked_op == crate::ble_gatt::OP_BIND_RELEASE
                                || prox_revoked_op == crate::ble_gatt::OP_RECOVERY_UNLOCK;
                            if revoked && crate::proximity::load_proximity_key(&storage).is_err() {
                                prox_key = [0u8; 16];
                                prox_key_present = false;
                            }
                        }
                    }
                    Ok(None) => {
                        ble::esp_ble_set_pending_len(ble::pending_len(&ble_server));
                    }
                    Err(e) => {
                        kprintln!("[BLE] fragmento rejeitado: {}", e);
                        let op = frag.first().copied().unwrap_or(0x83);
                        let frame = ble::notify_frame(op, e.to_vendor_status(), &[]);
                        let _ = ble::esp_ble_notify(&frame);
                    }
                }
            }
        }
        if is_boot_pressed {
            if press_start_tick.is_none() {
                press_start_tick = Some(tick);
                touch_latched = true;
                rescue_engine.set_user_presence(true);
                touch_expire_tick = tick + 150; // Keep touch valid for 1.5 seconds
                                                // Distingue software (TEST_UP) do dedo para nao poluir auditoria:
                                                // latch valido sem nivel fisico agora => veio de software.
                #[cfg(all(target_os = "espidf", feature = "test-mode"))]
                let via_software = !button_mgr.is_boot_pressed(|_| {}) && touch_latched;
                #[cfg(not(all(target_os = "espidf", feature = "test-mode")))]
                let via_software = false;
                if via_software {
                    kprintln!("[TEST] UP via software CONFIRMED (latch 1x).");
                } else {
                    kprintln!(
                        "[BUTTON] Physical touch detected on BOOT (GPIO 0)! User Presence CONFIRMED."
                    );
                }
            } else if let Some(start) = press_start_tick {
                // Phase8 UX-conex: hold>=5000 PairingReady vence; TOTP so em [2s,5s) sem pairing.
                let held_ms = tick.saturating_sub(start).saturating_mul(10);
                let hold_action = crate::pairing_flow::classify_hold(held_ms, pairing_open_now);
                if hold_action == crate::pairing_flow::HoldAction::PairingReady {
                    kprintln!("[PAIRING] 5s hold detected! Pairing window open (60s).");
                }
                // WAVE8: long-press 2s -> CALCULATE no device (UP confirmado pelo hold).
                if hold_action == crate::pairing_flow::HoldAction::Totp
                    && totp_display_until <= tick
                {
                    kprintln!(
                        "[LONG PRESS] 2-second hold detected! Calculating OATH TOTP on device..."
                    );
                    totp_display_until = tick + TOTP_SHOW_TICKS; // 15s (igual Vault auto-clear)
                    let entries = collect_totp_codes(&mut oath_applet, now_secs, true);
                    if entries.is_empty() {
                        display_mgr.set_screen(UiScreen::Error {
                            message: NO_ACCOUNTS_MSG.into(),
                        });
                    } else {
                        totp_account_idx %= entries.len();
                        let entry = &entries[totp_account_idx];
                        // Log so rotulo/contagem — codigo e segredo nunca vao para o log.
                        kprintln!(
                            "[TOTP] account '{}' ({} conta(s))",
                            entry.account,
                            entries.len()
                        );
                        display_mgr.set_screen(UiScreen::TotpCode {
                            label: entry.account.clone(),
                            code: entry.code.clone(),
                            remaining_seconds: entry.remaining_seconds,
                        });
                    }
                }
            }
        } else {
            press_start_tick = None;
            if tick > touch_expire_tick && touch_latched {
                touch_latched = false;
                rescue_engine.set_user_presence(false);
            }
            if totp_display_until > 0 && tick >= totp_display_until {
                totp_display_until = 0;
                display_mgr.set_screen(UiScreen::IdleStandby {
                    status_text: "Aguardando solicitação FIDO2...".into(),
                });
            }
        }

        // WAVE8: KEY (GPIO 14) alterna entre as contas reais do device.
        if is_key_pressed {
            let entries = collect_totp_codes(&mut oath_applet, now_secs, true);
            if entries.is_empty() {
                totp_display_until = tick + TOTP_SHOW_TICKS;
                display_mgr.set_screen(UiScreen::Error {
                    message: NO_ACCOUNTS_MSG.into(),
                });
            } else {
                totp_account_idx = (totp_account_idx + 1) % entries.len();
                let entry = &entries[totp_account_idx];
                kprintln!("[KEY BUTTON] Cycled TOTP Account -> {}", entry.account);
                totp_display_until = tick + TOTP_SHOW_TICKS; // 15s (igual Vault auto-clear)
                display_mgr.set_screen(UiScreen::TotpCode {
                    label: entry.account.clone(),
                    code: entry.code.clone(),
                    remaining_seconds: entry.remaining_seconds,
                });
            }
        }

        // WAVE8: enquanto o TOTP esta visivel, atualiza o countdown a cada 1s
        // (codigo recalculado no device — trata a virada da janela de 30s).
        if totp_display_until > tick && tick.is_multiple_of(100) {
            let entries = collect_totp_codes(&mut oath_applet, now_secs, true);
            if !entries.is_empty() {
                totp_account_idx %= entries.len();
                let entry = &entries[totp_account_idx];
                display_mgr.set_screen(UiScreen::TotpCode {
                    label: entry.account.clone(),
                    code: entry.code.clone(),
                    remaining_seconds: entry.remaining_seconds,
                });
            }
        }

        // Wave7 test-mode: TEST_PAIRING_OPEN (mesma janela 60s do hold 5s,
        // source=software; UP/bonding seguem exigidos) + TEST_PAIRING_CLOSE
        // (fecha p/ determinismo entre sessões) + TEST_LIFETIME_DUMP.
        #[cfg(all(feature = "test-mode", not(target_os = "espidf")))]
        while let Ok(cmd) = diag_rx.try_recv() {
            if cmd.trim() == crate::pairing::TEST_PAIRING_OPEN_CMD {
                pairing_mgr.open_test_window(now_ms);
                std::println!("pairing_open window_s=60 source=software");
                continue;
            }
            if cmd.trim() == crate::pairing::TEST_PAIRING_CLOSE_CMD {
                pairing_mgr.close_test_window();
                std::println!("pairing_closed source=software");
                continue;
            }
            let extra = format!("uptime_s={} up_latched={}", tick * 10 / 1000, touch_latched);
            if let Some(resp) = crate::lifetime_trace::dispatch_test_command(&cmd, &extra) {
                std::println!("{}", resp);
            }
        }

        // B. Update Display Animation & LED
        display_mgr.tick(elapsed);
        // Pairing journey drives the LED from Idle screens (headless parity):
        // arming = rapid touch prompt, pairing window = blue breathing,
        // bonded idle = solid green, locked = solid red. Any other screen
        // (UP prompt, TOTP, success/error) keeps its own LED effect.
        {
            let bonded = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
            if matches!(display_mgr.current_screen, UiScreen::IdleStandby { .. })
                && (pairing_mgr.state() != crate::pairing::PairingState::Idle || bonded)
            {
                if let Some(ref mut led) = display_mgr.led_controller {
                    led.set_effect(crate::pairing_led::effect_for_pairing_state(
                        pairing_mgr.state(),
                        bonded,
                    ));
                }
            }
        }

        // C. Service USB CTAPHID Packets (native USB-OTG; classic serves
        // the same UART through the serial section D below instead).
        #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
        if usb_installed {
            let bytes_read =
                unsafe { aegis_usb_pop_packet(rx_buf.as_mut_ptr(), PACKET_SIZE as u16) };

            if bytes_read == PACKET_SIZE as u16 {
                match ctaphid_mgr.process_packet(&rx_buf, now_ms) {
                    Ok(Some(msg)) => {
                        kprintln!(
                            "[CTAPHID] Message received! CID: 0x{:08X}, CMD: 0x{:02X}, Len: {}",
                            msg.cid,
                            msg.cmd,
                            msg.payload.len()
                        );

                        match msg.cmd {
                            CMD_INIT => {
                                if msg.payload.len() >= 8 {
                                    let mut nonce = [0u8; 8];
                                    nonce.copy_from_slice(&msg.payload[0..8]);
                                    let new_cid = ctaphid_mgr.allocate_cid();
                                    let resp_pkt = CtapHidFramer::frame_init_response(
                                        msg.cid,
                                        &nonce,
                                        new_cid,
                                        1,
                                        0,
                                        0,
                                        CAPABILITY_WINK | CAPABILITY_CBOR,
                                    );
                                    unsafe {
                                        aegis_usb_send_report(
                                            resp_pkt.as_ptr(),
                                            PACKET_SIZE as u16,
                                        );
                                    }
                                    kprintln!("[CTAPHID] Allocated CID: 0x{:08X}", new_cid);
                                }
                            }
                            CMD_PING => {
                                let pkts = CtapHidFramer::frame_ping(msg.cid, &msg.payload);
                                for p in pkts {
                                    unsafe {
                                        aegis_usb_send_report(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                }
                            }
                            CMD_WINK => {
                                if let Some(ref mut led) = display_mgr.led_controller {
                                    led.set_effect(LedEffect::Wink);
                                }
                                let pkts = CtapHidFramer::frame_message(msg.cid, CMD_WINK, &[]);
                                for p in pkts {
                                    unsafe {
                                        aegis_usb_send_report(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                }
                            }
                            CMD_CBOR | CMD_MSG => {
                                // OTA vendor 0x30-0x34 over CMD_MSG (R-04/R-06):
                                // staged verify-before-swap; COMMIT consumes the UP latch.
                                // Any OtaError rolls back (NVS intact); real esp-ota
                                // partition swap = factory follow-up.
                                let ota_op = if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && is_ota_op(msg.payload[0])
                                {
                                    Some(msg.payload[0])
                                } else {
                                    None
                                };
                                if let Some(op) = ota_op {
                                    let ota_ctx = OtaRequestCtx {
                                        provisioned: ota_provisioned(&efuse_mgr),
                                        up: touch_latched,
                                        ota_pubkey: ota_active_pubkey(),
                                        current_version: FIRMWARE_VERSION,
                                    };
                                    let mut ota_sink = FlashOtaSink::new(storage.backend_mut());
                                    let (ota_consumed_up, ota_resp) = match dispatch_ota_request(
                                        &mut ota_state,
                                        &mut ota_sink,
                                        op,
                                        &msg.payload[1..],
                                        &ota_ctx,
                                    ) {
                                        Some((st, body)) => {
                                            if st == OTA_STATUS_OK {
                                                kprintln!(
                                                    "[OTA] op 0x{:02X} ok (phase {:?}).",
                                                    op,
                                                    ota_state.phase()
                                                );
                                            } else {
                                                kprintln!(
                                                    "[OTA] op 0x{:02X} denied (status 0x{:02X}, phase {:?}).",
                                                    op,
                                                    st,
                                                    ota_state.phase()
                                                );
                                            }
                                            let mut out = Vec::with_capacity(1 + body.len());
                                            out.push(st);
                                            out.extend_from_slice(&body);
                                            (st == OTA_STATUS_OK && op == OP_OTA_COMMIT, out)
                                        }
                                        // Unreachable (pre-filtered by is_ota_op): fail-closed.
                                        None => (false, vec![OTA_STATUS_FAIL]),
                                    };
                                    if ota_consumed_up {
                                        touch_latched = false;
                                        rescue_engine.set_user_presence(true);
                                    }
                                    let ota_pkts =
                                        CtapHidFramer::frame_message(msg.cid, msg.cmd, &ota_resp);
                                    for p in ota_pkts {
                                        unsafe {
                                            aegis_usb_send_report(p.as_ptr(), PACKET_SIZE as u16);
                                        }
                                    }
                                    kprintln!(
                                        "[CTAPHID] Sent OTA response ({} bytes)",
                                        ota_resp.len()
                                    );
                                } else if msg.cmd == CMD_MSG
                                    && crate::serial_ctaphid::is_rescue_msg(msg.cmd, &msg.payload)
                                {
                                    // Rescue Wave2 Step3 (0x2E): UP do latch (uso unico),
                                    // PIN via plumbing ClientPIN (sessão viva = PIN
                                    // verificado; sem ela o remoto nega fail-closed).
                                    // Resposta status-first.
                                    rescue_engine.set_user_presence(touch_latched);
                                    rescue_engine.set_pin_uv_authenticated(
                                        ctap_engine.pin_state.has_valid_pin_uv_session(),
                                    );
                                    touch_latched = false;
                                    let (st, body) = crate::serial_ctaphid::dispatch_serial_rescue(
                                        &mut rescue_engine,
                                        &msg.payload[1..],
                                    );
                                    kprintln!("[RESCUE] op 0x2E via USB (status 0x{:02X}).", st);
                                    let mut resp = Vec::with_capacity(1 + body.len());
                                    resp.push(st);
                                    resp.extend_from_slice(&body);
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp) {
                                        unsafe {
                                            aegis_usb_send_report(p.as_ptr(), PACKET_SIZE as u16);
                                        }
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && crate::pairing::is_host_pairing_msg(
                                        msg.payload[0],
                                        msg.payload.len() - 1,
                                    )
                                {
                                    // Pareamento por software (produto 0x2F): abre a
                                    // mesma janela do hold; UP/bonding seguem
                                    // exigidos. Só existe no USB físico.
                                    pairing_mgr.open_host_window(now_ms);
                                    kprintln!("[PAIRING] 0x2F via USB: janela 60s aberta (UP/bond seguem).");
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &[0x00])
                                    {
                                        unsafe {
                                            aegis_usb_send_report(p.as_ptr(), PACKET_SIZE as u16);
                                        }
                                    }
                                } else {
                                    // 1. Determine if this command requires User Presence (UP)
                                    let ctap_subcmd = if !msg.payload.is_empty() {
                                        msg.payload[0]
                                    } else {
                                        0
                                    };
                                    let is_up_required = match msg.cmd {
                                        CMD_CBOR => {
                                            ctap_subcmd == CTAP_CMD_MAKE_CREDENTIAL
                                                || ctap_subcmd == CTAP_CMD_GET_ASSERTION
                                                || ctap_subcmd == CTAP_CMD_RESET
                                        }
                                        CMD_MSG => {
                                            // U2F APDU: INS=0x01 (Register) or INS=0x02 (Authenticate with check/sign)
                                            if msg.payload.len() >= 4 {
                                                let ins = msg.payload[1];
                                                let p1 = msg.payload[2];
                                                ins == 0x01 || (ins == 0x02 && p1 == 0x03)
                                            } else {
                                                false
                                            }
                                        }
                                        _ => false,
                                    };

                                    let (rp_id, user_name, op_name) =
                                        extract_rp_and_user(ctap_subcmd, &msg.payload);

                                    let mut up_confirmed = false;
                                    if is_up_required {
                                        if touch_latched {
                                            up_confirmed = true;
                                            touch_latched = false;
                                            rescue_engine.set_user_presence(true);
                                            kprintln!("[UP] Touch already latched on GPIO 0! Confirming User Presence for: {}", rp_id);
                                        } else {
                                            kprintln!(
                                            "[UP] Touch required for {} ({})! Waiting up to 25s...",
                                            rp_id,
                                            op_name
                                        );

                                            display_mgr.set_screen(UiScreen::UserPresencePrompt {
                                                rp_id: rp_id.clone(),
                                                user_name: user_name.clone(),
                                                operation: op_name.into(),
                                                remaining_seconds: 25,
                                            });

                                            // Wait up to 25s (1250 * 20ms)
                                            for wait_step in 0..1250 {
                                                // Send CTAPHID Keepalive STATUS_UPNEEDED every 100ms (every 5 steps)
                                                if wait_step % 5 == 0 {
                                                    let keepalive = CtapHidFramer::frame_keepalive(
                                                        msg.cid,
                                                        STATUS_UPNEEDED,
                                                    );
                                                    unsafe {
                                                        aegis_usb_send_report(
                                                            keepalive.as_ptr(),
                                                            PACKET_SIZE as u16,
                                                        );
                                                    }
                                                }

                                                // Advance Display animation & countdown bar
                                                if wait_step % 25 == 0 {
                                                    let rem_s = 25u32.saturating_sub(
                                                        (wait_step * 20 / 1000) as u32,
                                                    );
                                                    display_mgr.set_screen(
                                                        UiScreen::UserPresencePrompt {
                                                            rp_id: rp_id.clone(),
                                                            user_name: user_name.clone(),
                                                            operation: op_name.into(),
                                                            remaining_seconds: rem_s,
                                                        },
                                                    );
                                                }
                                                display_mgr
                                                    .tick(Duration::from_millis(wait_step * 20));

                                                // Check physical buttons:
                                                // BOOT (GPIO 0) -> Confirm User Presence
                                                // KEY (GPIO 14) -> Cancel / Reject Transaction
                                                if button_mgr.is_boot_pressed(std::thread::sleep) {
                                                    up_confirmed = true;
                                                    rescue_engine.set_user_presence(true);
                                                    kprintln!("[BUTTON] Physical touch confirmed on BOOT (GPIO 0)! (t={}ms)", wait_step * 20);
                                                    break;
                                                }
                                                if button_mgr.is_key_pressed(std::thread::sleep) {
                                                    up_confirmed = false;
                                                    kprintln!("[BUTTON] User cancelled transaction via KEY (GPIO 14)! (t={}ms)", wait_step * 20);
                                                    break;
                                                }

                                                // Check if host sent CANCEL
                                                #[cfg(target_os = "espidf")]
                                                {
                                                    let mut check_buf = [0u8; PACKET_SIZE];
                                                    let n = unsafe {
                                                        aegis_usb_pop_packet(
                                                            check_buf.as_mut_ptr(),
                                                            PACKET_SIZE as u16,
                                                        )
                                                    };
                                                    if n == PACKET_SIZE as u16 {
                                                        if let Ok(raw_pkt) =
                                                            CtapHidManager::parse_raw_packet(
                                                                &check_buf,
                                                            )
                                                        {
                                                            if let RawPacket::Init {
                                                                cid,
                                                                cmd,
                                                                ..
                                                            } = raw_pkt
                                                            {
                                                                if cid == msg.cid
                                                                    && cmd == CMD_CANCEL
                                                                {
                                                                    kprintln!("[UP] Host cancelled transaction (CMD_CANCEL received).");
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }

                                                std::thread::sleep(Duration::from_millis(20));
                                            }
                                        }

                                        if up_confirmed {
                                            display_mgr.set_screen(UiScreen::Success {
                                                title: "ACESSO AUTORIZADO".into(),
                                                subtitle: {
                                                    let mut sbuf: [u8; 64] = [0u8; 64];
                                                    let pre = b"Dominio: ";
                                                    sbuf[..pre.len()].copy_from_slice(pre);
                                                    let mut slen = pre.len();
                                                    let idb = rp_id.as_bytes();
                                                    let mut take =
                                                        (sbuf.len() - slen).min(idb.len().min(48));
                                                    while take > 0 && !rp_id.is_char_boundary(take)
                                                    {
                                                        take -= 1;
                                                    }
                                                    sbuf[slen..slen + take]
                                                        .copy_from_slice(&idb[..take]);
                                                    slen += take;
                                                    core::str::from_utf8(&sbuf[..slen])
                                                        .unwrap_or("Dominio: ?")
                                                        .into()
                                                },
                                            });
                                        } else {
                                            display_mgr.set_screen(UiScreen::Error {
                                                message: "Tempo esgotado ou cancelado".into(),
                                            });
                                            kprintln!("[UP] User Presence denied or timed out!");
                                        }
                                    } else {
                                        // Command does not require user presence (GetInfo, ClientPIN, etc.)
                                        up_confirmed = true;
                                    }

                                    ctap_engine.set_user_presence(up_confirmed);

                                    let mut rng = rand_core::OsRng;
                                    let ctap_res = ctap_engine.process_packet(
                                        &msg.payload,
                                        now_secs,
                                        &mut rng,
                                    );

                                    // F3: ClientPIN (0x06) mudou estado? Persiste.
                                    if msg.payload.first() == Some(&0x06)
                                        && !crate::vendor_exec::save_pin_state(
                                            &mut storage,
                                            &ctap_engine.pin_state,
                                        )
                                    {
                                        kprintln!("[WARN] NVS pin save falhou (USB).");
                                    }

                                    kprintln!(
                                        "[CTAP2] Response status: 0x{:02X}, length: {} bytes",
                                        ctap_res.get(0).unwrap_or(&0xFF),
                                        ctap_res.len()
                                    );

                                    let pkts =
                                        CtapHidFramer::frame_message(msg.cid, msg.cmd, &ctap_res);
                                    for (p_idx, p) in pkts.iter().enumerate() {
                                        let sent = unsafe {
                                            aegis_usb_send_report(p.as_ptr(), PACKET_SIZE as u16)
                                        };
                                        if !sent {
                                            kprintln!(
                                                "[USB] Error: packet {}/{} failed to send!",
                                                p_idx + 1,
                                                pkts.len()
                                            );
                                            crate::ltrace!(LtCat::Transport, LtEvt::TpError, "usb");
                                        }
                                    }
                                    kprintln!(
                                        "[CTAPHID] Sent CTAP response ({} bytes in {} USB packets)",
                                        ctap_res.len(),
                                        pkts.len()
                                    );

                                    // Return display back to idle standby after brief celebration
                                    if is_up_required && up_confirmed {
                                        std::thread::sleep(Duration::from_millis(800));
                                        display_mgr.set_screen(UiScreen::IdleStandby {
                                            status_text: "Aguardando solicitação FIDO2...".into(),
                                        });
                                    }
                                } // end OTA else (non-OTA CTAP routing above untouched)
                            }
                            _ => {
                                let err_pkt = CtapHidFramer::frame_error(msg.cid, 0x01); // ERR_INVALID_CMD
                                unsafe {
                                    aegis_usb_send_report(err_pkt.as_ptr(), PACKET_SIZE as u16);
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        // Multi-packet message continuing reassembly
                    }
                    Err(err) => {
                        kprintln!("[CTAPHID] Protocol error: {}", err);
                        crate::ltrace!(LtCat::Transport, LtEvt::TpError, "usb");
                        let err_pkt = err.to_packet();
                        unsafe {
                            aegis_usb_send_report(err_pkt.as_ptr(), PACKET_SIZE as u16);
                        }
                    }
                }
            }
            // C2. Service CCID frames (F4 PIV; composite interface 2).
            // O driver C remonta frames bulk completos; o applet Rust
            // (em `ccid_transport`) sobrevive entre polls; NVS+chaves
            // são emprestados por frame.
            #[cfg(all(target_os = "espidf", not(feature = "board-ttgo-classic")))]
            if usb_installed {
                const CCID_FRAME_MAX: usize = 2048;
                let mut frame = [0u8; CCID_FRAME_MAX];
                let n = unsafe { aegis_ccid_pop_frame(frame.as_mut_ptr(), CCID_FRAME_MAX as u16) };
                if n >= 10 {
                    if let Some(rpdu) = crate::ccid_dispatch::process_ccid_frame(
                        &mut ccid_transport,
                        &frame[..n as usize],
                        &mut storage,
                        &mut key_mgr,
                        now_secs,
                    ) {
                        if !unsafe { aegis_ccid_send(rpdu.as_ptr(), rpdu.len() as u16) } {
                            kprintln!("[CCID] bulk-IN send falhou ({} B).", rpdu.len());
                        }
                    }
                }
            }
        }

        // D. Service serial CTAPHID (UART 115200, framing identical to USB).
        //
        // Classic: this IS the transport (single serial port). S3/S2: UART0
        // diagnostic channel alongside native USB (section C untouched).
        // Heartbeat text stays outside the framing (the router ignores it);
        // test-mode answers TEST_LIFETIME_DUMP text lines on the same wire.
        // Vendor keys/OATH (0x20-0x27) use the BLE-identical gates with a
        // status-only answer (on-device executor = follow-up, status 0x04).
        // Binding mgmt over serial (0x28-0x2D) reuses the BLE dispatch_*
        // helpers (same binding -> UP -> PIN gates), status-first answer.
        #[cfg(target_os = "espidf")]
        if serial_installed {
            use crate::ble_gatt::{
                is_bind_mgmt_op, is_piv_enroll_op, is_vendor_keys_oath_op, is_wallet_op,
                OP_WALLET_ADDR, OP_WALLET_GEN, OP_WALLET_LIST,
            };
            use crate::serial_ctaphid::{
                authorize_serial, deny_response, dispatch_serial_bind_mgmt, dispatch_serial_rescue,
                is_rescue_msg, serial_bind_mgmt_consumes_up, serial_is_up_required, SerialFeed,
                SerialGate,
            };
            #[cfg(feature = "test-mode")]
            use crate::serial_ctaphid::{dispatch_serial_pairing_line, dispatch_serial_text_line};

            // D1. Diagnostic text lines (test-mode only; idle use only).
            // CI-GREP: TEST-HOOK (test-mode only; absent in release).
            // TEST_PAIRING_OPEN abre a mesma janela 60s do hold (software);
            // TEST_PAIRING_CLOSE fecha (determinismo entre sessões);
            // TEST_LIFETIME_DUMP responde o dump. Release: linhas desconhecidas.
            // D1b. LED ground-truth + primarias (test-mode only).
            // TEST_LED_STATE devolve tela + pairing + efeito ativo (diz o que o
            // firmware MANDA mostrar). TEST_LED_{RED,GREEN,BLUE,OFF} trava uma
            // cor solida (latch reaplicado todo poll, vence o override da
            // jornada); TEST_LED_RELEASE devolve o controle a jornada.
            #[cfg(feature = "test-mode")]
            {
                let mut chunk = [0u8; 32];
                let n = serial_read_chunk(&mut chunk, 32);
                for b in chunk.iter().take(n as usize) {
                    if *b == b'\n' {
                        if let Ok(line) = core::str::from_utf8(&serial_line) {
                            let t = line.trim();
                            if t == "TEST_UP" {
                                // UM toque BOOT via software (vale no proximo
                                // poll, mesma semantica do tap fisico).
                                test_up_latch = true;
                                kprintln!("[TEST] UP via software (latch 1x).");
                                let resp = "up_latched source=software\n";
                                serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                            } else if t == "TEST_DOWNLOAD" {
                                // CI-GREP: TEST-HOOK (test-mode only).
                                // Reboot p/ download ROM via RTC_CNTL
                                // (dispensa BOOT/DTR/RTS). Nunca retorna.
                                kprintln!("[TEST] download via software (RTC_CNTL).");
                                let resp = "download_mode source=software\n";
                                serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                                unsafe { aegis_reboot_to_download() };
                            } else if t == "TEST_USB_RECONNECT" {
                                // CI-GREP: TEST-HOOK (test-mode only).
                                // Drop + re-enumera o USB nativo via software
                                // (dispensa replug físico; Windows rebinda).
                                kprintln!("[TEST] usb reconnect via software.");
                                let resp = "usb_reconnect source=software\n";
                                serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                                unsafe { aegis_usb_reconnect() };
                            } else if t == "TEST_LED_STATE" {
                                let screen = match &display_mgr.current_screen {
                                    UiScreen::BootSplash { .. } => "BootSplash",
                                    UiScreen::IdleStandby { .. } => "IdleStandby",
                                    UiScreen::UserPresencePrompt { .. } => "UP-Prompt",
                                    UiScreen::Success { .. } => "Success",
                                    UiScreen::Error { .. } => "Error",
                                    UiScreen::TotpCode { .. } => "TotpCode",
                                };
                                let bonded = pairing_mgr.is_bonded() || binding_mgr.is_claimed();
                                let effect = display_mgr
                                    .led_controller
                                    .as_ref()
                                    .map(|l| format!("{:?}", l.current_effect()));
                                let resp = format!(
                                    "led_state screen={} pairing={:?} bonded={} claimed={} effect={} tick_ms={}\n",
                                    screen,
                                    pairing_mgr.state(),
                                    bonded as u8,
                                    binding_mgr.is_claimed() as u8,
                                    effect.as_deref().unwrap_or("no-led"),
                                    now_ms
                                );
                                serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                            } else if t == "TEST_LED_RELEASE" {
                                led_test_hold = None;
                                let resp = "led_set released\n";
                                serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                            } else if let Some(held) = match t {
                                "TEST_LED_RED" => Some(LedEffect::Solid(crate::led::Color::RED)),
                                "TEST_LED_GREEN" => {
                                    Some(LedEffect::Solid(crate::led::Color::GREEN))
                                }
                                "TEST_LED_BLUE" => Some(LedEffect::Solid(crate::led::Color::BLUE)),
                                "TEST_LED_OFF" => Some(LedEffect::Off),
                                _ => None,
                            } {
                                led_test_hold = Some(held);
                                if let Some(ref mut led) = display_mgr.led_controller {
                                    led.set_effect(held);
                                }
                                let resp = format!("led_set {}\n", t);
                                serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                            } else if let Some(resp) =
                                dispatch_serial_pairing_line(line, &mut pairing_mgr, now_ms)
                            {
                                serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                            } else {
                                let extra = format!(
                                    "uptime_s={} up_latched={}",
                                    tick * 10 / 1000,
                                    touch_latched
                                );
                                if let Some(resp) = dispatch_serial_text_line(line, &extra) {
                                    serial_send_bytes(resp.as_ptr(), resp.len() as u16);
                                }
                            }
                        }
                        serial_line.clear();
                    } else if serial_line.len() < 48 {
                        serial_line.push(*b);
                    } else {
                        serial_line.clear();
                    }
                }
                // Reaplica o latch de cor solida todo poll: vence o override
                // da jornada (B-block) sem altera-lo.
                if let Some(held) = led_test_hold {
                    if let Some(ref mut led) = display_mgr.led_controller {
                        led.set_effect(held);
                    }
                }
            }

            // D2. 64-byte packets (INIT/CONT, CID, keepalive — same as USB).
            let serial_n = serial_pop_packet(&mut rx_buf);
            if serial_n == PACKET_SIZE as u16 {
                match serial_router.feed(&rx_buf, now_ms) {
                    SerialFeed::IgnoredText | SerialFeed::NeedMore => {}
                    SerialFeed::Error(err) => {
                        kprintln!("[SERIAL] Protocol error: {}", err);
                        let pkt = err.to_packet();
                        serial_send_bytes(pkt.as_ptr(), PACKET_SIZE as u16);
                    }
                    SerialFeed::Message(msg) => {
                        kprintln!(
                            "[SERIAL] Message! CID: 0x{:08X}, CMD: 0x{:02X}, Len: {}",
                            msg.cid,
                            msg.cmd,
                            msg.payload.len()
                        );
                        match msg.cmd {
                            CMD_INIT => {
                                if msg.payload.len() >= 8 {
                                    let mut nonce = [0u8; 8];
                                    nonce.copy_from_slice(&msg.payload[0..8]);
                                    let new_cid = serial_router.allocate_cid();
                                    let pkt = CtapHidFramer::frame_init_response(
                                        msg.cid,
                                        &nonce,
                                        new_cid,
                                        1,
                                        0,
                                        0,
                                        CAPABILITY_WINK | CAPABILITY_CBOR,
                                    );
                                    serial_send_bytes(pkt.as_ptr(), PACKET_SIZE as u16);
                                    kprintln!("[SERIAL] Allocated CID: 0x{:08X}", new_cid);
                                }
                            }
                            CMD_PING => {
                                for p in CtapHidFramer::frame_ping(msg.cid, &msg.payload) {
                                    serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                }
                            }
                            CMD_WINK => {
                                if let Some(ref mut led) = display_mgr.led_controller {
                                    led.set_effect(LedEffect::Wink);
                                }
                                for p in CtapHidFramer::frame_message(msg.cid, CMD_WINK, &[]) {
                                    serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                }
                            }
                            CMD_CBOR | CMD_MSG => {
                                if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && is_bind_mgmt_op(msg.payload[0])
                                {
                                    // Binding mgmt 0x28-0x2D: same gates as BLE
                                    // (shared dispatch_* helpers); status-first
                                    // answer, framing untouched.
                                    let op = msg.payload[0];
                                    let (st, body) = dispatch_serial_bind_mgmt(
                                        op,
                                        &msg.payload[1..],
                                        pairing_open_now,
                                        touch_latched,
                                        &mut binding_mgr,
                                        &mut storage,
                                        &mut rand_core::OsRng,
                                    );
                                    if st == 0x00 && serial_bind_mgmt_consumes_up(op) {
                                        touch_latched = false;
                                        rescue_engine.set_user_presence(true);
                                    }
                                    if st != 0x00 {
                                        kprintln!(
                                            "[SERIAL] Bind-mgmt 0x{:02X} denied (status 0x{:02X}).",
                                            op,
                                            st
                                        );
                                    }
                                    let mut resp = Vec::with_capacity(1 + body.len());
                                    resp.push(st);
                                    resp.extend_from_slice(&body);
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp) {
                                        serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && msg.payload[0] == crate::fw_log::OP_FW_LOG
                                {
                                    // Log da firmware over serial: posse física
                                    // = livre (sem pairing, sem UP, sem latch).
                                    use crate::fw_log as fl;
                                    fw_log.record(fl::EV_OP_RX, fl::OP_FW_LOG, now_ms);
                                    let body = fw_log.render_ascii(1024);
                                    fw_log.record(fl::EV_OP_RESP, 0x00, now_ms);
                                    let mut resp = Vec::with_capacity(1 + body.len());
                                    resp.push(0x00);
                                    resp.extend_from_slice(&body);
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp) {
                                        serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && (is_vendor_keys_oath_op(msg.payload[0])
                                        || is_wallet_op(msg.payload[0])
                                        || is_piv_enroll_op(msg.payload[0]))
                                {
                                    // Vendor keys/OATH + carteira + PIV enroll:
                                    // app-driven UP (latch, like BLE); denial
                                    // carries the BLE wire status.
                                    let op = msg.payload[0];
                                    match authorize_serial(
                                        msg.cmd,
                                        &msg.payload,
                                        pairing_open_now,
                                        touch_latched,
                                    ) {
                                        SerialGate::NeedPairing => {
                                            kprintln!(
                                                "[SERIAL] Pairing-mode required (hold BOOT 5s)."
                                            );
                                            for p in deny_response(&msg) {
                                                serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                            }
                                        }
                                        SerialGate::NeedUp => {
                                            // NEED_UP (0x01); the app re-sends after
                                            // the user taps BOOT (BLE parity).
                                            for p in CtapHidFramer::frame_message(
                                                msg.cid,
                                                msg.cmd,
                                                &[0x01],
                                            ) {
                                                serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                            }
                                        }
                                        SerialGate::Ok => {
                                            touch_latched = false;
                                            rescue_engine.set_user_presence(true);
                                            let (st, body) = if is_wallet_op(op) {
                                                // Carteira Fase7: executa de verdade
                                                // (gate pairing+UP já passou acima).
                                                let mut rng = rand_core::OsRng;
                                                use crate::wallet_exec as w;
                                                match op {
                                                    OP_WALLET_GEN => w::wallet_gen(
                                                        &mut wallet_store,
                                                        &msg.payload[1..],
                                                        now_secs,
                                                        true,
                                                        &mut rng,
                                                    ),
                                                    OP_WALLET_LIST => {
                                                        w::wallet_list(&wallet_store, true)
                                                    }
                                                    OP_WALLET_ADDR => w::wallet_addr(
                                                        &wallet_store,
                                                        &msg.payload[1..],
                                                        true,
                                                    ),
                                                    _ => (0x04, Vec::new()),
                                                }
                                            } else {
                                                // F2: executor real on-device
                                                // (gate pairing+UP já passou;
                                                // PIN via plumbing ClientPIN).
                                                let mut rng = rand_core::OsRng;
                                                let (st, body) = crate::vendor_exec::exec_vendor_op(
                                                    &mut key_mgr,
                                                    &mut oath_applet,
                                                    &mut storage,
                                                    op,
                                                    &msg.payload[1..],
                                                    binding_mgr.is_claimed(),
                                                    ctap_engine
                                                        .pin_state
                                                        .has_valid_pin_uv_session(),
                                                    true,
                                                    now_secs,
                                                    &mut rng,
                                                );
                                                (st, body)
                                            };
                                            let mut resp = Vec::with_capacity(1 + body.len());
                                            resp.push(st);
                                            resp.extend_from_slice(&body);
                                            for p in CtapHidFramer::frame_message(
                                                msg.cid, msg.cmd, &resp,
                                            ) {
                                                serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                            }
                                        }
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && crate::ota_store::is_ota_op(msg.payload[0])
                                {
                                    // F5: OTA over serial (mesmos gates do USB:
                                    // provisionado-lab + UP só no COMMIT).
                                    // Sem swap real (partição única): COMMIT
                                    // grava só o marker NVS (zero risco brick).
                                    #[cfg(all(
                                        target_os = "espidf",
                                        not(feature = "board-ttgo-classic")
                                    ))]
                                    {
                                        use crate::ota::OP_OTA_COMMIT;
                                        use crate::ota_store::{
                                            dispatch_ota_request, FlashOtaSink, OtaRequestCtx,
                                            OTA_STATUS_OK,
                                        };
                                        let ota_ctx = OtaRequestCtx {
                                            provisioned: ota_provisioned(&efuse_mgr),
                                            up: touch_latched,
                                            ota_pubkey: ota_active_pubkey(),
                                            current_version: FIRMWARE_VERSION,
                                        };
                                        let mut ota_sink = FlashOtaSink::new(storage.backend_mut());
                                        let op = msg.payload[0];
                                        let (st, body) = match dispatch_ota_request(
                                            &mut ota_state,
                                            &mut ota_sink,
                                            op,
                                            &msg.payload[1..],
                                            &ota_ctx,
                                        ) {
                                            Some((st, body)) => {
                                                kprintln!(
                                                    "[SERIAL][OTA] op 0x{:02X} (status 0x{:02X}).",
                                                    op,
                                                    st
                                                );
                                                (st, body)
                                            }
                                            None => (0x04, Vec::new()),
                                        };
                                        if st == OTA_STATUS_OK && op == OP_OTA_COMMIT {
                                            touch_latched = false;
                                            rescue_engine.set_user_presence(true);
                                        }
                                        let mut resp = Vec::with_capacity(1 + body.len());
                                        resp.push(st);
                                        resp.extend_from_slice(&body);
                                        for p in
                                            CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp)
                                        {
                                            serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                        }
                                    }
                                    // Classic (sem OTA): nega genérico, nunca silencia.
                                    #[cfg(not(all(
                                        target_os = "espidf",
                                        not(feature = "board-ttgo-classic")
                                    )))]
                                    {
                                        for p in
                                            CtapHidFramer::frame_message(msg.cid, msg.cmd, &[0x04])
                                        {
                                            serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                        }
                                    }
                                } else if msg.cmd == CMD_MSG && is_rescue_msg(msg.cmd, &msg.payload)
                                {
                                    // Rescue Wave2 Step3 (0x2E) over serial: mesmo gate do
                                    // USB (UP do latch + plumbing ClientPIN).
                                    rescue_engine.set_user_presence(touch_latched);
                                    rescue_engine.set_pin_uv_authenticated(
                                        ctap_engine.pin_state.has_valid_pin_uv_session(),
                                    );
                                    touch_latched = false;
                                    let (st, body) = dispatch_serial_rescue(
                                        &mut rescue_engine,
                                        &msg.payload[1..],
                                    );
                                    kprintln!("[SERIAL][RESCUE] op 0x2E (status 0x{:02X}).", st);
                                    let mut resp = Vec::with_capacity(1 + body.len());
                                    resp.push(st);
                                    resp.extend_from_slice(&body);
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp) {
                                        serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                } else if msg.cmd == CMD_MSG
                                    && !msg.payload.is_empty()
                                    && crate::pairing::is_host_pairing_msg(
                                        msg.payload[0],
                                        msg.payload.len() - 1,
                                    )
                                {
                                    // Pareamento por software (produto 0x2F) over
                                    // serial: mesma janela do hold; UP/bonding
                                    // seguem exigidos. UART = posse física.
                                    pairing_mgr.open_host_window(now_ms);
                                    kprintln!("[SERIAL][PAIRING] 0x2F: janela 60s aberta.");
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &[0x00])
                                    {
                                        serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                } else if authorize_serial(
                                    msg.cmd,
                                    &msg.payload,
                                    pairing_open_now,
                                    touch_latched,
                                ) == SerialGate::NeedPairing
                                {
                                    kprintln!("[SERIAL] Pairing-mode required (hold BOOT 5s).");
                                    for p in deny_response(&msg) {
                                        serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16);
                                    }
                                } else {
                                    // CTAP/U2F path: latch fast-path, else a
                                    // bounded 25s UP wait with serial keepalive
                                    // (same UX contract as the USB section).
                                    let ctap_subcmd = msg.payload.first().copied().unwrap_or(0);
                                    let up_needed = serial_is_up_required(msg.cmd, &msg.payload);
                                    let (rp_id, user_name, op_name) =
                                        extract_rp_and_user(ctap_subcmd, &msg.payload);
                                    let mut up_ok = false;
                                    if up_needed {
                                        if touch_latched {
                                            up_ok = true;
                                            touch_latched = false;
                                            rescue_engine.set_user_presence(true);
                                            kprintln!(
                                                "[SERIAL][UP] Latched touch confirms {}.",
                                                rp_id
                                            );
                                        } else {
                                            kprintln!(
                                                "[SERIAL][UP] Touch BOOT for {} ({}), 25s...",
                                                rp_id,
                                                op_name
                                            );
                                            display_mgr.set_screen(UiScreen::UserPresencePrompt {
                                                rp_id: rp_id.clone(),
                                                user_name: user_name.clone(),
                                                operation: op_name.into(),
                                                remaining_seconds: 25,
                                            });
                                            for wait_step in 0..1250u32 {
                                                if wait_step % 5 == 0 {
                                                    let ka = CtapHidFramer::frame_keepalive(
                                                        msg.cid,
                                                        STATUS_UPNEEDED,
                                                    );
                                                    serial_send_bytes(
                                                        ka.as_ptr(),
                                                        PACKET_SIZE as u16,
                                                    );
                                                }
                                                if button_mgr.is_boot_pressed(std::thread::sleep) {
                                                    up_ok = true;
                                                    rescue_engine.set_user_presence(true);
                                                    kprintln!(
                                                        "[SERIAL][BUTTON] UP confirmed on BOOT."
                                                    );
                                                    break;
                                                }
                                                if button_mgr.is_key_pressed(std::thread::sleep) {
                                                    kprintln!(
                                                        "[SERIAL][BUTTON] Cancelled via KEY."
                                                    );
                                                    break;
                                                }
                                                std::thread::sleep(Duration::from_millis(20));
                                            }
                                            if up_ok {
                                                display_mgr.set_screen(UiScreen::Success {
                                                    title: "ACESSO AUTORIZADO".into(),
                                                    subtitle: rp_id.clone(),
                                                });
                                            } else {
                                                display_mgr.set_screen(UiScreen::Error {
                                                    message: "Tempo esgotado ou cancelado".into(),
                                                });
                                            }
                                        }
                                    } else {
                                        up_ok = true;
                                    }
                                    ctap_engine.set_user_presence(up_ok);
                                    let mut rng = rand_core::OsRng;
                                    let res = ctap_engine.process_packet(
                                        &msg.payload,
                                        now_secs,
                                        &mut rng,
                                    );
                                    // F3: ClientPIN (0x06) mudou estado? Persiste.
                                    if msg.payload.first() == Some(&0x06)
                                        && !crate::vendor_exec::save_pin_state(
                                            &mut storage,
                                            &ctap_engine.pin_state,
                                        )
                                    {
                                        kprintln!("[WARN] NVS pin save falhou (serial).");
                                    }
                                    kprintln!(
                                        "[SERIAL][CTAP2] status 0x{:02X}, {} bytes",
                                        res.first().copied().unwrap_or(0xFF),
                                        res.len()
                                    );
                                    for p in CtapHidFramer::frame_message(msg.cid, msg.cmd, &res) {
                                        if !serial_send_bytes(p.as_ptr(), PACKET_SIZE as u16) {
                                            kprintln!("[SERIAL] TX failed (packet dropped).");
                                        }
                                    }
                                    if up_needed && up_ok {
                                        std::thread::sleep(Duration::from_millis(800));
                                        display_mgr.set_screen(UiScreen::IdleStandby {
                                            status_text: "Aguardando solicitação FIDO2...".into(),
                                        });
                                    }
                                }
                            }
                            _ => {
                                let pkt = CtapHidFramer::frame_error(msg.cid, 0x01);
                                serial_send_bytes(pkt.as_ptr(), PACKET_SIZE as u16);
                            }
                        }
                    }
                }
            }
        }

        // Heartbeat log every 3 seconds (300 ticks * 10ms = 3000ms).
        // Silent mid-transaction on the shared serial wire so heartbeat text
        // never interleaves a 64-byte CTAPHID exchange (framing stays clean).
        #[cfg(target_os = "espidf")]
        let serial_busy = serial_router.has_pending();
        #[cfg(not(target_os = "espidf"))]
        let serial_busy = false;
        if tick.is_multiple_of(300) && !serial_busy {
            #[cfg(target_os = "espidf")]
            let usb_mounted = if usb_installed {
                unsafe { aegis_usb_is_mounted() }
            } else {
                false
            };
            #[cfg(not(target_os = "espidf"))]
            let usb_mounted = false;

            kprintln!(
                "[HEARTBEAT] AegisKey S3 alive | uptime: {}s | USB Mounted: {}",
                tick * 10 / 1000,
                usb_mounted
            );
        }

        tick = tick.wrapping_add(1);
        std::thread::sleep(Duration::from_millis(10));
    }
}
