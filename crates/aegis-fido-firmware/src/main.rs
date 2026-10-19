//! AegisKey S3 Authenticator - Firmware Main Entry Point.
//!
//! 100% Native Rust implementation for ESP32-S3.
//! Integrates:
//! - USB CTAPHID (FIDO2 / WebAuthn Passkeys & ClientPIN)
//! - WS2812 RGB LED (GPIO 48) on DevKitC-1
//! - ST7789 IPS LCD Color Screen (170x320) on LilyGO T-Display-S3
//! - Anti-phishing domain inspection and countdown display
//! - BOOT Button User Presence (GPIO 0) and Long-press (2s) TOTP auto-typer
//! - Hardware-backed cryptographic persistence with eFuse OTP master key.

use core::time::Duration;
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::otp::rescue::RescueEngine;
use aegis_fido_core::ctap::{CtapEngine, CTAP_CMD_GET_ASSERTION, CTAP_CMD_MAKE_CREDENTIAL};
#[cfg(target_os = "espidf")]
use aegis_fido_core::ctap::CTAP_CMD_RESET;
#[cfg(all(feature = "debug-terminal", target_os = "espidf"))]
use aegis_fido_firmware::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};
use aegis_fido_firmware::{
    button::{DualButtonManager, EspBootButtonInput, EspKeyButtonInput},
    display::{DisplayManager, UiScreen},
    efuse::{EfuseManager, RamEfuseStorage},
    led::{EspWs2812Output, Ws2812Controller},
    persistence::{RamFlashBackend, SecureStorage},
    provision::load_device_keys,
    totp_view::{collect_totp_codes, NO_ACCOUNTS_MSG, TOTP_SHOW_TICKS},
    watchdog::Watchdog,
    usb_descriptors,
};
#[cfg(target_os = "espidf")]
use aegis_fido_firmware::led::LedEffect;
use aegis_fido_usb::ctaphid::CtapHidManager;
#[cfg(target_os = "espidf")]
use aegis_fido_usb::ctaphid::{CtapHidFramer, RawPacket, CAPABILITY_CBOR, CAPABILITY_WINK, CMD_CANCEL, CMD_CBOR, CMD_INIT, CMD_MSG, CMD_PING, CMD_WINK, PACKET_SIZE, STATUS_UPNEEDED};

#[cfg(target_os = "espidf")]
extern "C" {
    fn aegis_usb_init() -> esp_idf_sys::esp_err_t;
    fn aegis_usb_is_mounted() -> bool;
    fn aegis_usb_send_report(packet: *const u8, len: u16) -> bool;
    fn aegis_usb_pop_packet(out_buf: *mut u8, max_len: u16) -> u16;
}

macro_rules! kprintln {
    () => {
        kprintln!("");
    };
    ($($arg:tt)*) => {{
        let mut raw: [u8; 256] = [0u8; 256];
        let mut w = aegis_fido_firmware::watchdog::StaticBuf::new(&mut raw);
        let _ = core::fmt::Write::write_fmt(&mut w, format_args!($($arg)*));
        let s = w.as_str();
        #[cfg(target_os = "espidf")]
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
            if let Some(ciborium::value::Value::Map(rp_map)) = aegis_fido_core::ctap::cbor::get_int_key(&map, 2) {
                for (k, v) in rp_map {
                    if let (ciborium::value::Value::Text(key), ciborium::value::Value::Text(val)) = (k, v) {
                        if key == "id" {
                            rp_id = val.clone();
                        }
                    }
                }
            }
            if let Some(ciborium::value::Value::Map(user_map)) = aegis_fido_core::ctap::cbor::get_int_key(&map, 3) {
                for (k, v) in user_map {
                    if let (ciborium::value::Value::Text(key), ciborium::value::Value::Text(val)) = (k, v) {
                        if key == "name" || key == "displayName" {
                            user_name = val.clone();
                        }
                    }
                }
            }
            return (rp_id, user_name, "Registro de Passkey");
        } else if cmd == CTAP_CMD_GET_ASSERTION {
            let mut rp_id = String::from("localhost");
            if let Some(ciborium::value::Value::Text(s)) = aegis_fido_core::ctap::cbor::get_int_key(&map, 1) {
                rp_id = s.clone();
            }
            return (rp_id, "Credencial Residente".into(), "Autenticação FIDO2");
        }
    }
    ("WebAuthn".into(), "Chave FIDO2".into(), "Autorização FIDO2")
}

/// Etapa B — despacha 1 mensagem GATT completa e notifica via FFF2.
///
/// PING ecoa; CANCEL confirma vazio; MSG delega ao `CtapEngine` (mesmo
/// `[cmd, CBOR...]` do `CMD_CBOR` USB); bind-mgmt `0x28-0x2D` usa os helpers
/// de `ble_gatt` (gates binding -> UP -> PIN preservados); vendor `0x20-0x27`
/// valida os gates e responde `0x04` (executor on-device = follow-up,
/// `docs/ble-nimble.md`). USB/CTAP intactos.
#[allow(clippy::too_many_arguments)]
fn ble_dispatch_complete(
    msg: aegis_fido_firmware::ble_gatt::BleCompleteMessage,
    up: bool,
    pairing_window_open: bool,
    now_secs: u64,
    ctap_engine: &mut CtapEngine,
    binding_mgr: &mut aegis_fido_firmware::binding::BindingManager,
    storage: &mut SecureStorage<RamFlashBackend>,
) {
    use aegis_fido_firmware::ble_gatt as g;
    use aegis_fido_firmware::ble_nimble as ble;
    use aegis_fido_firmware::binding::{BIND_CHALLENGE_LEN, BIND_ID_LEN, BIND_PUB_LEN};

    let op = msg.opcode;
    let p = &msg.payload;
    let frame: Vec<u8> = match op {
        g::OP_PING => ble::notify_frame(op, 0x00, &g::BleGattServer::dispatch_ping(p)),
        g::OP_CANCEL => ble::notify_frame(op, 0x00, &[]),
        g::OP_MSG => {
            ctap_engine.set_user_presence(up);
            let mut rng = rand_core::OsRng;
            let resp = ctap_engine.process_packet(p, now_secs, &mut rng);
            ble::notify_frame(op, 0x00, &resp)
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
                    Ok(()) => ble::notify_frame(op, 0x00, &[]),
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
                Ok(()) => ble::notify_frame(op, 0x00, &[]),
                Err(e) => ble::notify_frame(op, e.to_vendor_status(), &[]),
            },
            Err(_) => {
                ble::notify_frame(op, g::BleGattError::InvalidFragment.to_vendor_status(), &[])
            }
        },
        o if g::is_vendor_keys_oath_op(o) => {
            // Gates §9.4 preservados (app ve NEED_UP/NEED_BINDING/NEED_PIN
            // corretos); executor TLV on-device = follow-up.
            match g::authorize_vendor_op(o, binding_mgr.is_claimed(), false, up) {
                Ok(()) => {
                    kprintln!("[BLE] op vendor 0x{:02X} com gate ok (executor = follow-up)", o);
                    ble::notify_frame(o, 0x04, &[])
                }
                Err(e) => ble::notify_frame(o, e.to_vendor_status(), &[]),
            }
        }
        _ => ble::notify_frame(op, 0x04, &[]),
    };
    let _ = ble::esp_ble_notify(&frame);
}

#[no_mangle]
pub extern "C" fn app_main() {
    #[cfg(target_os = "espidf")]
    esp_idf_sys::link_patches();

    let builder = std::thread::Builder::new()
        .name("aegis_auth".into())
        .stack_size(96 * 1024);

    let handle = builder
        .spawn(|| {
            run_authenticator();
        })
        .expect("Spawn authenticator thread");

    let _ = handle.join();
}

fn main() {
    app_main();
}

fn run_authenticator() {
    kprintln!("\r\n============================================================");
    kprintln!("   AegisKey S3 Authenticator - Firmware Booting up");
    kprintln!("   Target: ESP32-S3 (Dual-Core Xtensa LX7 @ 240MHz)");
    kprintln!("   VID: 0x{:04X} | PID: 0x{:04X}", usb_descriptors::USB_VID, usb_descriptors::USB_PID);
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
            aegis_fido_firmware::provision::DeviceKeys { master_key, device_salt: salt }
        }
    };
    let master_key = keys.master_key;
    let salt = keys.device_salt;

    // 3. Initialize Encrypted Flash / NVS Persistence
    kprintln!("[INIT] Initializing AES-256-GCM Encrypted Storage...");
    let flash_backend = RamFlashBackend::new();
    let mut storage = SecureStorage::new(flash_backend, &master_key, &salt);
    // AUDIT-PREP: wiring na Wave4

    let init_nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
    storage
        .store("boot_state", b"BOOT_SUCCESS_V1", &init_nonce)
        .expect("Persist boot state");
    kprintln!("[INIT] Encrypted Flash / NVS storage ready.");

    // Binding: dono exclusivo de BLE vendor + WiFi mgmt (release exige vinculo
    // para CONFIGURAR; teste faz bypass com ltrace). USB/CTAP zero mudanca.
    // Carrega da NVS (par ausente = Unclaimed; parcial = Corrupted e exige reset).
    let mut binding_mgr = match aegis_fido_firmware::binding::BindingManager::load_from_storage(&storage) {
        Ok(m) => {
            kprintln!("[INIT] Binding loaded (claimed={}).", m.is_claimed());
            m
        }
        Err(e) => {
            kprintln!("[WARN] Binding store inconsistent ({e}); starting unclaimed (factory_reset recovers).");
            aegis_fido_firmware::binding::BindingManager::new()
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
    #[cfg(not(target_os = "espidf"))]
    let _ = (&ctaphid_mgr, &ctap_engine);
    let mut rescue_engine = RescueEngine::new();
    // Wave1: latch uso unico; PIN para RESC so apos verify_token_permission Ok.

    kprintln!("============================================================");
    kprintln!("   AegisKey S3 Authenticator ONLINE & ACTIVE!");
    kprintln!("   FIDO2 / WebAuthn ready on native USB (HID Usage Page 0xF1D0)");
    kprintln!("   Dual-Board Ready: DevKitC-1 (WS2812) / LilyGO T-Display-S3");
    kprintln!("============================================================");

    // Main Event Loop
    let mut tick: u64 = 0;
    let mut touch_latched = false;
    let mut touch_expire_tick: u64 = 0;

    let mut press_start_tick: Option<u64> = None;
    let mut totp_display_until: u64 = 0;
    let mut totp_account_idx: usize = 0;
    // Phase8 UX-conex: PairingManager orfao agora alimentado no loop (hold 5s vence TOTP 2s).
    let mut pairing_mgr = aegis_fido_firmware::pairing::PairingManager::new();
    // Etapa B (BLE NimBLE real): servidor GATT 0xFFFD + estado do radio.
    let mut ble_server = aegis_fido_firmware::ble_gatt::BleGattServer::new();
    let mut ble_adv_active = false;
    let mut ble_bond_pending = false;
    let mut ble_rx = [0u8; aegis_fido_firmware::ble_nimble::BLE_RX_FRAGMENT_MAX];
    // Phase8 UX-conex: mDNS+station so fora de pareamento, com fallback AP.
    let mut wifi_ap_mgr = aegis_fido_firmware::wifi_ap::WifiApManager::new();
    let mut mdns_mgr = aegis_fido_firmware::mdns::MdnsManager::new();
    let mut sta_mgr = aegis_fido_firmware::wifi_station::WifiStationManager::new();
    // Etapa B (WiFi real): espelhos do radio p/ edge-trigger + backoff.
    let mut wifi_ap_active = false;
    let mut mdns_active = false;
    let mut wifi_radio_on = false;
    let mut last_sta_attempt_ms: Option<u64> = None;
    // WAVE8: sem TOTP literal — o display mostra SO codigos calculados no device
    // via `OathApplet::device_code` (contas do NVS via PUT). Sem contas -> "sem contas".

    #[cfg(target_os = "espidf")]
    let mut rx_buf = [0u8; PACKET_SIZE];

    let mut watchdog = Watchdog::new(300); // L5: feed sem mudar timing USB

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
        let is_boot_pressed = button_mgr.is_boot_pressed(std::thread::sleep);
        let is_key_pressed = button_mgr.is_key_pressed(std::thread::sleep);

        // Phase8 UX-conex: alimenta PairingManager todo poll (corrige orfao).
        pairing_mgr.on_button_level(is_boot_pressed, now_ms);
        pairing_mgr.tick(now_ms);
        let pairing_open_now = pairing_mgr.is_pairing_window_open(now_ms);
        // Binding + recovery: fiação transporte GATT/main (tick todo poll; USB intacto).
        binding_mgr.tick(now_ms);
        let _ = binding_mgr.is_claimed();
        // Etapa B (WiFi real via `aegis_wifi`): AP em pareamento (SSID do
        // serial + senha da NVS, aberta no bootstrap), station fora dele com
        // backoff (bateria), mDNS com station up, power-down fora de uso.
        // Precedencia de radio: USB (controlador dedicado, intacto) > WiFi >
        // BLE (intervalo lento com WiFi ativo; ver `adv_intervals`).
        wifi_ap_mgr.update(pairing_open_now, false, now_ms);
        let ap_want = wifi_ap_mgr.is_active(now_ms);
        if ap_want != wifi_ap_active {
            if ap_want {
                let ssid = aegis_fido_firmware::wifi_ap::ap_ssid_for_serial(
                    usb_descriptors::SERIAL_NUMBER_STRING,
                );
                let pass_bytes = storage
                    .load(aegis_fido_firmware::wifi_ap::WIFI_PASS_NVS_KEY)
                    .unwrap_or_default();
                let pass_opt = aegis_fido_firmware::wifi_ap::resolve_ap_password(
                    if pass_bytes.is_empty() { None } else { Some(&pass_bytes) },
                );
                let pass_str = pass_opt.unwrap_or_default();
                // Nunca loga a senha.
                let rc = aegis_fido_firmware::wifi_ap::esp_ap_start(&ssid, &pass_str);
                if rc == 0 {
                    wifi_ap_active = true;
                    kprintln!("[WIFI] AP '{}' on (pareamento).", ssid);
                } else {
                    kprintln!("[WIFI] AP start rc={} (nova tentativa no proximo poll).", rc);
                }
            } else {
                let _ = aegis_fido_firmware::wifi_ap::esp_ap_stop();
                wifi_ap_active = false;
                kprintln!("[WIFI] AP off.");
            }
        }
        // Station: so fora de pareamento, com credenciais e backoff 60s.
        let has_creds = aegis_fido_firmware::wifi_station::has_station_credentials(&storage);
        sta_mgr.update(pairing_open_now, has_creds, now_ms);
        let mut sta_radio = aegis_fido_firmware::wifi_station::esp_sta_state();
        if sta_radio == aegis_fido_firmware::wifi_station::STA_CONNECTED {
            if !sta_mgr.is_up() {
                sta_mgr.on_connected();
                let ip = aegis_fido_firmware::wifi_station::esp_sta_ip();
                kprintln!(
                    "[WIFI] station conectada (DHCP {}.{}.{}.{}).",
                    ip[0], ip[1], ip[2], ip[3]
                );
            }
        } else if sta_radio == aegis_fido_firmware::wifi_station::STA_FAILED {
            sta_mgr.on_failed();
        }
        if matches!(
            sta_mgr.state(),
            aegis_fido_firmware::wifi_station::WifiStationState::Connecting { .. }
        ) && sta_radio == aegis_fido_firmware::wifi_station::STA_OFF
            && !pairing_open_now
            && aegis_fido_firmware::wifi_station::sta_retry_due(now_ms, last_sta_attempt_ms)
        {
            let got = storage.load(aegis_fido_firmware::wifi_station::WIFI_STA_SSID_NVS_KEY);
            let got_pass = storage.load(aegis_fido_firmware::wifi_station::WIFI_STA_PASS_NVS_KEY);
            match (got, got_pass) {
                (Ok(ssid_b), Ok(pass_b)) => {
                    match (core::str::from_utf8(&ssid_b), core::str::from_utf8(&pass_b)) {
                        (Ok(ssid), Ok(pass)) => {
                            // Credenciais nunca vao para o log.
                            let rc = aegis_fido_firmware::wifi_station::esp_sta_start(ssid, pass);
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
        if (pairing_open_now || !has_creds)
            && sta_radio != aegis_fido_firmware::wifi_station::STA_OFF
        {
            let _ = aegis_fido_firmware::wifi_station::esp_sta_stop();
            sta_mgr.disconnect();
            sta_radio = aegis_fido_firmware::wifi_station::STA_OFF;
        }
        mdns_mgr.update(pairing_open_now, sta_mgr.is_up());
        let mdns_want = mdns_mgr.is_active();
        if mdns_want != mdns_active {
            if mdns_want {
                let host = aegis_fido_firmware::mdns::mdns_hostname_for_serial(
                    usb_descriptors::SERIAL_NUMBER_STRING,
                );
                let bare = aegis_fido_firmware::mdns::mdns_bare_hostname(&host);
                let rc = aegis_fido_firmware::mdns::esp_mdns_start(bare);
                if rc == 0 {
                    mdns_active = true;
                    kprintln!("[WIFI] mDNS '{}' on.", host);
                } else {
                    kprintln!("[WIFI] mDNS start rc={}.", rc);
                }
            } else {
                let _ = aegis_fido_firmware::mdns::esp_mdns_stop();
                mdns_active = false;
            }
        }
        // Bateria: radio totalmente off fora de uso (nem AP, nem station).
        // Rele apos start/stop deste poll (evita off imediato).
        sta_radio = aegis_fido_firmware::wifi_station::esp_sta_state();
        let radio_in_use =
            wifi_ap_active || sta_radio != aegis_fido_firmware::wifi_station::STA_OFF;
        if !radio_in_use && wifi_radio_on {
            let _ = aegis_fido_firmware::wifi_ap::esp_wifi_off();
            wifi_radio_on = false;
            kprintln!("[WIFI] radio off (bateria).");
        } else if radio_in_use {
            wifi_radio_on = true;
        }
        // Etapa B (BLE NimBLE real): advertising SOMENTE em PairingBle com
        // janela aberta; fora disso o radio fica mudo (privacidade + bateria).
        // Coexistencia USB > WiFi > BLE: com WiFi ativo o intervalo e lento.
        let ble_want_adv = aegis_fido_firmware::ble_nimble::should_advertise(&pairing_mgr, now_ms);
        if ble_want_adv != ble_adv_active {
            if ble_want_adv {
                let wifi_active = wifi_ap_mgr.is_active(now_ms) || sta_mgr.is_up();
                let rc = aegis_fido_firmware::ble_nimble::esp_ble_start(true, wifi_active);
                if rc == 0 {
                    ble_adv_active = true;
                } else {
                    kprintln!("[BLE] adv start rc={} (nova tentativa no proximo poll)", rc);
                }
            } else {
                let _ = aegis_fido_firmware::ble_nimble::esp_ble_stop();
                ble_adv_active = false;
                ble_bond_pending = false;
            }
        }
        // Etapa B: bomba BLE (eventos GAP + fragmentos FFF1). USB intacto.
        {
            use aegis_fido_firmware::ble_nimble as ble;
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
                                led.set_effect(LedEffect::Solid(
                                    aegis_fido_firmware::led::Color::GREEN,
                                ));
                            }
                            kprintln!("[BLE] bonding ok: advertising parado, pareamento encerrado.");
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
                        led.set_effect(LedEffect::Solid(
                            aegis_fido_firmware::led::Color::GREEN,
                        ));
                    }
                    kprintln!("[BLE] bonding ok (apos UP): advertising parado.");
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
                        ble_dispatch_complete(
                            msg,
                            up,
                            pairing_open_now,
                            now_secs,
                            &mut ctap_engine,
                            &mut binding_mgr,
                            &mut storage,
                        );
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
                kprintln!("[BUTTON] Physical touch detected on BOOT (GPIO 0)! User Presence CONFIRMED.");
            } else if let Some(start) = press_start_tick {
                // Phase8 UX-conex: hold>=5000 PairingReady vence; TOTP so em [2s,5s) sem pairing.
                let held_ms = tick.saturating_sub(start).saturating_mul(10);
                let hold_action = aegis_fido_firmware::pairing_flow::classify_hold(held_ms, pairing_open_now);
                if hold_action == aegis_fido_firmware::pairing_flow::HoldAction::PairingReady {
                    kprintln!("[PAIRING] 5s hold detected! Pairing window open (60s).");
                }
                // WAVE8: long-press 2s -> CALCULATE no device (UP confirmado pelo hold).
                if hold_action == aegis_fido_firmware::pairing_flow::HoldAction::Totp && totp_display_until <= tick {
                    kprintln!("[LONG PRESS] 2-second hold detected! Calculating OATH TOTP on device...");
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
                        kprintln!("[TOTP] account '{}' ({} conta(s))", entry.account, entries.len());
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

        // Wave7 test-mode: answer TEST_LIFETIME_DUMP from the serial inbox (metadata only).
        #[cfg(all(feature = "test-mode", not(target_os = "espidf")))]
        while let Ok(cmd) = diag_rx.try_recv() {
            let extra = format!("uptime_s={} up_latched={}", tick * 10 / 1000, touch_latched);
            if let Some(resp) =
                aegis_fido_firmware::lifetime_trace::dispatch_test_command(&cmd, &extra)
            {
                std::println!("{}", resp);
            }
        }

        // B. Update Display Animation & LED
        display_mgr.tick(elapsed);

        // C. Service USB CTAPHID Packets
        #[cfg(target_os = "espidf")]
        if usb_installed {
            let bytes_read = unsafe {
                aegis_usb_pop_packet(rx_buf.as_mut_ptr(), PACKET_SIZE as u16)
            };

            if bytes_read == PACKET_SIZE as u16 {
                match ctaphid_mgr.process_packet(&rx_buf, now_ms) {
                    Ok(Some(msg)) => {
                        kprintln!("[CTAPHID] Message received! CID: 0x{:08X}, CMD: 0x{:02X}, Len: {}",
                                 msg.cid, msg.cmd, msg.payload.len());

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
                                        1, 0, 0,
                                        CAPABILITY_WINK | CAPABILITY_CBOR,
                                    );
                                    unsafe {
                                        aegis_usb_send_report(resp_pkt.as_ptr(), PACKET_SIZE as u16);
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
                                // 1. Determine if this command requires User Presence (UP)
                                let ctap_subcmd = if !msg.payload.is_empty() { msg.payload[0] } else { 0 };
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

                                let (rp_id, user_name, op_name) = extract_rp_and_user(ctap_subcmd, &msg.payload);

                                let mut up_confirmed = false;
                                if is_up_required {
                                    if touch_latched {
                                        up_confirmed = true;
                                        touch_latched = false;
                                        rescue_engine.set_user_presence(true);
                                        kprintln!("[UP] Touch already latched on GPIO 0! Confirming User Presence for: {}", rp_id);
                                    } else {
                                        kprintln!("[UP] Touch required for {} ({})! Waiting up to 25s...", rp_id, op_name);

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
                                                let rem_s = 25u32.saturating_sub((wait_step * 20 / 1000) as u32);
                                                display_mgr.set_screen(UiScreen::UserPresencePrompt {
                                                    rp_id: rp_id.clone(),
                                                    user_name: user_name.clone(),
                                                    operation: op_name.into(),
                                                    remaining_seconds: rem_s,
                                                });
                                            }
                                            display_mgr.tick(Duration::from_millis(wait_step * 20));

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
                                                    aegis_usb_pop_packet(check_buf.as_mut_ptr(), PACKET_SIZE as u16)
                                                };
                                                if n == PACKET_SIZE as u16 {
                                                    if let Ok(raw_pkt) = CtapHidManager::parse_raw_packet(&check_buf) {
                                                        if let RawPacket::Init { cid, cmd, .. } = raw_pkt {
                                                            if cid == msg.cid && cmd == CMD_CANCEL {
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
                                                let mut take = (sbuf.len() - slen).min(idb.len().min(48));
                                                while take > 0 && !rp_id.is_char_boundary(take) {
                                                    take -= 1;
                                                }
                                                sbuf[slen..slen + take].copy_from_slice(&idb[..take]);
                                                slen += take;
                                                core::str::from_utf8(&sbuf[..slen]).unwrap_or("Dominio: ?").into()
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

                                kprintln!("[CTAP2] Response status: 0x{:02X}, length: {} bytes",
                                         ctap_res.get(0).unwrap_or(&0xFF), ctap_res.len());

                                let pkts = CtapHidFramer::frame_message(msg.cid, msg.cmd, &ctap_res);
                                for (p_idx, p) in pkts.iter().enumerate() {
                                    let sent = unsafe {
                                        aegis_usb_send_report(p.as_ptr(), PACKET_SIZE as u16)
                                    };
                                    if !sent {
                                        kprintln!("[USB] Error: packet {}/{} failed to send!", p_idx + 1, pkts.len());
                                        aegis_fido_firmware::ltrace!(LtCat::Transport, LtEvt::TpError, "usb");
                                    }
                                }
                                kprintln!("[CTAPHID] Sent CTAP response ({} bytes in {} USB packets)",
                                         ctap_res.len(), pkts.len());

                                // Return display back to idle standby after brief celebration
                                if is_up_required && up_confirmed {
                                    std::thread::sleep(Duration::from_millis(800));
                                    display_mgr.set_screen(UiScreen::IdleStandby {
                                        status_text: "Aguardando solicitação FIDO2...".into(),
                                    });
                                }
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
                        aegis_fido_firmware::ltrace!(LtCat::Transport, LtEvt::TpError, "usb");
                        let err_pkt = err.to_packet();
                        unsafe {
                            aegis_usb_send_report(err_pkt.as_ptr(), PACKET_SIZE as u16);
                        }
                    }
                }
            }
        }

        // Heartbeat log every 3 seconds (300 ticks * 10ms = 3000ms)
        if tick.is_multiple_of(300) {
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


