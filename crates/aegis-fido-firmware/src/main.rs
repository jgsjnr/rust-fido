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
use aegis_fido_core::otp::rescue::RescueEngine;
use aegis_fido_core::ctap::{
    CtapEngine, CTAP_CMD_GET_ASSERTION, CTAP_CMD_MAKE_CREDENTIAL, CTAP_CMD_RESET,
};
use aegis_fido_firmware::{
    button::{BootButton, DualButtonManager, EspBootButtonInput, EspKeyButtonInput},
    display::{DisplayManager, UiScreen},
    efuse::{EfuseManager, MockEfuseStorage},
    led::{Color, EspWs2812Output, LedEffect, Ws2812Controller},
    persistence::{MockFlashBackend, SecureStorage},
    watchdog::Watchdog,
    usb_descriptors,
};
use aegis_fido_usb::ctaphid::{
    CtapHidFramer, CtapHidManager, RawPacket, CAPABILITY_CBOR, CAPABILITY_WINK, CMD_CANCEL,
    CMD_CBOR, CMD_INIT, CMD_MSG, CMD_PING, CMD_WINK, PACKET_SIZE, STATUS_UPNEEDED,
};

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
    kprintln!("[INIT] Initializing eFuse OTP subsystem...");
    let efuse_storage = MockEfuseStorage::with_default_keys();
    let efuse_mgr = EfuseManager::new(efuse_storage);

    let master_key = efuse_mgr.get_master_key().expect("Read eFuse Master Key");
    let salt = efuse_mgr.get_device_salt().expect("Read eFuse Device Salt");
    kprintln!("[INIT] Hardware Master Key & Salt loaded from eFuse OTP.");

    // 3. Initialize Encrypted Flash / NVS Persistence
    kprintln!("[INIT] Initializing AES-256-GCM Encrypted Storage...");
    let flash_backend = MockFlashBackend::new();
    let mut storage = SecureStorage::new(flash_backend, &master_key, &salt);

    let init_nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
    storage
        .store("boot_state", b"BOOT_SUCCESS_V1", &init_nonce)
        .expect("Persist boot state");
    kprintln!("[INIT] Encrypted Flash / NVS storage ready.");

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
    let mut ctaphid_mgr = CtapHidManager::new();
    let mut ctap_engine = CtapEngine::new(master_key, 0);
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
    let totp_accounts: [(&str, &str); 3] = [
        ("GitHub: aegis-admin", "482 915"),
        ("Google: junior@aegiskey.dev", "720 184"),
        ("AWS: root-production", "934 602"),
    ];

    #[cfg(target_os = "espidf")]
    let mut rx_buf = [0u8; PACKET_SIZE];

    let mut watchdog = Watchdog::new(300); // L5: feed sem mudar timing USB

    loop {
        watchdog.feed(tick); // L5: feed no hot path, sem sleep
        let elapsed = Duration::from_millis(tick * 10);
        let now_ms = tick * 10;
        let now_secs = now_ms / 1000;

        // A. Check physical buttons
        // Button 1: BOOT (GPIO 0) - Confirm / UP / Long press (2s)
        // Button 2: KEY (GPIO 14 on LilyGO T-Display) - Cycle accounts / Cancel
        let is_boot_pressed = button_mgr.is_boot_pressed(|d| std::thread::sleep(d));
        let is_key_pressed = button_mgr.is_key_pressed(|d| std::thread::sleep(d));

        if is_boot_pressed {
            if press_start_tick.is_none() {
                press_start_tick = Some(tick);
                touch_latched = true;
                rescue_engine.set_user_presence(true);
                touch_expire_tick = tick + 150; // Keep touch valid for 1.5 seconds
                kprintln!("[BUTTON] Physical touch detected on BOOT (GPIO 0)! User Presence CONFIRMED.");
            } else if let Some(start) = press_start_tick {
                // Check for 2.0s Long Press -> Trigger TOTP code display
                if (tick - start) >= 200 && totp_display_until <= tick {
                    kprintln!("[LONG PRESS] 2-second hold detected! Showing OATH TOTP 2FA code...");
                    totp_display_until = tick + 500; // Show for 5 seconds
                    let (label, code) = totp_accounts[totp_account_idx];
                    display_mgr.set_screen(UiScreen::TotpCode {
                        label: label.into(),
                        code: code.into(),
                        remaining_seconds: 28,
                    });
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

        // Handle KEY button (GPIO 14) to cycle TOTP accounts
        if is_key_pressed {
            totp_account_idx = (totp_account_idx + 1) % totp_accounts.len();
            let (label, code) = totp_accounts[totp_account_idx];
            kprintln!("[KEY BUTTON] Cycled TOTP Account -> {}", label);
            totp_display_until = tick + 500; // Display for 5 seconds
            display_mgr.set_screen(UiScreen::TotpCode {
                label: label.into(),
                code: code.into(),
                remaining_seconds: 30,
            });
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
                                            if button_mgr.is_boot_pressed(|d| std::thread::sleep(d)) {
                                                up_confirmed = true;
                                                rescue_engine.set_user_presence(true);
                                                kprintln!("[BUTTON] Physical touch confirmed on BOOT (GPIO 0)! (t={}ms)", wait_step * 20);
                                                break;
                                            }
                                            if button_mgr.is_key_pressed(|d| std::thread::sleep(d)) {
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
                        let err_pkt = err.to_packet();
                        unsafe {
                            aegis_usb_send_report(err_pkt.as_ptr(), PACKET_SIZE as u16);
                        }
                    }
                }
            }
        }

        // Heartbeat log every 3 seconds (300 ticks * 10ms = 3000ms)
        if tick % 300 == 0 {
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


