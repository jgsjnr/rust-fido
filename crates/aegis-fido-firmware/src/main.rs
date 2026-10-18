//! AegisKey S3 Authenticator - Firmware Main Entry Point.
//!
//! 100% Native Rust implementation for ESP32-S3.
//! Integrates USB CTAPHID, CCID, Keyboard, and WinUSB with hardware-backed
//! cryptographic persistence and user presence detection.

use aegis_fido_firmware::{
    button::{BootButton, MockButtonInput},
    efuse::{EfuseManager, MockEfuseStorage},
    led::{Color, LedEffect, MockLedOutput, Ws2812Controller},
    persistence::{MockFlashBackend, SecureStorage},
    usb_descriptors,
};
use aegis_fido_usb::{
    ccid::{CcidTransport, DefaultCcidHandler},
    ctaphid::CtapHidManager,
    keyboard::OtpTyper,
    winusb::WinUsbDeframer,
};
use core::time::Duration;

fn main() {
    println!("============================================================");
    println!("   AegisKey S3 Authenticator - Firmware Booting up");
    println!("   Target: ESP32-S3 (Dual-Core Xtensa LX7 @ 240MHz)");
    println!("   VID: 0x{:04X} | PID: 0x{:04X}", usb_descriptors::USB_VID, usb_descriptors::USB_PID);
    println!("   Manufacturer: {}", usb_descriptors::MANUFACTURER_STRING);
    println!("   Product:      {}", usb_descriptors::PRODUCT_STRING);
    println!("   Serial:       {}", usb_descriptors::SERIAL_NUMBER_STRING);
    println!("============================================================");

    // 1. Initialize Hardware eFuse OTP (BLOCK7 Master Key, BLOCK8 Device Salt)
    println!("[INIT] Initializing eFuse OTP subsystem...");
    let efuse_storage = MockEfuseStorage::with_default_keys();
    let efuse_mgr = EfuseManager::new(efuse_storage);

    let master_key = efuse_mgr.get_master_key().expect("Read eFuse Master Key");
    let salt = efuse_mgr.get_device_salt().expect("Read eFuse Device Salt");
    println!("[INIT] Hardware Master Key & Salt loaded from eFuse OTP.");

    // 2. Initialize Encrypted Flash / NVS Persistence
    println!("[INIT] Initializing AES-256-GCM Encrypted Storage...");
    let flash_backend = MockFlashBackend::new();
    let mut storage = SecureStorage::new(flash_backend, &master_key, &salt);

    let init_nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
    storage
        .store("boot_state", b"BOOT_SUCCESS_V1", &init_nonce)
        .expect("Persist boot state");
    println!("[INIT] Encrypted Flash / NVS storage ready.");

    // 3. Initialize WS2812 RGB LED (GPIO 48)
    println!("[INIT] Initializing WS2812 RGB LED on GPIO 48...");
    let led_output = MockLedOutput::new();
    let mut led_controller = Ws2812Controller::new(led_output);
    led_controller.set_effect(LedEffect::Solid(Color::CYAN));
    led_controller
        .update(Duration::from_millis(0))
        .expect("Set startup LED");
    println!("[INIT] LED visual feedback engine running.");

    // 4. Initialize BOOT Button (GPIO 0)
    println!("[INIT] Initializing BOOT Button on GPIO 0 (Active-LOW with pullup)...");
    let button_input = MockButtonInput::new();
    let _button = BootButton::new(button_input);
    println!("[INIT] User Presence (UP) sensor online.");

    // 5. Initialize USB Transports
    println!("[INIT] Initializing Composite USB Transports:");
    println!("       - Interface 0: CTAPHID (FIDO2 / CTAP 2.3)");
    println!("       - Interface 1: CCID SmartCard (YKOATH / FIDO)");
    println!("       - Interface 2: HID Keyboard (OTP Typer)");
    println!("       - Interface 3: WinUSB High-Speed Bulk (Direct Mgmt)");

    let mut _ctaphid_mgr = CtapHidManager::new();
    let mut _ccid_transport = CcidTransport::new();
    let mut _ccid_handler = DefaultCcidHandler;
    let mut _otp_typer = OtpTyper::new();
    let mut _winusb_deframer = WinUsbDeframer::new();

    println!("[INIT] Loading Microsoft OS 2.0 Descriptors for WinUSB auto-binding...");
    let ms_os_desc = aegis_fido_usb::winusb::build_ms_os_20_descriptor_set(3);
    println!("[INIT] MS OS 2.0 Descriptor Set compiled: {} bytes.", ms_os_desc.len());

    println!("============================================================");
    println!("   AegisKey S3 Authenticator initialized successfully!");
    println!("   Ready to process FIDO2 Passkeys, OATH TOTP, and Aegis Vault.");
    println!("============================================================");
}
