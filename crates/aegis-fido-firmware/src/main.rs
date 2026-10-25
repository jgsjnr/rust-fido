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

#[cfg(not(feature = "freertos"))]
use aegis_fido_firmware::run::run_authenticator;
#[cfg(feature = "freertos")]
use aegis_fido_firmware::run::run_authenticator_freertos;

#[no_mangle]
pub extern "C" fn app_main() {
    #[cfg(target_os = "espidf")]
    esp_idf_sys::link_patches();

    // Variante FreeRTOS em Rust (feature `freertos`): três tarefas explícitas
    // (usb_ctaphid, ui_button, housekeeping) sobre fila + event-group.
    #[cfg(feature = "freertos")]
    {
        let builder = std::thread::Builder::new()
            .name("aegis_freertos".into())
            .stack_size(96 * 1024);

        let handle = builder
            .spawn(|| {
                run_authenticator_freertos();
            })
            .expect("Spawn authenticator freertos thread");

        let _ = handle.join();
    }

    #[cfg(not(feature = "freertos"))]
    {
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
}

fn main() {
    app_main();
}
