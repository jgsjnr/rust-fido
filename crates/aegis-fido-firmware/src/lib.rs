//! AegisKey S3 Authenticator Firmware Library.
//!
//! Provides drivers for:
//! - Physical BOOT button on GPIO 0 with debounce and User Presence (UP) detection.
//! - WS2812 addressable RGB LED on GPIO 48 with visual animation effects.
//! - eFuse OTP hardware integration (BLOCK7 Master Key, BLOCK8 Device Salt).
//! - Secure encrypted persistence in NVS/Flash with AES-256-GCM.
//! - Composite USB descriptors (CTAPHID, CCID, Keyboard, WinUSB with MS OS 2.0).
//! - Wave4: pairing journey (5s hold), BLE GATT 0xFFFD, WiFi AP, UI journey.

pub mod ble_gatt;
pub mod ble_nimble;
pub mod binding;
pub mod recovery;
pub mod button;
pub mod config;
pub mod display;
pub mod efuse;
pub mod fw_log;
pub mod identity;
pub mod led;
pub mod lifetime_trace;
pub mod mdns;
pub mod migrations;
pub mod oath_store;
pub mod ota;
pub mod pairing;
pub mod pairing_flow;
pub mod pairing_led;
pub mod persistence;
pub mod provision;
#[cfg(feature = "proximity")]
pub mod proximity;
pub mod serial_ctaphid;
pub mod totp_view;
pub mod ui_journey;
pub mod watchdog;
pub mod wifi_ap;
pub mod wifi_station;
pub mod usb_descriptors;
pub mod vault_store;
pub mod wallet_exec;

pub use button::{BootButton, ButtonInput, MockButtonInput, PressEvent, UserPresenceError};
pub use display::{AegisUiRenderer, DisplayBuffer, DisplayManager, UiScreen};
pub use efuse::{EfuseError, EfuseManager, EfuseStorage, MockEfuseStorage, RamEfuseStorage};
pub use led::{Color, LedEffect, LedOutput, MockLedOutput, Ws2812Controller};
pub use persistence::{FlashStorageBackend, MockFlashBackend, RamFlashBackend, SecureStorage, StorageError};
pub use watchdog::{StaticBuf, Watchdog};
pub use usb_descriptors::*;

