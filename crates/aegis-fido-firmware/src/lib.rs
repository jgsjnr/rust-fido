//! AegisKey S3 Authenticator Firmware Library.
//!
//! Provides drivers for:
//! - Physical BOOT button on GPIO 0 with debounce and User Presence (UP) detection.
//! - WS2812 addressable RGB LED on GPIO 48 with visual animation effects.
//! - eFuse OTP hardware integration (BLOCK7 Master Key, BLOCK8 Device Salt).
//! - Secure encrypted persistence in NVS/Flash with AES-256-GCM.
//! - Composite USB descriptors (CTAPHID, CCID, Keyboard, WinUSB with MS OS 2.0).
//! - Wave4: pairing journey (5s hold), BLE GATT 0xFFFD, WiFi AP, UI journey.

pub mod binding;
pub mod ble_gatt;
pub mod ble_nimble;
pub mod button;
pub mod ccid_dispatch;
pub mod config;
pub mod display;
pub mod efuse;
pub mod freertos;
pub mod fw_log;
pub mod identity;
pub mod led;
pub mod lifetime_trace;
pub mod mdns;
pub mod migrations;
pub mod nvs_backend;
pub mod oath_store;
pub mod ota;
pub mod pairing;
pub mod pairing_flow;
pub mod pairing_led;
pub mod persistence;
pub mod piv_store;
pub mod provision;
#[cfg(feature = "proximity")]
pub mod proximity;
pub mod recovery;
pub mod serial_ctaphid;
pub mod test_hooks;
pub mod totp_view;
pub mod ui_journey;
pub mod usb_descriptors;
pub mod vault_store;
pub mod vendor_exec;
pub mod wallet_exec;
pub mod watchdog;
pub mod wifi_ap;
pub mod wifi_station;

#[cfg(any(test, not(target_os = "espidf")))]
pub use button::MockButtonInput;
pub use button::{BootButton, ButtonInput, PressEvent, UserPresenceError};
#[cfg(feature = "has-display")]
pub use display::{AegisUiRenderer, DisplayBuffer};
pub use display::{DisplayManager, UiScreen};
#[cfg(any(test, not(target_os = "espidf")))]
pub use efuse::MockEfuseStorage;
pub use efuse::{EfuseError, EfuseManager, EfuseStorage, RamEfuseStorage};
pub use freertos::{EventGroup, FirmwareEvent, FreeRtosQueue, FreeRtosScheduler, TaskConfig};
#[cfg(any(test, not(target_os = "espidf")))]
pub use led::MockLedOutput;
pub use led::{Color, LedEffect, LedOutput, Ws2812Controller};
#[cfg(any(test, not(target_os = "espidf")))]
pub use persistence::MockFlashBackend;
pub use persistence::{FlashStorageBackend, PlatformFlashBackend, SecureStorage, StorageError};
pub use usb_descriptors::*;
pub use watchdog::{StaticBuf, Watchdog};
