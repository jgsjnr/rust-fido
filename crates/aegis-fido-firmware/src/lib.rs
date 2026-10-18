//! AegisKey S3 Authenticator Firmware Library.
//!
//! Provides drivers for:
//! - Physical BOOT button on GPIO 0 with debounce and User Presence (UP) detection.
//! - WS2812 addressable RGB LED on GPIO 48 with visual animation effects.
//! - eFuse OTP hardware integration (BLOCK7 Master Key, BLOCK8 Device Salt).
//! - Secure encrypted persistence in NVS/Flash with AES-256-GCM.
//! - Composite USB descriptors (CTAPHID, CCID, Keyboard, WinUSB with MS OS 2.0).

pub mod button;
pub mod efuse;
pub mod led;
pub mod persistence;
pub mod usb_descriptors;

pub use button::{BootButton, ButtonInput, MockButtonInput, PressEvent, UserPresenceError};
pub use efuse::{EfuseError, EfuseManager, EfuseStorage, MockEfuseStorage};
pub use led::{Color, LedEffect, LedOutput, MockLedOutput, Ws2812Controller};
pub use persistence::{FlashStorageBackend, MockFlashBackend, SecureStorage, StorageError};
pub use usb_descriptors::*;
