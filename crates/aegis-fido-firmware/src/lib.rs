//! AegisKey S3 Authenticator Firmware Library.
//!
//! Provides drivers for:
//! - Physical BOOT button on GPIO 0 with debounce and User Presence (UP) detection.
//! - WS2812 addressable RGB LED on GPIO 48 with visual animation effects.
//! - eFuse OTP hardware integration (BLOCK7 Master Key, BLOCK8 Device Salt).
//! - Secure encrypted persistence in NVS/Flash with AES-256-GCM.
//! - Composite USB descriptors (CTAPHID, CCID, Keyboard, WinUSB with MS OS 2.0).
//! - Wave4: pairing journey (5s hold), BLE GATT 0xFFFD, WiFi AP, UI journey.

pub mod anti_rollback;
pub mod apdu;
pub mod backup_envelope;
pub mod binding;
pub mod ble_gatt;
pub mod ble_nimble;
pub mod button;
pub mod ccid_dispatch;
pub mod config;
pub mod cred_store;
pub mod crypto_aead;
pub mod crypto_extra;
pub mod crypto_hash;
pub mod crypto_hrng;
pub mod crypto_p256;
pub mod crypto_rsa;
pub mod ctap_cmd;
pub mod ctap_ext;
pub mod ctap_state;
pub mod display;
pub mod dkek;
pub mod efuse;
pub mod efuse_plan;
pub mod freertos;
pub mod freertos_route;
pub mod freertos_sched;
pub mod fw_log;
pub mod hd_wallet;
pub mod identity;
pub mod led;
pub mod led_policy;
pub mod lifetime_trace;
pub mod mdns;
pub mod migrations;
pub mod nvs_backend;
pub mod oath_cmd;
pub mod oath_store;
pub mod openpgp_cmd;
pub mod ota;
pub mod ota_store;
pub mod pairing;
pub mod pairing_flow;
pub mod pairing_led;
pub mod persistence;
pub mod pin_uv;
pub mod piv_cmd;
pub mod piv_store;
pub mod provision;
#[cfg(feature = "proximity")]
pub mod proximity;
#[cfg(feature = "proximity")]
pub mod proximity_sched;
pub mod recovery;
pub mod run;
pub mod secure_msg;
pub mod serial_ctaphid;
pub mod test_hooks;
pub mod totp;
pub mod totp_view;
pub mod trust_facade;
pub mod trust_gap;
pub mod ui_journey;
pub mod up_policy;
pub mod usb_descriptors;
pub mod vault_aead;
pub mod vault_store;
pub mod vendor_exec;
pub mod wallet_exec;
pub mod watchdog;
pub mod wifi_ap;
pub mod wifi_station;
pub mod zeroize;

pub use crate::crypto_aead::{AeadAlgorithm, AeadBackend, AeadError};
pub use crate::crypto_extra::{ExtraCurve, ExtraError};
pub use crate::crypto_hash::HashError;
pub use crate::crypto_hrng::{HrngError, HrngSource};
pub use crate::crypto_p256::{P256Error, P256Secret};
pub use crate::crypto_rsa::{RsaError, RsaKeyBits, RsaScheme};
pub use crate::efuse_plan::{EfusePlan, PlanError};
pub use crate::led_policy::{LedAuthError, LedCommand, LedPolicy};
pub use crate::up_policy::{OperationHash, UpDeny, UpGrant, UpPolicy};
pub use crate::zeroize::{scrub, SecretBytes};
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
pub use led::{Color, LedEffect, LedOutput, MockLedOutput, Ws2812Controller};
#[cfg(any(test, not(target_os = "espidf")))]
pub use persistence::MockFlashBackend;
pub use persistence::{FlashStorageBackend, PlatformFlashBackend, SecureStorage, StorageError};
pub use usb_descriptors::*;
pub use watchdog::{StaticBuf, Watchdog};
