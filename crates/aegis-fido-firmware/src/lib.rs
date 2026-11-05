//! AegisKey S3 Authenticator Firmware Library.
//!
//! Provides drivers for:
//! - Physical BOOT button on GPIO 0 with debounce and User Presence (UP) detection.
//! - WS2812 addressable RGB LED on GPIO 48 with visual animation effects.
//! - eFuse OTP hardware integration (BLOCK7 Master Key, BLOCK8 Device Salt).
//! - Secure encrypted persistence in NVS/Flash with AES-256-GCM.
//! - Composite USB descriptors (CTAPHID, CCID, Keyboard, WinUSB with MS OS 2.0).
//! - Wave4: pairing journey (5s hold), BLE GATT 0xFFFD, WiFi AP, UI journey.
//!
//! Capability diet (owner-requested presets; ver
//! `reports/refactoring/CAPABILITY_DIET.md`).
//!
//! Predicados (escritos por extenso em cada `#[cfg]`):
//! - DIET      = `any(feature = "cap-fido-only", feature = "cap-fido-totp")`
//! - FIDO_ONLY = `all(feature = "cap-fido-only", not(feature = "cap-fido-totp"))`
//! - TOTP_ON   = `any(feature = "cap-fido-totp", not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))`
//! - FULL_ONLY = `not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))`
//!
//! `full` = default como hoje (tudo compilado). `cap-*` sao raizes
//! alternativas: mutuamente exclusivas entre si e com `default`.
//! Modulos pesados saem do preset via `#[cfg]` + stubs fail-closed com
//! `UNSUPPORTED_FEATURE` onde o comando fica indisponivel (nunca queda
//! silenciosa). CTAP2 + CCID/HID + SecureGuard + NVS + OTA + USB ficam
//! sempre ligados.
// `cap-fido-only` x `cap-fido-totp`: raizes alternativas mutuamente exclusivas.
#[cfg(all(feature = "cap-fido-only", feature = "cap-fido-totp"))]
compile_error!("cap-fido-only and cap-fido-totp are mutually exclusive capability roots");
// `cap-*` exige `--no-default-features` (`full` = default como hoje).
#[cfg(all(feature = "default", feature = "cap-fido-only"))]
compile_error!("cap-fido-only is an alternative root: build with --no-default-features --features board-devkitc,cap-fido-only");
#[cfg(all(feature = "default", feature = "cap-fido-totp"))]
compile_error!("cap-fido-totp is an alternative root: build with --no-default-features --features board-devkitc,cap-fido-totp");
// Diet exclui radios extras, display, diagnosticos e binds de teste.
#[cfg(all(
    any(feature = "cap-fido-only", feature = "cap-fido-totp"),
    any(
        feature = "proximity",
        feature = "debug-terminal",
        feature = "test-mode",
        feature = "has-display",
        feature = "board-t-display",
        feature = "board-ttgo-classic",
        feature = "wifi"
    )
))]
compile_error!(
    "capability diet presets exclude proximity/debug-terminal/test-mode/display/wifi features"
);
/// Vendor status fail-closed para comando compilado para fora da capability
/// (diet presets). Namespace vendor section 9.5: `0x00` OK | `0x01` NEED_UP |
/// `0x02` NEED_PIN | `0x03` NO_SLOT | `0x04` falha generica |
/// `0x05` NEED_BINDING. `0x06` = UNSUPPORTED_FEATURE (comando indisponivel
/// no preset; nunca queda silenciosa).
pub const UNSUPPORTED_FEATURE: u8 = 0x06;

pub mod anti_rollback;
pub mod apdu;
pub mod backup_envelope;
pub mod binding;
pub mod ble;
pub mod ble_gatt;
pub mod ble_nimble;
pub mod button;
pub mod ccid_dispatch;
pub mod config;
pub mod cred_store;
pub mod crypto_aead;
#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
pub mod crypto_extra;
pub mod crypto_hash;
pub mod crypto_hrng;
pub mod crypto_p256;
#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
pub mod crypto_rsa;
pub mod ctap_cmd;
pub mod ctap_ext;
pub mod ctap_state;
pub mod display;
pub mod dkek;
pub mod efuse;
pub mod efuse_plan;
pub mod efuse_safety_lock;
pub mod freertos;
#[cfg(target_os = "espidf")]
pub mod freertos_native;
pub mod freertos_queue;
pub mod freertos_route;
pub mod freertos_sched;
pub mod fw_log;
#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
pub mod hd_wallet;
pub mod hmac_cr_compat_layer;
pub mod identity;
pub mod led;
pub mod led_policy;
pub mod lifetime_trace;
pub mod mdns;
pub mod migrations;
pub mod net;
pub mod nvs_backend;
#[cfg(any(
    feature = "cap-fido-totp",
    not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))
))]
pub mod oath_cmd;
#[cfg(any(
    feature = "cap-fido-totp",
    not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))
))]
pub mod oath_store;
pub mod oled_ssd1306_code_only;
pub mod openpgp_applet;
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
#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
pub mod pm_dispatch;
#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
pub mod pm_store;
pub mod prod_strict_guard;
pub mod provision;
#[cfg(feature = "proximity")]
pub mod proximity;
#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
pub mod proximity_crypto;
#[cfg(feature = "proximity")]
pub mod proximity_sched;
pub mod psram_public_alloc;
pub mod recovery;
pub mod run;
pub mod secure_guard_exec;
pub mod secure_guard_sched;
pub mod secure_guard_storage;
pub mod secure_msg;
pub mod serial_ctaphid;
pub mod serial_text;
pub mod serial_vendor;
pub mod stores;
pub mod test_hooks;
#[cfg(any(
    feature = "cap-fido-totp",
    not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))
))]
pub mod time_sync;
#[cfg(any(
    feature = "cap-fido-totp",
    not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))
))]
pub mod totp;
pub mod totp_view;
pub mod transport_lock;
pub mod trust_facade;
pub mod trust_gap;
#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
pub mod ui_journey;
pub mod up_policy;
pub mod usb_descriptors;
#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
pub mod vault_aead;
#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
pub mod vault_store;
pub mod vendor_exec;
#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
pub mod wallet_exec;
pub mod watchdog;
pub mod wifi_ap;
pub mod wifi_station;
pub mod zeroize;

pub use crate::crypto_aead::{AeadAlgorithm, AeadBackend, AeadError};
#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
pub use crate::crypto_extra::{ExtraCurve, ExtraError};
pub use crate::crypto_hash::HashError;
pub use crate::crypto_hrng::{HrngError, HrngSource};
pub use crate::crypto_p256::{P256Error, P256Secret};
#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
pub use crate::crypto_rsa::{RsaError, RsaKeyBits, RsaScheme};
pub use crate::efuse_plan::{EfusePlan, PlanError};
pub use crate::efuse_safety_lock::{
    inspect_efuse_safety_status, EfuseSafetyError, EfuseSafetyStatusReport,
    FlashEncryptionAesXtsSpec, HardwareHmacEfuseBlock7Spec, MonotonicAntiRollbackEfuseSpec,
    SecureBootV2Rsa3072Spec, EFUSE_PERMANENT_LOCK_WARNING, EFUSE_WRITE_HARD_LOCKED,
};
pub use crate::led_policy::{LedAuthError, LedCommand, LedPolicy};
pub use crate::oled_ssd1306_code_only::{
    Ssd1306Driver, VirtualOledDisplayBuffer, HARDWARE_I2C_OLED_ATTACHED, OLED_FRAME_BYTES,
    OLED_HEIGHT, OLED_WIDTH, SSD1306_DEFAULT_I2C_ADDR, SSD1306_DEFAULT_SCL_PIN,
    SSD1306_DEFAULT_SDA_PIN,
};
pub use crate::prod_strict_guard::{
    is_software_touch_allowed, verify_software_touch_allowed, ProductionIsolationGate,
    PROD_STRICT_ACTIVE,
};
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
#[cfg(any(test, not(target_os = "espidf")))]
pub use led::MockLedOutput;
pub use led::{Color, LedEffect, LedOutput, Ws2812Controller};
#[cfg(any(test, not(target_os = "espidf")))]
pub use persistence::MockFlashBackend;
pub use persistence::{
    delete_recovery_envelope, load_recovery_envelope, save_recovery_envelope, FlashStorageBackend,
    PlatformFlashBackend, SecureStorage, StorageError, RECOVERY_ENVELOPE_NVS_KEY,
};
pub use secure_guard_exec::exec_secure_guard_op;
pub use secure_guard_sched::{
    tick_secure_guard, SecureGuardSupervisor, SECURE_GUARD_TASK_PRIO, SECURE_GUARD_TASK_STACK,
};
pub use secure_guard_storage::{
    destroy_recovery_envelope, load_secure_guard_record, recover_error_locked_with_envelope,
    save_secure_guard_record, NVS_SECURE_GUARD_RECORD,
};
pub use usb_descriptors::*;
pub use watchdog::{StaticBuf, Watchdog};
