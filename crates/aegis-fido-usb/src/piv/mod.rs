//! PIV (NIST SP 800-73-4) applet: roteamento de comandos por arquivo.
//!
//! - `apdu`: dono unico dos parsers de campo APDU (TLV + GET/PUT/GEN/AUTH).
//! - `piv_cmd`: applet, PIN/PUK, slots, store/crypt traits e testes.
//!
//! Compat: todo simbolo publico de `piv.rs` segue em `crate::piv::*`.

pub mod apdu;
pub mod cmd;
pub mod piv_applet;
pub mod piv_cmd;

pub use piv_cmd::{
    is_valid_piv_pin, is_valid_piv_puk, provision_pin, provision_pin_with_rng, NoBackend,
    PivApplet, PivCryptoError, PivKeyBackend, PivPinError, PivRecordStore, PivSlot, PivStoreError,
    MAX_PIV_CERT_BYTES, PIV_HASH_LEN, PIV_NVS_PIN_HASH, PIV_NVS_PIN_RETRIES, PIV_NVS_PIN_SALT,
    PIV_NVS_PUK_HASH, PIV_NVS_PUK_RETRIES, PIV_NVS_PUK_SALT, PIV_PIN_MAX_LEN, PIV_PIN_MAX_RETRIES,
    PIV_PIN_MIN_LEN, PIV_PUK_LEN, PIV_PUK_MAX_RETRIES, PIV_SALT_LEN, PIV_SLOT_9A, PIV_SLOT_9C,
    PIV_SLOT_9D, PIV_SLOT_9E,
};
