//! Secure Guard command surface (thin re-export shim; move-only).
//!
//! Concrete items live in `dispatch` (shared consts/helpers + opcode
//! dispatcher), `status`/`unlock`/`lock`/`config`/`wipe` (command groups)
//! and `tests` (unit tests, same coverage). Every
//! `secure_guard_exec::X` path keeps compiling via the re-exports below.
pub mod bench;
pub mod config;
pub mod dispatch;
pub mod lock;
pub mod status;
pub mod unlock;
pub mod wipe;

#[cfg(test)]
mod tests;

pub(crate) use config::handle_config;
pub(crate) use dispatch::{
    cbor_err, extract_bytes, get_field, hex_decode, hex_encode, to_cbor_bytes,
};
pub use dispatch::{
    exec_secure_guard_op, shamir_2_of_3_recover, shamir_2_of_3_split, CTAP2_ERR_PIN_AUTH_INVALID,
    CTAP2_ERR_PIN_REQUIRED, CTAP2_ERR_VENDOR_INTERNAL,
};
pub(crate) use lock::handle_lock;
pub use status::{handle_status, handle_status_with_ota};
pub(crate) use unlock::handle_unlock_or_mgmt;
pub(crate) use wipe::handle_wipe_selective;
