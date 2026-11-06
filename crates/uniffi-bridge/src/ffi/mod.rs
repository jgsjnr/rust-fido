//! C ABI surface for JNI/JNA callers, split by family.
//!
//! `lib.rs` re-exports this module wholesale (`pub use ffi::*`), so the
//! ABI and symbol set are unchanged: this split only moves code.

mod ble_ffi;
mod common;
mod envelope_ffi;
mod oath_ffi;
mod pm_ffi;
mod secure_guard_ffi;
mod wallet_ffi;

pub use ble_ffi::*;
pub use common::*;
pub use envelope_ffi::*;
pub use oath_ffi::*;
pub use pm_ffi::*;
pub use secure_guard_ffi::*;
pub use wallet_ffi::*;
