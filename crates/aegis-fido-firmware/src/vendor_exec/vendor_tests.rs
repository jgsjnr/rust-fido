//! Vendor executor tests (move-only split of `vendor_exec::tests`).
//!
//! Thin shim: shared `test_storage` helper plus one submodule per command
//! group (`pin`, `piv`, `store`, `caps`). No behavior change.

use crate::persistence::{MockFlashBackend, SecureStorage};

mod caps;
mod pin;
mod piv;
mod sign;
mod store;

fn test_storage() -> SecureStorage<MockFlashBackend> {
    SecureStorage::new(MockFlashBackend::new(), &[0x11u8; 32], &[0x22u8; 32])
}
