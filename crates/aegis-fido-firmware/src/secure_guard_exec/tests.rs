//! Secure Guard exec tests (hub; move-only split by area).
//!
//! Shared fixtures live here; area suites live in sibling files wired via
//! `#[path]` so `secure_guard_exec/mod.rs` stays untouched:
//! - `tests_status` (status op + feature flags)
//! - `tests_unlock` (provision/unlock/change-pin backoff)
//! - `tests_features` (ecdh/shamir/clear-sign/keepassxc/ble proximity)
//! - `tests_config_wipe` (config + selective wipe)
//! - `tests_recovery` (recover op + envelope lifecycle)

use crate::persistence::{MockFlashBackend, SecureStorage};

#[path = "tests_config_wipe.rs"]
mod tests_config_wipe;
#[path = "tests_features.rs"]
mod tests_features;
#[path = "tests_recovery.rs"]
mod tests_recovery;
#[path = "tests_status.rs"]
mod tests_status;
#[path = "tests_unlock.rs"]
mod tests_unlock;

fn test_storage() -> SecureStorage<MockFlashBackend> {
    SecureStorage::new(MockFlashBackend::new(), &[0x11; 32], &[0x22; 32])
}
