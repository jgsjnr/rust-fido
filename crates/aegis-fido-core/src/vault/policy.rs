//! Vault policy view: thin delegation for RP/eligibility queries.
//!
//! No duplication: all storage stays in `super::AegisVault`.

use super::{AegisVault, VaultPasskey};

/// Policy query view delegating to `AegisVault`.
#[derive(Debug)]
pub struct VaultPolicy<CHAR>(pub CHAR);

impl<CHAR> VaultPolicy<CHAR> where CHAR: AsRef<AegisVault> {
    /// Creates a policy view.
    pub fn new(inner: CHAR) -> Self {
        Self(inner)
    }
    /// Finds passkeys by RP (delegates to `AegisVault::find_by_rp`).
    pub fn find_by_rp(&self, rp_id: &str) -> alloc::vec::Vec<&VaultPasskey> {
        self.0.as_ref().find_by_rp(rp_id)
    }
    /// Whether vault is empty (delegates to `AegisVault::is_empty`).
    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }
}
