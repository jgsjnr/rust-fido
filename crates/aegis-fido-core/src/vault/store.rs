//! Vault store view: thin mutable delegation to existing `AegisVault`.
//!
//! No duplication: `put`/`delete`/`get_mut` delegate directly.

use super::{AegisVault, VaultPasskey};

/// Mutable store view delegating to `AegisVault`.
#[derive(Debug)]
pub struct VaultStore<CHAR>(pub CHAR);

impl<CHAR> VaultStore<CHAR> where CHAR: AsMut<AegisVault> + AsRef<AegisVault> {
    /// Creates a store view.
    pub fn new(inner: CHAR) -> Self {
        Self(inner)
    }
    /// Stores a passkey (delegates to `AegisVault::put`).
    pub fn put(&mut self, passkey: VaultPasskey) {
        self.0.as_mut().put(passkey)
    }
    /// Deletes by ID (delegates to `AegisVault::delete`).
    pub fn delete(&mut self, credential_id: &[u8]) -> bool {
        self.0.as_mut().delete(credential_id)
    }
    /// Mutable lookup (delegates to `AegisVault::get_mut`).
    pub fn get_mut(&mut self, credential_id: &[u8]) -> Option<&mut VaultPasskey> {
        self.0.as_mut().get_mut(credential_id)
    }
    /// Read lookup (delegates to `AegisVault::get`).
    pub fn get(&self, credential_id: &[u8]) -> Option<&VaultPasskey> {
        self.0.as_ref().get(credential_id)
    }
}
