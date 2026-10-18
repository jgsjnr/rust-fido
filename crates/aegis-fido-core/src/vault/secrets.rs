//! Vault secrets view: thin read-only delegation to existing `AegisVault`.

use super::{AegisVault, VaultPasskey};

/// Read-only secrets view delegating to `AegisVault`.
#[derive(Debug)]
pub struct VaultSecrets<CHAR> {
    inner: CHAR,
}

impl<CHAR> VaultSecrets<CHAR>
where
    CHAR: AsRef<AegisVault>,
{
    /// Creates a secrets view.
    pub fn new(inner: CHAR) -> Self {
        Self { inner }
    }
    /// Number of passkeys (delegates to `AegisVault::len`).
    pub fn len(&self) -> usize {
        self.inner.as_ref().len()
    }
    /// Whether vault is empty (delegates to `AegisVault::is_empty`).
    pub fn is_empty(&self) -> bool {
        self.inner.as_ref().is_empty()
    }
    /// Retrieves a passkey by ID (delegates to `AegisVault::get`).
    pub fn get(&self, credential_id: &[u8]) -> Option<&VaultPasskey> {
        self.inner.as_ref().get(credential_id)
    }
}
