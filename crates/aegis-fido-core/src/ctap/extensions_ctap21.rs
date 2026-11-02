//! CTAP 2.1 Extensions Engine (`OPP-02`): `hmac-secret` & `largeBlobs`
//!
//! Provides native `no_std` CTAP 2.1 implementation for:
//! 1. `hmac-secret`: User-Verification-conditioned HMAC-SHA256 evaluation of salts against
//!    credential random secrets (`credRandom`), enabling SSH hardware tokens, LUKS keys, and KeePassXC.
//! 2. `largeBlobKey` / `largeBlobs`: Authenticated large blob storage protected by a 16-byte
//!    truncated SHA-256 digest adhering strictly to CTAP 2.1 §6.6 and §7.1.

use alloc::vec::Vec;
use rand_core::CryptoRng;
use zeroize::Zeroize;

use crate::crypto::hash::sha256;
use crate::crypto::kdf::hmac_sha256;
use crate::secure_guard::crypto::constant_time_eq_32;

/// Default capacity for CTAP 2.1 Large Blobs storage in bytes (4 KiB).
pub const DEFAULT_LARGE_BLOB_CAPACITY: usize = 4096;
/// Truncated SHA-256 authentication tag length in bytes (CTAP 2.1 §7.1).
pub const LARGE_BLOB_TAG_LEN: usize = 16;

/// Strongly-typed errors for CTAP 2.1 extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ctap21ExtensionError {
    /// Offset is beyond currently allocated buffer.
    OffsetOutOfBounds { offset: usize, len: usize },
    /// Requested data exceeds configured large blob storage capacity.
    CapacityExceeded { requested: usize, capacity: usize },
    /// Large blob authentication tag (SHA-256 truncated) does not match payload.
    IntegrityTagMismatch,
    /// Payload is too short to contain the 16-byte CTAP 2.1 integrity tag.
    PayloadTooShort { actual_len: usize },
    /// Access denied because Secure Guard is locked.
    SecureGuardLocked,
    /// Invalid salt length (expected 32 bytes).
    InvalidSaltLength,
    /// Serialization or CBOR decoding error.
    MalformedEntry,
}

impl core::fmt::Display for Ctap21ExtensionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OffsetOutOfBounds { offset, len } => {
                write!(f, "largeBlobs offset {} out of bounds (len: {})", offset, len)
            }
            Self::CapacityExceeded { requested, capacity } => {
                write!(
                    f,
                    "largeBlobs requested size {} exceeds capacity {}",
                    requested, capacity
                )
            }
            Self::IntegrityTagMismatch => {
                write!(f, "largeBlobs 16-byte truncated SHA-256 tag mismatch")
            }
            Self::PayloadTooShort { actual_len } => {
                write!(f, "largeBlobs payload len {} is smaller than 16-byte tag", actual_len)
            }
            Self::SecureGuardLocked => {
                write!(f, "Access denied: Secure Guard authority is locked")
            }
            Self::InvalidSaltLength => {
                write!(f, "Invalid salt length: expected exactly 32 bytes")
            }
            Self::MalformedEntry => {
                write!(f, "Malformed large blob entry or corrupted CBOR")
            }
        }
    }
}

/// Credential random secrets (`credRandom`) partitioned into with-UV and without-UV materials.
#[derive(Clone, PartialEq, Eq)]
pub struct CredRandomMaterial {
    /// 32-byte secret evaluated when User Verification (UV) is performed.
    pub cred_random_uv: [u8; 32],
    /// 32-byte secret evaluated when User Verification (UV) is omitted / not performed.
    pub cred_random_no_uv: [u8; 32],
}

impl core::fmt::Debug for CredRandomMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CredRandomMaterial")
            .field("cred_random_uv", &"[REDACTED]")
            .field("cred_random_no_uv", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CredRandomMaterial {
    fn drop(&mut self) {
        self.cred_random_uv.zeroize();
        self.cred_random_no_uv.zeroize();
    }
}

impl CredRandomMaterial {
    /// Generates new random secrets using a cryptographically secure RNG.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        let mut uv = [0u8; 32];
        let mut no_uv = [0u8; 32];
        rng.fill_bytes(&mut uv);
        rng.fill_bytes(&mut no_uv);
        Self {
            cred_random_uv: uv,
            cred_random_no_uv: no_uv,
        }
    }

    /// Creates secrets from explicit 32-byte slices (e.g. from persistent storage or tests).
    pub fn from_slices(uv: &[u8; 32], no_uv: &[u8; 32]) -> Self {
        Self {
            cred_random_uv: *uv,
            cred_random_no_uv: *no_uv,
        }
    }

    /// Derives the 32-byte symmetric `largeBlobKey` according to CTAP 2.1 §6.6:
    /// `largeBlobKey = HMAC-SHA256(credRandom, b"CTAP2.1-largeBlobKey")`.
    pub fn derive_large_blob_key(&self, uv_verified: bool) -> [u8; 32] {
        let key = if uv_verified {
            &self.cred_random_uv
        } else {
            &self.cred_random_no_uv
        };
        hmac_sha256(key, b"CTAP2.1-largeBlobKey")
    }
}

/// Output of a CTAP 2.1 `hmac-secret` evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacSecretOutput {
    /// Primary evaluated HMAC: `HMAC-SHA256(credRandom, salt1)`.
    pub output1: [u8; 32],
    /// Secondary evaluated HMAC: `HMAC-SHA256(credRandom, salt2)`, if `salt2` was supplied.
    pub output2: Option<[u8; 32]>,
}

/// Engine for evaluating CTAP 2.1 `hmac-secret` requests.
#[derive(Debug, Clone, Default)]
pub struct HmacSecretExtension;

impl HmacSecretExtension {
    /// Evaluates `hmac-secret` against the provided salts, conditioned on UV status and Secure Guard state.
    ///
    /// # Arguments
    /// * `material` - The credential's `credRandom` secrets.
    /// * `salt1` - 32-byte primary salt.
    /// * `salt2` - Optional 32-byte secondary salt.
    /// * `uv_verified` - True if User Verification was performed during assertion.
    /// * `guard_unlocked` - True if Secure Guard is currently unlocked.
    /// * `require_guard_unlock_for_uv` - If true, rejects evaluation when UV is requested but Secure Guard is locked.
    pub fn evaluate(
        &self,
        material: &CredRandomMaterial,
        salt1: &[u8; 32],
        salt2: Option<&[u8; 32]>,
        uv_verified: bool,
        guard_unlocked: bool,
        require_guard_unlock_for_uv: bool,
    ) -> Result<HmacSecretOutput, Ctap21ExtensionError> {
        if uv_verified && require_guard_unlock_for_uv && !guard_unlocked {
            return Err(Ctap21ExtensionError::SecureGuardLocked);
        }

        let secret = if uv_verified {
            &material.cred_random_uv
        } else {
            &material.cred_random_no_uv
        };

        let output1 = hmac_sha256(secret, salt1);
        let output2 = salt2.map(|s2| hmac_sha256(secret, s2));

        Ok(HmacSecretOutput { output1, output2 })
    }
}

/// Single authenticated entry inside `LargeBlobStore` (e.g. for an SSH key or config blob).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LargeBlobEntry {
    /// Associated `largeBlobKey` digest or credential ID.
    pub key: [u8; 32],
    /// Stored plaintext or ciphertext payload.
    pub data: Vec<u8>,
}

/// Authenticated Large Blob Storage conforming to CTAP 2.1 §7.1.
///
/// Format on wire / in storage: `data || SHA-256(data)[0..16]`.
#[derive(Debug, Clone)]
pub struct LargeBlobStore {
    storage: Vec<u8>,
    capacity: usize,
    entries: Vec<LargeBlobEntry>,
}

impl Default for LargeBlobStore {
    fn default() -> Self {
        Self::new(DEFAULT_LARGE_BLOB_CAPACITY)
    }
}

impl LargeBlobStore {
    /// Creates a new `LargeBlobStore` with the specified maximum byte capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            storage: Vec::new(),
            capacity,
            entries: Vec::new(),
        }
    }

    /// Current committed buffer size including 16-byte tag.
    pub fn len(&self) -> usize {
        self.storage.len()
    }

    /// True if no large blob is currently committed.
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }

    /// Configured maximum capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Reads raw chunk from the storage array.
    pub fn read_chunk(&self, offset: usize, count: usize) -> Result<Vec<u8>, Ctap21ExtensionError> {
        if offset > self.storage.len() {
            return Ok(Vec::new());
        }
        let end = (offset + count).min(self.storage.len());
        Ok(self.storage[offset..end].to_vec())
    }

    /// Writes raw chunk into the storage array.
    pub fn write_chunk(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Ctap21ExtensionError> {
        let needed_len = offset.checked_add(bytes.len()).ok_or(Ctap21ExtensionError::CapacityExceeded {
            requested: usize::MAX,
            capacity: self.capacity,
        })?;

        if needed_len > self.capacity {
            return Err(Ctap21ExtensionError::CapacityExceeded {
                requested: needed_len,
                capacity: self.capacity,
            });
        }

        if self.storage.len() < needed_len {
            self.storage.resize(needed_len, 0);
        }

        self.storage[offset..needed_len].copy_from_slice(bytes);
        Ok(())
    }

    /// Commits authenticated payload by appending the 16-byte truncated SHA-256 tag.
    ///
    /// Layout: `payload || SHA-256(payload)[0..16]`.
    pub fn commit_authenticated_payload(&mut self, payload: &[u8]) -> Result<(), Ctap21ExtensionError> {
        let total_len = payload.len() + LARGE_BLOB_TAG_LEN;
        if total_len > self.capacity {
            return Err(Ctap21ExtensionError::CapacityExceeded {
                requested: total_len,
                capacity: self.capacity,
            });
        }

        let digest = sha256(payload);
        let tag = &digest[0..LARGE_BLOB_TAG_LEN];

        self.storage.clear();
        self.storage.reserve(total_len);
        self.storage.extend_from_slice(payload);
        self.storage.extend_from_slice(tag);

        Ok(())
    }

    /// Verifies the 16-byte truncated SHA-256 integrity tag in constant time.
    pub fn verify_integrity(&self) -> bool {
        if self.storage.len() < LARGE_BLOB_TAG_LEN {
            return false;
        }

        let payload_len = self.storage.len() - LARGE_BLOB_TAG_LEN;
        let payload = &self.storage[..payload_len];
        let tag_stored = &self.storage[payload_len..];

        let digest = sha256(payload);
        let tag_computed = &digest[0..LARGE_BLOB_TAG_LEN];

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0..16].copy_from_slice(tag_stored);
        b[0..16].copy_from_slice(tag_computed);

        constant_time_eq_32(&a, &b)
    }

    /// Extracts the verified payload if the 16-byte truncated SHA-256 tag is valid.
    pub fn get_verified_payload(&self) -> Result<&[u8], Ctap21ExtensionError> {
        if self.storage.len() < LARGE_BLOB_TAG_LEN {
            return Err(Ctap21ExtensionError::PayloadTooShort {
                actual_len: self.storage.len(),
            });
        }

        if !self.verify_integrity() {
            return Err(Ctap21ExtensionError::IntegrityTagMismatch);
        }

        let payload_len = self.storage.len() - LARGE_BLOB_TAG_LEN;
        Ok(&self.storage[..payload_len])
    }

    /// Stores or replaces an indexed blob entry by `largeBlobKey`.
    pub fn put_blob_entry(&mut self, key: &[u8; 32], data: &[u8]) -> Result<(), Ctap21ExtensionError> {
        if let Some(pos) = self.entries.iter().position(|e| e.key == *key) {
            self.entries[pos].data = data.to_vec();
        } else {
            self.entries.push(LargeBlobEntry {
                key: *key,
                data: data.to_vec(),
            });
        }
        self.rebuild_and_commit()
    }

    /// Retrieves an entry's data matching `largeBlobKey`.
    pub fn get_blob_entry(&self, key: &[u8; 32]) -> Option<&[u8]> {
        self.entries.iter().find(|e| e.key == *key).map(|e| e.data.as_slice())
    }

    /// Deletes an entry by `largeBlobKey`. Returns true if found and removed.
    pub fn delete_blob_entry(&mut self, key: &[u8; 32]) -> Result<bool, Ctap21ExtensionError> {
        if let Some(pos) = self.entries.iter().position(|e| e.key == *key) {
            self.entries.remove(pos);
            self.rebuild_and_commit()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Clears all large blob storage.
    pub fn clear(&mut self) {
        self.storage.clear();
        self.entries.clear();
    }

    /// Serializes entries into flat payload and commits with 16-byte authentication tag.
    fn rebuild_and_commit(&mut self) -> Result<(), Ctap21ExtensionError> {
        let mut flat = Vec::new();
        for entry in &self.entries {
            flat.extend_from_slice(&entry.key);
            let len = entry.data.len() as u32;
            flat.extend_from_slice(&len.to_be_bytes());
            flat.extend_from_slice(&entry.data);
        }
        self.commit_authenticated_payload(&flat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_secret_evaluation_uv_and_no_uv() {
        let material = CredRandomMaterial::from_slices(&[0x11u8; 32], &[0x22u8; 32]);
        let ext = HmacSecretExtension;

        let salt1 = [0xAAu8; 32];
        let salt2 = [0xBBu8; 32];

        // 1. UV verified evaluation
        let out_uv = ext
            .evaluate(&material, &salt1, Some(&salt2), true, true, false)
            .expect("uv evaluation");
        assert_eq!(out_uv.output1, hmac_sha256(&[0x11u8; 32], &salt1));
        assert_eq!(out_uv.output2, Some(hmac_sha256(&[0x11u8; 32], &salt2)));

        // 2. Without UV evaluation
        let out_no_uv = ext
            .evaluate(&material, &salt1, None, false, true, false)
            .expect("no-uv evaluation");
        assert_eq!(out_no_uv.output1, hmac_sha256(&[0x22u8; 32], &salt1));
        assert_eq!(out_no_uv.output2, None);

        // Secrets differ
        assert_ne!(out_uv.output1, out_no_uv.output1);
    }

    #[test]
    fn test_hmac_secret_respects_secure_guard_lock() {
        let material = CredRandomMaterial::from_slices(&[0x11u8; 32], &[0x22u8; 32]);
        let ext = HmacSecretExtension;
        let salt1 = [0x55u8; 32];

        // When guard lock check is active and guard is locked, access is denied
        let err = ext.evaluate(&material, &salt1, None, true, false, true);
        assert_eq!(err, Err(Ctap21ExtensionError::SecureGuardLocked));

        // When unlocked, succeeds
        let ok = ext.evaluate(&material, &salt1, None, true, true, true);
        assert!(ok.is_ok());
    }

    #[test]
    fn test_large_blob_key_derivation() {
        let material = CredRandomMaterial::from_slices(&[0x33u8; 32], &[0x44u8; 32]);
        let key_uv = material.derive_large_blob_key(true);
        let key_no_uv = material.derive_large_blob_key(false);

        assert_ne!(key_uv, [0u8; 32]);
        assert_ne!(key_no_uv, [0u8; 32]);
        assert_ne!(key_uv, key_no_uv);
    }

    #[test]
    fn test_large_blob_store_commit_verify_and_tamper() {
        let mut store = LargeBlobStore::new(1024);
        let payload = b"SSH-ED25519-CERTIFICATE-AND-SSH-CONFIG-BYTES";

        store.commit_authenticated_payload(payload).expect("commit");
        assert!(store.verify_integrity());
        assert_eq!(store.get_verified_payload().unwrap(), payload);

        // Tamper with payload byte
        store.storage[5] ^= 0x01;
        assert!(!store.verify_integrity());
        assert_eq!(
            store.get_verified_payload(),
            Err(Ctap21ExtensionError::IntegrityTagMismatch)
        );
    }

    #[test]
    fn test_large_blob_store_capacity_guard() {
        let mut store = LargeBlobStore::new(64);
        let payload_60 = [0xAAu8; 60];
        // 60 bytes + 16-byte tag = 76 bytes > 64 capacity
        let err = store.commit_authenticated_payload(&payload_60);
        assert!(matches!(err, Err(Ctap21ExtensionError::CapacityExceeded { .. })));
    }

    #[test]
    fn test_large_blob_entry_management() {
        let mut store = LargeBlobStore::new(1024);
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];

        store.put_blob_entry(&key1, b"key1-data").expect("put key1");
        store.put_blob_entry(&key2, b"key2-data").expect("put key2");

        assert_eq!(store.get_blob_entry(&key1), Some(&b"key1-data"[..]));
        assert_eq!(store.get_blob_entry(&key2), Some(&b"key2-data"[..]));
        assert!(store.verify_integrity());

        store.delete_blob_entry(&key1).expect("delete key1");
        assert_eq!(store.get_blob_entry(&key1), None);
        assert_eq!(store.get_blob_entry(&key2), Some(&b"key2-data"[..]));
        assert!(store.verify_integrity());
    }
}
