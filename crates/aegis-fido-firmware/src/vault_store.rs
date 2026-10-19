//! Vault per-item encrypted slots (`vault/<label>`) with quota via `vault/index`.
//!
//! - Per-item: each label maps to `vault/<label>` (label 1..32B utf8, blob <=512B).
//! - Quota: `DeviceConfig::max_vault_slots` enforced via encrypted `vault/index`
//!   CBOR label list (whole-vault `seal_to_blob` is export-only, not here).
//! - Verify-after-write on put (readback compare, like migrations/oath_store).
//! - Reuses `SecureStorage` store/load/delete; no new crypto, no eFuse burn.
//! - Zeroize after use; typed errors, no panics, no stringly errors.
//! - `no_std`-compatible (alloc only, like oath_store).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use zeroize::Zeroize;

use ciborium::value::Value;

use crate::config::{DeviceConfig, MAX_LABEL_BYTES};
use crate::migrations::vault_v7::VAULT_LIVE_PREFIX;
use crate::persistence::{FlashStorageBackend, SecureStorage, StorageError};
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};

/// Max blob bytes per vault slot (envelope budget, like OATH).
pub const VAULT_STORE_MAX_BYTES: usize = 512;
/// Encrypted quota index (CBOR label list) under the live prefix.
pub const VAULT_INDEX_KEY: &str = "vault/index";
/// Reserved label (collides with the quota index key).
const VAULT_INDEX_LABEL: &str = "index";
/// Nonce placeholder (ignored, TRNG inside `store`).
const IGNORED_NONCE: [u8; 12] = [0u8; 12];

/// Typed vault_store failure (no panics, no stringly errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultStoreError {
    /// Label outside 1..32B utf8, or the reserved `index` label.
    BadLabel,
    /// Blob larger than 512B.
    TooLarge,
    /// Quota `max_vault_slots` already reached by distinct labels.
    QuotaExceeded,
    /// Slot absent.
    NotFound,
    /// Storage failure, verify-after-write mismatch, or corrupt index.
    Storage,
}

impl core::fmt::Display for VaultStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadLabel => write!(f, "bad vault label"),
            Self::TooLarge => write!(f, "vault blob too large"),
            Self::QuotaExceeded => write!(f, "vault quota exceeded"),
            Self::NotFound => write!(f, "vault slot not found"),
            Self::Storage => write!(f, "vault storage failure"),
        }
    }
}

impl From<StorageError> for VaultStoreError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::KeyNotFound => Self::NotFound,
            _ => Self::Storage,
        }
    }
}

/// Validates a vault label: 1..32B utf8, never the reserved `index` label
/// (which would collide with the encrypted `vault/index` quota list).
pub fn validate_vault_label(label: &str) -> Result<(), VaultStoreError> {
    let n = label.len();
    if !(1..=MAX_LABEL_BYTES).contains(&n) {
        return Err(VaultStoreError::BadLabel);
    }
    if label == VAULT_INDEX_LABEL {
        return Err(VaultStoreError::BadLabel);
    }
    Ok(())
}

/// NVS key `vault/<label>` (live prefix shared with the v7 migration).
pub fn vault_key(label: &str) -> String {
    let mut s = String::from(VAULT_LIVE_PREFIX);
    s.push_str(label);
    s
}

/// Decodes the encrypted `vault/index` CBOR label list (absent = empty).
fn load_index<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
) -> Result<Vec<String>, VaultStoreError> {
    let mut bytes = match storage.load(VAULT_INDEX_KEY) {
        Ok(b) => b,
        Err(StorageError::KeyNotFound) => return Ok(Vec::new()),
        Err(_) => return Err(VaultStoreError::Storage),
    };
    let res = decode_index(&bytes);
    bytes.zeroize();
    res
}

/// Encodes and stores the `vault/index` CBOR label list with verify-after-write.
///
/// Fail-closed (M2): on verify mismatch the index is NEVER deleted (deleting
/// would reset quota and fail open). Returns `Storage`; the caller rolls back
/// only its own data slot.
fn save_index<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    labels: &[String],
) -> Result<(), VaultStoreError> {
    let mut plain = encode_index(labels)?;
    let res = (|| -> Result<(), VaultStoreError> {
        storage.store(VAULT_INDEX_KEY, &plain, &IGNORED_NONCE)?;
        let mut back = storage.load(VAULT_INDEX_KEY)?;
        let ok = back.as_slice() == plain.as_slice();
        back.zeroize();
        if !ok {
            return Err(VaultStoreError::Storage);
        }
        Ok(())
    })();
    plain.zeroize();
    res
}

/// Encodes labels as a CBOR array of text (quota index plaintext).
fn encode_index(labels: &[String]) -> Result<Vec<u8>, VaultStoreError> {
    let items: Vec<Value> = labels.iter().map(|s| Value::Text(s.clone())).collect();
    let mut buf = Vec::new();
    ciborium::into_writer(&Value::Array(items), &mut buf)
        .map_err(|_| VaultStoreError::Storage)?;
    Ok(buf)
}

/// Decodes a CBOR array of text back into labels.
fn decode_index(bytes: &[u8]) -> Result<Vec<String>, VaultStoreError> {
    let value: Value = ciborium::from_reader(bytes).map_err(|_| VaultStoreError::Storage)?;
    match value {
        Value::Array(items) => items
            .into_iter()
            .map(|item| match item {
                Value::Text(s) => Ok(s),
                _ => Err(VaultStoreError::Storage),
            })
            .collect(),
        _ => Err(VaultStoreError::Storage),
    }
}

/// Adds labels to the quota index (union, no truncation, no quota check).
///
/// Additive helper for the v7 migration: after all slot copies verify, the
/// migration unions the existing index with migrated labels so quota counts
/// migrated slots. The union may exceed `max_vault_slots`; future puts then
/// fail closed with `QuotaExceeded` until deletes. Verify-after-write via
/// `save_index`.
pub fn vault_index_union_add<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    new_labels: &[String],
) -> Result<(), VaultStoreError> {
    for label in new_labels {
        validate_vault_label(label)?;
    }
    let mut index = load_index(storage)?;
    for label in new_labels {
        if !index.iter().any(|l| l == label) {
            index.push(label.clone());
        }
    }
    save_index(storage, &index)
}

/// Stores blob at `vault/<label>` with verify-after-write; new labels consume
/// one quota slot (`max_vault_slots`), overwrites do not.
pub fn vault_store_put<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    cfg: &DeviceConfig,
    label: &str,
    blob: &[u8],
) -> Result<(), VaultStoreError> {
    validate_vault_label(label)?;
    if blob.len() > VAULT_STORE_MAX_BYTES {
        return Err(VaultStoreError::TooLarge);
    }
    let mut index = load_index(storage)?;
    let known = index.iter().any(|l| l.as_str() == label);
    if !known && index.len() >= cfg.max_vault_slots {
        return Err(VaultStoreError::QuotaExceeded);
    }
    let key = vault_key(label);
    storage.store(&key, blob, &IGNORED_NONCE)?;
    let mut back = storage.load(&key)?;
    let ok = back.as_slice() == blob;
    back.zeroize();
    if !ok {
        let _ = storage.delete(&key);
        return Err(VaultStoreError::Storage);
    }
    if !known {
        index.push(String::from(label));
        if save_index(storage, &index).is_err() {
            let _ = storage.delete(&key);
            return Err(VaultStoreError::Storage);
        }
    }
    crate::ltrace!(LtCat::Oath, LtEvt::OathPut, label);
    Ok(())
}

/// Loads blob from `vault/<label>` (envelope decrypt; absent = NotFound).
///
/// Fail-closed on corrupt quota index: reads also require an intact index.
pub fn vault_store_get<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    label: &str,
) -> Result<Vec<u8>, VaultStoreError> {
    validate_vault_label(label)?;
    let _ = load_index(storage)?;
    let key = vault_key(label);
    let blob = storage.load(&key)?;
    crate::ltrace!(LtCat::Oath, LtEvt::OathCode, label);
    Ok(blob)
}

/// Deletes `vault/<label>` and frees its quota slot; absent = NotFound.
///
/// Fail-closed: the quota index is loaded before the existence check, so a
/// corrupt index reports `Storage` instead of `NotFound`.
pub fn vault_store_delete<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    label: &str,
) -> Result<(), VaultStoreError> {
    validate_vault_label(label)?;
    let mut index = load_index(storage)?;
    let key = vault_key(label);
    if !storage.exists(&key) {
        return Err(VaultStoreError::NotFound);
    }
    storage.delete(&key)?;
    index.retain(|l| l.as_str() != label);
    save_index(storage, &index)?;
    crate::ltrace!(LtCat::Oath, LtEvt::OathDelete, label);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;
    use alloc::vec;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    fn small_cfg() -> DeviceConfig {
        DeviceConfig::new(50, 512, 4, 8, 3, 32, 64, 1).expect("small vault cfg valid")
    }

    /// Backend that flips envelope bytes on reads of one slot key
    /// (emulates tampered flash; TRNG writes themselves stay intact).
    #[derive(Clone)]
    struct CorruptSlotReads {
        inner: MockFlashBackend,
        target: String,
        corrupt: alloc::rc::Rc<core::cell::Cell<bool>>,
    }

    impl FlashStorageBackend for CorruptSlotReads {
        fn read_raw(&self, key: &str) -> Result<Vec<u8>, StorageError> {
            let mut raw = self.inner.read_raw(key)?;
            if self.corrupt.get() && key == self.target {
                if let Some(last) = raw.last_mut() {
                    *last ^= 0xFF;
                }
            }
            Ok(raw)
        }
        fn write_raw(&mut self, key: &str, data: &[u8]) -> Result<(), StorageError> {
            self.inner.write_raw(key, data)
        }
        fn delete_raw(&mut self, key: &str) -> Result<(), StorageError> {
            self.inner.delete_raw(key)
        }
        fn exists(&self, key: &str) -> bool {
            self.inner.exists(key)
        }
    }

    #[test]
    fn put_get_delete_roundtrip() {
        let mut st = test_storage();
        let cfg = DeviceConfig::default();
        vault_store_put(&mut st, &cfg, "login:bank", b"vault-blob").unwrap();
        assert_eq!(vault_store_get(&st, "login:bank").unwrap(), b"vault-blob");
        vault_store_delete(&mut st, "login:bank").unwrap();
        assert_eq!(
            vault_store_get(&st, "login:bank"),
            Err(VaultStoreError::NotFound)
        );
    }

    #[test]
    fn tampered_slot_returns_storage_error() {
        let flag = alloc::rc::Rc::new(core::cell::Cell::new(false));
        let backend = CorruptSlotReads {
            inner: MockFlashBackend::new(),
            target: String::from("vault/k"),
            corrupt: flag.clone(),
        };
        let mut st = SecureStorage::new(backend, &[0x55u8; 32], &[0xAAu8; 32]);
        let cfg = DeviceConfig::default();
        vault_store_put(&mut st, &cfg, "k", b"secret").unwrap();
        flag.set(true);
        // Tampered envelope fails authenticated decrypt.
        assert_eq!(vault_store_get(&st, "k"), Err(VaultStoreError::Storage));
        // Overwrite readback also fails closed (mirrors oath_store `?` path:
        // intact envelope stays, no silent partial state).
        assert_eq!(
            vault_store_put(&mut st, &cfg, "k", b"secret2"),
            Err(VaultStoreError::Storage)
        );
        flag.set(false);
        assert_eq!(vault_store_get(&st, "k").unwrap(), b"secret2");
        // Slot recovers with a fresh put.
        vault_store_put(&mut st, &cfg, "k", b"secret3").unwrap();
        assert_eq!(vault_store_get(&st, "k").unwrap(), b"secret3");
    }

    #[test]
    fn rejects_bad_label() {
        let mut st = test_storage();
        let cfg = DeviceConfig::default();
        assert_eq!(
            vault_store_put(&mut st, &cfg, "", b"x"),
            Err(VaultStoreError::BadLabel)
        );
        let big = String::from_utf8(vec![0x78u8; MAX_LABEL_BYTES + 1]).unwrap();
        assert_eq!(
            vault_store_put(&mut st, &cfg, &big, b"x"),
            Err(VaultStoreError::BadLabel)
        );
        assert_eq!(
            vault_store_put(&mut st, &cfg, "index", b"x"),
            Err(VaultStoreError::BadLabel)
        );
        assert_eq!(vault_store_get(&st, ""), Err(VaultStoreError::BadLabel));
        assert_eq!(
            vault_store_delete(&mut st, ""),
            Err(VaultStoreError::BadLabel)
        );
    }

    #[test]
    fn rejects_blob_over_512() {
        let mut st = test_storage();
        let cfg = DeviceConfig::default();
        let huge = vec![0x41u8; VAULT_STORE_MAX_BYTES + 1];
        assert_eq!(
            vault_store_put(&mut st, &cfg, "a", &huge),
            Err(VaultStoreError::TooLarge)
        );
        assert_eq!(vault_store_get(&st, "a"), Err(VaultStoreError::NotFound));
    }

    #[test]
    fn quota_exceeded_with_small_cfg() {
        let mut st = test_storage();
        let cfg = small_cfg();
        vault_store_put(&mut st, &cfg, "a", b"one").unwrap();
        assert_eq!(
            vault_store_put(&mut st, &cfg, "b", b"two"),
            Err(VaultStoreError::QuotaExceeded)
        );
        // Failed put stored nothing.
        assert_eq!(vault_store_get(&st, "b"), Err(VaultStoreError::NotFound));
        // Overwrite within quota is allowed.
        vault_store_put(&mut st, &cfg, "a", b"uno").unwrap();
        assert_eq!(vault_store_get(&st, "a").unwrap(), b"uno");
    }

    #[test]
    fn delete_absent_is_notfound() {
        let mut st = test_storage();
        assert_eq!(
            vault_store_delete(&mut st, "nope"),
            Err(VaultStoreError::NotFound)
        );
    }

    #[test]
    fn index_consistent_after_overwrite_and_delete() {
        let mut st = test_storage();
        let cfg = small_cfg();
        vault_store_put(&mut st, &cfg, "a", b"v1").unwrap();
        vault_store_put(&mut st, &cfg, "a", b"v2").unwrap();
        // Overwrite did not consume a second quota slot.
        assert_eq!(
            vault_store_put(&mut st, &cfg, "b", b"other"),
            Err(VaultStoreError::QuotaExceeded)
        );
        assert_eq!(vault_store_get(&st, "a").unwrap(), b"v2");
        // Delete frees the quota slot.
        vault_store_delete(&mut st, "a").unwrap();
        vault_store_put(&mut st, &cfg, "b", b"other").unwrap();
        assert_eq!(vault_store_get(&st, "b").unwrap(), b"other");
    }

    /// Backend that ack-drops `vault/index` writes (torn write: acknowledged
    /// but lost). Forces `save_index` verify-after-write mismatch without
    /// touching data slots.
    #[derive(Clone)]
    struct DropIndexWrites {
        inner: MockFlashBackend,
        target: String,
        drop: alloc::rc::Rc<core::cell::Cell<bool>>,
    }

    impl FlashStorageBackend for DropIndexWrites {
        fn read_raw(&self, key: &str) -> Result<Vec<u8>, StorageError> {
            self.inner.read_raw(key)
        }
        fn write_raw(&mut self, key: &str, data: &[u8]) -> Result<(), StorageError> {
            if self.drop.get() && key == self.target {
                return Ok(());
            }
            self.inner.write_raw(key, data)
        }
        fn delete_raw(&mut self, key: &str) -> Result<(), StorageError> {
            self.inner.delete_raw(key)
        }
        fn exists(&self, key: &str) -> bool {
            self.inner.exists(key)
        }
    }

    #[test]
    fn corrupt_index_fails_closed_on_put_get_delete() {
        let mut st = test_storage();
        let cfg = DeviceConfig::default();
        vault_store_put(&mut st, &cfg, "a", b"one").unwrap();
        // Garbage quota plaintext (valid envelope, invalid CBOR): corrupt index.
        st.store(VAULT_INDEX_KEY, b"\xff\xfe not-cbor", &IGNORED_NONCE)
            .unwrap();
        assert_eq!(
            vault_store_put(&mut st, &cfg, "b", b"two"),
            Err(VaultStoreError::Storage)
        );
        // Fail-closed: with a corrupt index even reads report Storage.
        assert_eq!(vault_store_get(&st, "b"), Err(VaultStoreError::Storage));
        assert_eq!(vault_store_get(&st, "a"), Err(VaultStoreError::Storage));
        assert_eq!(
            vault_store_delete(&mut st, "a"),
            Err(VaultStoreError::Storage)
        );
    }

    #[test]
    fn index_verify_failure_keeps_index_and_rolls_back_slot() {
        let drop = alloc::rc::Rc::new(core::cell::Cell::new(false));
        let backend = DropIndexWrites {
            inner: MockFlashBackend::new(),
            target: String::from(VAULT_INDEX_KEY),
            drop: drop.clone(),
        };
        let mut st = SecureStorage::new(backend, &[0x55u8; 32], &[0xAAu8; 32]);
        let cfg = DeviceConfig::new(50, 512, 4, 8, 3, 32, 64, 2).expect("m2 cfg valid");
        vault_store_put(&mut st, &cfg, "a", b"one").unwrap();
        drop.set(true);
        // Torn index write => verify mismatch => Storage, data slot rolled back.
        assert_eq!(
            vault_store_put(&mut st, &cfg, "b", b"two"),
            Err(VaultStoreError::Storage)
        );
        assert_eq!(vault_store_get(&st, "b"), Err(VaultStoreError::NotFound));
        // Fail-closed: the quota index is never deleted on verify failure.
        assert!(st.exists(VAULT_INDEX_KEY));
        assert_eq!(vault_store_get(&st, "a").unwrap(), b"one");
        drop.set(false);
        // Quota intact: delete frees, re-put heals.
        vault_store_delete(&mut st, "a").unwrap();
        vault_store_put(&mut st, &cfg, "b", b"two").unwrap();
        assert_eq!(vault_store_get(&st, "b").unwrap(), b"two");
    }
}
