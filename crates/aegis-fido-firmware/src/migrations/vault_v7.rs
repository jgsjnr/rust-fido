//! Vault v7 — idempotent per-item migration to live + A/B/backup.
//!
//! - Idempotent: second run returns `already_migrated` without touching slots.
//! - Per-item slots (B2): each legacy key is copied to live `vault/`,
//!   `vault_a/`, `vault_b/`, and `vault_backup/`, each with
//!   verify-after-write (readback compare).
//! - Rollback: legacy keys are never deleted; on failure partial new-slot
//!   writes are cleaned and legacy data stays readable.
//! - Version marker `aegn_vault_v7 = [0x07]` set only after full verify.
//! - Reuses `SecureStorage` API only, no new crypto, alloc only.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::persistence::{FlashStorageBackend, SecureStorage, StorageError};
use crate::vault_store::{validate_vault_label, vault_index_union_add};

use super::aegn_v1_to_v2::MigrationError;

/// NVS key holding vault layout version (`[0x07]` encrypted).
pub const MIGRATION_VAULT_V7_KEY: &str = "aegn_vault_v7";
/// Vault layout version.
pub const MIGRATION_VAULT_V7_VERSION: u8 = 0x07;
/// Live prefix.
pub const VAULT_LIVE_PREFIX: &str = "vault/";
/// Copy A prefix.
pub const VAULT_A_PREFIX: &str = "vault_a/";
/// Copy B prefix.
pub const VAULT_B_PREFIX: &str = "vault_b/";
/// Backup prefix.
pub const VAULT_BACKUP_PREFIX: &str = "vault_backup/";
/// Fixed nonce placeholder (ignored, TRNG inside `store`).
const IGNORED_NONCE: [u8; 12] = [0u8; 12];

/// Vault v7 migration outcome (idempotent marker included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultV7Report {
    /// Number of legacy keys copied to vault slots.
    pub migrated: usize,
    /// True when no work was needed (already v7).
    pub already_migrated: bool,
}

/// Returns true when layout is already v7 (idempotence check).
pub fn is_migrated_v7<B: FlashStorageBackend>(storage: &SecureStorage<B>) -> bool {
    if let Ok(v) = storage.load(MIGRATION_VAULT_V7_KEY) {
        return v.first().copied() == Some(MIGRATION_VAULT_V7_VERSION);
    }
    false
}

/// Migrates explicit legacy keys to live `vault/` + A/B/backup copies.
/// Never deletes legacy keys (rollback = legacy stays readable).
///
/// Validate-upfront-before-any-write: every legacy key must be a valid vault
/// label (rejects the reserved `index` label and bad lengths) or the whole
/// migration fails without writing anything. After all copies verify, the
/// quota index is rebuilt as the union of the existing index and migrated
/// labels (no truncation: it may exceed `max_vault_slots`, future puts then
/// fail closed with `QuotaExceeded` until deletes).
pub fn migrate_vault_v7<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    legacy_keys: &[&str],
) -> Result<VaultV7Report, MigrationError> {
    if is_migrated_v7(storage) {
        return Ok(VaultV7Report {
            migrated: 0,
            already_migrated: true,
        });
    }
    for key in legacy_keys {
        validate_vault_label(key).map_err(|_| MigrationError::LegacyUnreadable)?;
    }
    let mut done: Vec<String> = Vec::new();
    for key in legacy_keys {
        if !storage.exists(key) {
            continue;
        }
        let res = migrate_one(storage, key);
        if res.is_err() {
            cleanup_single(storage, key);
            cleanup_partial(storage, &done);
            return res.map(|_| VaultV7Report {
                migrated: 0,
                already_migrated: false,
            });
        }
        done.push(String::from(*key));
    }
    if !done.is_empty() {
        if let Err(e) = vault_index_union_add(storage, &done) {
            cleanup_partial(storage, &done);
            return Err(match e {
                crate::vault_store::VaultStoreError::BadLabel => {
                    MigrationError::LegacyUnreadable
                }
                _ => MigrationError::Storage(StorageError::FlashWriteError),
            });
        }
    }
    storage
        .store(
            MIGRATION_VAULT_V7_KEY,
            &[MIGRATION_VAULT_V7_VERSION],
            &IGNORED_NONCE,
        )
        .map_err(MigrationError::Storage)?;
    let back = storage
        .load(MIGRATION_VAULT_V7_KEY)
        .map_err(MigrationError::Storage)?;
    if back.first().copied() != Some(MIGRATION_VAULT_V7_VERSION) {
        cleanup_partial(storage, &done);
        return Err(MigrationError::VerifyFailed);
    }
    Ok(VaultV7Report {
        migrated: done.len(),
        already_migrated: false,
    })
}

/// Copies one legacy key to live + A/B/backup with verify-after-write.
fn migrate_one<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    key: &str,
) -> Result<(), MigrationError> {
    let plain = storage
        .load(key)
        .map_err(|_| MigrationError::LegacyUnreadable)?;
    let slots = [
        slot_key(VAULT_LIVE_PREFIX, key),
        slot_key(VAULT_A_PREFIX, key),
        slot_key(VAULT_B_PREFIX, key),
        slot_key(VAULT_BACKUP_PREFIX, key),
    ];
    for slot in &slots {
        storage
            .store(slot, &plain, &IGNORED_NONCE)
            .map_err(MigrationError::Storage)?;
        verify_after_write(storage, slot, &plain)?;
    }
    Ok(())
}

/// Reads back and compares (verify-after-write).
fn verify_after_write<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    slot: &str,
    expected: &[u8],
) -> Result<(), MigrationError> {
    let back = storage.load(slot).map_err(MigrationError::Storage)?;
    if back != expected {
        return Err(MigrationError::VerifyFailed);
    }
    Ok(())
}

/// Deletes the 4 slots of one key; legacy key untouched (rollback).
fn cleanup_single<B: FlashStorageBackend>(storage: &mut SecureStorage<B>, key: &str) {
    for prefix in [
        VAULT_LIVE_PREFIX,
        VAULT_A_PREFIX,
        VAULT_B_PREFIX,
        VAULT_BACKUP_PREFIX,
    ] {
        let slot = slot_key(prefix, key);
        let _ = storage.delete(&slot);
    }
}

/// Deletes partial slot writes; legacy keys untouched (rollback).
fn cleanup_partial<B: FlashStorageBackend>(storage: &mut SecureStorage<B>, done: &[String]) {
    for key in done {
        cleanup_single(storage, key);
    }
    let _ = storage.delete(MIGRATION_VAULT_V7_KEY);
}

/// Builds `prefix + key` slot name.
fn slot_key(prefix: &str, key: &str) -> String {
    let mut s = String::from(prefix);
    s.push_str(key);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    #[test]
    fn migrates_two_keys_to_all_namespaces_with_marker() {
        let mut st = test_storage();
        st.store("legacy1", b"secret-one", &IGNORED_NONCE).unwrap();
        st.store("legacy2", b"secret-two", &IGNORED_NONCE).unwrap();
        let rep = migrate_vault_v7(&mut st, &["legacy1", "legacy2"]).unwrap();
        assert_eq!(rep.migrated, 2);
        assert!(!rep.already_migrated);
        assert!(is_migrated_v7(&st));
        for key in ["legacy1", "legacy2"] {
            let expected: &[u8] = if key == "legacy1" { b"secret-one" } else { b"secret-two" };
            let mut live = String::from(VAULT_LIVE_PREFIX);
            live.push_str(key);
            let mut a = String::from(VAULT_A_PREFIX);
            a.push_str(key);
            let mut b = String::from(VAULT_B_PREFIX);
            b.push_str(key);
            let mut bak = String::from(VAULT_BACKUP_PREFIX);
            bak.push_str(key);
            assert_eq!(st.load(&live).unwrap(), expected);
            assert_eq!(st.load(&a).unwrap(), expected);
            assert_eq!(st.load(&b).unwrap(), expected);
            assert_eq!(st.load(&bak).unwrap(), expected);
        }
    }

    #[test]
    fn second_run_is_idempotent_untouched() {
        let mut st = test_storage();
        st.store("legacy1", b"secret-one", &IGNORED_NONCE).unwrap();
        migrate_vault_v7(&mut st, &["legacy1"]).unwrap();
        let mut a = String::from(VAULT_A_PREFIX);
        a.push_str("legacy1");
        let before = st.load(&a).unwrap();
        let rep2 = migrate_vault_v7(&mut st, &["legacy1"]).unwrap();
        assert!(rep2.already_migrated);
        assert_eq!(rep2.migrated, 0);
        assert_eq!(st.load(&a).unwrap(), before);
    }

    #[test]
    fn legacy_keys_stay_intact() {
        let mut st = test_storage();
        st.store("legacy1", b"secret-one", &IGNORED_NONCE).unwrap();
        migrate_vault_v7(&mut st, &["legacy1"]).unwrap();
        assert_eq!(st.load("legacy1").unwrap(), b"secret-one");
    }

    #[test]
    fn corrupt_slot_b_keeps_slot_a_live_and_legacy() {
        let mut st = test_storage();
        st.store("legacy1", b"secret-one", &IGNORED_NONCE).unwrap();
        migrate_vault_v7(&mut st, &["legacy1"]).unwrap();
        let mut b = String::from(VAULT_B_PREFIX);
        b.push_str("legacy1");
        // Corrupt copy B post-migrate.
        st.store(&b, b"tampered", &IGNORED_NONCE).unwrap();
        let mut a = String::from(VAULT_A_PREFIX);
        a.push_str("legacy1");
        let mut live = String::from(VAULT_LIVE_PREFIX);
        live.push_str("legacy1");
        assert_eq!(st.load(&a).unwrap(), b"secret-one");
        assert_eq!(st.load(&live).unwrap(), b"secret-one");
        assert_eq!(st.load("legacy1").unwrap(), b"secret-one");
    }

    /// Backend that fails writes to one slot key (emulates torn write).
    struct FailOnSlot {
        inner: MockFlashBackend,
        fail_key: String,
    }

    impl FlashStorageBackend for FailOnSlot {
        fn read_raw(&self, key: &str) -> Result<Vec<u8>, crate::persistence::StorageError> {
            self.inner.read_raw(key)
        }
        fn write_raw(&mut self, key: &str, data: &[u8]) -> Result<(), crate::persistence::StorageError> {
            if key == self.fail_key {
                return Err(crate::persistence::StorageError::FlashWriteError);
            }
            self.inner.write_raw(key, data)
        }
        fn delete_raw(&mut self, key: &str) -> Result<(), crate::persistence::StorageError> {
            self.inner.delete_raw(key)
        }
        fn exists(&self, key: &str) -> bool {
            self.inner.exists(key)
        }
    }

    #[test]
    fn failing_backend_sets_no_marker_and_cleans_partial() {
        let failing = FailOnSlot {
            inner: MockFlashBackend::new(),
            fail_key: String::from("vault_a/k2"),
        };
        let mut st = SecureStorage::new(failing, &[0x55u8; 32], &[0xAAu8; 32]);
        st.store("k1", b"one", &IGNORED_NONCE).unwrap();
        st.store("k2", b"two", &IGNORED_NONCE).unwrap();
        let res = migrate_vault_v7(&mut st, &["k1", "k2"]);
        assert!(res.is_err());
        assert!(!is_migrated_v7(&st));
        assert!(!st.exists(MIGRATION_VAULT_V7_KEY));
        for prefix in [VAULT_LIVE_PREFIX, VAULT_A_PREFIX, VAULT_B_PREFIX, VAULT_BACKUP_PREFIX] {
            let mut s1 = String::from(prefix);
            s1.push_str("k1");
            let mut s2 = String::from(prefix);
            s2.push_str("k2");
            assert!(!st.exists(&s1));
            assert!(!st.exists(&s2));
        }
        assert_eq!(st.load("k1").unwrap(), b"one");
        assert_eq!(st.load("k2").unwrap(), b"two");
    }

    #[test]
    fn rejects_reserved_index_label_without_writing() {
        let mut st = test_storage();
        st.store("credential_01", b"data", &IGNORED_NONCE).unwrap();
        let res = migrate_vault_v7(&mut st, &["credential_01", "index"]);
        assert!(res.is_err());
        assert!(!is_migrated_v7(&st));
        assert!(!st.exists("vault/credential_01"));
        assert!(!st.exists("vault_a/credential_01"));
        assert!(!st.exists("vault/index"));
        assert_eq!(st.load("credential_01").unwrap(), b"data");
    }

    #[test]
    fn rejects_empty_label_without_writing() {
        let mut st = test_storage();
        st.store("k1", b"one", &IGNORED_NONCE).unwrap();
        let res = migrate_vault_v7(&mut st, &["k1", ""]);
        assert!(res.is_err());
        assert!(!is_migrated_v7(&st));
        assert!(!st.exists("vault/k1"));
        assert_eq!(st.load("k1").unwrap(), b"one");
    }

    #[test]
    fn post_migration_quota_counts_migrated_slots() {
        use crate::config::DeviceConfig;
        use crate::vault_store::{vault_store_get, vault_store_put, VaultStoreError};
        let mut st = test_storage();
        st.store("k1", b"one", &IGNORED_NONCE).unwrap();
        let rep = migrate_vault_v7(&mut st, &["k1"]).unwrap();
        assert_eq!(rep.migrated, 1);
        assert_eq!(vault_store_get(&st, "k1").unwrap(), b"one");
        let cfg = DeviceConfig::new(50, 512, 4, 8, 3, 32, 64, 1).expect("quota cfg valid");
        assert_eq!(
            vault_store_put(&mut st, &cfg, "k2", b"two"),
            Err(VaultStoreError::QuotaExceeded)
        );
        assert_eq!(vault_store_get(&st, "k2"), Err(VaultStoreError::NotFound));
    }
}
