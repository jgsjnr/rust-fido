//! Wave3 P3 — `aegn_v1_to_v2`: idempotent dual-slot + backup migration.
//!
//! - Idempotente: second run returns `AlreadyMigrated` without touching slots.
//! - Dual-slot + backup: each legacy key is copied to `slot_a`, `slot_b`,
//!   and `backup`, each with verify-after-write (readback compare).
//! - Rollback: legacy keys are never deleted; on failure partial slot writes
//!   are cleaned and legacy data stays readable (emulator-tested).
//! - Envelope v1 preserved: uses `SecureStorage` API only, no byte changes.
//! - MAX-ESP: migration runs once at boot/factory, not in USB hot path.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::persistence::{FlashStorageBackend, SecureStorage, StorageError};

/// NVS key holding layout version (`[0x01]` or `[0x02]` encrypted).
pub const MIGRATION_VERSION_KEY: &str = "aegn_migration_version";
/// Legacy layout version.
pub const MIGRATION_VERSION_V1: u8 = 0x01;
/// Dual-slot layout version.
pub const MIGRATION_VERSION_V2: u8 = 0x02;
/// Slot A prefix (active).
pub const SLOT_A_PREFIX: &str = "cred_slot_a/";
/// Slot B prefix (standby).
pub const SLOT_B_PREFIX: &str = "cred_slot_b/";
/// Backup prefix (rollback source).
pub const BACKUP_PREFIX: &str = "cred_backup/";
/// Fixed nonce placeholder (ignored, TRNG inside `store`).
const IGNORED_NONCE: [u8; 12] = [0u8; 12];

/// Migration failure (typed, preserves legacy on error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationError {
    /// Underlying storage failure.
    Storage(StorageError),
    /// Verify-after-write mismatch.
    VerifyFailed,
    /// Legacy key unreadable (corrupted envelope).
    LegacyUnreadable,
}

impl From<StorageError> for MigrationError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}

impl core::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage: {:?}", e),
            Self::VerifyFailed => write!(f, "verify-after-write failed"),
            Self::LegacyUnreadable => write!(f, "legacy key unreadable"),
        }
    }
}

/// Migration outcome (idempotent marker included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// Number of legacy keys copied to slots.
    pub migrated: usize,
    /// True when no work was needed (already v2).
    pub already_migrated: bool,
}

/// Returns true when layout is already v2 (idempotence check).
pub fn is_migrated<B: FlashStorageBackend>(storage: &SecureStorage<B>) -> bool {
    if let Ok(v) = storage.load(MIGRATION_VERSION_KEY) {
        return v.first().copied() == Some(MIGRATION_VERSION_V2);
    }
    false
}

/// Migrates legacy single-slot keys to dual-slot + backup.
/// Never deletes legacy keys (rollback = legacy stays readable).
pub fn migrate_v1_to_v2<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    legacy_keys: &[&str],
) -> Result<MigrationReport, MigrationError> {
    if is_migrated(storage) {
        return Ok(MigrationReport {
            migrated: 0,
            already_migrated: true,
        });
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
            return res.map(|_| MigrationReport {
                migrated: 0,
                already_migrated: false,
            });
        }
        done.push(String::from(*key));
    }
    storage
        .store(MIGRATION_VERSION_KEY, &[MIGRATION_VERSION_V2], &IGNORED_NONCE)
        .map_err(MigrationError::Storage)?;
    let back = storage
        .load(MIGRATION_VERSION_KEY)
        .map_err(MigrationError::Storage)?;
    if back.first().copied() != Some(MIGRATION_VERSION_V2) {
        cleanup_partial(storage, &done);
        return Err(MigrationError::VerifyFailed);
    }
    Ok(MigrationReport {
        migrated: done.len(),
        already_migrated: false,
    })
}

/// Copies one legacy key to A/B/backup with verify-after-write.
fn migrate_one<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    key: &str,
) -> Result<(), MigrationError> {
    let plain = storage
        .load(key)
        .map_err(|_| MigrationError::LegacyUnreadable)?;
    let slots = [
        slot_key(SLOT_A_PREFIX, key),
        slot_key(SLOT_B_PREFIX, key),
        slot_key(BACKUP_PREFIX, key),
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

/// Deletes the 3 slots of one key; legacy key untouched (rollback).
fn cleanup_single<B: FlashStorageBackend>(storage: &mut SecureStorage<B>, key: &str) {
    for prefix in [SLOT_A_PREFIX, SLOT_B_PREFIX, BACKUP_PREFIX] {
        let slot = slot_key(prefix, key);
        let _ = storage.delete(&slot);
    }
}

/// Deletes partial slot writes; legacy keys untouched (rollback).
fn cleanup_partial<B: FlashStorageBackend>(storage: &mut SecureStorage<B>, done: &[String]) {
    for key in done {
        cleanup_single(storage, key);
    }
    let _ = storage.delete(MIGRATION_VERSION_KEY);
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
    fn migrates_and_verifies_slots() {
        let mut st = test_storage();
        st.store("credential_01", b"cred-bytes", &IGNORED_NONCE).unwrap();
        st.store("pin_hash", b"pin-bytes", &IGNORED_NONCE).unwrap();
        let rep = migrate_v1_to_v2(&mut st, &["credential_01", "pin_hash"]).unwrap();
        assert_eq!(rep.migrated, 2);
        assert!(!rep.already_migrated);
        assert!(is_migrated(&st));
        assert_eq!(st.load("cred_slot_a/credential_01").unwrap(), b"cred-bytes");
        assert_eq!(st.load("cred_slot_b/credential_01").unwrap(), b"cred-bytes");
        assert_eq!(st.load("cred_backup/credential_01").unwrap(), b"cred-bytes");
        assert_eq!(st.load("credential_01").unwrap(), b"cred-bytes");
    }

    #[test]
    fn second_run_is_idempotent() {
        let mut st = test_storage();
        st.store("credential_01", b"x", &IGNORED_NONCE).unwrap();
        migrate_v1_to_v2(&mut st, &["credential_01"]).unwrap();
        let rep2 = migrate_v1_to_v2(&mut st, &["credential_01"]).unwrap();
        assert!(rep2.already_migrated);
        assert_eq!(rep2.migrated, 0);
    }

    /// Backend that corrupts one legacy key on read (emulates torn envelope).
    struct CorruptOnRead {
        inner: MockFlashBackend,
        corrupt_key: String,
    }

    impl FlashStorageBackend for CorruptOnRead {
        fn read_raw(&self, key: &str) -> Result<Vec<u8>, StorageError> {
            if key == self.corrupt_key {
                return Err(StorageError::CorruptedEnvelope);
            }
            self.inner.read_raw(key)
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
    fn corrupt_legacy_rolls_back() {
        let inner = MockFlashBackend::new();
        let corrupt = CorruptOnRead {
            inner,
            corrupt_key: String::from("pin_hash"),
        };
        let mut st = SecureStorage::new(corrupt, &[0x55u8; 32], &[0xAAu8; 32]);
        st.store("credential_01", b"good", &IGNORED_NONCE).unwrap();
        st.store("pin_hash", b"good2", &IGNORED_NONCE).unwrap();
        let res = migrate_v1_to_v2(&mut st, &["credential_01", "pin_hash"]);
        assert!(res.is_err());
        assert!(!is_migrated(&st));
        assert_eq!(st.load("credential_01").unwrap(), b"good");
    }

    /// Backend that fails writes to one slot key (emulates torn write).
    struct FailOnSlot {
        inner: MockFlashBackend,
        fail_key: String,
    }

    impl FlashStorageBackend for FailOnSlot {
        fn read_raw(&self, key: &str) -> Result<Vec<u8>, StorageError> {
            self.inner.read_raw(key)
        }
        fn write_raw(&mut self, key: &str, data: &[u8]) -> Result<(), StorageError> {
            if key == self.fail_key {
                return Err(StorageError::FlashWriteError);
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
    fn failure_on_second_slot_leaves_zero_residual() {
        let failing = FailOnSlot {
            inner: MockFlashBackend::new(),
            fail_key: String::from("cred_slot_b/k2"),
        };
        let mut st = SecureStorage::new(failing, &[0x55u8; 32], &[0xAAu8; 32]);
        st.store("k1", b"one", &IGNORED_NONCE).unwrap();
        st.store("k2", b"two", &IGNORED_NONCE).unwrap();
        let res = migrate_v1_to_v2(&mut st, &["k1", "k2"]);
        assert!(res.is_err());
        assert!(!is_migrated(&st));
        for prefix in [SLOT_A_PREFIX, SLOT_B_PREFIX, BACKUP_PREFIX] {
            assert!(!st.exists(&slot_key(prefix, "k2")));
            assert!(!st.exists(&slot_key(prefix, "k1")));
        }
        assert!(!st.exists(MIGRATION_VERSION_KEY));
        assert_eq!(st.load("k1").unwrap(), b"one");
        assert_eq!(st.load("k2").unwrap(), b"two");
    }
}
