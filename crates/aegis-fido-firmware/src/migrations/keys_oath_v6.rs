//! Fase6 - `keys_oath_v6`: migracao NVS aditiva Keys/OATH sobre BLE (apendice 9).
//!
//! - Aditiva: nunca apaga chaves legado; copia para `keys6/` + `oath6/`
//!   com verify-after-write (readback compare), igual `aegn_v1_to_v2`.
//! - Idempotente: second run retorna `already_migrated` sem tocar slots.
//! - Versao: `aegn_migration_keys6 = [0x06]` (namespaces `keys6/`, `oath6/`).
//! - Bounds: label 1..32B utf8 (§9.2/§9.3), TLV total <=512B (§9.3, via envelope).
//! - Zeroize apos uso; sem nova cripto (reusa `SecureStorage::store/load`).
//! - MAX-ESP: roda uma vez no boot/fabrica, fora do hot path USB/CTAP.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use zeroize::Zeroize;

use crate::persistence::{FlashStorageBackend, SecureStorage};

use super::aegn_v1_to_v2::MigrationError;

/// NVS key com layout version Fase6 (`[0x06]` cifrado).
pub const MIGRATION_KEYS6_VERSION_KEY: &str = "aegn_migration_keys6";
/// Layout version Fase6.
pub const MIGRATION_KEYS6_VERSION: u8 = 0x06;
/// Prefixo NVS dos metadados de chave (§9.2 tags 0x01-0x04, sem privada).
pub const KEYS6_PREFIX: &str = "keys6/";
/// Prefixo NVS dos metadados OATH (§9.2 tags 0x71..., sem secret).
pub const OATH6_PREFIX: &str = "oath6/";
/// Bounds do label compartilhado (§9.2/§9.3 1..32B utf8).
pub const MAX_KEYS6_LABEL_BYTES: usize = 32;
pub const MIN_KEYS6_LABEL_BYTES: usize = 1;
/// Limites de slots (§9.3 MAX_CREDENTIALS=64; keys<=32 para envelope 512B).
pub const MAX_KEYS6_SLOTS: usize = 32;
pub const MAX_OATH6_SLOTS: usize = 64;
/// Nonce placeholder (ignorado, TRNG dentro de `store`).
const IGNORED_NONCE: [u8; 12] = [0u8; 12];

/// Resultado da migracao Fase6 (idempotente).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysOathV6Report {
    /// Chaves legado copiadas para `keys6/`.
    pub migrated_keys: usize,
    /// Entradas OATH copiadas para `oath6/`.
    pub migrated_oath: usize,
    /// True quando nenhum trabalho foi necessario (ja v6).
    pub already_migrated: bool,
}

/// True quando layout ja e v6 (check de idempotencia).
pub fn is_migrated_v6<B: FlashStorageBackend>(storage: &SecureStorage<B>) -> bool {
    if let Ok(v) = storage.load(MIGRATION_KEYS6_VERSION_KEY) {
        return v.first().copied() == Some(MIGRATION_KEYS6_VERSION);
    }
    false
}

/// Valida label §9 (1..32B). Erro vira `VerifyFailed` (mapeia a BAD_ENVELOPE §9.5).
pub fn validate_v6_label(label: &str) -> Result<(), MigrationError> {
    let n = label.len();
    if !(MIN_KEYS6_LABEL_BYTES..=MAX_KEYS6_LABEL_BYTES).contains(&n) {
        return Err(MigrationError::VerifyFailed);
    }
    Ok(())
}

/// Chave NVS `keys6/<name>`.
pub fn keys6_key(name: &str) -> String {
    let mut s = String::from(KEYS6_PREFIX);
    s.push_str(name);
    s
}

/// Chave NVS `oath6/<name>`.
pub fn oath6_key(name: &str) -> String {
    let mut s = String::from(OATH6_PREFIX);
    s.push_str(name);
    s
}

/// Migra chaves legado para `keys6/` + `oath6/` (aditiva, com rollback).
/// Nunca apaga legado; em falha limpa slots parciais e mantem legado legivel.
pub fn migrate_keys_oath_v6<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    legacy_keys: &[&str],
    legacy_oath: &[&str],
) -> Result<KeysOathV6Report, MigrationError> {
    if is_migrated_v6(storage) {
        return Ok(KeysOathV6Report {
            migrated_keys: 0,
            migrated_oath: 0,
            already_migrated: true,
        });
    }
    if legacy_keys.len() > MAX_KEYS6_SLOTS || legacy_oath.len() > MAX_OATH6_SLOTS {
        return Err(MigrationError::VerifyFailed);
    }
    let mut done_keys: Vec<String> = Vec::new();
    let mut done_oath: Vec<String> = Vec::new();
    for key in legacy_keys {
        if !storage.exists(key) {
            continue;
        }
        let slot = keys6_key(key);
        if migrate_one(storage, key, &slot).is_err() {
            cleanup_slots(storage, &done_keys);
            cleanup_slots(storage, &done_oath);
            return Err(MigrationError::LegacyUnreadable);
        }
        done_keys.push(String::from(*key));
    }
    for key in legacy_oath {
        if !storage.exists(key) {
            continue;
        }
        let slot = oath6_key(key);
        if migrate_one(storage, key, &slot).is_err() {
            cleanup_slots(storage, &done_keys);
            cleanup_slots(storage, &done_oath);
            let _ = storage.delete(&slot);
            return Err(MigrationError::LegacyUnreadable);
        }
        done_oath.push(String::from(*key));
    }
    storage
        .store(MIGRATION_KEYS6_VERSION_KEY, &[MIGRATION_KEYS6_VERSION], &IGNORED_NONCE)
        .map_err(MigrationError::Storage)?;
    let back = storage
        .load(MIGRATION_KEYS6_VERSION_KEY)
        .map_err(MigrationError::Storage)?;
    if back.first().copied() != Some(MIGRATION_KEYS6_VERSION) {
        cleanup_slots(storage, &done_keys);
        cleanup_slots(storage, &done_oath);
        return Err(MigrationError::VerifyFailed);
    }
    Ok(KeysOathV6Report {
        migrated_keys: done_keys.len(),
        migrated_oath: done_oath.len(),
        already_migrated: false,
    })
}

/// Copia um legado para o slot com verify-after-write + zeroize do plain.
fn migrate_one<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    legacy: &str,
    slot: &str,
) -> Result<(), MigrationError> {
    let mut plain = storage
        .load(legacy)
        .map_err(|_| MigrationError::LegacyUnreadable)?;
    let res = (|| -> Result<(), MigrationError> {
        storage
            .store(slot, &plain, &IGNORED_NONCE)
            .map_err(MigrationError::Storage)?;
        let back = storage.load(slot).map_err(MigrationError::Storage)?;
        if back != plain {
            return Err(MigrationError::VerifyFailed);
        }
        Ok(())
    })();
    plain.zeroize();
    res
}

/// Apaga slots parciais; legado intacto (rollback).
fn cleanup_slots<B: FlashStorageBackend>(storage: &mut SecureStorage<B>, done: &[String]) {
    for key in done {
        let _ = storage.delete(&keys6_key(key));
        let _ = storage.delete(&oath6_key(key));
    }
    let _ = storage.delete(MIGRATION_KEYS6_VERSION_KEY);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    #[test]
    fn v6_label_bounds() {
        assert!(validate_v6_label("a").is_ok());
        assert!(validate_v6_label("GitHub:alice").is_ok());
        assert!(validate_v6_label("").is_err());
        let big = alloc::string::String::from_utf8(vec![0x78u8; MAX_KEYS6_LABEL_BYTES + 1]).unwrap();
        assert!(validate_v6_label(&big).is_err());
        assert_eq!(keys6_key("k1"), "keys6/k1");
        assert_eq!(oath6_key("a1"), "oath6/a1");
        assert_eq!(MIGRATION_KEYS6_VERSION, 0x06);
        assert_eq!(MIGRATION_KEYS6_VERSION_KEY, "aegn_migration_keys6");
    }

    #[test]
    fn migrates_keys_and_oath_with_verify() {
        let mut st = test_storage();
        st.store("cred1", b"key-bytes", &IGNORED_NONCE).unwrap();
        st.store("oath1", b"oath-bytes", &IGNORED_NONCE).unwrap();
        let rep = migrate_keys_oath_v6(&mut st, &["cred1"], &["oath1"]).unwrap();
        assert_eq!(rep.migrated_keys, 1);
        assert_eq!(rep.migrated_oath, 1);
        assert!(!rep.already_migrated);
        assert!(is_migrated_v6(&st));
        assert_eq!(st.load(&keys6_key("cred1")).unwrap(), b"key-bytes");
        assert_eq!(st.load(&oath6_key("oath1")).unwrap(), b"oath-bytes");
        assert_eq!(st.load("cred1").unwrap(), b"key-bytes");
        assert_eq!(st.load("oath1").unwrap(), b"oath-bytes");
    }

    #[test]
    fn second_run_is_idempotent() {
        let mut st = test_storage();
        st.store("k", b"v", &IGNORED_NONCE).unwrap();
        migrate_keys_oath_v6(&mut st, &["k"], &[]).unwrap();
        let rep2 = migrate_keys_oath_v6(&mut st, &["k"], &[]).unwrap();
        assert!(rep2.already_migrated);
        assert_eq!(rep2.migrated_keys, 0);
    }

    #[test]
    fn rejects_over_slot_bounds() {
        let mut st = test_storage();
        let many: Vec<&str> = vec![];
        let _ = many;
        let too_many_keys = ["k"; MAX_KEYS6_SLOTS + 1];
        assert!(migrate_keys_oath_v6(&mut st, &too_many_keys, &[]).is_err());
        assert!(!is_migrated_v6(&st));
    }
}