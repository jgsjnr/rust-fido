//! Wave3 P3 — integration `migration_tests` (dual-slot + backup + rollback).
//!
//! Uses public `SecureStorage` + `migrations` API only (no private access).
//! Envelope v1 preserved: asserts legacy bytes still readable after migrate.

use aegis_fido_firmware::migrations::{is_migrated, migrate_v1_to_v2};
use aegis_fido_firmware::persistence::{MockFlashBackend, SecureStorage};

fn storage() -> SecureStorage<MockFlashBackend> {
    SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
}

#[test]
fn migrates_dual_slot_with_backup() {
    let mut st = storage();
    let nonce = [0u8; 12];
    st.store("credential_01", b"cred-bytes", &nonce).unwrap();
    let rep = migrate_v1_to_v2(&mut st, &["credential_01"]).unwrap();
    assert_eq!(rep.migrated, 1);
    assert!(is_migrated(&st));
    assert_eq!(st.load("cred_slot_a/credential_01").unwrap(), b"cred-bytes");
    assert_eq!(st.load("cred_slot_b/credential_01").unwrap(), b"cred-bytes");
    assert_eq!(st.load("cred_backup/credential_01").unwrap(), b"cred-bytes");
    // Legacy preserved (rollback source).
    assert_eq!(st.load("credential_01").unwrap(), b"cred-bytes");
}

#[test]
fn idempotent_second_run() {
    let mut st = storage();
    let nonce = [0u8; 12];
    st.store("credential_01", b"x", &nonce).unwrap();
    migrate_v1_to_v2(&mut st, &["credential_01"]).unwrap();
    let rep2 = migrate_v1_to_v2(&mut st, &["credential_01"]).unwrap();
    assert!(rep2.already_migrated);
}

#[test]
fn skips_missing_keys() {
    let mut st = storage();
    let rep = migrate_v1_to_v2(&mut st, &["no_such_key"]).unwrap();
    assert_eq!(rep.migrated, 0);
    assert!(is_migrated(&st));
}
