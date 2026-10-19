//! Wave3 P3 — migrations root (dual-slot + backup, idempotent).
// AUDIT-PREP: wiring na Wave4
//!
//! Layout version (`aegn_migration_version`):
//! - `1` = legacy single-slot (`credential_01`, `pin_hash`, ...)
//! - `2` = dual-slot A/B + backup (`cred_slot_a/*`, `cred_slot_b/*`, `cred_backup/*`)
//!
//! Envelope AEGN v1 bytes preserved (G0): migration never re-encodes
//! envelopes by hand; it reuses `SecureStorage::store/load` (TRNG nonce,
//! verify-after-write). Rollback keeps legacy keys intact until verified.
//!
//! Fase6 — `keys_oath_v6` (aditivo, apendice 9):
//! - version `aegn_migration_keys6 = [0x06]`, namespaces `keys6/` + `oath6/`
//! - bounds label 1..32B, TLV total <=512B; zeroize apos uso; sem nova cripto.

pub mod aegn_v1_to_v2;
pub mod keys_oath_v6;
pub mod vault_v7;

pub use aegn_v1_to_v2::{
    is_migrated, migrate_v1_to_v2, MigrationError, MigrationReport,
    MIGRATION_VERSION_KEY, MIGRATION_VERSION_V1, MIGRATION_VERSION_V2,
};

pub use keys_oath_v6::{
    is_migrated_v6, keys6_key, migrate_keys_oath_v6, oath6_key, validate_v6_label,
    KeysOathV6Report, KEYS6_PREFIX, MAX_KEYS6_LABEL_BYTES, MAX_KEYS6_SLOTS, MAX_OATH6_SLOTS,
    MIGRATION_KEYS6_VERSION, MIGRATION_KEYS6_VERSION_KEY, MIN_KEYS6_LABEL_BYTES, OATH6_PREFIX,
};

pub use vault_v7::{
    is_migrated_v7, migrate_vault_v7, VaultV7Report, MIGRATION_VAULT_V7_KEY,
    MIGRATION_VAULT_V7_VERSION, VAULT_A_PREFIX, VAULT_B_PREFIX, VAULT_BACKUP_PREFIX,
    VAULT_LIVE_PREFIX,
};