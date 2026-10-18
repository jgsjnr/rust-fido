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

pub mod aegn_v1_to_v2;

pub use aegn_v1_to_v2::{
    is_migrated, migrate_v1_to_v2, MigrationError, MigrationReport,
    MIGRATION_VERSION_KEY, MIGRATION_VERSION_V1, MIGRATION_VERSION_V2,
};
