//! DEV-ONLY on-device recovery-code cache.
//!
//! # SECURITY DOWNGRADE (confined to `test-mode` by construction)
//!
//! This module persists the last recovery CODE (not just the KEK-wrapped
//! envelope) in a separate plaintext NVS blob. That is an intentional,
//! DEV-only security downgrade: anyone with flash read access recovers the
//! code without brute force. It exists solely to survive DEV/bench reboots,
//! where eFuse provisioning is owner-forbidden and every boot mints fresh
//! ephemeral TRNG device keys.
//!
//! * NEVER enable outside `test-mode`. Release builds use eFuse-provisioned
//!   keys; eFuse burns require an explicit owner ceremony and are untouched
//!   by this module (no reads, no burns, no key-purpose changes — eFuse stays
//!   exactly as-is: ready but never used by this path).
//! * The module is compiled ONLY under `#[cfg(feature = "test-mode")]`
//!   (declared in `lib.rs`). Release builds contain no auto-recovery path:
//!   any release reference to this module is a compile error.
//! * The cached code is written ONLY at provision / rotation / recovery inside
//!   `test-mode` builds, via a separate NVS blob with magic + version + CRC32
//!   (see `DEV_RECOVERY_CODE_BLOB_SIZE`). Firmware persists it outside the
//!   device-key envelope next to `sg_recovery_v1`.
//! * Auto-recovery is a SINGLE attempt on `ErrorLocked` load in `test-mode`
//!   builds only, audit-logged as dev-auto-recovery. A wrong or tampered
//!   cache fails closed to normal `ErrorLocked`: no retry loop.
//! * Never log the code. The caller must zeroize copies after single use.
//!
//! eFuse confirmation (read-only audit): this module performs NO eFuse
//! operation of any kind — no burn, no provision, no `BLOCK7`/key-purpose
//! access. The only eFuse-adjacent symbol in this crate is the pre-existing
//! `DO_NOT_BURN_EFUSE_BLOCK7_WARNING` constant and the software-fallback HMAC
//! anchor, both unchanged.

use super::crypto::crc32;
use super::error::SecureGuardError;
use zeroize::Zeroize;

/// Magic header identifying a DEV recovery-code cache blob: "AEGSGD01".
pub const DEV_RECOVERY_CODE_MAGIC: [u8; 8] = *b"AEGSGD01";
/// Format version of the DEV recovery-code cache blob layout.
pub const DEV_RECOVERY_CODE_VERSION: u16 = 1;
/// Length of a recovery code in bytes.
pub const DEV_RECOVERY_CODE_LEN: usize = 16;
/// Fixed wire size: magic(8) + version(2) + code(16) + crc32(4).
pub const DEV_RECOVERY_CODE_BLOB_SIZE: usize = 30;

/// Typed DEV-only recovery-code cache (in-memory representation).
///
/// The NVS wire form is produced/consumed only via [`Self::to_bytes`] /
/// [`Self::from_bytes`]. Absent cache is reported as `None` by callers,
/// never as zero bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevRecoveryCodeCache {
    code: [u8; 16],
}

impl Drop for DevRecoveryCodeCache {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

impl DevRecoveryCodeCache {
    /// Wraps a raw 16-byte recovery code for DEV-cache persistence.
    pub fn new(code: [u8; 16]) -> Self {
        Self { code }
    }

    /// Returns a copy of the cached code for single-attempt use.
    ///
    /// The caller must zeroize the copy after use.
    pub fn code(&self) -> [u8; 16] {
        self.code
    }

    /// Serializes to the fixed-size NVS wire form with CRC32 integrity.
    pub fn to_bytes(&self) -> [u8; DEV_RECOVERY_CODE_BLOB_SIZE] {
        let mut out = [0u8; DEV_RECOVERY_CODE_BLOB_SIZE];
        out[0..8].copy_from_slice(&DEV_RECOVERY_CODE_MAGIC);
        out[8..10].copy_from_slice(&DEV_RECOVERY_CODE_VERSION.to_be_bytes());
        out[10..26].copy_from_slice(&self.code);
        let crc = crc32(&out[0..26]);
        out[26..30].copy_from_slice(&crc.to_be_bytes());
        out
    }

    /// Deserializes the NVS wire form, failing closed on any structural fault.
    ///
    /// Wrong/tampered blobs surface as `PersistenceCorrupted` so the caller
    /// can fail closed to normal `ErrorLocked` without retrying.
    pub fn from_bytes(bytes: &[u8; DEV_RECOVERY_CODE_BLOB_SIZE]) -> Result<Self, SecureGuardError> {
        let stored_crc = u32::from_be_bytes([bytes[26], bytes[27], bytes[28], bytes[29]]);
        if stored_crc != crc32(&bytes[0..26]) {
            return Err(SecureGuardError::PersistenceCorrupted(
                "dev recovery-code cache CRC32 mismatch",
            ));
        }
        if bytes[0..8] != DEV_RECOVERY_CODE_MAGIC {
            return Err(SecureGuardError::PersistenceCorrupted(
                "dev recovery-code cache invalid magic",
            ));
        }
        let version = u16::from_be_bytes([bytes[8], bytes[9]]);
        if version != DEV_RECOVERY_CODE_VERSION {
            return Err(SecureGuardError::PersistenceCorrupted(
                "dev recovery-code cache unsupported version",
            ));
        }
        let mut code = [0u8; 16];
        code.copy_from_slice(&bytes[10..26]);
        Ok(Self { code })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CODE: [u8; 16] = *b"0123456789abcdef";

    #[test]
    fn test_dev_code_cache_roundtrip() {
        let cache = DevRecoveryCodeCache::new(TEST_CODE);
        let bytes = cache.to_bytes();
        assert_eq!(bytes.len(), DEV_RECOVERY_CODE_BLOB_SIZE);
        assert_eq!(&bytes[0..8], b"AEGSGD01");
        // DEV downgrade is explicit: the blob carries the code (plaintext store).
        assert_eq!(&bytes[10..26], &TEST_CODE);
        let parsed = DevRecoveryCodeCache::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, cache);
        assert_eq!(parsed.code(), TEST_CODE);
    }

    #[test]
    fn test_dev_code_cache_tamper_fails_closed() {
        let good = DevRecoveryCodeCache::new(TEST_CODE).to_bytes();

        // Tampered code byte without CRC fix: CRC mismatch fails closed.
        let mut bad_crc = good;
        bad_crc[12] ^= 0xFF;
        assert!(matches!(
            DevRecoveryCodeCache::from_bytes(&bad_crc),
            Err(SecureGuardError::PersistenceCorrupted(_))
        ));

        // Tampered magic with recomputed CRC: magic check fails closed.
        let mut bad_magic = good;
        bad_magic[0] = b'X';
        let crc = crc32(&bad_magic[0..26]);
        bad_magic[26..30].copy_from_slice(&crc.to_be_bytes());
        assert!(matches!(
            DevRecoveryCodeCache::from_bytes(&bad_magic),
            Err(SecureGuardError::PersistenceCorrupted(
                "dev recovery-code cache invalid magic"
            ))
        ));

        // Wrong version with recomputed CRC: version check fails closed.
        let mut bad_version = good;
        bad_version[9] = 0x7F;
        let crc = crc32(&bad_version[0..26]);
        bad_version[26..30].copy_from_slice(&crc.to_be_bytes());
        assert!(matches!(
            DevRecoveryCodeCache::from_bytes(&bad_version),
            Err(SecureGuardError::PersistenceCorrupted(
                "dev recovery-code cache unsupported version"
            ))
        ));
    }
}
