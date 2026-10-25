//! Persistent Serialization for Secure Guard
//!
//! Compact, deterministic 256-byte binary record with CRC32 integrity validation
//! designed for atomic storage on ESP32-S3 Flash/NVS.

use super::crypto::crc32;
use super::error::SecureGuardError;
use super::policy::SecureGuardPolicy;
use super::state::SecureGuardState;

/// Magic header for identifying valid Secure Guard persistent records: "AEGSG001".
pub const PERSISTENCE_MAGIC: [u8; 8] = *b"AEGSG001";
/// Format version for the persistent binary layout.
pub const PERSISTENCE_VERSION: u16 = 1;
/// Fixed size of the binary record in bytes.
pub const PERSISTENT_RECORD_SIZE: usize = 256;

/// Persistent state of the Secure Guard engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureGuardPersistentRecord {
    /// True if a PIN and recovery secret have been provisioned.
    pub is_provisioned: bool,
    /// Wire code representation of the last persisted state.
    pub state_wire: u8,
    /// Consecutive failed authentication attempts counter (0..=5).
    pub failed_attempts: u8,
    /// Whether the last wipe action was simulated in test mode.
    pub last_wipe_simulated: bool,
    /// Rate-limit penalty expiry timestamp in milliseconds.
    pub rate_limit_until_ms: u64,
    /// 16-byte random salt for PIN KDF.
    pub pin_salt: [u8; 16],
    /// 32-byte PBKDF2 verifier for the PIN.
    pub pin_verifier: [u8; 32],
    /// 16-byte random salt for Recovery Code KDF.
    pub recovery_salt: [u8; 16],
    /// 32-byte PBKDF2 verifier for the Recovery Code.
    pub recovery_verifier: [u8; 32],
    /// Security policy configuration.
    pub policy: SecureGuardPolicy,
}

impl Default for SecureGuardPersistentRecord {
    fn default() -> Self {
        Self {
            is_provisioned: false,
            state_wire: SecureGuardState::Unprovisioned.wire_code(),
            failed_attempts: 0,
            last_wipe_simulated: false,
            rate_limit_until_ms: 0,
            pin_salt: [0u8; 16],
            pin_verifier: [0u8; 32],
            recovery_salt: [0u8; 16],
            recovery_verifier: [0u8; 32],
            policy: SecureGuardPolicy::default(),
        }
    }
}

impl SecureGuardPersistentRecord {
    /// Serializes this record into a deterministic [u8; 256] byte array with CRC32.
    pub fn to_bytes(&self) -> [u8; PERSISTENT_RECORD_SIZE] {
        let mut out = [0u8; PERSISTENT_RECORD_SIZE];

        out[0..8].copy_from_slice(&PERSISTENCE_MAGIC);
        out[8..10].copy_from_slice(&PERSISTENCE_VERSION.to_be_bytes());

        out[10] = self.is_provisioned as u8;
        out[11] = self.state_wire;
        out[12] = self.failed_attempts;
        out[13] = self.last_wipe_simulated as u8;

        out[14..22].copy_from_slice(&self.rate_limit_until_ms.to_be_bytes());
        out[22..38].copy_from_slice(&self.pin_salt);
        out[38..70].copy_from_slice(&self.pin_verifier);
        out[70..86].copy_from_slice(&self.recovery_salt);
        out[86..118].copy_from_slice(&self.recovery_verifier);

        out[118] = self.policy.wipe_on_5_failures as u8;
        out[119] = self.policy.protect_keys_and_aegn as u8;
        out[120] = self.policy.protect_oath as u8;
        out[121] = self.policy.test_mode_non_destructive_wipe as u8;
        out[122] = self.policy.min_pin_len;
        out[123] = self.policy.max_pin_len;
        out[124] = self.policy.reject_trivial_pins as u8;
        out[125] = 0; // reserved byte

        out[126..134].copy_from_slice(&self.policy.session_duration_ms.to_be_bytes());
        out[134..142].copy_from_slice(&self.policy.inactivity_timeout_ms.to_be_bytes());
        out[142..146].copy_from_slice(&self.policy.pbkdf2_iterations.to_be_bytes());

        // Bytes 146..252 remain zeroed as reserved padding

        // Compute CRC32 over bytes 0..252
        let crc = crc32(&out[0..252]);
        out[252..256].copy_from_slice(&crc.to_be_bytes());

        out
    }

    /// Deserializes a [u8; 256] array, checking CRC32 and magic/version.
    ///
    /// Fails closed if the record is corrupted.
    pub fn from_bytes(bytes: &[u8; PERSISTENT_RECORD_SIZE]) -> Result<Self, SecureGuardError> {
        // 1. Verify CRC32
        let stored_crc = u32::from_be_bytes([bytes[252], bytes[253], bytes[254], bytes[255]]);
        let computed_crc = crc32(&bytes[0..252]);
        if stored_crc != computed_crc {
            return Err(SecureGuardError::PersistenceCorrupted("CRC32 mismatch"));
        }

        // 2. Check Magic
        if bytes[0..8] != PERSISTENCE_MAGIC {
            return Err(SecureGuardError::PersistenceCorrupted(
                "Invalid magic bytes",
            ));
        }

        // 3. Check Version
        let version = u16::from_be_bytes([bytes[8], bytes[9]]);
        if version != PERSISTENCE_VERSION {
            return Err(SecureGuardError::PersistenceCorrupted(
                "Unsupported version",
            ));
        }

        let is_provisioned = bytes[10] != 0;
        let state_wire = bytes[11];
        let failed_attempts = bytes[12];
        let last_wipe_simulated = bytes[13] != 0;

        let rate_limit_until_ms = u64::from_be_bytes(
            bytes[14..22]
                .try_into()
                .map_err(|_| SecureGuardError::PersistenceCorrupted("Bad rate limit"))?,
        );

        let mut pin_salt = [0u8; 16];
        pin_salt.copy_from_slice(&bytes[22..38]);

        let mut pin_verifier = [0u8; 32];
        pin_verifier.copy_from_slice(&bytes[38..70]);

        let mut recovery_salt = [0u8; 16];
        recovery_salt.copy_from_slice(&bytes[70..86]);

        let mut recovery_verifier = [0u8; 32];
        recovery_verifier.copy_from_slice(&bytes[86..118]);

        let policy =
            SecureGuardPolicy {
                wipe_on_5_failures: bytes[118] != 0,
                protect_keys_and_aegn: bytes[119] != 0,
                protect_oath: bytes[120] != 0,
                test_mode_non_destructive_wipe: bytes[121] != 0,
                min_pin_len: bytes[122],
                max_pin_len: bytes[123],
                reject_trivial_pins: bytes[124] != 0,
                session_duration_ms: u64::from_be_bytes(
                    bytes[126..134].try_into().map_err(|_| {
                        SecureGuardError::PersistenceCorrupted("Bad session duration")
                    })?,
                ),
                inactivity_timeout_ms: u64::from_be_bytes(bytes[134..142].try_into().map_err(
                    |_| SecureGuardError::PersistenceCorrupted("Bad inactivity timeout"),
                )?),
                pbkdf2_iterations: u32::from_be_bytes(bytes[142..146].try_into().map_err(
                    |_| SecureGuardError::PersistenceCorrupted("Bad PBKDF2 iterations"),
                )?),
            };

        Ok(Self {
            is_provisioned,
            state_wire,
            failed_attempts,
            last_wipe_simulated,
            rate_limit_until_ms,
            pin_salt,
            pin_verifier,
            recovery_salt,
            recovery_verifier,
            policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_serialization_roundtrip() {
        let record = SecureGuardPersistentRecord {
            is_provisioned: true,
            state_wire: SecureGuardState::Locked.wire_code(),
            failed_attempts: 2,
            last_wipe_simulated: true,
            rate_limit_until_ms: 123456789,
            pin_salt: [0x11; 16],
            pin_verifier: [0x22; 32],
            recovery_salt: [0x33; 16],
            recovery_verifier: [0x44; 32],
            policy: SecureGuardPolicy {
                wipe_on_5_failures: true,
                protect_keys_and_aegn: false,
                protect_oath: true,
                test_mode_non_destructive_wipe: true,
                min_pin_len: 6,
                max_pin_len: 12,
                reject_trivial_pins: true,
                session_duration_ms: 180_000,
                inactivity_timeout_ms: 60_000,
                pbkdf2_iterations: 5_000,
            },
        };

        let bytes = record.to_bytes();
        assert_eq!(bytes.len(), 256);

        let parsed = SecureGuardPersistentRecord::from_bytes(&bytes).unwrap();
        assert_eq!(record, parsed);
    }

    #[test]
    fn test_corrupted_crc_fails_closed() {
        let record = SecureGuardPersistentRecord::default();
        let mut bytes = record.to_bytes();

        // Tamper with one byte in the payload
        bytes[20] ^= 0xFF;

        let err = SecureGuardPersistentRecord::from_bytes(&bytes);
        assert!(matches!(
            err,
            Err(SecureGuardError::PersistenceCorrupted(_))
        ));
    }

    #[test]
    fn test_corrupted_magic_fails_closed() {
        let record = SecureGuardPersistentRecord::default();
        let mut bytes = record.to_bytes();

        // Corrupt magic and re-calculate CRC
        bytes[0] = b'X';
        let crc = crc32(&bytes[0..252]);
        bytes[252..256].copy_from_slice(&crc.to_be_bytes());

        let err = SecureGuardPersistentRecord::from_bytes(&bytes);
        assert!(matches!(
            err,
            Err(SecureGuardError::PersistenceCorrupted(
                "Invalid magic bytes"
            ))
        ));
    }
}
