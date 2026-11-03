//! Device-Key-Independent Recovery Envelope for Secure Guard
//!
//! # Why this exists (DEV reboot rescue)
//!
//! The 256-byte [`SecureGuardPersistentRecord`](crate::persistence::SecureGuardPersistentRecord)
//! is sealed at rest inside the firmware's device-key envelope
//! (`SecureStorage`, AES-256-GCM under a key derived from the eFuse OTP master
//! key). On DEV/bench boards eFuse provisioning is owner-forbidden, so every
//! boot mints fresh ephemeral TRNG keys: the NVS `sg_record` bytes can no
//! longer be opened, the firmware maps the failure to
//! [`SecureGuardState::ErrorLocked`](crate::state::SecureGuardState::ErrorLocked),
//! and the in-RAM verifiers are gone (zeroed). The pre-existing
//! [`SecureGuardEngine::recover_with_code`](crate::engine::SecureGuardEngine::recover_with_code)
//! path cannot help there: it rejects `ErrorLocked` and, worse, has nothing to
//! check the presented code against once the device-key envelope is lost.
//!
//! This module is the durable non-eFuse rescue: a small self-contained envelope
//! that carries everything needed to authenticate a recovery code and rebuild
//! provisioned state **without any device key**:
//!
//! * KEK derivation: `KEK = PBKDF2-HMAC-SHA256(recovery_code, recovery_salt,
//!   iterations)` — same KDF and same iteration count as the live policy
//!   (never weakened; the count is stored inside the envelope so verification
//!   reproduces the creation KEK even if the policy later changes).
//! * Wrapped credential copy: the live `pin_salt`/`pin_verifier` XOR-wrapped
//!   under an HMAC-based keystream keyed by the KEK (counter mode, domain
//!   separated). No AES dependency is introduced.
//! * Verifier storage: `recovery_verifier = HMAC(KEK, VERIFY_DOMAIN || salt)`,
//!   checkable in constant time without device keys.
//! * Integrity: an HMAC tag over the wrapped material (keyed by the KEK) plus a
//!   CRC32 over the whole blob. Tampering fails closed; a wrong code and a
//!   tampered blob both surface as [`SecureGuardError::InvalidRecoveryCode`]
//!   so no oracle distinguishes them.
//!
//! # Firmware wiring contract (owner: firmware persistence agent)
//!
//! The envelope bytes travel in a **separate NVS blob outside the device-key
//! envelope** (plaintext + internal CRC, e.g. key `sg_recovery_v1`):
//!
//! * on provision / recovery rotation: persist `engine.recovery_envelope_bytes()`
//!   next to the encrypted `sg_record_v1`;
//! * on `ErrorLocked` after a device-key failure: load the envelope blob and
//!   call [`SecureGuardEngine::recover_with_envelope`](crate::engine::SecureGuardEngine::recover_with_envelope);
//! * after `change_pin` (which the envelope cannot observe): call
//!   [`SecureGuardEngine::refresh_recovery_envelope`](crate::engine::SecureGuardEngine::refresh_recovery_envelope)
//!   with the recovery code when available, otherwise the envelope still
//!   rescues to the provision-time PIN.
//!
//! Never log the recovery code, the KEK, or unwrapped material. The envelope
//! itself is safe to store in plaintext flash: without the recovery code it
//! reveals nothing (offline attack cost = creation PBKDF2 iterations).

use super::crypto::{constant_time_eq_32, crc32, derive_verifier, hmac_sha256};
use super::error::SecureGuardError;
use zeroize::Zeroize;

/// Magic header identifying a valid recovery envelope: "AEGSGR01".
pub const RECOVERY_ENVELOPE_MAGIC: [u8; 8] = *b"AEGSGR01";
/// Format version of the recovery envelope binary layout.
pub const RECOVERY_ENVELOPE_VERSION: u16 = 1;
/// Fixed size of the serialized recovery envelope in bytes:
/// magic(8) + version(2) + iterations(4) + salt(16) + verifier(32)
/// + wrapped_pin_salt(16) + wrapped_pin_verifier(32) + tag(32) + crc32(4).
pub const RECOVERY_ENVELOPE_SIZE: usize = 146;

/// Domain separation: recovery-code verifier derivation.
const VERIFY_DOMAIN: &[u8] = b"AEGIS-SG-RECOVERY-VERIFY-V1";
/// Domain separation: credential-wrap keystream derivation.
const WRAP_DOMAIN: &[u8] = b"AEGIS-SG-RECOVERY-WRAP-V1";
/// Domain separation: wrapped-material integrity tag.
const TAG_DOMAIN: &[u8] = b"AEGIS-SG-RECOVERY-TAG-V1";

/// Self-contained, device-key-independent recovery envelope.
///
/// Typed in-memory representation; the NVS wire form is produced/consumed only
/// via [`Self::to_bytes`] / [`Self::from_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureGuardRecoveryEnvelope {
    /// PBKDF2 iteration count used at creation (reproduces the KEK exactly).
    pub pbkdf2_iterations: u32,
    /// 16-byte random salt for the recovery-code KDF.
    pub recovery_salt: [u8; 16],
    /// 32-byte HMAC verifier for the recovery code (checkable w/o device keys).
    pub recovery_verifier: [u8; 32],
    /// XOR-wrapped live `pin_salt`.
    pub wrapped_pin_salt: [u8; 16],
    /// XOR-wrapped live `pin_verifier`.
    pub wrapped_pin_verifier: [u8; 32],
    /// HMAC integrity tag over the wrapped material, keyed by the KEK.
    pub integrity_tag: [u8; 32],
}

impl Drop for SecureGuardRecoveryEnvelope {
    fn drop(&mut self) {
        self.recovery_verifier.zeroize();
        self.wrapped_pin_salt.zeroize();
        self.wrapped_pin_verifier.zeroize();
        self.integrity_tag.zeroize();
        self.recovery_salt.zeroize();
        self.pbkdf2_iterations = 0;
    }
}

impl SecureGuardRecoveryEnvelope {
    /// Derives the recovery KEK from a presented code (PBKDF2, unweakened).
    fn derive_kek(recovery_code: &[u8], salt: &[u8; 16], iterations: u32) -> [u8; 32] {
        derive_verifier(recovery_code, salt, iterations)
    }

    /// Verifier preimage input: `VERIFY_DOMAIN || salt`.
    fn verifier_input(salt: &[u8; 16]) -> [u8; 64] {
        let mut input = [0u8; 64];
        let mut off = 0;
        input[off..off + VERIFY_DOMAIN.len()].copy_from_slice(VERIFY_DOMAIN);
        off += VERIFY_DOMAIN.len();
        input[off..off + salt.len()].copy_from_slice(salt);
        // Zero-padded remainder is deterministic: every field above is
        // fixed-size and the preimage is domain separated.
        input
    }

    /// Keystream block `i`: `HMAC(KEK, WRAP_DOMAIN || salt || i)` (32 bytes).
    fn keystream_block(kek: &[u8; 32], salt: &[u8; 16], index: u8) -> [u8; 32] {
        let mut input = [0u8; 64];
        let mut off = 0;
        input[off..off + WRAP_DOMAIN.len()].copy_from_slice(WRAP_DOMAIN);
        off += WRAP_DOMAIN.len();
        input[off..off + salt.len()].copy_from_slice(salt);
        off += salt.len();
        input[off] = index;
        let block = hmac_sha256(kek, &input);
        input.zeroize();
        block
    }

    /// Tag preimage covers wrapped material + salt + iterations (bound together).
    fn tag_over(
        kek: &[u8; 32],
        wrapped_pin_salt: &[u8; 16],
        wrapped_pin_verifier: &[u8; 32],
        salt: &[u8; 16],
        iterations: u32,
    ) -> [u8; 32] {
        let mut input = [0u8; 128];
        let mut off = 0;
        input[off..off + TAG_DOMAIN.len()].copy_from_slice(TAG_DOMAIN);
        off += TAG_DOMAIN.len();
        input[off..off + wrapped_pin_salt.len()].copy_from_slice(wrapped_pin_salt);
        off += wrapped_pin_salt.len();
        input[off..off + wrapped_pin_verifier.len()].copy_from_slice(wrapped_pin_verifier);
        off += wrapped_pin_verifier.len();
        input[off..off + salt.len()].copy_from_slice(salt);
        off += salt.len();
        input[off..off + 4].copy_from_slice(&iterations.to_be_bytes());
        let tag = hmac_sha256(kek, &input);
        input.zeroize();
        tag
    }

    /// Seals live credential material under a KEK derived from the recovery code.
    ///
    /// Fails closed on empty codes or zero iterations (the latter would panic
    /// inside PBKDF2); KDF strength is never weakened.
    pub fn seal(
        recovery_code: &[u8],
        recovery_salt: &[u8; 16],
        pin_salt: &[u8; 16],
        pin_verifier: &[u8; 32],
        pbkdf2_iterations: u32,
    ) -> Result<Self, SecureGuardError> {
        if recovery_code.is_empty() {
            return Err(SecureGuardError::InvalidRecoveryCode);
        }
        if pbkdf2_iterations == 0 {
            return Err(SecureGuardError::PersistenceCorrupted(
                "recovery envelope requires non-zero KDF iterations",
            ));
        }

        let mut kek = Self::derive_kek(recovery_code, recovery_salt, pbkdf2_iterations);

        let verifier_input = Self::verifier_input(recovery_salt);
        let recovery_verifier = hmac_sha256(&kek, &verifier_input);

        let mut block0 = Self::keystream_block(&kek, recovery_salt, 0);
        let mut block1 = Self::keystream_block(&kek, recovery_salt, 1);

        let mut wrapped_pin_salt = [0u8; 16];
        for i in 0..16 {
            wrapped_pin_salt[i] = pin_salt[i] ^ block0[i];
        }
        let mut wrapped_pin_verifier = [0u8; 32];
        for i in 0..32 {
            wrapped_pin_verifier[i] = pin_verifier[i] ^ block1[i];
        }
        block0.zeroize();
        block1.zeroize();

        let integrity_tag = Self::tag_over(
            &kek,
            &wrapped_pin_salt,
            &wrapped_pin_verifier,
            recovery_salt,
            pbkdf2_iterations,
        );
        kek.zeroize();

        Ok(Self {
            pbkdf2_iterations,
            recovery_salt: *recovery_salt,
            recovery_verifier,
            wrapped_pin_salt,
            wrapped_pin_verifier,
            integrity_tag,
        })
    }

    /// Authenticates a presented code and unwraps the credential copy.
    ///
    /// Structural misuse (zero stored iterations) fails closed without running
    /// the KDF. Code/tag mismatches both surface as `InvalidRecoveryCode`.
    pub fn verify_and_unwrap(
        &self,
        recovery_code: &[u8],
    ) -> Result<([u8; 16], [u8; 32]), SecureGuardError> {
        if recovery_code.is_empty() || self.pbkdf2_iterations == 0 {
            return Err(SecureGuardError::InvalidRecoveryCode);
        }

        let mut kek = Self::derive_kek(recovery_code, &self.recovery_salt, self.pbkdf2_iterations);

        let verifier_input = Self::verifier_input(&self.recovery_salt);
        let mut candidate_verifier = hmac_sha256(&kek, &verifier_input);
        let code_valid = constant_time_eq_32(&candidate_verifier, &self.recovery_verifier);
        candidate_verifier.zeroize();
        if !code_valid {
            kek.zeroize();
            return Err(SecureGuardError::InvalidRecoveryCode);
        }

        let expected_tag = Self::tag_over(
            &kek,
            &self.wrapped_pin_salt,
            &self.wrapped_pin_verifier,
            &self.recovery_salt,
            self.pbkdf2_iterations,
        );
        let tag_valid = constant_time_eq_32(&expected_tag, &self.integrity_tag);
        if !tag_valid {
            kek.zeroize();
            return Err(SecureGuardError::InvalidRecoveryCode);
        }

        let mut block0 = Self::keystream_block(&kek, &self.recovery_salt, 0);
        let mut block1 = Self::keystream_block(&kek, &self.recovery_salt, 1);
        kek.zeroize();

        let mut pin_salt = [0u8; 16];
        for i in 0..16 {
            pin_salt[i] = self.wrapped_pin_salt[i] ^ block0[i];
        }
        let mut pin_verifier = [0u8; 32];
        for i in 0..32 {
            pin_verifier[i] = self.wrapped_pin_verifier[i] ^ block1[i];
        }
        block0.zeroize();
        block1.zeroize();

        Ok((pin_salt, pin_verifier))
    }

    /// Serializes to the fixed-size NVS wire form with CRC32 integrity.
    pub fn to_bytes(&self) -> [u8; RECOVERY_ENVELOPE_SIZE] {
        let mut out = [0u8; RECOVERY_ENVELOPE_SIZE];
        out[0..8].copy_from_slice(&RECOVERY_ENVELOPE_MAGIC);
        out[8..10].copy_from_slice(&RECOVERY_ENVELOPE_VERSION.to_be_bytes());
        out[10..14].copy_from_slice(&self.pbkdf2_iterations.to_be_bytes());
        out[14..30].copy_from_slice(&self.recovery_salt);
        out[30..62].copy_from_slice(&self.recovery_verifier);
        out[62..78].copy_from_slice(&self.wrapped_pin_salt);
        out[78..110].copy_from_slice(&self.wrapped_pin_verifier);
        out[110..142].copy_from_slice(&self.integrity_tag);
        let crc = crc32(&out[0..142]);
        out[142..146].copy_from_slice(&crc.to_be_bytes());
        out
    }

    /// Deserializes the NVS wire form, failing closed on any structural fault.
    pub fn from_bytes(bytes: &[u8; RECOVERY_ENVELOPE_SIZE]) -> Result<Self, SecureGuardError> {
        let stored_crc = u32::from_be_bytes([bytes[142], bytes[143], bytes[144], bytes[145]]);
        if stored_crc != crc32(&bytes[0..142]) {
            return Err(SecureGuardError::PersistenceCorrupted(
                "recovery envelope CRC32 mismatch",
            ));
        }
        if bytes[0..8] != RECOVERY_ENVELOPE_MAGIC {
            return Err(SecureGuardError::PersistenceCorrupted(
                "recovery envelope invalid magic",
            ));
        }
        let version = u16::from_be_bytes([bytes[8], bytes[9]]);
        if version != RECOVERY_ENVELOPE_VERSION {
            return Err(SecureGuardError::PersistenceCorrupted(
                "recovery envelope unsupported version",
            ));
        }

        let pbkdf2_iterations = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
        if pbkdf2_iterations == 0 {
            return Err(SecureGuardError::PersistenceCorrupted(
                "recovery envelope zero KDF iterations",
            ));
        }

        let mut recovery_salt = [0u8; 16];
        recovery_salt.copy_from_slice(&bytes[14..30]);
        let mut recovery_verifier = [0u8; 32];
        recovery_verifier.copy_from_slice(&bytes[30..62]);
        let mut wrapped_pin_salt = [0u8; 16];
        wrapped_pin_salt.copy_from_slice(&bytes[62..78]);
        let mut wrapped_pin_verifier = [0u8; 32];
        wrapped_pin_verifier.copy_from_slice(&bytes[78..110]);
        let mut integrity_tag = [0u8; 32];
        integrity_tag.copy_from_slice(&bytes[110..142]);

        Ok(Self {
            pbkdf2_iterations,
            recovery_salt,
            recovery_verifier,
            wrapped_pin_salt,
            wrapped_pin_verifier,
            integrity_tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CODE: &[u8] = b"recovery-code-01";
    const TEST_SALT: [u8; 16] = [0x33; 16];
    const TEST_PIN_SALT: [u8; 16] = [0x11; 16];
    const TEST_PIN_VERIFIER: [u8; 32] = [0x22; 32];

    fn test_envelope() -> SecureGuardRecoveryEnvelope {
        SecureGuardRecoveryEnvelope::seal(
            TEST_CODE,
            &TEST_SALT,
            &TEST_PIN_SALT,
            &TEST_PIN_VERIFIER,
            10,
        )
        .expect("seal test envelope")
    }

    #[test]
    fn test_seal_verify_roundtrip() {
        let env = test_envelope();
        assert_eq!(env.pbkdf2_iterations, 10);
        assert_eq!(env.recovery_salt, TEST_SALT);
        // Wrapped copy reveals nothing about the credential material.
        assert_ne!(env.wrapped_pin_salt, TEST_PIN_SALT);
        assert_ne!(env.wrapped_pin_verifier, TEST_PIN_VERIFIER);

        let (salt, verifier) = env
            .verify_and_unwrap(TEST_CODE)
            .expect("valid code unwraps");
        assert_eq!(salt, TEST_PIN_SALT);
        assert_eq!(verifier, TEST_PIN_VERIFIER);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let env = test_envelope();
        let bytes = env.to_bytes();
        assert_eq!(bytes.len(), RECOVERY_ENVELOPE_SIZE);
        let parsed = SecureGuardRecoveryEnvelope::from_bytes(&bytes).expect("parse");
        assert_eq!(env, parsed);
        let (_, verifier) = parsed
            .verify_and_unwrap(TEST_CODE)
            .expect("unwrap after parse");
        assert_eq!(verifier, TEST_PIN_VERIFIER);
    }

    #[test]
    fn test_wrong_code_rejected() {
        let env = test_envelope();
        let err = env.verify_and_unwrap(b"wrong-code-xxxxxx");
        assert_eq!(err, Err(SecureGuardError::InvalidRecoveryCode));
    }

    #[test]
    fn test_empty_code_rejected() {
        assert_eq!(
            SecureGuardRecoveryEnvelope::seal(
                b"",
                &TEST_SALT,
                &TEST_PIN_SALT,
                &TEST_PIN_VERIFIER,
                10
            ),
            Err(SecureGuardError::InvalidRecoveryCode)
        );
        let env = test_envelope();
        assert_eq!(
            env.verify_and_unwrap(b""),
            Err(SecureGuardError::InvalidRecoveryCode)
        );
    }

    #[test]
    fn test_zero_iterations_rejected() {
        assert!(SecureGuardRecoveryEnvelope::seal(
            TEST_CODE,
            &TEST_SALT,
            &TEST_PIN_SALT,
            &TEST_PIN_VERIFIER,
            0
        )
        .is_err());
    }

    #[test]
    fn test_tampered_wrapped_material_fails_closed() {
        let mut bytes = test_envelope().to_bytes();
        bytes[70] ^= 0xFF;
        // Fix CRC so the failure must come from the KEK-bound tag, not the CRC.
        let crc = crc32(&bytes[0..142]);
        bytes[142..146].copy_from_slice(&crc.to_be_bytes());
        let parsed =
            SecureGuardRecoveryEnvelope::from_bytes(&bytes).expect("structure still valid");
        assert_eq!(
            parsed.verify_and_unwrap(TEST_CODE),
            Err(SecureGuardError::InvalidRecoveryCode)
        );
    }

    #[test]
    fn test_tampered_tag_fails_closed() {
        let mut bytes = test_envelope().to_bytes();
        bytes[120] ^= 0x01;
        let crc = crc32(&bytes[0..142]);
        bytes[142..146].copy_from_slice(&crc.to_be_bytes());
        let parsed =
            SecureGuardRecoveryEnvelope::from_bytes(&bytes).expect("structure still valid");
        assert_eq!(
            parsed.verify_and_unwrap(TEST_CODE),
            Err(SecureGuardError::InvalidRecoveryCode)
        );
    }

    #[test]
    fn test_tampered_verifier_fails_closed() {
        let mut bytes = test_envelope().to_bytes();
        bytes[40] ^= 0x01;
        let crc = crc32(&bytes[0..142]);
        bytes[142..146].copy_from_slice(&crc.to_be_bytes());
        let parsed =
            SecureGuardRecoveryEnvelope::from_bytes(&bytes).expect("structure still valid");
        assert_eq!(
            parsed.verify_and_unwrap(TEST_CODE),
            Err(SecureGuardError::InvalidRecoveryCode)
        );
    }

    #[test]
    fn test_corrupted_crc_magic_version_fail_closed() {
        let mut bytes = test_envelope().to_bytes();

        let mut bad_crc = bytes;
        bad_crc[50] ^= 0xFF;
        assert!(matches!(
            SecureGuardRecoveryEnvelope::from_bytes(&bad_crc),
            Err(SecureGuardError::PersistenceCorrupted(_))
        ));

        let mut bad_magic = bytes;
        bad_magic[0] = b'X';
        let crc = crc32(&bad_magic[0..142]);
        bad_magic[142..146].copy_from_slice(&crc.to_be_bytes());
        assert!(matches!(
            SecureGuardRecoveryEnvelope::from_bytes(&bad_magic),
            Err(SecureGuardError::PersistenceCorrupted(_))
        ));

        let mut bad_version = bytes;
        bad_version[9] = 0x7F;
        let crc = crc32(&bad_version[0..142]);
        bad_version[142..146].copy_from_slice(&crc.to_be_bytes());
        assert!(matches!(
            SecureGuardRecoveryEnvelope::from_bytes(&bad_version),
            Err(SecureGuardError::PersistenceCorrupted(_))
        ));

        // Zero iterations on the wire fails closed instead of panicking the KDF.
        bytes[10..14].copy_from_slice(&0u32.to_be_bytes());
        let crc = crc32(&bytes[0..142]);
        bytes[142..146].copy_from_slice(&crc.to_be_bytes());
        assert!(matches!(
            SecureGuardRecoveryEnvelope::from_bytes(&bytes),
            Err(SecureGuardError::PersistenceCorrupted(_))
        ));
    }

    #[test]
    fn test_kdf_params_bound_to_envelope() {
        // Same code + salt but different iteration counts seal different verifiers;
        // verification reproduces the creation KEK from the stored count.
        let a = SecureGuardRecoveryEnvelope::seal(
            TEST_CODE,
            &TEST_SALT,
            &TEST_PIN_SALT,
            &TEST_PIN_VERIFIER,
            10,
        )
        .unwrap();
        let b = SecureGuardRecoveryEnvelope::seal(
            TEST_CODE,
            &TEST_SALT,
            &TEST_PIN_SALT,
            &TEST_PIN_VERIFIER,
            11,
        )
        .unwrap();
        assert_ne!(a.recovery_verifier, b.recovery_verifier);
        assert!(a.verify_and_unwrap(TEST_CODE).is_ok());
        assert!(b.verify_and_unwrap(TEST_CODE).is_ok());
        // Cross-count unwrap fails: verifier is bound to the creation count.
        let mut tampered = a;
        tampered.pbkdf2_iterations = 11;
        assert_eq!(
            tampered.verify_and_unwrap(TEST_CODE),
            Err(SecureGuardError::InvalidRecoveryCode)
        );
    }
}
