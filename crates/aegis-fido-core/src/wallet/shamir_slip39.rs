//! Shamir Secret Sharing (SLIP-0039 2-of-3) & DS/HMAC BIP-39 Seed Enveloping (`OPP-03` & `OPP-05`)
//!
//! # Mathematical Foundations
//! - Implements Shamir's Secret Sharing over Galois Field `GF(256)` using the irreducible
//!   AES polynomial: `P(x) = x^8 + x^4 + x^3 + x + 1` (`0x11B`).
//! - Threshold `K = 2`, Total `N = 3`:
//!   - Share 1: AegisKey Primary Hardware Authenticator
//!   - Share 2: AegisKey Secondary / Backup Hardware Authenticator
//!   - Share 3: Contingency Paper Recovery Card
//! - Secret reconstruction uses Lagrange polynomial interpolation in `GF(256)`.
//! - Integrity is protected by an IEEE 802.3 CRC32 checksum over the reconstructed 32-byte secret.
//! - BIP-39 Master Seeds are sealed with AES-256-GCM authenticated encryption using keys derived
//!   from the hardware Digital Signature / HMAC peripheral (`DsHmacSeedEnvelope`).

use alloc::vec::Vec;
use rand_core::CryptoRng;
use zeroize::Zeroize;

use crate::crypto::aead::{aes_256_gcm_decrypt, aes_256_gcm_encrypt};
use crate::secure_guard::crypto::crc32;

/// Irreducible AES polynomial modulo mask (`0x11B` without bit 8).
pub const GF256_MODULO: u8 = 0x1B;
/// Associated authenticated data for DS/HMAC BIP-39 seed envelopes.
pub const DS_HMAC_SEED_AAD: &[u8] = b"AEGIS_DS_HMAC_BIP39_SEED_V1";

/// Errors encountered in Shamir Secret Sharing or BIP-39 envelope operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShamirError {
    /// Inversion of 0 is mathematically undefined in GF(256).
    DivisionByZero,
    /// Share index x is 0 or out of legal bounds (1..=255).
    InvalidShareIndex,
    /// Both supplied shares have identical indices (2 distinct shares required).
    DuplicateShareIndex,
    /// CRC32 checksum verification failed on reconstructed secret (corruption/tampering).
    ChecksumMismatch,
    /// Hardware DS/HMAC seed encryption failed.
    EncryptionFailed,
    /// Hardware DS/HMAC seed decryption or authentication tag check failed.
    DecryptionFailed,
}

impl core::fmt::Display for ShamirError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DivisionByZero => write!(f, "Division by zero in GF(256)"),
            Self::InvalidShareIndex => write!(f, "Invalid Shamir share index (must be 1..=255)"),
            Self::DuplicateShareIndex => write!(f, "Supplied shares have identical indices"),
            Self::ChecksumMismatch => write!(f, "Reconstructed secret CRC32 checksum mismatch"),
            Self::EncryptionFailed => write!(f, "AES-256-GCM seed encryption failed"),
            Self::DecryptionFailed => write!(f, "AES-256-GCM seed decryption/authentication failed"),
        }
    }
}

/// Multiplies two elements in `GF(256)` modulo `x^8 + x^4 + x^3 + x + 1` (AES polynomial).
#[inline]
pub fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi_bit = (a & 0x80) != 0;
        a <<= 1;
        if hi_bit {
            a ^= GF256_MODULO;
        }
        b >>= 1;
    }
    p
}

/// Computes the multiplicative inverse of an element in `GF(256)` using Fermat's Little Theorem:
/// `a^-1 = a^(255-1) = a^254`.
#[inline]
pub fn gf256_inv(a: u8) -> Result<u8, ShamirError> {
    if a == 0 {
        return Err(ShamirError::DivisionByZero);
    }
    let mut res = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    while exp > 0 {
        if (exp & 1) != 0 {
            res = gf256_mul(res, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    Ok(res)
}

/// Divides `a` by `b` in `GF(256)`.
#[inline]
pub fn gf256_div(a: u8, b: u8) -> Result<u8, ShamirError> {
    let inv_b = gf256_inv(b)?;
    Ok(gf256_mul(a, inv_b))
}

/// A single Shamir share in a 2-of-3 split.
#[derive(Clone, PartialEq, Eq)]
pub struct ShamirShare {
    /// Evaluation coordinate x in `1..=3`.
    pub index: u8,
    /// 32-byte polynomial evaluation point `P(x)`.
    pub data: [u8; 32],
    /// IEEE 802.3 CRC32 checksum of the original 32-byte secret.
    pub crc32: u32,
}

impl core::fmt::Debug for ShamirShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShamirShare")
            .field("index", &self.index)
            .field("data", &"[REDACTED_SHARE]")
            .field("crc32", &core::format_args!("0x{:08X}", self.crc32))
            .finish()
    }
}

impl Drop for ShamirShare {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Splits a 32-byte master secret into 3 shares with a 2-of-3 reconstruction threshold.
///
/// Polynomial for byte i: `P_i(x) = secret[i] ^ (entropy_p1[i] * x)`.
/// - Share 1: evaluated at `x = 1`
/// - Share 2: evaluated at `x = 2`
/// - Share 3: evaluated at `x = 3`
pub fn split_secret_2_of_3(
    secret: &[u8; 32],
    entropy_p1: &[u8; 32],
) -> [ShamirShare; 3] {
    let checksum = crc32(secret);

    let mut shares = [
        ShamirShare {
            index: 1,
            data: [0u8; 32],
            crc32: checksum,
        },
        ShamirShare {
            index: 2,
            data: [0u8; 32],
            crc32: checksum,
        },
        ShamirShare {
            index: 3,
            data: [0u8; 32],
            crc32: checksum,
        },
    ];

    for (idx, share) in shares.iter_mut().enumerate() {
        let x = (idx + 1) as u8;
        for i in 0..32 {
            let s = secret[i];
            let p1 = entropy_p1[i];
            share.data[i] = s ^ gf256_mul(p1, x);
        }
    }

    shares
}

/// Reconstructs the 32-byte master secret from any 2 distinct shares using Lagrange interpolation.
///
/// At `x = 0`:
/// `lambda_a = x_b / (x_a ^ x_b)`
/// `lambda_b = x_a / (x_a ^ x_b)`
/// `secret[i] = (y_a[i] * lambda_a) ^ (y_b[i] * lambda_b)`
pub fn recover_secret_from_2_shares(
    share_a: &ShamirShare,
    share_b: &ShamirShare,
) -> Result<[u8; 32], ShamirError> {
    if share_a.index == 0 || share_b.index == 0 {
        return Err(ShamirError::InvalidShareIndex);
    }
    if share_a.index == share_b.index {
        return Err(ShamirError::DuplicateShareIndex);
    }
    if share_a.crc32 != share_b.crc32 {
        return Err(ShamirError::ChecksumMismatch);
    }

    let diff = share_a.index ^ share_b.index;
    let inv_diff = gf256_inv(diff)?;
    let lambda_a = gf256_mul(share_b.index, inv_diff);
    let lambda_b = gf256_mul(share_a.index, inv_diff);

    let mut secret = [0u8; 32];
    for (i, byte) in secret.iter_mut().enumerate() {
        let term_a = gf256_mul(share_a.data[i], lambda_a);
        let term_b = gf256_mul(share_b.data[i], lambda_b);
        *byte = term_a ^ term_b;
    }

    // Verify CRC32 checksum against original commitment
    let computed_crc = crc32(&secret);
    if computed_crc != share_a.crc32 {
        secret.zeroize();
        return Err(ShamirError::ChecksumMismatch);
    }

    Ok(secret)
}

/// BIP-39 Seed Envelope sealed with a hardware DS/HMAC derived key (`OPP-03`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsHmacSeedEnvelope {
    /// 12-byte initialization nonce.
    pub nonce: [u8; 12],
    /// AES-256-GCM ciphertext concatenated with 16-byte authentication tag.
    pub ciphertext_and_tag: Vec<u8>,
}

impl DsHmacSeedEnvelope {
    /// Seals a BIP-39 seed (typically 32 to 64 bytes) with the hardware DS/HMAC key.
    pub fn seal<R: CryptoRng>(
        seed: &[u8],
        ds_hmac_key: &[u8; 32],
        rng: &mut R,
    ) -> Result<Self, ShamirError> {
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);

        let ciphertext = aes_256_gcm_encrypt(ds_hmac_key, &nonce, seed, DS_HMAC_SEED_AAD)
            .map_err(|_| ShamirError::EncryptionFailed)?;

        Ok(Self {
            nonce,
            ciphertext_and_tag: ciphertext,
        })
    }

    /// Opens the seed envelope, validating integrity with the hardware DS/HMAC key.
    pub fn open(&self, ds_hmac_key: &[u8; 32]) -> Result<Vec<u8>, ShamirError> {
        aes_256_gcm_decrypt(
            ds_hmac_key,
            &self.nonce,
            &self.ciphertext_and_tag,
            DS_HMAC_SEED_AAD,
        )
        .map_err(|_| ShamirError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_gf256_arithmetic() {
        // Test identity
        assert_eq!(gf256_mul(0x57, 1), 0x57);
        assert_eq!(gf256_mul(0, 0x83), 0);

        // Standard AES test vector: 0x57 * 0x13 = 0xFE in GF(2^8)
        assert_eq!(gf256_mul(0x57, 0x13), 0xFE);

        // Inverse test: a * a^-1 == 1 for all non-zero elements
        for val in 1..=255 {
            let inv = gf256_inv(val).expect("inv");
            assert_eq!(gf256_mul(val, inv), 1);
        }

        // Inversion of 0 fails
        assert_eq!(gf256_inv(0), Err(ShamirError::DivisionByZero));
    }

    #[test]
    fn test_shamir_2_of_3_all_combinations_recover_secret() {
        let secret = [0x42u8; 32];
        let entropy_p1 = [0x99u8; 32];

        let shares = split_secret_2_of_3(&secret, &entropy_p1);

        assert_eq!(shares[0].index, 1);
        assert_eq!(shares[1].index, 2);
        assert_eq!(shares[2].index, 3);

        // Combination 1: Share 1 (Primary) + Share 2 (Backup)
        let rec_1_2 = recover_secret_from_2_shares(&shares[0], &shares[1]).expect("rec 1+2");
        assert_eq!(rec_1_2, secret);

        // Combination 2: Share 1 (Primary) + Share 3 (Paper Card)
        let rec_1_3 = recover_secret_from_2_shares(&shares[0], &shares[2]).expect("rec 1+3");
        assert_eq!(rec_1_3, secret);

        // Combination 3: Share 2 (Backup) + Share 3 (Paper Card)
        let rec_2_3 = recover_secret_from_2_shares(&shares[1], &shares[2]).expect("rec 2+3");
        assert_eq!(rec_2_3, secret);
    }

    #[test]
    fn test_shamir_duplicate_share_fails() {
        let secret = [0x77u8; 32];
        let entropy = [0x12u8; 32];
        let shares = split_secret_2_of_3(&secret, &entropy);

        let err = recover_secret_from_2_shares(&shares[0], &shares[0]);
        assert_eq!(err, Err(ShamirError::DuplicateShareIndex));
    }

    #[test]
    fn test_shamir_tampered_share_fails_checksum() {
        let secret = [0x88u8; 32];
        let entropy = [0x34u8; 32];
        let shares = split_secret_2_of_3(&secret, &entropy);

        let mut tampered_share_2 = shares[1].clone();
        tampered_share_2.data[5] ^= 0x01;

        let err = recover_secret_from_2_shares(&shares[0], &tampered_share_2);
        assert_eq!(err, Err(ShamirError::ChecksumMismatch));
    }

    #[test]
    fn test_ds_hmac_seed_envelope_roundtrip() {
        let mut rng = rand::rng();
        let ds_key = [0x5Au8; 32];
        let seed = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let envelope = DsHmacSeedEnvelope::seal(seed, &ds_key, &mut rng).expect("seal");
        assert_ne!(envelope.ciphertext_and_tag.as_slice(), seed);

        let opened = envelope.open(&ds_key).expect("open");
        assert_eq!(opened.as_slice(), seed);

        // Wrong key fails decryption
        let wrong_key = [0x5Bu8; 32];
        let err = envelope.open(&wrong_key);
        assert_eq!(err, Err(ShamirError::DecryptionFailed));
    }
}
