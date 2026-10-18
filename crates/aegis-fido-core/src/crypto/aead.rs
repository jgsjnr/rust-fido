//! Authenticated Encryption with Associated Data (AEAD) via AES-256-GCM.
//!
//! 100% Native Rust implementation conforming to NIST SP 800-38D.
//! Used for sealing credentials, passkeys, master seeds, and secure blobs.

use alloc::vec::Vec;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use rand_core::{CryptoRng, RngCore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidKeyLength,
    InvalidNonceLength,
    CiphertextTooShort,
}

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "AES-256-GCM encryption failed"),
            Self::DecryptionFailed => write!(f, "AES-256-GCM decryption failed (integrity/auth check failed)"),
            Self::InvalidKeyLength => write!(f, "Invalid AES-256 key length: expected 32 bytes"),
            Self::InvalidNonceLength => write!(f, "Invalid nonce length: expected 12 bytes"),
            Self::CiphertextTooShort => write!(f, "Sealed blob payload too short (must contain at least 12-byte nonce + 16-byte auth tag)"),
        }
    }
}

/// Encrypts `plaintext` with AES-256-GCM using `key` (32 bytes), `nonce` (12 bytes), and optional `aad`.
/// Returns ciphertext appended with 16-byte authentication tag.
pub fn aes_256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_arr = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce_arr, Payload { msg: plaintext, aad })
        .map_err(|_| AeadError::EncryptionFailed)
}

/// Decrypts `ciphertext_and_tag` with AES-256-GCM using `key` (32 bytes), `nonce` (12 bytes), and optional `aad`.
/// Verifies the 16-byte authentication tag in constant time.
pub fn aes_256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_arr = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce_arr, Payload { msg: ciphertext_and_tag, aad })
        .map_err(|_| AeadError::DecryptionFailed)
}

/// Convenience envelope: Generates random 12-byte nonce, encrypts `plaintext` with AES-256-GCM,
/// and returns `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
pub fn seal_blob<R: RngCore + CryptoRng>(
    master_key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, AeadError> {
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);

    let ciphertext = aes_256_gcm_encrypt(master_key, &nonce, plaintext, aad)?;
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Convenience envelope: Extracts 12-byte nonce and decrypts `nonce || ciphertext || tag`.
pub fn open_blob(
    master_key: &[u8; 32],
    payload: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if payload.len() < 12 + 16 {
        return Err(AeadError::CiphertextTooShort);
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&payload[..12]);
    let ciphertext_and_tag = &payload[12..];

    aes_256_gcm_decrypt(master_key, &nonce, ciphertext_and_tag, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_256_gcm_seal_open_roundtrip() {
        let mut rng = rand::rngs::OsRng;
        let master_key = [0x42u8; 32];
        let secret_data = b"AegisKey Secret Hardware Master Seed Payload 2026";
        let aad = b"Aegis-Vault-Header-v1";

        // Seal blob
        let blob = seal_blob(&master_key, secret_data, aad, &mut rng).unwrap();
        assert_eq!(blob.len(), 12 + secret_data.len() + 16);

        // Open blob
        let decrypted = open_blob(&master_key, &blob, aad).unwrap();
        assert_eq!(decrypted, secret_data);

        // Tamper with ciphertext -> authentication failure
        let mut corrupted_blob = blob.clone();
        corrupted_blob[15] ^= 0x01;
        assert_eq!(
            open_blob(&master_key, &corrupted_blob, aad),
            Err(AeadError::DecryptionFailed)
        );

        // Tamper with AAD -> authentication failure
        let wrong_aad = b"Wrong-Vault-Header";
        assert_eq!(
            open_blob(&master_key, &blob, wrong_aad),
            Err(AeadError::DecryptionFailed)
        );

        // Wrong master key -> authentication failure
        let wrong_key = [0x99u8; 32];
        assert_eq!(
            open_blob(&wrong_key, &blob, aad),
            Err(AeadError::DecryptionFailed)
        );
    }

    #[test]
    fn test_aes_256_gcm_nist_test_vector() {
        // NIST SP 800-38D Test Case:
        let key = hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308").unwrap();
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key);

        let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&nonce);

        let plaintext = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();
        let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();

        let expected_ciphertext = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
        let expected_tag = "76fc6ece0f4e1768cddf8853bb2d551b";

        let encrypted = aes_256_gcm_encrypt(&key_arr, &nonce_arr, &plaintext, &aad).unwrap();
        let ct_hex = hex::encode(&encrypted[..encrypted.len() - 16]);
        let tag_hex = hex::encode(&encrypted[encrypted.len() - 16..]);

        assert_eq!(ct_hex, expected_ciphertext);
        assert_eq!(tag_hex, expected_tag);

        let decrypted = aes_256_gcm_decrypt(&key_arr, &nonce_arr, &encrypted, &aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
