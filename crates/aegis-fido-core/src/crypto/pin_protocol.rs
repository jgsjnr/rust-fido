use alloc::vec::Vec;
use crate::crypto::aes_cbc::{aes_256_cbc_decrypt, aes_256_cbc_encrypt};
use crate::crypto::hash::{hkdf_sha256, hmac_sha256, sha256};

pub fn pad_pin(pin: &[u8]) -> Result<[u8; 64], &'static str> {
    if pin.len() < 4 || pin.len() > 63 {
        return Err("PIN length must be between 4 and 63 bytes");
    }
    let mut padded = [0u8; 64];
    padded[..pin.len()].copy_from_slice(pin);
    Ok(padded)
}

pub fn pin_hash(pin: &[u8]) -> [u8; 16] {
    let full = sha256(pin);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

pub struct PinProtocol1;

impl PinProtocol1 {
    pub const VERSION: u32 = 1;

    pub fn kdf(z: &[u8; 32]) -> [u8; 32] {
        sha256(z)
    }

    pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let iv = [0u8; 16];
        aes_256_cbc_encrypt(key, &iv, plaintext)
    }

    pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let iv = [0u8; 16];
        aes_256_cbc_decrypt(key, &iv, ciphertext)
    }

    pub fn authenticate(key: &[u8], message: &[u8]) -> [u8; 16] {
        let mac = hmac_sha256(key, message);
        let mut out = [0u8; 16];
        out.copy_from_slice(&mac[..16]);
        out
    }
}

pub struct PinProtocol2;

impl PinProtocol2 {
    pub const VERSION: u32 = 2;

    pub fn kdf(z: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let salt = [0u8; 32];
        let e_vec = hkdf_sha256(&salt, z, b"CTAP2 AES key", 32);
        let m_vec = hkdf_sha256(&salt, z, b"CTAP2 HMAC key", 32);

        let mut e_ks = [0u8; 32];
        let mut m_ks = [0u8; 32];
        e_ks.copy_from_slice(&e_vec);
        m_ks.copy_from_slice(&m_vec);
        (e_ks, m_ks)
    }

    pub fn encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + plaintext.len());
        out.extend_from_slice(iv);
        out.extend_from_slice(&aes_256_cbc_encrypt(key, iv, plaintext));
        out
    }

    pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < 32 || (ciphertext.len() - 16) % 16 != 0 {
            return Err("Invalid ciphertext length for Protocol 2");
        }
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&ciphertext[..16]);
        aes_256_cbc_decrypt(key, &iv, &ciphertext[16..])
    }

    pub fn authenticate(key: &[u8], message: &[u8]) -> [u8; 32] {
        hmac_sha256(key, message)
    }
}

