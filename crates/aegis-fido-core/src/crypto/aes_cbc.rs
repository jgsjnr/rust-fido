#![allow(deprecated)] // RustCrypto 0.14 deprecated re-export; upgrade to generic-array 1.x needs major bump (out of scope), behavior identical.
use aes::Aes256;
use alloc::vec::Vec;
// RustCrypto 0.8/0.10 still pins generic-array 0.14 (deprecated re-export).
// Full upgrade to generic-array 1.x requires major bump of aes/p256/aes-gcm — out of scope.
// Key init migrated to current KeyInit::new_from_slice API; block handling keeps
// 0.14 via allow(deprecated) with identical behavior (no semantic change).
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

pub fn aes_256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    assert_eq!(
        plaintext.len() % 16,
        0,
        "Plaintext length must be multiple of 16"
    );
    let cipher = Aes256::new_from_slice(key).expect("AES-256 key is always 32 bytes");
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut prev_block = *iv;

    for chunk in plaintext.chunks(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ prev_block[i];
        }
        let mut generic_block = GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut generic_block);
        prev_block.copy_from_slice(generic_block.as_ref());
        ciphertext.extend_from_slice(&prev_block);
    }

    ciphertext
}

pub fn aes_256_cbc_decrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if !ciphertext.len().is_multiple_of(16) {
        return Err("Ciphertext length must be multiple of 16");
    }
    let cipher = Aes256::new_from_slice(key).expect("AES-256 key is always 32 bytes");
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut prev_block = *iv;

    for chunk in ciphertext.chunks(16) {
        let mut generic_block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut generic_block);
        let mut plain_block = [0u8; 16];
        for i in 0..16 {
            plain_block[i] = generic_block[i] ^ prev_block[i];
        }
        prev_block.copy_from_slice(chunk);
        plaintext.extend_from_slice(&plain_block);
    }

    Ok(plaintext)
}
