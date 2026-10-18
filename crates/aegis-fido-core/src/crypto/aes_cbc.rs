use alloc::vec::Vec;
use aes::Aes256;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

pub fn aes_256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    assert_eq!(plaintext.len() % 16, 0, "Plaintext length must be multiple of 16");
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut prev_block = *iv;

    for chunk in plaintext.chunks(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ prev_block[i];
        }
        let mut generic_block = GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut generic_block);
        prev_block.copy_from_slice(generic_block.as_slice());
        ciphertext.extend_from_slice(&prev_block);
    }

    ciphertext
}

pub fn aes_256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ciphertext.len() % 16 != 0 {
        return Err("Ciphertext length must be multiple of 16");
    }
    let cipher = Aes256::new(GenericArray::from_slice(key));
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
