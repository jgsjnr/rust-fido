use alloc::string::String;
use alloc::vec::Vec;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand_core::{CryptoRng, RngCore};
use crate::credential::record::CredentialRecord;
use crate::crypto::hash::sha256;
use zeroize::Zeroize;

const CRED_WRAP_VERSION: u8 = 0x01;

pub struct CredentialWrapper {
    master_key: [u8; 32],
}

impl CredentialWrapper {
    pub fn new(master_key: [u8; 32]) -> Self {
        Self { master_key }
    }

    /// Wraps a non-resident credential into an encrypted credential ID
    pub fn wrap<R: RngCore + CryptoRng>(
        &self,
        record: &CredentialRecord,
        rng: &mut R,
    ) -> Result<Vec<u8>, &'static str> {
        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|_| "Failed to create AES-GCM cipher")?;

        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let rp_id_hash = sha256(record.rp_id.as_bytes());

        // Plaintext payload:
        // [32 bytes: rp_id_hash]
        // [4 bytes: algorithm (i32 big-endian)]
        // [32 bytes: hmac_secret_key (or zeros)]
        // [1 byte: has_cred_protect] + [1 byte: cred_protect value]
        // [2 bytes: user_id len] + [user_id bytes]
        // [2 bytes: priv_key len] + [private_key bytes]
        // [2 bytes: pub_cose len] + [pub_cose bytes]
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&rp_id_hash);
        plaintext.extend_from_slice(&record.algorithm.to_be_bytes());
        plaintext.extend_from_slice(&record.hmac_secret_key.unwrap_or([0u8; 32]));

        if let Some(cp) = record.cred_protect {
            plaintext.push(1);
            plaintext.push(cp);
        } else {
            plaintext.push(0);
            plaintext.push(0);
        }

        plaintext.extend_from_slice(&(record.user_id.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(&record.user_id);

        plaintext.extend_from_slice(&(record.private_key.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(&record.private_key);

        plaintext.extend_from_slice(&(record.public_key_cose.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(&record.public_key_cose);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| {
                plaintext.zeroize();
                "AES-GCM encryption failed"
            })?;

        let mut wrapped_id = Vec::with_capacity(1 + 12 + ciphertext.len());
        wrapped_id.push(CRED_WRAP_VERSION);
        wrapped_id.extend_from_slice(&nonce_bytes);
        wrapped_id.extend_from_slice(&ciphertext);

        plaintext.zeroize();

        Ok(wrapped_id)
    }

    /// Unwraps an encrypted credential ID into a CredentialRecord
    pub fn unwrap(&self, cred_id: &[u8], rp_id: &str, stored_sign_count: u32) -> Result<CredentialRecord, &'static str> {
        if cred_id.len() < 1 + 12 + 16 {
            return Err("Credential ID too short");
        }
        if cred_id[0] != CRED_WRAP_VERSION {
            return Err("Unknown credential wrap version");
        }

        let nonce_bytes = &cred_id[1..13];
        let ciphertext = &cred_id[13..];

        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|_| "Failed to initialize AES-GCM cipher")?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let mut plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "AES-GCM decryption failed")?;

        if plaintext.len() < 32 + 4 + 32 + 2 + 2 + 2 {
            plaintext.zeroize();
            return Err("Unwrapped plaintext is corrupted or truncated");
        }

        let mut offset = 0;
        let mut stored_rp_id_hash = [0u8; 32];
        stored_rp_id_hash.copy_from_slice(&plaintext[offset..offset + 32]);
        offset += 32;

        let expected_rp_id_hash = sha256(rp_id.as_bytes());
        if stored_rp_id_hash != expected_rp_id_hash {
            plaintext.zeroize();
            return Err("RP ID mismatch");
        }

        let alg_bytes: [u8; 4] = match plaintext[offset..offset + 4].try_into() {
            Ok(b) => b,
            Err(_) => {
                plaintext.zeroize();
                return Err("Invalid algorithm field");
            }
        };
        let algorithm = i32::from_be_bytes(alg_bytes);
        offset += 4;

        let mut hmac_secret = [0u8; 32];
        hmac_secret.copy_from_slice(&plaintext[offset..offset + 32]);
        let hmac_secret_key = if hmac_secret == [0u8; 32] {
            None
        } else {
            Some(hmac_secret)
        };
        offset += 32;

        let has_cred_protect = plaintext[offset] == 1;
        let cred_protect = if has_cred_protect {
            Some(plaintext[offset + 1])
        } else {
            None
        };
        offset += 2;

        let user_id_len = u16::from_be_bytes(match plaintext[offset..offset + 2].try_into() {
            Ok(b) => b,
            Err(_) => {
                plaintext.zeroize();
                hmac_secret.zeroize();
                return Err("Corrupted user_id length");
            }
        }) as usize;
        offset += 2;
        if offset + user_id_len > plaintext.len() {
            plaintext.zeroize();
            hmac_secret.zeroize();
            return Err("Corrupted user_id length");
        }
        let mut user_id = plaintext[offset..offset + user_id_len].to_vec();
        offset += user_id_len;

        let priv_len = u16::from_be_bytes(match plaintext[offset..offset + 2].try_into() {
            Ok(b) => b,
            Err(_) => {
                plaintext.zeroize();
                hmac_secret.zeroize();
                user_id.zeroize();
                return Err("Corrupted private_key length");
            }
        }) as usize;
        offset += 2;
        if offset + priv_len > plaintext.len() {
            plaintext.zeroize();
            hmac_secret.zeroize();
            user_id.zeroize();
            return Err("Corrupted private_key length");
        }
        let mut private_key = plaintext[offset..offset + priv_len].to_vec();
        offset += priv_len;

        let pub_len = u16::from_be_bytes(match plaintext[offset..offset + 2].try_into() {
            Ok(b) => b,
            Err(_) => {
                plaintext.zeroize();
                hmac_secret.zeroize();
                user_id.zeroize();
                private_key.zeroize();
                return Err("Corrupted public_key_cose length");
            }
        }) as usize;
        offset += 2;
        if offset + pub_len > plaintext.len() {
            plaintext.zeroize();
            hmac_secret.zeroize();
            user_id.zeroize();
            private_key.zeroize();
            return Err("Corrupted public_key_cose length");
        }
        let public_key_cose = plaintext[offset..offset + pub_len].to_vec();
        plaintext.zeroize();
        hmac_secret.zeroize();

        Ok(CredentialRecord {
            id: cred_id.to_vec(),
            rp_id: String::from(rp_id),
            rp_name: None,
            user_id,
            user_name: None,
            user_display_name: None,
            algorithm,
            private_key,
            public_key_cose,
            sign_count: stored_sign_count,
            is_resident: false,
            created_at: 0,
            expires_at: None,
            is_revoked: false,
            cred_protect,
            large_blob_key: None,
            cred_blob: None,
            hmac_secret_key,
        })
    }
}


