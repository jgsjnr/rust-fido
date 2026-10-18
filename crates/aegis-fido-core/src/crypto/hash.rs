use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// HKDF-SHA-256 extract and expand per RFC 5869
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    // 1. Extract: PRK = HMAC-Hash(salt, IKM)
    let prk = hmac_sha256(salt, ikm);

    // 2. Expand: T(1) = HMAC-Hash(PRK, info || 0x01), etc.
    let mut okm = Vec::with_capacity(len);
    let mut t_prev = Vec::new();
    let mut counter: u8 = 1;

    while okm.len() < len {
        let mut msg = Vec::new();
        msg.extend_from_slice(&t_prev);
        msg.extend_from_slice(info);
        msg.push(counter);

        let t_curr = hmac_sha256(&prk, &msg);
        let needed = len - okm.len();
        let to_take = needed.min(32);
        okm.extend_from_slice(&t_curr[..to_take]);

        t_prev = t_curr.to_vec();
        counter = counter.checked_add(1).expect("HKDF counter overflow");
    }

    okm
}
