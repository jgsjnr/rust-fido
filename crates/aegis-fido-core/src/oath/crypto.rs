extern crate alloc;

use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// Constant-time byte slice comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

use super::types::OathAlgorithm;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Compute HMAC using the specified algorithm
pub fn compute_hmac(algo: OathAlgorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
    match algo {
        OathAlgorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        OathAlgorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        OathAlgorithm::Sha512 => {
            let mut mac = HmacSha512::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// Dynamic truncation according to RFC 4226 (HOTP) / RFC 6238 (TOTP)
pub fn calculate_code(algo: OathAlgorithm, secret: &[u8], counter_or_challenge: u64, digits: u8) -> u32 {
    let counter_bytes = counter_or_challenge.to_be_bytes();
    let digest = compute_hmac(algo, secret, &counter_bytes);
    truncate_digest(&digest, digits)
}

/// Calculate code directly from an arbitrary challenge byte slice (typically 8 bytes big-endian)
pub fn calculate_code_from_challenge(algo: OathAlgorithm, secret: &[u8], challenge: &[u8], digits: u8) -> u32 {
    let digest = compute_hmac(algo, secret, challenge);
    truncate_digest(&digest, digits)
}

/// Perform dynamic truncation on HMAC digest
pub fn truncate_digest(digest: &[u8], digits: u8) -> u32 {
    if digest.is_empty() {
        return 0;
    }
    let offset = (digest[digest.len() - 1] & 0x0F) as usize;
    if offset + 4 > digest.len() {
        return 0;
    }

    let binary = (((digest[offset] & 0x7F) as u32) << 24)
        | (((digest[offset + 1] & 0xFF) as u32) << 16)
        | (((digest[offset + 2] & 0xFF) as u32) << 8)
        | ((digest[offset + 3] & 0xFF) as u32);

    let d = match digits {
        6 => 1_000_000,
        7 => 10_000_000,
        8 => 100_000_000,
        _ => 1_000_000,
    };

    binary % d
}

/// Pure-Rust PBKDF2 with HMAC-SHA1 according to RFC 2898 / RFC 8018
pub fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, output_len: usize) -> Vec<u8> {
    let mut derived = Vec::with_capacity(output_len);
    let mut block_index: u32 = 1;

    while derived.len() < output_len {
        let mut u = {
            let mut mac = HmacSha1::new_from_slice(password).expect("HMAC key");
            mac.update(salt);
            mac.update(&block_index.to_be_bytes());
            mac.finalize().into_bytes().to_vec()
        };

        let mut t = u.clone();

        for _ in 1..iterations {
            let mut mac = HmacSha1::new_from_slice(password).expect("HMAC key");
            mac.update(&u);
            u = mac.finalize().into_bytes().to_vec();

            for (t_byte, u_byte) in t.iter_mut().zip(u.iter()) {
                *t_byte ^= *u_byte;
            }
        }

        let needed = output_len - derived.len();
        if needed < t.len() {
            derived.extend_from_slice(&t[..needed]);
        } else {
            derived.extend_from_slice(&t);
        }

        block_index += 1;
    }

    derived
}

/// Constant-time authentication response verification
pub fn verify_challenge_response(key: &[u8], challenge: &[u8], expected_response: &[u8]) -> bool {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC key");
    mac.update(challenge);
    let computed = mac.finalize().into_bytes();
    constant_time_eq(&computed, expected_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc4226_hotp() {
        // RFC 4226 Section 5.4 Test vectors for HMAC-SHA1 HOTP
        let secret = b"12345678901234567890";
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];

        for (counter, &exp) in expected.iter().enumerate() {
            let code = calculate_code(OathAlgorithm::Sha1, secret, counter as u64, 6);
            assert_eq!(code, exp, "HOTP mismatch at counter {}", counter);
        }
    }

    #[test]
    fn test_rfc6238_totp_sha256_sha512() {
        // RFC 6238 Section 8 test vector
        let secret_sha256 = b"12345678901234567890123456789012";
        // Time = 59s, T0 = 0, X = 30 -> T = 1
        let code_sha256 = calculate_code(OathAlgorithm::Sha256, secret_sha256, 1, 8);
        assert_eq!(code_sha256, 46119246);

        let secret_sha512 = b"1234567890123456789012345678901234567890123456789012345678901234";
        let code_sha512 = calculate_code(OathAlgorithm::Sha512, secret_sha512, 1, 8);
        assert_eq!(code_sha512, 90693936);
    }

    #[test]
    fn test_pbkdf2_sha1() {
        // RFC 6070 Test Vector 1:
        // P = "password", S = "salt", c = 1, dkLen = 20
        // DK = 0c 60 c8 0f 96 1f 0e 71 f3 a9 b5 24 af 60 12 06 2f e0 37 a6
        let res = pbkdf2_sha1(b"password", b"salt", 1, 20);
        let expected = hex::decode("0c60c80f961f0e71f3a9b524af6012062fe037a6").unwrap();
        assert_eq!(res, expected);

        // RFC 6070 Test Vector 2:
        // P = "password", S = "salt", c = 2, dkLen = 20
        // DK = ea 6c 01 4d c7 2d 6f 8c cd 1e d9 2a ce 1d 41 f0 d8 de 89 57
        let res2 = pbkdf2_sha1(b"password", b"salt", 2, 20);
        let expected2 = hex::decode("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957").unwrap();
        assert_eq!(res2, expected2);
    }
}
