//! Key Derivation Functions (HKDF-SHA256, HMAC-SHA256, PRF)
//!
//! 100% native Rust implementation adhering to RFC 5869 and CTAP2 PRF extension.

use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha2::Sha256;

extern crate alloc;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfError {
    InvalidOutputLength,
    InvalidKeyLength,
}

impl core::fmt::Display for KdfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidOutputLength => write!(
                f,
                "Requested HKDF output length exceeds maximum (255 * HashLen)"
            ),
            Self::InvalidKeyLength => write!(f, "Invalid HMAC key length"),
        }
    }
}

/// Computes HMAC-SHA256 of data using the given key.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC can take key of any length");
    mac.update(data);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// HKDF-Extract(salt, IKM) -> PRK (RFC 5869 Section 2.2)
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let default_salt = [0u8; 32];
    let actual_salt = if salt.is_empty() {
        &default_salt[..]
    } else {
        salt
    };
    hmac_sha256(actual_salt, ikm)
}

/// HKDF-Expand(PRK, info, L) -> OKM (RFC 5869 Section 2.3)
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Result<Vec<u8>, KdfError> {
    if length > 255 * 32 {
        return Err(KdfError::InvalidOutputLength);
    }
    if length == 0 {
        return Ok(Vec::new());
    }

    let n = length.div_ceil(32);
    let mut okm = Vec::with_capacity(n * 32);
    let mut t: Vec<u8> = Vec::new();

    for i in 1..=n {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(prk).map_err(|_| KdfError::InvalidKeyLength)?;
        mac.update(&t);
        mac.update(info);
        mac.update(&[i as u8]);
        let step_res = mac.finalize().into_bytes();
        t.clear();
        t.extend_from_slice(&step_res);
        okm.extend_from_slice(&step_res);
    }

    okm.truncate(length);
    Ok(okm)
}

/// Full HKDF-SHA256 (Extract + Expand)
pub fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, KdfError> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}

/// CTAP2 PRF / hmac-secret evaluation: HMAC-SHA256(key, salt)
pub fn evaluate_prf(key: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    hmac_sha256(key, salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc5869_test_case_1() {
        // RFC 5869 Test Case 1:
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let l = 42;

        let expected_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
        let expected_okm =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(hex::encode(prk), expected_prk);

        let okm = hkdf_expand(&prk, &info, l).unwrap();
        assert_eq!(hex::encode(&okm), expected_okm);

        let full_okm = hkdf_sha256(&salt, &ikm, &info, l).unwrap();
        assert_eq!(hex::encode(&full_okm), expected_okm);
    }
}
