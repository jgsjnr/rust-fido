//! Pure CryptoCore facade: re-exports existing AEAD/KDF/ECDH/COSE.
//!
//! No duplication: all logic lives in `aead`, `kdf`, `ecdh`, `cose`,
//! `hash`, `keys`, `curves`. This module only re-exports and provides
//! the `CryptoCore` marker for L2 audit boundaries (CBOR/USB/frames preserved).

pub use super::aead::{aes_256_gcm_decrypt, aes_256_gcm_encrypt, open_blob, seal_blob, AeadError};
pub use super::cose::{CoseKey, COSE_ALG_EDDSA, COSE_ALG_ES256, COSE_ALG_ES256K, COSE_ALG_ES384, COSE_ALG_ES512};
pub use super::ecdh::EcdhKeyAgreement;
pub use super::hash::{hkdf_sha256, hmac_sha256, sha256, sha512};
pub use super::kdf::{evaluate_prf, hkdf_expand, hkdf_extract, hkdf_sha256 as kdf_hkdf_sha256, KdfError};

/// Pure cryptographic core marker.
///
/// Stateless facade; all operations delegate to existing free functions.
/// Use `CryptoCore` as a namespace bound in future refactors without
/// duplicating primitives.
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoCore;

impl CryptoCore {
    /// SHA-256 helper delegating to existing `hash::sha256`.
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        super::hash::sha256(data)
    }

    /// HKDF-SHA256 helper delegating to existing `kdf::hkdf_sha256`.
    pub fn hkdf(
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<alloc::vec::Vec<u8>, KdfError> {
        super::kdf::hkdf_sha256(salt, ikm, info, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reexports_match_existing() {
        let h1 = sha256(b"abc");
        let h2 = CryptoCore::sha256(b"abc");
        assert_eq!(h1, h2);
        let okm = CryptoCore::hkdf(b"s", b"ikm", b"i", 32).unwrap();
        assert_eq!(okm.len(), 32);
        // COSE constants preserved
        assert_eq!(COSE_ALG_ES256, -7);
        // ECDH type available without duplication
        fn _takes(_: Option<EcdhKeyAgreement>) {}
    }
}
