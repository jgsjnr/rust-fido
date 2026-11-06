//! Extended-key serialization codec (Base58check envelope).
//!
//! BEHAVIOR: pure encode/decode for the protocol's 78-byte extended-key
//! payloads and their 111-character Base58check renderings. No derivation
//! here (see [`super::hd`]); this module only moves bytes between the typed
//! [`ExtendedPrivateKey`](super::hd::ExtendedPrivateKey) /
//! [`ExtendedPublicKey`](super::hd::ExtendedPublicKey) nodes and their
//! wire/print form, validating every structural rule fail-closed.
//!
//! The decode half is the trust boundary for imported key material:
//! version bytes, master lineage, key prefixes, curve membership, and the
//! checksum are all verified before a node is rebuilt.

use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::hd::{ExtendedPrivateKey, ExtendedPublicKey, HdError};

/// Serialized extended-key payload length (protocol serialization format).
pub const EXTENDED_KEY_LEN: usize = 78;
/// Base58check encoding length of a serialized extended key.
pub const EXTENDED_KEY_STRLEN: usize = 111;
/// Extended private key version bytes (protocol serialization format).
pub const XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
/// Extended public key version bytes (protocol serialization format).
pub const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];

/// A decoded extended key of either kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedExtendedKey {
    /// A decoded extended private key.
    Private(ExtendedPrivateKey),
    /// A decoded extended public key.
    Public(ExtendedPublicKey),
}

impl ExtendedPrivateKey {
    /// Serializes to the 78-byte protocol payload (private version).
    pub fn to_extended_bytes(&self) -> [u8; EXTENDED_KEY_LEN] {
        let mut secret = self.secret_bytes();
        let mut out = [0u8; EXTENDED_KEY_LEN];
        out[0..4].copy_from_slice(&XPRV_VERSION);
        out[4] = self.depth();
        out[5..9].copy_from_slice(&self.parent_fingerprint());
        out[9..13].copy_from_slice(&self.child_number_raw().to_be_bytes());
        out[13..45].copy_from_slice(&self.chain_code());
        out[45] = 0x00;
        out[46..78].copy_from_slice(&secret);
        secret.zeroize();
        out
    }

    /// Base58check rendering of [`Self::to_extended_bytes`].
    pub fn to_extended_string(&self) -> String {
        base58check_encode(&self.to_extended_bytes())
    }

    /// Decodes a 78-byte protocol payload (validates version, master
    /// lineage, key prefix, and curve range fail-closed).
    pub fn decode_extended(payload: &[u8]) -> Result<Self, HdError> {
        if payload.len() != EXTENDED_KEY_LEN {
            return Err(HdError::InvalidExtendedKey);
        }
        if payload[0..4] != XPRV_VERSION {
            return Err(HdError::InvalidExtendedKey);
        }
        if payload[45] != 0x00 {
            return Err(HdError::InvalidExtendedKey);
        }
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&payload[5..9]);
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&payload[46..78]);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&payload[13..45]);
        Self::from_raw_parts(
            secret,
            chain_code,
            payload[4],
            parent_fingerprint,
            u32::from_be_bytes([payload[9], payload[10], payload[11], payload[12]]),
        )
    }
}

impl ExtendedPublicKey {
    /// Serializes to the 78-byte protocol payload (public version).
    pub fn to_extended_bytes(&self) -> [u8; EXTENDED_KEY_LEN] {
        let mut out = [0u8; EXTENDED_KEY_LEN];
        out[0..4].copy_from_slice(&XPUB_VERSION);
        out[4] = self.depth();
        out[5..9].copy_from_slice(&self.parent_fingerprint());
        out[9..13].copy_from_slice(&self.child_number_raw().to_be_bytes());
        out[13..45].copy_from_slice(&self.chain_code());
        out[45..78].copy_from_slice(&self.public_key_compressed());
        out
    }

    /// Base58check rendering of [`Self::to_extended_bytes`].
    pub fn to_extended_string(&self) -> String {
        base58check_encode(&self.to_extended_bytes())
    }

    /// Decodes a 78-byte protocol payload (validates version, master
    /// lineage, point prefix, and curve membership fail-closed).
    pub fn decode_extended(payload: &[u8]) -> Result<Self, HdError> {
        if payload.len() != EXTENDED_KEY_LEN {
            return Err(HdError::InvalidExtendedKey);
        }
        if payload[0..4] != XPUB_VERSION {
            return Err(HdError::InvalidExtendedKey);
        }
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&payload[5..9]);
        let mut public_key = [0u8; 33];
        public_key.copy_from_slice(&payload[45..78]);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&payload[13..45]);
        Self::from_raw_parts(
            public_key,
            chain_code,
            payload[4],
            parent_fingerprint,
            u32::from_be_bytes([payload[9], payload[10], payload[11], payload[12]]),
        )
    }
}

/// Base58check-encodes a 78-byte extended-key payload (double-SHA256
/// checksum, protocol serialization format).
pub fn base58check_encode(payload: &[u8; EXTENDED_KEY_LEN]) -> String {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    let mut enveloped = Vec::with_capacity(EXTENDED_KEY_LEN + 4);
    enveloped.extend_from_slice(payload);
    enveloped.extend_from_slice(&second[..4]);
    bs58::encode(enveloped).into_string()
}

/// Decodes a Base58check extended-key string of either kind. Rejects
/// fail-closed: bad alphabet/length, checksum mismatch, unknown version,
/// structural violations (see `decode_extended` on either key type).
pub fn decode_extended_key(encoded: &str) -> Result<DecodedExtendedKey, HdError> {
    if encoded.len() != EXTENDED_KEY_STRLEN {
        return Err(HdError::InvalidEncoding);
    }
    let raw = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| HdError::InvalidEncoding)?;
    if raw.len() != EXTENDED_KEY_LEN + 4 {
        return Err(HdError::InvalidEncoding);
    }
    let mut payload = [0u8; EXTENDED_KEY_LEN];
    payload.copy_from_slice(&raw[..EXTENDED_KEY_LEN]);
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    if raw[EXTENDED_KEY_LEN..] != second[..4] {
        return Err(HdError::InvalidEncoding);
    }
    match [payload[0], payload[1], payload[2], payload[3]] {
        XPRV_VERSION => Ok(DecodedExtendedKey::Private(
            ExtendedPrivateKey::decode_extended(&payload)?,
        )),
        XPUB_VERSION => Ok(DecodedExtendedKey::Public(
            ExtendedPublicKey::decode_extended(&payload)?,
        )),
        _ => Err(HdError::InvalidExtendedKey),
    }
}

#[cfg(test)]
mod tests {
    use super::super::hd::ExtendedPrivateKey;
    use super::super::hd_paths::DerivationPath;
    use super::*;

    fn vector_master() -> ExtendedPrivateKey {
        ExtendedPrivateKey::master_from_seed(
            &hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn should_dispatch_private_and_public_on_version_and_roundtrip() {
        let node = vector_master()
            .derive_path(&"m/0'/1".parse::<DerivationPath>().unwrap())
            .unwrap();
        match decode_extended_key(&node.to_extended_string()).unwrap() {
            DecodedExtendedKey::Private(back) => {
                assert_eq!(back.to_extended_bytes(), node.to_extended_bytes())
            }
            DecodedExtendedKey::Public(_) => panic!("xprv must decode as private"),
        }
        match decode_extended_key(&node.neutered().to_extended_string()).unwrap() {
            DecodedExtendedKey::Public(back) => {
                assert_eq!(
                    back.to_extended_bytes(),
                    node.neutered().to_extended_bytes()
                )
            }
            DecodedExtendedKey::Private(_) => panic!("xpub must decode as public"),
        }
    }

    #[test]
    fn should_reject_bad_envelope_before_any_crypto() {
        // Wrong length, bad alphabet, and truncated input never reach
        // checksum or curve validation.
        assert!(decode_extended_key("").is_err());
        assert!(decode_extended_key("xpub661MyMwAqRbcFtXgS5sYJABqqG9").is_err());
        assert!(decode_extended_key(&" ".repeat(EXTENDED_KEY_STRLEN)).is_err());
        // Payload-level decode rejects short buffers and wrong versions.
        assert!(ExtendedPrivateKey::decode_extended(&[0u8; 10]).is_err());
        assert!(ExtendedPublicKey::decode_extended(&[0u8; 10]).is_err());
        let mut payload = vector_master().to_extended_bytes();
        payload[0..4].copy_from_slice(&XPUB_VERSION);
        assert!(ExtendedPrivateKey::decode_extended(&payload).is_err());
    }
}
