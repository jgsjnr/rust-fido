pub mod aead;
pub mod aes_cbc;
pub mod bip39;
pub mod core;
pub mod cose;
pub mod curves;
pub mod ecdh;
pub mod hash;
pub mod kdf;
pub mod keys;
pub mod pin_protocol;

pub use aead::{aes_256_gcm_decrypt, aes_256_gcm_encrypt, open_blob, seal_blob, AeadError};
pub use bip39::{Bip39Error, Mnemonic24};
pub use curves::{CoseAlgorithm, KeyPair, PublicKey};

pub use aes_cbc::{aes_256_cbc_decrypt, aes_256_cbc_encrypt};
pub use core::CryptoCore;
pub use cose::{
    CoseKey, COSE_ALG_EDDSA, COSE_ALG_ES256, COSE_ALG_ES256K, COSE_ALG_ES384, COSE_ALG_ES512,
};
pub use ecdh::EcdhKeyAgreement;
pub use hash::{hkdf_sha256, hmac_sha256, sha256, sha512};
pub use keys::FidoKeyPair;
pub use pin_protocol::{pad_pin, pin_hash, PinProtocol1, PinProtocol2};
