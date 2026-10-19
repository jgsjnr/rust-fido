//! Pure address derivation from existing public keys.
//!
//! BEHAVIOR: encodings only — no private material is touched (inputs are
//! public keys / public encodings). Bitcoin P2WPKH follows BIP-173
//! (`bech32("bc", v0, RIPEMD160(SHA256(compressed secp256k1)))`, SHA256
//! reused from `crate::crypto::hash`); Ethereum follows EIP-55
//! (`keccak256(x||y)[12..32]` with checksum-case); Solana is the base58 of
//! the 32-byte Ed25519 public key. A curve that does not belong to the
//! requested network maps to [`KeyManagerError::BadEnvelope`] so the 9.5
//! closed status set stays intact (no new wire status).

use alloc::string::String;

use ripemd::Ripemd160;
use sha3::{Digest, Keccak256};

use super::types::CryptoNetwork;
use crate::credential::KeyManagerError;
use crate::crypto::hash::sha256;
use crate::crypto::PublicKey;

/// Keccak-256 output bytes skipped to keep the last 20 (EVM address length).
const EVM_ADDRESS_SKIP: usize = 12;
/// EIP-55: checksum-case bit — hash nibble at or above this uppercases the letter.
const EIP55_UPPER_NIBBLE: u8 = 8;

/// Derives a mainnet P2WPKH (BIP-173 segwit v0) address from a 33-byte
/// compressed secp256k1 public key.
pub fn bitcoin_p2wpkh_address(compressed_sec1: &[u8; 33]) -> String {
    let hash160 = Ripemd160::digest(sha256(compressed_sec1));
    // 20-byte v0 program with a const HRP always satisfies the encoder's
    // validity checks; failure here would be a bech32-crate bug.
    bech32::segwit::encode_v0(bech32::hrp::BC, &hash160)
        .expect("const-HRP v0 encode of a 20-byte program never fails")
}

/// Derives an EIP-55 checksummed address from a 64-byte uncompressed
/// secp256k1 public key (`x || y`, no `0x04` prefix).
pub fn ethereum_address(uncompressed_64: &[u8; 64]) -> String {
    let hash = Keccak256::digest(uncompressed_64);
    let lower = hex::encode(&hash[EVM_ADDRESS_SKIP..32]);
    let checksum_source = Keccak256::digest(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.bytes().enumerate() {
        let nibble = if i % 2 == 0 {
            checksum_source[i / 2] >> 4
        } else {
            checksum_source[i / 2] & 0x0f
        };
        if c.is_ascii_alphabetic() && nibble >= EIP55_UPPER_NIBBLE {
            out.push(c.to_ascii_uppercase() as char);
        } else {
            out.push(c as char);
        }
    }
    out
}

/// Derives a Solana address (base58 of the 32-byte Ed25519 public key).
pub fn solana_address(pubkey_bytes: &[u8; 32]) -> String {
    bs58::encode(pubkey_bytes).into_string()
}

/// Derives the [`CryptoNetwork`] address for an existing [`PublicKey`].
/// Wrong-curve-for-network (including P-256/P-384/P-521, which have no
/// wallet network) maps to [`KeyManagerError::BadEnvelope`].
pub fn address_for_public_key(
    pubkey: &PublicKey,
    network: CryptoNetwork,
) -> Result<String, KeyManagerError> {
    match (pubkey, network) {
        (PublicKey::K256(vk), CryptoNetwork::Bitcoin) => {
            let mut compressed = [0u8; 33];
            compressed.copy_from_slice(vk.to_encoded_point(true).as_bytes());
            Ok(bitcoin_p2wpkh_address(&compressed))
        }
        (PublicKey::K256(vk), CryptoNetwork::EthereumEvm) => {
            let mut raw = [0u8; 64];
            raw.copy_from_slice(&vk.to_encoded_point(false).as_bytes()[1..65]);
            Ok(ethereum_address(&raw))
        }
        (PublicKey::Ed25519(vk), CryptoNetwork::Solana) => {
            Ok(solana_address(&vk.to_bytes()))
        }
        _ => Err(KeyManagerError::BadEnvelope),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curves::CoseAlgorithm;
    use crate::crypto::{KeyPair, PublicKey};

    /// secp256k1 generator G (private key = 1): BIP-173 reference vector.
    const G_COMPRESSED: [u8; 33] = [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];
    /// Uncompressed G without prefix (x || y, 64 bytes).
    const G_UNCOMPRESSED_64: [u8; 64] = [
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8,
        0x17, 0x98, 0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E,
        0x11, 0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F,
        0xFB, 0x10, 0xD4, 0xB8,
    ];

    #[test]
    fn should_derive_bip173_p2wpkh_for_generator_g() {
        assert_eq!(
            bitcoin_p2wpkh_address(&G_COMPRESSED),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
    }

    #[test]
    fn should_derive_eip55_address_for_generator_g() {
        assert_eq!(
            ethereum_address(&G_UNCOMPRESSED_64),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
    }

    #[test]
    fn should_derive_base58_address_for_zero_seed_ed25519() {
        // Zero-seed Ed25519 pubkey 3b6a27bc...da29 (RFC 8032-style vector);
        // expected base58 cross-checked with an independent BigInteger
        // implementation (PowerShell): 4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS.
        let kp = KeyPair::from_private_key_bytes(CoseAlgorithm::EdDSA, &[0u8; 32]).unwrap();
        let pub_hex = match kp.public_key() {
            PublicKey::Ed25519(vk) => hex::encode(vk.to_bytes()),
            _ => alloc::string::String::from("unreachable"),
        };
        assert_eq!(
            pub_hex,
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        );
        let addr = address_for_public_key(&kp.public_key(), CryptoNetwork::Solana).unwrap();
        assert_eq!(addr, "4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS");
    }

    #[test]
    fn should_reject_wrong_curve_for_network() {
        let secp = KeyPair::from_private_key_bytes(CoseAlgorithm::ES256K, &[1u8; 32]).unwrap();
        assert_eq!(
            address_for_public_key(&secp.public_key(), CryptoNetwork::Solana).unwrap_err(),
            KeyManagerError::BadEnvelope
        );
        let ed = KeyPair::from_private_key_bytes(CoseAlgorithm::EdDSA, &[2u8; 32]).unwrap();
        assert_eq!(
            address_for_public_key(&ed.public_key(), CryptoNetwork::Bitcoin).unwrap_err(),
            KeyManagerError::BadEnvelope
        );
        assert_eq!(
            address_for_public_key(&ed.public_key(), CryptoNetwork::EthereumEvm).unwrap_err(),
            KeyManagerError::BadEnvelope
        );
        let p256 = KeyPair::from_private_key_bytes(CoseAlgorithm::ES256, &[3u8; 32]).unwrap();
        assert_eq!(
            address_for_public_key(&p256.public_key(), CryptoNetwork::Bitcoin).unwrap_err(),
            KeyManagerError::BadEnvelope
        );
    }

    #[test]
    fn should_derive_all_networks_end_to_end_from_private_bytes() {
        // Private key 0x00..01 is G: full private-bytes -> address pipeline.
        let mut one = [0u8; 32];
        one[31] = 1;
        let secp = KeyPair::from_private_key_bytes(CoseAlgorithm::ES256K, &one).unwrap();
        assert_eq!(
            address_for_public_key(&secp.public_key(), CryptoNetwork::Bitcoin).unwrap(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        let g_pub =
            PublicKey::from_cose_cbor(&secp.to_cose_cbor()).unwrap();
        assert_eq!(
            address_for_public_key(&g_pub, CryptoNetwork::EthereumEvm).unwrap(),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
    }
}
