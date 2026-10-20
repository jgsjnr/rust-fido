//! Wallet types: network selector and metadata-only record.
//!
//! BEHAVIOR: every [`CryptoNetwork`] maps to exactly one pre-existing
//! [`CoseAlgorithm`] (BTC+EVM share secp256k1/ES256K, SOL uses EdDSA —
//! reuse of KeyManager curves, no new crypto engine). [`WalletRecord`]
//! carries address/label metadata only; it has no private-bytes field by
//! construction, so LIST-style clones can never leak key material.

use alloc::string::String;

use crate::crypto::curves::CoseAlgorithm;

/// Supported crypto networks (storage + message-sign only, no transactions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoNetwork {
    /// Bitcoin P2WPKH (bech32 over secp256k1).
    Bitcoin,
    /// EVM address (EIP-55 checksum over secp256k1).
    EthereumEvm,
    /// Solana (base58 over Ed25519).
    Solana,
}

impl CryptoNetwork {
    /// Maps the network to its single existing COSE algorithm.
    pub fn cose_algorithm(self) -> CoseAlgorithm {
        match self {
            Self::Bitcoin | Self::EthereumEvm => CoseAlgorithm::ES256K,
            Self::Solana => CoseAlgorithm::EdDSA,
        }
    }

    /// Stable NVS discriminant (`wallet_slot_*` routing codec).
    ///
    /// `0x00` is reserved/invalid so a zeroed flash page never decodes to
    /// a real network (fail-closed on corrupt storage).
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Bitcoin => 0x01,
            Self::EthereumEvm => 0x02,
            Self::Solana => 0x03,
        }
    }

    /// Inverse of [`CryptoNetwork::as_u8`]; unknown (incl. `0x00`) → `None`.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Bitcoin),
            0x02 => Some(Self::EthereumEvm),
            0x03 => Some(Self::Solana),
            _ => None,
        }
    }
}

/// Metadata-only wallet record. Never carries private bytes (none stored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletRecord {
    /// Slot id inside the wallet's dedicated KeyManager (0..32).
    pub slot_id: u8,
    /// Network this record belongs to.
    pub network: CryptoNetwork,
    /// Derived address (bech32 / EIP-55 / base58).
    pub address: String,
    /// `wallet:`-prefixed label (B1 namespace marker).
    pub label: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curves::CoseAlgorithm;

    #[test]
    fn should_map_each_network_to_its_cose_algorithm() {
        assert_eq!(CryptoNetwork::Bitcoin.cose_algorithm(), CoseAlgorithm::ES256K);
        assert_eq!(CryptoNetwork::EthereumEvm.cose_algorithm(), CoseAlgorithm::ES256K);
        assert_eq!(CryptoNetwork::Solana.cose_algorithm(), CoseAlgorithm::EdDSA);
    }

    #[test]
    fn should_roundtrip_stable_nvs_discriminants() {
        for net in [
            CryptoNetwork::Bitcoin,
            CryptoNetwork::EthereumEvm,
            CryptoNetwork::Solana,
        ] {
            assert_eq!(CryptoNetwork::from_u8(net.as_u8()), Some(net));
        }
        assert_eq!(CryptoNetwork::from_u8(0x00), None);
        assert_eq!(CryptoNetwork::from_u8(0x04), None);
        assert_eq!(CryptoNetwork::from_u8(0xFF), None);
    }

    #[test]
    fn should_hold_metadata_only_with_no_private_bytes() {
        let rec = WalletRecord {
            slot_id: 7,
            network: CryptoNetwork::Bitcoin,
            address: String::from("bc1qtest"),
            label: String::from("wallet:savings"),
        };
        assert_eq!(rec.slot_id, 7);
        assert_eq!(rec.network, CryptoNetwork::Bitcoin);
        let dbg = alloc::format!("{:?}", rec);
        assert!(dbg.contains("bc1qtest"));
        assert!(!dbg.contains("private"));
    }
}
