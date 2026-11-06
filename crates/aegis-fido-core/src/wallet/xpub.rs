//! Account-level extended public key export (RAM only).
//!
//! BEHAVIOR: pure derivation over the F2 vocabulary
//! ([`ExtendedPrivateKey`](super::hd::ExtendedPrivateKey) master from seed
//! bytes, [`wallet_account_path`](super::hd_paths::wallet_account_path) for
//! the account shape, [`DerivationPath`](super::hd_paths::DerivationPath)
//! walk, then neuter to the public-only node). No wire, no NVS, no transport:
//! everything runs on caller-provided bytes and returns public-only nodes or
//! their Base58check rendering. Private bytes never leave this module except
//! through the caller-owned input borrow, which is never copied out.
//!
//! SCOPE: secp256k1 account shapes only (protocol levels 44/84). Networks
//! whose curve is not secp256k1 are rejected fail-closed via
//! [`HdError::UnsupportedNetwork`](super::hd::HdError::UnsupportedNetwork);
//! no silent fallback, no zero key.
//!
//! SESSION GATES: the pure functions below take no presence flag (they are
//! safe off-device: output is public-only). On-device exposure goes only
//! through [`WalletStore::export_xpub`], which requires the single-use UP
//! latch (`presence_confirmed`, consumed by the caller) and fails closed
//! with [`WalletError::NeedUp`] otherwise. Transport already gates the
//! account-export opcode behind binding -> UP; the firmware executor stays
//! fail-closed until the session seed exists (follow-up ceremony phase).
//!
//! CONVENTIONS: terminology follows the public derivation protocol only
//! (master, account, chain code, fingerprint, extended key). No product or
//! service names appear here.

use alloc::string::String;

use super::hd::{ExtendedPrivateKey, ExtendedPublicKey, HdError};
use super::hd_paths::{wallet_account_path, DerivationPath};
use super::store::WalletStore;
use super::types::CryptoNetwork;
use super::WalletError;

/// Derives the extended public key at an arbitrary path below the master.
///
/// Pure function over caller bytes: `master_from_seed` (`16..=64` bytes),
/// level-by-level derivation, then neutered to the public-only node. Any
/// hardened level derives through the private side internally; the returned
/// node carries no signing power (see
/// [`ExtendedPublicKey`](super::hd::ExtendedPublicKey)).
pub fn xpub_at_path(seed: &[u8], path: &DerivationPath) -> Result<ExtendedPublicKey, HdError> {
    let master = ExtendedPrivateKey::master_from_seed(seed)?;
    Ok(master.derive_path(path)?.neutered())
}

/// Derives the account-level extended public key for a secp256k1 network.
///
/// Builds the standard account path
/// ([`wallet_account_path`](super::hd_paths::wallet_account_path):
/// purpose'/coin'/account') and delegates to [`xpub_at_path`]. Rejects
/// out-of-range accounts and non-secp256k1 networks fail-closed; the output
/// is public-only by construction (neutered node, no secret field).
pub fn xpub_at_account(
    seed: &[u8],
    network: CryptoNetwork,
    account: u32,
) -> Result<ExtendedPublicKey, HdError> {
    let path = wallet_account_path(network, account)?;
    xpub_at_path(seed, &path)
}

impl WalletStore {
    /// Session-gated account xpub export: Base58check rendering of
    /// [`xpub_at_account`].
    ///
    /// `presence` arrives from the single-use UP latch (consumed by the
    /// caller); without it this fails closed with [`WalletError::NeedUp`]
    /// and derives nothing. The seed stays caller-owned (borrowed, never
    /// retained, never logged); the returned string carries only the public
    /// point, chain code, and lineage — never seed or private bytes.
    pub fn export_xpub(
        &self,
        seed: &[u8],
        network: CryptoNetwork,
        account: u32,
        presence_confirmed: bool,
    ) -> Result<String, WalletError> {
        if !presence_confirmed {
            return Err(WalletError::NeedUp);
        }
        Ok(xpub_at_account(seed, network, account)?.to_extended_string())
    }
}

#[cfg(test)]
mod tests {
    use super::super::hd_codec::decode_extended_key;
    use super::super::hd_paths::DerivationPath;
    use super::*;

    fn vector_seed() -> [u8; 16] {
        hex::decode("000102030405060708090a0b0c0d0e0f")
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn should_require_presence_before_deriving_anything() {
        let store = WalletStore::new();
        assert_eq!(
            store.export_xpub(&vector_seed(), CryptoNetwork::Bitcoin, 0, false),
            Err(WalletError::NeedUp)
        );
        // With the latch set the same call succeeds (public output only).
        let xpub = store
            .export_xpub(&vector_seed(), CryptoNetwork::Bitcoin, 0, true)
            .unwrap();
        assert!(xpub.starts_with("xpub"));
    }

    #[test]
    fn should_match_manual_derivation_for_both_account_shapes() {
        for network in [CryptoNetwork::Bitcoin, CryptoNetwork::EthereumEvm] {
            let seed = vector_seed();
            let via_account = xpub_at_account(&seed, network, 0).unwrap();
            let path = wallet_account_path(network, 0).unwrap();
            let master = ExtendedPrivateKey::master_from_seed(&seed).unwrap();
            let via_manual = master.derive_path(&path).unwrap().neutered();
            assert_eq!(
                via_account.to_extended_bytes(),
                via_manual.to_extended_bytes()
            );
            // Account nodes sit three levels below the master.
            assert_eq!(via_account.depth(), 3);
        }
    }

    #[test]
    fn should_reject_non_secp256k1_networks_fail_closed() {
        let seed = vector_seed();
        assert_eq!(
            xpub_at_account(&seed, CryptoNetwork::Solana, 0).unwrap_err(),
            HdError::UnsupportedNetwork
        );
        // The session gate maps it onto the closed wire status set.
        let store = WalletStore::new();
        assert_eq!(
            store.export_xpub(&seed, CryptoNetwork::Solana, 0, true),
            Err(WalletError::BadEnvelope)
        );
    }

    #[test]
    fn should_reject_bad_seed_lengths_and_out_of_range_accounts() {
        let path: DerivationPath = "m/84'/0'/0'".parse().unwrap();
        assert_eq!(
            xpub_at_path(&[0u8; 15], &path).unwrap_err(),
            HdError::InvalidSeedLength(15)
        );
        assert_eq!(
            xpub_at_path(&[0u8; 65], &path).unwrap_err(),
            HdError::InvalidSeedLength(65)
        );
        assert_eq!(
            xpub_at_account(&vector_seed(), CryptoNetwork::Bitcoin, 0x8000_0000).unwrap_err(),
            HdError::InvalidChildNumber(0x8000_0000)
        );
    }

    #[test]
    fn should_emit_public_only_strings_that_decode_as_public() {
        use super::super::hd_codec::DecodedExtendedKey;
        let store = WalletStore::new();
        let xpub = store
            .export_xpub(&vector_seed(), CryptoNetwork::Bitcoin, 0, true)
            .unwrap();
        assert_eq!(xpub.len(), super::super::hd_codec::EXTENDED_KEY_STRLEN);
        match decode_extended_key(&xpub).unwrap() {
            DecodedExtendedKey::Public(back) => {
                assert_eq!(back.depth(), 3);
                assert_eq!(back.to_extended_string(), xpub);
            }
            DecodedExtendedKey::Private(_) => panic!("account export must decode as public"),
        }
    }
}
