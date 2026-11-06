//! AegisKey crypto-wallet store: key custody + address derivation.
//!
//! BEHAVIOR: [`WalletStore`] delegates every key operation to the existing
//! [`KeyManager`](crate::credential::KeyManager) (GEN/IMPORT/SIGN/LIST/DELETE)
//! and every envelope open to the existing AEGN
//! [`AegisVault`](crate::vault::AegisVault) seal/open pair — zero changes to
//! either, envelope byte-identical. Gates are inherited, never reimplemented:
//! generate/sign/list/address/get/public_cose require UP passthrough,
//! import/delete require UP+PIN passthrough. There is NO OTP path and NO
//! global lock (the vault is borrowed per import call). Scope is storage +
//! message-sign only; no transactions are constructed here.
//!
//! B1 DECISION (slot namespace): [`KeyManager`] owns a single 32-slot
//! namespace shared with other consumers (FIDO2 credentials). Of the three
//! candidates — (a) dedicated [`KeyManager`] instance, (b) reserved slot
//! range, (c) `wallet:` label prefix alone — this module implements (a) with
//! the prefix as defense-in-depth:
//! - (b) reserved range needs cross-consumer coordination, wastes slots when
//!   the wallet is empty, and still shares mutable state (one logic bug can
//!   evict a foreign slot).
//! - (c) bare prefix is unenforced convention: labels are user metadata, any
//!   consumer can write `wallet:*` and collide.
//! - (a) dedicated instance gives hard isolation by construction: the wallet
//!   manager shares no state with any other manager, so wallet operations
//!   cannot overwrite or evict a non-wallet slot even under total logic
//!   failure of the wallet layer. The `wallet:` prefix
//!   ([`WALLET_LABEL_PREFIX`](store::WALLET_LABEL_PREFIX)) is additionally
//!   enforced on every slot the store creates so LIST output stays auditable.
//!
//! Enforcement: the manager field is private with no accessor (no `&mut`
//! leak), and `should_never_touch_non_wallet_slots` pins the property.

pub mod address;
pub mod clear_signing;
pub mod hd;
pub mod hd_codec;
pub mod hd_paths;
pub mod shamir_slip39;
pub mod store;
pub mod types;

pub use address::{
    address_for_public_key, bitcoin_p2wpkh_address, ethereum_address, solana_address,
};
pub use clear_signing::{
    parse_bitcoin_tx, parse_ethereum_tx, parse_solana_tx, ClearSignError,
    ClearSignTransactionSummary, OledFrame128x64, OLED_BUFFER_SIZE, OLED_HEIGHT, OLED_PAGES,
    OLED_WIDTH,
};
pub use hd::{
    ExtendedPrivateKey, ExtendedPublicKey, HdError, HARDENED_OFFSET, MAX_PATH_DEPTH, MAX_SEED_LEN,
    MIN_SEED_LEN,
};
pub use hd_codec::{
    base58check_encode, decode_extended_key, DecodedExtendedKey, EXTENDED_KEY_LEN,
    EXTENDED_KEY_STRLEN, XPRV_VERSION, XPUB_VERSION,
};
pub use hd_paths::{
    wallet_account_path, wallet_address_path, ChildNumber, DerivationPath, COIN_TYPE_BITCOIN,
    COIN_TYPE_EVM, PURPOSE_BIP44, PURPOSE_BIP84,
};
pub use shamir_slip39::{
    gf256_div, gf256_inv, gf256_mul, recover_secret_from_2_shares, split_secret_2_of_3,
    DsHmacSeedEnvelope, ShamirError, ShamirShare,
};
pub use store::{WalletStore, WALLET_LABEL_PREFIX};
pub use types::{CryptoNetwork, WalletRecord};

use crate::credential::{
    KeyManagerError, STATUS_BAD_ENVELOPE, STATUS_NEED_PIN, STATUS_NEED_UP, STATUS_NO_SLOT,
};

/// Wallet errors, one-to-one with [`KeyManagerError`] and the 9.5 statuses.
/// A curve that does not belong to the requested network (including a
/// caller-declared algorithm that disagrees with the network) maps to
/// `BadEnvelope` so the closed status set stays intact — no new wire status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletError {
    /// User presence required (9.5 `0x01`).
    NeedUp,
    /// PIN authentication required (9.5 `0x02`).
    NeedPin,
    /// Slot unavailable or unknown (9.5 `0x03`).
    NoSlot,
    /// Bad envelope, label, id, or network/curve mismatch (9.5 `0x04`).
    BadEnvelope,
}

impl WalletError {
    /// Maps the error to its 9.5 wire status byte.
    pub fn status(self) -> u8 {
        match self {
            Self::NeedUp => STATUS_NEED_UP,
            Self::NeedPin => STATUS_NEED_PIN,
            Self::NoSlot => STATUS_NO_SLOT,
            Self::BadEnvelope => STATUS_BAD_ENVELOPE,
        }
    }
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NeedUp => write!(f, "user presence required"),
            Self::NeedPin => write!(f, "PIN authentication required"),
            Self::NoSlot => write!(f, "wallet slot unavailable"),
            Self::BadEnvelope => write!(f, "bad wallet envelope or network"),
        }
    }
}

impl From<KeyManagerError> for WalletError {
    fn from(e: KeyManagerError) -> Self {
        match e {
            KeyManagerError::NeedUp => Self::NeedUp,
            KeyManagerError::NeedPin => Self::NeedPin,
            KeyManagerError::NoSlot => Self::NoSlot,
            KeyManagerError::BadEnvelope => Self::BadEnvelope,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_map_wallet_errors_to_9_5_statuses() {
        assert_eq!(WalletError::NeedUp.status(), STATUS_NEED_UP);
        assert_eq!(WalletError::NeedPin.status(), STATUS_NEED_PIN);
        assert_eq!(WalletError::NoSlot.status(), STATUS_NO_SLOT);
        assert_eq!(WalletError::BadEnvelope.status(), STATUS_BAD_ENVELOPE);
        assert_eq!(
            WalletError::from(KeyManagerError::NeedUp),
            WalletError::NeedUp
        );
        assert_eq!(
            WalletError::from(KeyManagerError::NeedPin),
            WalletError::NeedPin
        );
        assert_eq!(
            WalletError::from(KeyManagerError::NoSlot),
            WalletError::NoSlot
        );
        assert_eq!(
            WalletError::from(KeyManagerError::BadEnvelope),
            WalletError::BadEnvelope
        );
        assert_eq!(
            alloc::format!("{}", WalletError::NeedUp),
            "user presence required"
        );
        assert_eq!(
            alloc::format!("{}", WalletError::NeedPin),
            "PIN authentication required"
        );
        assert_eq!(
            alloc::format!("{}", WalletError::NoSlot),
            "wallet slot unavailable"
        );
        assert_eq!(
            alloc::format!("{}", WalletError::BadEnvelope),
            "bad wallet envelope or network"
        );
    }
}
