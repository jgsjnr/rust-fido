//! Hardwallet address types (feature `hardwallet` only).
//!
//! Compiled in only with `hardwallet`; when off, the stable stub is
//! `SdkError::NotCompiled` via `require_hardwallet` (R12). Hash crates are
//! re-exported here so consumers never depend on `aegis-fido-core`.
//! Zero derivation logic: types only.

pub use bech32;
pub use bs58;
pub use ripemd;
pub use sha3;

/// Coin family for an address derivation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinKind {
    /// BIP-32/84 style (SegWit-capable).
    Bitcoin,
    /// BIP-32/44 style (EVM).
    Ethereum,
}

/// Typed address derivation request (derivation itself runs in firmware).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRequest {
    /// Coin family.
    pub coin: CoinKind,
    /// BIP-32 account level.
    pub account: u32,
    /// Change level (`0` external, `1` internal).
    pub change: u32,
    /// Address index level.
    pub index: u32,
}

impl AddressRequest {
    /// Build a typed derivation request (no crypto here).
    pub const fn new(coin: CoinKind, account: u32, change: u32, index: u32) -> Self {
        Self {
            coin,
            account,
            change,
            index,
        }
    }
}

/// Typed account-level extended public key request.
///
/// Derivation itself runs in firmware (RAM-only) behind the `hardwallet`
/// gate; off-device preview travels through the bridge FFI. Only secp256k1
/// families are representable: no extended-key protocol exists for the
/// ed25519 family, so it is unrepresentable by construction (fail-closed
/// without a runtime check).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XpubRequest {
    /// Coin family.
    pub coin: CoinKind,
    /// BIP-32 account level (`< 2^31`; hardened by derivation).
    pub account: u32,
}

impl XpubRequest {
    /// Build a typed xpub request (no crypto here).
    pub const fn new(coin: CoinKind, account: u32) -> Self {
        Self { coin, account }
    }
}

#[cfg(test)]
mod tests {
    use crate::hardwallet::{AddressRequest, CoinKind, XpubRequest};

    #[test]
    fn const_constructible() {
        const REQ: AddressRequest = AddressRequest::new(CoinKind::Bitcoin, 0, 0, 0);
        let req = REQ;
        assert_eq!(req.coin, CoinKind::Bitcoin);
        assert_eq!(req.account, 0);
        assert_eq!(req.change, 0);
        assert_eq!(req.index, 0);
    }

    #[test]
    fn coin_kinds_distinct() {
        assert_ne!(CoinKind::Bitcoin, CoinKind::Ethereum);
    }

    #[test]
    fn xpub_request_const_constructible_and_copied() {
        const REQ: XpubRequest = XpubRequest::new(CoinKind::Bitcoin, 0);
        let req = REQ;
        let dup = req;
        assert_eq!(req.coin, CoinKind::Bitcoin);
        assert_eq!(req.account, 0);
        assert_eq!(dup, req);
        assert_ne!(
            XpubRequest::new(CoinKind::Ethereum, 1),
            XpubRequest::new(CoinKind::Ethereum, 0)
        );
    }
}
