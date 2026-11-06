//! Derivation-path language: levels, parsing, and standard wallet paths.
//!
//! BEHAVIOR: typed path vocabulary over the shared [`HdError`](super::hd::HdError).
//! [`ChildNumber`] is one level (index below 2^31 plus the hardened flag);
//! [`DerivationPath`] is an ordered stack of levels parsed from `"m/..."` text
//! with fail-closed validation. The [`wallet_account_path`] /
//! [`wallet_address_path`] builders pin the standard account/address shapes
//! per secp256k1 network (purpose and registered coin type fixed; change is
//! 0 external or 1 internal). No key math here (see [`super::hd`]), no
//! encoding here (see [`super::hd_codec`]).

use alloc::vec::Vec;

use super::hd::{HdError, HARDENED_OFFSET, MAX_PATH_DEPTH};
use super::types::CryptoNetwork;

/// Account-level purpose for the EVM-style derivation scheme (protocol 44).
pub const PURPOSE_BIP44: u32 = 44;
/// Account-level purpose for the segwit derivation scheme (protocol 84).
pub const PURPOSE_BIP84: u32 = 84;
/// Registered coin type for the main payment network (registry value 0).
pub const COIN_TYPE_BITCOIN: u32 = 0;
/// Registered coin type for the EVM network family (registry value 60).
pub const COIN_TYPE_EVM: u32 = 60;

/// A single level of a derivation path: an index below `2^31` plus the
/// hardened flag (raw form adds [`HARDENED_OFFSET`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChildNumber {
    index: u32,
    hardened: bool,
}

impl ChildNumber {
    /// Normal (non-hardened) child. Fails when `index >= 2^31`.
    pub fn normal(index: u32) -> Result<Self, HdError> {
        if index >= HARDENED_OFFSET {
            return Err(HdError::InvalidChildNumber(index));
        }
        Ok(Self {
            index,
            hardened: false,
        })
    }

    /// Hardened child. Fails when `index >= 2^31`.
    pub fn hardened(index: u32) -> Result<Self, HdError> {
        if index >= HARDENED_OFFSET {
            return Err(HdError::InvalidChildNumber(index));
        }
        Ok(Self {
            index,
            hardened: true,
        })
    }

    /// Splits a raw `0..2^32` value into index + hardened flag (infallible).
    pub fn from_raw(raw: u32) -> Self {
        Self {
            index: raw & !HARDENED_OFFSET,
            hardened: raw & HARDENED_OFFSET != 0,
        }
    }

    /// Whether this child is hardened.
    pub fn is_hardened(self) -> bool {
        self.hardened
    }

    /// Index without the hardened bit (always `< 2^31`).
    pub fn index(self) -> u32 {
        self.index
    }

    /// Raw `ser32` form (`index + 2^31` when hardened).
    pub fn raw(self) -> u32 {
        if self.hardened {
            self.index | HARDENED_OFFSET
        } else {
            self.index
        }
    }

    /// Parses one path component: decimal digits with an optional
    /// hardened suffix (`'` or `h`). Rejects empty input, inner
    /// whitespace, signs, values `>= 2^31`, and stacked suffixes.
    pub fn parse_component(component: &str) -> Result<Self, HdError> {
        if component.is_empty() {
            return Err(HdError::InvalidPath);
        }
        let (digits, hardened) = match component.as_bytes().last() {
            Some(b'\'') | Some(b'h') | Some(b'H') => (&component[..component.len() - 1], true),
            _ => (component, false),
        };
        if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(HdError::InvalidPath);
        }
        let mut index: u32 = 0;
        for b in digits.bytes() {
            index = index
                .checked_mul(10)
                .and_then(|v| v.checked_add(u32::from(b - b'0')))
                .ok_or(HdError::InvalidPath)?;
        }
        if index >= HARDENED_OFFSET {
            return Err(HdError::InvalidPath);
        }
        Ok(Self { index, hardened })
    }
}

impl core::fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.hardened {
            write!(f, "{}'", self.index)
        } else {
            write!(f, "{}", self.index)
        }
    }
}

/// A parsed derivation path: ordered child numbers below the master.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DerivationPath {
    levels: Vec<ChildNumber>,
}

impl DerivationPath {
    /// Master path (empty: no derivation below the root).
    pub fn master() -> Self {
        Self { levels: Vec::new() }
    }

    /// Builds a path from explicit levels. Fails past [`MAX_PATH_DEPTH`].
    pub fn from_levels(levels: &[ChildNumber]) -> Result<Self, HdError> {
        if levels.len() > MAX_PATH_DEPTH {
            return Err(HdError::InvalidPath);
        }
        Ok(Self {
            levels: levels.to_vec(),
        })
    }

    /// Number of levels below the master.
    pub fn len(&self) -> usize {
        self.levels.len()
    }

    /// Whether this is the master path itself.
    pub fn is_empty(&self) -> bool {
        self.levels.is_empty()
    }

    /// Ordered levels of this path.
    pub fn levels(&self) -> &[ChildNumber] {
        &self.levels
    }
}

impl core::str::FromStr for DerivationPath {
    type Err = HdError;

    /// Parses `"m"` (master) or `"m/<level>/..."`. Fail-closed: the root
    /// must be exactly `m`, components must be non-empty, depth is capped
    /// at [`MAX_PATH_DEPTH`], and each level parses via
    /// [`ChildNumber::parse_component`].
    fn from_str(path: &str) -> Result<Self, HdError> {
        if path == "m" {
            return Ok(Self::master());
        }
        let rest = path.strip_prefix("m/").ok_or(HdError::InvalidPath)?;
        if rest.is_empty() || rest.len() > MAX_PATH_DEPTH * 12 {
            return Err(HdError::InvalidPath);
        }
        let mut levels = Vec::new();
        for component in rest.split('/') {
            levels.push(ChildNumber::parse_component(component)?);
            if levels.len() > MAX_PATH_DEPTH {
                return Err(HdError::InvalidPath);
            }
        }
        Ok(Self { levels })
    }
}

impl core::fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "m")?;
        for level in &self.levels {
            write!(f, "/{}", level)?;
        }
        Ok(())
    }
}

/// Account-level path for a secp256k1 wallet network: `m/<purpose>'/`
/// `<coin>'/<account>'` with the purpose and coin type fixed per network
/// (84'/0' for the main payment network, 44'/60' for the EVM family).
/// Rejects out-of-range accounts and non-secp256k1 networks fail-closed.
pub fn wallet_account_path(
    network: CryptoNetwork,
    account: u32,
) -> Result<DerivationPath, HdError> {
    if account >= HARDENED_OFFSET {
        return Err(HdError::InvalidChildNumber(account));
    }
    let (purpose, coin) = match network {
        CryptoNetwork::Bitcoin => (PURPOSE_BIP84, COIN_TYPE_BITCOIN),
        CryptoNetwork::EthereumEvm => (PURPOSE_BIP44, COIN_TYPE_EVM),
        CryptoNetwork::Solana => return Err(HdError::UnsupportedNetwork),
    };
    DerivationPath::from_levels(&[
        ChildNumber::hardened(purpose).map_err(|_| HdError::InvalidPath)?,
        ChildNumber::hardened(coin).map_err(|_| HdError::InvalidPath)?,
        ChildNumber::hardened(account).map_err(|_| HdError::InvalidPath)?,
    ])
}

/// Full address-level path for a secp256k1 wallet network: the account
/// path plus `change/index` (both non-hardened; `change` is 0 external or
/// 1 internal). Anything else is rejected fail-closed.
pub fn wallet_address_path(
    network: CryptoNetwork,
    account: u32,
    change: u32,
    index: u32,
) -> Result<DerivationPath, HdError> {
    if change > 1 {
        return Err(HdError::InvalidChildNumber(change));
    }
    if index >= HARDENED_OFFSET {
        return Err(HdError::InvalidChildNumber(index));
    }
    let account_path = wallet_account_path(network, account)?;
    let mut levels: Vec<ChildNumber> = account_path.levels().to_vec();
    levels.push(ChildNumber::normal(change).map_err(|_| HdError::InvalidPath)?);
    levels.push(ChildNumber::normal(index).map_err(|_| HdError::InvalidPath)?);
    DerivationPath::from_levels(&levels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};

    #[test]
    fn should_parse_valid_paths_and_roundtrip_display() {
        let master: DerivationPath = "m".parse().unwrap();
        assert!(master.is_empty());
        assert_eq!(master.to_string(), "m");
        let path: DerivationPath = "m/44'/0'/0'/0/0".parse().unwrap();
        assert_eq!(path.len(), 5);
        assert_eq!(path.levels()[0], ChildNumber::hardened(44).unwrap());
        assert_eq!(path.levels()[3], ChildNumber::normal(0).unwrap());
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
        let h_suffix: DerivationPath = "m/84h/0h/0h".parse().unwrap();
        assert!(h_suffix.levels()[0].is_hardened());
        assert_eq!(h_suffix.to_string(), "m/84'/0'/0'");
    }

    #[test]
    fn should_reject_malformed_paths_fail_closed() {
        for bad in [
            "",
            "M",
            "m/",
            "m//0",
            "m/0//1",
            "m/0/",
            "/m/0",
            "n/0",
            "m/0 '",
            "m/ 0",
            "m/-1",
            "m/+1",
            "m/0''",
            "m/'",
            "m/2147483648",
            "m/2147483648'",
            "m/99999999999",
            "m/abc",
            "m/0x10",
        ] {
            assert!(bad.parse::<DerivationPath>().is_err(), "path {bad:?}");
        }
        // Depth past the cap is rejected.
        let mut deep = String::from("m");
        for _ in 0..=MAX_PATH_DEPTH {
            deep.push_str("/0");
        }
        assert!(deep.parse::<DerivationPath>().is_err());
    }

    #[test]
    fn should_build_child_numbers_with_fail_closed_bounds() {
        assert!(ChildNumber::normal(HARDENED_OFFSET).is_err());
        assert!(ChildNumber::hardened(HARDENED_OFFSET).is_err());
        assert_eq!(
            ChildNumber::from_raw(0x8000_0005),
            ChildNumber::hardened(5).unwrap()
        );
        assert_eq!(ChildNumber::from_raw(7), ChildNumber::normal(7).unwrap());
        assert_eq!(ChildNumber::hardened(3).unwrap().raw(), 0x8000_0003);
    }

    #[test]
    fn should_build_standard_account_and_address_paths() {
        let account = wallet_account_path(CryptoNetwork::Bitcoin, 0).unwrap();
        assert_eq!(account.to_string(), "m/84'/0'/0'");
        let addr = wallet_address_path(CryptoNetwork::Bitcoin, 0, 0, 0).unwrap();
        assert_eq!(addr.to_string(), "m/84'/0'/0'/0/0");
        let evm = wallet_address_path(CryptoNetwork::EthereumEvm, 1, 1, 7).unwrap();
        assert_eq!(evm.to_string(), "m/44'/60'/1'/1/7");
        assert_eq!(
            wallet_account_path(CryptoNetwork::Solana, 0).unwrap_err(),
            HdError::UnsupportedNetwork
        );
        assert!(wallet_address_path(CryptoNetwork::Bitcoin, 0, 2, 0).is_err());
        assert!(wallet_address_path(CryptoNetwork::Bitcoin, 0, 0, HARDENED_OFFSET).is_err());
        assert!(wallet_account_path(CryptoNetwork::Bitcoin, HARDENED_OFFSET).is_err());
    }
}
