//! PM-domain Shamir backup (SRP: backup math lives here, not in `store`).
//!
//! Reuses `aegis_fido_core::wallet::{split_secret_2_of_3,
//! recover_secret_from_2_shares}` (GF(256) 2-of-3, CRC32-committed) without
//! changing the wallet path. Domain separation is enforced by TYPE:
//! [`PmShare`] wraps the raw share and carries the [`PM_SHARE_DOMAIN`] tag,
//! so a wallet share cannot be passed where a PM share is expected and a
//! single PM share reveals nothing about the master key.

use aegis_fido_core::wallet::{recover_secret_from_2_shares, split_secret_2_of_3};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::policy::PmError;

/// Domain tag bound to every PM backup share. Distinct from any wallet
/// share domain; mixed-domain recovery is rejected by the type system
/// (wallet shares are a different type and cannot be supplied here).
pub const PM_SHARE_DOMAIN: &[u8] = b"Aegis-PM-Share-v1";

/// A 2-of-3 Shamir share of the PM master key.
///
/// `Debug` prints only the index and the domain tag — never share bytes.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PmShare {
    index: u8,
    #[zeroize(skip)]
    crc32: u32,
    data: [u8; 32],
}

impl PmShare {
    /// Domain tag carried by this share (always [`PM_SHARE_DOMAIN`]).
    pub fn domain(&self) -> &'static [u8] {
        PM_SHARE_DOMAIN
    }

    /// Share coordinate `x` in `1..=3`.
    pub fn index(&self) -> u8 {
        self.index
    }
}

impl core::fmt::Debug for PmShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmShare")
            .field("index", &self.index)
            .field("domain", &"Aegis-PM-Share-v1")
            .field("data", &"[REDACTED_SHARE]")
            .finish()
    }
}

/// Splits the 32-byte PM master key into 3 shares (any 2 restore).
/// `entropy` must be 32 fresh random bytes from the device TRNG.
pub fn split_pm_master(master: &[u8; 32], entropy: &[u8; 32]) -> [PmShare; 3] {
    let raw = split_secret_2_of_3(master, entropy);
    [
        PmShare {
            index: raw[0].index,
            crc32: raw[0].crc32,
            data: raw[0].data,
        },
        PmShare {
            index: raw[1].index,
            crc32: raw[1].crc32,
            data: raw[1].data,
        },
        PmShare {
            index: raw[2].index,
            crc32: raw[2].crc32,
            data: raw[2].data,
        },
    ]
}

/// Restores the PM master key from any 2 distinct shares.
/// A single share is mathematically insufficient (one equation, two
/// unknowns per byte); duplicates or cross-domain mixes fail closed.
pub fn recover_pm_master(a: &PmShare, b: &PmShare) -> Result<[u8; 32], PmError> {
    if a.index == b.index {
        return Err(PmError::Backup);
    }
    let sa = aegis_fido_core::wallet::ShamirShare {
        index: a.index,
        data: a.data,
        crc32: a.crc32,
    };
    let sb = aegis_fido_core::wallet::ShamirShare {
        index: b.index,
        data: b.data,
        crc32: b.crc32,
    };
    recover_secret_from_2_shares(&sa, &sb).map_err(|_| PmError::Backup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn any_two_of_three_restore() {
        let master = [0x77u8; 32];
        let entropy = [0x3Cu8; 32];
        let shares = split_pm_master(&master, &entropy);
        for (a, b) in [(0, 1), (0, 2), (1, 2)] {
            let rec = recover_pm_master(&shares[a], &shares[b]).unwrap();
            assert_eq!(rec, master);
        }
    }

    #[test]
    fn single_share_reveals_nothing() {
        let master = [0xABu8; 32];
        let entropy = [0x11u8; 32];
        let shares = split_pm_master(&master, &entropy);
        // No single share contains the master as a subsequence, and share
        // bytes differ from the secret (one equation, two unknowns per byte).
        for s in &shares {
            assert_ne!(s.data, master);
            let dump: Vec<u8> = s.data.to_vec();
            assert!(dump.windows(master.len()).all(|w| w != master));
        }
        // Recovery needs two DISTINCT shares.
        assert_eq!(
            recover_pm_master(&shares[0], &shares[0]),
            Err(PmError::Backup)
        );
    }

    #[test]
    fn debug_never_logs_share_bytes() {
        let shares = split_pm_master(&[0x01u8; 32], &[0x02u8; 32]);
        let dbg = alloc::format!("{:?}", shares[0]);
        assert!(dbg.contains("Aegis-PM-Share-v1"));
        assert!(dbg.contains("[REDACTED_SHARE]"));
        assert_eq!(shares[0].domain(), PM_SHARE_DOMAIN);
    }

    #[test]
    fn tampered_share_fails_closed() {
        let master = [0x42u8; 32];
        let shares = split_pm_master(&master, &[0x09u8; 32]);
        let mut bad = shares[1].clone();
        bad.data[0] ^= 0xFF;
        assert!(recover_pm_master(&shares[0], &bad).is_err());
    }
}
