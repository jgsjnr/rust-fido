//! Compile-time capability set (R12).
//!
//! `capabilities()` is `const`: callers (and firmware `main`) can branch on
//! compiled-in families without hard-coding modules.

/// Bitset of families compiled into this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySet {
    bits: u32,
}

impl CapabilitySet {
    /// No capabilities.
    pub const EMPTY: Self = Self { bits: 0 };
    /// FIDO/CTAP family (feature `fido`).
    pub const FIDO: Self = Self { bits: 1 << 0 };
    /// Wallet family (feature `hardwallet`).
    pub const HARDWALLET: Self = Self { bits: 1 << 1 };
    /// Vendor TLV family (always compiled).
    pub const VENDOR: Self = Self { bits: 1 << 2 };
    /// Binding family (always compiled).
    pub const BINDING: Self = Self { bits: 1 << 3 };
    /// System family (always compiled).
    pub const SYSTEM: Self = Self { bits: 1 << 4 };
    /// Security-monitor family (feature `secmon`).
    pub const SECMON: Self = Self { bits: 1 << 5 };
    /// Lab test-hook surface (feature `test-mode`, never in `default`).
    pub const TEST_MODE: Self = Self { bits: 1 << 6 };

    /// Raw bits (for logging/metadata only).
    pub const fn bits(self) -> u32 {
        self.bits
    }

    /// `true` when all of `other` is present.
    pub const fn contains(self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    /// Union of two sets.
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }
}

/// Capabilities compiled into this build (const-evaluable).
pub const fn capabilities() -> CapabilitySet {
    let mut bits =
        CapabilitySet::VENDOR.bits() | CapabilitySet::BINDING.bits() | CapabilitySet::SYSTEM.bits();
    if cfg!(feature = "fido") {
        bits |= CapabilitySet::FIDO.bits();
    }
    if cfg!(feature = "hardwallet") {
        bits |= CapabilitySet::HARDWALLET.bits();
    }
    if cfg!(feature = "secmon") {
        bits |= CapabilitySet::SECMON.bits();
    }
    if cfg!(feature = "test-mode") {
        bits |= CapabilitySet::TEST_MODE.bits();
    }
    CapabilitySet { bits }
}

#[cfg(test)]
mod tests {
    use crate::capabilities::{capabilities, CapabilitySet};

    #[test]
    fn const_evaluable() {
        const CAPS: CapabilitySet = capabilities();
        let caps = CAPS;
        assert!(caps.contains(CapabilitySet::VENDOR));
        assert!(caps.contains(CapabilitySet::BINDING));
        assert!(caps.contains(CapabilitySet::SYSTEM));
    }

    #[test]
    fn gated_bits_follow_features() {
        const CAPS: CapabilitySet = capabilities();
        let caps = CAPS;
        assert_eq!(caps.contains(CapabilitySet::FIDO), cfg!(feature = "fido"));
        assert_eq!(
            caps.contains(CapabilitySet::HARDWALLET),
            cfg!(feature = "hardwallet")
        );
        assert_eq!(
            caps.contains(CapabilitySet::SECMON),
            cfg!(feature = "secmon")
        );
        assert_eq!(
            caps.contains(CapabilitySet::TEST_MODE),
            cfg!(feature = "test-mode")
        );
    }

    #[test]
    fn set_algebra() {
        const BOTH: CapabilitySet = CapabilitySet::FIDO.union(CapabilitySet::HARDWALLET);
        let both = BOTH;
        assert!(both.contains(CapabilitySet::FIDO));
        assert!(both.contains(CapabilitySet::HARDWALLET));
        assert!(!both.contains(CapabilitySet::VENDOR));
        assert!(!CapabilitySet::EMPTY.contains(CapabilitySet::SYSTEM));
    }
}
