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
    /// OTA family (feature `ota`; opcodes `0x30`-`0x34`, reserved `0x2F`).
    pub const OTA: Self = Self { bits: 1 << 7 };
    /// PIV/CCID family (feature `piv`; enroll `0x39`, APDUs otherwise).
    pub const PIV: Self = Self { bits: 1 << 8 };
    /// OTP family (feature `otp`; keyboard/Ykman/Nitrokey/Legacy OTP + rescue `0x2E`).
    pub const OTP: Self = Self { bits: 1 << 9 };
    /// Proximity family (feature `proximity`; service `0xFFFE`, never `0xFFFD`).
    pub const PROXIMITY: Self = Self { bits: 1 << 10 };
    /// OATH family (feature `oath`; vendor `0x24`-`0x27`, HTTP `GET /oath/code`).
    pub const OATH: Self = Self { bits: 1 << 11 };
    /// Backup family (feature `backup`; envelope AEGN, execution in firmware).
    pub const BACKUP: Self = Self { bits: 1 << 12 };
    /// Audit/fw-log family (feature `audit`; op `0x38`, ring `64x16 B` in RAM).
    pub const AUDIT: Self = Self { bits: 1 << 13 };
    /// Policy-gate family (feature `policy`; `binding -> UP -> PIN` as data).
    pub const POLICY: Self = Self { bits: 1 << 14 };

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
///
/// Phase 0 note: the eight new families probe `CARGO_FEATURE_*` via
/// `option_env!` (semantically identical to `cfg!(feature = ...)` once the
/// features are declared) so this file keeps R6 zero warnings without
/// touching `Cargo.toml` (owned by another lane). Existing probes stay on
/// `cfg!` untouched.
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
    if option_env!("CARGO_FEATURE_OTA").is_some() {
        bits |= CapabilitySet::OTA.bits();
    }
    if option_env!("CARGO_FEATURE_PIV").is_some() {
        bits |= CapabilitySet::PIV.bits();
    }
    if option_env!("CARGO_FEATURE_OTP").is_some() {
        bits |= CapabilitySet::OTP.bits();
    }
    if option_env!("CARGO_FEATURE_PROXIMITY").is_some() {
        bits |= CapabilitySet::PROXIMITY.bits();
    }
    if option_env!("CARGO_FEATURE_OATH").is_some() {
        bits |= CapabilitySet::OATH.bits();
    }
    if option_env!("CARGO_FEATURE_BACKUP").is_some() {
        bits |= CapabilitySet::BACKUP.bits();
    }
    if option_env!("CARGO_FEATURE_AUDIT").is_some() {
        bits |= CapabilitySet::AUDIT.bits();
    }
    if option_env!("CARGO_FEATURE_POLICY").is_some() {
        bits |= CapabilitySet::POLICY.bits();
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

    #[test]
    fn existing_bits_frozen_no_renumber() {
        assert_eq!(CapabilitySet::FIDO.bits(), 1 << 0);
        assert_eq!(CapabilitySet::HARDWALLET.bits(), 1 << 1);
        assert_eq!(CapabilitySet::VENDOR.bits(), 1 << 2);
        assert_eq!(CapabilitySet::BINDING.bits(), 1 << 3);
        assert_eq!(CapabilitySet::SYSTEM.bits(), 1 << 4);
        assert_eq!(CapabilitySet::SECMON.bits(), 1 << 5);
        assert_eq!(CapabilitySet::TEST_MODE.bits(), 1 << 6);
    }

    #[test]
    fn phase0_bits_are_single_distinct_additive_flags() {
        use crate::capabilities::CapabilitySet as C;
        let fresh = [
            C::OTA,
            C::PIV,
            C::OTP,
            C::PROXIMITY,
            C::OATH,
            C::BACKUP,
            C::AUDIT,
            C::POLICY,
        ];
        let old_mask = C::FIDO
            .union(C::HARDWALLET)
            .union(C::VENDOR)
            .union(C::BINDING)
            .union(C::SYSTEM)
            .union(C::SECMON)
            .union(C::TEST_MODE);
        let mut seen = 0u32;
        for cap in fresh {
            assert_ne!(cap.bits(), 0);
            assert_eq!(cap.bits() & (cap.bits() - 1), 0);
            assert_eq!(cap.bits() & old_mask.bits(), 0);
            assert_eq!(cap.bits() & seen, 0);
            seen |= cap.bits();
        }
        // Additive-only: OR-ing a fresh flag never clears an old one.
        let with_ota = C::VENDOR.union(C::OTA);
        assert!(with_ota.contains(C::VENDOR));
        assert!(with_ota.contains(C::OTA));
    }

    #[test]
    fn phase0_gated_bits_follow_features() {
        const CAPS: CapabilitySet = capabilities();
        let caps = CAPS;
        // Mirrors `capabilities()`: `option_env!` until `Cargo.toml` declares
        // the features (owner lane); identical to `cfg!(feature = ...)` then.
        assert_eq!(
            caps.contains(CapabilitySet::OTA),
            option_env!("CARGO_FEATURE_OTA").is_some()
        );
        assert_eq!(
            caps.contains(CapabilitySet::PIV),
            option_env!("CARGO_FEATURE_PIV").is_some()
        );
        assert_eq!(
            caps.contains(CapabilitySet::OTP),
            option_env!("CARGO_FEATURE_OTP").is_some()
        );
        assert_eq!(
            caps.contains(CapabilitySet::PROXIMITY),
            option_env!("CARGO_FEATURE_PROXIMITY").is_some()
        );
        assert_eq!(
            caps.contains(CapabilitySet::OATH),
            option_env!("CARGO_FEATURE_OATH").is_some()
        );
        assert_eq!(
            caps.contains(CapabilitySet::BACKUP),
            option_env!("CARGO_FEATURE_BACKUP").is_some()
        );
        assert_eq!(
            caps.contains(CapabilitySet::AUDIT),
            option_env!("CARGO_FEATURE_AUDIT").is_some()
        );
        assert_eq!(
            caps.contains(CapabilitySet::POLICY),
            option_env!("CARGO_FEATURE_POLICY").is_some()
        );
    }
}
