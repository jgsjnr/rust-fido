//! Anti-Glitching / Fault Injection Protection (`GAP-06`)
//!
//! Provides fault-resistant representations and redundant validation barriers against
//! Electromagnetic Fault Injection (EMFI), voltage brownouts, and clock glitching attacks
//! targeting authorization branches on the microcontroller.
//!
//! # Architecture & Principles
//! - Uses hamming-distance-32 bit patterns (`0xA5A5_5A5A` and `0x5A5A_A5A5`) rather than single-bit booleans.
//! - Enforces dual-condition checks (`cond_a` and inverted `cond_b_inv`).
//! - Employs `core::hint::black_box` to prevent LLVM/rustc from optimizing redundant checks.
//! - Introduces deterministic micro-loop jitter to disperse glitch timing.

use super::error::SecureGuardError;

/// Glitch-resistant boolean representation with 32-bit Hamming distance.
///
/// `True` is encoded as `0xA5A5_5A5A` and `False` as `0x5A5A_A5A5`.
/// The two states are exact 32-bit bitwise complements (`!0xA5A5_5A5A == 0x5A5A_A5A5`).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlitchResistantBool {
    True = 0xA5A5_5A5A,
    False = 0x5A5A_A5A5,
}

impl GlitchResistantBool {
    /// Bit pattern representing logical True.
    pub const PATTERN_TRUE: u32 = 0xA5A5_5A5A;
    /// Bit pattern representing logical False.
    pub const PATTERN_FALSE: u32 = 0x5A5A_A5A5;

    /// Returns `true` if and only if self matches the strict `True` pattern.
    #[inline(always)]
    pub fn is_true(self) -> bool {
        core::hint::black_box(self as u32) == Self::PATTERN_TRUE
    }

    /// Returns `true` if and only if self matches the strict `False` pattern.
    #[inline(always)]
    pub fn is_false(self) -> bool {
        core::hint::black_box(self as u32) == Self::PATTERN_FALSE
    }

    /// Converts standard bool to `GlitchResistantBool`.
    #[inline]
    pub fn from_bool(val: bool) -> Self {
        if core::hint::black_box(val) {
            Self::True
        } else {
            Self::False
        }
    }

    /// Encodes to raw u32 pattern.
    #[inline]
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    /// Validates raw u32 pattern against legal states, failing closed on glitch/corruption.
    #[inline]
    pub fn from_raw(raw: u32) -> Result<Self, SecureGuardError> {
        let val = core::hint::black_box(raw);
        if val == Self::PATTERN_TRUE {
            Ok(Self::True)
        } else if val == Self::PATTERN_FALSE {
            Ok(Self::False)
        } else {
            Err(SecureGuardError::GlitchDetected)
        }
    }
}

/// Executes a redundant, time-delayed double authorization check.
///
/// # Arguments
/// * `cond_a` - Primary authorization condition (e.g. `is_unlocked`)
/// * `cond_b_inv` - Strict bitwise/logical inverse of `cond_a` (e.g. `!is_unlocked`)
/// * `jitter_seed` - Entropy seed for deterministic micro-loop dispersion
///
/// # Security Guarantees
/// - If `cond_a == cond_b_inv`, an active fault injection is detected -> `Err(GlitchDetected)`.
/// - `core::hint::black_box` prevents dead-code elimination.
/// - Deterministic micro-loops inject non-zero CPU cycle delay between verification points.
pub fn double_check_authorization(
    cond_a: bool,
    cond_b_inv: bool,
    jitter_seed: u32,
) -> Result<GlitchResistantBool, SecureGuardError> {
    // Stage 1: Initial barrier
    let a1 = core::hint::black_box(cond_a);
    let b1 = core::hint::black_box(cond_b_inv);

    // Invariant check: conditions must be complementary
    if a1 == b1 {
        return Err(SecureGuardError::GlitchDetected);
    }

    // Stage 2: Micro-loop delay against EMFI / voltage glitch transient
    let loops = (core::hint::black_box(jitter_seed) & 0x0F) + 5;
    let mut acc = jitter_seed;
    for i in 0..loops {
        acc = core::hint::black_box(acc.rotate_left(3) ^ (i.wrapping_mul(0x9E37_79B9)));
    }
    core::hint::black_box(acc);

    // Stage 3: Second redundant barrier after temporal delay
    let a2 = core::hint::black_box(cond_a);
    let b2 = core::hint::black_box(cond_b_inv);

    if a2 == b2 {
        return Err(SecureGuardError::GlitchDetected);
    }

    // Stage 4: Cross-stage consistency check
    if a1 != a2 || b1 != b2 {
        return Err(SecureGuardError::GlitchDetected);
    }

    // Stage 5: Final output synthesis
    if a2 && !b2 {
        Ok(GlitchResistantBool::True)
    } else if !a2 && b2 {
        Ok(GlitchResistantBool::False)
    } else {
        Err(SecureGuardError::GlitchDetected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glitch_resistant_bool_bit_inversion() {
        assert_eq!(
            !GlitchResistantBool::PATTERN_TRUE,
            GlitchResistantBool::PATTERN_FALSE
        );
        assert_eq!(
            !GlitchResistantBool::PATTERN_FALSE,
            GlitchResistantBool::PATTERN_TRUE
        );

        assert!(GlitchResistantBool::True.is_true());
        assert!(!GlitchResistantBool::True.is_false());
        assert!(GlitchResistantBool::False.is_false());
        assert!(!GlitchResistantBool::False.is_true());
    }

    #[test]
    fn test_double_check_authorization_valid_cases() {
        // Legitimate true: cond_a = true, cond_b_inv = false
        let res_true = double_check_authorization(true, false, 0x1234_5678);
        assert_eq!(res_true, Ok(GlitchResistantBool::True));

        // Legitimate false: cond_a = false, cond_b_inv = true
        let res_false = double_check_authorization(false, true, 0x8765_4321);
        assert_eq!(res_false, Ok(GlitchResistantBool::False));
    }

    #[test]
    fn test_double_check_authorization_detects_inconsistent_faults() {
        // Fault injection: both conditions forced to true
        let fault_both_true = double_check_authorization(true, true, 0xABCD_EF01);
        assert_eq!(fault_both_true, Err(SecureGuardError::GlitchDetected));

        // Fault injection: both conditions forced to false
        let fault_both_false = double_check_authorization(false, false, 0xDEAD_BEEF);
        assert_eq!(fault_both_false, Err(SecureGuardError::GlitchDetected));
    }

    #[test]
    fn test_from_raw_pattern() {
        assert_eq!(
            GlitchResistantBool::from_raw(0xA5A5_5A5A),
            Ok(GlitchResistantBool::True)
        );
        assert_eq!(
            GlitchResistantBool::from_raw(0x5A5A_A5A5),
            Ok(GlitchResistantBool::False)
        );
        // Corrupted single-bit or intermediate values fail closed
        assert_eq!(
            GlitchResistantBool::from_raw(0xA5A5_5A5B),
            Err(SecureGuardError::GlitchDetected)
        );
        assert_eq!(
            GlitchResistantBool::from_raw(0x0000_0000),
            Err(SecureGuardError::GlitchDetected)
        );
        assert_eq!(
            GlitchResistantBool::from_raw(0xFFFF_FFFF),
            Err(SecureGuardError::GlitchDetected)
        );
    }
}
