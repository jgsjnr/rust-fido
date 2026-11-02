//! Secure Guard Security Policy
//!
//! Enforces PIN length, complexity, progressive backoff rate-limiting,
//! session duration, and wipe-on-failure policies.

use super::crypto::PBKDF2_DEFAULT_ITERATIONS;
use super::error::SecureGuardError;

/// Strict maximum consecutive PIN failures before lockout or wipe.
pub const MAX_ATTEMPTS: u8 = 5;

/// Security policy configuration for Secure Guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureGuardPolicy {
    /// If true, reaching 5 consecutive failures triggers WipePending -> WipeInProgress.
    /// If false (default), reaching 5 consecutive failures transitions to RecoveryRequired.
    pub wipe_on_5_failures: bool,
    /// Protect KeyManager and AEGN envelope operations (0x20..0x23). Default true.
    pub protect_keys_and_aegn: bool,
    /// Protect OATH/TOTP operations (0x24..0x27). Default false (allows rapid read).
    pub protect_oath: bool,
    /// Non-destructive test mode: executes full wipe rite and marks `last_wipe_simulated = true`
    /// without erasing real user keys during bench/HIL tests.
    pub test_mode_non_destructive_wipe: bool,
    /// Minimum PIN length in bytes (default 4).
    pub min_pin_len: u8,
    /// Maximum PIN length in bytes (default 16).
    pub max_pin_len: u8,
    /// Reject trivial PINs (all-repeating or strictly sequential ascending/descending).
    pub reject_trivial_pins: bool,
    /// Absolute session duration timeout in milliseconds (default: 300,000 ms / 5 min).
    pub session_duration_ms: u64,
    /// Inactivity timeout in milliseconds (default: 120,000 ms / 2 min).
    pub inactivity_timeout_ms: u64,
    /// Iterations for PBKDF2-HMAC-SHA256 derivation.
    pub pbkdf2_iterations: u32,
}

impl Default for SecureGuardPolicy {
    fn default() -> Self {
        Self {
            wipe_on_5_failures: false,
            protect_keys_and_aegn: true,
            protect_oath: false,
            test_mode_non_destructive_wipe: false,
            min_pin_len: 4,
            max_pin_len: 16,
            reject_trivial_pins: false,
            session_duration_ms: 300_000,
            inactivity_timeout_ms: 120_000,
            pbkdf2_iterations: PBKDF2_DEFAULT_ITERATIONS,
        }
    }
}

impl SecureGuardPolicy {
    /// Validates a candidate PIN against the length and triviality constraints.
    pub fn validate_pin(&self, pin: &[u8]) -> Result<(), SecureGuardError> {
        let len = pin.len();
        if len < self.min_pin_len as usize {
            return Err(SecureGuardError::PinTooShort {
                min: self.min_pin_len,
                actual: len as u8,
            });
        }
        if len > self.max_pin_len as usize {
            return Err(SecureGuardError::PinTooLong {
                max: self.max_pin_len,
                actual: len as u8,
            });
        }

        if self.reject_trivial_pins && len >= 2 {
            // 1. All repeating characters (e.g., "0000", "1111", "aaaa")
            let first = pin[0];
            if pin.iter().all(|&b| b == first) {
                return Err(SecureGuardError::TrivialPinRejected);
            }

            // 2. Sequential ascending (e.g., "1234") or descending ("4321")
            let mut is_asc = true;
            let mut is_desc = true;
            for window in pin.windows(2) {
                let diff = (window[1] as i16) - (window[0] as i16);
                if diff != 1 {
                    is_asc = false;
                }
                if diff != -1 {
                    is_desc = false;
                }
            }
            if is_asc || is_desc {
                return Err(SecureGuardError::TrivialPinRejected);
            }
        }

        Ok(())
    }

    /// Computes progressive backoff penalty in milliseconds for the given failure count.
    ///
    /// - Attempt 1: 0 ms
    /// - Attempt 2: 2,000 ms
    /// - Attempt 3: 5,000 ms
    /// - Attempt 4: 15,000 ms
    pub fn compute_backoff_ms(&self, failed_attempts: u8) -> u64 {
        match failed_attempts {
            0 | 1 => 0,
            2 => 2_000,
            3 => 5_000,
            4 => 15_000,
            _ => 60_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_length_validation() {
        let policy = SecureGuardPolicy::default();

        // Too short (< 4)
        assert!(matches!(
            policy.validate_pin(b"123"),
            Err(SecureGuardError::PinTooShort { min: 4, actual: 3 })
        ));

        // Too long (> 16)
        assert!(matches!(
            policy.validate_pin(b"12345678901234567"),
            Err(SecureGuardError::PinTooLong {
                max: 16,
                actual: 17
            })
        ));

        // Valid length
        assert!(policy.validate_pin(b"4927").is_ok());
    }

    #[test]
    fn test_trivial_pin_rejection() {
        let mut policy = SecureGuardPolicy::default();
        policy.reject_trivial_pins = true;

        // Repeating
        assert_eq!(
            policy.validate_pin(b"0000"),
            Err(SecureGuardError::TrivialPinRejected)
        );
        assert_eq!(
            policy.validate_pin(b"99999"),
            Err(SecureGuardError::TrivialPinRejected)
        );

        // Sequential ascending
        assert_eq!(
            policy.validate_pin(b"1234"),
            Err(SecureGuardError::TrivialPinRejected)
        );
        assert_eq!(
            policy.validate_pin(b"23456"),
            Err(SecureGuardError::TrivialPinRejected)
        );

        // Sequential descending
        assert_eq!(
            policy.validate_pin(b"4321"),
            Err(SecureGuardError::TrivialPinRejected)
        );
        assert_eq!(
            policy.validate_pin(b"65432"),
            Err(SecureGuardError::TrivialPinRejected)
        );

        // Non-trivial valid PINs
        assert!(policy.validate_pin(b"4927").is_ok());
        assert!(policy.validate_pin(b"8193").is_ok());
        assert!(policy.validate_pin(b"a1b2c3").is_ok());
    }

    #[test]
    fn test_default_policy_accepts_any_pin_length_4_to_16() {
        let policy = SecureGuardPolicy::default();
        assert!(!policy.reject_trivial_pins);
        assert!(policy.validate_pin(b"000000").is_ok());
        assert!(policy.validate_pin(b"123456").is_ok());
        assert!(policy.validate_pin(b"849201").is_ok());
        assert!(policy.validate_pin(b"1111").is_ok());
        assert!(policy.validate_pin(b"1234").is_ok());
    }

    #[test]
    fn test_backoff_delays() {
        let policy = SecureGuardPolicy::default();
        assert_eq!(policy.compute_backoff_ms(0), 0);
        assert_eq!(policy.compute_backoff_ms(1), 0);
        assert_eq!(policy.compute_backoff_ms(2), 2_000);
        assert_eq!(policy.compute_backoff_ms(3), 5_000);
        assert_eq!(policy.compute_backoff_ms(4), 15_000);
    }
}
