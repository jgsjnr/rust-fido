//! Secure Guard Error Definitions
//!
//! Strongly-typed errors for the Secure Guard subsystem adhering to fail-closed
//! zero-trust principles.

use super::state::SecureGuardState;

/// Errors produced by Secure Guard state transitions, cryptographic verifications,
/// session enforcement, and persistence integrity checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureGuardError {
    /// Invalid state machine transition attempted.
    InvalidStateTransition {
        from: SecureGuardState,
        to: SecureGuardState,
    },
    /// Operation invoked while Secure Guard is in an incompatible state.
    InvalidStateForOperation {
        current: SecureGuardState,
        expected: &'static str,
    },
    /// The Secure Guard is not provisioned with a PIN.
    NotProvisioned,
    /// PIN is already provisioned; re-provisioning is prohibited without wipe.
    AlreadyProvisioned,
    /// PIN length is below the minimum required by policy.
    PinTooShort {
        min: u8,
        actual: u8,
    },
    /// PIN length exceeds the maximum allowed by policy.
    PinTooLong {
        max: u8,
        actual: u8,
    },
    /// PIN was rejected by policy complexity checks (e.g., trivial repetition or sequence).
    TrivialPinRejected,
    /// PIN verification failed; includes remaining attempts before lockout/wipe.
    InvalidPin {
        remaining_attempts: u8,
    },
    /// PIN verification is temporarily blocked by progressive backoff rate-limiting.
    RateLimited {
        remaining_ms: u64,
    },
    /// PIN verification failed 5 consecutive times and policy requires recovery code.
    MaxAttemptsReachedRecoveryRequired,
    /// PIN verification failed 5 consecutive times and scoped wipe was triggered.
    MaxAttemptsWipeTriggered {
        simulated: bool,
    },
    /// Recovery code was rejected or invalid.
    InvalidRecoveryCode,
    /// Access denied to protected resource because Secure Guard is locked.
    AccessDeniedLocked {
        state: SecureGuardState,
        opcode: u8,
    },
    /// Session expired due to inactivity or absolute timeout.
    SessionExpired,
    /// Operation requires an active unlocked session.
    NoActiveSession,
    /// Corrupted persistent record (CRC mismatch or invalid magic/version).
    PersistenceCorrupted(&'static str),
    /// Unrecognized wire state code.
    UnknownStateCode(u8),
}

impl core::fmt::Display for SecureGuardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidStateTransition { from, to } => {
                write!(f, "Invalid state transition from {:?} to {:?}", from, to)
            }
            Self::InvalidStateForOperation { current, expected } => {
                write!(
                    f,
                    "Invalid state {:?} for operation, expected {}",
                    current, expected
                )
            }
            Self::NotProvisioned => write!(f, "Secure Guard is not provisioned"),
            Self::AlreadyProvisioned => write!(f, "Secure Guard is already provisioned"),
            Self::PinTooShort { min, actual } => {
                write!(f, "PIN too short: min is {}, got {}", min, actual)
            }
            Self::PinTooLong { max, actual } => {
                write!(f, "PIN too long: max is {}, got {}", max, actual)
            }
            Self::TrivialPinRejected => write!(f, "Trivial PIN rejected by policy"),
            Self::InvalidPin { remaining_attempts } => {
                write!(
                    f,
                    "Invalid PIN ({} attempts remaining)",
                    remaining_attempts
                )
            }
            Self::RateLimited { remaining_ms } => {
                write!(
                    f,
                    "Authentication rate limited, wait {} ms",
                    remaining_ms
                )
            }
            Self::MaxAttemptsReachedRecoveryRequired => {
                write!(f, "Maximum PIN attempts reached: recovery code required")
            }
            Self::MaxAttemptsWipeTriggered { simulated } => {
                write!(
                    f,
                    "Maximum PIN attempts reached: wipe triggered (simulated={})",
                    simulated
                )
            }
            Self::InvalidRecoveryCode => write!(f, "Invalid recovery code"),
            Self::AccessDeniedLocked { state, opcode } => {
                write!(
                    f,
                    "Access denied to opcode 0x{:02X}: Secure Guard is {:?}",
                    opcode, state
                )
            }
            Self::SessionExpired => write!(f, "Secure Guard session expired"),
            Self::NoActiveSession => write!(f, "No active Secure Guard session"),
            Self::PersistenceCorrupted(reason) => {
                write!(f, "Secure Guard persistent record corrupted: {}", reason)
            }
            Self::UnknownStateCode(code) => {
                write!(f, "Unknown state code 0x{:02X}", code)
            }
        }
    }
}
