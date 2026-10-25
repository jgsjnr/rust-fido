//! Secure Guard Formal State Machine
//!
//! Implements the 10 canonical states with deterministic, auditable transitions
//! as specified in Section 5.4.

use super::error::SecureGuardError;

/// The 10 canonical states of the Secure Guard state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SecureGuardState {
    /// Factory fresh or wiped; no PIN provisioned (wire code 0x00).
    Unprovisioned = 0x00,
    /// Actively provisioning a new PIN and recovery secret (wire code 0x01).
    Provisioning = 0x01,
    /// Provisioned, armed, and locked awaiting authentication (wire code 0x02).
    Locked = 0x02,
    /// In the process of evaluating PIN or recovery credentials (wire code 0x03).
    Authenticating = 0x03,
    /// Successfully authenticated; active session authorized for protected resources (wire code 0x04).
    Unlocked = 0x04,
    /// 5 consecutive PIN failures reached and policy specifies recovery required (wire code 0x05).
    RecoveryRequired = 0x05,
    /// Temporary progressive backoff penalty enforced after failed attempt (wire code 0x06).
    RateLimited = 0x06,
    /// 5 consecutive PIN failures reached and policy specifies wipe pending (wire code 0x07).
    WipePending = 0x07,
    /// Scoped wipe execution in progress (wire code 0x08).
    WipeInProgress = 0x08,
    /// Fail-closed terminal error state due to integrity or persistent storage fault (wire code 0x09).
    ErrorLocked = 0x09,
}

impl SecureGuardState {
    /// Returns the wire protocol representation code for the state.
    pub const fn wire_code(self) -> u8 {
        self as u8
    }

    /// Converts a wire protocol byte to `SecureGuardState`.
    pub const fn from_wire_code(code: u8) -> Result<Self, SecureGuardError> {
        match code {
            0x00 => Ok(Self::Unprovisioned),
            0x01 => Ok(Self::Provisioning),
            0x02 => Ok(Self::Locked),
            0x03 => Ok(Self::Authenticating),
            0x04 => Ok(Self::Unlocked),
            0x05 => Ok(Self::RecoveryRequired),
            0x06 => Ok(Self::RateLimited),
            0x07 => Ok(Self::WipePending),
            0x08 => Ok(Self::WipeInProgress),
            0x09 => Ok(Self::ErrorLocked),
            other => Err(SecureGuardError::UnknownStateCode(other)),
        }
    }

    /// Validates whether a transition from `self` to `target` is permitted.
    pub const fn can_transition_to(self, target: Self) -> bool {
        // Idempotent transitions are always permitted
        if self as u8 == target as u8 {
            return true;
        }

        // Any state can transition to ErrorLocked on persistent/integrity fault
        if matches!(target, Self::ErrorLocked) {
            return true;
        }

        match self {
            Self::Unprovisioned => matches!(target, Self::Provisioning),
            Self::Provisioning => matches!(target, Self::Locked | Self::Unlocked | Self::Unprovisioned),
            Self::Locked => matches!(
                target,
                Self::Authenticating
                    | Self::RateLimited
                    | Self::RecoveryRequired
                    | Self::WipePending
            ),
            Self::Authenticating => matches!(
                target,
                Self::Unlocked
                    | Self::Locked
                    | Self::RateLimited
                    | Self::RecoveryRequired
                    | Self::WipePending
            ),
            Self::Unlocked => matches!(target, Self::Locked | Self::Authenticating),
            Self::RecoveryRequired => matches!(target, Self::Authenticating | Self::Locked | Self::Unlocked),
            Self::RateLimited => matches!(target, Self::Locked),
            Self::WipePending => matches!(target, Self::WipeInProgress),
            Self::WipeInProgress => matches!(target, Self::Unprovisioned | Self::Locked),
            Self::ErrorLocked => matches!(target, Self::Unprovisioned),
        }
    }

    /// Validates the transition and returns an error if illegal.
    pub fn validate_transition(self, target: Self) -> Result<(), SecureGuardError> {
        if self.can_transition_to(target) {
            Ok(())
        } else {
            Err(SecureGuardError::InvalidStateTransition {
                from: self,
                to: target,
            })
        }
    }

    /// True if the state permits executing protected operations without re-authentication.
    pub const fn is_unlocked(self) -> bool {
        matches!(self, Self::Unlocked)
    }

    /// True if PIN authentication can be attempted from this state.
    pub const fn can_authenticate(self) -> bool {
        matches!(self, Self::Locked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_wire_codes() {
        assert_eq!(SecureGuardState::Unprovisioned.wire_code(), 0x00);
        assert_eq!(SecureGuardState::Provisioning.wire_code(), 0x01);
        assert_eq!(SecureGuardState::Locked.wire_code(), 0x02);
        assert_eq!(SecureGuardState::Authenticating.wire_code(), 0x03);
        assert_eq!(SecureGuardState::Unlocked.wire_code(), 0x04);
        assert_eq!(SecureGuardState::RecoveryRequired.wire_code(), 0x05);
        assert_eq!(SecureGuardState::RateLimited.wire_code(), 0x06);
        assert_eq!(SecureGuardState::WipePending.wire_code(), 0x07);
        assert_eq!(SecureGuardState::WipeInProgress.wire_code(), 0x08);
        assert_eq!(SecureGuardState::ErrorLocked.wire_code(), 0x09);

        for code in 0x00..=0x09 {
            let state = SecureGuardState::from_wire_code(code).unwrap();
            assert_eq!(state.wire_code(), code);
        }

        assert!(SecureGuardState::from_wire_code(0x0A).is_err());
        assert!(SecureGuardState::from_wire_code(0xFF).is_err());
    }

    #[test]
    fn test_valid_transitions() {
        // Unprovisioned
        assert!(SecureGuardState::Unprovisioned.can_transition_to(SecureGuardState::Provisioning));
        assert!(SecureGuardState::Unprovisioned.can_transition_to(SecureGuardState::ErrorLocked));
        assert!(!SecureGuardState::Unprovisioned.can_transition_to(SecureGuardState::Unlocked));

        // Locked
        assert!(SecureGuardState::Locked.can_transition_to(SecureGuardState::Authenticating));
        assert!(SecureGuardState::Locked.can_transition_to(SecureGuardState::RateLimited));
        assert!(SecureGuardState::Locked.can_transition_to(SecureGuardState::RecoveryRequired));
        assert!(SecureGuardState::Locked.can_transition_to(SecureGuardState::WipePending));
        assert!(!SecureGuardState::Locked.can_transition_to(SecureGuardState::Unlocked));

        // Authenticating
        assert!(SecureGuardState::Authenticating.can_transition_to(SecureGuardState::Unlocked));
        assert!(SecureGuardState::Authenticating.can_transition_to(SecureGuardState::Locked));
        assert!(SecureGuardState::Authenticating.can_transition_to(SecureGuardState::RateLimited));

        // Unlocked
        assert!(SecureGuardState::Unlocked.can_transition_to(SecureGuardState::Locked));
        assert!(!SecureGuardState::Unlocked.can_transition_to(SecureGuardState::Unprovisioned));

        // RecoveryRequired
        assert!(SecureGuardState::RecoveryRequired.can_transition_to(SecureGuardState::Authenticating));
        assert!(SecureGuardState::RecoveryRequired.can_transition_to(SecureGuardState::Locked));
        assert!(!SecureGuardState::RecoveryRequired.can_transition_to(SecureGuardState::RateLimited));

        // RateLimited
        assert!(SecureGuardState::RateLimited.can_transition_to(SecureGuardState::Locked));
        assert!(!SecureGuardState::RateLimited.can_transition_to(SecureGuardState::Unlocked));

        // Wipe cycle
        assert!(SecureGuardState::WipePending.can_transition_to(SecureGuardState::WipeInProgress));
        assert!(SecureGuardState::WipeInProgress.can_transition_to(SecureGuardState::Unprovisioned));
    }
}
