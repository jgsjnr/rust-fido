//! User Presence policy shared by RESC and future CTAP paths.
//!
//! Extracts the `check_up(pin, presence)` gate previously inlined in
//! `RescueEngine::handle_packet` so destructive RESC operations and future
//! CTAP commands share one saturating, allocation-free policy.
//! Error codes are preserved: RESC keeps `RESCUE_STATUS_CONFIRMATION_FAILED`
//! on the wire, CTAP mapping reuses existing `CtapError` codes via `From`.

use crate::ctap::status_code::CtapError;
use crate::otp::rescue::RESCUE_STATUS_CONFIRMATION_FAILED;

/// Typed policy denial. Maps to existing wire codes without changing them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// User presence latch missing.
    PresenceRequired,
    /// PIN/UV auth missing where required.
    PinRequired,
}

impl PolicyError {
    /// Existing CTAP error preserving wire codes.
    pub fn to_ctap_error(self) -> CtapError {
        match self {
            Self::PresenceRequired => CtapError::OperationDenied,
            Self::PinRequired => CtapError::PinRequired,
        }
    }

    /// Existing RESC status preserving magic/opcodes/frames.
    pub fn to_rescue_status(self) -> u8 {
        RESCUE_STATUS_CONFIRMATION_FAILED
    }
}

impl From<PolicyError> for CtapError {
    fn from(e: PolicyError) -> Self {
        e.to_ctap_error()
    }
}

/// Presence + PIN gate: `check_up(pin, presence)` shared by RESC and CTAP.
///
/// Implementors encode whether PIN is required (`requires_pin`); `check_up`
/// is allocation-free and performs no I/O.
pub trait UpPolicy {
    /// Whether this policy requires PIN/UV in addition to presence.
    fn requires_pin(&self) -> bool;
    /// Checks `pin_authenticated` and `presence_confirmed` per policy.
    fn check_up(
        &self,
        pin_authenticated: bool,
        presence_confirmed: bool,
    ) -> Result<(), PolicyError>;
}

/// Presence-only gate (RESC PING/DIAGNOSTICS, CTAP GetInfo-style).
#[derive(Debug, Clone, Copy, Default)]
pub struct UpOnly;

/// Presence + PIN gate (RESC WIPE/RECOVERY/REBOOT, future CTAP sensitive ops).
#[derive(Debug, Clone, Copy, Default)]
pub struct UpAndPin;

impl UpPolicy for UpOnly {
    fn requires_pin(&self) -> bool {
        false
    }
    fn check_up(
        &self,
        _pin_authenticated: bool,
        presence_confirmed: bool,
    ) -> Result<(), PolicyError> {
        if presence_confirmed {
            Ok(())
        } else {
            Err(PolicyError::PresenceRequired)
        }
    }
}

impl UpPolicy for UpAndPin {
    fn requires_pin(&self) -> bool {
        true
    }
    fn check_up(
        &self,
        pin_authenticated: bool,
        presence_confirmed: bool,
    ) -> Result<(), PolicyError> {
        if !presence_confirmed {
            return Err(PolicyError::PresenceRequired);
        }
        if !pin_authenticated {
            return Err(PolicyError::PinRequired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn up_only_allows_without_pin() {
        let p = UpOnly;
        assert!(!p.requires_pin());
        assert!(p.check_up(false, true).is_ok());
        assert_eq!(
            p.check_up(false, false).unwrap_err(),
            PolicyError::PresenceRequired
        );
    }
    #[test]
    fn up_and_pin_requires_both() {
        let p = UpAndPin;
        assert!(p.requires_pin());
        assert!(p.check_up(true, true).is_ok());
        assert_eq!(
            p.check_up(true, false).unwrap_err(),
            PolicyError::PresenceRequired
        );
        assert_eq!(
            p.check_up(false, true).unwrap_err(),
            PolicyError::PinRequired
        );
    }
    #[test]
    fn preserves_wire_codes() {
        assert_eq!(
            PolicyError::PresenceRequired.to_ctap_error(),
            CtapError::OperationDenied
        );
        assert_eq!(
            PolicyError::PinRequired.to_ctap_error(),
            CtapError::PinRequired
        );
        assert_eq!(
            CtapError::from(PolicyError::PresenceRequired).to_status_code(),
            CtapError::OperationDenied.to_status_code()
        );
        assert_eq!(
            PolicyError::PresenceRequired.to_rescue_status(),
            RESCUE_STATUS_CONFIRMATION_FAILED
        );
        assert_eq!(
            PolicyError::PinRequired.to_rescue_status(),
            RESCUE_STATUS_CONFIRMATION_FAILED
        );
    }
}
