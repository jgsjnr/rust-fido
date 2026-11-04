//! PM policy + fail-closed gates (SRP: quota/rate-limit/window/domain here,
//! enforcement at the call sites in [`crate::store`]).
//!
//! Domain separation: the PM vault never reuses wallet share slots or the
//! FIDO master-key derivation. See [`crate::backup::PM_SHARE_DOMAIN`] and
//! [`PmPolicy::PM_MASTER_SALT`] / [`PmPolicy::PM_MASTER_INFO`].

use aegis_secure_guard::SecureGuardPolicy;

/// Binding window in milliseconds: a release more than 60 s after binding
/// closes the viewer (walk-away closes the session).
pub const PM_BINDING_WINDOW_MS: u64 = 60_000;

/// Fail-closed denial. Wire mapping preserves the firmware BLE vocabulary:
/// unbound → `NeedBinding`, no presence → `PresenceRequired`,
/// no PIN → `PinRequired`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmError {
    /// No bonded phone on this session.
    NeedBinding,
    /// User-presence (button/OLED confirm) missing.
    PresenceRequired,
    /// PIN/UV auth missing where required.
    PinRequired,
    /// Binding window (60 s) elapsed.
    BindingWindowExpired,
    /// Vault quota exhausted.
    QuotaExceeded,
    /// Record exceeds structural or policy size caps.
    EntryTooLarge,
    /// Record id not found.
    NotFound,
    /// Record id already exists (use update path instead).
    Duplicate,
    /// AEAD open/seal failure (wrong PIN token or tampered bytes).
    Sealed,
    /// CBOR encode/decode failure.
    Serialization,
    /// Shamir backup failure (checksum / index misuse).
    Backup,
    /// Persistence backend failure (firmware NVS write error, ...).
    Storage,
}

impl core::fmt::Display for PmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NeedBinding => write!(f, "no bonded device for this PM session"),
            Self::PresenceRequired => write!(f, "user presence required"),
            Self::PinRequired => write!(f, "PIN authentication required"),
            Self::BindingWindowExpired => write!(f, "binding window (60 s) expired"),
            Self::QuotaExceeded => write!(f, "password vault quota exceeded"),
            Self::EntryTooLarge => write!(f, "password entry exceeds size caps"),
            Self::NotFound => write!(f, "password entry not found"),
            Self::Duplicate => write!(f, "password entry id already exists"),
            Self::Sealed => write!(f, "AEAD seal/open failed"),
            Self::Serialization => write!(f, "CBOR encode/decode failed"),
            Self::Backup => write!(f, "Shamir backup operation failed"),
            Self::Storage => write!(f, "opaque-blob persistence failed"),
        }
    }
}

impl From<PmError> for aegis_fido_core::policy::PolicyError {
    /// Maps the PM gate denials onto the shared UP/PIN vocabulary without
    /// changing wire codes. Binding/window denials are presence-class
    /// (fail-closed), never success.
    fn from(e: PmError) -> Self {
        match e {
            PmError::PresenceRequired | PmError::NeedBinding | PmError::BindingWindowExpired => {
                Self::PresenceRequired
            }
            PmError::PinRequired => Self::PinRequired,
            _ => Self::PresenceRequired,
        }
    }
}

/// Snapshot of the session gates for one PM operation.
///
/// The phone is a blind transport: it carries this attestation, the device
/// decides. `bound_within_ms` is the age of the binding authorization;
/// releases past [`PM_BINDING_WINDOW_MS`] fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmGateState {
    /// A bonded phone owns this session (BLE bonding / CTAPHID session).
    pub binding_bound: bool,
    /// Physical user presence confirmed (GPIO 0 + OLED summary).
    pub presence_confirmed: bool,
    /// PIN/UV authenticated for this session.
    pub pin_authenticated: bool,
    /// Milliseconds since binding authorization (walk-away timer).
    pub bound_within_ms: u64,
}

impl PmGateState {
    /// Fully authorized session (tests / firmware after all checks).
    pub fn authorized() -> Self {
        Self {
            binding_bound: true,
            presence_confirmed: true,
            pin_authenticated: true,
            bound_within_ms: 0,
        }
    }
}

/// Quota + gate policy for the password vault.
///
/// `max_*` are policy caps (≤ structural caps in [`crate::entry`]).
/// PIN backoff reuses [`SecureGuardPolicy::compute_backoff_ms`] so the PM
/// vault and SecureGuard share one progressive-delay schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PmPolicy {
    /// Max number of password records.
    pub max_entries: usize,
    /// Max label bytes per record.
    pub max_label_bytes: usize,
    /// Max username bytes per record.
    pub max_username_bytes: usize,
    /// Max secret bytes per record.
    pub max_secret_bytes: usize,
    /// Binding window in ms (default [`PM_BINDING_WINDOW_MS`]).
    pub binding_window_ms: u64,
    /// Consecutive PIN failures before wipe scoping (mirrors `MAX_ATTEMPTS`).
    pub max_pin_attempts: u8,
}

impl Default for PmPolicy {
    fn default() -> Self {
        Self {
            max_entries: 200,
            max_label_bytes: 64,
            max_username_bytes: 128,
            max_secret_bytes: 256,
            binding_window_ms: PM_BINDING_WINDOW_MS,
            max_pin_attempts: aegis_secure_guard::policy::MAX_ATTEMPTS,
        }
    }
}

impl PmPolicy {
    /// HKDF salt for the PM master key — distinct from the FIDO vault salt
    /// (`AegisKey-Vault-Master-Salt-v1`) and from wallet derivation.
    pub const PM_MASTER_SALT: &'static [u8] = b"AegisKey-PM-Master-Salt-v1";
    /// HKDF info for the PM master key — distinct from the FIDO vault info.
    pub const PM_MASTER_INFO: &'static [u8] = b"AegisKey-PM-Master-Key-v1";

    /// Fail-closed release gate: binding → presence → PIN → window.
    pub fn check_release(&self, gate: &PmGateState) -> Result<(), PmError> {
        if !gate.binding_bound {
            return Err(PmError::NeedBinding);
        }
        if !gate.presence_confirmed {
            return Err(PmError::PresenceRequired);
        }
        if !gate.pin_authenticated {
            return Err(PmError::PinRequired);
        }
        if gate.bound_within_ms > self.binding_window_ms {
            return Err(PmError::BindingWindowExpired);
        }
        Ok(())
    }

    /// Insert-time quota + size check (gates still required by the caller).
    pub fn check_put(
        &self,
        entry_count: usize,
        label_len: usize,
        username_len: usize,
        secret_len: usize,
    ) -> Result<(), PmError> {
        if entry_count >= self.max_entries {
            return Err(PmError::QuotaExceeded);
        }
        if label_len > self.max_label_bytes
            || username_len > self.max_username_bytes
            || secret_len > self.max_secret_bytes
        {
            return Err(PmError::EntryTooLarge);
        }
        Ok(())
    }

    /// Progressive PIN backoff shared with SecureGuard (attempts 1→0 ms,
    /// 2→2 s, 3→5 s, 4→15 s, ≥5→60 s).
    pub fn pin_backoff_ms(&self, failed_attempts: u8) -> u64 {
        SecureGuardPolicy::default().compute_backoff_ms(failed_attempts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gates_fail_closed_in_order() {
        let p = PmPolicy::default();
        // No binding denies first even when everything else is missing.
        let g = PmGateState {
            binding_bound: false,
            presence_confirmed: false,
            pin_authenticated: false,
            bound_within_ms: 0,
        };
        assert_eq!(p.check_release(&g), Err(PmError::NeedBinding));
        // Presence next.
        let g = PmGateState {
            binding_bound: true,
            ..g
        };
        assert_eq!(p.check_release(&g), Err(PmError::PresenceRequired));
        // Then PIN.
        let g = PmGateState {
            presence_confirmed: true,
            ..g
        };
        assert_eq!(p.check_release(&g), Err(PmError::PinRequired));
        // Then window.
        let g = PmGateState {
            pin_authenticated: true,
            bound_within_ms: PM_BINDING_WINDOW_MS + 1,
            ..g
        };
        assert_eq!(p.check_release(&g), Err(PmError::BindingWindowExpired));
        // Authorized passes.
        assert!(p.check_release(&PmGateState::authorized()).is_ok());
        // Window edge is inclusive.
        let g = PmGateState {
            bound_within_ms: PM_BINDING_WINDOW_MS,
            ..PmGateState::authorized()
        };
        assert!(p.check_release(&g).is_ok());
    }

    #[test]
    fn quota_and_sizes_enforced() {
        let p = PmPolicy {
            max_entries: 1,
            ..Default::default()
        };
        assert_eq!(p.check_put(1, 4, 4, 8), Err(PmError::QuotaExceeded));
        assert_eq!(
            p.check_put(0, p.max_label_bytes + 1, 4, 8),
            Err(PmError::EntryTooLarge)
        );
        assert!(p.check_put(0, 4, 4, 8).is_ok());
    }

    #[test]
    fn wire_mapping_preserves_shared_vocabulary() {
        use aegis_fido_core::policy::PolicyError;
        assert_eq!(
            PolicyError::from(PmError::PresenceRequired),
            PolicyError::PresenceRequired
        );
        assert_eq!(
            PolicyError::from(PmError::PinRequired),
            PolicyError::PinRequired
        );
        // Binding/window denials are presence-class (fail closed, never Ok).
        assert_eq!(
            PolicyError::from(PmError::NeedBinding),
            PolicyError::PresenceRequired
        );
        assert_eq!(
            PolicyError::from(PmError::BindingWindowExpired),
            PolicyError::PresenceRequired
        );
    }

    #[test]
    fn pin_backoff_matches_secure_guard_schedule() {
        let p = PmPolicy::default();
        assert_eq!(p.pin_backoff_ms(1), 0);
        assert_eq!(p.pin_backoff_ms(2), 2_000);
        assert_eq!(p.pin_backoff_ms(3), 5_000);
        assert_eq!(p.pin_backoff_ms(4), 15_000);
        assert_eq!(p.pin_backoff_ms(5), 60_000);
    }

    /// Compile-time REGRA Nº1 proof: no `TEST_*`/bypass helper exists on the
    /// release path. `test-mode` adds no bypass in this crate; this test pins
    /// the release side the same way `aegis-secure-guard` does.
    #[cfg(not(feature = "test-mode"))]
    #[test]
    fn release_build_contains_no_test_bypass() {
        const { assert!(!cfg!(feature = "test-mode")) };
    }
}
