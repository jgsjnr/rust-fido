//! SDK error states (R4) plus the R12 `NotCompiled` mapping.
//!
//! `NotCompiled` is returned *only* by the `require_*` gates below when the
//! matching Cargo feature is off. It is never produced for a runtime
//! failure.

use core::fmt::{self, Display, Formatter};

/// Facade-level outcome (no synthetic success, no mock paths).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdkError {
    /// Operation not supported by this device build.
    Unsupported,
    /// Temporarily unavailable (e.g. transport busy).
    Unavailable,
    /// Denied: fail-closed gate (binding/UP/PIN, wire `0x05`/`0x01`/`0x02`).
    PermissionDenied,
    /// Family compiled off (feature missing). Only source of this variant.
    NotCompiled,
    /// Blocked on an external dependency (lab-mocks off, no hardware).
    ExternalBlocked,
}

impl Display for SdkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "unsupported"),
            Self::Unavailable => write!(f, "unavailable"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::NotCompiled => write!(f, "not compiled in this build"),
            Self::ExternalBlocked => write!(f, "externally blocked"),
        }
    }
}

impl core::error::Error for SdkError {}

/// R12 gate: `Ok` only with feature `fido`, else `NotCompiled`.
pub const fn require_fido() -> Result<(), SdkError> {
    if cfg!(feature = "fido") {
        Ok(())
    } else {
        Err(SdkError::NotCompiled)
    }
}

/// R12 gate: `Ok` only with feature `hardwallet`, else `NotCompiled`.
pub const fn require_hardwallet() -> Result<(), SdkError> {
    if cfg!(feature = "hardwallet") {
        Ok(())
    } else {
        Err(SdkError::NotCompiled)
    }
}

/// R12 gate: `Ok` only with feature `secmon`, else `NotCompiled`.
pub const fn require_secmon() -> Result<(), SdkError> {
    if cfg!(feature = "secmon") {
        Ok(())
    } else {
        Err(SdkError::NotCompiled)
    }
}

/// R12 gate: `Ok` only with feature `pm`, else `NotCompiled`.
///
/// Phase F-PM2 contract only: typed CBOR transport lives behind this gate
/// here; envelope/policy enforcement lives in `aegis-pm-vault` + firmware.
pub const fn require_pm() -> Result<(), SdkError> {
    if cfg!(feature = "pm") {
        Ok(())
    } else {
        Err(SdkError::NotCompiled)
    }
}

/// R7 gate: `Ok` only with lab feature `test-mode`, else `NotCompiled`.
///
/// Never in `default`: without it the crate exposes no test surface at all.
pub const fn require_test_mode() -> Result<(), SdkError> {
    if cfg!(feature = "test-mode") {
        Ok(())
    } else {
        Err(SdkError::NotCompiled)
    }
}

/// R12 gate: `Ok` only with feature `ota`, else `NotCompiled`.
///
/// Phase 0 contract only: no execution logic lives behind this gate here.
pub const fn require_ota() -> Result<(), SdkError> {
    if cfg!(feature = "ota") {
        Ok(())
    } else {
        Err(SdkError::NotCompiled)
    }
}

/// R12 gate: `Ok` only with feature `piv`, else `NotCompiled`.
///
/// Phase 0 contract only: no execution logic lives behind this gate here.
pub const fn require_piv() -> Result<(), SdkError> {
    if cfg!(feature = "piv") {
        Ok(())
    } else {
        Err(SdkError::NotCompiled)
    }
}

/// R12 gate: `Ok` only with feature `otp`, else `NotCompiled`.
///
/// Phase 0 contract only: no execution logic lives behind this gate here.
pub const fn require_otp() -> Result<(), SdkError> {
    if cfg!(feature = "otp") {
        Ok(())
    } else {
        Err(SdkError::NotCompiled)
    }
}

/// R12 gate: `Ok` only with feature `proximity`, else `NotCompiled`.
///
/// Phase 0 contract only: no execution logic lives behind this gate here.
pub const fn require_proximity() -> Result<(), SdkError> {
    if cfg!(feature = "proximity") {
        Ok(())
    } else {
        Err(SdkError::NotCompiled)
    }
}

/// R12 gate: `Ok` only with feature `oath`, else `NotCompiled`.
///
/// Phase 0 contract only: no execution logic lives behind this gate here.
pub const fn require_oath() -> Result<(), SdkError> {
    if cfg!(feature = "oath") {
        Ok(())
    } else {
        Err(SdkError::NotCompiled)
    }
}

/// R12 gate: `Ok` only with feature `backup`, else `NotCompiled`.
///
/// Phase 0 contract only: no execution logic lives behind this gate here.
pub const fn require_backup() -> Result<(), SdkError> {
    if cfg!(feature = "backup") {
        Ok(())
    } else {
        Err(SdkError::NotCompiled)
    }
}

/// R12 gate: `Ok` only with feature `audit`, else `NotCompiled`.
///
/// Phase 0 contract only: no execution logic lives behind this gate here.
pub const fn require_audit() -> Result<(), SdkError> {
    if cfg!(feature = "audit") {
        Ok(())
    } else {
        Err(SdkError::NotCompiled)
    }
}

/// R12 gate: `Ok` only with feature `policy`, else `NotCompiled`.
///
/// Phase 0 contract only: no execution logic lives behind this gate here.
pub const fn require_policy() -> Result<(), SdkError> {
    if cfg!(feature = "policy") {
        Ok(())
    } else {
        Err(SdkError::NotCompiled)
    }
}

#[cfg(test)]
mod tests {
    use crate::error::{
        require_audit, require_backup, require_fido, require_hardwallet, require_oath, require_ota,
        require_otp, require_piv, require_policy, require_proximity, require_secmon,
        require_test_mode, SdkError,
    };
    use alloc::string::ToString;

    #[test]
    fn gates_follow_features() {
        if cfg!(feature = "fido") {
            assert_eq!(require_fido(), Ok(()));
        } else {
            assert_eq!(require_fido(), Err(SdkError::NotCompiled));
        }
        if cfg!(feature = "hardwallet") {
            assert_eq!(require_hardwallet(), Ok(()));
        } else {
            assert_eq!(require_hardwallet(), Err(SdkError::NotCompiled));
        }
        if cfg!(feature = "secmon") {
            assert_eq!(require_secmon(), Ok(()));
        } else {
            assert_eq!(require_secmon(), Err(SdkError::NotCompiled));
        }
        if cfg!(feature = "test-mode") {
            assert_eq!(require_test_mode(), Ok(()));
        } else {
            assert_eq!(require_test_mode(), Err(SdkError::NotCompiled));
        }
        if cfg!(feature = "ota") {
            assert_eq!(require_ota(), Ok(()));
        } else {
            assert_eq!(require_ota(), Err(SdkError::NotCompiled));
        }
        if cfg!(feature = "piv") {
            assert_eq!(require_piv(), Ok(()));
        } else {
            assert_eq!(require_piv(), Err(SdkError::NotCompiled));
        }
        if cfg!(feature = "otp") {
            assert_eq!(require_otp(), Ok(()));
        } else {
            assert_eq!(require_otp(), Err(SdkError::NotCompiled));
        }
        if cfg!(feature = "proximity") {
            assert_eq!(require_proximity(), Ok(()));
        } else {
            assert_eq!(require_proximity(), Err(SdkError::NotCompiled));
        }
        if cfg!(feature = "oath") {
            assert_eq!(require_oath(), Ok(()));
        } else {
            assert_eq!(require_oath(), Err(SdkError::NotCompiled));
        }
        if cfg!(feature = "backup") {
            assert_eq!(require_backup(), Ok(()));
        } else {
            assert_eq!(require_backup(), Err(SdkError::NotCompiled));
        }
        if cfg!(feature = "audit") {
            assert_eq!(require_audit(), Ok(()));
        } else {
            assert_eq!(require_audit(), Err(SdkError::NotCompiled));
        }
        if cfg!(feature = "policy") {
            assert_eq!(require_policy(), Ok(()));
        } else {
            assert_eq!(require_policy(), Err(SdkError::NotCompiled));
        }
    }

    #[test]
    fn display_is_non_empty() {
        for e in [
            SdkError::Unsupported,
            SdkError::Unavailable,
            SdkError::PermissionDenied,
            SdkError::NotCompiled,
            SdkError::ExternalBlocked,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
