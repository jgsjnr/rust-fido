//! Caller-supplied authorization facts (R5 order as data, not logic).
//!
//! Field order mirrors the canonical fail-closed order
//! (`binding -> UP -> PIN`); this crate never evaluates gates — firmware
//! transports enforce them. Absent proofs are plain `false`.

/// Authorization facts presented with a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthContext {
    /// Binding proof verified (ownership of the device).
    pub binding_verified: bool,
    /// Physical user presence confirmed.
    pub presence_confirmed: bool,
    /// PIN verified where required.
    pub pin_verified: bool,
}

impl AuthContext {
    /// Build from explicit facts.
    pub const fn new(binding_verified: bool, presence_confirmed: bool, pin_verified: bool) -> Self {
        Self {
            binding_verified,
            presence_confirmed,
            pin_verified,
        }
    }

    /// No proofs at all (anonymous caller).
    pub const fn anonymous() -> Self {
        Self::new(false, false, false)
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::AuthContext;

    #[test]
    fn const_constructible() {
        const FULL: AuthContext = AuthContext::new(true, true, true);
        let full = FULL;
        assert!(full.binding_verified);
        assert!(full.presence_confirmed);
        assert!(full.pin_verified);
    }

    #[test]
    fn anonymous_has_no_proofs() {
        const ANON: AuthContext = AuthContext::anonymous();
        assert_eq!(ANON, AuthContext::new(false, false, false));
    }
}
