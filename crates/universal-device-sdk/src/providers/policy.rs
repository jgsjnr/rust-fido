//! Policy provider contract (`policy`; types only, no firmware).

use crate::error::SdkError;
use crate::request::PolicyRequest;
use crate::response::SdkResponse;

/// Validates [`PolicyRequest`] (`binding -> UP -> PIN` as data).
///
/// Carries only the operation class under validation; enforcement lives in
/// firmware gates, never here.
pub trait PolicyProvider {
    /// Validate one policy-gate request.
    fn execute(request: PolicyRequest) -> Result<SdkResponse, SdkError>;
}

#[cfg(test)]
mod tests {
    use crate::error::SdkError;
    use crate::providers::PolicyProvider;
    use crate::request::PolicyRequest;
    use crate::response::SdkResponse;
    use alloc::vec::Vec;

    /// Test-only honest stub: reports `NotCompiled`, never a faked success.
    struct Unimplemented;

    impl PolicyProvider for Unimplemented {
        fn execute(_request: PolicyRequest) -> Result<SdkResponse, SdkError> {
            Err(SdkError::NotCompiled)
        }
    }

    #[test]
    fn honest_stub_reports_not_compiled() {
        let out = <Unimplemented as PolicyProvider>::execute(PolicyRequest {
            opcode: 0x00,
            payload: Vec::new(),
        });
        assert_eq!(out, Err(SdkError::NotCompiled));
    }
}
