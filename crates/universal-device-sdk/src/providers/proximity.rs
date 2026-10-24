//! Proximity provider contract (`proximity`; types only, no firmware).

use crate::error::SdkError;
use crate::request::ProximityRequest;
use crate::response::SdkResponse;

/// Executes [`ProximityRequest`] (service `0xFFFE`, never `0xFFFD`).
///
/// `K_prox`/advertising walkaway lives in firmware; never here.
pub trait ProximityProvider {
    /// Execute one proximity request.
    fn execute(request: ProximityRequest) -> Result<SdkResponse, SdkError>;
}

#[cfg(test)]
mod tests {
    use crate::error::SdkError;
    use crate::providers::ProximityProvider;
    use crate::request::ProximityRequest;
    use crate::response::SdkResponse;
    use alloc::vec::Vec;

    /// Test-only honest stub: reports `NotCompiled`, never a faked success.
    struct Unimplemented;

    impl ProximityProvider for Unimplemented {
        fn execute(_request: ProximityRequest) -> Result<SdkResponse, SdkError> {
            Err(SdkError::NotCompiled)
        }
    }

    #[test]
    fn honest_stub_reports_not_compiled() {
        let out = <Unimplemented as ProximityProvider>::execute(ProximityRequest {
            opcode: 0x00,
            payload: Vec::new(),
        });
        assert_eq!(out, Err(SdkError::NotCompiled));
    }
}
