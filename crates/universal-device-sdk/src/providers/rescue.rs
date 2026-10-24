//! Rescue-extension provider contract (`otp` gate; types only, no firmware).

use crate::error::SdkError;
use crate::request::RescueRequest;
use crate::response::SdkResponse;

/// Executes [`RescueRequest`] (`0x2E` transport; killswitch `0x06`).
///
/// Killswitch/wipe execution lives in firmware (jig+HSM); never here.
pub trait RescueProvider {
    /// Execute one rescue-extension request.
    fn execute(request: RescueRequest) -> Result<SdkResponse, SdkError>;
}

#[cfg(test)]
mod tests {
    use crate::error::SdkError;
    use crate::providers::RescueProvider;
    use crate::request::RescueRequest;
    use crate::response::SdkResponse;
    use alloc::vec::Vec;

    /// Test-only honest stub: reports `NotCompiled`, never a faked success.
    struct Unimplemented;

    impl RescueProvider for Unimplemented {
        fn execute(_request: RescueRequest) -> Result<SdkResponse, SdkError> {
            Err(SdkError::NotCompiled)
        }
    }

    #[test]
    fn honest_stub_reports_not_compiled() {
        let out = <Unimplemented as RescueProvider>::execute(RescueRequest {
            command: 0x06,
            payload: Vec::new(),
        });
        assert_eq!(out, Err(SdkError::NotCompiled));
    }
}
