//! OTA provider contract (`ota`; types only, no firmware).

use crate::error::SdkError;
use crate::request::OtaRequest;
use crate::response::SdkResponse;

/// Executes [`OtaRequest`] (`0x30`-`0x34`, reserved `0x2F`).
///
/// Staging/commit/wipe run in firmware; this contract only names the shape.
pub trait OtaProvider {
    /// Execute one OTA request.
    fn execute(request: OtaRequest) -> Result<SdkResponse, SdkError>;
}

#[cfg(test)]
mod tests {
    use crate::error::SdkError;
    use crate::providers::OtaProvider;
    use crate::request::OtaRequest;
    use crate::response::SdkResponse;
    use alloc::vec::Vec;

    /// Test-only honest stub: reports `NotCompiled`, never a faked success.
    struct Unimplemented;

    impl OtaProvider for Unimplemented {
        fn execute(_request: OtaRequest) -> Result<SdkResponse, SdkError> {
            Err(SdkError::NotCompiled)
        }
    }

    #[test]
    fn honest_stub_reports_not_compiled() {
        let out = <Unimplemented as OtaProvider>::execute(OtaRequest {
            opcode: 0x30,
            payload: Vec::new(),
        });
        assert_eq!(out, Err(SdkError::NotCompiled));
    }
}
