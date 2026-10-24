//! PIV provider contract (`piv`; types only, no firmware).

use crate::error::SdkError;
use crate::request::PivRequest;
use crate::response::SdkResponse;

/// Executes [`PivRequest`] (enroll `0x39`, APDUs otherwise).
///
/// APDU execution lives in firmware/USB stack; never here.
pub trait PivProvider {
    /// Execute one PIV request.
    fn execute(request: PivRequest) -> Result<SdkResponse, SdkError>;
}

#[cfg(test)]
mod tests {
    use crate::error::SdkError;
    use crate::providers::PivProvider;
    use crate::request::PivRequest;
    use crate::response::SdkResponse;
    use alloc::vec::Vec;

    /// Test-only honest stub: reports `NotCompiled`, never a faked success.
    struct Unimplemented;

    impl PivProvider for Unimplemented {
        fn execute(_request: PivRequest) -> Result<SdkResponse, SdkError> {
            Err(SdkError::NotCompiled)
        }
    }

    #[test]
    fn honest_stub_reports_not_compiled() {
        let out = <Unimplemented as PivProvider>::execute(PivRequest {
            opcode: 0x39,
            payload: Vec::new(),
        });
        assert_eq!(out, Err(SdkError::NotCompiled));
    }
}
