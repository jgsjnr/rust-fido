//! OTP provider contract (`otp`; types only, no firmware).

use crate::error::SdkError;
use crate::request::OtpRequest;
use crate::response::SdkResponse;

/// Executes [`OtpRequest`] (keyboard modhex / Ykman / Nitrokey / YubiOTP).
///
/// Typing/crypto live in firmware; never here.
pub trait OtpProvider {
    /// Execute one OTP request.
    fn execute(request: OtpRequest) -> Result<SdkResponse, SdkError>;
}

#[cfg(test)]
mod tests {
    use crate::error::SdkError;
    use crate::providers::OtpProvider;
    use crate::request::OtpRequest;
    use crate::response::SdkResponse;
    use alloc::vec::Vec;

    /// Test-only honest stub: reports `NotCompiled`, never a faked success.
    struct Unimplemented;

    impl OtpProvider for Unimplemented {
        fn execute(_request: OtpRequest) -> Result<SdkResponse, SdkError> {
            Err(SdkError::NotCompiled)
        }
    }

    #[test]
    fn honest_stub_reports_not_compiled() {
        let out = <Unimplemented as OtpProvider>::execute(OtpRequest {
            opcode: 0x00,
            payload: Vec::new(),
        });
        assert_eq!(out, Err(SdkError::NotCompiled));
    }
}
