//! Audit provider contract (`audit`; types only, no firmware).

use crate::error::SdkError;
use crate::request::AuditRequest;
use crate::response::SdkResponse;

/// Executes [`AuditRequest`] (op `0x38`).
///
/// The ring buffer (`64x16 B`, RAM, lost on reboot) lives in firmware.
pub trait AuditProvider {
    /// Execute one audit/fw-log request.
    fn execute(request: AuditRequest) -> Result<SdkResponse, SdkError>;
}

#[cfg(test)]
mod tests {
    use crate::error::SdkError;
    use crate::providers::AuditProvider;
    use crate::request::AuditRequest;
    use crate::response::SdkResponse;
    use alloc::vec::Vec;

    /// Test-only honest stub: reports `NotCompiled`, never a faked success.
    struct Unimplemented;

    impl AuditProvider for Unimplemented {
        fn execute(_request: AuditRequest) -> Result<SdkResponse, SdkError> {
            Err(SdkError::NotCompiled)
        }
    }

    #[test]
    fn honest_stub_reports_not_compiled() {
        let out = <Unimplemented as AuditProvider>::execute(AuditRequest {
            opcode: 0x38,
            payload: Vec::new(),
        });
        assert_eq!(out, Err(SdkError::NotCompiled));
    }
}
