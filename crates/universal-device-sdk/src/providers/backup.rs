//! Backup provider contract (`backup`; types only, no firmware).

use crate::error::SdkError;
use crate::request::BackupRequest;
use crate::response::SdkResponse;

/// Executes [`BackupRequest`] (AEGN envelope).
///
/// Restore/provision execution lives in firmware; never here.
pub trait BackupProvider {
    /// Execute one backup request.
    fn execute(request: BackupRequest) -> Result<SdkResponse, SdkError>;
}

#[cfg(test)]
mod tests {
    use crate::error::SdkError;
    use crate::providers::BackupProvider;
    use crate::request::BackupRequest;
    use crate::response::SdkResponse;
    use alloc::vec::Vec;

    /// Test-only honest stub: reports `NotCompiled`, never a faked success.
    struct Unimplemented;

    impl BackupProvider for Unimplemented {
        fn execute(_request: BackupRequest) -> Result<SdkResponse, SdkError> {
            Err(SdkError::NotCompiled)
        }
    }

    #[test]
    fn honest_stub_reports_not_compiled() {
        let out = <Unimplemented as BackupProvider>::execute(BackupRequest {
            opcode: 0x00,
            payload: Vec::new(),
        });
        assert_eq!(out, Err(SdkError::NotCompiled));
    }
}
