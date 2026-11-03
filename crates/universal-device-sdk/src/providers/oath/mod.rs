//! OATH provider contract (`oath`; types only, no firmware).

mod contract;

pub use contract::OathProvider;

#[cfg(test)]
mod tests {
    use crate::error::SdkError;
    use crate::providers::OathProvider;
    use crate::request::OathRequest;
    use crate::response::SdkResponse;
    use alloc::vec::Vec;

    /// Test-only honest stub: reports `NotCompiled`, never a faked success.
    struct Unimplemented;

    impl OathProvider for Unimplemented {
        fn execute(_request: OathRequest) -> Result<SdkResponse, SdkError> {
            Err(SdkError::NotCompiled)
        }
    }

    #[test]
    fn honest_stub_reports_not_compiled() {
        let out = <Unimplemented as OathProvider>::execute(OathRequest {
            opcode: 0x25,
            payload: Vec::new(),
        });
        assert_eq!(out, Err(SdkError::NotCompiled));
    }
}
