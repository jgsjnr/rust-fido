//! Wallet provider contract (`hardwallet`; types only, no firmware).

use crate::error::SdkError;
use crate::request::{WalletRequest, WalletSignRequest};
use crate::response::SdkResponse;

/// Executes [`WalletRequest`] and [`WalletSignRequest`].
///
/// Derivation/signing run in firmware (RAM-only). Both typed families share
/// this provider because both sit behind the same `require_hardwallet` gate
/// (see `SdkRequest::check_compiled`).
pub trait WalletProvider {
    /// Execute one wallet request.
    fn execute(request: WalletRequest) -> Result<SdkResponse, SdkError>;
    /// Execute one wallet-sign request.
    fn execute_sign(request: WalletSignRequest) -> Result<SdkResponse, SdkError>;
}

#[cfg(test)]
mod tests {
    use crate::error::SdkError;
    use crate::providers::WalletProvider;
    use crate::request::{WalletRequest, WalletSignRequest, WALLET_OP_GEN};
    use crate::response::SdkResponse;
    use alloc::vec::Vec;

    /// Test-only honest stub: reports `NotCompiled`, never a faked success.
    struct Unimplemented;

    impl WalletProvider for Unimplemented {
        fn execute(_request: WalletRequest) -> Result<SdkResponse, SdkError> {
            Err(SdkError::NotCompiled)
        }

        fn execute_sign(_request: WalletSignRequest) -> Result<SdkResponse, SdkError> {
            Err(SdkError::NotCompiled)
        }
    }

    #[test]
    fn honest_stub_reports_not_compiled() {
        let out = <Unimplemented as WalletProvider>::execute(WalletRequest {
            opcode: WALLET_OP_GEN,
            payload: Vec::new(),
        });
        assert_eq!(out, Err(SdkError::NotCompiled));
        let sign = <Unimplemented as WalletProvider>::execute_sign(WalletSignRequest {
            opcode: WALLET_OP_GEN,
            payload: Vec::new(),
        });
        assert_eq!(sign, Err(SdkError::NotCompiled));
    }
}
