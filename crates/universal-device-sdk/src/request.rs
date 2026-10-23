//! Closed request enum: Fido / Wallet / Vendor / Binding / System.
//!
//! The enum itself is always fully available (stable stub API, R12); when a
//! feature-gated family is compiled off, `check_compiled` reports
//! `SdkError::NotCompiled` instead of executing anything.

use crate::error::{require_fido, require_hardwallet, SdkError};
use alloc::vec::Vec;

/// Wallet opcodes (free range, never colliding with vendor `0x20`-`0x27`).
pub const WALLET_OP_GEN: u8 = 0x35;
/// Wallet opcodes: list.
pub const WALLET_OP_LIST: u8 = 0x36;
/// Wallet opcodes: address.
pub const WALLET_OP_ADDR: u8 = 0x37;

/// FIDO request (CTAP payload carried opaquely; engine lives in firmware).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FidoRequest {
    /// CTAP instruction byte.
    pub opcode: u8,
    /// CBOR payload bytes.
    pub payload: Vec<u8>,
}

/// Wallet request (key derivation/display lives in firmware; RAM-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletRequest {
    /// One of `WALLET_OP_*`.
    pub opcode: u8,
    /// TLV payload bytes.
    pub payload: Vec<u8>,
}

/// Vendor request (OATH/PIV/rescue TLVs transit here opaquely).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorRequest {
    /// Vendor opcode byte.
    pub opcode: u8,
    /// TLV payload bytes.
    pub payload: Vec<u8>,
}

/// Binding operation (claim/challenge/verify/release handshake step).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingOp {
    /// First-time claim of an unclaimed device.
    Claim,
    /// Request a fresh 32 B anti-replay challenge.
    Challenge,
    /// Prove ownership over `challenge || op || payload_hash`.
    Verify,
    /// Signed release (or physical factory reset path).
    Release,
}

/// Binding request (ownership proof never leaves typed form here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRequest {
    /// Handshake step.
    pub op: BindingOp,
    /// Opaque step payload bytes.
    pub payload: Vec<u8>,
}

/// System operation (diagnostics without secrets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemOp {
    /// Echo / liveness.
    Ping,
    /// Static device info (no secrets).
    DeviceInfo,
}

/// System request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemRequest {
    /// System operation.
    pub op: SystemOp,
}

/// Closed request family: exactly these five variants, no fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkRequest {
    /// FIDO/CTAP (feature `fido`).
    Fido(FidoRequest),
    /// Wallet ops (feature `hardwallet`).
    Wallet(WalletRequest),
    /// Vendor TLV ops (always compiled).
    Vendor(VendorRequest),
    /// Binding handshake (always compiled).
    Binding(BindingRequest),
    /// System diagnostics (always compiled).
    System(SystemRequest),
}

impl SdkRequest {
    /// R12 stub mapping: `NotCompiled` only when the matching feature is
    /// off; always-compiled families always pass.
    pub fn check_compiled(&self) -> Result<(), SdkError> {
        match self {
            Self::Fido(_) => require_fido(),
            Self::Wallet(_) => require_hardwallet(),
            Self::Vendor(_) | Self::Binding(_) | Self::System(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::SdkError;
    use crate::request::{
        BindingOp, BindingRequest, FidoRequest, SdkRequest, SystemOp, SystemRequest, VendorRequest,
        WalletRequest, WALLET_OP_ADDR, WALLET_OP_GEN, WALLET_OP_LIST,
    };
    use alloc::vec::Vec;

    fn fido() -> SdkRequest {
        SdkRequest::Fido(FidoRequest {
            opcode: 0x83,
            payload: Vec::new(),
        })
    }

    fn wallet() -> SdkRequest {
        SdkRequest::Wallet(WalletRequest {
            opcode: WALLET_OP_GEN,
            payload: Vec::new(),
        })
    }

    #[test]
    fn wallet_opcodes_in_free_range() {
        assert_eq!(
            (WALLET_OP_GEN, WALLET_OP_LIST, WALLET_OP_ADDR),
            (0x35, 0x36, 0x37)
        );
    }

    #[test]
    fn always_compiled_families_pass() {
        let vendor = SdkRequest::Vendor(VendorRequest {
            opcode: 0x20,
            payload: Vec::new(),
        });
        let binding = SdkRequest::Binding(BindingRequest {
            op: BindingOp::Claim,
            payload: Vec::new(),
        });
        let system = SdkRequest::System(SystemRequest { op: SystemOp::Ping });
        assert_eq!(vendor.check_compiled(), Ok(()));
        assert_eq!(binding.check_compiled(), Ok(()));
        assert_eq!(system.check_compiled(), Ok(()));
    }

    #[test]
    fn gated_families_follow_features() {
        if cfg!(feature = "fido") {
            assert_eq!(fido().check_compiled(), Ok(()));
        } else {
            assert_eq!(fido().check_compiled(), Err(SdkError::NotCompiled));
        }
        if cfg!(feature = "hardwallet") {
            assert_eq!(wallet().check_compiled(), Ok(()));
        } else {
            assert_eq!(wallet().check_compiled(), Err(SdkError::NotCompiled));
        }
    }

    #[test]
    fn all_binding_and_system_ops_constructible() {
        for op in [
            BindingOp::Claim,
            BindingOp::Challenge,
            BindingOp::Verify,
            BindingOp::Release,
        ] {
            let _ = BindingRequest {
                op,
                payload: Vec::new(),
            };
        }
        for op in [SystemOp::Ping, SystemOp::DeviceInfo] {
            let _ = SystemRequest { op };
        }
    }
}
