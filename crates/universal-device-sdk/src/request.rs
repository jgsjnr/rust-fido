//! Closed request enum: Fido / Wallet / Vendor / Binding / System plus
//! Phase 0 typed stubs (Ota / Piv / Otp / Proximity / Rescue / WalletSign /
//! Oath / Backup / Audit / Policy).
//!
//! The enum itself is always fully available (stable stub API, R12); when a
//! feature-gated family is compiled off, `check_compiled` reports
//! `SdkError::NotCompiled` instead of executing anything. Phase 0 adds only
//! types plus gates — no execution logic lives in this crate.

use crate::error::{
    require_audit, require_backup, require_fido, require_hardwallet, require_oath, require_ota,
    require_otp, require_piv, require_policy, require_proximity, SdkError,
};
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

/// OTA request (opcodes `0x30`-`0x34`, reserved `0x2F`; feature `ota`).
///
/// Opaque carrier only: staging/commit/wipe execution lives in firmware,
/// never in this crate (Phase 0: types + gates, no logic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtaRequest {
    /// OTA opcode byte.
    pub opcode: u8,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

/// PIV/CCID request (feature `piv`; enroll `0x39`, APDUs otherwise).
///
/// Opaque carrier only; APDU execution lives in firmware/USB stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PivRequest {
    /// PIV opcode / INS byte.
    pub opcode: u8,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

/// OTP request (feature `otp`; keyboard modhex / Ykman / Nitrokey / Legacy OTP).
///
/// Opaque carrier only; typing/crypto lives in firmware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpRequest {
    /// OTP opcode byte.
    pub opcode: u8,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

/// Proximity request (feature `proximity`; service `0xFFFE`, never `0xFFFD`).
///
/// Opaque carrier only; K_prox/advertising walkaway lives in firmware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProximityRequest {
    /// Proximity opcode byte.
    pub opcode: u8,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

/// Rescue-extension request (`0x2E` transport; feature `otp`).
///
/// Carries the `RESC` frame command byte plus opaque payload; killswitch/wipe
/// execution lives in firmware (jig+HSM), never here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RescueRequest {
    /// Rescue command byte (e.g. ping / killswitch `0x06`).
    pub command: u8,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

/// Wallet-sign request (feature `hardwallet`; address derivation stays in
/// firmware, RAM-only).
///
/// Opaque carrier only; no signing logic in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSignRequest {
    /// Wallet-sign opcode byte.
    pub opcode: u8,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

/// OATH request (feature `oath`; vendor `0x24`-`0x27`, HTTP `GET /oath/code`).
///
/// Opaque carrier only; secret storage/calc lives in firmware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OathRequest {
    /// OATH opcode byte.
    pub opcode: u8,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

/// Backup request (feature `backup`; AEGN envelope).
///
/// Opaque carrier only; restore/provision execution lives in firmware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRequest {
    /// Backup opcode byte.
    pub opcode: u8,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

/// Audit/fw-log request (feature `audit`; op `0x38`).
///
/// Opaque carrier only; ring buffer (`64x16 B`, RAM, lost on reboot) lives
/// in firmware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRequest {
    /// Audit opcode byte.
    pub opcode: u8,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

/// Policy-gate request (feature `policy`; `binding -> UP -> PIN` as data).
///
/// Carries only the operation class under validation; enforcement lives in
/// firmware gates, never in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequest {
    /// Policy opcode byte.
    pub opcode: u8,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

/// Closed request family: the five original variants (frozen order/meaning)
/// plus ten Phase 0 typed stubs, no fallback.
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
    /// OTA update (feature `ota`; types + gates only).
    Ota(OtaRequest),
    /// PIV/CCID (feature `piv`; types + gates only).
    Piv(PivRequest),
    /// OTP (feature `otp`; types + gates only).
    Otp(OtpRequest),
    /// Proximity `0xFFFE` (feature `proximity`; types + gates only).
    Proximity(ProximityRequest),
    /// Rescue extension `0x2E` (feature `otp`; types + gates only).
    Rescue(RescueRequest),
    /// Wallet signing (feature `hardwallet`; types + gates only).
    WalletSign(WalletSignRequest),
    /// OATH (feature `oath`; types + gates only).
    Oath(OathRequest),
    /// Backup (feature `backup`; types + gates only).
    Backup(BackupRequest),
    /// Audit/fw-log (feature `audit`; types + gates only).
    Audit(AuditRequest),
    /// Policy gate (feature `policy`; types + gates only).
    Policy(PolicyRequest),
}

impl SdkRequest {
    /// R12 stub mapping: `NotCompiled` only when the matching feature is
    /// off; always-compiled families always pass.
    pub fn check_compiled(&self) -> Result<(), SdkError> {
        match self {
            Self::Fido(_) => require_fido(),
            Self::Wallet(_) | Self::WalletSign(_) => require_hardwallet(),
            Self::Vendor(_) | Self::Binding(_) | Self::System(_) => Ok(()),
            Self::Ota(_) => require_ota(),
            Self::Piv(_) => require_piv(),
            Self::Otp(_) | Self::Rescue(_) => require_otp(),
            Self::Proximity(_) => require_proximity(),
            Self::Oath(_) => require_oath(),
            Self::Backup(_) => require_backup(),
            Self::Audit(_) => require_audit(),
            Self::Policy(_) => require_policy(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::SdkError;
    use crate::request::{
        AuditRequest, BackupRequest, BindingOp, BindingRequest, FidoRequest, OathRequest,
        OtaRequest, OtpRequest, PivRequest, PolicyRequest, ProximityRequest, RescueRequest,
        SdkRequest, SystemOp, SystemRequest, VendorRequest, WalletRequest, WalletSignRequest,
        WALLET_OP_ADDR, WALLET_OP_GEN, WALLET_OP_LIST,
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
    fn phase0_variants_follow_gates_no_logic() {
        let cases: &[(&str, SdkRequest, bool)] = &[
            (
                "ota",
                SdkRequest::Ota(OtaRequest {
                    opcode: 0x30,
                    payload: Vec::new(),
                }),
                option_env!("CARGO_FEATURE_OTA").is_some(),
            ),
            (
                "piv",
                SdkRequest::Piv(PivRequest {
                    opcode: 0x39,
                    payload: Vec::new(),
                }),
                option_env!("CARGO_FEATURE_PIV").is_some(),
            ),
            (
                "otp",
                SdkRequest::Otp(OtpRequest {
                    opcode: 0x00,
                    payload: Vec::new(),
                }),
                option_env!("CARGO_FEATURE_OTP").is_some(),
            ),
            (
                "proximity",
                SdkRequest::Proximity(ProximityRequest {
                    opcode: 0x00,
                    payload: Vec::new(),
                }),
                option_env!("CARGO_FEATURE_PROXIMITY").is_some(),
            ),
            (
                "rescue-via-otp",
                SdkRequest::Rescue(RescueRequest {
                    command: 0x06,
                    payload: Vec::new(),
                }),
                option_env!("CARGO_FEATURE_OTP").is_some(),
            ),
            (
                "wallet-sign-via-hardwallet",
                SdkRequest::WalletSign(WalletSignRequest {
                    opcode: 0x35,
                    payload: Vec::new(),
                }),
                cfg!(feature = "hardwallet"),
            ),
            (
                "oath",
                SdkRequest::Oath(OathRequest {
                    opcode: 0x25,
                    payload: Vec::new(),
                }),
                option_env!("CARGO_FEATURE_OATH").is_some(),
            ),
            (
                "backup",
                SdkRequest::Backup(BackupRequest {
                    opcode: 0x00,
                    payload: Vec::new(),
                }),
                option_env!("CARGO_FEATURE_BACKUP").is_some(),
            ),
            (
                "audit",
                SdkRequest::Audit(AuditRequest {
                    opcode: 0x38,
                    payload: Vec::new(),
                }),
                option_env!("CARGO_FEATURE_AUDIT").is_some(),
            ),
            (
                "policy",
                SdkRequest::Policy(PolicyRequest {
                    opcode: 0x00,
                    payload: Vec::new(),
                }),
                option_env!("CARGO_FEATURE_POLICY").is_some(),
            ),
        ];
        for (name, req, enabled) in cases {
            if *enabled {
                assert_eq!(req.check_compiled(), Ok(()), "{name} gate");
            } else {
                assert_eq!(
                    req.check_compiled(),
                    Err(SdkError::NotCompiled),
                    "{name} gate"
                );
            }
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
