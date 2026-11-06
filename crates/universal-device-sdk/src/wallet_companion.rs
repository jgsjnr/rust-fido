//! Host companion flows over the wallet facade (feature `hardwallet`).
//!
//! Typed app-side builders for the F7 companion contract: watch-only xpub
//! export (`0x49`) and pending preview (`0x4B`, display first) plus the PSBT
//! sign round-trip (`0x4A` with a biometric-gated receipt). This module only
//! composes the closed `SdkRequest` vocabulary (frozen `request` opcodes,
//! `wallet_approval` TLV codecs, the `require_hardwallet` gate): no
//! transport, no crypto, no secrets — digests stay opaque 32 B commitments.
//! Enforcement lives in firmware; malformed shapes fail here as
//! `SdkError::Unsupported` (wire `0x04`), never a forged success.
//!
//! `no_std` + `alloc` only; no `std`, no `unsafe`, no JSON (typed structs
//! rule the inside; JSON is restricted to FFI/JNI edges).

use crate::error::{require_hardwallet, SdkError};
use crate::request::{
    WalletRequest, WalletSignRequest, WALLET_OP_PENDING, WALLET_OP_PSBT, WALLET_OP_XPUB,
};
use crate::wallet_approval::{
    decode_pending_summary, encode_pending_query, encode_sign_payload, receipt_for,
    ApprovalDecision, PendingWalletTx, APPROVAL_RECEIPT_APPROVE, APPROVAL_RECEIPT_DENY,
};
use alloc::vec::Vec;

/// Max PSBT bytes a companion preview/sign envelope may carry.
///
/// Documented copy of the BLE control-point transport ceiling
/// (`uniffi-bridge::CONTROL_POINT_LENGTH`); parity is enforced by
/// `companion_psbt_ceiling_matches_transport`. Larger envelopes fail as
/// `Unsupported` before any wire byte is built.
pub const COMPANION_PSBT_MAX_BYTES: usize = 512;

/// Wallet slots addressable by companions (`0..32`, firmware `WalletStore`).
pub const COMPANION_MAX_SLOTS: u8 = 32;

/// Companion round-trip opcodes: watch-only xpub export, PSBT sign, pending
/// preview (display first, never approved itself).
pub const COMPANION_OPS: [u8; 3] = [WALLET_OP_XPUB, WALLET_OP_PSBT, WALLET_OP_PENDING];

/// `true` for the F7 companion round-trip surface (`0x49` xpub, `0x4A`
/// PSBT, `0x4B` pending preview). Frozen wallet-family members `0x35`-`0x37`
/// and derivation `0x48` are device flows, not companion round-trips.
pub const fn is_companion_opcode(op: u8) -> bool {
    matches!(op, WALLET_OP_XPUB | WALLET_OP_PSBT | WALLET_OP_PENDING)
}

fn check_slot(slot: u8) -> Result<(), SdkError> {
    if slot < COMPANION_MAX_SLOTS {
        Ok(())
    } else {
        Err(SdkError::Unsupported)
    }
}

fn check_psbt(psbt: &[u8]) -> Result<(), SdkError> {
    if psbt.is_empty() || psbt.len() > COMPANION_PSBT_MAX_BYTES {
        Err(SdkError::Unsupported)
    } else {
        Ok(())
    }
}

fn check_receipt(receipt: &[u8]) -> Result<(), SdkError> {
    if receipt == APPROVAL_RECEIPT_APPROVE || receipt == APPROVAL_RECEIPT_DENY {
        Ok(())
    } else {
        Err(SdkError::Unsupported)
    }
}

/// Builds the pending-preview request (`0x4B`, display first).
///
/// The preview never needs app approval itself (it is the display that
/// precedes the approve/deny decision); shape violations fail closed.
pub fn build_pending_query(slot: u8, psbt: &[u8]) -> Result<WalletRequest, SdkError> {
    require_hardwallet()?;
    check_slot(slot)?;
    check_psbt(psbt)?;
    Ok(WalletRequest {
        opcode: WALLET_OP_PENDING,
        payload: encode_pending_query(slot, psbt),
    })
}

/// Builds the PSBT sign request (`0x4A`) carrying the approval receipt.
///
/// `receipt` must be exactly `approve` (post-biometry) or `deny`; anything
/// else fails closed before any wire byte is built. The firmware re-checks
/// the receipt plus preview integrity plus binding → UP → PIN.
pub fn build_sign_request(
    slot: u8,
    psbt: &[u8],
    receipt: &[u8],
) -> Result<WalletSignRequest, SdkError> {
    require_hardwallet()?;
    check_slot(slot)?;
    check_psbt(psbt)?;
    check_receipt(receipt)?;
    Ok(WalletSignRequest {
        opcode: WALLET_OP_PSBT,
        payload: encode_sign_payload(slot, psbt, receipt),
    })
}

/// Decodes a pending-summary body into display-only fields.
///
/// Unknown tags are ignored (§9.6); malformed shapes fail as `Unsupported`.
/// The result is display data only — integrity is enforced device-side on
/// sign, never here.
pub fn preview_of(body: &[u8]) -> Result<PendingWalletTx, SdkError> {
    require_hardwallet()?;
    decode_pending_summary(body)
}

/// Receipt bytes for `decision`, gated on the in-app biometric.
///
/// `Approve` yields the `approve` receipt ONLY with `biometric_ok` — without
/// a live biometric the companion sends nothing (`None`), never a forged
/// approve. `Deny` always yields the explicit `deny` receipt.
pub fn receipt_bytes(decision: ApprovalDecision, biometric_ok: bool) -> Option<Vec<u8>> {
    receipt_for(decision, biometric_ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::{is_wallet_family_opcode, wallet_op_is_approval_preview};

    #[test]
    fn companion_surface_is_xpub_psbt_and_preview_only() {
        assert_eq!(
            COMPANION_OPS,
            [WALLET_OP_XPUB, WALLET_OP_PSBT, WALLET_OP_PENDING]
        );
        for op in COMPANION_OPS {
            assert!(is_companion_opcode(op));
            assert!(is_wallet_family_opcode(op));
        }
        for op in [0x00u8, 0x35, 0x36, 0x37, 0x48, 0x4C] {
            assert!(!is_companion_opcode(op), "op 0x{op:02X}");
        }
        assert!(wallet_op_is_approval_preview(WALLET_OP_PENDING));
    }

    #[test]
    fn companion_psbt_ceiling_matches_transport() {
        // Transport ceiling: bridge `CONTROL_POINT_LENGTH` (512). The
        // companion never frames a larger envelope.
        assert_eq!(COMPANION_PSBT_MAX_BYTES, 512);
        assert_eq!(COMPANION_MAX_SLOTS, 32);
    }

    #[test]
    fn pending_query_builds_display_first_request() {
        let psbt = [0x70u8, 0x73, 0x62, 0x74];
        let req = build_pending_query(3, &psbt).expect("valid shape");
        assert_eq!(req.opcode, WALLET_OP_PENDING);
        assert!(!req.payload.is_empty());
        if cfg!(feature = "hardwallet") {
            use crate::request::SdkRequest;
            assert_eq!(SdkRequest::Wallet(req).check_compiled(), Ok(()));
        }
    }

    #[test]
    fn shapes_fail_closed_before_wire() {
        let psbt = [0x70u8, 0x73];
        assert_eq!(build_pending_query(32, &psbt), Err(SdkError::Unsupported));
        assert_eq!(build_pending_query(0, &[]), Err(SdkError::Unsupported));
        assert_eq!(
            build_pending_query(0, &[0xABu8; COMPANION_PSBT_MAX_BYTES + 1]),
            Err(SdkError::Unsupported)
        );
        assert_eq!(
            build_sign_request(0, &psbt, b"approve"),
            build_sign_request(0, &psbt, b"approve")
        );
        assert_eq!(
            build_sign_request(0, &psbt, b"maybe"),
            Err(SdkError::Unsupported)
        );
        assert_eq!(
            build_sign_request(0, &psbt, &[]),
            Err(SdkError::Unsupported)
        );
        assert_eq!(
            build_sign_request(32, &psbt, b"deny"),
            Err(SdkError::Unsupported)
        );
    }

    #[test]
    fn receipt_gate_never_forges_approve() {
        assert_eq!(
            receipt_bytes(ApprovalDecision::Approve, true).as_deref(),
            Some(b"approve".as_slice())
        );
        assert_eq!(receipt_bytes(ApprovalDecision::Approve, false), None);
        assert_eq!(
            receipt_bytes(ApprovalDecision::Deny, false).as_deref(),
            Some(b"deny".as_slice())
        );
    }
}
