//! F6 host: SDK approval-gate contract (no board, no transport).
//!
//! - The preview query/summary TLV round-trips through the typed SDK codec;
//!   unknown tags are ignored (§9.6), malformed shapes fail closed.
//! - The receipt is sent only after an in-app biometric approve: approve
//!   without biometry yields nothing (never a forged `approve`); deny
//!   always yields the explicit `deny` receipt.
//! - Only PSBT requires app-mediated approval; the preview opcode never
//!   does (it is the display that precedes the decision).

use universal_device_sdk::{
    decode_pending_summary, encode_pending_query, encode_sign_payload, is_wallet_compat_opcode,
    is_wallet_family_opcode, receipt_for, wallet_op_is_approval_preview,
    wallet_op_requires_app_approval, ApprovalDecision, SdkError, SdkRequest, WalletRequest,
    WalletSignRequest, WALLET_OP_ADDR, WALLET_OP_DERIVE, WALLET_OP_GEN, WALLET_OP_LIST,
    WALLET_OP_PENDING, WALLET_OP_PSBT, WALLET_OP_XPUB,
};

fn summary_body(slot: u8, hash: &[u8; 32], inputs: u16, outputs: u16) -> Vec<u8> {
    fn w(out: &mut Vec<u8>, tag: u8, v: &[u8]) {
        out.push(tag);
        if v.len() < 0x80 {
            out.push(v.len() as u8);
        } else {
            out.push(0x81);
            out.push(v.len() as u8);
        }
        out.extend_from_slice(v);
    }
    let mut out = Vec::new();
    w(&mut out, 0x01, &[slot]);
    w(&mut out, 0x0E, hash);
    w(
        &mut out,
        0x0F,
        &[
            (inputs & 0xFF) as u8,
            (inputs >> 8) as u8,
            (outputs & 0xFF) as u8,
            (outputs >> 8) as u8,
        ],
    );
    out
}

#[test]
fn preview_opcode_joins_family_without_requiring_approval() {
    assert_eq!(WALLET_OP_PENDING, 0x4B);
    assert!(is_wallet_compat_opcode(WALLET_OP_PENDING));
    assert!(is_wallet_family_opcode(WALLET_OP_PENDING));
    assert!(!wallet_op_requires_app_approval(WALLET_OP_PENDING));
    assert!(wallet_op_is_approval_preview(WALLET_OP_PENDING));
    assert!(wallet_op_requires_app_approval(WALLET_OP_PSBT));
    assert!(!wallet_op_is_approval_preview(WALLET_OP_PSBT));
    for op in [
        WALLET_OP_GEN,
        WALLET_OP_LIST,
        WALLET_OP_ADDR,
        WALLET_OP_DERIVE,
        WALLET_OP_XPUB,
    ] {
        assert!(!wallet_op_requires_app_approval(op), "op 0x{op:02X}");
        assert!(!wallet_op_is_approval_preview(op), "op 0x{op:02X}");
    }
}

#[test]
fn summary_decodes_display_fields_and_ignores_unknown_tags() {
    let hash = [0xABu8; 32];
    let mut body = summary_body(3, &hash, 1, 2);
    // Unknown tags are ignored (§9.6), never fail the decode.
    body.push(0x77);
    body.push(0x03);
    body.extend_from_slice(b"new");
    let pending = decode_pending_summary(&body).expect("preview decodes");
    assert_eq!(pending.slot, 3);
    assert_eq!(pending.tx_hash, hash);
    assert_eq!((pending.inputs, pending.outputs), (1, 2));
    assert_eq!(pending.tx_hash_hex(), "ab".repeat(32));
    // Malformed shapes fail closed.
    assert_eq!(decode_pending_summary(&[]), Err(SdkError::Unsupported));
    assert_eq!(
        decode_pending_summary(&body[..5]),
        Err(SdkError::Unsupported)
    );
}

#[test]
fn receipt_is_sent_only_after_biometric_approve() {
    // Approve + live biometric: the only path that sends `approve`.
    assert_eq!(
        receipt_for(ApprovalDecision::Approve, true).as_deref(),
        Some(b"approve".as_slice())
    );
    // Approve without biometry: nothing sent, never a forged `approve`.
    assert_eq!(receipt_for(ApprovalDecision::Approve, false), None);
    // Deny always sends the explicit `deny` receipt (safe to withdraw).
    assert_eq!(
        receipt_for(ApprovalDecision::Deny, true).as_deref(),
        Some(b"deny".as_slice())
    );
    assert_eq!(
        receipt_for(ApprovalDecision::Deny, false).as_deref(),
        Some(b"deny".as_slice())
    );
}

#[test]
fn sign_payload_binds_slot_psbt_and_receipt() {
    let psbt = vec![0x70u8, 0x73, 0x62, 0x74, 0xFF];
    let query = encode_pending_query(3, &psbt);
    let approve = receipt_for(ApprovalDecision::Approve, true).expect("biometric ok");
    let body = encode_sign_payload(3, &psbt, &approve);
    // The query carries no receipt; the sign envelope carries it.
    assert_eq!(query.len() + 2 + approve.len(), body.len());
    assert!(body.windows(approve.len()).any(|w| w == approve));
    // Both ride the `hardwallet` family gate, never `NotCompiled` here.
    let pending_req = SdkRequest::Wallet(WalletRequest {
        opcode: WALLET_OP_PENDING,
        payload: query,
    });
    let sign_req = SdkRequest::WalletSign(WalletSignRequest {
        opcode: WALLET_OP_PSBT,
        payload: body,
    });
    if cfg!(feature = "hardwallet") {
        assert_eq!(pending_req.check_compiled(), Ok(()));
        assert_eq!(sign_req.check_compiled(), Ok(()));
    } else {
        assert_eq!(pending_req.check_compiled(), Err(SdkError::NotCompiled));
        assert_eq!(sign_req.check_compiled(), Err(SdkError::NotCompiled));
    }
}
