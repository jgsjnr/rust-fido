//! F7 host: companion flows over the facade (no board, no transport).
//!
//! - The companion round-trip surface is exactly xpub (`0x49`), PSBT sign
//!   (`0x4A`) and pending preview (`0x4B`): derivation and the frozen
//!   `0x35`-`0x37` family are device flows, not companion round-trips.
//! - Query/sign builders fail closed on malformed shapes (`Unsupported`,
//!   wire `0x04`): bad slot, empty or oversize PSBT, forged receipt.
//! - The receipt is sent only after a live biometric approve; deny always
//!   sends the explicit `deny` receipt.

use universal_device_sdk::{
    build_pending_query, build_sign_request, is_companion_opcode, is_wallet_family_opcode,
    preview_of, receipt_bytes, wallet_op_requires_app_approval, ApprovalDecision, SdkError,
    SdkRequest, COMPANION_MAX_SLOTS, COMPANION_OPS, COMPANION_PSBT_MAX_BYTES, WALLET_OP_PENDING,
    WALLET_OP_PSBT, WALLET_OP_XPUB,
};

fn psbt() -> Vec<u8> {
    vec![0x70u8, 0x73, 0x62, 0x74, 0xFF]
}

fn summary_body(slot: u8) -> Vec<u8> {
    let mut out = vec![0x01u8, 0x01, slot, 0x0Eu8, 0x20];
    out.extend_from_slice(&[0xABu8; 32]);
    out.extend_from_slice(&[0x0Fu8, 0x04, 0x01, 0x00, 0x02, 0x00]);
    out
}

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
    assert_eq!(COMPANION_MAX_SLOTS, 32);
    assert_eq!(COMPANION_PSBT_MAX_BYTES, 512);
}

#[test]
fn companion_builders_round_trip_through_typed_requests() {
    let query = build_pending_query(3, &psbt()).expect("valid shape");
    assert_eq!(query.opcode, WALLET_OP_PENDING);
    let pending = preview_of(&summary_body(3)).expect("preview decodes");
    assert_eq!(pending.slot, 3);
    assert_eq!(pending.tx_hash_hex(), "ab".repeat(32));
    let receipt = receipt_bytes(ApprovalDecision::Approve, true).expect("biometric ok");
    let sign = build_sign_request(pending.slot, &psbt(), &receipt).expect("valid envelope");
    assert_eq!(sign.opcode, WALLET_OP_PSBT);
    // Both ride the `hardwallet` family gate, never `NotCompiled` here.
    if cfg!(feature = "hardwallet") {
        assert_eq!(SdkRequest::Wallet(query).check_compiled(), Ok(()));
        assert_eq!(SdkRequest::WalletSign(sign).check_compiled(), Ok(()));
    } else {
        assert_eq!(
            SdkRequest::Wallet(query).check_compiled(),
            Err(SdkError::NotCompiled)
        );
        assert_eq!(
            SdkRequest::WalletSign(sign).check_compiled(),
            Err(SdkError::NotCompiled)
        );
    }
}

#[test]
fn companion_shapes_fail_closed_before_wire() {
    assert_eq!(build_pending_query(32, &psbt()), Err(SdkError::Unsupported));
    assert_eq!(build_pending_query(0, &[]), Err(SdkError::Unsupported));
    assert_eq!(
        build_pending_query(0, &[0xAAu8; COMPANION_PSBT_MAX_BYTES + 1]),
        Err(SdkError::Unsupported)
    );
    assert_eq!(
        build_sign_request(0, &psbt(), b"maybe"),
        Err(SdkError::Unsupported)
    );
    assert_eq!(
        build_sign_request(0, &psbt(), &[]),
        Err(SdkError::Unsupported)
    );
    assert_eq!(preview_of(&[]), Err(SdkError::Unsupported));
}

#[test]
fn companion_receipt_is_sent_only_after_biometric_approve() {
    assert_eq!(
        receipt_bytes(ApprovalDecision::Approve, true).as_deref(),
        Some(b"approve".as_slice())
    );
    assert_eq!(receipt_bytes(ApprovalDecision::Approve, false), None);
    assert_eq!(
        receipt_bytes(ApprovalDecision::Deny, true).as_deref(),
        Some(b"deny".as_slice())
    );
    assert_eq!(
        receipt_bytes(ApprovalDecision::Deny, false).as_deref(),
        Some(b"deny".as_slice())
    );
    // Only the PSBT sign opcode needs app-mediated approval.
    assert!(wallet_op_requires_app_approval(WALLET_OP_PSBT));
    assert!(!wallet_op_requires_app_approval(WALLET_OP_XPUB));
    assert!(!wallet_op_requires_app_approval(WALLET_OP_PENDING));
}
