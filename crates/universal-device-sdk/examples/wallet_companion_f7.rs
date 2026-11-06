//! F7 companion flows over the facade (no board, no transport).
//!
//! Shows the consumer-visible companion surface through
//! `universal-device-sdk` types only: the pending-preview query builder
//! (opcode `0x4B`, display first), the xpub watch-only opcode, the sign
//! envelope builder (`0x4A` with biometric-gated receipt), and the
//! `hardwallet` feature gate. No firmware, no bridge, no secrets: digests
//! are opaque.

use universal_device_sdk::{
    build_pending_query, build_sign_request, is_companion_opcode, is_wallet_family_opcode,
    preview_of, receipt_bytes, wallet_op_is_approval_preview, wallet_op_requires_app_approval,
    ApprovalDecision, SdkRequest, COMPANION_OPS, WALLET_OP_PENDING, WALLET_OP_PSBT, WALLET_OP_XPUB,
};

fn main() {
    // The companion surface is exactly xpub + PSBT + pending preview.
    assert_eq!(
        COMPANION_OPS,
        [WALLET_OP_XPUB, WALLET_OP_PSBT, WALLET_OP_PENDING]
    );
    for op in COMPANION_OPS {
        assert!(is_companion_opcode(op));
        assert!(is_wallet_family_opcode(op));
    }
    assert!(wallet_op_requires_app_approval(WALLET_OP_PSBT));
    assert!(wallet_op_is_approval_preview(WALLET_OP_PENDING));

    // 1. The companion asks the device for the pending preview (display first).
    let psbt = [0x70u8, 0x73, 0x62, 0x74, 0xFF];
    let query = build_pending_query(3, &psbt).expect("valid shape");
    assert_eq!(query.opcode, WALLET_OP_PENDING);
    match SdkRequest::Wallet(query).check_compiled() {
        Ok(()) => println!("PENDING 0x{WALLET_OP_PENDING:02X}: display first"),
        Err(e) => println!("PENDING: {e}"),
    }

    // 2. The device answers `[slot, tx_hash, counts]`; the companion shows it.
    let mut summary = vec![0x01u8, 0x01, 0x03, 0x0Eu8, 0x20];
    summary.extend_from_slice(&[0xABu8; 32]);
    summary.extend_from_slice(&[0x0Fu8, 0x04, 0x01, 0x00, 0x02, 0x00]);
    let pending = preview_of(&summary).expect("preview decodes");
    println!(
        "preview: slot={} inputs={} outputs={} tx={}",
        pending.slot,
        pending.inputs,
        pending.outputs,
        pending.tx_hash_hex()
    );

    // 3. The owner approves; the receipt travels only after live biometry.
    let receipt = receipt_bytes(ApprovalDecision::Approve, true).expect("biometric ok");
    assert!(receipt_bytes(ApprovalDecision::Approve, false).is_none());
    let sign = build_sign_request(pending.slot, &psbt, &receipt).expect("valid envelope");
    assert_eq!(sign.opcode, WALLET_OP_PSBT);
    match SdkRequest::WalletSign(sign).check_compiled() {
        Ok(()) => println!("PSBT 0x{WALLET_OP_PSBT:02X}: receipt attached"),
        Err(e) => println!("PSBT: {e}"),
    }
    println!("wallet companion ok (facade only, no secrets)");
}
