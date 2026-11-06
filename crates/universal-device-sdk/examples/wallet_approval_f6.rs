//! F6 app-mediated approval (facade-only demo, headless board).
//!
//! Shows the consumer-visible surface of app-mediated PSBT confirmation
//! through `universal-device-sdk` types: the preview query payload
//! (opcode `0x4B`), the pending-summary decode (display-only), the
//! biometric-gated receipt (tag `0x0C` on opcode `0x4A`), and the
//! `hardwallet` feature gate. No firmware, no transport, no secrets:
//! digests are opaque.

use universal_device_sdk::{
    decode_pending_summary, encode_pending_query, encode_sign_payload, is_wallet_family_opcode,
    receipt_for, wallet_op_is_approval_preview, wallet_op_requires_app_approval, ApprovalDecision,
    SdkRequest, WalletRequest, WalletSignRequest, WALLET_OP_PENDING, WALLET_OP_PSBT,
};

fn main() {
    // Preview and sign opcodes ride the wallet family behind `hardwallet`.
    assert!(is_wallet_family_opcode(WALLET_OP_PENDING));
    assert!(is_wallet_family_opcode(WALLET_OP_PSBT));
    assert!(wallet_op_requires_app_approval(WALLET_OP_PSBT));
    assert!(!wallet_op_requires_app_approval(WALLET_OP_PENDING));
    // The preview is the display that precedes the decision: never approved.
    assert!(wallet_op_is_approval_preview(WALLET_OP_PENDING));
    assert!(!wallet_op_is_approval_preview(WALLET_OP_PSBT));

    // 1. The app asks the device for the pending preview (display first).
    let psbt = vec![0x70, 0x73, 0x62, 0x74, 0xFF, 0x00];
    let query = SdkRequest::Wallet(WalletRequest {
        opcode: WALLET_OP_PENDING,
        payload: encode_pending_query(3, &psbt),
    });
    match query.check_compiled() {
        Ok(()) => println!(
            "PENDING 0x{PENDING:02X}: compiled in",
            PENDING = WALLET_OP_PENDING
        ),
        Err(e) => println!("PENDING: {e}"),
    }

    // 2. The device answers `[slot, tx_hash, counts]`; the app shows it.
    let mut summary = vec![0x01u8, 0x01, 0x03, 0x0Eu8, 0x20];
    summary.extend_from_slice(&[0xABu8; 32]);
    summary.extend_from_slice(&[0x0Fu8, 0x04, 0x01, 0x00, 0x02, 0x00]);
    let pending = decode_pending_summary(&summary).expect("preview decodes");
    assert_eq!(pending.slot, 3);
    println!(
        "preview: slot={} inputs={} outputs={} tx={}",
        pending.slot,
        pending.inputs,
        pending.outputs,
        pending.tx_hash_hex()
    );

    // 3. The owner approves in-app; the receipt is sent only after biometry.
    assert_eq!(
        receipt_for(ApprovalDecision::Approve, true).as_deref(),
        Some(b"approve".as_slice())
    );
    assert_eq!(receipt_for(ApprovalDecision::Approve, false), None);
    assert_eq!(
        receipt_for(ApprovalDecision::Deny, true).as_deref(),
        Some(b"deny".as_slice())
    );
    let receipt = receipt_for(ApprovalDecision::Approve, true).expect("biometric ok");
    let sign = SdkRequest::WalletSign(WalletSignRequest {
        opcode: WALLET_OP_PSBT,
        payload: encode_sign_payload(pending.slot, &psbt, &receipt),
    });
    match sign.check_compiled() {
        Ok(()) => println!("PSBT 0x{PSBT:02X}: receipt attached", PSBT = WALLET_OP_PSBT),
        Err(e) => println!("PSBT: {e}"),
    }
}
