//! F7 wallet companion passthrough (bridge-side demo).
//!
//! Shows that the bridge owns no wallet framing: the pending query, the
//! sign envelope and the summary decode below all delegate 1:1 to the
//! `universal-device-sdk` codecs. Only opaque bytes and display-only JSON
//! cross this edge; no crypto, no secrets.

use aegis_bridge::{
    pending_summary_json, wallet_approval_receipt, wallet_pending_query_encode,
    wallet_pending_summary_decode, wallet_sign_envelope_encode,
};

fn main() {
    let psbt = vec![0x70u8, 0x73, 0x62, 0x74, 0xFF];

    // 1. Companion builds the preview query through the passthrough.
    let query = wallet_pending_query_encode(3, psbt.clone()).expect("valid shape");
    assert_eq!(&query[..3], &[0x01, 0x01, 0x03]);
    println!("query ok ({} B, SDK framing)", query.len());

    // 2. The device answers `[slot, tx_hash, counts]`; the edge renders JSON.
    let mut body = vec![0x01u8, 0x01, 0x03, 0x0Eu8, 0x20];
    body.extend_from_slice(&[0xABu8; 32]);
    body.extend_from_slice(&[0x0Fu8, 0x04, 0x01, 0x00, 0x02, 0x00]);
    let summary = wallet_pending_summary_decode(body).expect("preview decodes");
    println!("summary: {}", pending_summary_json(&summary));

    // 3. The receipt travels only after a live biometric approve.
    let receipt = wallet_approval_receipt(true, true).expect("biometric ok");
    assert!(wallet_approval_receipt(true, false).is_none());
    let envelope = wallet_sign_envelope_encode(3, psbt, receipt).expect("valid envelope");
    assert!(envelope.windows(7).any(|w| w == b"approve"));
    println!("sign envelope ok ({} B, SDK framing)", envelope.len());

    println!("wallet companion passthrough ok (no local framing)");
}
