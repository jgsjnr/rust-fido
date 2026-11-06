//! Wallet companion passthrough (host edge, no business logic).
//!
//! Every constructor here delegates 1:1 to the `universal-device-sdk`
//! `wallet_companion` / `wallet_approval` codecs: this crate owns no TLV
//! framing, no opcode table and no receipt strings for wallet flows — it
//! only forwards bytes and maps `SdkError` onto the frozen `BridgeError`
//! set (no new codes). Structured values cross this edge as JSON only
//! (see [`pending_summary_json`]); the inside stays typed.
//!
//! Companions (desktop tray, Android app) call this passthrough for the F7
//! xpub/watch-only and PSBT round-trip flows; no crypto ever runs here.

use crate::BridgeError;
use universal_device_sdk::wallet_approval::{receipt_for, ApprovalDecision};
use universal_device_sdk::wallet_companion::{
    build_pending_query, build_sign_request, preview_of, COMPANION_PSBT_MAX_BYTES,
};

/// Display-only pending summary for the JNI/JSON edge.
///
/// Public metadata only: slot, digest commitment (lowercase hex), input /
/// output counts. No addresses, no amounts, no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSummaryDto {
    /// Wallet slot the previewed PSBT targets.
    pub slot: u8,
    /// `sha256(unsigned_tx)` commitment, lowercase hex (64 chars).
    pub tx_hash_hex: String,
    /// Inputs in the unsigned transaction.
    pub inputs: u16,
    /// Outputs in the unsigned transaction.
    pub outputs: u16,
}

fn sdk_err_to_bridge(err: universal_device_sdk::SdkError) -> BridgeError {
    match err {
        // The companion family is unreachable only when `hardwallet` is
        // compiled off this edge's SDK copy: no device family to address.
        universal_device_sdk::SdkError::NotCompiled => BridgeError::InvalidOpcode,
        // Every other shape/gate failure mirrors wire `0x04` fail-closed.
        _ => BridgeError::InvalidEnvelope,
    }
}

/// Encodes a companion pending-preview query (`0x4B` payload).
///
/// Pure passthrough over the SDK builder: `[slot, psbt]` TLV framing lives
/// in the SDK. Oversize envelopes fail as `Overflow` (transport ceiling);
/// every other shape violation fails as `InvalidEnvelope`.
pub fn wallet_pending_query_encode(slot: u8, psbt: Vec<u8>) -> Result<Vec<u8>, BridgeError> {
    if psbt.len() > COMPANION_PSBT_MAX_BYTES {
        return Err(BridgeError::Overflow);
    }
    build_pending_query(slot, &psbt)
        .map(|req| req.payload)
        .map_err(sdk_err_to_bridge)
}

/// Encodes a companion sign envelope (`0x4A` payload).
///
/// Pure passthrough over the SDK builder: `[slot, psbt, approval]` framing
/// lives in the SDK. `receipt` must be exactly `approve`/`deny`; anything
/// else fails as `InvalidEnvelope` before any wire byte is built.
pub fn wallet_sign_envelope_encode(
    slot: u8,
    psbt: Vec<u8>,
    receipt: Vec<u8>,
) -> Result<Vec<u8>, BridgeError> {
    if psbt.len() > COMPANION_PSBT_MAX_BYTES {
        return Err(BridgeError::Overflow);
    }
    build_sign_request(slot, &psbt, &receipt)
        .map(|req| req.payload)
        .map_err(sdk_err_to_bridge)
}

/// Decodes a pending-summary body into display-only fields.
///
/// Pure passthrough over the SDK codec: unknown tags are ignored (§9.6),
/// malformed shapes fail as `InvalidEnvelope`.
pub fn wallet_pending_summary_decode(body: Vec<u8>) -> Result<PendingSummaryDto, BridgeError> {
    preview_of(&body)
        .map(|pending| PendingSummaryDto {
            slot: pending.slot,
            tx_hash_hex: pending.tx_hash_hex(),
            inputs: pending.inputs,
            outputs: pending.outputs,
        })
        .map_err(sdk_err_to_bridge)
}

/// Approval receipt bytes for the sign envelope.
///
/// `approve=true` yields the `approve` receipt ONLY with `biometric_ok` —
/// without a live biometric there is no receipt (`None`: the companion
/// sends nothing, never a forged approve). `approve=false` always yields
/// the explicit `deny` receipt (safe to withdraw). Pure function, never fails.
pub fn wallet_approval_receipt(approve: bool, biometric_ok: bool) -> Option<Vec<u8>> {
    let decision = if approve {
        ApprovalDecision::Approve
    } else {
        ApprovalDecision::Deny
    };
    receipt_for(decision, biometric_ok)
}

/// Renders a pending summary as JNI-edge JSON (fixed key order).
///
/// `{"slot":N,"tx_hash_hex":"…","inputs":N,"outputs":N}` — the hex payload
/// is `[0-9a-f]` by construction, so no escaping is needed.
pub fn pending_summary_json(summary: &PendingSummaryDto) -> String {
    format!(
        "{{\"slot\":{},\"tx_hash_hex\":\"{}\",\"inputs\":{},\"outputs\":{}}}",
        summary.slot, summary.tx_hash_hex, summary.inputs, summary.outputs
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psbt() -> Vec<u8> {
        vec![0x70, 0x73, 0x62, 0x74, 0xFF]
    }

    fn summary_body(slot: u8) -> Vec<u8> {
        let mut out = vec![0x01u8, 0x01, slot, 0x0E, 0x20];
        out.extend_from_slice(&[0xABu8; 32]);
        out.extend_from_slice(&[0x0F, 0x04, 0x01, 0x00, 0x02, 0x00]);
        out
    }

    #[test]
    fn passthrough_query_delegates_to_sdk_framing() {
        let via_bridge = wallet_pending_query_encode(3, psbt()).unwrap();
        let via_sdk = build_pending_query(3, &psbt()).unwrap().payload;
        assert_eq!(via_bridge, via_sdk);
    }

    #[test]
    fn passthrough_sign_envelope_delegates_to_sdk_framing() {
        let via_bridge = wallet_sign_envelope_encode(3, psbt(), b"approve".to_vec()).unwrap();
        let via_sdk = build_sign_request(3, &psbt(), b"approve").unwrap().payload;
        assert_eq!(via_bridge, via_sdk);
        // Deny receipt travels the same passthrough.
        let deny = wallet_sign_envelope_encode(3, psbt(), b"deny".to_vec()).unwrap();
        assert!(deny.windows(4).any(|w| w == b"deny"));
    }

    #[test]
    fn passthrough_rejects_shapes_without_new_codes() {
        // Bad slot / empty / oversize fail on the frozen set only.
        assert_eq!(
            wallet_pending_query_encode(32, psbt()),
            Err(BridgeError::InvalidEnvelope)
        );
        assert_eq!(
            wallet_pending_query_encode(0, vec![]),
            Err(BridgeError::InvalidEnvelope)
        );
        assert_eq!(
            wallet_pending_query_encode(0, vec![0xAAu8; COMPANION_PSBT_MAX_BYTES + 1]),
            Err(BridgeError::Overflow)
        );
        assert_eq!(
            wallet_sign_envelope_encode(0, psbt(), b"maybe".to_vec()),
            Err(BridgeError::InvalidEnvelope)
        );
        assert_eq!(
            wallet_sign_envelope_encode(0, psbt(), vec![]),
            Err(BridgeError::InvalidEnvelope)
        );
        assert_eq!(
            wallet_pending_summary_decode(vec![]),
            Err(BridgeError::InvalidEnvelope)
        );
    }

    #[test]
    fn passthrough_summary_decodes_display_fields_only() {
        let dto = wallet_pending_summary_decode(summary_body(3)).unwrap();
        assert_eq!(dto.slot, 3);
        assert_eq!(dto.tx_hash_hex, "ab".repeat(32));
        assert_eq!((dto.inputs, dto.outputs), (1, 2));
        assert_eq!(
            pending_summary_json(&dto),
            format!(
                "{{\"slot\":3,\"tx_hash_hex\":\"{}\",\"inputs\":1,\"outputs\":2}}",
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn passthrough_receipt_never_forges_approve() {
        assert_eq!(
            wallet_approval_receipt(true, true).as_deref(),
            Some(b"approve".as_slice())
        );
        assert_eq!(wallet_approval_receipt(true, false), None);
        assert_eq!(
            wallet_approval_receipt(false, false).as_deref(),
            Some(b"deny".as_slice())
        );
    }

    #[test]
    fn companion_ceiling_matches_transport_cap() {
        assert_eq!(COMPANION_PSBT_MAX_BYTES, super::super::CONTROL_POINT_LENGTH);
    }
}
