//! App-mediated wallet approval types (feature `hardwallet`).
//!
//! Typed companion-app side of the F6 headless-board contract: the firmware
//! exposes the pending preview (`0x4B` → [`PendingWalletTx`]; display-only,
//! public metadata) and signs only with an explicit approval receipt
//! (tag `0x0C`) behind `binding -> UP -> PIN`. This module builds both
//! payloads and gates the receipt on the in-app biometric check —
//! enforcement stays in firmware, this crate only types the exchange
//! (R5). No crypto here: digests are opaque 32 B commitments.
//!
//! `no_std` + `alloc` only; no `core` dependency beyond TLV framing.

use crate::error::SdkError;
use alloc::string::String;
use alloc::vec::Vec;

/// Approval receipt value the app sends after an in-app biometric approve.
///
/// Byte-identical to the firmware vocabulary (`wallet_approval`): any other
/// value denies fail-closed device-side before any key touch.
pub const APPROVAL_RECEIPT_APPROVE: &[u8] = b"approve";

/// Explicit deny receipt value (informational: firmware treats any
/// non-`approve` value as deny).
pub const APPROVAL_RECEIPT_DENY: &[u8] = b"deny";

/// TLV wallet: slot id (1 byte; mirrors the wire tag `0x01`).
pub const TAG_WALLET_SLOT: u8 = 0x01;

/// TLV wallet: PSBT envelope (mirrors the wire tag `0x0B`).
pub const TAG_WALLET_PSBT: u8 = 0x0B;

/// TLV wallet: app-mediated approval receipt (mirrors the wire tag `0x0C`).
pub const TAG_WALLET_APPROVAL: u8 = 0x0C;

/// TLV wallet: `sha256(unsigned_tx)` commitment (mirrors tag `0x0E`).
pub const TAG_PENDING_TX_HASH: u8 = 0x0E;

/// TLV wallet: input/output counts (mirrors tag `0x0F`).
pub const TAG_PENDING_COUNTS: u8 = 0x0F;

/// Pending transaction the device exposed for app-mediated approval.
///
/// Display-only public metadata: slot, digest commitment, input/output
/// counts. No addresses, no amounts, no secrets — the notification signal
/// carries even less (opaque handle only, see the app `ApprovalSignal`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingWalletTx {
    /// Wallet slot the previewed PSBT targets.
    pub slot: u8,
    /// `sha256(unsigned_tx)`: the exact commitment the app displayed.
    pub tx_hash: [u8; 32],
    /// Inputs in the unsigned transaction.
    pub inputs: u16,
    /// Outputs in the unsigned transaction.
    pub outputs: u16,
}

impl PendingWalletTx {
    /// Lowercase hex rendering of the digest commitment (display only).
    pub fn tx_hash_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for b in self.tx_hash {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
        out
    }
}

/// Owner decision on a displayed pending transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// User confirmed the displayed details (biometry still required).
    Approve,
    /// User rejected, or the app auto-denied (timeout/lock/transport loss).
    Deny,
}

/// Receipt bytes to send for `decision`, gated on the in-app biometric.
///
/// `Approve` yields the `approve` receipt ONLY with `biometric_ok` — without
/// a live biometric the app sends nothing (`None`), never a forged approve.
/// `Deny` always yields the explicit `deny` receipt (safe to withdraw).
pub fn receipt_for(decision: ApprovalDecision, biometric_ok: bool) -> Option<Vec<u8>> {
    match decision {
        ApprovalDecision::Approve if biometric_ok => Some(APPROVAL_RECEIPT_APPROVE.to_vec()),
        ApprovalDecision::Approve => None,
        ApprovalDecision::Deny => Some(APPROVAL_RECEIPT_DENY.to_vec()),
    }
}

fn write_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else if value.len() < 0x100 {
        out.push(0x81);
        out.push(value.len() as u8);
    } else {
        out.push(0x82);
        out.push(((value.len() >> 8) & 0xFF) as u8);
        out.push((value.len() & 0xFF) as u8);
    }
    out.extend_from_slice(value);
}

fn find_tlv<'a>(records: &[TlvRecord<'a>], tag: u8) -> Option<&'a [u8]> {
    records.iter().find(|r| r.tag == tag).map(|r| r.value)
}

struct TlvRecord<'a> {
    tag: u8,
    value: &'a [u8],
}

fn parse_tlv_records(data: &[u8]) -> Result<Vec<TlvRecord<'_>>, SdkError> {
    let mut records = Vec::new();
    let mut idx = 0;
    while idx < data.len() {
        let tag = data[idx];
        idx += 1;
        if idx >= data.len() {
            return Err(SdkError::Unsupported);
        }
        let len_byte = data[idx];
        idx += 1;
        let len = if len_byte < 0x80 {
            len_byte as usize
        } else if len_byte == 0x81 {
            if idx >= data.len() {
                return Err(SdkError::Unsupported);
            }
            let l = data[idx] as usize;
            idx += 1;
            l
        } else if len_byte == 0x82 {
            if idx + 1 >= data.len() {
                return Err(SdkError::Unsupported);
            }
            let l = ((data[idx] as usize) << 8) | (data[idx + 1] as usize);
            idx += 2;
            l
        } else {
            return Err(SdkError::Unsupported);
        };
        if data.len() < idx.saturating_add(len) {
            return Err(SdkError::Unsupported);
        }
        records.push(TlvRecord {
            tag,
            value: &data[idx..idx + len],
        });
        idx += len;
    }
    Ok(records)
}

/// Encodes a pending-preview query (`0x4B` payload): `[slot, psbt]`.
pub fn encode_pending_query(slot: u8, psbt: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_tlv(&mut out, TAG_WALLET_SLOT, &[slot]);
    write_tlv(&mut out, TAG_WALLET_PSBT, psbt);
    out
}

/// Encodes a sign envelope (`0x4A` payload): `[slot, psbt, approval]`.
pub fn encode_sign_payload(slot: u8, psbt: &[u8], receipt: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_tlv(&mut out, TAG_WALLET_SLOT, &[slot]);
    write_tlv(&mut out, TAG_WALLET_PSBT, psbt);
    write_tlv(&mut out, TAG_WALLET_APPROVAL, receipt);
    out
}

/// Decodes a pending-summary response (`0x4B` body): `[slot, tx_hash, counts]`.
///
/// Unknown tags are ignored (§9.6); malformed shapes fail as `Unsupported`.
/// A parsed summary is display data only — integrity is enforced
/// device-side on sign (tamper denies there, never here).
pub fn decode_pending_summary(body: &[u8]) -> Result<PendingWalletTx, SdkError> {
    let records = parse_tlv_records(body)?;
    let slot = find_tlv(&records, TAG_WALLET_SLOT)
        .filter(|v| v.len() == 1)
        .ok_or(SdkError::Unsupported)?[0];
    let hash = find_tlv(&records, TAG_PENDING_TX_HASH)
        .filter(|v| v.len() == 32)
        .ok_or(SdkError::Unsupported)?;
    let counts = find_tlv(&records, TAG_PENDING_COUNTS)
        .filter(|v| v.len() == 4)
        .ok_or(SdkError::Unsupported)?;
    let mut tx_hash = [0u8; 32];
    tx_hash.copy_from_slice(hash);
    Ok(PendingWalletTx {
        slot,
        tx_hash,
        inputs: u16::from_le_bytes([counts[0], counts[1]]),
        outputs: u16::from_le_bytes([counts[2], counts[3]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_gates_approve_on_biometry_and_always_allows_deny() {
        // Approve + live biometry: the only path that sends `approve`.
        assert_eq!(
            receipt_for(ApprovalDecision::Approve, true),
            Some(b"approve".to_vec())
        );
        // Approve without biometry: nothing sent, never a forged approve.
        assert_eq!(receipt_for(ApprovalDecision::Approve, false), None);
        // Deny always sends the explicit deny receipt (safe to withdraw).
        assert_eq!(
            receipt_for(ApprovalDecision::Deny, true),
            Some(b"deny".to_vec())
        );
        assert_eq!(
            receipt_for(ApprovalDecision::Deny, false),
            Some(b"deny".to_vec())
        );
    }

    #[test]
    fn sign_payload_carries_slot_psbt_and_receipt() {
        let body = encode_sign_payload(3, &[0x70, 0x73], b"approve");
        let recs = parse_tlv_records(&body).unwrap();
        assert_eq!(find_tlv(&recs, TAG_WALLET_SLOT), Some(&[3u8][..]));
        assert_eq!(find_tlv(&recs, TAG_WALLET_PSBT), Some(&[0x70, 0x73][..]));
        assert_eq!(find_tlv(&recs, TAG_WALLET_APPROVAL), Some(&b"approve"[..]));
    }

    #[test]
    fn pending_summary_roundtrips_and_rejects_malformed() {
        let preview = PendingWalletTx {
            slot: 5,
            tx_hash: [0xABu8; 32],
            inputs: 1,
            outputs: 2,
        };
        let mut body = Vec::new();
        write_tlv(&mut body, TAG_WALLET_SLOT, &[5]);
        write_tlv(&mut body, TAG_PENDING_TX_HASH, &[0xABu8; 32]);
        write_tlv(&mut body, TAG_PENDING_COUNTS, &[1, 0, 2, 0]);
        // Unknown tags are ignored (§9.6), never fail the decode.
        write_tlv(&mut body, 0x77, b"future");
        let back = decode_pending_summary(&body).unwrap();
        assert_eq!(back, preview);
        assert_eq!(back.tx_hash_hex(), "ab".repeat(32));
        // Missing/short/truncated shapes fail closed.
        assert_eq!(decode_pending_summary(&[]), Err(SdkError::Unsupported));
        assert_eq!(
            decode_pending_summary(&body[..4]),
            Err(SdkError::Unsupported)
        );
        let mut short = Vec::new();
        write_tlv(&mut short, TAG_WALLET_SLOT, &[5]);
        write_tlv(&mut short, TAG_PENDING_TX_HASH, &[0xABu8; 16]);
        write_tlv(&mut short, TAG_PENDING_COUNTS, &[1, 0, 2, 0]);
        assert_eq!(decode_pending_summary(&short), Err(SdkError::Unsupported));
    }

    #[test]
    fn query_and_summary_use_distinct_pending_and_receipt_tags() {
        assert_eq!(
            (TAG_WALLET_SLOT, TAG_WALLET_PSBT, TAG_WALLET_APPROVAL),
            (0x01, 0x0B, 0x0C)
        );
        assert_eq!((TAG_PENDING_TX_HASH, TAG_PENDING_COUNTS), (0x0E, 0x0F));
        assert_eq!(
            (APPROVAL_RECEIPT_APPROVE, APPROVAL_RECEIPT_DENY),
            (&b"approve"[..], &b"deny"[..])
        );
    }
}
