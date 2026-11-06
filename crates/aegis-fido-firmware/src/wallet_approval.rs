//! App-mediated approval pending state (F6, headless board).
//!
//! The owner decision for boards without a display: the device exposes the
//! pending transaction ([`wallet_pending_summary`], opcode `0x4B`) and signs
//! only with an explicit approval receipt (tag `0x0C`, value
//! [`APPROVAL_RECEIPT_APPROVE`]) on the PSBT/sign opcode (`0x4A`), behind
//! the full `binding -> UP -> PIN` chain. The companion app shows the
//! details and returns approve/deny; the receipt is sent only after the
//! in-app biometric gate. No display dependency, no silent signing.
//!
//! [`WalletPendingApproval`] is RAM-only session state (same lifetime as
//! [`WalletStore`]): `announce` stores the parsed commitment, `verify_match`
//! enforces it single-use (any slot/hash drift denies as tamper and clears,
//! without touching keys). Absent preview stays compatible: signing without
//! a stored pending proceeds when receipt + gates pass (F4 single-shot).
//!
//! No wire status is added: denials reuse the closed set (`0x04` tamper or
//! malformed, `0x01` no UP, `0x02` no PIN, `0x03` no slot). Response tags
//! `0x0E`/`0x0F` sit above the frozen range; old decoders ignore them (§9.6).

use std::vec::Vec;

use aegis_fido_core::oath::tlv;
use aegis_fido_core::wallet::{parse_psbt, WalletError};

/// TLV: id do slot (1 B). Espelha `wallet_exec::TAG_WALLET_SLOT` sem
/// depender do modulo (que sai nas dietas `cap-fido-only`/`cap-fido-totp`;
/// este holder e inerte e compila em todas as variantes).
const TAG_WALLET_SLOT: u8 = 0x01;

/// Approval receipt value the app sends after an in-app biometric approve.
///
/// Exact byte comparison: anything else (including `deny`, empty, or absent)
/// denies fail-closed before any key touch. Protocol vocabulary, no marks.
pub const APPROVAL_RECEIPT_APPROVE: &[u8] = b"approve";

/// Explicit deny receipt value (informational: the executor treats any
/// non-`approve` value identically, as deny).
pub const APPROVAL_RECEIPT_DENY: &[u8] = b"deny";

/// TLV: `sha256(unsigned_tx)` commitment (32 B, pending-summary response).
///
/// Above the frozen tags; old decoders ignore it per §9.6.
pub const TAG_PENDING_TX_HASH: u8 = 0x0E;

/// TLV: input/output counts (`inputs u16 LE || outputs u16 LE`, 4 B).
///
/// Above the frozen tags; old decoders ignore it per §9.6.
pub const TAG_PENDING_COUNTS: u8 = 0x0F;

/// Pending transaction the device exposed for app-mediated approval.
///
/// Public metadata only: slot, digest commitment, input/output counts. No
/// addresses, no amounts, no secrets (amount policy is a follow-up).
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

/// Single pending approval slot (RAM-only, owned next to [`WalletStore`]).
///
/// At most one preview is live: `announce` replaces, `verify_match` consumes.
/// Fail-closed throughout: malformed envelopes never store, tamper clears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletPendingApproval {
    inner: Option<PendingWalletTx>,
}

impl WalletPendingApproval {
    /// Empty holder (no preview exposed yet).
    pub const fn new() -> Self {
        Self { inner: None }
    }

    /// Currently exposed preview, if any.
    pub const fn pending(&self) -> Option<PendingWalletTx> {
        self.inner
    }

    /// Parses `psbt`, stores its commitment, and returns the preview.
    ///
    /// Pure parse errors map to [`WalletError::BadEnvelope`]; nothing is
    /// stored on failure. Counts above `u16::MAX` are rejected (the PSBT
    /// length ceiling makes them unreachable, fail-closed anyway).
    pub fn announce(&mut self, slot: u8, psbt: &[u8]) -> Result<PendingWalletTx, WalletError> {
        let parsed = parse_psbt(psbt)?;
        let inputs = u16::try_from(parsed.inputs).map_err(|_| WalletError::BadEnvelope)?;
        let outputs = u16::try_from(parsed.outputs).map_err(|_| WalletError::BadEnvelope)?;
        let preview = PendingWalletTx {
            slot,
            tx_hash: parsed.tx_hash,
            inputs,
            outputs,
        };
        self.inner = Some(preview);
        Ok(preview)
    }

    /// Verifies the sign envelope against the stored preview (single-use).
    ///
    /// Returns the verified digest. With no stored preview, parses and
    /// returns the digest (F4 single-shot compatibility: still requires the
    /// receipt plus gates at the caller). With a stored preview, a slot or
    /// digest drift denies as tamper ([`WalletError::BadEnvelope`]) and
    /// clears the slot; a match consumes it. Never touches keys.
    pub fn verify_match(&mut self, slot: u8, psbt: &[u8]) -> Result<[u8; 32], WalletError> {
        let parsed = parse_psbt(psbt)?;
        match self.inner {
            None => Ok(parsed.tx_hash),
            Some(preview) if preview.slot == slot && preview.tx_hash == parsed.tx_hash => {
                self.inner = None;
                Ok(parsed.tx_hash)
            }
            Some(_) => {
                self.inner = None;
                Err(WalletError::BadEnvelope)
            }
        }
    }

    /// Withdraws any stored preview (lock, timeout, transport loss).
    pub fn clear(&mut self) {
        self.inner = None;
    }
}

impl Default for WalletPendingApproval {
    fn default() -> Self {
        Self::new()
    }
}

/// Encodes a pending preview as `[slot, tx_hash, counts]` TLV.
pub fn encode_pending_summary(preview: &PendingWalletTx) -> Vec<u8> {
    let mut out = Vec::new();
    tlv::write_tlv(&mut out, TAG_WALLET_SLOT, &[preview.slot]);
    tlv::write_tlv(&mut out, TAG_PENDING_TX_HASH, &preview.tx_hash);
    let mut counts = [0u8; 4];
    counts[..2].copy_from_slice(&preview.inputs.to_le_bytes());
    counts[2..].copy_from_slice(&preview.outputs.to_le_bytes());
    tlv::write_tlv(&mut out, TAG_PENDING_COUNTS, &counts);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psbt_1in_1out() -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        tx.push(0x01);
        tx.extend_from_slice(&[0xAAu8; 32]);
        tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        tx.push(0x00);
        tx.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        tx.push(0x01);
        tx.extend_from_slice(&1000u64.to_le_bytes());
        let mut script = Vec::from([0x00, 0x14]);
        script.extend_from_slice(&[0x11u8; 20]);
        tx.push(script.len() as u8);
        tx.extend_from_slice(&script);
        tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let mut out = Vec::from([0x70, 0x73, 0x62, 0x74, 0xFF]);
        out.push(0x01);
        out.push(0x00);
        out.push(tx.len() as u8);
        out.extend_from_slice(&tx);
        out.push(0x00);
        out.push(0x00);
        out.push(0x00);
        out
    }

    #[test]
    fn announce_stores_and_match_consumes_single_use() {
        let mut holder = WalletPendingApproval::new();
        assert_eq!(holder.pending(), None);
        let psbt = psbt_1in_1out();
        let preview = holder.announce(3, &psbt).unwrap();
        assert_eq!(preview.slot, 3);
        assert_eq!((preview.inputs, preview.outputs), (1, 1));
        assert_eq!(holder.pending(), Some(preview));
        // Match consumes single-use.
        let digest = holder.verify_match(3, &psbt).unwrap();
        assert_eq!(digest, preview.tx_hash);
        assert_eq!(holder.pending(), None);
        // No stored preview: compatible path still parses.
        assert_eq!(holder.verify_match(3, &psbt).unwrap(), preview.tx_hash);
    }

    #[test]
    fn tamper_clears_and_denies() {
        let mut holder = WalletPendingApproval::new();
        let mut psbt = psbt_1in_1out();
        holder.announce(3, &psbt).unwrap();
        // Flip one digest byte: drift denies and clears.
        psbt[20] ^= 0x55;
        assert_eq!(holder.verify_match(3, &psbt), Err(WalletError::BadEnvelope));
        assert_eq!(holder.pending(), None);
        // Wrong slot against the same bytes also denies.
        holder.announce(3, &psbt_1in_1out()).unwrap();
        assert_eq!(
            holder.verify_match(4, &psbt_1in_1out()),
            Err(WalletError::BadEnvelope)
        );
        assert_eq!(holder.pending(), None);
    }

    #[test]
    fn malformed_never_stores_and_summary_roundtrips() {
        let mut holder = WalletPendingApproval::new();
        assert_eq!(
            holder.announce(3, b"not-psbt"),
            Err(WalletError::BadEnvelope)
        );
        assert_eq!(holder.pending(), None);
        assert_eq!(
            holder.verify_match(3, b"not-psbt"),
            Err(WalletError::BadEnvelope)
        );
        let preview = holder.announce(5, &psbt_1in_1out()).unwrap();
        let body = encode_pending_summary(&preview);
        let recs = tlv::parse_tlv_records(&body).unwrap();
        assert_eq!(tlv::find_tlv(&recs, TAG_WALLET_SLOT), Some(&[5u8][..]));
        assert_eq!(
            tlv::find_tlv(&recs, TAG_PENDING_TX_HASH),
            Some(&preview.tx_hash[..])
        );
        let counts = tlv::find_tlv(&recs, TAG_PENDING_COUNTS).unwrap();
        assert_eq!(counts.len(), 4);
        assert_eq!(
            (
                u16::from_le_bytes([counts[0], counts[1]]),
                u16::from_le_bytes([counts[2], counts[3]])
            ),
            (1, 1)
        );
    }
}
