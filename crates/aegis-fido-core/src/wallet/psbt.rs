//! PSBT/BIP-174 envelope parsing with session-gated digest signing.
//!
//! BEHAVIOR: structural parser for version-0 PSBT envelopes
//! (`psbt\xff` magic, global map, per-input and per-output maps) plus a
//! minimal unsigned-transaction scan that counts inputs and outputs and
//! commits to the unsigned transaction with `sha256` (the approval-display
//! commitment). No network policy, no fee logic, no sighash surgery: the
//! signature produced here is a message-sign over that digest with the
//! slot key ([`WalletStore::sign_psbt`](super::store::WalletStore::sign_psbt`),
//! single-key scope), verifiable off-device against the slot public key.
//! Full per-input sighash (BIP-143/341) is an explicit follow-up, never
//! claimed here.
//!
//! SCOPE: Bitcoin-family envelope shape only at the structural level; any
//! slot key may sign the digest (message-sign semantics, documented, no
//! silent reinterpretation). Version-2 envelopes carry no unsigned
//! transaction, so they fail closed as missing-unsigned-tx (never a
//! version sniff, never a zero digest).
//!
//! GATES: parsing is pure (no presence needed, output is public
//! metadata). Signing requires the single-use UP latch
//! (`presence_confirmed`, consumed by the caller) and fails closed with
//! [`WalletError::NeedUp`](super::WalletError::NeedUp) otherwise. The
//! wire layer additionally requires the explicit app-mediated approval
//! receipt (owner decision: the companion app shows the details and
//! returns approve/deny; the firmware never signs without it and without
//! a display of its own).
//!
//! CONVENTIONS: protocol terms only (magic, map, unsigned transaction,
//! digest). No product or service names appear here.

use crate::crypto::hash::sha256;

use super::store::WalletStore;
use super::{CryptoNetwork, WalletError};

/// PSBT magic prefix (`psbt` + `0xff` separator).
pub const PSBT_MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

/// Maximum PSBT envelope accepted for parsing (control-point ceiling, no
/// extra allocation budget beyond the caller's slice).
pub const PSBT_MAX_LEN: usize = 4096;

/// Structural PSBT failures. Every variant maps to
/// [`WalletError::BadEnvelope`] (closed wire set `0x04`): no new status,
/// no secret in the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtError {
    /// First five bytes are not `psbt\xff`.
    BadMagic,
    /// Envelope ends mid-structure (short magic, cut varint, cut record).
    Truncated,
    /// Varint overflows `u64` or is non-minimal in a map length.
    BadVarint,
    /// Duplicate unsigned transaction, unterminated map, or empty
    /// input/output section where the scan needs counts.
    MalformedMap,
    /// Global map has no unsigned-transaction record (includes
    /// version-2 envelopes, which carry none by construction).
    MissingUnsignedTx,
    /// Unsigned transaction is not `version || inputs || outputs ||
    /// locktime` with at least one input and one output.
    MalformedTx,
}

impl core::fmt::Display for PsbtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not a PSBT envelope"),
            Self::Truncated => write!(f, "truncated PSBT envelope"),
            Self::BadVarint => write!(f, "invalid PSBT compact size"),
            Self::MalformedMap => write!(f, "malformed PSBT map"),
            Self::MissingUnsignedTx => write!(f, "PSBT global map without unsigned transaction"),
            Self::MalformedTx => write!(f, "malformed PSBT unsigned transaction"),
        }
    }
}

impl From<PsbtError> for WalletError {
    fn from(_: PsbtError) -> Self {
        Self::BadEnvelope
    }
}

/// Parsed PSBT view: public metadata only, borrows the unsigned
/// transaction bytes from the input envelope (no copy, no secret).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedPsbt<'a> {
    /// Unsigned transaction bytes (the exact signed commitment).
    pub unsigned_tx: &'a [u8],
    /// Number of inputs in the unsigned transaction.
    pub inputs: usize,
    /// Number of outputs in the unsigned transaction.
    pub outputs: usize,
    /// `sha256(unsigned_tx)`: approval-display commitment and the
    /// message actually signed by [`WalletStore::sign_psbt`].
    pub tx_hash: [u8; 32],
}

/// Approval-display summary: counts plus commitment, no addresses, no
/// amounts (amount policy is a follow-up; never zero, never forged).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsbtSummary {
    /// Number of inputs in the unsigned transaction.
    pub inputs: usize,
    /// Number of outputs in the unsigned transaction.
    pub outputs: usize,
    /// `sha256(unsigned_tx)` commitment.
    pub tx_hash: [u8; 32],
}

impl<'a> ParsedPsbt<'a> {
    /// Public summary view of this envelope.
    pub fn summary(&self) -> PsbtSummary {
        PsbtSummary {
            inputs: self.inputs,
            outputs: self.outputs,
            tx_hash: self.tx_hash,
        }
    }
}

fn read_varint(bytes: &[u8]) -> Result<(u64, usize), PsbtError> {
    if bytes.is_empty() {
        return Err(PsbtError::Truncated);
    }
    match bytes[0] {
        0..=0xFC => Ok((bytes[0] as u64, 1)),
        0xFD => {
            if bytes.len() < 3 {
                return Err(PsbtError::Truncated);
            }
            Ok((u16::from_le_bytes([bytes[1], bytes[2]]) as u64, 3))
        }
        0xFE => {
            if bytes.len() < 5 {
                return Err(PsbtError::Truncated);
            }
            Ok((
                u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64,
                5,
            ))
        }
        0xFF => {
            if bytes.len() < 9 {
                return Err(PsbtError::Truncated);
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[1..9]);
            Ok((u64::from_le_bytes(raw), 9))
        }
    }
}

/// One map record plus the bytes consumed (key/value borrows, no copy).
type MapRecord<'a> = (Option<(&'a [u8], &'a [u8])>, usize);

/// Reads one map record `(key, value)`; `Ok(None)` on the `0x00`
/// terminator. Bounds-checked: any overrun is [`PsbtError::Truncated`].
fn read_record(bytes: &[u8]) -> Result<MapRecord<'_>, PsbtError> {
    let (key_len, key_len_size) = read_varint(bytes)?;
    if key_len == 0 {
        return Ok((None, key_len_size));
    }
    let key_len = usize::try_from(key_len).map_err(|_| PsbtError::BadVarint)?;
    let mut cursor = key_len_size
        .checked_add(key_len)
        .ok_or(PsbtError::BadVarint)?;
    if bytes.len() < cursor {
        return Err(PsbtError::Truncated);
    }
    let key = &bytes[key_len_size..cursor];
    let (val_len, val_len_size) = read_varint(&bytes[cursor..]).map_err(|e| match e {
        PsbtError::Truncated => PsbtError::Truncated,
        _ => PsbtError::BadVarint,
    })?;
    let val_len = usize::try_from(val_len).map_err(|_| PsbtError::BadVarint)?;
    cursor = cursor
        .checked_add(val_len_size)
        .and_then(|c| c.checked_add(val_len))
        .ok_or(PsbtError::BadVarint)?;
    if bytes.len() < cursor {
        return Err(PsbtError::Truncated);
    }
    let value = &bytes[cursor - val_len..cursor];
    Ok((Some((key, value)), cursor))
}

/// Skips one map (records until the `0x00` terminator).
fn skip_map(bytes: &[u8]) -> Result<usize, PsbtError> {
    let mut cursor = 0;
    loop {
        if cursor >= bytes.len() {
            return Err(PsbtError::Truncated);
        }
        let (record, consumed) = read_record(&bytes[cursor..])?;
        cursor += consumed;
        if record.is_none() {
            return Ok(cursor);
        }
    }
}

/// Minimal unsigned-transaction scan: `version(4) [marker(1) flag(1)]?
/// in-count inputs out-count outputs locktime(4)`.
///
/// Returns `(inputs, outputs)`. Counts of zero, missing locktime, or any
/// overrun fail closed ([`PsbtError::MalformedTx`] / [`PsbtError::Truncated`]).
fn scan_unsigned_tx(tx: &[u8]) -> Result<(usize, usize), PsbtError> {
    if tx.len() < 4 {
        return Err(PsbtError::Truncated);
    }
    let mut cursor = 4;
    // Segwit marker/flag (`0x00 0x01`) when present.
    if tx.len() >= cursor + 2 && tx[cursor] == 0x00 && tx[cursor + 1] == 0x01 {
        cursor += 2;
    }
    let (in_count, in_size) = read_varint(&tx[cursor..]).map_err(|_| PsbtError::MalformedTx)?;
    if in_count == 0 || in_count > u64::from(u32::MAX) {
        return Err(PsbtError::MalformedTx);
    }
    cursor += in_size;
    for _ in 0..in_count {
        // prev-hash(32) + vout(4) + script(varint + bytes) + sequence(4).
        if tx.len() < cursor + 36 {
            return Err(PsbtError::Truncated);
        }
        cursor += 36;
        let (script_len, script_size) =
            read_varint(&tx[cursor..]).map_err(|_| PsbtError::MalformedTx)?;
        let script_len = usize::try_from(script_len).map_err(|_| PsbtError::MalformedTx)?;
        cursor = cursor
            .checked_add(script_size)
            .and_then(|c| c.checked_add(script_len))
            .and_then(|c| c.checked_add(4))
            .ok_or(PsbtError::MalformedTx)?;
        if tx.len() < cursor {
            return Err(PsbtError::Truncated);
        }
    }
    let (out_count, out_size) = read_varint(&tx[cursor..]).map_err(|_| PsbtError::MalformedTx)?;
    if out_count == 0 || out_count > u64::from(u32::MAX) {
        return Err(PsbtError::MalformedTx);
    }
    cursor += out_size;
    for _ in 0..out_count {
        // value(8) + script(varint + bytes).
        if tx.len() < cursor + 8 {
            return Err(PsbtError::Truncated);
        }
        cursor += 8;
        let (script_len, script_size) =
            read_varint(&tx[cursor..]).map_err(|_| PsbtError::MalformedTx)?;
        let script_len = usize::try_from(script_len).map_err(|_| PsbtError::MalformedTx)?;
        cursor = cursor
            .checked_add(script_size)
            .and_then(|c| c.checked_add(script_len))
            .ok_or(PsbtError::MalformedTx)?;
        if tx.len() < cursor {
            return Err(PsbtError::Truncated);
        }
    }
    if tx.len() < cursor + 4 {
        return Err(PsbtError::Truncated);
    }
    let inputs = usize::try_from(in_count).map_err(|_| PsbtError::MalformedTx)?;
    let outputs = usize::try_from(out_count).map_err(|_| PsbtError::MalformedTx)?;
    Ok((inputs, outputs))
}

/// Parses a version-0 PSBT envelope.
///
/// Requires the `psbt\xff` magic, exactly one unsigned-transaction
/// record (`keylen 1, key 0x00`) in the global map, and one map per
/// input/output declared by the unsigned transaction (contents skipped:
/// partial-signing state travels with the envelope, never trusted here).
/// Unknown global keys are skipped (readers ignore what they do not
/// understand); anything structurally wrong fails closed.
pub fn parse_psbt(bytes: &[u8]) -> Result<ParsedPsbt<'_>, PsbtError> {
    if bytes.len() > PSBT_MAX_LEN {
        return Err(PsbtError::Truncated);
    }
    if bytes.len() < PSBT_MAGIC.len() {
        return Err(PsbtError::Truncated);
    }
    if bytes[..PSBT_MAGIC.len()] != PSBT_MAGIC {
        return Err(PsbtError::BadMagic);
    }
    let mut cursor = PSBT_MAGIC.len();
    let mut unsigned_tx: Option<&[u8]> = None;
    loop {
        if cursor >= bytes.len() {
            return Err(PsbtError::Truncated);
        }
        let (record, consumed) = read_record(&bytes[cursor..])?;
        cursor += consumed;
        match record {
            None => break,
            Some((key, value)) => {
                if key == [0x00] {
                    if unsigned_tx.is_some() {
                        return Err(PsbtError::MalformedMap);
                    }
                    unsigned_tx = Some(value);
                }
                // Unknown global keys are skipped, never trusted.
            }
        }
    }
    let unsigned_tx = unsigned_tx.ok_or(PsbtError::MissingUnsignedTx)?;
    let (inputs, outputs) = scan_unsigned_tx(unsigned_tx)?;
    for _ in 0..inputs {
        let consumed = skip_map(&bytes[cursor..])?;
        cursor += consumed;
    }
    for _ in 0..outputs {
        let consumed = skip_map(&bytes[cursor..])?;
        cursor += consumed;
    }
    Ok(ParsedPsbt {
        unsigned_tx,
        inputs,
        outputs,
        tx_hash: sha256(unsigned_tx),
    })
}

impl WalletStore {
    /// Session-gated PSBT digest signing: parses the envelope, then
    /// signs `sha256(unsigned_tx)` with the slot key (message-sign only,
    /// single-key scope; full per-input sighash is a follow-up).
    ///
    /// `presence` arrives from the single-use UP latch (consumed by the
    /// caller); without it this fails closed with [`WalletError::NeedUp`]
    /// and parses nothing secret. Structural failures map to
    /// [`WalletError::BadEnvelope`]; unknown slots to [`WalletError::NoSlot`].
    /// Returns the public summary plus the opaque signature (verify
    /// off-device against the slot public key).
    pub fn sign_psbt(
        &mut self,
        slot_id: u8,
        psbt_bytes: &[u8],
        presence_confirmed: bool,
    ) -> Result<(PsbtSummary, Vec<u8>), WalletError> {
        if !presence_confirmed {
            return Err(WalletError::NeedUp);
        }
        let parsed = parse_psbt(psbt_bytes)?;
        let sig = self.sign(slot_id, &parsed.tx_hash, presence_confirmed)?;
        Ok((parsed.summary(), sig))
    }
}

/// PSBT envelopes are Bitcoin-family shapes; the digest signer above is
/// network-agnostic message-sign by construction. This helper pins the
/// documented envelope family for future policy without touching the
/// closed wire set today.
pub fn psbt_envelope_family() -> CryptoNetwork {
    CryptoNetwork::Bitcoin
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn unsigned_tx_1in_1out() -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // version 2
        tx.push(0x01); // 1 input
        tx.extend_from_slice(&[0xAAu8; 32]); // prev hash
        tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // vout
        tx.push(0x00); // empty script
        tx.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // sequence
        tx.push(0x01); // 1 output
        tx.extend_from_slice(&1000u64.to_le_bytes()); // 1000 sats
        let mut script = Vec::from([0x00, 0x14]);
        script.extend_from_slice(&[0x11u8; 20]);
        tx.push(script.len() as u8);
        tx.extend_from_slice(&script);
        tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // locktime
        tx
    }

    fn envelope_for(tx: &[u8]) -> Vec<u8> {
        let mut out = Vec::from(PSBT_MAGIC);
        out.push(0x01); // keylen 1
        out.push(0x00); // unsigned tx
        out.push(tx.len() as u8); // vallen (< 0xFD here)
        out.extend_from_slice(tx);
        out.push(0x00); // global terminator
        out.push(0x00); // input map (empty)
        out.push(0x00); // output map (empty)
        out
    }

    #[test]
    fn should_parse_minimal_v0_envelope_with_counts_and_commitment() {
        let tx = unsigned_tx_1in_1out();
        let env = envelope_for(&tx);
        let parsed = parse_psbt(&env).unwrap();
        assert_eq!((parsed.inputs, parsed.outputs), (1, 1));
        assert_eq!(parsed.unsigned_tx, tx.as_slice());
        assert_eq!(parsed.tx_hash, sha256(&tx));
        assert_eq!(
            parsed.summary(),
            PsbtSummary {
                inputs: 1,
                outputs: 1,
                tx_hash: sha256(&tx),
            }
        );
    }

    #[test]
    fn should_reject_non_psbt_magic_fail_closed() {
        let mut env = envelope_for(&unsigned_tx_1in_1out());
        env[0] = 0x00;
        assert_eq!(parse_psbt(&env).unwrap_err(), PsbtError::BadMagic);
        assert_eq!(parse_psbt(&[]).unwrap_err(), PsbtError::Truncated);
        assert_eq!(parse_psbt(&[0x70]).unwrap_err(), PsbtError::Truncated);
    }

    #[test]
    fn should_reject_envelope_without_unsigned_tx_including_v2_shape() {
        // Global map with only an xpub record: structurally valid, but no
        // unsigned transaction (this is also how a v2 envelope presents to
        // a v0 reader) -> MissingUnsignedTx, never a zero digest.
        let mut out = Vec::from(PSBT_MAGIC);
        out.push(0x01);
        out.push(0x01); // xpub key type (skipped content)
        out.push(0x01);
        out.push(0x00);
        out.push(0x00); // terminator
        assert_eq!(parse_psbt(&out).unwrap_err(), PsbtError::MissingUnsignedTx);
    }

    #[test]
    fn should_reject_duplicate_unsigned_tx_and_cut_maps() {
        let tx = unsigned_tx_1in_1out();
        let mut out = Vec::from(PSBT_MAGIC);
        for _ in 0..2 {
            out.push(0x01);
            out.push(0x00);
            out.push(tx.len() as u8);
            out.extend_from_slice(&tx);
        }
        out.push(0x00);
        assert_eq!(parse_psbt(&out).unwrap_err(), PsbtError::MalformedMap);
        // Cut right after the magic: truncated, never partial.
        let cut = Vec::from(PSBT_MAGIC);
        assert_eq!(parse_psbt(&cut).unwrap_err(), PsbtError::Truncated);
        // Declared input maps missing after the global terminator.
        let mut no_maps = Vec::from(PSBT_MAGIC);
        no_maps.push(0x01);
        no_maps.push(0x00);
        no_maps.push(tx.len() as u8);
        no_maps.extend_from_slice(&tx);
        no_maps.push(0x00);
        assert_eq!(parse_psbt(&no_maps).unwrap_err(), PsbtError::Truncated);
    }

    #[test]
    fn should_reject_unsigned_tx_without_inputs_or_outputs() {
        // in-count 0.
        let mut tx = unsigned_tx_1in_1out();
        tx[4] = 0x00;
        assert_eq!(
            parse_psbt(&envelope_for(&tx)).unwrap_err(),
            PsbtError::MalformedTx
        );
        // out-count 0 (input section intact: 4 + 1 + 41 = 46).
        let mut tx = unsigned_tx_1in_1out();
        tx[46] = 0x00;
        assert_eq!(
            parse_psbt(&envelope_for(&tx)).unwrap_err(),
            PsbtError::MalformedTx
        );
    }

    #[test]
    fn should_map_every_psbt_failure_onto_bad_envelope() {
        let err: WalletError = PsbtError::BadMagic.into();
        assert_eq!(err, WalletError::BadEnvelope);
        assert_eq!(err.status(), 0x04);
    }

    #[test]
    fn should_require_presence_before_signing_anything() {
        let mut rng = rand::rng();
        let mut store = WalletStore::new();
        store
            .generate(CryptoNetwork::Bitcoin, 0, "psbt", 0, true, &mut rng)
            .unwrap();
        let env = envelope_for(&unsigned_tx_1in_1out());
        assert_eq!(
            store.sign_psbt(0, &env, false).unwrap_err(),
            WalletError::NeedUp
        );
        assert_eq!(
            store.sign_psbt(9, &env, true).unwrap_err(),
            WalletError::NoSlot
        );
        assert_eq!(
            store.sign_psbt(0, b"not-psbt", true).unwrap_err(),
            WalletError::BadEnvelope
        );
    }

    #[test]
    fn should_sign_digest_and_verify_off_device() {
        use crate::crypto::PublicKey;
        let mut rng = rand::rng();
        let mut store = WalletStore::new();
        store
            .generate(CryptoNetwork::Bitcoin, 0, "psbt", 0, true, &mut rng)
            .unwrap();
        let env = envelope_for(&unsigned_tx_1in_1out());
        let (summary, sig) = store.sign_psbt(0, &env, true).unwrap();
        assert_eq!((summary.inputs, summary.outputs), (1, 1));
        assert!(!sig.is_empty());
        let cose = store.public_cose(0, true).unwrap();
        let pubkey = PublicKey::from_cose_cbor(&cose).unwrap();
        pubkey.verify(&summary.tx_hash, &sig).unwrap();
    }
}
