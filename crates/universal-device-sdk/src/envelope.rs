//! AEGN v1 backup/export envelope (GEN-APP-STORE, T-FD-06).
//!
//! Typed framing plus fail-closed gates for backup blobs: the app builds the
//! envelope only with `binding -> UP -> PIN` proofs (`AuthContext`), the
//! device only stores the opaque ciphertext and never sees key material in
//! the clear outside the envelope. AEAD itself runs in firmware / the FFI
//! bridge (this crate has no crypto dependency); here the ciphertext
//! (`ct + tag`) stays opaque end to end.
//!
//! Wire layout (mirrors firmware `persistence` and `wifi_ap`):
//! `MAGIC[4] | VER[1] | NONCE[12] | CT+TAG[>=16]`.
//!
//! Canonical wire source: firmware `persistence.rs`
//! (`ENVELOPE_MAGIC`, `ENVELOPE_VERSION`, `MAX_PLAINTEXT_BYTES = 4096`,
//! `MAX_ENVELOPE_BYTES = 4129`). This crate re-exports those ceilings as
//! typed constants; the UniFFI bridge (`crates/uniffi-bridge/src/lib.rs`)
//! keeps a documented copy (cdylib keeps no SDK/firmware dependency) and
//! parity is enforced by the mirrored cross-vector tests here and there
//! (`aegn_cross_vector_matches_bridge_and_firmware` <->
//! `envelope_cross_vector_matches_sdk_framing`). Full delegation of
//! seal/open into one shared call is blocked by the ABI: UniFFI exposes
//! only `Vec<u8>` over FFI while this crate seals opaque `ct + tag` behind
//! `AuthContext` + `ReplayWindow` and owns no AEAD (crypto lives in the
//! bridge via `aegis-fido-core` / in firmware). So the contract is
//! byte-exact framing plus identical ceilings, not a shared function.
//!
//! Rules enforced here (R5 fail-closed, §9):
//! - Gate order is data-checked as `binding -> UP -> PIN`; the first missing
//!   proof wins so a stranger always sees `NEED_BINDING` first.
//! - Nonce must be non-zero (device TRNG never emits zero) and fresh per
//!   `ReplayWindow` (constant-time compare, bounded FIFO; the device keeps
//!   the authoritative check).
//! - Sizes mirror firmware: plaintext `<= 4096`, envelope `<= 4129`.
//! - Nothing secret is printable: `Debug` renders lengths only.
//!
//! `no_std` + `alloc` only; no `std`, no JSON, no `unsafe`.

use crate::auth::AuthContext;
use crate::response::SdkResponse;
use crate::status::{STATUS_BAD_ENVELOPE, STATUS_NEED_BINDING, STATUS_NEED_PIN, STATUS_NEED_UP};
use alloc::vec::Vec;
use core::fmt::{self, Display, Formatter};

/// Envelope magic `"AEGN"`.
pub const ENVELOPE_MAGIC: [u8; 4] = [0x41, 0x45, 0x47, 0x4E];
/// Envelope version (`v1` only).
pub const ENVELOPE_VERSION: u8 = 0x01;
/// Nonce length in bytes (12 B, unique per seal).
pub const NONCE_LEN: usize = 12;
/// GCM tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Header length (`MAGIC[4] | VER[1] | NONCE[12]`).
pub const HEADER_LEN: usize = 4 + 1 + NONCE_LEN;
/// Floor (`HEADER | TAG` with empty ciphertext).
pub const MIN_ENVELOPE_LEN: usize = HEADER_LEN + TAG_LEN;
/// Plaintext ceiling per seal (mirrors firmware `MAX_PLAINTEXT_BYTES`).
pub const MAX_PLAINTEXT_BYTES: usize = 4096;
/// Ciphertext ceiling (`plaintext + TAG`).
pub const MAX_CIPHERTEXT_BYTES: usize = MAX_PLAINTEXT_BYTES + TAG_LEN;
/// Envelope ceiling (`HEADER + plaintext + TAG`).
pub const MAX_ENVELOPE_BYTES: usize = HEADER_LEN + MAX_PLAINTEXT_BYTES + TAG_LEN;
/// Bounded host-side replay memory (device keeps the authoritative check).
pub const REPLAY_WINDOW_CAP: usize = 32;

/// Typed envelope failure (no payload attached: never leaks secrets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Binding proof missing (wire `0x05`).
    NeedBinding,
    /// User-presence proof missing (wire `0x01`).
    NeedUp,
    /// PIN proof missing (wire `0x02`).
    NeedPin,
    /// Bad magic, bad version, or truncated bytes (wire `0x04`).
    InvalidEnvelope,
    /// Envelope shorter than `MIN_ENVELOPE_LEN` (wire `0x04`).
    TooShort,
    /// Ciphertext/envelope over the firmware ceiling (wire `0x04`).
    TooLarge,
    /// All-zero nonce (device TRNG never emits it; wire `0x04`).
    ZeroNonce,
    /// Nonce already observed in this window (wire `0x04`).
    Replay,
}

impl Display for EnvelopeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeedBinding => write!(f, "binding required"),
            Self::NeedUp => write!(f, "user presence required"),
            Self::NeedPin => write!(f, "pin required"),
            Self::InvalidEnvelope => write!(f, "invalid envelope"),
            Self::TooShort => write!(f, "envelope too short"),
            Self::TooLarge => write!(f, "envelope too large"),
            Self::ZeroNonce => write!(f, "zero nonce rejected"),
            Self::Replay => write!(f, "nonce replay rejected"),
        }
    }
}

impl core::error::Error for EnvelopeError {}

impl EnvelopeError {
    /// Preserved §9.5 wire status byte for this failure.
    pub const fn wire_status(self) -> u8 {
        match self {
            Self::NeedBinding => STATUS_NEED_BINDING,
            Self::NeedUp => STATUS_NEED_UP,
            Self::NeedPin => STATUS_NEED_PIN,
            Self::InvalidEnvelope
            | Self::TooShort
            | Self::TooLarge
            | Self::ZeroNonce
            | Self::Replay => STATUS_BAD_ENVELOPE,
        }
    }

    /// Fail-closed denial response carrying only the wire status.
    pub fn deny_response(self) -> SdkResponse {
        SdkResponse::new(self.wire_status(), Vec::new())
    }
}

/// Seal inputs: opaque `ct + tag` from the caller AEAD plus a fresh nonce.
///
/// `Debug` renders lengths only (never key/nonce/ciphertext bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct SealParams {
    /// Fresh 12 B nonce (non-zero, unseen in `replay`).
    pub nonce: [u8; NONCE_LEN],
    /// Opaque ciphertext (`ct + tag`, `TAG_LEN..=MAX_CIPHERTEXT_BYTES`).
    pub ciphertext: Vec<u8>,
}

impl SealParams {
    /// Build seal inputs (no checks; `seal_envelope` validates).
    pub fn new(nonce: [u8; NONCE_LEN], ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }
}

impl fmt::Debug for SealParams {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealParams")
            .field("nonce_len", &NONCE_LEN)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// Parsed envelope view: nonce plus opaque `ct + tag`.
///
/// `Debug` renders lengths only (never key/nonce/ciphertext bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct OpenedEnvelope {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl OpenedEnvelope {
    /// Envelope nonce (12 B, transmitted in the clear on the wire).
    pub const fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// Opaque ciphertext (`ct + tag`) for the caller AEAD to open.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for OpenedEnvelope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedEnvelope")
            .field("nonce_len", &NONCE_LEN)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// Bounded host-side replay memory (FIFO; device check stays authoritative).
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    seen: Vec<[u8; NONCE_LEN]>,
}

impl ReplayWindow {
    /// Empty window.
    pub fn new() -> Self {
        Self { seen: Vec::new() }
    }

    /// Number of nonces currently remembered.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// `true` when no nonce has been observed yet.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Record `nonce`: rejects zero and already-seen values.
    pub fn observe(&mut self, nonce: &[u8; NONCE_LEN]) -> Result<(), EnvelopeError> {
        if nonce == &[0u8; NONCE_LEN] {
            return Err(EnvelopeError::ZeroNonce);
        }
        for prev in self.seen.iter() {
            if nonce_eq(prev, nonce) {
                return Err(EnvelopeError::Replay);
            }
        }
        if self.seen.len() >= REPLAY_WINDOW_CAP {
            self.seen.remove(0);
        }
        self.seen.push(*nonce);
        Ok(())
    }
}

/// Constant-time 12 B compare (avoids a replay timing oracle).
fn nonce_eq(a: &[u8; NONCE_LEN], b: &[u8; NONCE_LEN]) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < NONCE_LEN {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

/// Fail-closed gate check in canonical order (`binding -> UP -> PIN`).
pub const fn check_envelope_auth(ctx: &AuthContext) -> Result<(), EnvelopeError> {
    if !ctx.binding_verified {
        return Err(EnvelopeError::NeedBinding);
    }
    if !ctx.presence_confirmed {
        return Err(EnvelopeError::NeedUp);
    }
    if !ctx.pin_verified {
        return Err(EnvelopeError::NeedPin);
    }
    Ok(())
}

/// Frame a caller-encrypted `ct + tag` into AEGN v1 wire bytes.
///
/// Checks gates first (stranger sees `NEED_BINDING` before format errors),
/// then ciphertext bounds, then nonce freshness, and records the nonce.
pub fn seal_envelope(
    ctx: &AuthContext,
    params: &SealParams,
    replay: &mut ReplayWindow,
) -> Result<Vec<u8>, EnvelopeError> {
    check_envelope_auth(ctx)?;
    if params.ciphertext.len() < TAG_LEN {
        return Err(EnvelopeError::InvalidEnvelope);
    }
    if params.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(EnvelopeError::TooLarge);
    }
    replay.observe(&params.nonce)?;
    let mut out = Vec::with_capacity(HEADER_LEN + params.ciphertext.len());
    out.extend_from_slice(&ENVELOPE_MAGIC);
    out.push(ENVELOPE_VERSION);
    out.extend_from_slice(&params.nonce);
    out.extend_from_slice(&params.ciphertext);
    Ok(out)
}

/// Validate AEGN v1 wire bytes and return the opaque view.
///
/// Checks gates first, then structure (`magic | ver | len`), then nonce
/// freshness, and records the nonce. AEAD opening stays with the caller.
pub fn open_envelope(
    ctx: &AuthContext,
    bytes: &[u8],
    replay: &mut ReplayWindow,
) -> Result<OpenedEnvelope, EnvelopeError> {
    check_envelope_auth(ctx)?;
    if bytes.len() < MIN_ENVELOPE_LEN {
        return Err(EnvelopeError::TooShort);
    }
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(EnvelopeError::TooLarge);
    }
    if bytes[0..4] != ENVELOPE_MAGIC || bytes[4] != ENVELOPE_VERSION {
        return Err(EnvelopeError::InvalidEnvelope);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[5..5 + NONCE_LEN]);
    replay.observe(&nonce)?;
    Ok(OpenedEnvelope {
        nonce,
        ciphertext: bytes[HEADER_LEN..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use crate::auth::AuthContext;
    use crate::envelope::{
        check_envelope_auth, open_envelope, seal_envelope, EnvelopeError, OpenedEnvelope,
        ReplayWindow, SealParams, ENVELOPE_MAGIC, ENVELOPE_VERSION, HEADER_LEN,
        MAX_CIPHERTEXT_BYTES, MAX_ENVELOPE_BYTES, MAX_PLAINTEXT_BYTES, MIN_ENVELOPE_LEN, NONCE_LEN,
        REPLAY_WINDOW_CAP, TAG_LEN,
    };
    use crate::status::{
        STATUS_BAD_ENVELOPE, STATUS_NEED_BINDING, STATUS_NEED_PIN, STATUS_NEED_UP,
    };
    use alloc::vec;
    use alloc::vec::Vec;

    const FULL: AuthContext = AuthContext::new(true, true, true);

    fn nonce(fill: u8) -> [u8; NONCE_LEN] {
        [fill; NONCE_LEN]
    }

    fn params(fill: u8, ct_len: usize) -> SealParams {
        SealParams::new(nonce(fill), vec![0xA5u8; ct_len])
    }

    #[test]
    fn constants_mirror_firmware_wire() {
        assert_eq!(ENVELOPE_MAGIC, [0x41, 0x45, 0x47, 0x4E]);
        assert_eq!(ENVELOPE_VERSION, 0x01);
        assert_eq!(HEADER_LEN, 17);
        assert_eq!(MIN_ENVELOPE_LEN, 33);
        assert_eq!(MAX_PLAINTEXT_BYTES, 4096);
        assert_eq!(MAX_CIPHERTEXT_BYTES, 4096 + 16);
        assert_eq!(MAX_ENVELOPE_BYTES, 17 + 4096 + 16);
        assert_eq!(REPLAY_WINDOW_CAP, 32);
    }

    #[test]
    fn reference_vector_layout() {
        let win = &mut ReplayWindow::new();
        let env = seal_envelope(&FULL, &params(0x11, TAG_LEN), win).unwrap();
        assert_eq!(env.len(), MIN_ENVELOPE_LEN);
        assert_eq!(&env[0..4], &ENVELOPE_MAGIC);
        assert_eq!(env[4], ENVELOPE_VERSION);
        assert_eq!(&env[5..17], &nonce(0x11));
        assert_eq!(&env[17..], &vec![0xA5u8; TAG_LEN]);
    }

    #[test]
    fn seal_open_round_trip() {
        let win = &mut ReplayWindow::new();
        let ct = vec![0xC3u8; 64];
        let env = seal_envelope(&FULL, &SealParams::new(nonce(0x07), ct.clone()), win).unwrap();
        // Fresh window for the peer side (device keeps its own check).
        let back = open_envelope(&FULL, &env, &mut ReplayWindow::new()).unwrap();
        assert_eq!(back.nonce(), &nonce(0x07));
        assert_eq!(back.ciphertext(), ct.as_slice());
    }

    #[test]
    fn gate_order_binding_first() {
        let cases = [
            (AuthContext::anonymous(), EnvelopeError::NeedBinding),
            (AuthContext::new(true, false, false), EnvelopeError::NeedUp),
            (AuthContext::new(true, true, false), EnvelopeError::NeedPin),
            (
                AuthContext::new(false, true, true),
                EnvelopeError::NeedBinding,
            ),
        ];
        for (ctx, want) in cases {
            assert_eq!(check_envelope_auth(&ctx), Err(want));
            assert_eq!(
                seal_envelope(&ctx, &params(0x02, TAG_LEN), &mut ReplayWindow::new()),
                Err(want)
            );
            assert_eq!(
                open_envelope(&ctx, &[0u8; MIN_ENVELOPE_LEN], &mut ReplayWindow::new()),
                Err(want)
            );
        }
        assert_eq!(check_envelope_auth(&FULL), Ok(()));
    }

    #[test]
    fn wire_statuses_preserved() {
        assert_eq!(
            EnvelopeError::NeedBinding.wire_status(),
            STATUS_NEED_BINDING
        );
        assert_eq!(EnvelopeError::NeedUp.wire_status(), STATUS_NEED_UP);
        assert_eq!(EnvelopeError::NeedPin.wire_status(), STATUS_NEED_PIN);
        for e in [
            EnvelopeError::InvalidEnvelope,
            EnvelopeError::TooShort,
            EnvelopeError::TooLarge,
            EnvelopeError::ZeroNonce,
            EnvelopeError::Replay,
        ] {
            assert_eq!(e.wire_status(), STATUS_BAD_ENVELOPE);
            let deny = e.deny_response();
            assert_eq!(deny.status, STATUS_BAD_ENVELOPE);
            assert!(deny.payload.is_empty());
        }
        let deny = EnvelopeError::NeedBinding.deny_response();
        assert_eq!(deny.status, 0x05);
    }

    #[test]
    fn truncated_and_corrupt_inputs_rejected() {
        let mut win = ReplayWindow::new();
        // Empty and short.
        assert_eq!(
            open_envelope(&FULL, &[], &mut win),
            Err(EnvelopeError::TooShort)
        );
        assert_eq!(
            open_envelope(&FULL, &[0x41u8; MIN_ENVELOPE_LEN - 1], &mut win),
            Err(EnvelopeError::TooShort)
        );
        // Bad magic / bad version with valid length.
        let mut bad = vec![0x00u8; MIN_ENVELOPE_LEN];
        assert_eq!(
            open_envelope(&FULL, &bad, &mut win),
            Err(EnvelopeError::InvalidEnvelope)
        );
        bad[0..4].copy_from_slice(&ENVELOPE_MAGIC);
        bad[4] = 0x02;
        assert_eq!(
            open_envelope(&FULL, &bad, &mut win),
            Err(EnvelopeError::InvalidEnvelope)
        );
        // Ciphertext below tag floor on seal.
        assert_eq!(
            seal_envelope(&FULL, &params(0x03, TAG_LEN - 1), &mut win),
            Err(EnvelopeError::InvalidEnvelope)
        );
    }

    #[test]
    fn size_ceilings_fail_closed() {
        let mut win = ReplayWindow::new();
        assert_eq!(
            seal_envelope(&FULL, &params(0x04, MAX_CIPHERTEXT_BYTES + 1), &mut win),
            Err(EnvelopeError::TooLarge)
        );
        assert_eq!(
            open_envelope(&FULL, &vec![0x41u8; MAX_ENVELOPE_BYTES + 1], &mut win),
            Err(EnvelopeError::TooLarge)
        );
        // Ceiling itself still frames.
        let top = seal_envelope(&FULL, &params(0x05, MAX_CIPHERTEXT_BYTES), &mut win).unwrap();
        assert_eq!(top.len(), MAX_ENVELOPE_BYTES);
    }

    #[test]
    fn zero_nonce_rejected_both_directions() {
        let mut win = ReplayWindow::new();
        assert_eq!(
            seal_envelope(&FULL, &params(0x00, TAG_LEN), &mut win),
            Err(EnvelopeError::ZeroNonce)
        );
        let mut env = Vec::with_capacity(MIN_ENVELOPE_LEN);
        env.extend_from_slice(&ENVELOPE_MAGIC);
        env.push(ENVELOPE_VERSION);
        env.extend_from_slice(&[0u8; NONCE_LEN]);
        env.extend_from_slice(&[0xA5u8; TAG_LEN]);
        assert_eq!(
            open_envelope(&FULL, &env, &mut win),
            Err(EnvelopeError::ZeroNonce)
        );
    }

    #[test]
    fn replay_rejected_with_constant_time_compare() {
        let mut win = ReplayWindow::new();
        seal_envelope(&FULL, &params(0x09, TAG_LEN), &mut win).unwrap();
        assert_eq!(
            seal_envelope(&FULL, &params(0x09, TAG_LEN), &mut win),
            Err(EnvelopeError::Replay)
        );
        // Near-miss nonce (single-bit flip) is a distinct value.
        let mut near = nonce(0x09);
        near[0] ^= 0x01;
        seal_envelope(
            &FULL,
            &SealParams::new(near, vec![0xA5u8; TAG_LEN]),
            &mut win,
        )
        .unwrap();
        assert_eq!(win.len(), 2);
    }

    #[test]
    fn window_evicts_oldest_and_stays_bounded() {
        let mut win = ReplayWindow::new();
        for i in 1..=REPLAY_WINDOW_CAP as u8 + 1 {
            seal_envelope(&FULL, &params(i, TAG_LEN), &mut win).unwrap();
        }
        assert_eq!(win.len(), REPLAY_WINDOW_CAP);
        // Evicted nonce is forgotten (documented bound; device check stays
        // authoritative for anything older than the window).
        seal_envelope(&FULL, &params(1, TAG_LEN), &mut win).unwrap();
        assert_eq!(win.len(), REPLAY_WINDOW_CAP);
    }

    #[test]
    fn debug_never_renders_secret_bytes() {
        let secret_ct = vec![
            0xDEu8, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C,
        ];
        let p = SealParams::new(nonce(0xDE), secret_ct);
        let rendered = alloc::format!("{p:?}");
        assert!(rendered.contains("ciphertext_len"));
        assert!(!rendered.contains("222"));
        assert!(!rendered.contains("173"));
        let back: OpenedEnvelope = open_envelope(
            &FULL,
            &seal_envelope(&FULL, &params(0x0D, TAG_LEN), &mut ReplayWindow::new()).unwrap(),
            &mut ReplayWindow::new(),
        )
        .unwrap();
        let shown = alloc::format!("{back:?}");
        assert!(shown.contains("ciphertext_len"));
        assert!(!shown.contains("165"));
    }

    #[test]
    fn error_display_carries_no_payload() {
        for e in [
            EnvelopeError::NeedBinding,
            EnvelopeError::NeedUp,
            EnvelopeError::NeedPin,
            EnvelopeError::InvalidEnvelope,
            EnvelopeError::TooShort,
            EnvelopeError::TooLarge,
            EnvelopeError::ZeroNonce,
            EnvelopeError::Replay,
        ] {
            let text = alloc::format!("{e}");
            assert!(!text.is_empty());
            assert!(!text.contains("AEGN"));
        }
    }

    /// Cross-vector: byte-exact framing shared with the UniFFI bridge and
    /// the firmware `persistence` ceiling (R15/R16, section 9).
    ///
    /// Mirrors `envelope_cross_vector_matches_sdk_framing` in
    /// `crates/uniffi-bridge/src/lib.rs`: same fixed nonce
    /// (`01..0C`), same opaque `ct + tag` (`0xA5 x 16`, the tag floor),
    /// same expected wire bytes. Any framing drift on either side breaks
    /// both tests. AEAD bytes stay opaque here by design (no crypto dep).
    #[test]
    fn aegn_cross_vector_matches_bridge_and_firmware() {
        // Canonical ceilings (firmware `persistence.rs` is the source).
        assert_eq!(MAX_PLAINTEXT_BYTES, 4096);
        assert_eq!(MAX_ENVELOPE_BYTES, 4129);
        assert_eq!(MIN_ENVELOPE_LEN, 33);
        assert_eq!(HEADER_LEN, 17);
        let nonce_bytes: [u8; NONCE_LEN] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let ct = vec![0xA5u8; TAG_LEN];
        let env = seal_envelope(
            &FULL,
            &SealParams::new(nonce_bytes, ct.clone()),
            &mut ReplayWindow::new(),
        )
        .unwrap();
        let mut expected = Vec::with_capacity(MIN_ENVELOPE_LEN);
        expected.extend_from_slice(&ENVELOPE_MAGIC);
        expected.push(ENVELOPE_VERSION);
        expected.extend_from_slice(&nonce_bytes);
        expected.extend_from_slice(&ct);
        assert_eq!(env, expected);
        assert_eq!(env.len(), MIN_ENVELOPE_LEN);
        // Bridge-equivalent header parse: magic | ver | ct_len = len - 17.
        assert_eq!(&env[0..4], &ENVELOPE_MAGIC);
        assert_eq!(env[4], ENVELOPE_VERSION);
        assert_eq!(&env[5..17], &nonce_bytes);
        assert_eq!(env.len() - HEADER_LEN, ct.len());
        let back = open_envelope(&FULL, &env, &mut ReplayWindow::new()).unwrap();
        assert_eq!(back.nonce(), &nonce_bytes);
        assert_eq!(back.ciphertext(), ct.as_slice());
    }
}
