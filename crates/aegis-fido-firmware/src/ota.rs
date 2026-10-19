//! Wave OTA core — staged verify-before-swap firmware update.
//!
//! BEHAVIOR: state machine `Idle → Staged → Verified → Applying → Committed`,
//! with `rollback()` returning the machine to `Idle` (rolled back). `begin()`
//! parses a fixed 104-byte manifest and rejects unprovisioned devices,
//! malformed manifests, zero versions, and images over the 2 MiB budget.
//! `stage_chunk(offset, data, sink)` accepts only in-order, non-empty,
//! in-budget chunks, feeding a running `Sha256` digest while streaming bytes
//! to an [`OtaSink`] — no whole-image RAM (required: a firmware image can
//! never fit a single 512 B `MAX_PLAINTEXT_BYTES` envelope, so verification
//! MUST stream). `verify()` checks the release signature fail-closed (Wave-1
//! stub denies; Step 4 wires `ed25519-dalek`), then digest equality, then
//! `version > current`. `commit()` (gated on user presence at the Step-4
//! wiring via [`OtaState::requires_up`]) finalizes the sink and lands in
//! `Committed` with `committed_version` updated; `rollback()` from any phase
//! discards staged state and returns to `Idle`, preserving `committed_version`.
//!
//! `no_std` compatible: `alloc` only (cf. `identity.rs`); no panics, no
//! `unwrap`/`expect` outside `#[cfg(test)]`; typed [`OtaError`] + `Display`
//! like `ProvisionError`/`ConfigError`.

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// Vendor opcode: start a staged OTA session (`manifest(104B)`).
pub const OP_OTA_BEGIN: u8 = 0x30;
/// Vendor opcode: stream one image chunk (`offset BE u32 || data`).
pub const OP_OTA_CHUNK: u8 = 0x31;
/// Vendor opcode: verify staged image (sig + digest + version).
pub const OP_OTA_FINISH: u8 = 0x32;
/// Vendor opcode: swap to the verified image (requires UP).
pub const OP_OTA_COMMIT: u8 = 0x33;
/// Vendor opcode: discard staged state, back to `Idle`.
pub const OP_OTA_ABORT: u8 = 0x34;

/// Budget: largest stageable firmware image, in bytes (2 MiB).
///
/// Rationale: the running-digest design needs no whole-image RAM, but the
/// second OTA partition + NVS/persistence must still fit beside the running
/// app on 4 MB+ flash. `begin()` rejects `size > MAX_OTA_IMAGE_BYTES` with
/// [`OtaError::Overflow`] before any byte is staged.
pub const MAX_OTA_IMAGE_BYTES: usize = 2 * 1024 * 1024;

/// Wire length of [`OtaManifest`]: `version(4) || size(4) || sha256(32) || signature(64)`.
pub const OTA_MANIFEST_LEN: usize = 104;

/// OTA failure (typed, no panics in prod path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtaError {
    /// Manifest is not exactly [`OTA_MANIFEST_LEN`] bytes, or size is zero.
    BadManifest,
    /// Release signature did not verify (fail-closed stub until Step 4).
    BadSignature,
    /// Staged bytes digest differs from manifest `sha256` (or short image).
    ShaMismatch,
    /// Manifest version is zero, equal, or older than current.
    Downgrade,
    /// Image exceeds [`MAX_OTA_IMAGE_BYTES`]/manifest size, or sink unwritable.
    Overflow,
    /// Chunk offset != bytes received so far, or empty chunk (no progress).
    OutOfOrder,
    /// Device never ran factory provisioning (cf. `ProvisionError`).
    Unprovisioned,
    /// Operation illegal in the current phase (e.g. chunk before `begin`).
    NotStaged,
}

impl core::fmt::Display for OtaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadManifest => write!(f, "malformed ota manifest"),
            Self::BadSignature => write!(f, "ota release signature invalid"),
            Self::ShaMismatch => write!(f, "ota image digest mismatch"),
            Self::Downgrade => write!(f, "ota version not newer than current"),
            Self::Overflow => write!(f, "ota image exceeds budget"),
            Self::OutOfOrder => write!(f, "ota chunk out of order"),
            Self::Unprovisioned => write!(f, "device unprovisioned (factory required)"),
            Self::NotStaged => write!(f, "ota session not in staged phase"),
        }
    }
}

/// Release manifest for one firmware image.
///
/// `version` is a monotonically increasing `u32` (pack semver or build
/// number — only ordering matters; `0` is never valid). `signature` is the
/// offline release Ed25519 signature over [`OtaManifest::signed_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtaManifest {
    /// Monotonically increasing firmware version (`0` invalid).
    pub version: u32,
    /// Exact image length in bytes (`1..=MAX_OTA_IMAGE_BYTES`).
    pub size: u32,
    /// Expected `Sha256` over the full image.
    pub sha256: [u8; 32],
    /// Release signature over [`OtaManifest::signed_bytes`].
    pub signature: [u8; 64],
}

impl OtaManifest {
    /// Parses the fixed 104-byte big-endian wire layout.
    ///
    /// Returns [`OtaError::BadManifest`] on any length mismatch or zero size.
    pub fn parse(raw: &[u8]) -> Result<Self, OtaError> {
        if raw.len() != OTA_MANIFEST_LEN {
            return Err(OtaError::BadManifest);
        }
        let mut version = [0u8; 4];
        let mut size = [0u8; 4];
        let mut sha256 = [0u8; 32];
        let mut signature = [0u8; 64];
        version.copy_from_slice(&raw[..4]);
        size.copy_from_slice(&raw[4..8]);
        sha256.copy_from_slice(&raw[8..40]);
        signature.copy_from_slice(&raw[40..104]);
        let size = u32::from_be_bytes(size);
        if size == 0 {
            return Err(OtaError::BadManifest);
        }
        Ok(Self {
            version: u32::from_be_bytes(version),
            size,
            sha256,
            signature,
        })
    }

    /// Canonical signed bytes: `version BE || size BE || sha256` (40 B).
    pub fn signed_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..4].copy_from_slice(&self.version.to_be_bytes());
        out[4..8].copy_from_slice(&self.size.to_be_bytes());
        out[8..].copy_from_slice(&self.sha256);
        out
    }
}

/// Quiescent-to-terminal phases of [`OtaState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtaPhase {
    /// Ready for [`OtaState::begin`].
    Idle,
    /// Manifest accepted; chunks streaming.
    Staged,
    /// Signature + digest + version accepted; ready to swap.
    Verified,
    /// Transient inside [`OtaState::commit`] while the sink finalizes.
    Applying,
    /// Swap done; terminal until reboot (Step 4 reboots on commit).
    Committed,
}

/// Staged verify-before-swap OTA state machine.
///
/// Construct with the running firmware version
/// ([`OtaState::new`]); Step 4 feeds NVS + eFuse provisioning here.
#[derive(Debug, Clone)]
pub struct OtaState {
    phase: OtaPhase,
    manifest: Option<OtaManifest>,
    received: usize,
    digest: Sha256,
    committed_version: u32,
}

impl OtaState {
    /// Creates an idle machine with the given running firmware version.
    pub fn new(committed_version: u32) -> Self {
        Self {
            phase: OtaPhase::Idle,
            manifest: None,
            received: 0,
            digest: Sha256::new(),
            committed_version,
        }
    }

    /// Current phase.
    pub fn phase(&self) -> OtaPhase {
        self.phase
    }

    /// Running firmware version (updated only by [`OtaState::commit`]).
    pub fn committed_version(&self) -> u32 {
        self.committed_version
    }

    /// Bytes staged so far in this session.
    pub fn received(&self) -> usize {
        self.received
    }

    /// Whether [`OtaState::commit`] requires a physical user-presence check.
    ///
    /// Always `true`: enforced at the Step-4 wiring (transport + BOOT button),
    /// never inside this core.
    pub const fn requires_up() -> bool {
        true
    }

    /// Opens a session: provisioned + idle + well-formed in-budget manifest.
    pub fn begin(&mut self, raw_manifest: &[u8], provisioned: bool) -> Result<(), OtaError> {
        if !provisioned {
            return Err(OtaError::Unprovisioned);
        }
        if self.phase != OtaPhase::Idle {
            return Err(OtaError::NotStaged);
        }
        let manifest = OtaManifest::parse(raw_manifest)?;
        if manifest.version == 0 {
            return Err(OtaError::Downgrade);
        }
        if manifest.size as usize > MAX_OTA_IMAGE_BYTES {
            return Err(OtaError::Overflow);
        }
        self.manifest = Some(manifest);
        self.received = 0;
        self.digest = Sha256::new();
        self.phase = OtaPhase::Staged;
        Ok(())
    }

    /// Streams one chunk: staged + in-order + non-empty + in-budget.
    ///
    /// Returns total bytes received so far.
    pub fn stage_chunk<S: OtaSink>(
        &mut self,
        offset: usize,
        data: &[u8],
        sink: &mut S,
    ) -> Result<usize, OtaError> {
        let manifest = self.manifest.as_ref().ok_or(OtaError::NotStaged)?;
        if self.phase != OtaPhase::Staged {
            return Err(OtaError::NotStaged);
        }
        if data.is_empty() || offset != self.received {
            return Err(OtaError::OutOfOrder);
        }
        let end = self
            .received
            .checked_add(data.len())
            .ok_or(OtaError::Overflow)?;
        if end > manifest.size as usize {
            return Err(OtaError::Overflow);
        }
        sink.write_chunk(offset, data)?;
        self.digest.update(data);
        self.received = end;
        Ok(self.received)
    }

    /// Full verification with the offline release pubkey: sig, then digest,
    /// then `version > current`.
    pub fn verify(&mut self, ota_pubkey: &[u8; 32], current_version: u32) -> Result<(), OtaError> {
        let manifest = self.manifest.as_ref().ok_or(OtaError::NotStaged)?;
        let sig_valid = verify_signature(
            ota_pubkey,
            &manifest.signed_bytes(),
            &manifest.signature,
        );
        self.verify_with(current_version, sig_valid)
    }

    /// Verification with an injected signature verdict (host-test seam).
    ///
    /// Prod [`OtaState::verify`] calls this with the result of
    /// `verify_signature`; tests pass explicit verdicts to drive every branch
    /// without the `ed25519-dalek` dep (see [`OtaState::verify`] docs).
    pub fn verify_with(&mut self, current_version: u32, sig_valid: bool) -> Result<(), OtaError> {
        let manifest = self.manifest.as_ref().ok_or(OtaError::NotStaged)?;
        if self.phase != OtaPhase::Staged {
            return Err(OtaError::NotStaged);
        }
        if !sig_valid {
            return Err(OtaError::BadSignature);
        }
        if self.received != manifest.size as usize {
            return Err(OtaError::ShaMismatch);
        }
        let sum = self.digest.clone().finalize();
        if sum[..] != manifest.sha256[..] {
            return Err(OtaError::ShaMismatch);
        }
        if manifest.version == 0 || manifest.version <= current_version {
            return Err(OtaError::Downgrade);
        }
        self.phase = OtaPhase::Verified;
        Ok(())
    }

    /// Swaps to the verified image: sink finalize, then `Committed`.
    pub fn commit<S: OtaSink>(&mut self, sink: &mut S) -> Result<u32, OtaError> {
        let manifest = self.manifest.as_ref().ok_or(OtaError::NotStaged)?;
        if self.phase != OtaPhase::Verified {
            return Err(OtaError::NotStaged);
        }
        self.phase = OtaPhase::Applying;
        if let Err(e) = sink.finalize() {
            self.phase = OtaPhase::Verified;
            return Err(e);
        }
        self.committed_version = manifest.version;
        self.phase = OtaPhase::Committed;
        Ok(manifest.version)
    }

    /// Discards staged state and returns to `Idle`, preserving
    /// `committed_version`. Idempotent; also valid from `Committed`
    /// pre-reboot (keeps the committed version).
    pub fn rollback(&mut self) {
        self.manifest = None;
        self.received = 0;
        self.digest = Sha256::new();
        self.phase = OtaPhase::Idle;
    }
}

/// Backing store for staged image bytes.
///
/// Step 4 provides the flash/partition sink; [`RamOtaSink`] covers host/tests.
/// Medium faults map to [`OtaError::Overflow`] (budget-exceeded-or-unwritable).
pub trait OtaSink {
    /// Persists `data` at absolute image `offset`.
    fn write_chunk(&mut self, offset: usize, data: &[u8]) -> Result<(), OtaError>;
    /// Seals the staged image (called once by [`OtaState::commit`]).
    fn finalize(&mut self) -> Result<(), OtaError>;
}

/// RAM-backed [`OtaSink`] for host/tests (Step-4 flash sink replaces it
/// on-device). Enforces in-order appends and the image budget itself.
#[derive(Debug, Default)]
pub struct RamOtaSink {
    /// Staged bytes.
    pub buf: Vec<u8>,
    /// Times [`OtaSink::finalize`] ran.
    pub finalize_calls: u32,
}

impl OtaSink for RamOtaSink {
    fn write_chunk(&mut self, offset: usize, data: &[u8]) -> Result<(), OtaError> {
        if offset != self.buf.len() {
            return Err(OtaError::OutOfOrder);
        }
        if self.buf.len() + data.len() > MAX_OTA_IMAGE_BYTES {
            return Err(OtaError::Overflow);
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), OtaError> {
        self.finalize_calls += 1;
        Ok(())
    }
}

/// Fail-closed release-signature gate (Wave 1 stub).
///
/// The release `signature` over [`OtaManifest::signed_bytes`] MUST verify with
/// the offline release pubkey before `Verified`. `ed25519-dalek` lives in the
/// workspace but is not yet a firmware-target dep, so — per the Wave-1 plan —
/// this stays a documented stub returning `false`: prod `verify()` always
/// yields [`OtaError::BadSignature`] and no image can reach `Verified`
/// on-device. Step-4 wiring adds `ed25519-dalek = { workspace = true }` to
/// the firmware `Cargo.toml` and swaps this body for
/// `VerifyingKey::from_bytes(pubkey)?.verify_strict(msg, &sig).is_ok()`
/// (no `cfg(feature)` gate: avoids `unexpected_cfgs` warnings without a
/// `Cargo.toml` change, which is out of scope for Wave 1).
/// Host tests drive the accept path via [`OtaState::verify_with`].
fn verify_signature(_pubkey: &[u8; 32], _message: &[u8], _signature: &[u8; 64]) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT: u32 = 7;
    const NEXT: u32 = 8;

    fn image_bytes() -> Vec<u8> {
        alloc::vec![0xA5u8; 1024]
    }

    fn manifest_for(version: u32, image: &[u8]) -> Vec<u8> {
        let digest = Sha256::digest(image);
        let mut raw = Vec::with_capacity(OTA_MANIFEST_LEN);
        raw.extend_from_slice(&version.to_be_bytes());
        raw.extend_from_slice(&(image.len() as u32).to_be_bytes());
        raw.extend_from_slice(&digest);
        raw.extend_from_slice(&[0x5Eu8; 64]);
        raw
    }

    fn staged(version: u32, image: &[u8]) -> (OtaState, RamOtaSink) {
        let mut ota = OtaState::new(CURRENT);
        let mut sink = RamOtaSink::default();
        ota.begin(&manifest_for(version, image), true).expect("begin");
        let mut off = 0;
        for chunk in image.chunks(256) {
            off = ota.stage_chunk(off, chunk, &mut sink).expect("chunk");
        }
        assert_eq!(off, image.len());
        (ota, sink)
    }

    #[test]
    fn manifest_parse_ok() {
        let image = image_bytes();
        let raw = manifest_for(NEXT, &image);
        let m = OtaManifest::parse(&raw).expect("parse");
        assert_eq!(m.version, NEXT);
        assert_eq!(m.size, image.len() as u32);
        assert_eq!(&m.sha256[..], &Sha256::digest(&image)[..]);
        assert_eq!(m.signature, [0x5Eu8; 64]);
        let mut signed = [0u8; 40];
        signed[..4].copy_from_slice(&NEXT.to_be_bytes());
        signed[4..8].copy_from_slice(&(image.len() as u32).to_be_bytes());
        signed[8..].copy_from_slice(&Sha256::digest(&image));
        assert_eq!(m.signed_bytes(), signed);
    }

    #[test]
    fn manifest_parse_garbage() {
        assert_eq!(OtaManifest::parse(&[]), Err(OtaError::BadManifest));
        assert_eq!(OtaManifest::parse(&[0u8; 10]), Err(OtaError::BadManifest));
        assert_eq!(
            OtaManifest::parse(&[0u8; OTA_MANIFEST_LEN + 1]),
            Err(OtaError::BadManifest)
        );
        let mut zero_size = manifest_for(NEXT, &image_bytes());
        zero_size[4..8].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(OtaManifest::parse(&zero_size), Err(OtaError::BadManifest));
    }

    #[test]
    fn begin_rejects_unprovisioned() {
        let mut ota = OtaState::new(CURRENT);
        let raw = manifest_for(NEXT, &image_bytes());
        assert_eq!(ota.begin(&raw, false), Err(OtaError::Unprovisioned));
        assert_eq!(ota.phase(), OtaPhase::Idle);
    }

    #[test]
    fn begin_rejects_oversize_manifest() {
        let mut ota = OtaState::new(CURRENT);
        let mut raw = manifest_for(NEXT, &image_bytes());
        let huge = (MAX_OTA_IMAGE_BYTES as u32) + 1;
        raw[4..8].copy_from_slice(&huge.to_be_bytes());
        assert_eq!(ota.begin(&raw, true), Err(OtaError::Overflow));
        assert_eq!(ota.phase(), OtaPhase::Idle);
    }

    #[test]
    fn begin_rejects_zero_version() {
        let mut ota = OtaState::new(0);
        let raw = manifest_for(0, &image_bytes());
        assert_eq!(ota.begin(&raw, true), Err(OtaError::Downgrade));
        assert_eq!(ota.phase(), OtaPhase::Idle);
    }

    #[test]
    fn begin_twice_needs_rollback_first() {
        let image = image_bytes();
        let (mut ota, _sink) = staged(NEXT, &image);
        let raw = manifest_for(NEXT + 1, &image);
        assert_eq!(ota.begin(&raw, true), Err(OtaError::NotStaged));
    }

    #[test]
    fn stage_chunk_rejects_overflow() {
        let image = image_bytes();
        let tiny = &image[..4];
        let mut ota = OtaState::new(CURRENT);
        let mut sink = RamOtaSink::default();
        ota.begin(&manifest_for(NEXT, tiny), true).expect("begin");
        assert_eq!(
            ota.stage_chunk(0, &image, &mut sink),
            Err(OtaError::Overflow)
        );
        assert_eq!(ota.received(), 0);
    }

    #[test]
    fn stage_chunk_rejects_out_of_order() {
        let image = image_bytes();
        let mut ota = OtaState::new(CURRENT);
        let mut sink = RamOtaSink::default();
        ota.begin(&manifest_for(NEXT, &image), true).expect("begin");
        assert_eq!(
            ota.stage_chunk(1, &image[..16], &mut sink),
            Err(OtaError::OutOfOrder)
        );
        assert_eq!(
            ota.stage_chunk(16, &image[..16], &mut sink),
            Err(OtaError::OutOfOrder)
        );
        assert_eq!(ota.received(), 0);
    }

    #[test]
    fn stage_chunk_rejects_empty() {
        let image = image_bytes();
        let mut ota = OtaState::new(CURRENT);
        let mut sink = RamOtaSink::default();
        ota.begin(&manifest_for(NEXT, &image), true).expect("begin");
        assert_eq!(ota.stage_chunk(0, &[], &mut sink), Err(OtaError::OutOfOrder));
    }

    #[test]
    fn stage_chunk_before_begin_is_not_staged() {
        let mut ota = OtaState::new(CURRENT);
        let mut sink = RamOtaSink::default();
        assert_eq!(
            ota.stage_chunk(0, &[0x01], &mut sink),
            Err(OtaError::NotStaged)
        );
    }

    #[test]
    fn verify_rejects_bad_sig() {
        let image = image_bytes();
        let (mut ota, _sink) = staged(NEXT, &image);
        // Wave-1 fail-closed stub denies every signature on prod path.
        assert_eq!(ota.verify(&[0x11u8; 32], CURRENT), Err(OtaError::BadSignature));
        assert_eq!(ota.phase(), OtaPhase::Staged);
    }

    #[test]
    fn verify_rejects_sha_mismatch() {
        let image = image_bytes();
        // Stage the manifest of `image` but feed one flipped byte.
        let mut bad = image.clone();
        bad[512] ^= 0xFF;
        let mut ota = OtaState::new(CURRENT);
        let mut sink = RamOtaSink::default();
        ota.begin(&manifest_for(NEXT, &image), true).expect("begin");
        ota.stage_chunk(0, &bad[..512], &mut sink).expect("c1");
        ota.stage_chunk(512, &bad[512..], &mut sink).expect("c2");
        assert_eq!(ota.verify_with(CURRENT, true), Err(OtaError::ShaMismatch));
        assert_eq!(ota.phase(), OtaPhase::Staged);
    }

    #[test]
    fn verify_rejects_downgrade_and_equal() {
        let image = image_bytes();
        let (mut ota, _sink) = staged(CURRENT, &image);
        assert_eq!(ota.verify_with(CURRENT, true), Err(OtaError::Downgrade));
        let (mut ota2, _s2) = staged(CURRENT - 1, &image);
        assert_eq!(ota2.verify_with(CURRENT, true), Err(OtaError::Downgrade));
        assert_eq!(ota2.phase(), OtaPhase::Staged);
    }

    #[test]
    fn verify_rejects_zero_version() {
        let image = image_bytes();
        // Version 0 is rejected at begin outright, even against current 0.
        let mut ota = OtaState::new(1);
        assert_eq!(
            ota.begin(&manifest_for(0, &image), true),
            Err(OtaError::Downgrade)
        );
        assert_eq!(ota.phase(), OtaPhase::Idle);
    }

    #[test]
    fn commit_requires_verified() {
        let image = image_bytes();
        let (mut ota, _sink) = staged(NEXT, &image);
        let mut sink2 = RamOtaSink::default();
        assert_eq!(ota.commit(&mut sink2), Err(OtaError::NotStaged));
        let mut fresh = OtaState::new(CURRENT);
        let mut sink3 = RamOtaSink::default();
        assert_eq!(fresh.commit(&mut sink3), Err(OtaError::NotStaged));
    }

    #[test]
    fn rollback_resets_to_idle_preserving_committed() {
        let image = image_bytes();
        let (mut ota, _sink) = staged(NEXT, &image);
        ota.rollback();
        assert_eq!(ota.phase(), OtaPhase::Idle);
        assert_eq!(ota.committed_version(), CURRENT);
        assert_eq!(ota.received(), 0);
        // Machine is usable again immediately.
        ota.begin(&manifest_for(NEXT, &image), true).expect("re-begin");
        assert_eq!(ota.phase(), OtaPhase::Staged);
    }

    #[test]
    fn rollback_after_verify_returns_to_idle() {
        let image = image_bytes();
        let (mut ota, _sink) = staged(NEXT, &image);
        ota.verify_with(CURRENT, true).expect("verify");
        assert_eq!(ota.phase(), OtaPhase::Verified);
        ota.rollback();
        assert_eq!(ota.phase(), OtaPhase::Idle);
        assert_eq!(ota.committed_version(), CURRENT);
    }

    #[test]
    fn happy_path_idle_to_committed() {
        assert!(OtaState::requires_up());
        let image = image_bytes();
        let (mut ota, mut sink) = staged(NEXT, &image);
        ota.verify_with(CURRENT, true).expect("verify");
        assert_eq!(ota.phase(), OtaPhase::Verified);
        let version = ota.commit(&mut sink).expect("commit");
        assert_eq!(version, NEXT);
        assert_eq!(ota.phase(), OtaPhase::Committed);
        assert_eq!(ota.committed_version(), NEXT);
        assert_eq!(sink.buf, image);
        assert_eq!(sink.finalize_calls, 1);
    }

    #[test]
    fn opcodes_live_in_vendor_ota_range() {
        assert_eq!(OP_OTA_BEGIN, 0x30);
        assert_eq!(OP_OTA_CHUNK, 0x31);
        assert_eq!(OP_OTA_FINISH, 0x32);
        assert_eq!(OP_OTA_COMMIT, 0x33);
        assert_eq!(OP_OTA_ABORT, 0x34);
    }
}
