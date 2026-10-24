//! T6 — `OtaKeyProvider` observable contracts (offline, frozen vectors).
//!
//! Covers what T6 finalized: lab key exists only in `test-mode` builds,
//! release is zeros fail-closed, `for_build` selects the key with no `cfg`
//! in the dispatcher (`main.rs`), and `OtaState::verify` denies
//! fail-closed (Ed25519 `BadSignature`, phase stays `Staged`).
//!
//! Host-only: frozen manifest/image vectors + `RamOtaSink`. No hardware,
//! no flash, no COM port, no network.

use aegis_fido_firmware::ota::{
    OtaError, OtaKeyProvider, OtaManifest, OtaPhase, OtaState, RamOtaSink, MAX_OTA_IMAGE_BYTES,
    OP_OTA_ABORT, OP_OTA_BEGIN, OP_OTA_CHUNK, OP_OTA_COMMIT, OP_OTA_FINISH,
};
use sha2::{Digest, Sha256};

// Frozen vectors (offline, deterministic).
const CURRENT_VERSION: u32 = 7;
const NEXT_VERSION: u32 = 8;
const FOREIGN_PUBKEY: [u8; 32] = [0x11u8; 32];

fn image_bytes() -> Vec<u8> {
    vec![0xA5u8; 1024]
}

fn manifest_raw(version: u32, image: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(image);
    let mut raw = Vec::with_capacity(104);
    raw.extend_from_slice(&version.to_be_bytes());
    raw.extend_from_slice(&(image.len() as u32).to_be_bytes());
    raw.extend_from_slice(&digest);
    raw.extend_from_slice(&[0x5Eu8; 64]);
    raw
}

fn staged_next() -> (OtaState, RamOtaSink) {
    let image = image_bytes();
    let mut ota = OtaState::new(CURRENT_VERSION);
    let mut sink = RamOtaSink::default();
    ota.begin(&manifest_raw(NEXT_VERSION, &image), true)
        .expect("begin");
    let mut off = 0;
    for chunk in image.chunks(256) {
        off = ota.stage_chunk(off, chunk, &mut sink).expect("chunk");
    }
    assert_eq!(off, image.len());
    (ota, sink)
}

// ---------------------------------------------------------------------------
// Feature presets: release zeros fail-closed, lab only under test-mode
// ---------------------------------------------------------------------------

#[test]
fn release_provider_is_zeros_fail_closed() {
    let p = OtaKeyProvider::release();
    assert_eq!(p.active_pubkey(), [0u8; 32]);
    assert_eq!(p.active_pubkey(), OtaKeyProvider::RELEASE_PUBKEY);
    assert!(OtaKeyProvider::is_denied(&p.active_pubkey()));
    assert!(OtaKeyProvider::is_denied(&OtaKeyProvider::RELEASE_PUBKEY));
    assert!(!OtaKeyProvider::is_denied(&FOREIGN_PUBKEY));
}

#[cfg(not(feature = "test-mode"))]
#[test]
fn for_build_is_zeros_without_test_mode() {
    assert_eq!(OtaKeyProvider::active_pubkey_for_build(), [0u8; 32]);
    assert_eq!(
        OtaKeyProvider::active_pubkey_for_build(),
        OtaKeyProvider::RELEASE_PUBKEY
    );
    assert!(OtaKeyProvider::is_denied(
        &OtaKeyProvider::active_pubkey_for_build()
    ));
}

#[cfg(feature = "test-mode")]
#[test]
fn lab_provider_only_with_test_mode() {
    let lab = OtaKeyProvider::lab();
    assert_eq!(lab.active_pubkey(), OtaKeyProvider::LAB_PUBKEY);
    assert_ne!(lab.active_pubkey(), [0u8; 32]);
    assert!(!OtaKeyProvider::is_denied(&lab.active_pubkey()));
    assert_eq!(
        OtaKeyProvider::active_pubkey_for_build(),
        OtaKeyProvider::LAB_PUBKEY
    );
}

// ---------------------------------------------------------------------------
// Extension boundary: dispatcher selects via for_build, no cfg, no hard key
// ---------------------------------------------------------------------------

#[test]
fn dispatcher_selects_key_via_for_build_without_cfg() {
    let run = include_str!("../src/run/mod.rs");
    // The single selection point: no hardcoded key material in the dispatcher.
    assert!(
        run.contains("OtaKeyProvider::active_pubkey_for_build()"),
        "dispatcher must select the OTA key via for_build"
    );
    assert!(
        !run.contains("LAB_PUBKEY"),
        "lab key material must not appear in the dispatcher"
    );
    // No test-mode branch around the key selection (R12: build-selected,
    // no `cfg` in run).
    // No test-mode branch inside the key-selection body itself (R12:
    // build-selected, no `cfg` in run): slice the function body from its
    // opening brace to its closing brace and inspect only that.
    let sel = run
        .find("fn ota_active_pubkey")
        .expect("ota_active_pubkey present");
    let body_start = run[sel..].find('{').map(|i| sel + i).expect("body opens");
    let body_end = run[body_start..]
        .find('}')
        .map(|i| body_start + i)
        .expect("body closes");
    let body = &run[body_start..body_end];
    assert!(
        body.contains("active_pubkey_for_build()"),
        "dispatcher must select the OTA key via for_build"
    );
    for banned in ["test-mode", "cfg", "LAB_PUBKEY", "0x65"] {
        assert!(
            !body.contains(banned),
            "key-selection body must not contain {banned:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Error semantics: Ed25519 verify fail-closed (BadSignature, stays Staged)
// ---------------------------------------------------------------------------

#[test]
fn verify_denies_release_zeros_fail_closed() {
    let (mut ota, _sink) = staged_next();
    assert_eq!(
        ota.verify(&OtaKeyProvider::RELEASE_PUBKEY, CURRENT_VERSION),
        Err(OtaError::BadSignature)
    );
    assert_eq!(ota.phase(), OtaPhase::Staged);
}

#[test]
fn verify_denies_foreign_key_fail_closed() {
    let (mut ota, _sink) = staged_next();
    assert_eq!(
        ota.verify(&FOREIGN_PUBKEY, CURRENT_VERSION),
        Err(OtaError::BadSignature)
    );
    assert_eq!(ota.phase(), OtaPhase::Staged);
    assert_eq!(
        OtaError::BadSignature.to_string(),
        "ota release signature invalid"
    );
}

#[test]
fn zeros_release_key_verifies_nothing_fail_closed() {
    // Cryptographic backstop behind `is_denied`: no signature can ever
    // verify against the all-zeros release default. `from_bytes` may parse
    // (all-zeros is a valid curve encoding), but `verify_strict` — which
    // additionally rejects small-order/weak keys — must deny any signature.
    let msg = b"frozen-ota-manifest-bytes-v8";
    let sig = ed25519_dalek::Signature::from_bytes(&[0x5Eu8; 64]);
    match ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]) {
        Err(_) => {} // rejected at parse: fail-closed
        Ok(vk) => assert!(vk.verify_strict(msg, &sig).is_err()),
    }
    assert!(OtaKeyProvider::is_denied(&[0u8; 32]));
}

#[test]
fn machine_untouched_provider_is_the_only_gate() {
    // The Idle→Staged→Verified→Committed machine is untouched: with an
    // injected accept verdict the staged image still verifies and commits.
    let (mut ota, mut sink) = staged_next();
    ota.verify_with(CURRENT_VERSION, true).expect("verify");
    assert_eq!(ota.phase(), OtaPhase::Verified);
    let version = ota.commit(&mut sink).expect("commit");
    assert_eq!(version, NEXT_VERSION);
    assert_eq!(ota.phase(), OtaPhase::Committed);
    assert_eq!(sink.buf, image_bytes());
}

#[test]
fn manifest_layout_and_opcode_and_budget_presets() {
    // Frozen wire layout: version(4) || size(4) || sha256(32) || sig(64).
    let image = image_bytes();
    let raw = manifest_raw(NEXT_VERSION, &image);
    assert_eq!(raw.len(), 104);
    let m = OtaManifest::parse(&raw).expect("parse");
    assert_eq!(m.version, NEXT_VERSION);
    assert_eq!(m.size, image.len() as u32);
    assert_eq!(&m.sha256[..], &Sha256::digest(&image)[..]);
    assert_eq!(m.signed_bytes().len(), 40);
    // Vendor opcode preset + 2 MiB budget preset unchanged by T6.
    assert_eq!(OP_OTA_BEGIN, 0x30);
    assert_eq!(OP_OTA_CHUNK, 0x31);
    assert_eq!(OP_OTA_FINISH, 0x32);
    assert_eq!(OP_OTA_COMMIT, 0x33);
    assert_eq!(OP_OTA_ABORT, 0x34);
    assert_eq!(MAX_OTA_IMAGE_BYTES, 2 * 1024 * 1024);
}
