//! `VENDOR_SIGN` (`0x41`) executor tests: dedicated SIGN opcode.
//!
//! Covers the root-cause fix: the app used to send sign requests to GEN
//! (`0x20`) with TLV `{0x01 slot, 0x74 challenge}` but GEN requires
//! `TAG_LABEL` (`0x02`) and deterministically denies (`0x04`).
//! `VENDOR_SIGN` takes that exact shape and calls `KeyManager::sign`;
//! GEN semantics stay untouched.

use super::super::exec_vendor_op;
use super::super::vendor_keys::{is_vendor_sign_op, OP_VENDOR_SIGN};
use super::test_storage;
use crate::persistence::{MockFlashBackend, SecureStorage};
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::applet::OathApplet;
use aegis_fido_core::oath::tlv::{write_tlv, TAG_LABEL, TAG_SLOT};
use aegis_fido_core::oath::types::TAG_CHALLENGE;

fn harness() -> (
    SecureStorage<MockFlashBackend>,
    KeyManager,
    OathApplet,
    rand_core::UnwrapErr<getrandom::SysRng>,
) {
    (
        test_storage(),
        KeyManager::new(),
        OathApplet::new(),
        rand_core::UnwrapErr(getrandom::SysRng),
    )
}

fn gen_slot(
    keys: &mut KeyManager,
    oath: &mut OathApplet,
    st: &mut SecureStorage<MockFlashBackend>,
    rng: &mut rand_core::UnwrapErr<getrandom::SysRng>,
    slot: u8,
) {
    let mut payload = Vec::new();
    write_tlv(&mut payload, TAG_SLOT, &[slot]);
    write_tlv(&mut payload, TAG_LABEL, b"sign-test");
    let (status, _) = exec_vendor_op(
        keys,
        oath,
        st,
        crate::ble_gatt::OP_KEY_GEN_ONDEVICE,
        &payload,
        true,
        false,
        true,
        0,
        rng,
    );
    assert_eq!(status, 0x00, "GEN slot {slot} via executor");
}

fn sign_body(slot: u8, msg: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    write_tlv(&mut payload, TAG_SLOT, &[slot]);
    write_tlv(&mut payload, TAG_CHALLENGE, msg);
    payload
}

#[test]
fn opcode_audit_sign_is_first_free_after_set_up_policy() {
    // Choice proof: 0x2F is TAKEN (pairing trigger), 0x40 is TAKEN
    // (SET_UP_POLICY); 0x41 is the documented next-free byte.
    assert_eq!(OP_VENDOR_SIGN, 0x41);
    assert!(is_vendor_sign_op(0x41));
    assert!(!is_vendor_sign_op(0x40));
    assert!(!is_vendor_sign_op(0x3F));
    assert!(!is_vendor_sign_op(0x2F));
    assert_eq!(crate::pairing::OP_HOST_PAIRING_OPEN, 0x2F);
    assert_eq!(crate::ctap_cmd::OP_SET_UP_POLICY, 0x40);
    // Not swallowed by any existing funnel predicate.
    assert!(!crate::ble_gatt::is_vendor_keys_oath_op(OP_VENDOR_SIGN));
    assert!(!crate::ble_gatt::is_wallet_op(OP_VENDOR_SIGN));
    assert!(!crate::ble_gatt::is_secure_guard_op(OP_VENDOR_SIGN));
    assert!(!crate::ble_gatt::is_bind_mgmt_op(OP_VENDOR_SIGN));
    assert!(!crate::vendor_exec::is_get_caps_op(OP_VENDOR_SIGN));
    assert!(!crate::ctap_cmd::is_set_up_policy_op(OP_VENDOR_SIGN));
}

#[test]
fn sign_happy_path_returns_signature_bytes() {
    let (mut st, mut keys, mut oath, mut rng) = harness();
    gen_slot(&mut keys, &mut oath, &mut st, &mut rng, 7);
    let msg = b"app-challenge-32-bytes-padded........";
    let (status, sig) = exec_vendor_op(
        &mut keys,
        &mut oath,
        &mut st,
        OP_VENDOR_SIGN,
        &sign_body(7, msg),
        true,
        false,
        true,
        0,
        &mut rng,
    );
    assert_eq!(status, 0x00);
    assert!(!sig.is_empty(), "signature bytes must be returned");
    // sign_count bump persisted: NVS roundtrip keeps the exact state.
    let blob = keys.export_state();
    let mut keys2 = KeyManager::new();
    let mut oath2 = OathApplet::new();
    assert!(super::super::load_states(&st, &mut keys2, &mut oath2));
    assert_eq!(keys2.export_state(), blob);
}

#[test]
fn gen_missing_label_still_denies_shape_unchanged() {
    // Root-cause regression: the legacy app shape {slot, challenge} WITHOUT
    // TAG_LABEL must keep denying on GEN 0x20 (deterministic 0x04).
    let (mut st, mut keys, mut oath, mut rng) = harness();
    let (status, body) = exec_vendor_op(
        &mut keys,
        &mut oath,
        &mut st,
        crate::ble_gatt::OP_KEY_GEN_ONDEVICE,
        &sign_body(7, b"challenge"),
        true,
        false,
        true,
        0,
        &mut rng,
    );
    assert_eq!(status, 0x04);
    assert!(body.is_empty());
    // And the full GEN shape with label still generates (untouched).
    gen_slot(&mut keys, &mut oath, &mut st, &mut rng, 7);
}

#[test]
fn sign_gates_mirror_gen_binding_up_no_pin() {
    let (mut st, mut keys, mut oath, mut rng) = harness();
    gen_slot(&mut keys, &mut oath, &mut st, &mut rng, 3);
    let body = sign_body(3, b"m");
    // No binding -> NEED_BINDING 0x05 (canonical order: binding first).
    let (status, out) = exec_vendor_op(
        &mut keys,
        &mut oath,
        &mut st,
        OP_VENDOR_SIGN,
        &body,
        false,
        false,
        true,
        0,
        &mut rng,
    );
    assert_eq!(status, 0x05);
    assert!(out.is_empty());
    // No UP -> PresenceRequired 0x01.
    let (status, out) = exec_vendor_op(
        &mut keys,
        &mut oath,
        &mut st,
        OP_VENDOR_SIGN,
        &body,
        true,
        false,
        false,
        0,
        &mut rng,
    );
    assert_eq!(status, 0x01);
    assert!(out.is_empty());
    // No PIN -> still OK (mirrors GEN exactly: CONFIG class without PIN,
    // never weaker than GEN).
    let (status, sig) = exec_vendor_op(
        &mut keys,
        &mut oath,
        &mut st,
        OP_VENDOR_SIGN,
        &body,
        true,
        false,
        true,
        0,
        &mut rng,
    );
    assert_eq!(status, 0x00);
    assert!(!sig.is_empty());
}

#[test]
fn sign_malformed_fails_closed() {
    let (mut st, mut keys, mut oath, mut rng) = harness();
    gen_slot(&mut keys, &mut oath, &mut st, &mut rng, 3);
    // Empty payload, missing slot, missing/empty challenge -> 0x04.
    let mut no_slot = Vec::new();
    write_tlv(&mut no_slot, TAG_CHALLENGE, b"m");
    let mut no_msg = Vec::new();
    write_tlv(&mut no_msg, TAG_SLOT, &[3]);
    let mut empty_msg = Vec::new();
    write_tlv(&mut empty_msg, TAG_SLOT, &[3]);
    write_tlv(&mut empty_msg, TAG_CHALLENGE, b"");
    for payload in [&[][..], &no_slot[..], &no_msg[..], &empty_msg[..]] {
        let (status, body) = exec_vendor_op(
            &mut keys,
            &mut oath,
            &mut st,
            OP_VENDOR_SIGN,
            payload,
            true,
            false,
            true,
            0,
            &mut rng,
        );
        assert_eq!(status, 0x04);
        assert!(body.is_empty());
    }
    // Unknown slot -> NO_SLOT 0x03 (never 0x00).
    let (status, body) = exec_vendor_op(
        &mut keys,
        &mut oath,
        &mut st,
        OP_VENDOR_SIGN,
        &sign_body(9, b"m"),
        true,
        false,
        true,
        0,
        &mut rng,
    );
    assert_eq!(status, 0x03);
    assert!(body.is_empty());
}
