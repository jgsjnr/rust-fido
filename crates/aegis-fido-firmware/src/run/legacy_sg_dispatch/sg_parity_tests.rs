//! Byte-parity tests: legacy serial SG dispatch vs freertos (move-only).
//!
//! Test bodies moved verbatim from `legacy_sg_dispatch::tests`; shared
//! setup lives in `super::sg_test_ctx`.

use super::sg_exec::dispatch_legacy_secure_guard_op;
use super::sg_test_ctx::{cbor_action_pin, frame_msg, freertos_ctx, legacy_setup};
use crate::ble_gatt::{OP_SECURE_GUARD_LOCK, OP_SECURE_GUARD_STATUS, OP_SECURE_GUARD_UNLOCK};
use aegis_fido_core::secure_guard::SecureGuardState;
use aegis_fido_usb::ctaphid::{CtapHidFramer, CMD_MSG};

#[test]
fn legacy_status_matches_freertos_bytes() {
    let pin = b"4829";
    let mut ctx = freertos_ctx(pin, false);
    let (mut sg, mut storage, mut wallet, mut key_mgr, mut oath, _pairing) =
        legacy_setup(pin, false);
    let now_ms = 2000u64;

    let msg = frame_msg(0x0102_0304, CMD_MSG, OP_SECURE_GUARD_STATUS, &[]);
    let out = crate::freertos_route::dispatch_serial_vendor_msg(&mut ctx, &msg)
        .expect("freertos handles 0x3A");
    assert!(!out.1, "SG never consumes UP");

    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let (st, body, effects) = dispatch_legacy_secure_guard_op(
        &mut sg,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_STATUS,
        &[],
        now_ms,
        &mut rng,
    );
    assert!(!effects.did_unlock && !effects.did_lock);
    assert!(effects.verified_pin.is_none());

    let mut resp = Vec::with_capacity(1 + body.len());
    resp.push(st);
    resp.extend_from_slice(&body);
    let expected = CtapHidFramer::frame_message(0x0102_0304, CMD_MSG, &resp);
    assert_eq!(out.0, expected, "status bytes must match freertos");
    assert_eq!(resp[0], 0x00);
    assert_eq!(sg.state(), SecureGuardState::Unprovisioned);
}

#[test]
fn legacy_unlock_matches_freertos_bytes() {
    let pin = b"4829";
    let mut ctx = freertos_ctx(pin, true);
    let (mut sg, mut storage, mut wallet, mut key_mgr, mut oath, mut pairing) =
        legacy_setup(pin, true);
    let now_ms = 3000u64;
    let cbor = cbor_action_pin("unlock", pin);

    let msg = frame_msg(0x1122_3344, CMD_MSG, OP_SECURE_GUARD_UNLOCK, &cbor);
    let out = crate::freertos_route::dispatch_serial_vendor_msg(&mut ctx, &msg)
        .expect("freertos handles 0x3B");
    assert!(!out.1, "SG never consumes UP");

    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let (st, body, effects) = dispatch_legacy_secure_guard_op(
        &mut sg,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &cbor,
        now_ms,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert!(effects.did_unlock);
    assert_eq!(effects.verified_pin.as_deref(), Some(pin.as_slice()));
    assert!(sg.is_unlocked());

    let mut resp = Vec::with_capacity(1 + body.len());
    resp.push(st);
    resp.extend_from_slice(&body);
    let expected = CtapHidFramer::frame_message(0x1122_3344, CMD_MSG, &resp);
    assert_eq!(out.0, expected, "unlock bytes must match freertos");
    // Freertos side effects parity: unlock opens window + arms UP + PIN.
    assert!(ctx.pin_verified);
    assert!(ctx.arm_up);
    assert!(ctx.pairing_open);
    assert!(ctx.verified_pin.is_some());
    // Legacy caller applies the same window effect.
    pairing.open_host_window(now_ms);
    assert!(pairing.is_pairing_window_open(now_ms));
}

#[test]
fn legacy_lock_matches_freertos_bytes() {
    let pin = b"4829";
    let mut ctx = freertos_ctx(pin, true);
    let (mut sg, mut storage, mut wallet, mut key_mgr, mut oath, _pairing) =
        legacy_setup(pin, true);
    let now_ms = 4000u64;
    // Unlock both sides first (deterministic: pre-provisioned above).
    let cbor = cbor_action_pin("unlock", pin);
    let msg_un = frame_msg(0x1122_3344, CMD_MSG, OP_SECURE_GUARD_UNLOCK, &cbor);
    let _ = crate::freertos_route::dispatch_serial_vendor_msg(&mut ctx, &msg_un);
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let (st_un, _, _) = dispatch_legacy_secure_guard_op(
        &mut sg,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &cbor,
        now_ms,
        &mut rng,
    );
    assert_eq!(st_un, 0x00);
    assert!(sg.is_unlocked());
    assert!(ctx.secure_guard.as_ref().unwrap().is_unlocked());

    // Now lock via both paths with identical input bytes.
    let msg = frame_msg(0x1122_3344, CMD_MSG, OP_SECURE_GUARD_LOCK, &[]);
    let out = crate::freertos_route::dispatch_serial_vendor_msg(&mut ctx, &msg)
        .expect("freertos handles 0x3C");
    let (st, body, effects) = dispatch_legacy_secure_guard_op(
        &mut sg,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_LOCK,
        &[],
        now_ms + 10,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert!(effects.did_lock && !effects.did_unlock);
    assert_eq!(sg.state(), SecureGuardState::Locked);

    let mut resp = Vec::with_capacity(1 + body.len());
    resp.push(st);
    resp.extend_from_slice(&body);
    let expected = CtapHidFramer::frame_message(0x1122_3344, CMD_MSG, &resp);
    assert_eq!(out.0, expected, "lock bytes must match freertos");
}
