//! GET_CAPS routing tests (executor level: the shared path behind the USB
//! serial + BLE vendor funnels, which both call `exec_vendor_op`).

use super::super::exec_vendor_op;
use super::super::vendor_caps::{
    capability_ids, get_map_field, preset_name, unsupported_count, OP_GET_CAPS,
};
use super::test_storage;
use crate::persistence::{MockFlashBackend, SecureStorage};
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::applet::OathApplet;
use ciborium::value::Value;

fn exec_caps(
    storage: &mut SecureStorage<MockFlashBackend>,
    op: u8,
    payload: &[u8],
    binding_ok: bool,
    pin_ok: bool,
    up: bool,
) -> (u8, Vec<u8>) {
    let mut keys = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    exec_vendor_op(
        &mut keys, &mut oath, storage, op, payload, binding_ok, pin_ok, up, 0, &mut rng,
    )
}

fn decode_caps_map(body: &[u8]) -> Vec<(Value, Value)> {
    let v: Value = ciborium::from_reader(body).expect("GET_CAPS body is CBOR");
    match v {
        Value::Map(m) => m,
        _ => panic!("GET_CAPS body must be a CBOR map"),
    }
}

#[test]
fn get_caps_routes_without_any_auth() {
    let mut st = test_storage();
    // All gates denied (no binding, no PIN, no UP) -- GET_CAPS still 0x00.
    let (status, body) = exec_caps(&mut st, OP_GET_CAPS, &[], false, false, false);
    assert_eq!(status, 0x00);
    assert!(!body.is_empty());
    let map = decode_caps_map(&body);
    assert_eq!(
        get_map_field(&map, "fw_version"),
        Some(&Value::Text(String::from(env!("CARGO_PKG_VERSION"))))
    );
    assert_eq!(
        get_map_field(&map, "preset"),
        Some(&Value::Text(String::from(preset_name())))
    );
    match get_map_field(&map, "caps") {
        Some(Value::Array(items)) => {
            assert_eq!(items.len(), capability_ids().len());
        }
        _ => panic!("caps must be an array"),
    }
    assert_eq!(
        get_map_field(&map, "unsupported_count"),
        Some(&Value::from(unsupported_count()))
    );
    // Same answer with all gates granted (no auth dependence either way).
    let (st2, body2) = exec_caps(&mut st, OP_GET_CAPS, &[], true, true, true);
    assert_eq!((st2, body2), (status, body));
}

#[test]
fn get_caps_payload_rejected_via_executor() {
    let mut st = test_storage();
    // Non-empty request fails closed even with full auth.
    let (status, body) = exec_caps(&mut st, OP_GET_CAPS, &[0x00], true, true, true);
    assert_eq!(status, 0x04);
    assert!(body.is_empty());
}

#[test]
fn unknown_op_behavior_unchanged_next_to_get_caps() {
    let mut st = test_storage();
    // Neighbors of 0x3F keep prior behavior: SG range is not this
    // executor's job, reserved/undefined deny fail-closed.
    for op in [0x2Eu8, 0x2Fu8, 0x3Eu8, 0x40u8, 0xFFu8] {
        let (status, body) = exec_caps(&mut st, op, &[], true, true, true);
        assert_eq!(status, 0x04, "op 0x{op:02X} must still deny");
        assert!(body.is_empty());
    }
    // And 0x3F itself still answers after the denials (no state carried).
    let (status, _) = exec_caps(&mut st, OP_GET_CAPS, &[], false, false, false);
    assert_eq!(status, 0x00);
}
