//! PM dispatch tests (moved verbatim from `pm_dispatch`, god-split).

use super::*;
use crate::ble_gatt::BleGattError;
use crate::pm_cbor::{
    decode_id_body, encode_id_body, field, from_cbor, get_bytes, get_text, get_u32,
};
use crate::pm_store::{
    PmRateLimiter, PM_BACKOFF_MS, PM_BINDING_WINDOW_MS, PM_MAX_CONSEC_FAIL, PM_UP_WINDOW_MS,
};
use alloc::string::String;

fn test_vault() -> (PmVault, PmPolicy) {
    (PmVault::new([0x5Au8; 32]), PmPolicy::default())
}

fn put_body(label: &str, user: &str, secret: &[u8]) -> Vec<u8> {
    let map = alloc::vec![
        (
            Value::Text("label".into()),
            Value::Text(String::from(label))
        ),
        (
            Value::Text("username".into()),
            Value::Text(String::from(user))
        ),
        (Value::Text("secret".into()), Value::Bytes(secret.to_vec())),
        (Value::Text("url".into()), Value::Null),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
    out
}

fn gate() -> PmGateState {
    PmGateState::authorized()
}

const NOW_MS: u64 = 1_770_000_000_000;

fn put_one(vault: &mut PmVault, policy: &PmPolicy) -> Vec<u8> {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let (st, body) = dispatch_pm_op(
        OP_PM_PUT,
        &put_body("bank", "alice", b"s3cr3t"),
        &gate(),
        vault,
        policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x00);
    decode_id_body(&body).expect("put answers opaque id")
}

#[test]
fn gates_deny_every_op_in_canonical_order() {
    let (mut vault, policy) = test_vault();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let bodies: [(u8, Vec<u8>); 5] = [
        (OP_PM_PUT, put_body("bank", "alice", b"s3cr3t")),
        (OP_PM_GET, encode_id_body(&[0x01; 16]).expect("id body")),
        (OP_PM_LIST, {
            let map = alloc::vec![
                (Value::Text("cursor".into()), Value::from(0u64)),
                (Value::Text("limit".into()), Value::from(32u64)),
            ];
            let mut out = Vec::new();
            ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
            out
        }),
        (OP_PM_DELETE, encode_id_body(&[0x01; 16]).expect("id body")),
        (OP_PM_STATUS, Vec::new()),
    ];
    // STATUS with empty body is a malformed frame (0x04), still gated first.
    let denied = [
        (
            PmGateState {
                binding_bound: false,
                ..gate()
            },
            BleGattError::NeedBinding.to_vendor_status(),
        ),
        (
            PmGateState {
                presence_confirmed: false,
                ..gate()
            },
            BleGattError::PresenceRequired.to_vendor_status(),
        ),
        (
            PmGateState {
                pin_authenticated: false,
                ..gate()
            },
            BleGattError::PinRequired.to_vendor_status(),
        ),
        (
            PmGateState {
                bound_within_ms: PM_BINDING_WINDOW_MS + 1,
                ..gate()
            },
            BleGattError::PresenceRequired.to_vendor_status(),
        ),
    ];
    for (op, body) in &bodies {
        for (g, want) in denied {
            let (st, _) = dispatch_pm_op(
                *op,
                body,
                &g,
                &mut vault,
                &policy,
                1_770_000_000,
                &mut rng,
                &mut PmRateLimiter::new(),
                NOW_MS,
            );
            assert_eq!(st, want, "op 0x{op:02X}");
        }
    }
    // Outside the family: InvalidOpcode, never routed to the vault.
    let (st, _) = dispatch_pm_op(
        0x22,
        &[],
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(
        st,
        BleGattError::InvalidOpcode.to_vendor_status(),
        "non-PM op"
    );
}

#[test]
fn put_get_delete_roundtrip() {
    let (mut vault, policy) = test_vault();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let id = put_one(&mut vault, &policy);
    // GET returns the punctual release (username + secret, no label).
    let (st, body) = dispatch_pm_op(
        OP_PM_GET,
        &encode_id_body(&id).unwrap(),
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x00);
    let entries = from_cbor(&body).expect("release cbor");
    assert_eq!(get_text(&entries, "username").unwrap(), "alice");
    assert_eq!(get_bytes(&entries, "secret").unwrap(), b"s3cr3t");
    // GET unknown id -> NO_SLOT (0x03).
    let (st, _) = dispatch_pm_op(
        OP_PM_GET,
        &encode_id_body(&[0xFF; 16]).unwrap(),
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x03);
    // DELETE then GET -> NO_SLOT.
    let (st, _) = dispatch_pm_op(
        OP_PM_DELETE,
        &encode_id_body(&id).unwrap(),
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x00);
    let (st, _) = dispatch_pm_op(
        OP_PM_GET,
        &encode_id_body(&id).unwrap(),
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x03);
    // DELETE unknown -> NO_SLOT (0x03), never 0x00.
    let (st, _) = dispatch_pm_op(
        OP_PM_DELETE,
        &encode_id_body(&[0xFF; 16]).unwrap(),
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x03);
}

#[test]
fn list_pages_over_opaque_ids_and_status_census() {
    let (mut vault, policy) = test_vault();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let id0 = put_one(&mut vault, &policy);
    let _id1 = put_one(&mut vault, &policy);
    let list_req = |cursor: u32, limit: u32| {
        let map = alloc::vec![
            (Value::Text("cursor".into()), Value::from(cursor as u64)),
            (Value::Text("limit".into()), Value::from(limit as u64)),
        ];
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
        out
    };
    // Page 1 of 2.
    let (st, body) = dispatch_pm_op(
        OP_PM_LIST,
        &list_req(0, 1),
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x00);
    let entries = from_cbor(&body).expect("list cbor");
    let ids = match field(&entries, "ids").unwrap() {
        Value::Array(a) => a.clone(),
        _ => panic!("ids array"),
    };
    assert_eq!(ids.len(), 1);
    let has_more = match field(&entries, "has_more") {
        Some(Value::Bool(b)) => *b,
        _ => panic!("has_more bool"),
    };
    assert!(has_more);
    let next = get_u32(&entries, "next_cursor", 0).unwrap();
    assert_eq!(next, 1);
    // Page 2 carries the remaining id (opaque: no labels cross the edge).
    let (st, body2) = dispatch_pm_op(
        OP_PM_LIST,
        &list_req(next, 1),
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x00);
    let entries2 = from_cbor(&body2).expect("list cbor");
    let has_more2 = match field(&entries2, "has_more") {
        Some(Value::Bool(b)) => *b,
        _ => panic!("has_more bool"),
    };
    assert!(!has_more2);
    // First id matches the created record (opaque, device-chosen).
    match &ids[0] {
        Value::Bytes(b) => assert_eq!(b, &id0),
        _ => panic!("id bytes"),
    }
    // STATUS census, no secrets.
    let (st, body) = dispatch_pm_op(
        OP_PM_STATUS,
        &{
            let mut out = Vec::new();
            ciborium::into_writer(&Value::Map(Vec::new()), &mut out).unwrap();
            out
        },
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x00);
    let entries = from_cbor(&body).expect("status cbor");
    assert_eq!(get_u32(&entries, "entry_count", 99), Some(2));
    assert_eq!(
        get_u32(&entries, "max_entries", 0),
        Some(policy.max_entries as u32)
    );
}

#[test]
fn malformed_frames_fail_closed_without_secrets() {
    let (mut vault, policy) = test_vault();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    // Empty secret rejected (transport cap, fail-closed 0x04).
    let (st, _) = dispatch_pm_op(
        OP_PM_PUT,
        &put_body("bank", "alice", b""),
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x04);
    // Non-CBOR body rejected.
    let (st, _) = dispatch_pm_op(
        OP_PM_GET,
        b"not-cbor",
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x04);
    // Empty id rejected.
    let map = alloc::vec![(Value::Text("id".into()), Value::Bytes(Vec::new()))];
    let mut bad = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut bad).unwrap();
    let (st, _) = dispatch_pm_op(
        OP_PM_DELETE,
        &bad,
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x04);
    // Debug of errors carries no blob bytes.
    let dbg = alloc::format!("{:?}", aegis_pm_vault::PmError::Sealed);
    assert!(!dbg.contains("s3cr3t"));
}

fn list_req(cursor: u32, limit: u32) -> Vec<u8> {
    let map = alloc::vec![
        (Value::Text("cursor".into()), Value::from(cursor as u64)),
        (Value::Text("limit".into()), Value::from(limit as u64)),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
    out
}

#[test]
fn persist_put_list_get_delete_survives_reboot() {
    use crate::persistence::{MockFlashBackend, SecureStorage};
    let mut storage = SecureStorage::new(MockFlashBackend::new(), &[0x11u8; 32], &[0x22u8; 32]);
    let policy = PmPolicy::default();
    let gate = gate();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    // PUT persists.
    let (st, body) = dispatch_pm_op_persist(
        OP_PM_PUT,
        &put_body("bank", "alice", b"s3cr3t"),
        &gate,
        &mut storage,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x00);
    let id = decode_id_body(&body).expect("opaque id");
    // LIST sees it on a fresh call (blob reloaded from NVS).
    let (st, body) = dispatch_pm_op_persist(
        OP_PM_LIST,
        &list_req(0, 32),
        &gate,
        &mut storage,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x00);
    let entries = from_cbor(&body).expect("list cbor");
    let ids = match field(&entries, "ids").unwrap() {
        Value::Array(a) => a.clone(),
        _ => panic!("ids array"),
    };
    assert_eq!(ids.len(), 1);
    // GET returns the record.
    let (st, _) = dispatch_pm_op_persist(
        OP_PM_GET,
        &encode_id_body(&id).unwrap(),
        &gate,
        &mut storage,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x00);
    // Simulated reboot: new engine over the persisted backend image.
    let backend_clone = storage.backend().clone();
    let mut rebooted = SecureStorage::new(backend_clone, &[0x11u8; 32], &[0x22u8; 32]);
    let (st, body) = dispatch_pm_op_persist(
        OP_PM_LIST,
        &list_req(0, 32),
        &gate,
        &mut rebooted,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x00);
    let entries = from_cbor(&body).expect("reboot list cbor");
    let ids = match field(&entries, "ids").unwrap() {
        Value::Array(a) => a.clone(),
        _ => panic!("ids array"),
    };
    assert_eq!(ids.len(), 1);
    // DELETE persists; post-reboot LIST is empty.
    let (st, _) = dispatch_pm_op_persist(
        OP_PM_DELETE,
        &encode_id_body(&id).unwrap(),
        &gate,
        &mut rebooted,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x00);
    let backend_clone = rebooted.backend().clone();
    let mut rebooted2 = SecureStorage::new(backend_clone, &[0x11u8; 32], &[0x22u8; 32]);
    let (st, body) = dispatch_pm_op_persist(
        OP_PM_LIST,
        &list_req(0, 32),
        &gate,
        &mut rebooted2,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut PmRateLimiter::new(),
        NOW_MS,
    );
    assert_eq!(st, 0x00);
    let entries = from_cbor(&body).expect("empty list cbor");
    let ids = match field(&entries, "ids").unwrap() {
        Value::Array(a) => a.clone(),
        _ => panic!("ids array"),
    };
    assert!(ids.is_empty());
}

#[test]
fn backoff_denies_authenticated_ops_until_lapse() {
    let (mut vault, policy) = test_vault();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let mut lim = PmRateLimiter::new();
    let unknown = encode_id_body(&[0xFF; 16]).expect("id body");
    // Five authenticated misses (0x03) spend the budget; the sixth op
    // is denied 0x04 even fully authorized (fail-closed backoff).
    for _ in 0..PM_MAX_CONSEC_FAIL {
        let (st, _) = dispatch_pm_op(
            OP_PM_GET,
            &unknown,
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut lim,
            NOW_MS,
        );
        assert_eq!(st, 0x03);
    }
    let (st, _) = dispatch_pm_op(
        OP_PM_GET,
        &unknown,
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut lim,
        NOW_MS,
    );
    assert_eq!(st, 0x04);
    // Backoff is per-limiter, not per-op: PUT also denied.
    let (st, _) = dispatch_pm_op(
        OP_PM_PUT,
        &put_body("bank", "alice", b"s3cr3t"),
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut lim,
        NOW_MS,
    );
    assert_eq!(st, 0x04);
    // After the window lapses the same op is evaluated normally again.
    let (st, _) = dispatch_pm_op(
        OP_PM_GET,
        &unknown,
        &gate(),
        &mut vault,
        &policy,
        1_770_000_000,
        &mut rng,
        &mut lim,
        NOW_MS + PM_BACKOFF_MS,
    );
    assert_eq!(st, 0x03);
}

#[test]
fn stale_up_and_missing_pin_deny_at_dispatch() {
    let (mut vault, policy) = test_vault();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let unknown = encode_id_body(&[0xFF; 16]).expect("id body");
    // Stale UP age denies even with the latch bit set.
    let stale_up = PmGateState {
        up_within_ms: PM_UP_WINDOW_MS + 1,
        ..gate()
    };
    for op in [OP_PM_PUT, OP_PM_GET, OP_PM_LIST, OP_PM_DELETE, OP_PM_STATUS] {
        let body = if op == OP_PM_PUT {
            put_body("bank", "alice", b"s3cr3t")
        } else if op == OP_PM_LIST || op == OP_PM_STATUS {
            list_req(0, 32)
        } else {
            unknown.clone()
        };
        let (st, _) = dispatch_pm_op(
            op,
            &body,
            &stale_up,
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x01, "stale UP must deny op 0x{op:02X}");
    }
    // Secret-touching ops require PIN strictly: binding + fresh UP
    // without PIN denies 0x02 on GET and DELETE.
    let no_pin = PmGateState {
        pin_authenticated: false,
        ..gate()
    };
    for op in [OP_PM_GET, OP_PM_DELETE] {
        let (st, _) = dispatch_pm_op(
            op,
            &unknown,
            &no_pin,
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x02, "GET/DELETE without PIN must deny 0x02");
    }
    // Unbound transport denies 0x05 on every PM op (fail-closed).
    let unbound = PmGateState {
        binding_bound: false,
        ..gate()
    };
    for op in [OP_PM_PUT, OP_PM_GET, OP_PM_LIST, OP_PM_DELETE, OP_PM_STATUS] {
        let body = if op == OP_PM_PUT {
            put_body("bank", "alice", b"s3cr3t")
        } else if op == OP_PM_LIST || op == OP_PM_STATUS {
            list_req(0, 32)
        } else {
            unknown.clone()
        };
        let (st, _) = dispatch_pm_op(
            op,
            &body,
            &unbound,
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x05, "unbound must deny op 0x{op:02X}");
    }
}
