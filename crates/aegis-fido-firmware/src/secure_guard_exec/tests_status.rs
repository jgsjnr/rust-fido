//! Status-op tests (moved from `tests.rs`; no behavior change).

use super::super::*;
use aegis_fido_core::secure_guard::{SecureGuardEngine, SecureGuardPolicy};
use ciborium::value::Value;

#[test]
fn test_status_op_returns_complete_fields() {
    let policy = SecureGuardPolicy {
        pbkdf2_iterations: 10,
        ..Default::default()
    };
    let mut engine = SecureGuardEngine::new(policy);
    let (st, body) = handle_status(&mut engine, 1000);
    assert_eq!(st, 0x00);
    let val: Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
    if let Value::Map(entries) = val {
        assert_eq!(
            get_field(&entries, "provisioned"),
            Some(&Value::Bool(false))
        );
        assert_eq!(get_field(&entries, "unlocked"), Some(&Value::Bool(false)));
        assert_eq!(get_field(&entries, "max_attempts"), Some(&Value::from(5u8)));
    } else {
        panic!("expected cbor map");
    }
}

#[test]
fn test_status_includes_security_feature_flags() {
    let policy = SecureGuardPolicy::default();
    let mut engine = SecureGuardEngine::new(policy);
    let (st, body) = handle_status(&mut engine, 1000);
    assert_eq!(st, 0x00);
    let val: Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
    if let Value::Map(entries) = val {
        assert_eq!(
            get_field(&entries, "efuse_safety_locked"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            get_field(&entries, "ecdh_channel_supported"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            get_field(&entries, "shamir_slip39_supported"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            get_field(&entries, "ctap21_hmac_secret_supported"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            get_field(&entries, "oled_clear_sign_code_ready"),
            Some(&Value::Bool(true))
        );
    } else {
        panic!("expected cbor map");
    }
}

/// Contrato 0x3A com o app: `bench_active` existe e é `false` sem `test-mode`
/// (release/default; sem PII, só o bool da bancada).
#[test]
#[cfg(not(feature = "test-mode"))]
fn test_status_bench_active_false_by_default() {
    let policy = SecureGuardPolicy {
        pbkdf2_iterations: 10,
        ..Default::default()
    };
    let mut engine = SecureGuardEngine::new(policy);
    let (st, body) = handle_status(&mut engine, 1_000);
    assert_eq!(st, 0x00);
    let val: Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
    if let Value::Map(entries) = val {
        assert_eq!(
            get_field(&entries, "bench_active"),
            Some(&Value::Bool(false)),
            "0x3A deve expor bench_active=false sem test-mode"
        );
    } else {
        panic!("expected cbor map");
    }
}
