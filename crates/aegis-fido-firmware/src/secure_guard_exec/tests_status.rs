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

/// Contrato 0x3A com o app: `ota_progress` ausente sem sessao OTA (compat)
/// e presente `0..=100` via `handle_status_with_ota` (nunca fabricado alem
/// do teto; o chamador alimenta com `OtaState::progress`).
#[test]
fn test_status_ota_progress_field() {
    use crate::secure_guard_exec::status::handle_status_with_ota;
    let policy = SecureGuardPolicy::default();
    let mut engine = SecureGuardEngine::new(policy);
    // Sem sessao OTA: campo ausente (mesmo corpo de `handle_status`).
    let (st, body) = handle_status(&mut engine, 1000);
    assert_eq!(st, 0x00);
    let val: Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
    if let Value::Map(entries) = val {
        assert_eq!(get_field(&entries, "ota_progress"), None);
    } else {
        panic!("expected cbor map");
    }
    // Com sessao OTA a 50%: campo presente.
    let (st, body) = handle_status_with_ota(&mut engine, 1000, Some(50));
    assert_eq!(st, 0x00);
    let val: Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
    if let Value::Map(entries) = val {
        assert_eq!(
            get_field(&entries, "ota_progress"),
            Some(&Value::from(50u8))
        );
    } else {
        panic!("expected cbor map");
    }
    // Clamp defensivo: >100 vira 100.
    let (st, body) = handle_status_with_ota(&mut engine, 1000, Some(255));
    assert_eq!(st, 0x00);
    let val: Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
    if let Value::Map(entries) = val {
        assert_eq!(
            get_field(&entries, "ota_progress"),
            Some(&Value::from(100u8))
        );
    } else {
        panic!("expected cbor map");
    }
}
