//! Config + selective-wipe tests (moved from `tests.rs`; no behavior change).

use super::super::*;
use super::*;
use crate::persistence::FlashStorageBackend;
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::secure_guard::{
    SecureGuardEngine, SecureGuardPolicy, SecureGuardState, OP_SECURE_GUARD_CONFIG,
    OP_SECURE_GUARD_UNLOCK, OP_SECURE_GUARD_WIPE_SELECTIVE,
};
use aegis_fido_core::wallet::WalletStore;
use ciborium::value::Value;

#[test]
fn test_config_pin_validation() {
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut engine = SecureGuardEngine::new(SecureGuardPolicy {
        pbkdf2_iterations: 10,
        ..Default::default()
    });
    let mut rng = rand::rng();

    // Provision PIN "4927"
    let prov_map = vec![
        (
            Value::Text("action".into()),
            Value::Text("provision".into()),
        ),
        (Value::Text("pin".into()), Value::Bytes(b"4927".to_vec())),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(prov_map)),
        1000,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert_eq!(engine.state(), SecureGuardState::Unlocked);
    assert!(engine.is_unlocked());
    let _ = engine.lock_now(1001);
    assert_eq!(engine.state(), SecureGuardState::Locked);

    // 1. Config without PIN while Locked -> Rejects with CTAP2_ERR_PIN_REQUIRED (0x36)
    let config_map = vec![(Value::Text("wipe_on_5_failures".into()), Value::Bool(true))];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_CONFIG,
        &to_cbor_bytes(&Value::Map(config_map)),
        1100,
        &mut rng,
    );
    assert_eq!(st, CTAP2_ERR_PIN_REQUIRED);

    // 2. Config with WRONG PIN -> Rejects with CTAP2_ERR_PIN_AUTH_INVALID (0x33)
    let config_bad_pin = vec![
        (Value::Text("wipe_on_5_failures".into()), Value::Bool(true)),
        (Value::Text("pin".into()), Value::Bytes(b"9999".to_vec())),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_CONFIG,
        &to_cbor_bytes(&Value::Map(config_bad_pin)),
        1200,
        &mut rng,
    );
    assert_eq!(st, CTAP2_ERR_PIN_AUTH_INVALID);

    // 3. Config with CORRECT PIN -> Succeeds (0x00) and updates policy
    let config_good_pin = vec![
        (Value::Text("wipe_on_5_failures".into()), Value::Bool(true)),
        (Value::Text("pin".into()), Value::Bytes(b"4927".to_vec())),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_CONFIG,
        &to_cbor_bytes(&Value::Map(config_good_pin)),
        1300,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert!(engine.policy().wipe_on_5_failures);
}

#[test]
fn test_wipe_selective_pin_validation() {
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut engine = SecureGuardEngine::new(SecureGuardPolicy {
        pbkdf2_iterations: 10,
        test_mode_non_destructive_wipe: false,
        ..Default::default()
    });
    let mut rng = rand::rng();

    // Provision PIN "4927"
    let prov_map = vec![
        (
            Value::Text("action".into()),
            Value::Text("provision".into()),
        ),
        (Value::Text("pin".into()), Value::Bytes(b"4927".to_vec())),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(prov_map)),
        1000,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert_eq!(engine.state(), SecureGuardState::Unlocked);
    assert!(engine.is_unlocked());
    let _ = engine.lock_now(1001);
    assert_eq!(engine.state(), SecureGuardState::Locked);

    // 1. Wipe without confirmation or PIN while Locked -> Rejects with CTAP2_ERR_PIN_REQUIRED (0x36)
    let wipe_no_confirm = vec![];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_WIPE_SELECTIVE,
        &to_cbor_bytes(&Value::Map(wipe_no_confirm)),
        1100,
        &mut rng,
    );
    assert_eq!(st, CTAP2_ERR_PIN_REQUIRED);

    // 2. Wipe Full confirmed without PIN -> Succeeds (0x00) and executes Wipe Full to Unprovisioned
    let wipe_confirmed = vec![
        (Value::Text("confirm".into()), Value::Bool(true)),
        (
            Value::Text("confirmation".into()),
            Value::Text("WIPE-CONFIRMED".into()),
        ),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_WIPE_SELECTIVE,
        &to_cbor_bytes(&Value::Map(wipe_confirmed)),
        1200,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert_eq!(engine.state(), SecureGuardState::Unprovisioned);
    assert!(!engine.is_provisioned());
}

#[test]
fn test_wipe_full_emergency_in_ratelimited_or_locked_state() {
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut engine = SecureGuardEngine::new(SecureGuardPolicy {
        pbkdf2_iterations: 10,
        wipe_on_5_failures: false,
        ..Default::default()
    });
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);

    // Provision PIN "849201"
    let prov = vec![
        (
            Value::Text("action".into()),
            Value::Text("provision".into()),
        ),
        (Value::Text("pin".into()), Value::Text("849201".into())),
    ];
    exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(prov)),
        1000,
        &mut rng,
    );
    let _ = engine.lock_now(1001);

    // 5 consecutive failures -> RateLimited (15s backoff)
    let mut time = 2000u64;
    for _ in 1..=5 {
        let bad = vec![
            (Value::Text("action".into()), Value::Text("unlock".into())),
            (Value::Text("pin".into()), Value::Text("000000".into())),
        ];
        exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(bad)),
            time,
            &mut rng,
        );
        time += 100;
    }
    assert_eq!(engine.state(), SecureGuardState::RateLimited);

    // Wipe Full emergency com confirmation "WIPE-CONFIRMED" mesmo em RateLimited!
    let emergency_wipe = vec![
        (
            Value::Text("confirmation".into()),
            Value::Text("WIPE-CONFIRMED".into()),
        ),
        (Value::Text("scope".into()), Value::from(0x07)),
    ];
    let (st, body) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_WIPE_SELECTIVE,
        &to_cbor_bytes(&Value::Map(emergency_wipe)),
        time,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert_eq!(engine.state(), SecureGuardState::Unprovisioned);
    assert!(!engine.is_provisioned());
    let val: Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
    if let Value::Map(entries) = val {
        assert_eq!(get_field(&entries, "wiped"), Some(&Value::Bool(true)));
        assert_eq!(get_field(&entries, "state"), Some(&Value::from(0u8)));
    }
}

/// Wipe seletivo full confirmado destroi o blob do envelope (sem ressurreicao).
#[test]
fn test_wipe_selective_destroys_envelope_blob() {
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut engine = SecureGuardEngine::new(SecureGuardPolicy {
        pbkdf2_iterations: 10,
        test_mode_non_destructive_wipe: false,
        ..Default::default()
    });
    let mut rng = rand::rng();

    let prov_map = vec![
        (
            Value::Text("action".into()),
            Value::Text("provision".into()),
        ),
        (Value::Text("pin".into()), Value::Bytes(b"4927".to_vec())),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(prov_map)),
        1000,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert!(storage
        .backend()
        .read_raw(crate::persistence::RECOVERY_ENVELOPE_NVS_KEY)
        .is_ok());

    let wipe_confirmed = vec![
        (Value::Text("confirm".into()), Value::Bool(true)),
        (
            Value::Text("confirmation".into()),
            Value::Text("WIPE-CONFIRMED".into()),
        ),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_WIPE_SELECTIVE,
        &to_cbor_bytes(&Value::Map(wipe_confirmed)),
        1100,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert_eq!(engine.state(), SecureGuardState::Unprovisioned);
    assert!(storage
        .backend()
        .read_raw(crate::persistence::RECOVERY_ENVELOPE_NVS_KEY)
        .is_err());
}
