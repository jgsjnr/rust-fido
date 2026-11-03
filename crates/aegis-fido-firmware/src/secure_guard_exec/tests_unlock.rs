//! Provision/unlock/change-pin tests (moved from `tests.rs`; no behavior change).

use super::super::*;
use super::*;
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::secure_guard::{
    SecureGuardEngine, SecureGuardPolicy, SecureGuardState, OP_SECURE_GUARD_LOCK,
    OP_SECURE_GUARD_UNLOCK, OP_SECURE_GUARD_WIPE_SELECTIVE,
};
use aegis_fido_core::wallet::WalletStore;
use ciborium::value::Value;

#[test]
fn test_provision_and_unlock_flow() {
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();
    let policy = SecureGuardPolicy {
        pbkdf2_iterations: 10,
        ..Default::default()
    };
    let mut engine = SecureGuardEngine::new(policy);
    let mut rng = rand::rng();

    // 1. Provision via 0x3B CBOR
    let prov_map = vec![
        (
            Value::Text("action".into()),
            Value::Text("provision".into()),
        ),
        (Value::Text("pin".into()), Value::Text("5839".into())),
    ];
    let prov_cbor = to_cbor_bytes(&Value::Map(prov_map));

    let (st, _body) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &prov_cbor,
        1000,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert_eq!(engine.state(), SecureGuardState::Unlocked);
    assert!(engine.is_unlocked());
    assert!(engine.is_provisioned());
    let _ = engine.lock_now(1001);
    assert_eq!(engine.state(), SecureGuardState::Locked);

    // 2. Unlock com PIN errado
    let bad_unlock = vec![
        (Value::Text("action".into()), Value::Text("unlock".into())),
        (Value::Text("pin".into()), Value::Text("9999".into())),
    ];
    let bad_cbor = to_cbor_bytes(&Value::Map(bad_unlock));

    let (st_bad, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &bad_cbor,
        1100,
        &mut rng,
    );
    assert_eq!(st_bad, CTAP2_ERR_PIN_REQUIRED);
    assert_eq!(engine.failed_attempts(), 1);

    // 3. Unlock com PIN correto
    let good_unlock = vec![
        (Value::Text("action".into()), Value::Text("unlock".into())),
        (Value::Text("pin".into()), Value::Text("5839".into())),
    ];
    let good_cbor = to_cbor_bytes(&Value::Map(good_unlock));

    let (st_good, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &good_cbor,
        1200,
        &mut rng,
    );
    assert_eq!(st_good, 0x00);
    assert_eq!(engine.state(), SecureGuardState::Unlocked);
    assert!(engine.is_unlocked());

    // 4. Lock via 0x3C
    let (st_lock, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_LOCK,
        &[],
        1300,
        &mut rng,
    );
    assert_eq!(st_lock, 0x00);
    assert_eq!(engine.state(), SecureGuardState::Locked);
}

#[test]
fn test_any_pin_creation_000000_and_849201() {
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();
    let policy = SecureGuardPolicy {
        pbkdf2_iterations: 10,
        ..Default::default()
    };
    let mut engine = SecureGuardEngine::new(policy.clone());
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);

    // 1. PIN 000000 is accepted
    let prov_zeros = vec![
        (
            Value::Text("action".into()),
            Value::Text("provision".into()),
        ),
        (Value::Text("pin".into()), Value::Text("000000".into())),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(prov_zeros)),
        1000,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert!(engine.is_provisioned());

    // Unlock com 000000
    let unl_zeros = vec![
        (Value::Text("action".into()), Value::Text("unlock".into())),
        (Value::Text("pin".into()), Value::Text("000000".into())),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(unl_zeros)),
        1100,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert!(engine.is_unlocked());

    // Wipe full com scope 0xFF
    let wipe_full = vec![
        (Value::Text("scope".into()), Value::from(0xFF)),
        (Value::Text("confirm".into()), Value::Bool(true)),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_WIPE_SELECTIVE,
        &to_cbor_bytes(&Value::Map(wipe_full)),
        1200,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert_eq!(engine.state(), SecureGuardState::Unprovisioned);

    // 2. PIN 849201 is accepted
    let prov_custom = vec![
        (
            Value::Text("action".into()),
            Value::Text("provision".into()),
        ),
        (Value::Text("pin".into()), Value::Text("849201".into())),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(prov_custom)),
        1300,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert!(engine.is_provisioned());

    // Unlock com 849201
    let unl_custom = vec![
        (Value::Text("action".into()), Value::Text("unlock".into())),
        (Value::Text("pin".into()), Value::Text("849201".into())),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(unl_custom)),
        1400,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert!(engine.is_unlocked());
}

fn change_pin_payload(current: &[u8], new_pin: &[u8]) -> Vec<u8> {
    let m = vec![
        (
            Value::Text("action".into()),
            Value::Text("change_pin".into()),
        ),
        (
            Value::Text("current_pin".into()),
            Value::Bytes(current.to_vec()),
        ),
        (
            Value::Text("new_pin".into()),
            Value::Bytes(new_pin.to_vec()),
        ),
    ];
    to_cbor_bytes(&Value::Map(m))
}

fn unlock_payload(pin: &[u8]) -> Vec<u8> {
    let m = vec![
        (Value::Text("action".into()), Value::Text("unlock".into())),
        (Value::Text("pin".into()), Value::Bytes(pin.to_vec())),
    ];
    to_cbor_bytes(&Value::Map(m))
}

#[test]
fn change_pin_applies_unlock_backoff_policy() {
    // F-05: change_pin usa o mesmo backoff progressivo do unlock
    // (`compute_backoff_ms`), sem segunda tabela; negado sem oraculo.
    super::super::unlock::clear_change_pin_backoff();
    let mut rng = rand::rng();
    let mut storage = test_storage();
    let policy = SecureGuardPolicy {
        pbkdf2_iterations: 10,
        ..Default::default()
    };
    let mut engine = SecureGuardEngine::new(policy);
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();

    // Provision + lock.
    let prov = vec![
        (
            Value::Text("action".into()),
            Value::Text("provision".into()),
        ),
        (Value::Text("pin".into()), Value::Bytes(b"5839".to_vec())),
    ];
    let (st, _) = exec_secure_guard_op(
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
    assert_eq!(st, 0x00);
    let _ = engine.lock_now(1001);

    // Falha #1: atraso 0 -> 0x33, sem janela armada.
    let (st1, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &change_pin_payload(b"0000", b"9999"),
        2000,
        &mut rng,
    );
    assert_eq!(st1, CTAP2_ERR_PIN_AUTH_INVALID);
    assert_eq!(engine.failed_attempts(), 1);
    assert_eq!(super::super::unlock::change_pin_backoff_until_ms(), 0);

    // Falha #2: atraso 2000 (mesma tabela do unlock) -> 0x36 + janela ate 4100.
    let (st2, body2) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &change_pin_payload(b"0000", b"9999"),
        2100,
        &mut rng,
    );
    assert_eq!(st2, CTAP2_ERR_PIN_REQUIRED);
    assert_eq!(engine.failed_attempts(), 2);
    assert_eq!(super::super::unlock::change_pin_backoff_until_ms(), 4100);
    let v2: Value = ciborium::from_reader(body2.as_slice()).expect("cbor");
    assert_eq!(
        get_field(v2.as_map().expect("map"), "rate_limit_remaining_ms"),
        Some(&Value::from(2000u64)),
    );

    // PIN correto DENTRO da janela: negado sem oraculo (contador intacto).
    let (st3, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &change_pin_payload(b"5839", b"1234"),
        2200,
        &mut rng,
    );
    assert_eq!(st3, CTAP2_ERR_PIN_REQUIRED);
    assert_eq!(engine.failed_attempts(), 2);

    // Janela vencida: troca com PIN correto e limpa a janela.
    let (st4, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &change_pin_payload(b"5839", b"1234"),
        4200,
        &mut rng,
    );
    assert_eq!(st4, 0x00);
    assert_eq!(engine.failed_attempts(), 0);
    assert_eq!(super::super::unlock::change_pin_backoff_until_ms(), 0);

    // Janela do engine (via unlock) tambem fecha o change_pin sem oraculo.
    let _ = engine.lock_now(4201);
    let (u1, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &unlock_payload(b"0000"),
        5000,
        &mut rng,
    );
    assert_eq!(u1, CTAP2_ERR_PIN_REQUIRED);
    assert_eq!(engine.failed_attempts(), 1);
    let (u2, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &unlock_payload(b"0000"),
        5100,
        &mut rng,
    );
    assert_eq!(u2, CTAP2_ERR_PIN_REQUIRED);
    assert_eq!(engine.failed_attempts(), 2);
    assert_eq!(engine.state(), SecureGuardState::RateLimited);
    let (st5, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &change_pin_payload(b"1234", b"5678"),
        5200,
        &mut rng,
    );
    assert_eq!(st5, CTAP2_ERR_PIN_REQUIRED);
    assert_eq!(engine.failed_attempts(), 2);
    super::super::unlock::clear_change_pin_backoff();
}
