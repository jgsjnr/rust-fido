//! Recovery-op + envelope-lifecycle tests (moved from `tests.rs`; no behavior change).

use super::super::*;
use super::*;
use crate::persistence::{FlashStorageBackend, SecureStorage};
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::secure_guard::{
    SecureGuardEngine, SecureGuardPolicy, SecureGuardState, OP_SECURE_GUARD_UNLOCK,
};
use aegis_fido_core::wallet::WalletStore;
use ciborium::value::Value;

/// Resgate fim-a-fim pelo op recover: provision via op, reboot simulado
/// (mesma NVS crua, chaves de dispositivo novas) => ErrorLocked, recover op
/// SEM new_pin via envelope => Locked, unlock op com o PIN ORIGINAL => ok.
/// Prova o caminho do firmware sem nenhuma chave de dispositivo.
#[test]
fn test_recover_op_rescues_error_locked_via_envelope() {
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut engine = SecureGuardEngine::new(SecureGuardPolicy {
        pbkdf2_iterations: 10,
        ..Default::default()
    });
    let mut rng = rand::rng();

    // 1. Provision via op; captura o recovery_code (hex) da resposta.
    let prov_map = vec![
        (
            Value::Text("action".into()),
            Value::Text("provision".into()),
        ),
        (Value::Text("pin".into()), Value::Bytes(b"7391".to_vec())),
    ];
    let (st, body) = exec_secure_guard_op(
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
    let val: Value = ciborium::from_reader(body.as_slice()).expect("prov cbor");
    let rec_hex = match &val {
        Value::Map(entries) => match get_field(entries, "recovery_code") {
            Some(Value::Text(s)) => s.clone(),
            other => panic!("expected recovery_code text, got {:?}", other),
        },
        _ => panic!("expected cbor map"),
    };
    assert_eq!(rec_hex.len(), 32);
    // Envelope persistido em plaintext fora do envelope AES.
    let env_raw = storage
        .backend()
        .read_raw(crate::persistence::RECOVERY_ENVELOPE_NVS_KEY)
        .expect("envelope blob after provision");
    assert_eq!(env_raw.len(), 146);
    let _ = engine.lock_now(1001);
    assert_eq!(engine.state(), SecureGuardState::Locked);

    // 2. Reboot simulado: mesma NVS crua, chaves de dispositivo novas.
    let mut storage_b = SecureStorage::new(storage.backend().clone(), &[0x77; 32], &[0x88; 32]);
    let mut rebooted = crate::secure_guard_storage::load_secure_guard_record(&storage_b, 2000);
    assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);

    // 3. Recover op SEM new_pin: resgata via envelope para Locked.
    let rec_map = vec![
        (Value::Text("action".into()), Value::Text("recover".into())),
        (Value::Text("recovery_code".into()), Value::Text(rec_hex)),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut rebooted,
        &mut storage_b,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(rec_map)),
        2100,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert_eq!(rebooted.state(), SecureGuardState::Locked);

    // 4. Unlock op com o PIN ORIGINAL (restaurado pelo envelope).
    let unl_map = vec![
        (Value::Text("action".into()), Value::Text("unlock".into())),
        (Value::Text("pin".into()), Value::Bytes(b"7391".to_vec())),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut rebooted,
        &mut storage_b,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(unl_map)),
        2200,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert!(rebooted.is_unlocked());
}

/// Recover op em ErrorLocked com codigo errado: 0x33, segue ErrorLocked.
#[test]
fn test_recover_op_error_locked_wrong_code_fails_closed() {
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut engine = SecureGuardEngine::new(SecureGuardPolicy {
        pbkdf2_iterations: 10,
        ..Default::default()
    });
    let mut rng = rand::rng();

    let prov_map = vec![
        (
            Value::Text("action".into()),
            Value::Text("provision".into()),
        ),
        (Value::Text("pin".into()), Value::Bytes(b"7391".to_vec())),
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

    let mut storage_b = SecureStorage::new(storage.backend().clone(), &[0x77; 32], &[0x88; 32]);
    let mut rebooted = crate::secure_guard_storage::load_secure_guard_record(&storage_b, 2000);
    assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);

    let bad_map = vec![
        (Value::Text("action".into()), Value::Text("recover".into())),
        (
            Value::Text("recovery_code".into()),
            Value::Bytes(b"wrong-code-00000000".to_vec()),
        ),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut rebooted,
        &mut storage_b,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(bad_map)),
        2100,
        &mut rng,
    );
    assert_eq!(st, CTAP2_ERR_PIN_AUTH_INVALID);
    assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);
}
