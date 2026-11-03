//! Feature-action tests: ecdh/shamir/clear-sign/keepassxc/ble proximity
//! (moved from `tests.rs`; no behavior change).

use super::super::*;
use super::*;
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::secure_guard::{
    SecureGuardEngine, SecureGuardPolicy, SecureGuardState, OP_SECURE_GUARD_LOCK,
    OP_SECURE_GUARD_STATUS, OP_SECURE_GUARD_UNLOCK,
};
use aegis_fido_core::wallet::WalletStore;
use ciborium::value::Value;

#[test]
fn test_ecdh_handshake_action() {
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut engine = SecureGuardEngine::new(SecureGuardPolicy::default());
    let mut rng = rand::rng();

    let req = vec![(
        Value::Text("action".into()),
        Value::Text("ecdh_handshake".into()),
    )];
    let req_cbor = to_cbor_bytes(&Value::Map(req));

    let (st, body) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &req_cbor,
        1000,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    let val: Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
    if let Value::Map(entries) = val {
        assert_eq!(
            get_field(&entries, "status"),
            Some(&Value::Text("ecdh_ready".into()))
        );
        assert_eq!(
            get_field(&entries, "curve"),
            Some(&Value::Text("P-256".into()))
        );
        let pub_bytes = get_field(&entries, "device_public_key")
            .and_then(extract_bytes)
            .expect("public key bytes");
        assert_eq!(pub_bytes.len(), 65);
        assert_eq!(pub_bytes[0], 0x04);
    } else {
        panic!("expected cbor map");
    }
}

#[test]
fn test_shamir_2_of_3_workflow() {
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut engine = SecureGuardEngine::new(SecureGuardPolicy {
        pbkdf2_iterations: 10,
        ..Default::default()
    });
    let mut rng = rand::rng();

    // Provision e unlock primeiro
    let prov_map = vec![
        (
            Value::Text("action".into()),
            Value::Text("provision".into()),
        ),
        (Value::Text("pin".into()), Value::Text("5839".into())),
    ];
    exec_secure_guard_op(
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
    let unlock_map = vec![
        (Value::Text("action".into()), Value::Text("unlock".into())),
        (Value::Text("pin".into()), Value::Text("5839".into())),
    ];
    exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(unlock_map)),
        1100,
        &mut rng,
    );
    assert!(engine.is_unlocked());

    // Split
    let secret = b"my_super_secret_seed_phrase_backup";
    let split_map = vec![
        (
            Value::Text("action".into()),
            Value::Text("shamir_split".into()),
        ),
        (Value::Text("secret".into()), Value::Bytes(secret.to_vec())),
    ];
    let (st_split, split_body) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(split_map)),
        1200,
        &mut rng,
    );
    assert_eq!(st_split, 0x00);
    let split_val: Value = ciborium::from_reader(split_body.as_slice()).expect("cbor parse");
    let (s1, s2, s3) = if let Value::Map(entries) = split_val {
        let shares = get_field(&entries, "shares").expect("shares");
        if let Value::Array(arr) = shares {
            (
                extract_bytes(&arr[0]).unwrap(),
                extract_bytes(&arr[1]).unwrap(),
                extract_bytes(&arr[2]).unwrap(),
            )
        } else {
            panic!("shares not array");
        }
    } else {
        panic!("not map");
    };

    // Recover usando (s1, s2)
    let rec12 = shamir_2_of_3_recover(&s1, &s2).expect("recover 1+2");
    assert_eq!(rec12, secret);

    // Recover usando (s1, s3)
    let rec13 = shamir_2_of_3_recover(&s1, &s3).expect("recover 1+3");
    assert_eq!(rec13, secret);

    // Recover usando (s2, s3)
    let rec23 = shamir_2_of_3_recover(&s2, &s3).expect("recover 2+3");
    assert_eq!(rec23, secret);
}

#[test]
fn test_clear_sign_preview_action() {
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut engine = SecureGuardEngine::new(SecureGuardPolicy::default());
    let mut rng = rand::rng();

    let preview_map = vec![
        (
            Value::Text("action".into()),
            Value::Text("clear_sign_preview".into()),
        ),
        (Value::Text("chain".into()), Value::Text("ETH".into())),
        (
            Value::Text("tx_type".into()),
            Value::Text("EIP-1559".into()),
        ),
        (
            Value::Text("recipient".into()),
            Value::Text("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".into()),
        ),
        (Value::Text("amount".into()), Value::Text("2.5 ETH".into())),
        (Value::Text("fee".into()), Value::Text("0.003 ETH".into())),
    ];

    let (st, body) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(preview_map)),
        1000,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    let val: Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
    if let Value::Map(entries) = val {
        assert_eq!(
            get_field(&entries, "status"),
            Some(&Value::Text("preview_rendered".into()))
        );
        assert_eq!(
            get_field(&entries, "hardware_oled_attached"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            get_field(&entries, "frame_size"),
            Some(&Value::from(1024u64))
        );
        let frame = get_field(&entries, "frame_bytes")
            .and_then(extract_bytes)
            .expect("frame bytes");
        assert_eq!(frame.len(), 1024);
    } else {
        panic!("not map");
    }
}

#[test]
fn test_keepassxc_slot_config_and_challenge_vendor_exec() {
    let mut rng = rand::rng();
    let mut storage = test_storage();
    let mut engine = SecureGuardEngine::new(SecureGuardPolicy {
        pbkdf2_iterations: 10,
        ..Default::default()
    });
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();

    // 1. Provision & Unlock
    let prov_payload = vec![
        (
            Value::Text("action".into()),
            Value::Text("provision".into()),
        ),
        (Value::Text("pin".into()), Value::Text("5839".into())),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(prov_payload)),
        100,
        &mut rng,
    );
    assert_eq!(st, 0x00);

    let unlock_payload = vec![
        (Value::Text("action".into()), Value::Text("unlock".into())),
        (Value::Text("pin".into()), Value::Text("5839".into())),
    ];
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(unlock_payload)),
        200,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    assert!(engine.is_unlocked());

    // 2. Configure KeePassXC slot 2
    let cfg_payload = vec![
        (
            Value::Text("action".into()),
            Value::Text("keepassxc_slot_config".into()),
        ),
        (Value::Text("slot".into()), Value::from(2)),
        (Value::Text("key".into()), Value::Bytes(vec![0x77u8; 20])),
        (Value::Text("require_touch".into()), Value::Bool(false)),
    ];
    let (st, resp_bytes) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(cfg_payload)),
        300,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    let resp_val: Value = ciborium::from_reader(&resp_bytes[..]).unwrap();
    assert_eq!(
        get_field(resp_val.as_map().unwrap(), "status"),
        Some(&Value::Text("slot_configured".into()))
    );

    // 3. Challenge on slot 2
    let chal_payload = vec![
        (
            Value::Text("action".into()),
            Value::Text("keepassxc_challenge".into()),
        ),
        (Value::Text("slot".into()), Value::from(2)),
        (
            Value::Text("challenge".into()),
            Value::Bytes(b"MySecretKeePassChallenge".to_vec()),
        ),
    ];
    let (st, resp_bytes) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(chal_payload)),
        400,
        &mut rng,
    );
    assert_eq!(st, 0x00);
    let resp_val: Value = ciborium::from_reader(&resp_bytes[..]).unwrap();
    assert_eq!(
        get_field(resp_val.as_map().unwrap(), "status"),
        Some(&Value::Text("challenge_response_ok".into()))
    );
    let resp_hmac =
        extract_bytes(get_field(resp_val.as_map().unwrap(), "response").unwrap()).unwrap();
    assert_eq!(resp_hmac.len(), 20);

    // 4. When locked, challenge is rejected
    let (st_lock, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_LOCK,
        &[],
        500,
        &mut rng,
    );
    assert_eq!(st_lock, 0x00);
    assert!(!engine.is_unlocked());

    let (st_chal_locked, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(vec![
            (
                Value::Text("action".into()),
                Value::Text("keepassxc_challenge".into()),
            ),
            (Value::Text("slot".into()), Value::from(2)),
            (
                Value::Text("challenge".into()),
                Value::Bytes(b"MySecretKeePassChallenge".to_vec()),
            ),
        ])),
        600,
        &mut rng,
    );
    assert_eq!(st_chal_locked, CTAP2_ERR_PIN_REQUIRED);
}

#[test]
fn test_register_ble_proximity_and_rssi_update_cbor() {
    let mut rng = rand::rng();
    let mut storage = test_storage();
    let mut engine = SecureGuardEngine::new(SecureGuardPolicy::default());
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();

    // 1. Provision and Unlock
    let prov_payload = vec![
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
        &to_cbor_bytes(&Value::Map(prov_payload)),
        100,
        &mut rng,
    );
    assert_eq!(st, 0x00);

    let unl_payload = vec![
        (Value::Text("action".into()), Value::Text("unlock".into())),
        (Value::Text("pin".into()), Value::Bytes(b"4927".to_vec())),
    ];
    let (st_unl, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(unl_payload)),
        150,
        &mut rng,
    );
    assert_eq!(st_unl, 0x00);
    assert!(engine.is_unlocked());

    // 2. Register Bluetooth device
    let reg_payload = vec![
        (
            Value::Text("action".into()),
            Value::Text("register_ble_proximity".into()),
        ),
        (
            Value::Text("mac".into()),
            Value::Text("AA:BB:CC:DD:EE:FF".into()),
        ),
        (Value::Text("name".into()), Value::Text("Galaxy S24".into())),
    ];
    let (st_reg, resp_reg) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(reg_payload)),
        200,
        &mut rng,
    );
    assert_eq!(st_reg, 0x00);
    let resp_val: Value = ciborium::from_reader(&resp_reg[..]).unwrap();
    assert_eq!(
        get_field(resp_val.as_map().unwrap(), "status"),
        Some(&Value::Text("ble_proximity_registered".into()))
    );
    assert!(engine.ble_proximity_registered());
    assert_eq!(
        engine.paired_ble_mac(),
        &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
    );

    // 3. Status includes BLE registration info
    let (st_st, resp_st) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_STATUS,
        &[],
        250,
        &mut rng,
    );
    assert_eq!(st_st, 0x00);
    let st_val: Value = ciborium::from_reader(&resp_st[..]).unwrap();
    assert_eq!(
        get_field(st_val.as_map().unwrap(), "ble_proximity_registered"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        get_field(st_val.as_map().unwrap(), "paired_ble_name"),
        Some(&Value::Text("Galaxy S24".into()))
    );
    assert_eq!(
        get_field(st_val.as_map().unwrap(), "device_ble_mac"),
        Some(&Value::Bytes(vec![0x3C, 0x84, 0x27, 0xC7, 0x17, 0x78]))
    );
    assert_eq!(
        get_field(st_val.as_map().unwrap(), "device_ble_name"),
        Some(&Value::Text("AegisKey".into()))
    );

    // 4. Update RSSI: away -> Locks session immediately!
    let away_payload = vec![
        (
            Value::Text("action".into()),
            Value::Text("update_ble_rssi".into()),
        ),
        (Value::Text("rssi".into()), Value::from(-92)),
        (Value::Text("is_away".into()), Value::Bool(true)),
    ];
    let (st_away, resp_away) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut key_mgr,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor_bytes(&Value::Map(away_payload)),
        300,
        &mut rng,
    );
    assert_eq!(st_away, 0x00);
    let away_val: Value = ciborium::from_reader(&resp_away[..]).unwrap();
    assert_eq!(
        get_field(away_val.as_map().unwrap(), "locked"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        get_field(away_val.as_map().unwrap(), "unlocked"),
        Some(&Value::Bool(false))
    );
    assert!(!engine.is_unlocked());
    assert_eq!(engine.state(), SecureGuardState::Locked);
}
