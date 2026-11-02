use super::*;
use crate::persistence::MockFlashBackend;
use aegis_fido_core::secure_guard::{SecureGuardPolicy, SecureGuardState};
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::secure_guard::{
    SecureGuardEngine, OP_SECURE_GUARD_CONFIG, OP_SECURE_GUARD_LOCK, OP_SECURE_GUARD_STATUS,
    OP_SECURE_GUARD_UNLOCK, OP_SECURE_GUARD_WIPE_SELECTIVE,
};
use aegis_fido_core::wallet::WalletStore;
use ciborium::value::Value;
use crate::persistence::SecureStorage;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x11; 32], &[0x22; 32])
    }

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
            (Value::Text("action".into()), Value::Text("provision".into())),
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
            (Value::Text("action".into()), Value::Text("shamir_split".into())),
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
            assert_eq!(get_field(&entries, "frame_size"), Some(&Value::from(1024u64)));
            let frame = get_field(&entries, "frame_bytes")
                .and_then(extract_bytes)
                .expect("frame bytes");
            assert_eq!(frame.len(), 1024);
        } else {
            panic!("not map");
        }
    }

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
            (Value::Text("action".into()), Value::Text("provision".into())),
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
        let config_map = vec![
            (Value::Text("wipe_on_5_failures".into()), Value::Bool(true)),
        ];
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
            (Value::Text("action".into()), Value::Text("provision".into())),
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
            (Value::Text("confirmation".into()), Value::Text("WIPE-CONFIRMED".into())),
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
            (Value::Text("action".into()), Value::Text("provision".into())),
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
            (Value::Text("action".into()), Value::Text("provision".into())),
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
            (Value::Text("action".into()), Value::Text("provision".into())),
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
            (Value::Text("confirmation".into()), Value::Text("WIPE-CONFIRMED".into())),
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

    #[test]
    fn test_keepassxc_slot_config_and_challenge_vendor_exec() {
        let mut rng = rand::rng();
        let mut storage = test_storage();
        let mut engine = SecureGuardEngine::new(SecureGuardPolicy { pbkdf2_iterations: 10, ..Default::default() });
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();

        // 1. Provision & Unlock
        let prov_payload = vec![
            (Value::Text("action".into()), Value::Text("provision".into())),
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
            (Value::Text("action".into()), Value::Text("keepassxc_slot_config".into())),
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
        assert_eq!(get_field(resp_val.as_map().unwrap(), "status"), Some(&Value::Text("slot_configured".into())));

        // 3. Challenge on slot 2
        let chal_payload = vec![
            (Value::Text("action".into()), Value::Text("keepassxc_challenge".into())),
            (Value::Text("slot".into()), Value::from(2)),
            (Value::Text("challenge".into()), Value::Bytes(b"MySecretKeePassChallenge".to_vec())),
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
        assert_eq!(get_field(resp_val.as_map().unwrap(), "status"), Some(&Value::Text("challenge_response_ok".into())));
        let resp_hmac = extract_bytes(get_field(resp_val.as_map().unwrap(), "response").unwrap()).unwrap();
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
                (Value::Text("action".into()), Value::Text("keepassxc_challenge".into())),
                (Value::Text("slot".into()), Value::from(2)),
                (Value::Text("challenge".into()), Value::Bytes(b"MySecretKeePassChallenge".to_vec())),
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
            (Value::Text("action".into()), Value::Text("provision".into())),
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
            (Value::Text("action".into()), Value::Text("register_ble_proximity".into())),
            (Value::Text("mac".into()), Value::Text("AA:BB:CC:DD:EE:FF".into())),
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
        assert_eq!(get_field(resp_val.as_map().unwrap(), "status"), Some(&Value::Text("ble_proximity_registered".into())));
        assert!(engine.ble_proximity_registered());
        assert_eq!(engine.paired_ble_mac(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

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
        assert_eq!(get_field(st_val.as_map().unwrap(), "ble_proximity_registered"), Some(&Value::Bool(true)));
        assert_eq!(get_field(st_val.as_map().unwrap(), "paired_ble_name"), Some(&Value::Text("Galaxy S24".into())));
        assert_eq!(get_field(st_val.as_map().unwrap(), "device_ble_mac"), Some(&Value::Bytes(vec![0x3C, 0x84, 0x27, 0xC7, 0x17, 0x78])));
        assert_eq!(get_field(st_val.as_map().unwrap(), "device_ble_name"), Some(&Value::Text("AegisKey".into())));

        // 4. Update RSSI: away -> Locks session immediately!
        let away_payload = vec![
            (Value::Text("action".into()), Value::Text("update_ble_rssi".into())),
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
        assert_eq!(get_field(away_val.as_map().unwrap(), "locked"), Some(&Value::Bool(true)));
        assert_eq!(get_field(away_val.as_map().unwrap(), "unlocked"), Some(&Value::Bool(false)));
        assert!(!engine.is_unlocked());
        assert_eq!(engine.state(), SecureGuardState::Locked);
    }

    fn change_pin_payload(current: &[u8], new_pin: &[u8]) -> Vec<u8> {
        let m = vec![
            (Value::Text("action".into()), Value::Text("change_pin".into())),
            (Value::Text("current_pin".into()), Value::Bytes(current.to_vec())),
            (Value::Text("new_pin".into()), Value::Bytes(new_pin.to_vec())),
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
        super::unlock::clear_change_pin_backoff();
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
            (Value::Text("action".into()), Value::Text("provision".into())),
            (Value::Text("pin".into()), Value::Bytes(b"5839".to_vec())),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine, &mut storage, &mut wallet, &mut key_mgr, &mut oath,
            OP_SECURE_GUARD_UNLOCK, &to_cbor_bytes(&Value::Map(prov)), 1000, &mut rng,
        );
        assert_eq!(st, 0x00);
        let _ = engine.lock_now(1001);

        // Falha #1: atraso 0 -> 0x33, sem janela armada.
        let (st1, _) = exec_secure_guard_op(
            &mut engine, &mut storage, &mut wallet, &mut key_mgr, &mut oath,
            OP_SECURE_GUARD_UNLOCK, &change_pin_payload(b"0000", b"9999"), 2000, &mut rng,
        );
        assert_eq!(st1, CTAP2_ERR_PIN_AUTH_INVALID);
        assert_eq!(engine.failed_attempts(), 1);
        assert_eq!(super::unlock::change_pin_backoff_until_ms(), 0);

        // Falha #2: atraso 2000 (mesma tabela do unlock) -> 0x36 + janela ate 4100.
        let (st2, body2) = exec_secure_guard_op(
            &mut engine, &mut storage, &mut wallet, &mut key_mgr, &mut oath,
            OP_SECURE_GUARD_UNLOCK, &change_pin_payload(b"0000", b"9999"), 2100, &mut rng,
        );
        assert_eq!(st2, CTAP2_ERR_PIN_REQUIRED);
        assert_eq!(engine.failed_attempts(), 2);
        assert_eq!(super::unlock::change_pin_backoff_until_ms(), 4100);
        let v2: Value = ciborium::from_reader(body2.as_slice()).expect("cbor");
        assert_eq!(
            get_field(v2.as_map().expect("map"), "rate_limit_remaining_ms"),
            Some(&Value::from(2000u64)),
        );

        // PIN correto DENTRO da janela: negado sem oraculo (contador intacto).
        let (st3, _) = exec_secure_guard_op(
            &mut engine, &mut storage, &mut wallet, &mut key_mgr, &mut oath,
            OP_SECURE_GUARD_UNLOCK, &change_pin_payload(b"5839", b"1234"), 2200, &mut rng,
        );
        assert_eq!(st3, CTAP2_ERR_PIN_REQUIRED);
        assert_eq!(engine.failed_attempts(), 2);

        // Janela vencida: troca com PIN correto e limpa a janela.
        let (st4, _) = exec_secure_guard_op(
            &mut engine, &mut storage, &mut wallet, &mut key_mgr, &mut oath,
            OP_SECURE_GUARD_UNLOCK, &change_pin_payload(b"5839", b"1234"), 4200, &mut rng,
        );
        assert_eq!(st4, 0x00);
        assert_eq!(engine.failed_attempts(), 0);
        assert_eq!(super::unlock::change_pin_backoff_until_ms(), 0);

        // Janela do engine (via unlock) tambem fecha o change_pin sem oraculo.
        let _ = engine.lock_now(4201);
        let (u1, _) = exec_secure_guard_op(
            &mut engine, &mut storage, &mut wallet, &mut key_mgr, &mut oath,
            OP_SECURE_GUARD_UNLOCK, &unlock_payload(b"0000"), 5000, &mut rng,
        );
        assert_eq!(u1, CTAP2_ERR_PIN_REQUIRED);
        assert_eq!(engine.failed_attempts(), 1);
        let (u2, _) = exec_secure_guard_op(
            &mut engine, &mut storage, &mut wallet, &mut key_mgr, &mut oath,
            OP_SECURE_GUARD_UNLOCK, &unlock_payload(b"0000"), 5100, &mut rng,
        );
        assert_eq!(u2, CTAP2_ERR_PIN_REQUIRED);
        assert_eq!(engine.failed_attempts(), 2);
        assert_eq!(engine.state(), SecureGuardState::RateLimited);
        let (st5, _) = exec_secure_guard_op(
            &mut engine, &mut storage, &mut wallet, &mut key_mgr, &mut oath,
            OP_SECURE_GUARD_UNLOCK, &change_pin_payload(b"1234", b"5678"), 5200, &mut rng,
        );
        assert_eq!(st5, CTAP2_ERR_PIN_REQUIRED);
        assert_eq!(engine.failed_attempts(), 2);
        super::unlock::clear_change_pin_backoff();
    }
