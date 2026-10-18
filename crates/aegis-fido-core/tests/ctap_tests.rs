use aegis_fido_core::crypto::cose::{
    CoseKey, COSE_ALG_EDDSA, COSE_ALG_ES256, COSE_ALG_ES256K, COSE_ALG_ES384, COSE_ALG_ES512,
};
use aegis_fido_core::crypto::ecdh::EcdhKeyAgreement;
use aegis_fido_core::crypto::hash::sha256;
use aegis_fido_core::crypto::pin_protocol::{pad_pin, pin_hash, PinProtocol1, PinProtocol2};
use aegis_fido_core::ctap::cbor::{decode_cbor_map, encode_cbor_value, get_int_key, get_text_key};
use aegis_fido_core::ctap::client_pin::*;
use aegis_fido_core::ctap::cred_mgmt::*;
use aegis_fido_core::ctap::config::*;
use aegis_fido_core::ctap::status_code::*;
use aegis_fido_core::ctap::*;
use ciborium::value::Value;
use rand::RngCore;

fn test_engine() -> CtapEngine {
    let master_key = [0x42u8; 32];
    CtapEngine::new(master_key, 1000)
}

#[test]
fn test_get_info() {
    let mut engine = test_engine();
    let mut rng = rand::thread_rng();

    let res = engine.process_packet(&[CTAP_CMD_GET_INFO], 1001, &mut rng);
    assert_eq!(res[0], CTAP1_ERR_SUCCESS);

    let map = decode_cbor_map(&res[1..]).expect("CBOR decode failed");

    // 1. Check versions
    let versions = get_int_key(&map, 1).expect("versions missing");
    if let Value::Array(v) = versions {
        let list: Vec<String> = v
            .iter()
            .map(|x| match x {
                Value::Text(s) => s.clone(),
                _ => String::new(),
            })
            .collect();
        assert!(list.contains(&"FIDO_2_0".into()));
        assert!(list.contains(&"FIDO_2_1".into()));
        assert!(list.contains(&"FIDO_2_1_PRE".into()));
        assert!(list.contains(&"U2F_V2".into()));
    } else {
        panic!("versions not an array");
    }

    // 2. Check extensions
    let extensions = get_int_key(&map, 2).expect("extensions missing");
    if let Value::Array(exts) = extensions {
        let list: Vec<String> = exts
            .iter()
            .map(|x| match x {
                Value::Text(s) => s.clone(),
                _ => String::new(),
            })
            .collect();
        assert!(list.contains(&"credProtect".into()));
        assert!(list.contains(&"hmac-secret".into()));
        assert!(list.contains(&"credBlobs".into()));
        assert!(list.contains(&"largeBlobKey".into()));
        assert!(list.contains(&"minPinLength".into()));
        assert!(list.contains(&"pinComplexity".into()));
        assert!(list.contains(&"uvm".into()));
        assert!(list.contains(&"thirdPartyPayment".into()));
    } else {
        panic!("extensions not an array");
    }

    // 3. Check AAGUID
    let aaguid = get_int_key(&map, 3).expect("aaguid missing");
    if let Value::Bytes(b) = aaguid {
        assert_eq!(
            b.as_slice(),
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f
            ]
        );
    } else {
        panic!("aaguid not bytes");
    }

    // 4. Check options
    let options = get_int_key(&map, 4).expect("options missing");
    if let Value::Map(opts) = options {
        assert_eq!(get_text_key(opts, "plat"), Some(&Value::Bool(false)));
        assert_eq!(get_text_key(opts, "rk"), Some(&Value::Bool(true)));
        assert_eq!(get_text_key(opts, "clientPin"), Some(&Value::Bool(false)));
        assert_eq!(get_text_key(opts, "up"), Some(&Value::Bool(true)));
        assert_eq!(get_text_key(opts, "uv"), Some(&Value::Bool(true)));
        assert_eq!(get_text_key(opts, "pinUvAuthToken"), Some(&Value::Bool(true)));
        assert_eq!(
            get_text_key(opts, "noMcGaPermissionsWithClientPin"),
            Some(&Value::Bool(true))
        );
        assert_eq!(get_text_key(opts, "largeBlobs"), Some(&Value::Bool(true)));
        assert_eq!(get_text_key(opts, "userPresence"), Some(&Value::Bool(true)));
        assert_eq!(get_text_key(opts, "credMgmt"), Some(&Value::Bool(true)));
        assert_eq!(get_text_key(opts, "authnrCfg"), Some(&Value::Bool(true)));
        assert_eq!(get_text_key(opts, "uvBioEnroll"), Some(&Value::Bool(false)));
        assert_eq!(get_text_key(opts, "alwaysUv"), Some(&Value::Bool(false)));
        assert_eq!(
            get_text_key(opts, "setMinPINLength"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            get_text_key(opts, "makeCredUvNotRqd"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            get_text_key(opts, "credentialMgmtPreview"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            get_text_key(opts, "userVerificationMgmtPreview"),
            Some(&Value::Bool(true))
        );
    } else {
        panic!("options not a map");
    }

    // 5. Check pinUvProtocols
    let protos = get_int_key(&map, 6).expect("pinUvProtocols missing");
    if let Value::Array(p) = protos {
        let list: Vec<i64> = p
            .iter()
            .map(|x| match x {
                Value::Integer(i) => {
                    let v: i128 = (*i).into();
                    v as i64
                }
                _ => 0,
            })
            .collect();
        assert_eq!(list, vec![1, 2]);
    } else {
        panic!("protocols not an array");
    }
}

#[test]
fn test_client_pin_protocol_1_and_2() {
    let mut engine = test_engine();
    let mut rng = rand::thread_rng();

    // 1. Get PIN retries (initially 8)
    let mut req_retries = Vec::new();
    req_retries.push((Value::Integer(1.into()), Value::Integer(1.into()))); // proto 1
    req_retries.push((
        Value::Integer(2.into()),
        Value::Integer(SUBCMD_GET_PIN_RETRIES.into()),
    ));
    let packet = encode_cbor_value(&Value::Map(req_retries)).unwrap();

    let mut full_packet = vec![CTAP_CMD_CLIENT_PIN];
    full_packet.extend_from_slice(&packet);

    let res = engine.process_packet(&full_packet, 1001, &mut rng);
    assert_eq!(res[0], CTAP1_ERR_SUCCESS);
    let map = decode_cbor_map(&res[1..]).unwrap();
    assert_eq!(get_int_key(&map, 3), Some(&Value::Integer(8.into())));

    // 2. Get Key Agreement
    let mut req_ka = Vec::new();
    req_ka.push((Value::Integer(1.into()), Value::Integer(1.into())));
    req_ka.push((
        Value::Integer(2.into()),
        Value::Integer(SUBCMD_GET_KEY_AGREEMENT.into()),
    ));
    let packet_ka = encode_cbor_value(&Value::Map(req_ka)).unwrap();

    let mut full_packet_ka = vec![CTAP_CMD_CLIENT_PIN];
    full_packet_ka.extend_from_slice(&packet_ka);

    let res_ka = engine.process_packet(&full_packet_ka, 1001, &mut rng);
    assert_eq!(res_ka[0], CTAP1_ERR_SUCCESS);
    let map_ka = decode_cbor_map(&res_ka[1..]).unwrap();
    let peer_cose_val = get_int_key(&map_ka, 1).expect("keyAgreement missing");
    let authenticator_cose = CoseKey::from_cbor_value(peer_cose_val).unwrap();

    // 3. Client sets PIN "654321" using Protocol 1
    let client_ecdh = EcdhKeyAgreement::generate(&mut rng);
    let client_cose = client_ecdh.to_cose_key();
    let shared_secret = client_ecdh
        .compute_shared_secret(&authenticator_cose)
        .unwrap();

    let key_proto1 = PinProtocol1::kdf(&shared_secret);
    let pin_padded = pad_pin(b"654321").unwrap();
    let new_pin_enc = PinProtocol1::encrypt(&key_proto1, &pin_padded);
    let pin_auth = PinProtocol1::authenticate(&key_proto1, &new_pin_enc);

    let mut set_pin_map = Vec::new();
    set_pin_map.push((Value::Integer(1.into()), Value::Integer(1.into()))); // proto 1
    set_pin_map.push((Value::Integer(2.into()), Value::Integer(SUBCMD_SET_PIN.into())));
    set_pin_map.push((Value::Integer(3.into()), client_cose.to_cbor_value()));
    set_pin_map.push((Value::Integer(4.into()), Value::Bytes(pin_auth.to_vec())));
    set_pin_map.push((Value::Integer(5.into()), Value::Bytes(new_pin_enc)));

    let packet_set = encode_cbor_value(&Value::Map(set_pin_map)).unwrap();
    let mut full_packet_set = vec![CTAP_CMD_CLIENT_PIN];
    full_packet_set.extend_from_slice(&packet_set);

    let res_set = engine.process_packet(&full_packet_set, 1001, &mut rng);
    assert_eq!(res_set[0], CTAP1_ERR_SUCCESS);
    assert!(engine.pin_state.is_pin_set());

    // 4. Get token using Protocol 2 with permissions MC and GA
    // Step 4a: Get Key Agreement for Proto 2
    let mut req_ka2 = Vec::new();
    req_ka2.push((Value::Integer(1.into()), Value::Integer(2.into()))); // proto 2
    req_ka2.push((
        Value::Integer(2.into()),
        Value::Integer(SUBCMD_GET_KEY_AGREEMENT.into()),
    ));
    let packet_ka2 = encode_cbor_value(&Value::Map(req_ka2)).unwrap();
    let mut full_packet_ka2 = vec![CTAP_CMD_CLIENT_PIN];
    full_packet_ka2.extend_from_slice(&packet_ka2);

    let res_ka2 = engine.process_packet(&full_packet_ka2, 1001, &mut rng);
    assert_eq!(res_ka2[0], CTAP1_ERR_SUCCESS);
    let map_ka2 = decode_cbor_map(&res_ka2[1..]).unwrap();
    let auth_cose2 = CoseKey::from_cbor_value(get_int_key(&map_ka2, 1).unwrap()).unwrap();

    // Step 4b: Compute shared secret & proto 2 keys
    let client_ecdh2 = EcdhKeyAgreement::generate(&mut rng);
    let client_cose2 = client_ecdh2.to_cose_key();
    let shared2 = client_ecdh2.compute_shared_secret(&auth_cose2).unwrap();
    let (e_ks2, _m_ks2) = PinProtocol2::kdf(&shared2);

    let p_hash = pin_hash(b"654321");
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);
    let pin_hash_enc = PinProtocol2::encrypt(&e_ks2, &iv, &p_hash);

    let perms = PIN_UV_PERM_MC | PIN_UV_PERM_GA;
    let mut req_token = Vec::new();
    req_token.push((Value::Integer(1.into()), Value::Integer(2.into()))); // proto 2
    req_token.push((
        Value::Integer(2.into()),
        Value::Integer(SUBCMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS.into()),
    ));
    req_token.push((Value::Integer(3.into()), client_cose2.to_cbor_value()));
    req_token.push((Value::Integer(6.into()), Value::Bytes(pin_hash_enc)));
    req_token.push((Value::Integer(9.into()), Value::Integer((perms as i64).into())));
    req_token.push((
        Value::Integer(10.into()),
        Value::Text(String::from("example.com")),
    ));

    let packet_token = encode_cbor_value(&Value::Map(req_token)).unwrap();
    let mut full_packet_token = vec![CTAP_CMD_CLIENT_PIN];
    full_packet_token.extend_from_slice(&packet_token);

    let res_token = engine.process_packet(&full_packet_token, 1001, &mut rng);
    assert_eq!(res_token[0], CTAP1_ERR_SUCCESS);
    let map_token = decode_cbor_map(&res_token[1..]).unwrap();
    let enc_token = match get_int_key(&map_token, 2).unwrap() {
        Value::Bytes(b) => b.clone(),
        _ => panic!("token not bytes"),
    };

    let token_decrypted = PinProtocol2::decrypt(&e_ks2, &enc_token).expect("Token decrypt failed");
    assert_eq!(token_decrypted.len(), 32);

    // Verify token can authorize a command
    let client_data_hash = [0x55u8; 32];
    let auth_param = PinProtocol2::authenticate(&token_decrypted, &client_data_hash);

    assert!(engine
        .pin_state
        .verify_token_permission(
            &auth_param,
            &client_data_hash,
            2,
            PIN_UV_PERM_MC,
            Some("example.com")
        )
        .is_ok());

    // Fails with unauthorized permission (e.g. Credential Management CM)
    assert_eq!(
        engine.pin_state.verify_token_permission(
            &auth_param,
            &client_data_hash,
            2,
            PIN_UV_PERM_CM,
            Some("example.com")
        ),
        Err(CtapError::UnauthorizedPermission)
    );
}

#[test]
fn test_make_credential_and_get_assertion_all_algorithms() {
    let algorithms = [
        COSE_ALG_ES256,
        COSE_ALG_ES384,
        COSE_ALG_ES512,
        COSE_ALG_ES256K,
        COSE_ALG_EDDSA,
    ];

    for &alg in &algorithms {
        let mut engine = test_engine();
        let mut rng = rand::thread_rng();

        let client_data_hash = [0x11u8; 32];

        // 1. Build MakeCredential request
        let mut req = Vec::new();
        req.push((Value::Integer(1.into()), Value::Bytes(client_data_hash.to_vec())));

        // rp
        let mut rp = Vec::new();
        rp.push((Value::Text("id".into()), Value::Text("aegiskey.dev".into())));
        rp.push((Value::Text("name".into()), Value::Text("AegisKey Dev".into())));
        req.push((Value::Integer(2.into()), Value::Map(rp)));

        // user
        let mut user = Vec::new();
        user.push((Value::Text("id".into()), Value::Bytes(vec![1, 2, 3, 4])));
        user.push((Value::Text("name".into()), Value::Text("alice".into())));
        user.push((Value::Text("displayName".into()), Value::Text("Alice Smith".into())));
        req.push((Value::Integer(3.into()), Value::Map(user)));

        // pubKeyCredParams
        let mut param = Vec::new();
        param.push((Value::Text("type".into()), Value::Text("public-key".into())));
        param.push((Value::Text("alg".into()), Value::Integer((alg as i64).into())));
        req.push((Value::Integer(4.into()), Value::Array(vec![Value::Map(param)])));

        // options: rk = true
        let mut opts = Vec::new();
        opts.push((Value::Text("rk".into()), Value::Bool(true)));
        req.push((Value::Integer(7.into()), Value::Map(opts)));

        // extensions: hmac-secret = true
        let mut exts = Vec::new();
        exts.push((Value::Text("hmac-secret".into()), Value::Bool(true)));
        req.push((Value::Integer(6.into()), Value::Map(exts)));

        let req_bytes = encode_cbor_value(&Value::Map(req)).unwrap();
        let mut packet = vec![CTAP_CMD_MAKE_CREDENTIAL];
        packet.extend_from_slice(&req_bytes);

        let res = engine.process_packet(&packet, 1001, &mut rng);
        assert_eq!(res[0], CTAP1_ERR_SUCCESS, "MakeCredential failed for alg {}", alg);

        let map = decode_cbor_map(&res[1..]).unwrap();
        let auth_data_val = get_text_key(&map, "authData").expect("authData missing");
        let auth_data = match auth_data_val {
            Value::Bytes(b) => b.clone(),
            _ => panic!("authData not bytes"),
        };

        // Extract Credential ID from authData
        // rp_id_hash (32) + flags (1) + sign_count (4) + aaguid (16) + cred_id_len (2)
        let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        let cred_id = auth_data[55..55 + cred_id_len].to_vec();

        // 2. Perform GetAssertion
        let mut ga_req = Vec::new();
        ga_req.push((Value::Integer(1.into()), Value::Text("aegiskey.dev".into())));
        ga_req.push((Value::Integer(2.into()), Value::Bytes(client_data_hash.to_vec())));

        // allowList
        let mut desc = Vec::new();
        desc.push((Value::Text("type".into()), Value::Text("public-key".into())));
        desc.push((Value::Text("id".into()), Value::Bytes(cred_id.clone())));
        ga_req.push((Value::Integer(3.into()), Value::Array(vec![Value::Map(desc)])));

        let ga_packet_bytes = encode_cbor_value(&Value::Map(ga_req)).unwrap();
        let mut ga_packet = vec![CTAP_CMD_GET_ASSERTION];
        ga_packet.extend_from_slice(&ga_packet_bytes);

        let ga_res = engine.process_packet(&ga_packet, 1001, &mut rng);
        assert_eq!(ga_res[0], CTAP1_ERR_SUCCESS, "GetAssertion failed for alg {}", alg);

        let ga_map = decode_cbor_map(&ga_res[1..]).unwrap();
        let ga_auth_data = get_int_key(&ga_map, 2).expect("authData in assertion missing");
        let ga_signature = get_int_key(&ga_map, 3).expect("signature in assertion missing");

        match (ga_auth_data, ga_signature) {
            (Value::Bytes(ad), Value::Bytes(sig)) => {
                assert!(!ad.is_empty());
                assert!(!sig.is_empty());
            }
            _ => panic!("Assertion authData or signature not bytes"),
        }
    }
}

#[test]
fn test_authenticator_reset() {
    let mut engine = test_engine();
    let mut rng = rand::thread_rng();

    // 1. Reset within 10 seconds with touch -> Success
    let res = engine.process_packet(&[CTAP_CMD_RESET], 1005, &mut rng);
    assert_eq!(res[0], CTAP1_ERR_SUCCESS);

    // 2. Reset after 10 seconds -> Fails with NotAllowed
    let res_late = engine.process_packet(&[CTAP_CMD_RESET], 1015, &mut rng);
    assert_eq!(res_late[0], CTAP2_ERR_NOT_ALLOWED);

    // 3. Reset without user touch -> Fails with OperationDenied
    engine.set_user_presence(false);
    let res_no_touch = engine.process_packet(&[CTAP_CMD_RESET], 1002, &mut rng);
    assert_eq!(res_no_touch[0], CTAP2_ERR_OPERATION_DENIED);
}

#[test]
fn test_large_blobs_read_write() {
    let mut engine = test_engine();
    let mut rng = rand::thread_rng();

    // Setup PIN & get LBW token
    let client_ecdh = EcdhKeyAgreement::generate(&mut rng);
    let ka_res = engine.process_packet(&[CTAP_CMD_CLIENT_PIN, 0xA2, 0x01, 0x01, 0x02, 0x02], 1001, &mut rng);
    let ka_map = decode_cbor_map(&ka_res[1..]).unwrap();
    let auth_cose = CoseKey::from_cbor_value(get_int_key(&ka_map, 1).unwrap()).unwrap();
    let shared = client_ecdh.compute_shared_secret(&auth_cose).unwrap();
    let k = PinProtocol1::kdf(&shared);

    let pin_enc = PinProtocol1::encrypt(&k, &pad_pin(b"4321").unwrap());
    let pin_auth = PinProtocol1::authenticate(&k, &pin_enc);

    // Set PIN
    let mut set_req = Vec::new();
    set_req.push((Value::Integer(1.into()), Value::Integer(1.into())));
    set_req.push((Value::Integer(2.into()), Value::Integer(SUBCMD_SET_PIN.into())));
    set_req.push((Value::Integer(3.into()), client_ecdh.to_cose_key().to_cbor_value()));
    set_req.push((Value::Integer(4.into()), Value::Bytes(pin_auth.to_vec())));
    set_req.push((Value::Integer(5.into()), Value::Bytes(pin_enc)));
    let p_bytes = encode_cbor_value(&Value::Map(set_req)).unwrap();
    let mut full_p = vec![CTAP_CMD_CLIENT_PIN];
    full_p.extend_from_slice(&p_bytes);
    assert_eq!(engine.process_packet(&full_p, 1001, &mut rng)[0], CTAP1_ERR_SUCCESS);

    // Get Token with LBW permission
    let p_hash_enc = PinProtocol1::encrypt(&k, &pin_hash(b"4321"));
    let mut tok_req = Vec::new();
    tok_req.push((Value::Integer(1.into()), Value::Integer(1.into())));
    tok_req.push((Value::Integer(2.into()), Value::Integer(SUBCMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS.into())));
    tok_req.push((Value::Integer(3.into()), client_ecdh.to_cose_key().to_cbor_value()));
    tok_req.push((Value::Integer(6.into()), Value::Bytes(p_hash_enc)));
    tok_req.push((Value::Integer(9.into()), Value::Integer((PIN_UV_PERM_LBW as i64).into())));
    let t_bytes = encode_cbor_value(&Value::Map(tok_req)).unwrap();
    let mut full_t = vec![CTAP_CMD_CLIENT_PIN];
    full_t.extend_from_slice(&t_bytes);
    let t_res = engine.process_packet(&full_t, 1001, &mut rng);
    assert_eq!(t_res[0], CTAP1_ERR_SUCCESS);
    let t_map = decode_cbor_map(&t_res[1..]).unwrap();
    let enc_tok = match get_int_key(&t_map, 2).unwrap() {
        Value::Bytes(b) => b.clone(),
        _ => panic!(),
    };
    let token = PinProtocol1::decrypt(&k, &enc_tok).unwrap();

    // Write Large Blob
    let blob_data = vec![0xAB; 256];
    let blob_hash = sha256(&blob_data);
    let lb_auth = PinProtocol1::authenticate(&token, &blob_hash);

    let mut set_lb = Vec::new();
    set_lb.push((Value::Integer(2.into()), Value::Bytes(blob_data.clone())));
    set_lb.push((Value::Integer(3.into()), Value::Integer(0.into()))); // offset = 0
    set_lb.push((Value::Integer(5.into()), Value::Bytes(lb_auth.to_vec())));
    set_lb.push((Value::Integer(6.into()), Value::Integer(1.into())));

    let lb_packet = encode_cbor_value(&Value::Map(set_lb)).unwrap();
    let mut full_lb = vec![CTAP_CMD_LARGE_BLOBS];
    full_lb.extend_from_slice(&lb_packet);
    assert_eq!(engine.process_packet(&full_lb, 1001, &mut rng)[0], CTAP1_ERR_SUCCESS);

    // Read Large Blob back
    let mut get_lb = Vec::new();
    get_lb.push((Value::Integer(1.into()), Value::Integer(256.into()))); // get 256 bytes
    get_lb.push((Value::Integer(3.into()), Value::Integer(0.into()))); // offset 0
    let get_lb_packet = encode_cbor_value(&Value::Map(get_lb)).unwrap();
    let mut full_get_lb = vec![CTAP_CMD_LARGE_BLOBS];
    full_get_lb.extend_from_slice(&get_lb_packet);

    let read_res = engine.process_packet(&full_get_lb, 1001, &mut rng);
    assert_eq!(read_res[0], CTAP1_ERR_SUCCESS);
    let read_map = decode_cbor_map(&read_res[1..]).unwrap();
    if let Some(Value::Bytes(b)) = get_int_key(&read_map, 1) {
        assert_eq!(b, &blob_data);
    } else {
        panic!("Large blob not returned");
    }
}

#[test]
fn test_credential_management_and_rk() {
    let mut engine = test_engine();
    let mut rng = rand::thread_rng();

    // 1. Setup PIN & get CM permission token
    let client_ecdh = EcdhKeyAgreement::generate(&mut rng);
    let ka_res = engine.process_packet(&[CTAP_CMD_CLIENT_PIN, 0xA2, 0x01, 0x01, 0x02, 0x02], 1001, &mut rng);
    let ka_map = decode_cbor_map(&ka_res[1..]).unwrap();
    let auth_cose = CoseKey::from_cbor_value(get_int_key(&ka_map, 1).unwrap()).unwrap();
    let shared = client_ecdh.compute_shared_secret(&auth_cose).unwrap();
    let k = PinProtocol1::kdf(&shared);

    let pin_enc = PinProtocol1::encrypt(&k, &pad_pin(b"987654").unwrap());
    let pin_auth = PinProtocol1::authenticate(&k, &pin_enc);

    let mut set_req = Vec::new();
    set_req.push((Value::Integer(1.into()), Value::Integer(1.into())));
    set_req.push((Value::Integer(2.into()), Value::Integer(SUBCMD_SET_PIN.into())));
    set_req.push((Value::Integer(3.into()), client_ecdh.to_cose_key().to_cbor_value()));
    set_req.push((Value::Integer(4.into()), Value::Bytes(pin_auth.to_vec())));
    set_req.push((Value::Integer(5.into()), Value::Bytes(pin_enc)));
    let p_bytes = encode_cbor_value(&Value::Map(set_req)).unwrap();
    let mut full_p = vec![CTAP_CMD_CLIENT_PIN];
    full_p.extend_from_slice(&p_bytes);
    assert_eq!(engine.process_packet(&full_p, 1001, &mut rng)[0], CTAP1_ERR_SUCCESS);

    // 2. Make Resident Credential
    let client_data_hash = [0x33u8; 32];
    let mut req = Vec::new();
    req.push((Value::Integer(1.into()), Value::Bytes(client_data_hash.to_vec())));
    let mut rp = Vec::new();
    rp.push((Value::Text("id".into()), Value::Text("example.org".into())));
    rp.push((Value::Text("name".into()), Value::Text("Example Org".into())));
    req.push((Value::Integer(2.into()), Value::Map(rp)));
    let mut user = Vec::new();
    user.push((Value::Text("id".into()), Value::Bytes(vec![9, 9, 9])));
    user.push((Value::Text("name".into()), Value::Text("bob".into())));
    req.push((Value::Integer(3.into()), Value::Map(user)));
    let mut param = Vec::new();
    param.push((Value::Text("type".into()), Value::Text("public-key".into())));
    param.push((Value::Text("alg".into()), Value::Integer((COSE_ALG_ES256 as i64).into())));
    req.push((Value::Integer(4.into()), Value::Array(vec![Value::Map(param)])));
    let mut opts = Vec::new();
    opts.push((Value::Text("rk".into()), Value::Bool(true)));
    req.push((Value::Integer(7.into()), Value::Map(opts)));

    let mc_bytes = encode_cbor_value(&Value::Map(req)).unwrap();
    let mut full_mc = vec![CTAP_CMD_MAKE_CREDENTIAL];
    full_mc.extend_from_slice(&mc_bytes);
    let mc_res = engine.process_packet(&full_mc, 1001, &mut rng);
    assert_eq!(mc_res[0], CTAP1_ERR_SUCCESS);

    // 3. Obtain Token with CM permission
    let p_hash_enc = PinProtocol1::encrypt(&k, &pin_hash(b"987654"));
    let mut tok_req = Vec::new();
    tok_req.push((Value::Integer(1.into()), Value::Integer(1.into())));
    tok_req.push((Value::Integer(2.into()), Value::Integer(SUBCMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS.into())));
    tok_req.push((Value::Integer(3.into()), client_ecdh.to_cose_key().to_cbor_value()));
    tok_req.push((Value::Integer(6.into()), Value::Bytes(p_hash_enc)));
    tok_req.push((Value::Integer(9.into()), Value::Integer((PIN_UV_PERM_CM as i64).into())));
    let t_bytes = encode_cbor_value(&Value::Map(tok_req)).unwrap();
    let mut full_t = vec![CTAP_CMD_CLIENT_PIN];
    full_t.extend_from_slice(&t_bytes);
    let t_res = engine.process_packet(&full_t, 1001, &mut rng);
    assert_eq!(t_res[0], CTAP1_ERR_SUCCESS);
    let t_map = decode_cbor_map(&t_res[1..]).unwrap();
    let enc_tok = match get_int_key(&t_map, 2).unwrap() {
        Value::Bytes(b) => b.clone(),
        _ => panic!(),
    };
    let cm_token = PinProtocol1::decrypt(&k, &enc_tok).unwrap();

    // 4. Test getCredsMetadata
    let auth_param = PinProtocol1::authenticate(&cm_token, &[SUBCMD_GET_CREDS_METADATA as u8]);
    let mut meta_req = Vec::new();
    meta_req.push((Value::Integer(1.into()), Value::Integer(SUBCMD_GET_CREDS_METADATA.into())));
    meta_req.push((Value::Integer(3.into()), Value::Integer(1.into())));
    meta_req.push((Value::Integer(4.into()), Value::Bytes(auth_param.to_vec())));

    let meta_packet = encode_cbor_value(&Value::Map(meta_req)).unwrap();
    let mut full_meta = vec![CTAP_CMD_CREDENTIAL_MANAGEMENT];
    full_meta.extend_from_slice(&meta_packet);

    let meta_res = engine.process_packet(&full_meta, 1001, &mut rng);
    assert_eq!(meta_res[0], CTAP1_ERR_SUCCESS);
    let meta_map = decode_cbor_map(&meta_res[1..]).unwrap();
    assert_eq!(get_int_key(&meta_map, 1), Some(&Value::Integer(1.into()))); // 1 resident cred

    // 5. Enumerate RPs Begin
    let auth_param_rp = PinProtocol1::authenticate(&cm_token, &[SUBCMD_ENUMERATE_RPS_BEGIN as u8]);
    let mut enum_rp_req = Vec::new();
    enum_rp_req.push((Value::Integer(1.into()), Value::Integer(SUBCMD_ENUMERATE_RPS_BEGIN.into())));
    enum_rp_req.push((Value::Integer(3.into()), Value::Integer(1.into())));
    enum_rp_req.push((Value::Integer(4.into()), Value::Bytes(auth_param_rp.to_vec())));

    let erp_packet = encode_cbor_value(&Value::Map(enum_rp_req)).unwrap();
    let mut full_erp = vec![CTAP_CMD_CREDENTIAL_MANAGEMENT];
    full_erp.extend_from_slice(&erp_packet);

    let erp_res = engine.process_packet(&full_erp, 1001, &mut rng);
    assert_eq!(erp_res[0], CTAP1_ERR_SUCCESS);
    let erp_map = decode_cbor_map(&erp_res[1..]).unwrap();
    let rp_val = get_int_key(&erp_map, 3).unwrap();
    if let Value::Map(m) = rp_val {
        assert_eq!(get_text_key(m, "id"), Some(&Value::Text("example.org".into())));
    } else {
        panic!("RP not a map");
    }
}

#[test]
fn test_rk_deny_policy() {
    let mut engine = test_engine();
    let mut rng = rand::thread_rng();

    engine.set_rk_deny_policy(true);

    let client_data_hash = [0x77u8; 32];
    let mut req = Vec::new();
    req.push((Value::Integer(1.into()), Value::Bytes(client_data_hash.to_vec())));
    let mut rp = Vec::new();
    rp.push((Value::Text("id".into()), Value::Text("deny.org".into())));
    req.push((Value::Integer(2.into()), Value::Map(rp)));
    let mut user = Vec::new();
    user.push((Value::Text("id".into()), Value::Bytes(vec![1])));
    req.push((Value::Integer(3.into()), Value::Map(user)));
    let mut param = Vec::new();
    param.push((Value::Text("type".into()), Value::Text("public-key".into())));
    param.push((Value::Text("alg".into()), Value::Integer((COSE_ALG_ES256 as i64).into())));
    req.push((Value::Integer(4.into()), Value::Array(vec![Value::Map(param)])));
    let mut opts = Vec::new();
    opts.push((Value::Text("rk".into()), Value::Bool(true)));
    req.push((Value::Integer(7.into()), Value::Map(opts)));

    let mc_bytes = encode_cbor_value(&Value::Map(req)).unwrap();
    let mut full_mc = vec![CTAP_CMD_MAKE_CREDENTIAL];
    full_mc.extend_from_slice(&mc_bytes);

    let mc_res = engine.process_packet(&full_mc, 1001, &mut rng);
    assert_eq!(mc_res[0], CTAP2_ERR_OPERATION_DENIED);
}

#[test]
fn test_authenticator_config() {
    let mut engine = test_engine();
    let mut rng = rand::thread_rng();

    // Verify initially enterprise attestation is false
    assert!(!engine.info_config.enterprise_attestation);

    // Call authenticatorConfig to enable enterprise attestation
    let mut cfg_req = Vec::new();
    cfg_req.push((Value::Integer(1.into()), Value::Integer(CONFIG_ENABLE_ENTERPRISE_ATTESTATION.into())));
    cfg_req.push((Value::Integer(3.into()), Value::Integer(1.into())));
    cfg_req.push((Value::Integer(4.into()), Value::Bytes(vec![0u8; 16])));

    let cfg_packet = encode_cbor_value(&Value::Map(cfg_req)).unwrap();
    let mut full_cfg = vec![CTAP_CMD_CONFIG];
    full_cfg.extend_from_slice(&cfg_packet);

    let cfg_res = engine.process_packet(&full_cfg, 1001, &mut rng);
    assert_eq!(cfg_res[0], CTAP1_ERR_SUCCESS);
    assert!(engine.info_config.enterprise_attestation);
}
