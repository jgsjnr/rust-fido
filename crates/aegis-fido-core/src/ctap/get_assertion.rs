use alloc::string::String;
use alloc::vec::Vec;
use ciborium::value::Value;
use rand_core::CryptoRng;
use zeroize::Zeroize;

use crate::credential::non_resident::CredentialWrapper;
use crate::credential::record::CredentialRecord;
use crate::credential::store::CredentialStore;
use crate::crypto::hash::{hmac_sha256, sha256};
use crate::crypto::keys::FidoKeyPair;
use crate::crypto::pin_protocol::{PinProtocol1, PinProtocol2};
use crate::ctap::cbor::{
    decode_cbor_map, encode_cbor_value, get_bytes_field, get_int_key, get_text_key,
};
use crate::ctap::client_pin::{ClientPinState, PIN_UV_PERM_GA};
use crate::ctap::status_code::CtapError;
use crate::extensions::{
    ExtensionInputs, ExtensionOutputs, CRED_PROTECT_OPTIONAL_WITH_LIST, CRED_PROTECT_REQUIRED,
};

#[derive(Default)]
pub struct GetAssertionState {
    pub pending_assertions: Vec<CredentialRecord>,
    pub current_idx: usize,
    pub cached_client_data_hash: Vec<u8>,
    pub cached_rp_id_hash: [u8; 32],
    pub cached_uv_success: bool,
}

pub struct GetAssertionHandler;

impl GetAssertionHandler {
    pub fn handle<S: CredentialStore, R: CryptoRng>(
        store: &mut S,
        wrapper: &CredentialWrapper,
        pin_state: &mut ClientPinState,
        assertion_state: &mut GetAssertionState,
        user_presence_confirmed: bool,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, CtapError> {
        let map = decode_cbor_map(payload)?;

        // 1. rpId
        let rp_id = match get_int_key(&map, 1) {
            Some(Value::Text(s)) => s.clone(),
            _ => return Err(CtapError::MissingParameter),
        };
        let rp_id_hash = sha256(rp_id.as_bytes());

        // 2. clientDataHash
        let client_data_hash = get_bytes_field(&map, 2)?;
        if client_data_hash.len() != 32 {
            return Err(CtapError::InvalidLength);
        }

        // 3. allowList
        let mut candidates = Vec::new();
        let mut had_allow_list = false;

        if let Some(Value::Array(allow_list)) = get_int_key(&map, 3) {
            had_allow_list = !allow_list.is_empty();
            for item in allow_list {
                if let Value::Map(im) = item {
                    if let Some(Value::Bytes(cred_id)) = get_text_key(im, "id") {
                        if let Some(res_cred) = store.get(cred_id) {
                            if res_cred.rp_id == rp_id {
                                candidates.push(res_cred.clone());
                            }
                        } else if let Ok(non_res_cred) = wrapper.unwrap(
                            cred_id,
                            &rp_id,
                            store.get_persistent_sign_count(cred_id),
                        ) {
                            candidates.push(non_res_cred);
                        }
                    }
                }
            }
        }

        if !had_allow_list {
            // Find all resident credentials for this RP
            let res_creds = store.find_by_rp_id(&rp_id);
            for cred in res_creds {
                candidates.push(cred.clone());
            }
        }

        if candidates.is_empty() {
            return Err(CtapError::NoCredentials);
        }

        // 4. options
        let mut uv_requested = false;
        if let Some(Value::Map(opt_map)) = get_int_key(&map, 5) {
            if let Some(Value::Bool(uv)) = get_text_key(opt_map, "uv") {
                uv_requested = *uv;
            }
        }

        // 5. extensions
        let ext_inputs = match get_int_key(&map, 4) {
            Some(v) => ExtensionInputs::parse(v),
            None => ExtensionInputs::default(),
        };

        // 6. User Verification
        let first_cand = &candidates[0];
        let mut uv_required = uv_requested;
        if let Some(cp) = first_cand.cred_protect {
            if cp == CRED_PROTECT_REQUIRED
                || (cp == CRED_PROTECT_OPTIONAL_WITH_LIST && !had_allow_list)
            {
                uv_required = true;
            }
        }

        let mut uv_success = false;
        let pin_auth_opt = match get_int_key(&map, 6) {
            Some(Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        };
        let proto_opt = match get_int_key(&map, 7) {
            Some(Value::Integer(i)) => {
                let p: i128 = (*i).into();
                Some(p as u32)
            }
            _ => None,
        };

        if let (Some(pin_auth), Some(proto)) = (pin_auth_opt, proto_opt) {
            pin_state.verify_token_permission(
                &pin_auth,
                &client_data_hash,
                proto,
                PIN_UV_PERM_GA,
                Some(&rp_id),
            )?;
            uv_success = true;
        } else if uv_required {
            if pin_state.is_pin_set() {
                return Err(CtapError::PinRequired);
            } else if let Some(cp) = first_cand.cred_protect {
                if cp == CRED_PROTECT_REQUIRED {
                    return Err(CtapError::PinNotSet);
                }
            }
        }

        // 7. User Presence
        if !user_presence_confirmed {
            return Err(CtapError::OperationDenied);
        }

        // Save remaining candidates if more than 1
        let total_candidates = candidates.len();
        assertion_state.pending_assertions = candidates;
        assertion_state.current_idx = 0;
        assertion_state.cached_client_data_hash = client_data_hash.clone();
        assertion_state.cached_rp_id_hash = rp_id_hash;
        assertion_state.cached_uv_success = uv_success;

        Self::format_assertion_response(
            store,
            Some(pin_state),
            assertion_state,
            &ext_inputs,
            total_candidates,
            rng,
        )
    }

    pub fn handle_next<S: CredentialStore, R: CryptoRng>(
        store: &mut S,
        assertion_state: &mut GetAssertionState,
        rng: &mut R,
    ) -> Result<Vec<u8>, CtapError> {
        assertion_state.current_idx += 1;
        if assertion_state.current_idx >= assertion_state.pending_assertions.len() {
            return Err(CtapError::NoCredentials);
        }

        let total = assertion_state.pending_assertions.len();
        let dummy_ext = ExtensionInputs::default();
        Self::format_assertion_response(store, None, assertion_state, &dummy_ext, total, rng)
    }

    fn format_assertion_response<S: CredentialStore, R: CryptoRng>(
        store: &mut S,
        pin_state: Option<&ClientPinState>,
        state: &mut GetAssertionState,
        ext_inputs: &ExtensionInputs,
        total_candidates: usize,
        rng: &mut R,
    ) -> Result<Vec<u8>, CtapError> {
        let cred = &state.pending_assertions[state.current_idx];

        // Increment counter if stored
        let mut sign_count = cred.sign_count;
        if cred.is_resident {
            if let Ok(c) = store.increment_sign_count(&cred.id) {
                sign_count = c;
            }
        } else if let Ok(c) = store.increment_sign_count(&cred.id) {
            sign_count = c;
        } else {
            sign_count = sign_count.saturating_add(1);
        }

        // Process extension outputs
        let mut ext_outputs = ExtensionOutputs::default();

        // 1. hmac-secret (PRF)
        if let Some(ref hmac_in) = ext_inputs.hmac_secret_get_assertion {
            if let Some(ref cred_hmac_key) = cred.hmac_secret_key {
                let ps = pin_state.ok_or(CtapError::PinAuthInvalid)?;
                let ecdh = ps
                    .key_agreement
                    .as_ref()
                    .or(ps.ephemeral_key.as_ref())
                    .ok_or(CtapError::PinAuthInvalid)?;
                let mut shared_secret = ecdh
                    .compute_shared_secret(&hmac_in.key_agreement)
                    .map_err(|_| CtapError::InvalidParameter)?;

                // Validate salt_auth if provided
                if !hmac_in.salt_auth.is_empty() {
                    let valid_auth = match hmac_in.pin_uv_protocol {
                        1 => {
                            let k = PinProtocol1::kdf(&shared_secret);
                            let expected = PinProtocol1::authenticate(&k, &hmac_in.salt_enc);
                            crate::oath::crypto::constant_time_eq(&hmac_in.salt_auth, &expected)
                        }
                        2 => {
                            let (_e_ks, m_ks) = PinProtocol2::kdf(&shared_secret);
                            let expected = PinProtocol2::authenticate(&m_ks, &hmac_in.salt_enc);
                            if hmac_in.salt_auth.len() == 16 {
                                crate::oath::crypto::constant_time_eq(&hmac_in.salt_auth, &expected[..16])
                            } else {
                                crate::oath::crypto::constant_time_eq(&hmac_in.salt_auth, &expected)
                            }
                        }
                        _ => {
                            shared_secret.zeroize();
                            return Err(CtapError::InvalidParameter);
                        }
                    };
                    if !valid_auth {
                        shared_secret.zeroize();
                        return Err(CtapError::PinAuthInvalid);
                    }
                }

                let mut decrypted_salts = match hmac_in.pin_uv_protocol {
                    1 => {
                        let k = PinProtocol1::kdf(&shared_secret);
                        PinProtocol1::decrypt(&k, &hmac_in.salt_enc).map_err(|_| {
                            shared_secret.zeroize();
                            CtapError::PinAuthInvalid
                        })?
                    }
                    2 => {
                        let (e_ks, _m_ks) = PinProtocol2::kdf(&shared_secret);
                        PinProtocol2::decrypt(&e_ks, &hmac_in.salt_enc).map_err(|_| {
                            shared_secret.zeroize();
                            CtapError::PinAuthInvalid
                        })?
                    }
                    _ => {
                        shared_secret.zeroize();
                        return Err(CtapError::InvalidParameter);
                    }
                };

                if decrypted_salts.len() >= 32 {
                    let salt1 = &decrypted_salts[..32];
                    let out1 = hmac_sha256(cred_hmac_key, salt1);
                    let mut prf_output = out1.to_vec();

                    if decrypted_salts.len() >= 64 {
                        let salt2 = &decrypted_salts[32..64];
                        let out2 = hmac_sha256(cred_hmac_key, salt2);
                        prf_output.extend_from_slice(&out2);
                    }

                    let enc_output = match hmac_in.pin_uv_protocol {
                        1 => {
                            let k = PinProtocol1::kdf(&shared_secret);
                            PinProtocol1::encrypt(&k, &prf_output)
                        }
                        2 => {
                            let (e_ks, _m_ks) = PinProtocol2::kdf(&shared_secret);
                            let mut iv = [0u8; 16];
                            rng.fill_bytes(&mut iv);
                            PinProtocol2::encrypt(&e_ks, &iv, &prf_output)
                        }
                        _ => {
                            prf_output.zeroize();
                            decrypted_salts.zeroize();
                            shared_secret.zeroize();
                            return Err(CtapError::InvalidParameter);
                        }
                    };

                    prf_output.zeroize();
                    ext_outputs.hmac_secret_output_enc = Some(enc_output);
                }
                decrypted_salts.zeroize();
                shared_secret.zeroize();
            }
        }

        // 2. credBlob
        if ext_inputs.cred_blob_requested {
            if let Some(ref blob) = cred.cred_blob {
                ext_outputs.cred_blob = Some(blob.clone());
            }
        }

        // 3. largeBlobKey
        if ext_inputs.large_blob_key_requested {
            if let Some(ref lb_key) = cred.large_blob_key {
                ext_outputs.large_blob_key = Some(lb_key.to_vec());
            }
        }

        // 4. uvm
        if ext_inputs.uvm_requested {
            ext_outputs.uvm = Some(vec![vec![0x02, 0x01, 0x01]]);
        }

        // Construct authData
        let mut flags: u8 = 0x01; // UP
        if state.cached_uv_success {
            flags |= 0x04; // UV
        }

        let ext_cbor_bytes = ext_outputs.to_cbor_bytes();
        if ext_cbor_bytes.is_some() {
            flags |= 0x80; // ED
        }

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&state.cached_rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());

        if let Some(ext_bytes) = ext_cbor_bytes {
            auth_data.extend_from_slice(&ext_bytes);
        }

        // Digital signature
        let mut to_sign = Vec::with_capacity(auth_data.len() + state.cached_client_data_hash.len());
        to_sign.extend_from_slice(&auth_data);
        to_sign.extend_from_slice(&state.cached_client_data_hash);

        let key_pair = FidoKeyPair::from_private_bytes(cred.algorithm, &cred.private_key)
            .map_err(|_| CtapError::Processing)?;
        let sig = key_pair.sign(&to_sign);

        // Build CBOR response map
        let mut resp = Vec::new();

        // 1: credential map
        let cred_map = vec![
            (
                Value::Text(String::from("id")),
                Value::Bytes(cred.id.clone()),
            ),
            (
                Value::Text(String::from("type")),
                Value::Text(String::from("public-key")),
            ),
        ];
        resp.push((Value::Integer(1.into()), Value::Map(cred_map)));

        // 2: authData
        resp.push((Value::Integer(2.into()), Value::Bytes(auth_data)));

        // 3: signature
        resp.push((Value::Integer(3.into()), Value::Bytes(sig)));

        // 4: user map (if resident)
        if cred.is_resident {
            let mut user_map = vec![(
                Value::Text(String::from("id")),
                Value::Bytes(cred.user_id.clone()),
            )];
            if let Some(ref name) = cred.user_name {
                user_map.push((Value::Text(String::from("name")), Value::Text(name.clone())));
            }
            if let Some(ref disp) = cred.user_display_name {
                user_map.push((
                    Value::Text(String::from("displayName")),
                    Value::Text(disp.clone()),
                ));
            }
            resp.push((Value::Integer(4.into()), Value::Map(user_map)));
        }

        // 5: numberOfCredentials (if > 1)
        if total_candidates > 1 {
            resp.push((
                Value::Integer(5.into()),
                Value::Integer((total_candidates as i64).into()),
            ));
        }

        // 7: largeBlobKey
        if let Some(ref lb_key) = cred.large_blob_key {
            resp.push((Value::Integer(7.into()), Value::Bytes(lb_key.to_vec())));
        }

        encode_cbor_value(&Value::Map(resp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cose::CoseKey;
    use crate::crypto::ecdh::EcdhKeyAgreement;
    use crate::crypto::pin_protocol::PinProtocol1;
    use crate::ctap::cbor::{decode_cbor_map, encode_cbor_value, get_int_key};
    use crate::ctap::status_code::CTAP1_ERR_SUCCESS;
    use crate::ctap::{
        CtapEngine, CTAP_CMD_CLIENT_PIN, CTAP_CMD_GET_ASSERTION, CTAP_CMD_MAKE_CREDENTIAL,
    };

    #[test]
    fn test_keepassxc_hmac_secret_client_e2e() {
        let mut engine = CtapEngine::new([0x42u8; 32], 1000);
        let mut rng = rand::rng();

        // Step 1: Client calls authenticatorClientPIN(getKeyAgreement)
        let pin_req = vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(2.into()), Value::Integer(2.into())),
        ];
        let mut pin_pkt = vec![CTAP_CMD_CLIENT_PIN];
        pin_pkt.extend_from_slice(&encode_cbor_value(&Value::Map(pin_req)).unwrap());
        let pin_res = engine.process_packet(&pin_pkt, 1001, &mut rng);
        assert_eq!(pin_res[0], CTAP1_ERR_SUCCESS, "getKeyAgreement must succeed");

        let pin_map = decode_cbor_map(&pin_res[1..]).unwrap();
        let auth_cose_val = get_int_key(&pin_map, 1).expect("authenticatorKeyAgreement missing");
        let auth_cose = CoseKey::from_cbor_value(auth_cose_val).expect("valid COSE key");

        // Step 2: MakeCredential with {"hmac-secret": true}
        let client_data_hash = [0x55u8; 32];
        let rp_id = "keepassxc.org";
        let mc_req = vec![
            (Value::Integer(1.into()), Value::Bytes(client_data_hash.to_vec())),
            (
                Value::Integer(2.into()),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Text(rp_id.into())),
                    (Value::Text("name".into()), Value::Text("KeePassXC".into())),
                ]),
            ),
            (
                Value::Integer(3.into()),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(vec![1, 2, 3])),
                    (Value::Text("name".into()), Value::Text("user".into())),
                ]),
            ),
            (
                Value::Integer(4.into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("alg".into()), Value::Integer((-7).into())),
                ])]),
            ),
            (
                Value::Integer(6.into()),
                Value::Map(vec![(Value::Text("hmac-secret".into()), Value::Bool(true))]),
            ),
            (
                Value::Integer(7.into()),
                Value::Map(vec![(Value::Text("rk".into()), Value::Bool(true))]),
            ),
        ];
        let mut mc_pkt = vec![CTAP_CMD_MAKE_CREDENTIAL];
        mc_pkt.extend_from_slice(&encode_cbor_value(&Value::Map(mc_req)).unwrap());
        let mc_res = engine.process_packet(&mc_pkt, 1002, &mut rng);
        assert_eq!(mc_res[0], CTAP1_ERR_SUCCESS, "MakeCredential must succeed");

        let mc_map = decode_cbor_map(&mc_res[1..]).unwrap();
        let auth_data_val = get_int_key(&mc_map, 2).expect("authData missing");
        let auth_data = match auth_data_val {
            Value::Bytes(b) => b,
            _ => panic!("authData not bytes"),
        };
        let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        let cred_id = auth_data[55..55 + cred_id_len].to_vec();

        // Step 3: Client generates ephemeral ECDH pair and encrypts salt
        let client_ecdh = EcdhKeyAgreement::generate(&mut rng);
        let shared_secret = client_ecdh
            .compute_shared_secret(&auth_cose)
            .expect("client ECDH shared secret");
        let k = PinProtocol1::kdf(&shared_secret);

        let salt1 = [0xAAu8; 32];
        let salt_enc = PinProtocol1::encrypt(&k, &salt1);
        let salt_auth = PinProtocol1::authenticate(&k, &salt_enc);

        // Step 4: GetAssertion with hmac-secret extension
        let hmac_ext_val = Value::Map(vec![
            (Value::Integer(1.into()), client_ecdh.to_cose_key().to_cbor_value()),
            (Value::Integer(2.into()), Value::Bytes(salt_enc)),
            (Value::Integer(3.into()), Value::Bytes(salt_auth.to_vec())),
            (Value::Integer(4.into()), Value::Integer(1.into())),
        ]);
        let ga_req = vec![
            (Value::Integer(1.into()), Value::Text(rp_id.into())),
            (Value::Integer(2.into()), Value::Bytes(client_data_hash.to_vec())),
            (
                Value::Integer(3.into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("id".into()), Value::Bytes(cred_id)),
                ])]),
            ),
            (
                Value::Integer(4.into()),
                Value::Map(vec![(Value::Text("hmac-secret".into()), hmac_ext_val)]),
            ),
        ];
        let mut ga_pkt = vec![CTAP_CMD_GET_ASSERTION];
        ga_pkt.extend_from_slice(&encode_cbor_value(&Value::Map(ga_req)).unwrap());
        let ga_res = engine.process_packet(&ga_pkt, 1003, &mut rng);
        assert_eq!(ga_res[0], CTAP1_ERR_SUCCESS, "GetAssertion must succeed");

        let ga_map = decode_cbor_map(&ga_res[1..]).unwrap();
        let ga_auth_data_val = get_int_key(&ga_map, 2).expect("ga authData missing");
        let ga_auth_data = match ga_auth_data_val {
            Value::Bytes(b) => b,
            _ => panic!("ga authData not bytes"),
        };

        let flags = ga_auth_data[32];
        assert_ne!(flags & 0x80, 0, "Extension data bit ED must be set in flags");
        let ext_cbor = &ga_auth_data[37..];
        let ext_map = decode_cbor_map(ext_cbor).expect("extensions map decode");
        let hmac_out_enc_val = ext_map
            .iter()
            .find_map(|(k, v)| match k {
                Value::Text(s) if s == "hmac-secret" => Some(v),
                _ => None,
            })
            .expect("hmac-secret extension in authData");
        let hmac_out_enc = match hmac_out_enc_val {
            Value::Bytes(b) => b,
            _ => panic!("hmac-secret output not bytes"),
        };

        // Step 5: Client decrypts output1
        let decrypted_out = PinProtocol1::decrypt(&k, hmac_out_enc)
            .expect("client successfully decrypts hmac-secret output");
        assert_eq!(decrypted_out.len(), 32, "Decrypted output must be 32 bytes");

        // Verify the output matches authenticator's HMAC-SHA256(cred_hmac_key, salt1)
        let cred = engine
            .store
            .find_by_rp_id(rp_id)
            .into_iter()
            .next()
            .expect("credential found");
        let expected_hmac = hmac_sha256(cred.hmac_secret_key.as_ref().unwrap(), &salt1);
        assert_eq!(
            decrypted_out.as_slice(),
            &expected_hmac,
            "100% match with expected HMAC output"
        );
    }

    #[test]
    fn test_keepassxc_hmac_secret_64byte_salts() {
        let mut engine = CtapEngine::new([0x33u8; 32], 2000);
        let mut rng = rand::rng();

        // 1. Client calls getKeyAgreement
        let pin_req = vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(2.into()), Value::Integer(2.into())),
        ];
        let mut pin_pkt = vec![CTAP_CMD_CLIENT_PIN];
        pin_pkt.extend_from_slice(&encode_cbor_value(&Value::Map(pin_req)).unwrap());
        let pin_res = engine.process_packet(&pin_pkt, 2001, &mut rng);
        let pin_map = decode_cbor_map(&pin_res[1..]).unwrap();
        let auth_cose = CoseKey::from_cbor_value(get_int_key(&pin_map, 1).unwrap()).unwrap();

        // 2. MakeCredential
        let client_data_hash = [0x77u8; 32];
        let rp_id = "keepassxc.org";
        let mc_req = vec![
            (Value::Integer(1.into()), Value::Bytes(client_data_hash.to_vec())),
            (
                Value::Integer(2.into()),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Text(rp_id.into())),
                    (Value::Text("name".into()), Value::Text("KeePassXC".into())),
                ]),
            ),
            (
                Value::Integer(3.into()),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(vec![4, 5, 6])),
                    (Value::Text("name".into()), Value::Text("vault".into())),
                ]),
            ),
            (
                Value::Integer(4.into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("alg".into()), Value::Integer((-7).into())),
                ])]),
            ),
            (
                Value::Integer(6.into()),
                Value::Map(vec![(Value::Text("hmac-secret".into()), Value::Bool(true))]),
            ),
            (
                Value::Integer(7.into()),
                Value::Map(vec![(Value::Text("rk".into()), Value::Bool(true))]),
            ),
        ];
        let mut mc_pkt = vec![CTAP_CMD_MAKE_CREDENTIAL];
        mc_pkt.extend_from_slice(&encode_cbor_value(&Value::Map(mc_req)).unwrap());
        let mc_res = engine.process_packet(&mc_pkt, 2002, &mut rng);
        let mc_map = decode_cbor_map(&mc_res[1..]).unwrap();
        let auth_data = match get_int_key(&mc_map, 2).unwrap() {
            Value::Bytes(b) => b,
            _ => panic!("bytes"),
        };
        let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        let cred_id = auth_data[55..55 + cred_id_len].to_vec();

        // 3. Client ECDH & 64-byte salt encryption (two 32-byte salts)
        let client_ecdh = EcdhKeyAgreement::generate(&mut rng);
        let shared_secret = client_ecdh.compute_shared_secret(&auth_cose).unwrap();
        let k = PinProtocol1::kdf(&shared_secret);

        let salt1 = [0x11u8; 32];
        let salt2 = [0x22u8; 32];
        let mut both_salts = [0u8; 64];
        both_salts[..32].copy_from_slice(&salt1);
        both_salts[32..].copy_from_slice(&salt2);

        let salt_enc = PinProtocol1::encrypt(&k, &both_salts);
        let salt_auth = PinProtocol1::authenticate(&k, &salt_enc);

        // 4. GetAssertion
        let hmac_ext_val = Value::Map(vec![
            (Value::Integer(1.into()), client_ecdh.to_cose_key().to_cbor_value()),
            (Value::Integer(2.into()), Value::Bytes(salt_enc)),
            (Value::Integer(3.into()), Value::Bytes(salt_auth.to_vec())),
            (Value::Integer(4.into()), Value::Integer(1.into())),
        ]);
        let ga_req = vec![
            (Value::Integer(1.into()), Value::Text(rp_id.into())),
            (Value::Integer(2.into()), Value::Bytes(client_data_hash.to_vec())),
            (
                Value::Integer(3.into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("id".into()), Value::Bytes(cred_id.clone())),
                ])]),
            ),
            (
                Value::Integer(4.into()),
                Value::Map(vec![(Value::Text("hmac-secret".into()), hmac_ext_val)]),
            ),
        ];
        let mut ga_pkt = vec![CTAP_CMD_GET_ASSERTION];
        ga_pkt.extend_from_slice(&encode_cbor_value(&Value::Map(ga_req)).unwrap());
        let ga_res = engine.process_packet(&ga_pkt, 2003, &mut rng);
        assert_eq!(ga_res[0], CTAP1_ERR_SUCCESS);

        let ga_map = decode_cbor_map(&ga_res[1..]).unwrap();
        let ga_auth_data = match get_int_key(&ga_map, 2).unwrap() {
            Value::Bytes(b) => b,
            _ => panic!("bytes"),
        };
        let ext_map = decode_cbor_map(&ga_auth_data[37..]).unwrap();
        let hmac_out_enc = match ext_map.iter().find_map(|(k, v)| match k {
            Value::Text(s) if s == "hmac-secret" => Some(v),
            _ => None,
        }).unwrap() {
            Value::Bytes(b) => b,
            _ => panic!("bytes"),
        };

        let decrypted_out = PinProtocol1::decrypt(&k, hmac_out_enc).unwrap();
        assert_eq!(decrypted_out.len(), 64, "Decrypted output must be 64 bytes (output1 + output2)");

        let cred = engine.store.find_by_rp_id(rp_id).into_iter().next().unwrap();
        let expected1 = hmac_sha256(cred.hmac_secret_key.as_ref().unwrap(), &salt1);
        let expected2 = hmac_sha256(cred.hmac_secret_key.as_ref().unwrap(), &salt2);
        assert_eq!(&decrypted_out[..32], &expected1);
        assert_eq!(&decrypted_out[32..], &expected2);

        // 5. Test bad salt_auth rejection
        let bad_salt_auth = vec![0xFFu8; 16];
        let bad_ext_val = Value::Map(vec![
            (Value::Integer(1.into()), client_ecdh.to_cose_key().to_cbor_value()),
            (Value::Integer(2.into()), Value::Bytes(PinProtocol1::encrypt(&k, &salt1))),
            (Value::Integer(3.into()), Value::Bytes(bad_salt_auth)),
            (Value::Integer(4.into()), Value::Integer(1.into())),
        ]);
        let bad_ga_req = vec![
            (Value::Integer(1.into()), Value::Text(rp_id.into())),
            (Value::Integer(2.into()), Value::Bytes(client_data_hash.to_vec())),
            (
                Value::Integer(3.into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("id".into()), Value::Bytes(cred_id)),
                ])]),
            ),
            (
                Value::Integer(4.into()),
                Value::Map(vec![(Value::Text("hmac-secret".into()), bad_ext_val)]),
            ),
        ];
        let mut bad_ga_pkt = vec![CTAP_CMD_GET_ASSERTION];
        bad_ga_pkt.extend_from_slice(&encode_cbor_value(&Value::Map(bad_ga_req)).unwrap());
        let bad_res = engine.process_packet(&bad_ga_pkt, 2004, &mut rng);
        assert_ne!(bad_res[0], CTAP1_ERR_SUCCESS, "Bad saltAuth must be rejected with error status");
    }
}
