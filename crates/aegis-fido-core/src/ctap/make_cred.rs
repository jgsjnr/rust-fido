use alloc::string::String;
use alloc::vec::Vec;
use ciborium::value::Value;
use rand_core::{CryptoRng, RngCore};

use crate::credential::non_resident::CredentialWrapper;
use crate::credential::record::CredentialRecord;
use crate::credential::store::CredentialStore;
use crate::crypto::cose::{CoseKey, COSE_ALG_EDDSA, COSE_ALG_ES256, COSE_ALG_ES256K, COSE_ALG_ES384, COSE_ALG_ES512};
use crate::crypto::hash::sha256;
use crate::crypto::keys::FidoKeyPair;
use crate::ctap::cbor::{decode_cbor_map, encode_cbor_value, get_bytes_field, get_int_key, get_text_key};
use crate::ctap::client_pin::{ClientPinState, PIN_UV_PERM_MC};
use crate::ctap::info::AuthenticatorInfoConfig;
use crate::ctap::status_code::CtapError;
use crate::extensions::{ExtensionInputs, ExtensionOutputs, CRED_PROTECT_REQUIRED};

pub struct MakeCredentialHandler;

impl MakeCredentialHandler {
    pub fn handle<S: CredentialStore, R: RngCore + CryptoRng>(
        store: &mut S,
        wrapper: &CredentialWrapper,
        pin_state: &mut ClientPinState,
        info_config: &AuthenticatorInfoConfig,
        user_presence_confirmed: bool,
        rk_deny_policy: bool,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, CtapError> {
        let map = decode_cbor_map(payload)?;

        // 1. clientDataHash (32 bytes)
        let client_data_hash = get_bytes_field(&map, 1)?;
        if client_data_hash.len() != 32 {
            return Err(CtapError::InvalidLength);
        }

        // 2. rp (id: String, name: Option<String>)
        let rp_map = match get_int_key(&map, 2) {
            Some(Value::Map(m)) => m,
            _ => return Err(CtapError::MissingParameter),
        };
        let rp_id = match get_text_key(rp_map, "id") {
            Some(Value::Text(s)) => s.clone(),
            _ => return Err(CtapError::MissingParameter),
        };
        let rp_name = match get_text_key(rp_map, "name") {
            Some(Value::Text(s)) => Some(s.clone()),
            _ => None,
        };
        let rp_id_hash = sha256(rp_id.as_bytes());

        // 3. user (id: Vec<u8>, name: Option<String>, displayName: Option<String>)
        let user_map = match get_int_key(&map, 3) {
            Some(Value::Map(m)) => m,
            _ => return Err(CtapError::MissingParameter),
        };
        let user_id = match get_text_key(user_map, "id") {
            Some(Value::Bytes(b)) => b.clone(),
            _ => return Err(CtapError::MissingParameter),
        };
        let user_name = match get_text_key(user_map, "name") {
            Some(Value::Text(s)) => Some(s.clone()),
            _ => None,
        };
        let user_display_name = match get_text_key(user_map, "displayName") {
            Some(Value::Text(s)) => Some(s.clone()),
            _ => None,
        };

        // 4. pubKeyCredParams
        let cred_params = match get_int_key(&map, 4) {
            Some(Value::Array(a)) => a,
            _ => return Err(CtapError::MissingParameter),
        };

        // Select supported algorithm: -7, -35, -36, -47, -8
        let supported_algs = [
            COSE_ALG_ES256,
            COSE_ALG_ES384,
            COSE_ALG_ES512,
            COSE_ALG_ES256K,
            COSE_ALG_EDDSA,
        ];
        let mut selected_alg = None;
        for param in cred_params {
            if let Value::Map(pm) = param {
                if let Some(Value::Integer(alg_val)) = get_text_key(pm, "alg") {
                    let alg_i: i128 = (*alg_val).into();
                    let alg = alg_i as i32;
                    if supported_algs.contains(&alg) {
                        selected_alg = Some(alg);
                        break;
                    }
                }
            }
        }
        let alg = selected_alg.ok_or(CtapError::UnsupportedAlgorithm)?;

        // 5. excludeList check
        if let Some(Value::Array(exclude_list)) = get_int_key(&map, 5) {
            for item in exclude_list {
                if let Value::Map(im) = item {
                    if let Some(Value::Bytes(cred_id)) = get_text_key(im, "id") {
                        if store.get(cred_id).is_some() || wrapper.unwrap(cred_id, &rp_id).is_ok() {
                            return Err(CtapError::CredentialExcluded);
                        }
                    }
                }
            }
        }

        // 6. options
        let mut rk_requested = false;
        let mut uv_requested = false;
        if let Some(Value::Map(opt_map)) = get_int_key(&map, 7) {
            if let Some(Value::Bool(rk)) = get_text_key(opt_map, "rk") {
                rk_requested = *rk;
            }
            if let Some(Value::Bool(uv)) = get_text_key(opt_map, "uv") {
                uv_requested = *uv;
            }
        }

        if rk_deny_policy && rk_requested {
            return Err(CtapError::OperationDenied);
        }

        // 7. extensions
        let ext_inputs = match get_int_key(&map, 6) {
            Some(v) => ExtensionInputs::parse(v),
            None => ExtensionInputs::default(),
        };

        let mut uv_required = uv_requested;
        if let Some(cp) = ext_inputs.cred_protect {
            if cp == CRED_PROTECT_REQUIRED {
                uv_required = true;
            }
        }

        // 8. User Verification & User Presence
        let mut uv_success = false;
        let pin_auth_opt = match get_int_key(&map, 8) {
            Some(Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        };
        let proto_opt = match get_int_key(&map, 9) {
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
                PIN_UV_PERM_MC,
                Some(&rp_id),
            )?;
            uv_success = true;
        } else if uv_required {
            if pin_state.is_pin_set() {
                return Err(CtapError::PinRequired);
            } else if let Some(cp) = ext_inputs.cred_protect {
                if cp == CRED_PROTECT_REQUIRED {
                    return Err(CtapError::PinNotSet);
                }
            }
        }

        if !user_presence_confirmed {
            return Err(CtapError::OperationDenied);
        }

        // 9. Generate Key Pair
        let key_pair = FidoKeyPair::generate(alg, rng).map_err(|_| CtapError::Processing)?;
        let priv_bytes = key_pair.private_key_bytes();
        let cose_key = key_pair.to_cose_key();
        let cose_bytes = cose_key.to_cbor_bytes();

        // 10. Process extension outputs
        let mut ext_outputs = ExtensionOutputs::default();
        let mut hmac_secret_key = None;
        if ext_inputs.hmac_secret_make_cred {
            let mut sec = [0u8; 32];
            rng.fill_bytes(&mut sec);
            hmac_secret_key = Some(sec);
            ext_outputs.hmac_secret_make_cred = true;
        }

        let mut large_blob_key = None;
        if ext_inputs.large_blob_key_requested {
            let mut lb_input = Vec::new();
            lb_input.extend_from_slice(&priv_bytes);
            lb_input.extend_from_slice(b"largeBlobKey");
            large_blob_key = Some(sha256(&lb_input));
            ext_outputs.large_blob_key = large_blob_key.map(|k| k.to_vec());
        }

        if let Some(ref blob) = ext_inputs.cred_blob {
            ext_outputs.cred_blob = Some(blob.clone());
        }

        if let Some(cp) = ext_inputs.cred_protect {
            ext_outputs.cred_protect = Some(cp);
        }

        let mut record = CredentialRecord {
            id: Vec::new(),
            rp_id: rp_id.clone(),
            rp_name,
            user_id,
            user_name,
            user_display_name,
            algorithm: alg,
            private_key: priv_bytes,
            public_key_cose: cose_bytes.clone(),
            sign_count: 0,
            is_resident: rk_requested,
            created_at: 0,
            expires_at: None,
            is_revoked: false,
            cred_protect: ext_inputs.cred_protect,
            large_blob_key,
            cred_blob: ext_inputs.cred_blob,
            hmac_secret_key,
        };

        if rk_requested {
            let mut cred_id = [0u8; 16];
            rng.fill_bytes(&mut cred_id);
            record.id = cred_id.to_vec();
            store.save(record.clone()).map_err(|_| CtapError::KeyStoreFull)?;
        } else {
            let wrapped_id = wrapper.wrap(&record, rng).map_err(|_| CtapError::Processing)?;
            record.id = wrapped_id;
        }

        // 11. Construct authData
        let mut flags: u8 = 0x01; // UP (User Present)
        if uv_success {
            flags |= 0x04; // UV (User Verified)
        }
        flags |= 0x40; // AT (Attested credential data present)

        let ext_cbor_bytes = ext_outputs.to_cbor_bytes();
        if ext_cbor_bytes.is_some() {
            flags |= 0x80; // ED (Extension data included)
        }

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&0u32.to_be_bytes()); // sign count = 0

        // Attested Credential Data
        auth_data.extend_from_slice(&info_config.aaguid);
        auth_data.extend_from_slice(&(record.id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&record.id);
        auth_data.extend_from_slice(&cose_bytes);

        // Extensions data
        if let Some(ext_bytes) = ext_cbor_bytes {
            auth_data.extend_from_slice(&ext_bytes);
        }

        // 12. Create Attestation Object (Official AegisKey S3 Batch Attestation / packed with x5c)
        let mut to_sign = Vec::with_capacity(auth_data.len() + client_data_hash.len());
        to_sign.extend_from_slice(&auth_data);
        to_sign.extend_from_slice(&client_data_hash);
        let att_sig = crate::ctap::attestation::sign_batch_attestation(&to_sign);

        let mut att_stmt = Vec::new();
        att_stmt.push((Value::Text(String::from("alg")), Value::Integer((-7i64).into())));
        att_stmt.push((Value::Text(String::from("sig")), Value::Bytes(att_sig)));
        let x5c_arr = vec![Value::Bytes(crate::ctap::attestation::AEGIS_ATTESTATION_CERT_DER.to_vec())];
        att_stmt.push((Value::Text(String::from("x5c")), Value::Array(x5c_arr)));

        // Standard CTAP 2.0 / 2.1 response structure:
        // 0x01: fmt (text string)
        // 0x02: authData (byte string)
        // 0x03: attStmt (map)
        // 0x05: largeBlobKey (byte string, optional)
        let mut resp = Vec::new();
        resp.push((Value::Integer(1.into()), Value::Text(String::from("packed"))));
        resp.push((Value::Integer(2.into()), Value::Bytes(auth_data)));
        resp.push((Value::Integer(3.into()), Value::Map(att_stmt)));
        if let Some(lb_key) = ext_outputs.large_blob_key {
            resp.push((Value::Integer(5.into()), Value::Bytes(lb_key)));
        }

        encode_cbor_value(&Value::Map(resp))
    }
}
