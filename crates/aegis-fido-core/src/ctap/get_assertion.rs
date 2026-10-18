use alloc::string::String;
use alloc::vec::Vec;
use ciborium::value::Value;
use rand_core::{CryptoRng, RngCore};

use crate::credential::non_resident::CredentialWrapper;
use crate::credential::record::CredentialRecord;
use crate::credential::store::CredentialStore;
use crate::crypto::ecdh::EcdhKeyAgreement;
use crate::crypto::hash::{hmac_sha256, sha256};
use crate::crypto::keys::FidoKeyPair;
use crate::crypto::pin_protocol::{PinProtocol1, PinProtocol2};
use crate::ctap::cbor::{decode_cbor_map, encode_cbor_value, get_bytes_field, get_int_key, get_text_key};
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
    pub fn handle<S: CredentialStore, R: RngCore + CryptoRng>(
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
                        } else if let Ok(non_res_cred) = wrapper.unwrap(cred_id, &rp_id, store.get_persistent_sign_count(cred_id)) {
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
            if cp == CRED_PROTECT_REQUIRED {
                uv_required = true;
            } else if cp == CRED_PROTECT_OPTIONAL_WITH_LIST && !had_allow_list {
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
            assertion_state,
            &ext_inputs,
            total_candidates,
            rng,
        )
    }

    pub fn handle_next<S: CredentialStore, R: RngCore + CryptoRng>(
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
        Self::format_assertion_response(store, assertion_state, &dummy_ext, total, rng)
    }

    fn format_assertion_response<S: CredentialStore, R: RngCore + CryptoRng>(
        store: &mut S,
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
                let ecdh = EcdhKeyAgreement::generate(rng);
                let shared_secret = ecdh
                    .compute_shared_secret(&hmac_in.key_agreement)
                    .map_err(|_| CtapError::InvalidParameter)?;

                let decrypted_salts = match hmac_in.pin_uv_protocol {
                    1 => {
                        let k = PinProtocol1::kdf(&shared_secret);
                        PinProtocol1::decrypt(&k, &hmac_in.salt_enc).map_err(|_| CtapError::PinAuthInvalid)?
                    }
                    2 => {
                        let (e_ks, _m_ks) = PinProtocol2::kdf(&shared_secret);
                        PinProtocol2::decrypt(&e_ks, &hmac_in.salt_enc).map_err(|_| CtapError::PinAuthInvalid)?
                    }
                    _ => return Err(CtapError::InvalidParameter),
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
                        _ => return Err(CtapError::InvalidParameter),
                    };

                    ext_outputs.hmac_secret_output_enc = Some(enc_output);
                }
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
        let mut cred_map = Vec::new();
        cred_map.push((Value::Text(String::from("id")), Value::Bytes(cred.id.clone())));
        cred_map.push((Value::Text(String::from("type")), Value::Text(String::from("public-key"))));
        resp.push((Value::Integer(1.into()), Value::Map(cred_map)));

        // 2: authData
        resp.push((Value::Integer(2.into()), Value::Bytes(auth_data)));

        // 3: signature
        resp.push((Value::Integer(3.into()), Value::Bytes(sig)));

        // 4: user map (if resident)
        if cred.is_resident {
            let mut user_map = Vec::new();
            user_map.push((Value::Text(String::from("id")), Value::Bytes(cred.user_id.clone())));
            if let Some(ref name) = cred.user_name {
                user_map.push((Value::Text(String::from("name")), Value::Text(name.clone())));
            }
            if let Some(ref disp) = cred.user_display_name {
                user_map.push((Value::Text(String::from("displayName")), Value::Text(disp.clone())));
            }
            resp.push((Value::Integer(4.into()), Value::Map(user_map)));
        }

        // 5: numberOfCredentials (if > 1)
        if total_candidates > 1 {
            resp.push((Value::Integer(5.into()), Value::Integer((total_candidates as i64).into())));
        }

        // 7: largeBlobKey
        if let Some(ref lb_key) = cred.large_blob_key {
            resp.push((Value::Integer(7.into()), Value::Bytes(lb_key.to_vec())));
        }

        encode_cbor_value(&Value::Map(resp))
    }
}
