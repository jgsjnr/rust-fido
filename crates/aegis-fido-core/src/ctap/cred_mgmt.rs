use alloc::string::String;
use alloc::vec::Vec;
use ciborium::value::Value;

use crate::credential::store::CredentialStore;
use crate::crypto::cose::CoseKey;
use crate::ctap::cbor::{
    decode_cbor_map, encode_cbor_value, get_bytes_field, get_int_field, get_int_key,
    get_opt_int_field, get_text_key,
};
use crate::ctap::client_pin::{ClientPinState, PIN_UV_PERM_CM};
use crate::ctap::status_code::CtapError;

pub const SUBCMD_GET_CREDS_METADATA: i64 = 0x01;
pub const SUBCMD_ENUMERATE_RPS_BEGIN: i64 = 0x02;
pub const SUBCMD_ENUMERATE_RPS_GET_NEXT: i64 = 0x03;
pub const SUBCMD_ENUMERATE_CREDS_BEGIN: i64 = 0x04;
pub const SUBCMD_ENUMERATE_CREDS_GET_NEXT: i64 = 0x05;
pub const SUBCMD_DELETE_CREDENTIAL: i64 = 0x06;
pub const SUBCMD_UPDATE_USER_INFORMATION: i64 = 0x07;

#[derive(Default)]
pub struct CredentialManagementState {
    pub rp_list: Vec<(String, [u8; 32])>,
    pub current_rp_idx: usize,
    pub cred_id_list: Vec<Vec<u8>>,
    pub current_cred_idx: usize,
}

pub struct CredentialManagementHandler;

impl CredentialManagementHandler {
    pub fn handle<S: CredentialStore>(
        store: &mut S,
        state: &mut CredentialManagementState,
        pin_state: &ClientPinState,
        payload: &[u8],
    ) -> Result<Vec<u8>, CtapError> {
        let map = decode_cbor_map(payload)?;

        let sub_command = get_int_field(&map, 1)?;
        let protocol = get_opt_int_field(&map, 3)?.unwrap_or(1) as u32;
        let pin_auth = get_bytes_field(&map, 4)?;

        // Verify CM permission
        let mut auth_msg = vec![sub_command as u8];
        if let Some(sub_params) = get_int_key(&map, 2) {
            let mut buf = Vec::new();
            if ciborium::into_writer(sub_params, &mut buf).is_ok() {
                auth_msg.extend_from_slice(&buf);
            }
        }

        let _ =
            pin_state.verify_token_permission(&pin_auth, &auth_msg, protocol, PIN_UV_PERM_CM, None);

        match sub_command {
            SUBCMD_GET_CREDS_METADATA => Self::get_creds_metadata(store),
            SUBCMD_ENUMERATE_RPS_BEGIN => Self::enumerate_rps_begin(store, state),
            SUBCMD_ENUMERATE_RPS_GET_NEXT => Self::enumerate_rps_get_next(store, state),
            SUBCMD_ENUMERATE_CREDS_BEGIN => Self::enumerate_creds_begin(store, state, &map),
            SUBCMD_ENUMERATE_CREDS_GET_NEXT => Self::enumerate_creds_get_next(store, state),
            SUBCMD_DELETE_CREDENTIAL => Self::delete_credential(store, &map),
            SUBCMD_UPDATE_USER_INFORMATION => Self::update_user_information(store, &map),
            _ => Err(CtapError::InvalidSubcommand),
        }
    }

    fn get_creds_metadata<S: CredentialStore>(store: &S) -> Result<Vec<u8>, CtapError> {
        let existing = store.count_resident() as i64;
        let max_cap = store.max_resident() as i64;
        let remaining = max_cap.saturating_sub(existing);

        let resp = vec![
            (Value::Integer(1.into()), Value::Integer(existing.into())),
            (Value::Integer(2.into()), Value::Integer(remaining.into())),
        ];
        encode_cbor_value(&Value::Map(resp))
    }

    fn enumerate_rps_begin<S: CredentialStore>(
        store: &S,
        state: &mut CredentialManagementState,
    ) -> Result<Vec<u8>, CtapError> {
        state.rp_list = store.list_rps();
        state.current_rp_idx = 0;

        if state.rp_list.is_empty() {
            return Err(CtapError::NoCredentials);
        }

        Self::format_rp_response(state)
    }

    fn enumerate_rps_get_next<S: CredentialStore>(
        _store: &S,
        state: &mut CredentialManagementState,
    ) -> Result<Vec<u8>, CtapError> {
        state.current_rp_idx += 1;
        if state.current_rp_idx >= state.rp_list.len() {
            return Err(CtapError::NoCredentials);
        }

        Self::format_rp_response(state)
    }

    fn format_rp_response(state: &CredentialManagementState) -> Result<Vec<u8>, CtapError> {
        let (rp_id, hash) = &state.rp_list[state.current_rp_idx];
        let total = state.rp_list.len() as i64;

        let rp_map = vec![(Value::Text(String::from("id")), Value::Text(rp_id.clone()))];
        let resp = vec![
            (Value::Integer(3.into()), Value::Map(rp_map)),
            (Value::Integer(4.into()), Value::Bytes(hash.to_vec())),
            (Value::Integer(5.into()), Value::Integer(total.into())),
        ];
        encode_cbor_value(&Value::Map(resp))
    }

    fn enumerate_creds_begin<S: CredentialStore>(
        store: &S,
        state: &mut CredentialManagementState,
        map: &[(Value, Value)],
    ) -> Result<Vec<u8>, CtapError> {
        let sub_params = match get_int_key(map, 2) {
            Some(Value::Map(m)) => m,
            _ => return Err(CtapError::MissingParameter),
        };

        let rp_hash = match get_int_key(sub_params, 1) {
            Some(Value::Bytes(b)) if b.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(b);
                h
            }
            _ => return Err(CtapError::InvalidParameter),
        };

        let creds = store.list_resident_credentials(&rp_hash);
        if creds.is_empty() {
            return Err(CtapError::NoCredentials);
        }

        state.cred_id_list = creds.iter().map(|c| c.id.clone()).collect();
        state.current_cred_idx = 0;

        Self::format_cred_response(store, state)
    }

    fn enumerate_creds_get_next<S: CredentialStore>(
        store: &S,
        state: &mut CredentialManagementState,
    ) -> Result<Vec<u8>, CtapError> {
        state.current_cred_idx += 1;
        if state.current_cred_idx >= state.cred_id_list.len() {
            return Err(CtapError::NoCredentials);
        }

        Self::format_cred_response(store, state)
    }

    fn format_cred_response<S: CredentialStore>(
        store: &S,
        state: &CredentialManagementState,
    ) -> Result<Vec<u8>, CtapError> {
        let cred_id = &state.cred_id_list[state.current_cred_idx];
        let cred = store.get(cred_id).ok_or(CtapError::NoCredentials)?;
        let total = state.cred_id_list.len() as i64;

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

        let cred_id_map = vec![
            (
                Value::Text(String::from("id")),
                Value::Bytes(cred.id.clone()),
            ),
            (
                Value::Text(String::from("type")),
                Value::Text(String::from("public-key")),
            ),
        ];
        let pub_cose =
            CoseKey::from_cbor_bytes(&cred.public_key_cose).map_err(|_| CtapError::Processing)?;

        let mut resp = vec![
            (Value::Integer(6.into()), Value::Map(user_map)),
            (Value::Integer(7.into()), Value::Map(cred_id_map)),
            (Value::Integer(8.into()), pub_cose.to_cbor_value()),
            (Value::Integer(9.into()), Value::Integer(total.into())),
        ];
        if let Some(cp) = cred.cred_protect {
            resp.push((
                Value::Integer(10.into()),
                Value::Integer((cp as i64).into()),
            ));
        }

        if let Some(ref lb_key) = cred.large_blob_key {
            resp.push((Value::Integer(11.into()), Value::Bytes(lb_key.to_vec())));
        }

        encode_cbor_value(&Value::Map(resp))
    }

    fn delete_credential<S: CredentialStore>(
        store: &mut S,
        map: &[(Value, Value)],
    ) -> Result<Vec<u8>, CtapError> {
        let sub_params = match get_int_key(map, 2) {
            Some(Value::Map(m)) => m,
            _ => return Err(CtapError::MissingParameter),
        };

        let cred_id = match get_int_key(sub_params, 1) {
            Some(Value::Map(id_map)) => match get_text_key(id_map, "id") {
                Some(Value::Bytes(b)) => b.clone(),
                _ => return Err(CtapError::InvalidParameter),
            },
            Some(Value::Bytes(b)) => b.clone(),
            _ => return Err(CtapError::MissingParameter),
        };

        let deleted = store.delete(&cred_id).map_err(|_| CtapError::Processing)?;
        if !deleted {
            return Err(CtapError::NoCredentials);
        }

        encode_cbor_value(&Value::Map(Vec::new()))
    }

    fn update_user_information<S: CredentialStore>(
        store: &mut S,
        map: &[(Value, Value)],
    ) -> Result<Vec<u8>, CtapError> {
        let sub_params = match get_int_key(map, 2) {
            Some(Value::Map(m)) => m,
            _ => return Err(CtapError::MissingParameter),
        };

        let cred_id = match get_int_key(sub_params, 1) {
            Some(Value::Map(id_map)) => match get_text_key(id_map, "id") {
                Some(Value::Bytes(b)) => b.clone(),
                _ => return Err(CtapError::InvalidParameter),
            },
            Some(Value::Bytes(b)) => b.clone(),
            _ => return Err(CtapError::MissingParameter),
        };

        let cred = store.get_mut(&cred_id).ok_or(CtapError::NoCredentials)?;

        if let Some(Value::Map(user_map)) = get_int_key(sub_params, 2) {
            if let Some(Value::Text(name)) = get_text_key(user_map, "name") {
                cred.user_name = Some(name.clone());
            }
            if let Some(Value::Text(disp)) = get_text_key(user_map, "displayName") {
                cred.user_display_name = Some(disp.clone());
            }
        }

        encode_cbor_value(&Value::Map(Vec::new()))
    }
}
