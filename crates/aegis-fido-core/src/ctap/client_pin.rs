use alloc::string::String;
use alloc::vec::Vec;
use ciborium::value::Value;
use rand_core::{CryptoRng, RngCore};

use crate::crypto::cose::CoseKey;
use crate::crypto::ecdh::EcdhKeyAgreement;
use crate::crypto::pin_protocol::{pad_pin, pin_hash, PinProtocol1, PinProtocol2};
use crate::ctap::cbor::{
    decode_cbor_map, encode_cbor_value, get_bytes_field, get_int_field, get_int_key,
    get_opt_bytes_field, get_opt_int_field,
};
use crate::ctap::status_code::CtapError;
use crate::extensions::check_pin_complexity;

pub const SUBCMD_GET_PIN_RETRIES: i64 = 0x01;
pub const SUBCMD_GET_KEY_AGREEMENT: i64 = 0x02;
pub const SUBCMD_SET_PIN: i64 = 0x03;
pub const SUBCMD_CHANGE_PIN: i64 = 0x04;
pub const SUBCMD_GET_PIN_TOKEN: i64 = 0x05;
pub const SUBCMD_GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS: i64 = 0x06;
pub const SUBCMD_GET_UV_RETRIES: i64 = 0x07;
pub const SUBCMD_SET_MIN_PIN_LENGTH: i64 = 0x08;
pub const SUBCMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS: i64 = 0x09;

// CTAP 2.1 Permissions
pub const PIN_UV_PERM_MC: u32 = 0x01;
pub const PIN_UV_PERM_GA: u32 = 0x02;
pub const PIN_UV_PERM_CM: u32 = 0x04;
pub const PIN_UV_PERM_BE: u32 = 0x08;
pub const PIN_UV_PERM_LBW: u32 = 0x10;
pub const PIN_UV_PERM_ACFG: u32 = 0x20;

#[derive(Clone, Debug)]
pub struct PinUvTokenSession {
    pub token: [u8; 32],
    pub protocol: u32,
    pub permissions: u32,
    pub rp_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ClientPinState {
    pub pin_hash: Option<[u8; 16]>,
    pub pin_retries: u8,
    pub uv_retries: u8,
    pub min_pin_length: u32,
    pub pin_complexity_policy: bool,
    pub active_session: Option<PinUvTokenSession>,
    pub ephemeral_key: Option<EcdhKeyAgreement>,
}

impl Default for ClientPinState {
    fn default() -> Self {
        Self {
            pin_hash: None,
            pin_retries: 8,
            uv_retries: 3,
            min_pin_length: 4,
            pin_complexity_policy: false,
            active_session: None,
            ephemeral_key: None,
        }
    }
}

impl ClientPinState {
    pub fn is_pin_set(&self) -> bool {
        self.pin_hash.is_some()
    }

    pub fn verify_token_permission(
        &self,
        token_auth: &[u8],
        message: &[u8],
        protocol: u32,
        required_perm: u32,
        rp_id: Option<&str>,
    ) -> Result<(), CtapError> {
        let session = self.active_session.as_ref().ok_or(CtapError::PinTokenExpired)?;

        if session.protocol != protocol {
            return Err(CtapError::PinAuthInvalid);
        }

        if (session.permissions & required_perm) == 0 {
            return Err(CtapError::UnauthorizedPermission);
        }

        if let Some(expected_rpid) = &session.rp_id {
            if let Some(actual_rpid) = rp_id {
                if expected_rpid != actual_rpid {
                    return Err(CtapError::PinAuthInvalid);
                }
            } else {
                return Err(CtapError::PinAuthInvalid);
            }
        }

        match protocol {
            1 => {
                let expected = PinProtocol1::authenticate(&session.token, message);
                if token_auth != expected.as_slice() {
                    return Err(CtapError::PinAuthInvalid);
                }
            }
            2 => {
                let expected = PinProtocol2::authenticate(&session.token, message);
                if token_auth != expected.as_slice() {
                    return Err(CtapError::PinAuthInvalid);
                }
            }
            _ => return Err(CtapError::PinAuthInvalid),
        }

        Ok(())
    }
}

pub struct ClientPinHandler;

impl ClientPinHandler {
    pub fn handle<R: RngCore + CryptoRng>(
        state: &mut ClientPinState,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, CtapError> {
        let map = decode_cbor_map(payload)?;

        let protocol = get_int_field(&map, 1)? as u32;
        if protocol != 1 && protocol != 2 {
            return Err(CtapError::InvalidParameter);
        }

        let sub_command = get_int_field(&map, 2)?;

        match sub_command {
            SUBCMD_GET_PIN_RETRIES => Self::handle_get_pin_retries(state),
            SUBCMD_GET_KEY_AGREEMENT => Self::handle_get_key_agreement(state, rng),
            SUBCMD_SET_PIN => Self::handle_set_pin(state, &map, protocol),
            SUBCMD_CHANGE_PIN => Self::handle_change_pin(state, &map, protocol),
            SUBCMD_GET_PIN_TOKEN => Self::handle_get_pin_token(state, &map, protocol, rng),
            SUBCMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS => {
                Self::handle_get_pin_uv_auth_token_with_permissions(state, &map, protocol, rng)
            }
            SUBCMD_GET_UV_RETRIES => Self::handle_get_uv_retries(state),
            SUBCMD_SET_MIN_PIN_LENGTH => Self::handle_set_min_pin_length(state, &map, protocol),
            _ => Err(CtapError::InvalidSubcommand),
        }
    }

    fn handle_get_pin_retries(state: &ClientPinState) -> Result<Vec<u8>, CtapError> {
        let mut map = Vec::new();
        map.push((
            Value::Integer(3.into()),
            Value::Integer((state.pin_retries as i64).into()),
        ));
        map.push((Value::Integer(4.into()), Value::Bool(false)));
        encode_cbor_value(&Value::Map(map))
    }

    fn handle_get_uv_retries(state: &ClientPinState) -> Result<Vec<u8>, CtapError> {
        let mut map = Vec::new();
        map.push((
            Value::Integer(5.into()),
            Value::Integer((state.uv_retries as i64).into()),
        ));
        encode_cbor_value(&Value::Map(map))
    }

    fn handle_get_key_agreement<R: RngCore + CryptoRng>(
        state: &mut ClientPinState,
        rng: &mut R,
    ) -> Result<Vec<u8>, CtapError> {
        let ecdh = EcdhKeyAgreement::generate(rng);
        let cose_key = ecdh.to_cose_key();
        state.ephemeral_key = Some(ecdh);

        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), cose_key.to_cbor_value()));
        encode_cbor_value(&Value::Map(map))
    }

    fn handle_set_pin(
        state: &mut ClientPinState,
        map: &[(Value, Value)],
        protocol: u32,
    ) -> Result<Vec<u8>, CtapError> {
        if state.is_pin_set() {
            return Err(CtapError::PinAuthInvalid);
        }

        let ecdh = state.ephemeral_key.as_ref().ok_or(CtapError::PinAuthInvalid)?;
        let peer_cose_val = get_int_key(map, 3).ok_or(CtapError::MissingParameter)?;
        let peer_cose = CoseKey::from_cbor_value(peer_cose_val).map_err(|_| CtapError::InvalidParameter)?;
        let shared_secret = ecdh.compute_shared_secret(&peer_cose).map_err(|_| CtapError::InvalidParameter)?;

        let new_pin_enc = get_bytes_field(map, 5)?;
        let pin_auth = get_bytes_field(map, 4)?;

        // Verify pinAuth
        match protocol {
            1 => {
                let k = PinProtocol1::kdf(&shared_secret);
                let expected = PinProtocol1::authenticate(&k, &new_pin_enc);
                if pin_auth.as_slice() != expected.as_slice() {
                    return Err(CtapError::PinAuthInvalid);
                }
            }
            2 => {
                let (_e_ks, m_ks) = PinProtocol2::kdf(&shared_secret);
                let expected = PinProtocol2::authenticate(&m_ks, &new_pin_enc);
                if pin_auth.as_slice() != expected.as_slice() {
                    return Err(CtapError::PinAuthInvalid);
                }
            }
            _ => return Err(CtapError::InvalidParameter),
        }

        // Decrypt PIN
        let decrypted = match protocol {
            1 => {
                let k = PinProtocol1::kdf(&shared_secret);
                PinProtocol1::decrypt(&k, &new_pin_enc).map_err(|_| CtapError::PinAuthInvalid)?
            }
            2 => {
                let (e_ks, _m_ks) = PinProtocol2::kdf(&shared_secret);
                PinProtocol2::decrypt(&e_ks, &new_pin_enc).map_err(|_| CtapError::PinAuthInvalid)?
            }
            _ => return Err(CtapError::InvalidParameter),
        };

        let pin_bytes = Self::unpad_pin(&decrypted)?;
        if pin_bytes.len() < state.min_pin_length as usize || pin_bytes.len() > 63 {
            return Err(CtapError::PinPolicyViolation);
        }

        if let Ok(pin_str) = core::str::from_utf8(pin_bytes) {
            if state.pin_complexity_policy && !check_pin_complexity(pin_str) {
                return Err(CtapError::PinPolicyViolation);
            }
        }

        state.pin_hash = Some(pin_hash(pin_bytes));
        state.pin_retries = 8;
        encode_cbor_value(&Value::Map(Vec::new()))
    }

    fn handle_change_pin(
        state: &mut ClientPinState,
        map: &[(Value, Value)],
        protocol: u32,
    ) -> Result<Vec<u8>, CtapError> {
        if !state.is_pin_set() {
            return Err(CtapError::PinNotSet);
        }
        if state.pin_retries == 0 {
            return Err(CtapError::PinBlocked);
        }

        let ecdh = state.ephemeral_key.as_ref().ok_or(CtapError::PinAuthInvalid)?;
        let peer_cose_val = get_int_key(map, 3).ok_or(CtapError::MissingParameter)?;
        let peer_cose = CoseKey::from_cbor_value(peer_cose_val).map_err(|_| CtapError::InvalidParameter)?;
        let shared_secret = ecdh.compute_shared_secret(&peer_cose).map_err(|_| CtapError::InvalidParameter)?;

        let pin_hash_enc = get_bytes_field(map, 6)?;
        let new_pin_enc = get_bytes_field(map, 5)?;
        let pin_auth = get_bytes_field(map, 4)?;

        // pinAuth = authenticate(key, newPinEnc || pinHashEnc)
        let mut auth_data = Vec::with_capacity(new_pin_enc.len() + pin_hash_enc.len());
        auth_data.extend_from_slice(&new_pin_enc);
        auth_data.extend_from_slice(&pin_hash_enc);

        match protocol {
            1 => {
                let k = PinProtocol1::kdf(&shared_secret);
                let expected = PinProtocol1::authenticate(&k, &auth_data);
                if pin_auth.as_slice() != expected.as_slice() {
                    return Err(CtapError::PinAuthInvalid);
                }
            }
            2 => {
                let (_e_ks, m_ks) = PinProtocol2::kdf(&shared_secret);
                let expected = PinProtocol2::authenticate(&m_ks, &auth_data);
                if pin_auth.as_slice() != expected.as_slice() {
                    return Err(CtapError::PinAuthInvalid);
                }
            }
            _ => return Err(CtapError::InvalidParameter),
        }

        // Decrypt old pin hash
        let decrypted_old_hash = match protocol {
            1 => {
                let k = PinProtocol1::kdf(&shared_secret);
                PinProtocol1::decrypt(&k, &pin_hash_enc).map_err(|_| CtapError::PinAuthInvalid)?
            }
            2 => {
                let (e_ks, _m_ks) = PinProtocol2::kdf(&shared_secret);
                PinProtocol2::decrypt(&e_ks, &pin_hash_enc).map_err(|_| CtapError::PinAuthInvalid)?
            }
            _ => return Err(CtapError::InvalidParameter),
        };

        if decrypted_old_hash.len() < 16 || &decrypted_old_hash[..16] != state.pin_hash.as_ref().unwrap() {
            state.pin_retries = state.pin_retries.saturating_sub(1);
            if state.pin_retries == 0 {
                return Err(CtapError::PinBlocked);
            }
            return Err(CtapError::PinInvalid);
        }

        // Decrypt new PIN
        let decrypted_new_pin = match protocol {
            1 => {
                let k = PinProtocol1::kdf(&shared_secret);
                PinProtocol1::decrypt(&k, &new_pin_enc).map_err(|_| CtapError::PinAuthInvalid)?
            }
            2 => {
                let (e_ks, _m_ks) = PinProtocol2::kdf(&shared_secret);
                PinProtocol2::decrypt(&e_ks, &new_pin_enc).map_err(|_| CtapError::PinAuthInvalid)?
            }
            _ => return Err(CtapError::InvalidParameter),
        };

        let new_pin_bytes = Self::unpad_pin(&decrypted_new_pin)?;
        if new_pin_bytes.len() < state.min_pin_length as usize || new_pin_bytes.len() > 63 {
            return Err(CtapError::PinPolicyViolation);
        }

        if let Ok(pin_str) = core::str::from_utf8(new_pin_bytes) {
            if state.pin_complexity_policy && !check_pin_complexity(pin_str) {
                return Err(CtapError::PinPolicyViolation);
            }
        }

        state.pin_hash = Some(pin_hash(new_pin_bytes));
        state.pin_retries = 8;
        encode_cbor_value(&Value::Map(Vec::new()))
    }

    fn handle_get_pin_token<R: RngCore + CryptoRng>(
        state: &mut ClientPinState,
        map: &[(Value, Value)],
        protocol: u32,
        rng: &mut R,
    ) -> Result<Vec<u8>, CtapError> {
        if !state.is_pin_set() {
            return Err(CtapError::PinNotSet);
        }
        if state.pin_retries == 0 {
            return Err(CtapError::PinBlocked);
        }

        let ecdh = state.ephemeral_key.as_ref().ok_or(CtapError::PinAuthInvalid)?;
        let peer_cose_val = get_int_key(map, 3).ok_or(CtapError::MissingParameter)?;
        let peer_cose = CoseKey::from_cbor_value(peer_cose_val).map_err(|_| CtapError::InvalidParameter)?;
        let shared_secret = ecdh.compute_shared_secret(&peer_cose).map_err(|_| CtapError::InvalidParameter)?;

        let pin_hash_enc = get_bytes_field(map, 6)?;

        // Decrypt pin hash
        let decrypted_hash = match protocol {
            1 => {
                let k = PinProtocol1::kdf(&shared_secret);
                PinProtocol1::decrypt(&k, &pin_hash_enc).map_err(|_| CtapError::PinAuthInvalid)?
            }
            2 => {
                let (e_ks, _m_ks) = PinProtocol2::kdf(&shared_secret);
                PinProtocol2::decrypt(&e_ks, &pin_hash_enc).map_err(|_| CtapError::PinAuthInvalid)?
            }
            _ => return Err(CtapError::InvalidParameter),
        };

        if decrypted_hash.len() < 16 || &decrypted_hash[..16] != state.pin_hash.as_ref().unwrap() {
            state.pin_retries = state.pin_retries.saturating_sub(1);
            if state.pin_retries == 0 {
                return Err(CtapError::PinBlocked);
            }
            return Err(CtapError::PinInvalid);
        }

        state.pin_retries = 8;

        // Generate token
        let mut token = [0u8; 32];
        rng.fill_bytes(&mut token);

        state.active_session = Some(PinUvTokenSession {
            token,
            protocol,
            permissions: 0xFF, // legacy getPinToken grants all permissions
            rp_id: None,
        });

        let enc_token = match protocol {
            1 => {
                let k = PinProtocol1::kdf(&shared_secret);
                PinProtocol1::encrypt(&k, &token)
            }
            2 => {
                let (e_ks, _m_ks) = PinProtocol2::kdf(&shared_secret);
                let mut iv = [0u8; 16];
                rng.fill_bytes(&mut iv);
                PinProtocol2::encrypt(&e_ks, &iv, &token)
            }
            _ => return Err(CtapError::InvalidParameter),
        };

        let mut resp = Vec::new();
        resp.push((Value::Integer(2.into()), Value::Bytes(enc_token)));
        encode_cbor_value(&Value::Map(resp))
    }

    fn handle_get_pin_uv_auth_token_with_permissions<R: RngCore + CryptoRng>(
        state: &mut ClientPinState,
        map: &[(Value, Value)],
        protocol: u32,
        rng: &mut R,
    ) -> Result<Vec<u8>, CtapError> {
        if !state.is_pin_set() {
            return Err(CtapError::PinNotSet);
        }
        if state.pin_retries == 0 {
            return Err(CtapError::PinBlocked);
        }

        let ecdh = state.ephemeral_key.as_ref().ok_or(CtapError::PinAuthInvalid)?;
        let peer_cose_val = get_int_key(map, 3).ok_or(CtapError::MissingParameter)?;
        let peer_cose = CoseKey::from_cbor_value(peer_cose_val).map_err(|_| CtapError::InvalidParameter)?;
        let shared_secret = ecdh.compute_shared_secret(&peer_cose).map_err(|_| CtapError::InvalidParameter)?;

        let pin_hash_enc = get_bytes_field(map, 6)?;
        let permissions = get_int_field(map, 9)? as u32;

        let rp_id = match get_int_key(map, 10) {
            Some(Value::Text(s)) => Some(s.clone()),
            _ => None,
        };

        // Decrypt pin hash
        let decrypted_hash = match protocol {
            1 => {
                let k = PinProtocol1::kdf(&shared_secret);
                PinProtocol1::decrypt(&k, &pin_hash_enc).map_err(|_| CtapError::PinAuthInvalid)?
            }
            2 => {
                let (e_ks, _m_ks) = PinProtocol2::kdf(&shared_secret);
                PinProtocol2::decrypt(&e_ks, &pin_hash_enc).map_err(|_| CtapError::PinAuthInvalid)?
            }
            _ => return Err(CtapError::InvalidParameter),
        };

        if decrypted_hash.len() < 16 || &decrypted_hash[..16] != state.pin_hash.as_ref().unwrap() {
            state.pin_retries = state.pin_retries.saturating_sub(1);
            if state.pin_retries == 0 {
                return Err(CtapError::PinBlocked);
            }
            return Err(CtapError::PinInvalid);
        }

        state.pin_retries = 8;

        let mut token = [0u8; 32];
        rng.fill_bytes(&mut token);

        state.active_session = Some(PinUvTokenSession {
            token,
            protocol,
            permissions,
            rp_id,
        });

        let enc_token = match protocol {
            1 => {
                let k = PinProtocol1::kdf(&shared_secret);
                PinProtocol1::encrypt(&k, &token)
            }
            2 => {
                let (e_ks, _m_ks) = PinProtocol2::kdf(&shared_secret);
                let mut iv = [0u8; 16];
                rng.fill_bytes(&mut iv);
                PinProtocol2::encrypt(&e_ks, &iv, &token)
            }
            _ => return Err(CtapError::InvalidParameter),
        };

        let mut resp = Vec::new();
        resp.push((Value::Integer(2.into()), Value::Bytes(enc_token)));
        encode_cbor_value(&Value::Map(resp))
    }

    fn handle_set_min_pin_length(
        state: &mut ClientPinState,
        map: &[(Value, Value)],
        protocol: u32,
    ) -> Result<Vec<u8>, CtapError> {
        let new_min = get_int_field(map, 7)? as u32;
        let pin_auth = get_bytes_field(map, 4)?;

        // Verify pinAuth with ACFG or CM permission
        let mut msg = Vec::new();
        msg.extend_from_slice(&(new_min as u64).to_be_bytes());

        state.verify_token_permission(&pin_auth, &msg, protocol, PIN_UV_PERM_ACFG | PIN_UV_PERM_CM, None)?;

        if new_min < state.min_pin_length {
            return Err(CtapError::PinPolicyViolation);
        }

        state.min_pin_length = new_min;
        encode_cbor_value(&Value::Map(Vec::new()))
    }

    fn unpad_pin(padded: &[u8]) -> Result<&[u8], CtapError> {
        let first_zero = padded.iter().position(|&b| b == 0).unwrap_or(padded.len());
        Ok(&padded[..first_zero])
    }
}
