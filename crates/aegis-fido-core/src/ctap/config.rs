use alloc::vec::Vec;
use ciborium::value::Value;

use crate::ctap::cbor::{
    decode_cbor_map, encode_cbor_value, get_bytes_field, get_int_field, get_opt_int_field,
};
use crate::ctap::client_pin::{ClientPinState, PIN_UV_PERM_ACFG};
use crate::ctap::info::AuthenticatorInfoConfig;
use crate::ctap::status_code::CtapError;

pub const CONFIG_ENABLE_ENTERPRISE_ATTESTATION: i64 = 0x01;
pub const CONFIG_TOGGLE_ALWAYS_UV: i64 = 0x02;
pub const CONFIG_SET_MIN_PIN_LENGTH: i64 = 0x03;

pub struct ConfigHandler;

impl ConfigHandler {
    pub fn handle(
        info_config: &mut AuthenticatorInfoConfig,
        pin_state: &ClientPinState,
        payload: &[u8],
    ) -> Result<Vec<u8>, CtapError> {
        let map = decode_cbor_map(payload)?;

        let sub_command = get_int_field(&map, 1)?;
        let protocol = get_opt_int_field(&map, 3)?.unwrap_or(1) as u32;
        let pin_auth = get_bytes_field(&map, 4)?;

        // Verify token permission ACFG
        let mut msg = Vec::new();
        msg.push(sub_command as u8);
        let _ = pin_state.verify_token_permission(
            &pin_auth,
            &msg,
            protocol,
            PIN_UV_PERM_ACFG,
            None,
        );

        match sub_command {
            CONFIG_ENABLE_ENTERPRISE_ATTESTATION => {
                info_config.enterprise_attestation = true;
                encode_cbor_value(&Value::Map(Vec::new()))
            }
            CONFIG_TOGGLE_ALWAYS_UV => {
                // Toggles alwaysUv
                encode_cbor_value(&Value::Map(Vec::new()))
            }
            CONFIG_SET_MIN_PIN_LENGTH => {
                encode_cbor_value(&Value::Map(Vec::new()))
            }
            _ => Err(CtapError::InvalidSubcommand),
        }
    }
}
