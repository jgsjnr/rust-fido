use alloc::vec::Vec;
use ciborium::value::Value;

use crate::crypto::hash::sha256;
use crate::ctap::cbor::{
    decode_cbor_map, encode_cbor_value, get_bytes_field, get_int_key, get_opt_bytes_field,
    get_opt_int_field,
};
use crate::ctap::client_pin::{ClientPinState, PIN_UV_PERM_LBW};
use crate::ctap::status_code::CtapError;

pub const MAX_LARGE_BLOB_SIZE: usize = 2048;

#[derive(Clone, Debug, Default)]
pub struct LargeBlobsStorage {
    data: Vec<u8>,
}

impl LargeBlobsStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn read(&self, offset: usize, count: usize) -> Result<Vec<u8>, CtapError> {
        if offset > self.data.len() {
            return Ok(Vec::new());
        }
        let end = (offset + count).min(self.data.len());
        Ok(self.data[offset..end].to_vec())
    }

    pub fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), CtapError> {
        let needed_len = offset + bytes.len();
        if needed_len > MAX_LARGE_BLOB_SIZE {
            return Err(CtapError::LimitExceeded);
        }

        if self.data.len() < needed_len {
            self.data.resize(needed_len, 0);
        }

        self.data[offset..needed_len].copy_from_slice(bytes);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }
}

pub struct LargeBlobsHandler;

impl LargeBlobsHandler {
    pub fn handle(
        storage: &mut LargeBlobsStorage,
        pin_state: &ClientPinState,
        payload: &[u8],
    ) -> Result<Vec<u8>, CtapError> {
        let map = decode_cbor_map(payload)?;

        let offset = get_opt_int_field(&map, 3)?.unwrap_or(0) as usize;

        // Check if read request (get)
        if let Some(get_val) = get_int_key(&map, 1) {
            let count: i128 = match get_val {
                Value::Integer(i) => (*i).into(),
                _ => return Err(CtapError::CborUnexpectedType),
            };
            let chunk = storage.read(offset, count as usize)?;
            let resp = vec![(Value::Integer(1.into()), Value::Bytes(chunk))];
            return encode_cbor_value(&Value::Map(resp));
        }

        // Check if write request (set)
        if let Some(set_bytes) = get_opt_bytes_field(&map, 2)? {
            let pin_auth = get_bytes_field(&map, 5)?;
            let protocol = get_opt_int_field(&map, 6)?.unwrap_or(1) as u32;

            // Validate pinAuth with LBW permission
            // Message: sha256(set_bytes)
            let msg = sha256(&set_bytes);
            let token_verified =
                pin_state.verify_token_permission(&pin_auth, &msg, protocol, PIN_UV_PERM_LBW, None);

            // Also check raw set_bytes if client authenticated over set_bytes directly
            if token_verified.is_err() {
                pin_state.verify_token_permission(
                    &pin_auth,
                    &set_bytes,
                    protocol,
                    PIN_UV_PERM_LBW,
                    None,
                )?;
            }

            storage.write(offset, &set_bytes)?;
            return encode_cbor_value(&Value::Map(Vec::new()));
        }

        Err(CtapError::MissingParameter)
    }
}
