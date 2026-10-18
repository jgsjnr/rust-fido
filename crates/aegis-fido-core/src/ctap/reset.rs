use alloc::vec::Vec;
use ciborium::value::Value;
use crate::ctap::cbor::encode_cbor_value;
use crate::ctap::status_code::CtapError;

pub const RESET_BOOT_WINDOW_SECONDS: u64 = 10;

pub struct ResetHandler;

impl ResetHandler {
    pub fn handle(
        boot_timestamp_seconds: u64,
        current_timestamp_seconds: u64,
        user_touch_confirmed: bool,
    ) -> Result<Vec<u8>, CtapError> {
        let elapsed = current_timestamp_seconds.saturating_sub(boot_timestamp_seconds);
        if elapsed > RESET_BOOT_WINDOW_SECONDS {
            return Err(CtapError::NotAllowed);
        }

        if !user_touch_confirmed {
            return Err(CtapError::OperationDenied);
        }

        // Returns empty map on success
        encode_cbor_value(&Value::Map(Vec::new()))
    }
}
