//! Device response: preserved wire `status` byte plus opaque payload.
//!
//! The `status` byte is the §9.5 value (`0x00`/`0x01`/`0x02`/`0x05`, …),
//! never remapped by this crate.

use crate::status::STATUS_OK;
use alloc::vec::Vec;

/// Typed response envelope: wire status + raw payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkResponse {
    /// §9.5 status byte (see `crate::status`).
    pub status: u8,
    /// Opaque payload bytes (never secrets on the log path).
    pub payload: Vec<u8>,
}

impl SdkResponse {
    /// Build a response with an explicit wire status.
    pub fn new(status: u8, payload: Vec<u8>) -> Self {
        Self { status, payload }
    }

    /// Build a success (`0x00`) response.
    pub fn ok(payload: Vec<u8>) -> Self {
        Self::new(STATUS_OK, payload)
    }

    /// `true` only for `0x00`.
    pub fn is_ok(&self) -> bool {
        self.status == STATUS_OK
    }
}

#[cfg(test)]
mod tests {
    use crate::response::SdkResponse;
    use crate::status::{STATUS_NEED_BINDING, STATUS_OK};
    use alloc::vec::Vec;

    #[test]
    fn ok_sets_zero_status() {
        let r = SdkResponse::ok(Vec::new());
        assert_eq!(r.status, STATUS_OK);
        assert!(r.is_ok());
    }

    #[test]
    fn binding_denial_preserves_wire_byte() {
        let r = SdkResponse::new(STATUS_NEED_BINDING, Vec::new());
        assert_eq!(r.status, 0x05);
        assert!(!r.is_ok());
    }

    #[test]
    fn payload_round_trips() {
        let r = SdkResponse::new(STATUS_OK, alloc::vec![0x01, 0x02]);
        assert_eq!(r.payload, alloc::vec![0x01u8, 0x02u8]);
        assert!(r.is_ok());
    }
}
