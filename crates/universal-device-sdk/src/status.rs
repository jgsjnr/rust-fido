//! Wire status bytes (§9.5-compatible, frozen).
//!
//! `0x00` OK, `0x01` NEED_UP, `0x02` NEED_PIN, `0x03` NO_SLOT,
//! `0x04` BAD_ENVELOPE, `0x05` NEED_BINDING (BLE/WiFi only, never USB).

/// §9.5 OK.
pub const STATUS_OK: u8 = 0x00;
/// §9.5 user-presence required.
pub const STATUS_NEED_UP: u8 = 0x01;
/// §9.5 PIN required.
pub const STATUS_NEED_PIN: u8 = 0x02;
/// §9.5 no slot (e.g. PIV slots 24-27 full; never overwrite).
pub const STATUS_NO_SLOT: u8 = 0x03;
/// §9.5 generic failure (framing/opcode; no retry).
pub const STATUS_BAD_ENVELOPE: u8 = 0x04;
/// §9.5 extension: binding required (BLE/WiFi only, never USB/CTAP).
pub const STATUS_NEED_BINDING: u8 = 0x05;

#[cfg(test)]
mod tests {
    use crate::status::{
        STATUS_BAD_ENVELOPE, STATUS_NEED_BINDING, STATUS_NEED_PIN, STATUS_NEED_UP, STATUS_NO_SLOT,
        STATUS_OK,
    };

    #[test]
    fn wire_statuses_frozen() {
        assert_eq!(STATUS_OK, 0x00);
        assert_eq!(STATUS_NEED_UP, 0x01);
        assert_eq!(STATUS_NEED_PIN, 0x02);
        assert_eq!(STATUS_NO_SLOT, 0x03);
        assert_eq!(STATUS_BAD_ENVELOPE, 0x04);
        assert_eq!(STATUS_NEED_BINDING, 0x05);
    }
}
