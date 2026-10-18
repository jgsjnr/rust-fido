extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use crate::oath::presence::{PresenceError, PresenceVerifier};

/// Nitrokey Command IDs
pub const NK_CMD_STATUS: u8 = 0x01;
pub const NK_CMD_VERSION: u8 = 0x02;
pub const NK_CMD_UUID: u8 = 0x03;
pub const NK_CMD_TEST_TOUCH: u8 = 0x04;
pub const NK_CMD_PIN_STATUS: u8 = 0x05;
pub const NK_CMD_FACTORY_RESET: u8 = 0x07;

/// Nitrokey Command Status Codes
pub const NK_STATUS_SUCCESS: u8 = 0x00;
pub const NK_STATUS_INVALID_COMMAND: u8 = 0x01;
pub const NK_STATUS_INVALID_PARAMETER: u8 = 0x02;
pub const NK_STATUS_TOUCH_TIMEOUT: u8 = 0x03;
pub const NK_STATUS_BUSY: u8 = 0x04;

/// Nitrokey Device Status representation compatible with `nitropy nk3 status`
#[derive(Debug, Clone)]
pub struct NitrokeyStatus {
    pub uuid: [u8; 16],
    pub version: [u8; 3], // [1, 0, 0]
    pub variant: String,
    pub pin_retries: u8,
    pub pin_set: bool,
    pub is_locked: bool,
}

impl Default for NitrokeyStatus {
    fn default() -> Self {
        Self {
            uuid: [
                0xAE, 0x61, 0x50, 0x33, 0x10, 0x20, 0x30, 0x40,
                0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
            ],
            version: [1, 0, 0],
            variant: String::from("AegisKey S3 (Nitrokey Compatible)"),
            pin_retries: 3,
            pin_set: false,
            is_locked: false,
        }
    }
}

impl NitrokeyStatus {
    pub fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid,
            ..Default::default()
        }
    }

    /// Process a Nitrokey command packet and return status code + response payload
    pub fn handle_command<P: PresenceVerifier>(
        &mut self,
        cmd: u8,
        _payload: &[u8],
        presence: &mut P,
    ) -> (u8, Vec<u8>) {
        match cmd {
            NK_CMD_STATUS => {
                let mut resp = Vec::new();
                resp.extend_from_slice(&self.uuid);
                resp.extend_from_slice(&self.version);
                resp.push(self.pin_retries);
                resp.push(if self.pin_set { 1 } else { 0 });
                resp.push(if self.is_locked { 1 } else { 0 });
                (NK_STATUS_SUCCESS, resp)
            }
            NK_CMD_VERSION => {
                let mut resp = Vec::new();
                resp.extend_from_slice(self.variant.as_bytes());
                (NK_STATUS_SUCCESS, resp)
            }
            NK_CMD_UUID => {
                (NK_STATUS_SUCCESS, self.uuid.to_vec())
            }
            NK_CMD_TEST_TOUCH => {
                match presence.wait_for_presence(3000) {
                    Ok(true) => (NK_STATUS_SUCCESS, alloc::vec![1]),
                    Ok(false) | Err(PresenceError::Timeout) => (NK_STATUS_TOUCH_TIMEOUT, alloc::vec![0]),
                    Err(_) => (NK_STATUS_INVALID_PARAMETER, alloc::vec![0]),
                }
            }
            NK_CMD_PIN_STATUS => {
                let mut resp = Vec::new();
                resp.push(self.pin_retries);
                resp.push(if self.pin_set { 1 } else { 0 });
                (NK_STATUS_SUCCESS, resp)
            }
            _ => (NK_STATUS_INVALID_COMMAND, Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oath::presence::{AlwaysPresentVerifier, NeverPresentVerifier};

    #[test]
    fn test_nitrokey_status_command() {
        let mut nk = NitrokeyStatus::default();
        let mut presence = AlwaysPresentVerifier;

        let (status, resp) = nk.handle_command(NK_CMD_STATUS, &[], &mut presence);
        assert_eq!(status, NK_STATUS_SUCCESS);
        assert!(resp.len() >= 22);
        assert_eq!(&resp[0..16], &nk.uuid);
        assert_eq!(&resp[16..19], &[1, 0, 0]);
    }

    #[test]
    fn test_nitrokey_touch_command() {
        let mut nk = NitrokeyStatus::default();
        let mut touch = AlwaysPresentVerifier;
        let (status, _) = nk.handle_command(NK_CMD_TEST_TOUCH, &[], &mut touch);
        assert_eq!(status, NK_STATUS_SUCCESS);

        let mut no_touch = NeverPresentVerifier;
        let (status2, _) = nk.handle_command(NK_CMD_TEST_TOUCH, &[], &mut no_touch);
        assert_eq!(status2, NK_STATUS_TOUCH_TIMEOUT);
    }
}
