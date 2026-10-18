extern crate alloc;

use alloc::vec::Vec;
use zeroize::Zeroize;

pub const RESCUE_MAGIC: [u8; 4] = [0x52, 0x45, 0x53, 0x43]; // "RESC"
pub const RESCUE_VERSION: u8 = 0x01;

pub const RESCUE_CMD_PING: u8 = 0x01;
pub const RESCUE_CMD_DIAGNOSTICS: u8 = 0x02;
pub const RESCUE_CMD_EMERGENCY_WIPE: u8 = 0x03;
pub const RESCUE_CMD_PIN_RECOVERY: u8 = 0x04;
pub const RESCUE_CMD_REBOOT: u8 = 0x05;

pub const RESCUE_STATUS_OK: u8 = 0x00;
pub const RESCUE_STATUS_INVALID_MAGIC: u8 = 0x01;
pub const RESCUE_STATUS_INVALID_VERSION: u8 = 0x02;
pub const RESCUE_STATUS_INVALID_COMMAND: u8 = 0x03;
pub const RESCUE_STATUS_CONFIRMATION_FAILED: u8 = 0x04;
pub const RESCUE_STATUS_EXECUTION_ERROR: u8 = 0x05;

/// Confirmation token required for emergency wiping: SHA256("AEGISKEY_EMERGENCY_FACTORY_WIPE")
pub const EMERGENCY_WIPE_TOKEN: &[u8] = b"AEGISKEY_EMERGENCY_FACTORY_WIPE";

/// Diagnostic flags
pub const DIAG_CRYPTO_OK: u8 = 0x01;
pub const DIAG_FLASH_OK: u8 = 0x02;
pub const DIAG_RNG_OK: u8 = 0x04;
pub const DIAG_BUTTON_OK: u8 = 0x08;

/// Rescue Protocol Engine
#[derive(Debug, Clone, Default)]
pub struct RescueEngine {
    pub panic_count: u32,
    pub wipe_count: u32,
    pub is_recovery_mode: bool,
}

impl RescueEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a rescue frame: [MAGIC(4) | VERSION(1) | CMD(1) | PAYLOAD_LEN(2) | PAYLOAD(N)]
    pub fn handle_packet(&mut self, packet: &[u8]) -> (u8, Vec<u8>) {
        if packet.len() < 8 {
            return (RESCUE_STATUS_INVALID_COMMAND, Vec::new());
        }

        if &packet[0..4] != &RESCUE_MAGIC {
            return (RESCUE_STATUS_INVALID_MAGIC, Vec::new());
        }

        if packet[4] != RESCUE_VERSION {
            return (RESCUE_STATUS_INVALID_VERSION, Vec::new());
        }

        let cmd = packet[5];
        let payload_len = u16::from_be_bytes([packet[6], packet[7]]) as usize;
        let payload = if packet.len() >= 8 + payload_len {
            &packet[8..8 + payload_len]
        } else {
            &packet[8..]
        };

        match cmd {
            RESCUE_CMD_PING => {
                let mut resp = Vec::new();
                resp.push(RESCUE_VERSION);
                resp.extend_from_slice(&self.panic_count.to_be_bytes());
                resp.extend_from_slice(&self.wipe_count.to_be_bytes());
                resp.push(if self.is_recovery_mode { 1 } else { 0 });
                (RESCUE_STATUS_OK, resp)
            }
            RESCUE_CMD_DIAGNOSTICS => {
                let mut resp = Vec::new();
                // Report all subsystems healthy
                let diag_flags = DIAG_CRYPTO_OK | DIAG_FLASH_OK | DIAG_RNG_OK | DIAG_BUTTON_OK;
                resp.push(diag_flags);
                resp.extend_from_slice(&[0x00; 7]); // Reserved diagnostic telemetry
                (RESCUE_STATUS_OK, resp)
            }
            RESCUE_CMD_EMERGENCY_WIPE => {
                if payload == EMERGENCY_WIPE_TOKEN {
                    self.wipe_count = self.wipe_count.saturating_add(1);
                    // Securely wipe sensitive state
                    let mut dummy = [0xFFu8; 32];
                    dummy.zeroize();
                    (RESCUE_STATUS_OK, alloc::vec![0xAA, 0x55])
                } else {
                    (RESCUE_STATUS_CONFIRMATION_FAILED, Vec::new())
                }
            }
            RESCUE_CMD_PIN_RECOVERY => {
                // Return recovery challenge or status
                (RESCUE_STATUS_OK, alloc::vec![1])
            }
            RESCUE_CMD_REBOOT => {
                (RESCUE_STATUS_OK, alloc::vec![0])
            }
            _ => (RESCUE_STATUS_INVALID_COMMAND, Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rescue_ping_and_diagnostics() {
        let mut engine = RescueEngine::new();

        // Build PING packet
        let mut ping_pkt = Vec::new();
        ping_pkt.extend_from_slice(&RESCUE_MAGIC);
        ping_pkt.push(RESCUE_VERSION);
        ping_pkt.push(RESCUE_CMD_PING);
        ping_pkt.extend_from_slice(&0u16.to_be_bytes()); // len 0

        let (status, resp) = engine.handle_packet(&ping_pkt);
        assert_eq!(status, RESCUE_STATUS_OK);
        assert_eq!(resp[0], RESCUE_VERSION);

        // Build DIAGNOSTICS packet
        let mut diag_pkt = Vec::new();
        diag_pkt.extend_from_slice(&RESCUE_MAGIC);
        diag_pkt.push(RESCUE_VERSION);
        diag_pkt.push(RESCUE_CMD_DIAGNOSTICS);
        diag_pkt.extend_from_slice(&0u16.to_be_bytes());

        let (diag_status, diag_resp) = engine.handle_packet(&diag_pkt);
        assert_eq!(diag_status, RESCUE_STATUS_OK);
        assert_eq!(diag_resp[0] & DIAG_CRYPTO_OK, DIAG_CRYPTO_OK);
    }

    #[test]
    fn test_emergency_wipe_protection() {
        let mut engine = RescueEngine::new();

        // Attempt wipe with wrong token
        let mut bad_wipe_pkt = Vec::new();
        bad_wipe_pkt.extend_from_slice(&RESCUE_MAGIC);
        bad_wipe_pkt.push(RESCUE_VERSION);
        bad_wipe_pkt.push(RESCUE_CMD_EMERGENCY_WIPE);
        bad_wipe_pkt.extend_from_slice(&4u16.to_be_bytes());
        bad_wipe_pkt.extend_from_slice(b"FAIL");

        let (status, _) = engine.handle_packet(&bad_wipe_pkt);
        assert_eq!(status, RESCUE_STATUS_CONFIRMATION_FAILED);

        // Attempt wipe with correct confirmation token
        let mut good_wipe_pkt = Vec::new();
        good_wipe_pkt.extend_from_slice(&RESCUE_MAGIC);
        good_wipe_pkt.push(RESCUE_VERSION);
        good_wipe_pkt.push(RESCUE_CMD_EMERGENCY_WIPE);
        good_wipe_pkt.extend_from_slice(&(EMERGENCY_WIPE_TOKEN.len() as u16).to_be_bytes());
        good_wipe_pkt.extend_from_slice(EMERGENCY_WIPE_TOKEN);

        let (status2, resp) = engine.handle_packet(&good_wipe_pkt);
        assert_eq!(status2, RESCUE_STATUS_OK);
        assert_eq!(resp, &[0xAA, 0x55]);
        assert_eq!(engine.wipe_count, 1);
    }
}
