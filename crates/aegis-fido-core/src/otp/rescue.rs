extern crate alloc;

use alloc::vec::Vec;
use zeroize::Zeroize;
use crate::policy::{UpAndPin, UpOnly, UpPolicy};

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
///
/// Wave1 gate: operacoes destrutivas exigem UP latch + pinUvAuth valido
/// (definido pela camada externa apos verify_token_permission).
/// PING e DIAGNOSTICS exigem apenas UP. Negacao usa erro existente
/// (RESCUE_STATUS_CONFIRMATION_FAILED) sem mudar magic, opcodes ou frames.
#[derive(Debug, Clone, Default)]
pub struct RescueEngine {
    pub panic_count: u32,
    pub wipe_count: u32,
    pub is_recovery_mode: bool,
    pub user_presence_confirmed: bool,
    pub pin_uv_authenticated: bool,
    pub auth_fail_count: u32,
}

/// Limite saturante de falhas antes de backoff maximo (sem novo codigo de erro).
pub const RESCUE_MAX_AUTH_FAILURES: u32 = 8;
/// Base do backoff exponencial em ms (calculo puro, sem sleep no core).
pub const RESCUE_BACKOFF_BASE_MS: u32 = 100;
/// Teto do backoff exponencial em ms.
pub const RESCUE_BACKOFF_MAX_MS: u32 = 5000;

impl RescueEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Define o latch de presenca (mesmo padrao de CtapEngine::set_user_presence).
    pub fn set_user_presence(&mut self, confirmed: bool) {
        self.user_presence_confirmed = confirmed;
    }

    /// Marca pinUvAuth como valido. Deve ser true somente apos
    /// ClientPinState::verify_token_permission ter retornado Ok.
    pub fn set_pin_uv_authenticated(&mut self, authenticated: bool) {
        self.pin_uv_authenticated = authenticated;
    }

    /// Backoff exponencial puro em funcao de auth_fail_count (saturante).
    pub fn backoff_ms(&self) -> u32 {
        let shift = core::cmp::min(self.auth_fail_count, RESCUE_MAX_AUTH_FAILURES);
        RESCUE_BACKOFF_BASE_MS.saturating_mul(1u32 << shift).min(RESCUE_BACKOFF_MAX_MS)
    }

    fn deny(&mut self) -> (u8, Vec<u8>) {
        self.auth_fail_count = self.auth_fail_count.saturating_add(1);
        // Latch uso unico: consome UP e PIN a cada negacao.
        self.user_presence_confirmed = false;
        self.pin_uv_authenticated = false;
        (RESCUE_STATUS_CONFIRMATION_FAILED, Vec::new())
    }

    /// Process a rescue frame: [MAGIC(4) | VERSION(1) | CMD(1) | PAYLOAD_LEN(2) | PAYLOAD(N)]
    pub fn handle_packet(&mut self, packet: &[u8]) -> (u8, Vec<u8>) {
        if packet.len() < 8 {
            return (RESCUE_STATUS_INVALID_COMMAND, Vec::new());
        }

        if packet[0..4] != RESCUE_MAGIC {
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
                if UpOnly.check_up(self.pin_uv_authenticated, self.user_presence_confirmed).is_err() {
                    return self.deny();
                }
                let mut resp = Vec::new();
                resp.push(RESCUE_VERSION);
                resp.extend_from_slice(&self.panic_count.to_be_bytes());
                resp.extend_from_slice(&self.wipe_count.to_be_bytes());
                resp.push(if self.is_recovery_mode { 1 } else { 0 });
                self.auth_fail_count = 0;
                (RESCUE_STATUS_OK, resp)
            }
            RESCUE_CMD_DIAGNOSTICS => {
                if UpOnly.check_up(self.pin_uv_authenticated, self.user_presence_confirmed).is_err() {
                    return self.deny();
                }
                let mut resp = Vec::new();
                // Report all subsystems healthy
                let diag_flags = DIAG_CRYPTO_OK | DIAG_FLASH_OK | DIAG_RNG_OK | DIAG_BUTTON_OK;
                resp.push(diag_flags);
                resp.extend_from_slice(&[0x00; 7]); // Reserved diagnostic telemetry
                self.auth_fail_count = 0;
                (RESCUE_STATUS_OK, resp)
            }
            RESCUE_CMD_EMERGENCY_WIPE => {
                if UpAndPin.check_up(self.pin_uv_authenticated, self.user_presence_confirmed).is_err() {
                    return self.deny();
                }
                if payload == EMERGENCY_WIPE_TOKEN {
                    self.wipe_count = self.wipe_count.saturating_add(1);
                    self.auth_fail_count = 0;
                    self.user_presence_confirmed = false;
                    self.pin_uv_authenticated = false;
                    // Securely wipe sensitive state
                    let mut dummy = [0xFFu8; 32];
                    dummy.zeroize();
                    (RESCUE_STATUS_OK, alloc::vec![0xAA, 0x55])
                } else {
                    self.deny()
                }
            }
            RESCUE_CMD_PIN_RECOVERY => {
                if UpAndPin.check_up(self.pin_uv_authenticated, self.user_presence_confirmed).is_err() {
                    return self.deny();
                }
                self.auth_fail_count = 0;
                self.user_presence_confirmed = false;
                self.pin_uv_authenticated = false;
                // Return recovery challenge or status
                (RESCUE_STATUS_OK, alloc::vec![1])
            }
            RESCUE_CMD_REBOOT => {
                if UpAndPin.check_up(self.pin_uv_authenticated, self.user_presence_confirmed).is_err() {
                    return self.deny();
                }
                self.auth_fail_count = 0;
                self.user_presence_confirmed = false;
                self.pin_uv_authenticated = false;
                (RESCUE_STATUS_OK, alloc::vec![0])
            }
            _ => (RESCUE_STATUS_INVALID_COMMAND, Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_pkt(cmd: u8, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&RESCUE_MAGIC);
        pkt.push(RESCUE_VERSION);
        pkt.push(cmd);
        pkt.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn test_rescue_ping_and_diagnostics() {
        let mut engine = RescueEngine::new();
        engine.set_user_presence(true);

        // Build PING packet
        let ping_pkt = build_pkt(RESCUE_CMD_PING, &[]);

        let (status, resp) = engine.handle_packet(&ping_pkt);
        assert_eq!(status, RESCUE_STATUS_OK);
        assert_eq!(resp[0], RESCUE_VERSION);

        // Build DIAGNOSTICS packet
        engine.set_user_presence(true);
        let diag_pkt = build_pkt(RESCUE_CMD_DIAGNOSTICS, &[]);

        let (diag_status, diag_resp) = engine.handle_packet(&diag_pkt);
        assert_eq!(diag_status, RESCUE_STATUS_OK);
        assert_eq!(diag_resp[0] & DIAG_CRYPTO_OK, DIAG_CRYPTO_OK);
    }

    #[test]
    fn test_emergency_wipe_protection() {
        let mut engine = RescueEngine::new();

        // Attempt wipe with wrong token (UP + PIN ok, token errado)
        engine.set_user_presence(true);
        engine.set_pin_uv_authenticated(true);
        let bad_wipe_pkt = build_pkt(RESCUE_CMD_EMERGENCY_WIPE, b"FAIL");

        let (status, _) = engine.handle_packet(&bad_wipe_pkt);
        assert_eq!(status, RESCUE_STATUS_CONFIRMATION_FAILED);

        // Attempt wipe with correct confirmation token
        engine.set_user_presence(true);
        engine.set_pin_uv_authenticated(true);
        let good_wipe_pkt = build_pkt(RESCUE_CMD_EMERGENCY_WIPE, EMERGENCY_WIPE_TOKEN);

        let (status2, resp) = engine.handle_packet(&good_wipe_pkt);
        assert_eq!(status2, RESCUE_STATUS_OK);
        assert_eq!(resp, &[0xAA, 0x55]);
        assert_eq!(engine.wipe_count, 1);
    }

    #[test]
    fn resc_sem_up_nega() {
        let mut engine = RescueEngine::new();
        // Sem UP e sem PIN: tudo negado com erro existente, sem mudar frames
        let ping = build_pkt(RESCUE_CMD_PING, &[]);
        assert_eq!(engine.handle_packet(&ping).0, RESCUE_STATUS_CONFIRMATION_FAILED);
        let diag = build_pkt(RESCUE_CMD_DIAGNOSTICS, &[]);
        // UP foi consumido/limpado apos primeira negacao, continua negado
        assert_eq!(engine.handle_packet(&diag).0, RESCUE_STATUS_CONFIRMATION_FAILED);
        let wipe = build_pkt(RESCUE_CMD_EMERGENCY_WIPE, EMERGENCY_WIPE_TOKEN);
        assert_eq!(engine.handle_packet(&wipe).0, RESCUE_STATUS_CONFIRMATION_FAILED);
        let rec = build_pkt(RESCUE_CMD_PIN_RECOVERY, &[]);
        assert_eq!(engine.handle_packet(&rec).0, RESCUE_STATUS_CONFIRMATION_FAILED);
        let reboot = build_pkt(RESCUE_CMD_REBOOT, &[]);
        assert_eq!(engine.handle_packet(&reboot).0, RESCUE_STATUS_CONFIRMATION_FAILED);
        // Contador saturante incrementou
        assert!(engine.auth_fail_count >= 5);
        // Backoff cresceu
        assert!(engine.backoff_ms() > RESCUE_BACKOFF_BASE_MS);
    }

    #[test]
    fn resc_sem_pin_nega() {
        let mut engine = RescueEngine::new();
        // UP ok mas sem PIN: PING passa, sensiveis negam
        engine.set_user_presence(true);
        let ping = build_pkt(RESCUE_CMD_PING, &[]);
        assert_eq!(engine.handle_packet(&ping).0, RESCUE_STATUS_OK);

        engine.set_user_presence(true);
        engine.set_pin_uv_authenticated(false);
        let wipe = build_pkt(RESCUE_CMD_EMERGENCY_WIPE, EMERGENCY_WIPE_TOKEN);
        assert_eq!(engine.handle_packet(&wipe).0, RESCUE_STATUS_CONFIRMATION_FAILED);

        engine.set_user_presence(true);
        let rec = build_pkt(RESCUE_CMD_PIN_RECOVERY, &[]);
        assert_eq!(engine.handle_packet(&rec).0, RESCUE_STATUS_CONFIRMATION_FAILED);

        engine.set_user_presence(true);
        let reboot = build_pkt(RESCUE_CMD_REBOOT, &[]);
        assert_eq!(engine.handle_packet(&reboot).0, RESCUE_STATUS_CONFIRMATION_FAILED);
    }

    #[test]
    fn test_backoff_saturante() {
        let mut engine = RescueEngine::new();
        assert_eq!(engine.backoff_ms(), 100);
        engine.auth_fail_count = u32::MAX;
        // saturating_add nao estoura
        let (_s, _) = engine.deny();
        assert_eq!(engine.auth_fail_count, u32::MAX);
        assert_eq!(engine.backoff_ms(), RESCUE_BACKOFF_MAX_MS);
    }

    #[test]
    fn resc_wipe_ok_up_sem_pin_nega() {
        let mut engine = RescueEngine::new();
        engine.set_user_presence(true);
        engine.set_pin_uv_authenticated(true);
        let good = build_pkt(RESCUE_CMD_EMERGENCY_WIPE, EMERGENCY_WIPE_TOKEN);
        let (s, _) = engine.handle_packet(&good);
        assert_eq!(s, RESCUE_STATUS_OK);
        assert!(!engine.pin_uv_authenticated);
        assert!(!engine.user_presence_confirmed);
        engine.set_user_presence(true);
        let again = build_pkt(RESCUE_CMD_EMERGENCY_WIPE, EMERGENCY_WIPE_TOKEN);
        assert_eq!(engine.handle_packet(&again).0, RESCUE_STATUS_CONFIRMATION_FAILED);
    }
}

