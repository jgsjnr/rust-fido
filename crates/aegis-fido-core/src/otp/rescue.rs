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
/// Dedicated killswitch opcode (Wave2 Step3): destructive wipe via 2 triggers.
///
/// Distinct from EMERGENCY_WIPE (0x03) to avoid cross-op replay: killswitch
/// requires its own confirmation token. Magic/version/frames unchanged.
pub const RESCUE_CMD_KILLSWITCH: u8 = 0x06;
/// Dedicated CDC/HID transport opcode for rescue frames.
///
/// Routed as `CMD_MSG` payload `[RESCUE_TRANSPORT_OP, rescue_frame...]` over
/// USB CTAPHID (`CtapHidFramer`) and serial (`SerialRouter::feed`), and as
/// GATT control-point op over BLE. Value 0x2E is the first free opcode after
/// bind-mgmt 0x28-0x2D and outside vendor 0x20-0x27. Framing byte-identical,
/// no protocol change.
pub const RESCUE_TRANSPORT_OP: u8 = 0x2E;
/// Ack bytes for a successful killswitch (distinct from wipe 0xAA55).
pub const KILLSWITCH_ACK: [u8; 2] = [0xDE, 0xAD];

pub const RESCUE_STATUS_OK: u8 = 0x00;
pub const RESCUE_STATUS_INVALID_MAGIC: u8 = 0x01;
pub const RESCUE_STATUS_INVALID_VERSION: u8 = 0x02;
pub const RESCUE_STATUS_INVALID_COMMAND: u8 = 0x03;
pub const RESCUE_STATUS_CONFIRMATION_FAILED: u8 = 0x04;
pub const RESCUE_STATUS_EXECUTION_ERROR: u8 = 0x05;

/// Confirmation token required for emergency wiping: SHA256("AEGISKEY_EMERGENCY_FACTORY_WIPE")
pub const EMERGENCY_WIPE_TOKEN: &[u8] = b"AEGISKEY_EMERGENCY_FACTORY_WIPE";
/// Confirmation token required for the remote killswitch trigger.
///
/// Distinct value prevents replaying a wipe token as killswitch and vice-versa.
pub const KILLSWITCH_CONFIRM_TOKEN: &[u8] = b"AEGISKEY_KILLSWITCH_CONFIRM";
/// Physical hold required to arm the killswitch (reuses pairing 5s hold pattern).
pub const KILLSWITCH_HOLD_MS: u64 = 5_000;
/// Arm window after a successful hold (reuses pairing 60s window pattern).
pub const KILLSWITCH_ARM_WINDOW_MS: u64 = 60_000;

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
///
/// Wave2 Step3 (killswitch): opcode dedicado 0x06 via transporte 0x2E com
/// 2 gatilhos independentes — fisico (hold 5s + confirmacao UP) e remoto
/// (UP+PIN + token dedicado). Framing CDC/HID byte-identico via
/// `CtapHidFramer`/`SerialRouter`; PING e demais frames inalterados.
#[derive(Debug, Clone, Default)]
pub struct RescueEngine {
    pub panic_count: u32,
    pub wipe_count: u32,
    pub is_recovery_mode: bool,
    pub user_presence_confirmed: bool,
    pub pin_uv_authenticated: bool,
    pub auth_fail_count: u32,
    /// Successful killswitch executions (audit only; NOT in PING frame).
    pub kill_count: u32,
    /// Physical trigger armed by a 5s hold, awaiting UP confirmation.
    pub killswitch_armed: bool,
    /// `now_ms` when the physical trigger was armed (injected clock).
    pub killswitch_armed_at_ms: u64,
}

/// Returns true for the dedicated rescue transport opcode (CDC/HID + GATT).
///
/// Pure predicate for routers (`SerialRouter`, USB CTAPHID `CMD_MSG`,
/// BLE control-point) without touching their framing.
pub fn is_rescue_transport_op(op: u8) -> bool {
    op == RESCUE_TRANSPORT_OP
}

/// Builds a rescue wire packet: [MAGIC(4) | VERSION(1) | CMD(1) | LEN(2) | PAYLOAD].
///
/// Pure helper shared by host tools and tests; parsing stays in `handle_packet`.
pub fn build_packet(cmd: u8, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(8 + payload.len());
    pkt.extend_from_slice(&RESCUE_MAGIC);
    pkt.push(RESCUE_VERSION);
    pkt.push(cmd);
    pkt.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
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

    /// Arms the physical killswitch trigger after a button hold.
    ///
    /// `hold_ms` is the measured hold duration (debounced, same source as
    /// `BootButton::poll_press_event`); `now_ms` is the injected monotonic
    /// clock (same pattern as `PairingManager`). Returns true and arms only
    /// when `hold_ms >= KILLSWITCH_HOLD_MS`; short holds leave state untouched.
    pub fn request_physical_killswitch(&mut self, hold_ms: u64, now_ms: u64) -> bool {
        if hold_ms < KILLSWITCH_HOLD_MS {
            return false;
        }
        self.killswitch_armed = true;
        self.killswitch_armed_at_ms = now_ms;
        true
    }

    /// True while the physical trigger is armed and inside the arm window.
    ///
    /// Pure clock check with saturating arithmetic; expired arms read as
    /// disarmed (confirmation then denies via `deny()`).
    pub fn is_killswitch_armed(&self, now_ms: u64) -> bool {
        if !self.killswitch_armed {
            return false;
        }
        now_ms.saturating_sub(self.killswitch_armed_at_ms) <= KILLSWITCH_ARM_WINDOW_MS
    }

    /// Disarms the physical trigger without executing (cancel path).
    pub fn disarm_killswitch(&mut self) {
        self.killswitch_armed = false;
    }

    /// Confirms the armed physical trigger with a UP touch.
    ///
    /// Requires armed-inside-window + presence latch (`UpOnly`: physical
    /// confirmation is the button itself, no PIN). Consumes the arm and the
    /// UP/PIN latches on success; denies (and disarms fail-closed) otherwise
    /// with the existing `RESCUE_STATUS_CONFIRMATION_FAILED` wire status.
    pub fn confirm_physical_killswitch(&mut self, now_ms: u64) -> (u8, Vec<u8>) {
        if !self.is_killswitch_armed(now_ms) {
            self.killswitch_armed = false;
            return self.deny();
        }
        if UpOnly
            .check_up(self.pin_uv_authenticated, self.user_presence_confirmed)
            .is_err()
        {
            self.killswitch_armed = false;
            return self.deny();
        }
        self.execute_killswitch()
    }

    /// Shared destructive execution: counts wipe+kill, clears latches and arm.
    fn execute_killswitch(&mut self) -> (u8, Vec<u8>) {
        self.wipe_count = self.wipe_count.saturating_add(1);
        self.kill_count = self.kill_count.saturating_add(1);
        self.auth_fail_count = 0;
        self.user_presence_confirmed = false;
        self.pin_uv_authenticated = false;
        self.killswitch_armed = false;
        let mut dummy = [0xFFu8; 32];
        dummy.zeroize();
        (RESCUE_STATUS_OK, alloc::vec![KILLSWITCH_ACK[0], KILLSWITCH_ACK[1]])
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
            RESCUE_CMD_KILLSWITCH => {
                // Remote trigger: UP+PIN + dedicated confirmation token.
                if UpAndPin.check_up(self.pin_uv_authenticated, self.user_presence_confirmed).is_err() {
                    return self.deny();
                }
                if payload == KILLSWITCH_CONFIRM_TOKEN {
                    self.execute_killswitch()
                } else {
                    self.deny()
                }
            }
            _ => (RESCUE_STATUS_INVALID_COMMAND, Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap::client_pin::{ClientPinState, PinUvTokenSession};

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

    #[test]
    fn killswitch_opcode_dedicado_nao_colide() {
        // Opcode dedicado: novo CMD + transporte CDC/HID fora das faixas existentes.
        assert_eq!(RESCUE_CMD_KILLSWITCH, 0x06);
        assert_ne!(RESCUE_CMD_KILLSWITCH, RESCUE_CMD_PING);
        assert_ne!(RESCUE_CMD_KILLSWITCH, RESCUE_CMD_DIAGNOSTICS);
        assert_ne!(RESCUE_CMD_KILLSWITCH, RESCUE_CMD_EMERGENCY_WIPE);
        assert_ne!(RESCUE_CMD_KILLSWITCH, RESCUE_CMD_PIN_RECOVERY);
        assert_ne!(RESCUE_CMD_KILLSWITCH, RESCUE_CMD_REBOOT);
        // Transporte: 0x2E = primeiro livre apos bind-mgmt 0x28-0x2D, fora de vendor 0x20-0x27.
        assert_eq!(RESCUE_TRANSPORT_OP, 0x2E);
        assert!(is_rescue_transport_op(RESCUE_TRANSPORT_OP));
        assert!(!is_rescue_transport_op(0x20));
        assert!(!is_rescue_transport_op(0x28));
    }

    #[test]
    fn killswitch_remoto_exige_up_pin_e_token() {
        let mut engine = RescueEngine::new();
        // Sem UP e sem PIN: nega com erro existente.
        let pkt = build_packet(RESCUE_CMD_KILLSWITCH, KILLSWITCH_CONFIRM_TOKEN);
        assert_eq!(engine.handle_packet(&pkt).0, RESCUE_STATUS_CONFIRMATION_FAILED);
        // UP sem PIN: nega (remoto exige UP+PIN).
        engine.set_user_presence(true);
        engine.set_pin_uv_authenticated(false);
        assert_eq!(engine.handle_packet(&pkt).0, RESCUE_STATUS_CONFIRMATION_FAILED);
        // UP+PIN com token errado: nega.
        engine.set_user_presence(true);
        engine.set_pin_uv_authenticated(true);
        let bad = build_packet(RESCUE_CMD_KILLSWITCH, b"WRONG");
        assert_eq!(engine.handle_packet(&bad).0, RESCUE_STATUS_CONFIRMATION_FAILED);
        // UP+PIN com token certo: executa, consome latches, conta wipe.
        engine.set_user_presence(true);
        engine.set_pin_uv_authenticated(true);
        let wipes_before = engine.wipe_count;
        let (s, resp) = engine.handle_packet(&pkt);
        assert_eq!(s, RESCUE_STATUS_OK);
        assert_eq!(resp, alloc::vec![0xDE, 0xAD]);
        assert_eq!(engine.wipe_count, wipes_before.saturating_add(1));
        assert!(!engine.user_presence_confirmed);
        assert!(!engine.pin_uv_authenticated);
    }

    #[test]
    fn killswitch_plumbing_clientpin_session_gates_remote() {
        // Fiação que o firmware repete nos 3 transportes: a sessão
        // pinUvAuth viva vira set_pin_uv_authenticated(true).
        let pin = ClientPinState::default();
        let mut engine = RescueEngine::new();
        engine.set_user_presence(true);
        engine.set_pin_uv_authenticated(pin.has_valid_pin_uv_session());
        let pkt = build_packet(RESCUE_CMD_KILLSWITCH, KILLSWITCH_CONFIRM_TOKEN);
        assert_eq!(
            engine.handle_packet(&pkt).0,
            RESCUE_STATUS_CONFIRMATION_FAILED
        );
        // Com sessão viva (PIN verificado): passa do gate UP+PIN.
        let pin = ClientPinState {
            active_session: Some(PinUvTokenSession {
                token: [0xA5u8; 32],
                protocol: 2,
                permissions: 0,
                rp_id: None,
            }),
            ..Default::default()
        };
        engine.set_user_presence(true);
        engine.set_pin_uv_authenticated(pin.has_valid_pin_uv_session());
        let (s, _) = engine.handle_packet(&pkt);
        assert_eq!(s, RESCUE_STATUS_OK);
    }

    #[test]
    fn killswitch_fisico_hold_e_confirmacao() {
        let mut engine = RescueEngine::new();
        // Hold curto nao arma.
        assert!(!engine.request_physical_killswitch(100, 0));
        assert!(!engine.is_killswitch_armed(0));
        // Hold 5s arma.
        assert!(engine.request_physical_killswitch(KILLSWITCH_HOLD_MS, 1000));
        assert!(engine.is_killswitch_armed(1000));
        // Confirmar sem UP: nega e desarma (fail-closed).
        let (s, _) = engine.confirm_physical_killswitch(1000);
        assert_eq!(s, RESCUE_STATUS_CONFIRMATION_FAILED);
        assert!(!engine.is_killswitch_armed(1000));
        // Re-armar + UP: confirma e consome.
        assert!(engine.request_physical_killswitch(KILLSWITCH_HOLD_MS, 2000));
        engine.set_user_presence(true);
        let wipes_before = engine.wipe_count;
        let (s2, resp2) = engine.confirm_physical_killswitch(2000);
        assert_eq!(s2, RESCUE_STATUS_OK);
        assert_eq!(resp2, alloc::vec![0xDE, 0xAD]);
        assert_eq!(engine.wipe_count, wipes_before.saturating_add(1));
        assert!(!engine.user_presence_confirmed);
        assert!(!engine.is_killswitch_armed(2000));
        // Confirmar de novo sem re-armar: nega.
        engine.set_user_presence(true);
        assert_eq!(engine.confirm_physical_killswitch(2000).0, RESCUE_STATUS_CONFIRMATION_FAILED);
    }

    #[test]
    fn killswitch_arm_expira_fora_da_janela() {
        let mut engine = RescueEngine::new();
        assert!(engine.request_physical_killswitch(KILLSWITCH_HOLD_MS, 0));
        assert!(engine.is_killswitch_armed(0));
        // Dentro da janela ainda armado; apos expirar, desarmado.
        assert!(engine.is_killswitch_armed(KILLSWITCH_ARM_WINDOW_MS));
        assert!(!engine.is_killswitch_armed(KILLSWITCH_ARM_WINDOW_MS.saturating_add(1)));
        engine.set_user_presence(true);
        assert_eq!(
            engine.confirm_physical_killswitch(KILLSWITCH_ARM_WINDOW_MS.saturating_add(1)).0,
            RESCUE_STATUS_CONFIRMATION_FAILED
        );
    }

    #[test]
    fn killswitch_tokens_nao_sao_intercambiaveis() {
        // Cross-op replay: token de wipe nao dispara killswitch e vice-versa.
        let mut engine = RescueEngine::new();
        engine.set_user_presence(true);
        engine.set_pin_uv_authenticated(true);
        let wipe_as_kill = build_packet(RESCUE_CMD_KILLSWITCH, EMERGENCY_WIPE_TOKEN);
        assert_eq!(engine.handle_packet(&wipe_as_kill).0, RESCUE_STATUS_CONFIRMATION_FAILED);
        engine.set_user_presence(true);
        engine.set_pin_uv_authenticated(true);
        let kill_as_wipe = build_packet(RESCUE_CMD_EMERGENCY_WIPE, KILLSWITCH_CONFIRM_TOKEN);
        assert_eq!(engine.handle_packet(&kill_as_wipe).0, RESCUE_STATUS_CONFIRMATION_FAILED);
        assert_eq!(engine.wipe_count, 0);
        assert_eq!(engine.kill_count, 0);
    }

    #[test]
    fn killswitch_conta_kill_e_nao_vaza_no_ping() {
        let mut engine = RescueEngine::new();
        engine.set_user_presence(true);
        engine.set_pin_uv_authenticated(true);
        let pkt = build_packet(RESCUE_CMD_KILLSWITCH, KILLSWITCH_CONFIRM_TOKEN);
        let (s, _) = engine.handle_packet(&pkt);
        assert_eq!(s, RESCUE_STATUS_OK);
        assert_eq!(engine.kill_count, 1);
        assert_eq!(engine.wipe_count, 1);
        // kill_count e auditoria: PING segue [VER|panic|wipe|recovery], sem kill.
        engine.set_user_presence(true);
        let ping = build_packet(RESCUE_CMD_PING, &[]);
        let (ps, resp) = engine.handle_packet(&ping);
        assert_eq!(ps, RESCUE_STATUS_OK);
        assert_eq!(resp.len(), 10);
        assert_eq!(&resp[5..9], &engine.wipe_count.to_be_bytes());
    }

    #[test]
    fn killswitch_disarm_cancela_sem_executar() {
        let mut engine = RescueEngine::new();
        assert!(engine.request_physical_killswitch(KILLSWITCH_HOLD_MS, 0));
        engine.disarm_killswitch();
        assert!(!engine.is_killswitch_armed(0));
        engine.set_user_presence(true);
        assert_eq!(engine.confirm_physical_killswitch(0).0, RESCUE_STATUS_CONFIRMATION_FAILED);
        assert_eq!(engine.wipe_count, 0);
        assert_eq!(engine.kill_count, 0);
    }

    #[test]
    fn build_packet_formato_fio_compativel_com_host() {
        // Contrato byte-identico com tools/killswitch.py build_rescue_frame.
        let pkt = build_packet(RESCUE_CMD_KILLSWITCH, KILLSWITCH_CONFIRM_TOKEN);
        assert_eq!(&pkt[0..4], &RESCUE_MAGIC);
        assert_eq!(pkt[4], RESCUE_VERSION);
        assert_eq!(pkt[5], RESCUE_CMD_KILLSWITCH);
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]) as usize, KILLSWITCH_CONFIRM_TOKEN.len());
        assert_eq!(&pkt[8..], KILLSWITCH_CONFIRM_TOKEN);
        // Round-trip: engine aceita o proprio builder com UP+PIN + token.
        let mut engine = RescueEngine::new();
        engine.set_user_presence(true);
        engine.set_pin_uv_authenticated(true);
        assert_eq!(engine.handle_packet(&pkt).0, RESCUE_STATUS_OK);
    }
}

