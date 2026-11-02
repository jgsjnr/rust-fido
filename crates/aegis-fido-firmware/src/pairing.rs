//! Wave4 — jornada de pareamento via hold 5s (GPIO0).
//!
//! - Segurar BOOT 5s (`LONG_PRESS_MS=5000`, debounce 50ms) entra em pareamento.
//! - Janela 60s (`PAIRING_WINDOW_SECS`), exige UP por operacao + bonding.
//! - Saida por timeout, novo hold 5s, ou pareamento completo.
//! - `no_std` compativel: sem alloc, sem I/O, relogio injetado (`now_ms`).

use crate::button::DEBOUNCE_TIME_MS;
use crate::config::{LONG_PRESS_MS, PAIRING_WINDOW_MS};
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};

/// Debounce minimo antes de considerar borda estavel (ms).
pub const PAIRING_DEBOUNCE_MS: u64 = DEBOUNCE_TIME_MS;

/// Validade maxima de um bond BLE sem re-pareamento (30 dias, conservador).
///
/// Passou disso: `forget_stale_bond` derruba o flag em RAM e o chamador
/// apaga o LTK do NimBLE (`esp_ble_forget_bonds`); o dono re-pareia com
/// janela + UP + MITM. RAM-only de proposito: reboot ja zera `bonded`
/// (fail-closed sem NVS extra); este teto cobre sessoes longas ligadas.
pub const BLE_BOND_MAX_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// `true` quando o bond completado em `bonded_at_ms` expirou em `now_ms`.
///
/// Relogio monotonico: regressao nunca marca expirado por skew
/// (`saturating_sub`); reboot zera o flag em RAM de todo modo.
pub fn ble_bond_expired(bonded_at_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(bonded_at_ms) >= BLE_BOND_MAX_AGE_MS
}

/// Estados da jornada de pareamento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingState {
    /// Repouso, advertising BLE normal (sem flag pairing).
    Idle,
    /// Hold progressivo: botao pressionado, contando ate 5s.
    Arming {
        /// Instante em que o hold estavel comecou.
        start_ms: u64,
    },
    /// Pareamento BLE ativo (advertising com flag pairing).
    PairingBle {
        /// Instante de expiracao da janela de 60s.
        expires_ms: u64,
    },
    /// Pareamento via AP ativo (alternativa ao BLE).
    PairingAp {
        /// Instante de expiracao da janela de 60s.
        expires_ms: u64,
    },
    /// Bloqueado apos timeout/erro; exige novo hold 5s.
    Locked,
}

/// Maquina de pareamento com relogio fake (testavel no host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingManager {
    state: PairingState,
    /// `true` apos bonding completo (uso unico por sessao).
    bonded: bool,
    /// Instante do bonding (ms monotonicos); `None` = sem timestamp.
    bonded_at_ms: Option<u64>,
}

impl PairingManager {
    /// Cria em `Idle`, sem bonding.
    pub fn new() -> Self {
        Self {
            state: PairingState::Idle,
            bonded: false,
            bonded_at_ms: None,
        }
    }

    /// Estado atual (copia, sem borrow).
    pub fn state(&self) -> PairingState {
        self.state
    }

    /// `true` apos pareamento completo nesta sessao.
    pub fn is_bonded(&self) -> bool {
        self.bonded
    }

    /// `true` com bond valido e dentro da validade (fresco).
    ///
    /// Porta de reconexao sem janela (`should_advertise_reconnect`) e
    /// expiracao periodica (`forget_stale_bond`) usam esta porta, nao
    /// `is_bonded` cru: bond velho nao reconecta sozinho.
    pub fn is_bond_fresh(&self, now_ms: u64) -> bool {
        self.bonded && !self.bond_expired(now_ms)
    }

    /// `true` quando o bond existe mas passou da validade (ou esta sem
    /// timestamp: fail-closed, exige re-pareamento). Sem bond = `false`.
    pub fn bond_expired(&self, now_ms: u64) -> bool {
        if !self.bonded {
            return false;
        }
        match self.bonded_at_ms {
            Some(t) => ble_bond_expired(t, now_ms),
            None => true,
        }
    }

    /// Esquece bond expirado (RAM); `true` = limpou (o chamador remove o
    /// LTK do NimBLE via `esp_ble_forget_bonds`). Fresco/ausente = `false`.
    pub fn forget_stale_bond(&mut self, now_ms: u64) -> bool {
        if self.bond_expired(now_ms) {
            self.bonded = false;
            self.bonded_at_ms = None;
            crate::ltrace!(LtCat::Pairing, LtEvt::PairingTimeout, now_ms);
            true
        } else {
            false
        }
    }

    /// Bonding e sempre obrigatorio (JustWorks+bonding+UP).
    pub fn requires_bonding(&self) -> bool {
        true
    }

    /// `true` quando a janela de 60s esta aberta.
    pub fn is_pairing_window_open(&self, now_ms: u64) -> bool {
        match self.state {
            PairingState::PairingBle { expires_ms } | PairingState::PairingAp { expires_ms } => {
                now_ms < expires_ms
            }
            _ => false,
        }
    }

    /// Progresso do hold 0..100 (somente em `Arming`).
    pub fn arming_progress_pct(&self, now_ms: u64) -> u8 {
        match self.state {
            PairingState::Arming { start_ms } => {
                let elapsed = now_ms.saturating_sub(start_ms);
                let pct = (elapsed * 100) / LONG_PRESS_MS.max(1);
                pct.min(100) as u8
            }
            _ => 0,
        }
    }

    /// Atualiza a partir do nivel fisico do botao (chamar a cada poll).
    ///
    /// `pressed` ja deve refletir leitura crua; o debounce de 50ms e
    /// aplicado na transicao `Idle`/`Locked` -> `Arming`.
    pub fn on_button_level(&mut self, pressed: bool, now_ms: u64) {
        match self.state {
            PairingState::Idle | PairingState::Locked => {
                if pressed {
                    self.state = PairingState::Arming { start_ms: now_ms };
                    crate::ltrace!(LtCat::Pairing, LtEvt::PairingArming, now_ms);
                }
            }
            PairingState::Arming { start_ms } => {
                if !pressed {
                    // Soltou antes dos 5s: cancela (exige debounce estavel).
                    let held = now_ms.saturating_sub(start_ms);
                    if held < PAIRING_DEBOUNCE_MS {
                        return;
                    }
                    self.state = PairingState::Idle;
                } else if now_ms.saturating_sub(start_ms) >= LONG_PRESS_MS {
                    self.state = PairingState::PairingBle {
                        expires_ms: now_ms.saturating_add(PAIRING_WINDOW_MS),
                    };
                }
            }
            PairingState::PairingBle { .. } | PairingState::PairingAp { .. } => {
                // Novo hold 5s dentro da janela reinicia a janela (re-pareamento).
                // Fora da janela o `tick` ja moveu para `Locked`; tratado acima.
                let _ = pressed;
            }
        }
    }

    /// Avanca timeouts; chamar a cada tick com `now_ms` monotônico.
    pub fn tick(&mut self, now_ms: u64) {
        match self.state {
            PairingState::PairingBle { expires_ms } | PairingState::PairingAp { expires_ms }
                if now_ms >= expires_ms =>
            {
                self.state = PairingState::Locked;
                crate::ltrace!(LtCat::Pairing, LtEvt::PairingTimeout, now_ms);
            }
            _ => {}
        }
    }

    /// Alterna BLE -> AP (via menu); preserva expiracao restante.
    pub fn enter_ap_mode(&mut self) {
        if let PairingState::PairingBle { expires_ms } = self.state {
            self.state = PairingState::PairingAp { expires_ms };
        }
    }

    /// Alterna AP -> BLE (via menu); preserva expiracao restante.
    pub fn enter_ble_mode(&mut self) {
        if let PairingState::PairingAp { expires_ms } = self.state {
            self.state = PairingState::PairingBle { expires_ms };
        }
    }

    /// Completa o pareamento: exige UP (latch uso unico pelo chamador).
    /// Retorna `false` se fora da janela ou sem presenca.
    pub fn complete_pairing(&mut self, presence_confirmed: bool, now_ms: u64) -> bool {
        if !self.is_pairing_window_open(now_ms) {
            return false;
        }
        if !presence_confirmed {
            return false;
        }
        crate::ltrace!(LtCat::Pairing, LtEvt::PairingPaired, now_ms);
        self.bonded = true;
        self.bonded_at_ms = Some(now_ms);
        self.state = PairingState::Idle;
        true
    }

    /// Trava manual (erro/timeout reportado pelo transporte).
    pub fn lock(&mut self) {
        self.state = PairingState::Locked;
    }

    /// Abre a MESMA janela de 60s do hold 5s via comando de teste (test-mode).
    ///
    /// Software abre a janela, NAO confirma presenca: `bonded` segue `false`
    /// e os gates posteriores (UP por operacao + bonding) continuam exigidos.
    /// Auditoria: o `ltrace!` carrega `source=software` para distinguir do
    /// hold fisico (que registra o clock puro).
    #[cfg(feature = "test-mode")]
    pub fn open_test_window(&mut self, now_ms: u64) {
        self.open_test_window_secs(now_ms, PAIRING_WINDOW_MS / 1000);
    }

    /// Variante longa (coordenação humana lenta): mesma janela com N segundos.
    ///
    /// Test-mode only. Existe para o operador conseguir tocar no BOOT dentro
    /// da janela sem corrida de 60s; gates idênticos à janela normal.
    #[cfg(feature = "test-mode")]
    pub fn open_test_window_secs(&mut self, now_ms: u64, window_secs: u64) {
        self.state = PairingState::PairingBle {
            expires_ms: now_ms.saturating_add(window_secs.saturating_mul(1000)),
        };
        crate::ltrace!(LtCat::Pairing, LtEvt::PairingArming, SoftwareArming(now_ms));
    }

    /// Fecha a janela de teste (test-only; determinismo entre sessões).
    ///
    /// Espelha `TEST_PAIRING_CLOSE`: vira `Locked`, mesmo estado do timeout
    /// natural; não toca em `bonded`.
    #[cfg(feature = "test-mode")]
    pub fn close_test_window(&mut self) {
        self.state = PairingState::Locked;
    }

    /// Abre a janela de 60s por comando do host (produto, USB/serial).
    ///
    /// Software abre a janela, NÃO confirma presença: `bonded` segue `false`
    /// e os gates (UP por operação + bonding) continuam exigidos — as mesmas
    /// garantias do hold físico. Segurança: exposto só nos transportes
    /// físicos (USB nativo + UART); BLE nunca expõe. Auditoria: `ltrace!`
    /// carrega `source=host` para distinguir do hold e do test-mode.
    pub fn open_host_window(&mut self, now_ms: u64) {
        self.state = PairingState::PairingBle {
            expires_ms: now_ms.saturating_add(PAIRING_WINDOW_MS),
        };
        crate::ltrace!(LtCat::Pairing, LtEvt::PairingArming, HostArming(now_ms));
    }
}

/// Comando de teste que abre a janela de pareamento (so existe com test-mode).
///
/// Sem a feature a linha e desconhecida: nenhum dispatch a reconhece.
#[cfg(feature = "test-mode")]
pub const TEST_PAIRING_OPEN_CMD: &str = "TEST_PAIRING_OPEN";

/// Comando de teste que fecha a janela residual (determinismo entre sessões).
///
/// Fecha para `Locked` (mesmo estado do timeout natural); sem `test-mode` a
/// linha é desconhecida.
#[cfg(feature = "test-mode")]
pub const TEST_PAIRING_CLOSE_CMD: &str = "TEST_PAIRING_CLOSE";

/// Variante longa (300s) para coordenação humana: mesmos gates, mais folga.
#[cfg(feature = "test-mode")]
pub const TEST_PAIRING_OPEN_300_CMD: &str = "TEST_PAIRING_OPEN_300";
/// Janela longa em segundos.
#[cfg(feature = "test-mode")]
pub const TEST_PAIRING_OPEN_300_SECS: u64 = 300;

/// Opcode produto: abre a janela de 60s por comando do host (USB/serial).
///
/// Primeiro byte livre após rescue (`0x2E`); `0x2F` reservado aqui.
/// Segurança: só existe nos transportes físicos (USB nativo + UART);
/// BLE nunca expõe. Abrir a janela NÃO confirma presença nem bonding:
/// UP por operação + bonding seguem exigidos (fail-closed).
pub const OP_HOST_PAIRING_OPEN: u8 = 0x2F;

/// `true` para `[0x2F]` vazio (único formato aceito; resto é ignorado).
pub fn is_host_pairing_msg(op: u8, payload_len: usize) -> bool {
    op == OP_HOST_PAIRING_OPEN && payload_len == 0
}

/// Detalhe do `ltrace!` para abertura via software (auditoria).
///
/// `Display` = `software now_ms=<t>` - distingue do hold fisico no monitor.
#[cfg(feature = "test-mode")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftwareArming(pub u64);

#[cfg(feature = "test-mode")]
impl core::fmt::Display for SoftwareArming {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "software now_ms={}", self.0)
    }
}

/// Detalhe do `ltrace!` para abertura via host USB/serial (auditoria).
///
/// `Display` = `host now_ms=<t>` - distingue do hold físico e do test-mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostArming(pub u64);

impl core::fmt::Display for HostArming {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "host now_ms={}", self.0)
    }
}

impl Default for PairingManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hold_5s_enters_pairing_ble() {
        let mut m = PairingManager::new();
        assert_eq!(m.state(), PairingState::Idle);
        // Pressiona em t=1000, segura ate 1000+5000.
        m.on_button_level(true, 1000);
        assert!(matches!(m.state(), PairingState::Arming { .. }));
        // Meio do hold: 50%.
        assert_eq!(m.arming_progress_pct(3500), 50);
        m.on_button_level(true, 6000);
        assert!(m.is_pairing_window_open(6000));
        assert!(matches!(m.state(), PairingState::PairingBle { .. }));
    }

    #[test]
    fn release_early_cancels_arming() {
        let mut m = PairingManager::new();
        m.on_button_level(true, 0);
        m.on_button_level(false, 1000);
        assert_eq!(m.state(), PairingState::Idle);
    }

    #[test]
    fn timeout_locks_and_rehold_repairs() {
        let mut m = PairingManager::new();
        m.on_button_level(true, 0);
        m.on_button_level(true, LONG_PRESS_MS);
        assert!(m.is_pairing_window_open(LONG_PRESS_MS));
        m.tick(LONG_PRESS_MS + PAIRING_WINDOW_MS);
        assert_eq!(m.state(), PairingState::Locked);
        // Novo hold 5s a partir de Locked volta a parear.
        m.on_button_level(true, LONG_PRESS_MS + PAIRING_WINDOW_MS + 10);
        let t1 = LONG_PRESS_MS + PAIRING_WINDOW_MS + 10;
        m.on_button_level(true, t1 + LONG_PRESS_MS);
        assert!(m.is_pairing_window_open(t1 + LONG_PRESS_MS));
    }

    #[test]
    fn complete_requires_presence_and_window() {
        let mut m = PairingManager::new();
        m.on_button_level(true, 0);
        m.on_button_level(true, LONG_PRESS_MS);
        assert!(!m.complete_pairing(false, LONG_PRESS_MS + 100));
        assert!(!m.is_bonded());
        assert!(m.complete_pairing(true, LONG_PRESS_MS + 100));
        assert!(m.is_bonded());
        assert_eq!(m.state(), PairingState::Idle);
    }

    #[test]
    fn ap_mode_preserves_expiry() {
        let mut m = PairingManager::new();
        m.on_button_level(true, 0);
        m.on_button_level(true, LONG_PRESS_MS);
        m.enter_ap_mode();
        assert!(matches!(m.state(), PairingState::PairingAp { .. }));
        m.enter_ble_mode();
        assert!(matches!(m.state(), PairingState::PairingBle { .. }));
    }

    #[cfg(feature = "test-mode")]
    #[test]
    fn test_window_opens_same_60s_window_without_presence() {
        let mut m = PairingManager::new();
        m.open_test_window(1000);
        assert!(m.is_pairing_window_open(1000));
        assert!(m.is_pairing_window_open(1000 + PAIRING_WINDOW_MS - 1));
        // Software abre a janela, NAO confirma presenca nem bonding.
        assert!(!m.is_bonded());
        assert!(!m.complete_pairing(false, 1100));
        assert!(!m.is_bonded());
        // Expira em 60s igual ao hold: tick move para Locked.
        m.tick(1000 + PAIRING_WINDOW_MS);
        assert_eq!(m.state(), PairingState::Locked);
        assert!(!m.is_pairing_window_open(1000 + PAIRING_WINDOW_MS));
    }

    #[cfg(feature = "test-mode")]
    #[test]
    fn test_window_ltrace_marks_software_source() {
        use core::fmt::Write as _;
        let mut buf = [0u8; 64];
        let len = {
            let mut w = FmtBuf {
                buf: &mut buf,
                len: 0,
            };
            let _ = write!(w, "{}", SoftwareArming(1234));
            w.len
        };
        let text = core::str::from_utf8(&buf[..len]).expect("ascii");
        assert!(
            text.contains("software"),
            "audit must tell software apart from hold"
        );
        assert!(text.contains("1234"));
        assert_eq!(TEST_PAIRING_OPEN_CMD, "TEST_PAIRING_OPEN");
    }

    #[cfg(feature = "test-mode")]
    #[test]
    fn test_window_close_locks_and_reopen_works() {
        let mut m = PairingManager::new();
        m.open_test_window(1000);
        assert!(m.is_pairing_window_open(1000));
        m.close_test_window();
        assert_eq!(m.state(), PairingState::Locked);
        assert!(!m.is_pairing_window_open(1000));
        // Fechar nao confirma presenca nem bonding.
        assert!(!m.is_bonded());
        // Reabrir (60s) volta a funcionar sem reset.
        m.open_test_window(2000);
        assert!(m.is_pairing_window_open(2000));
        assert!(!m.is_bonded());
        // Reabrir (300s) tambem volta a funcionar; fechar encerra igual.
        m.close_test_window();
        assert!(!m.is_pairing_window_open(2100));
        m.open_test_window_secs(3000, TEST_PAIRING_OPEN_300_SECS);
        assert!(m.is_pairing_window_open(3000 + TEST_PAIRING_OPEN_300_SECS * 1000 - 1));
        assert!(!m.is_bonded());
        m.close_test_window();
        assert_eq!(m.state(), PairingState::Locked);
        assert!(!m.is_pairing_window_open(3000));
    }

    #[cfg(feature = "test-mode")]
    struct FmtBuf<'a> {
        buf: &'a mut [u8],
        len: usize,
    }

    #[cfg(feature = "test-mode")]
    impl core::fmt::Write for FmtBuf<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let take = s.len().min(self.buf.len().saturating_sub(self.len));
            self.buf[self.len..self.len + take].copy_from_slice(&s.as_bytes()[..take]);
            self.len += take;
            Ok(())
        }
    }

    #[test]
    fn host_window_opens_same_60s_without_presence() {
        let mut m = PairingManager::new();
        m.open_host_window(2000);
        assert!(m.is_pairing_window_open(2000));
        assert!(m.is_pairing_window_open(2000 + PAIRING_WINDOW_MS - 1));
        assert!(!m.is_bonded());
        assert!(!m.complete_pairing(false, 2100));
        m.tick(2000 + PAIRING_WINDOW_MS);
        assert!(!m.is_pairing_window_open(2000 + PAIRING_WINDOW_MS));
    }

    #[test]
    fn host_pairing_msg_accepts_only_empty_0x2f() {
        assert!(is_host_pairing_msg(OP_HOST_PAIRING_OPEN, 0));
        assert_eq!(OP_HOST_PAIRING_OPEN, 0x2F);
        assert!(!is_host_pairing_msg(OP_HOST_PAIRING_OPEN, 1));
        assert!(!is_host_pairing_msg(0x2E, 0));
        assert!(!is_host_pairing_msg(0x30, 0));
        let text = format!("{}", HostArming(77));
        assert!(text.contains("host"));
        assert!(text.contains("77"));
    }
}

// ---------------------------------------------------------------------------
// T8: gate de pareamento para a TrustFacade (ordem binding -> UP -> PIN).
//
// A janela de 60 s e a primeira condicao do `claim` (`BindingManager`);
// UP e PIN seguem na `TrustFacade::authorize_config`. `no_std` compativel.
//
// FAIL-SAFE / POWER-LOSS: `PairingManager` e so RAM; reset => `Idle`
// (janela perdida, exige novo hold 5 s: fail-closed, sem parcial).
// ---------------------------------------------------------------------------

/// `true` quando a janela de pareamento esta aberta (gate do `claim`).
///
/// Delega para `PairingManager::is_pairing_window_open`; `Locked` apos
/// timeout nao e janela aberta (exige novo hold 5 s).
pub fn pairing_gate_for_trust(mgr: &PairingManager, now_ms: u64) -> bool {
    mgr.is_pairing_window_open(now_ms)
}

#[cfg(test)]
mod pairing_trust_tests {
    use super::*;
    use crate::config::PAIRING_WINDOW_MS;

    #[test]
    fn gate_espelha_janela_60s() {
        let mut m = PairingManager::new();
        assert!(!pairing_gate_for_trust(&m, 0));
        m.open_host_window(1000);
        assert!(pairing_gate_for_trust(&m, 1000));
        assert!(pairing_gate_for_trust(&m, 1000 + PAIRING_WINDOW_MS - 1));
        m.tick(1000 + PAIRING_WINDOW_MS);
        assert!(!pairing_gate_for_trust(&m, 1000 + PAIRING_WINDOW_MS));
    }
}

#[cfg(test)]
mod bond_expiry_tests {
    use super::*;
    use crate::config::{LONG_PRESS_MS, PAIRING_WINDOW_MS};

    const DAY_MS: u64 = 24 * 60 * 60 * 1000;

    fn bonded_at(t: u64) -> PairingManager {
        let mut m = PairingManager::new();
        m.on_button_level(true, 0);
        m.on_button_level(true, LONG_PRESS_MS);
        assert!(m.complete_pairing(true, t));
        m
    }

    #[test]
    fn teto_conservador_30_dias() {
        assert_eq!(BLE_BOND_MAX_AGE_MS, 30 * DAY_MS);
        assert!(!ble_bond_expired(1_000, 1_000 + BLE_BOND_MAX_AGE_MS - 1));
        assert!(ble_bond_expired(1_000, 1_000 + BLE_BOND_MAX_AGE_MS));
        assert!(ble_bond_expired(0, u64::MAX));
        // Skew (now < bonded_at): nunca expira por skew.
        assert!(!ble_bond_expired(9_000, 1_000));
    }

    #[test]
    fn par_fresco_expira_e_esquece() {
        let mut m = bonded_at(LONG_PRESS_MS + 10);
        let t0 = LONG_PRESS_MS + 10;
        assert!(m.is_bonded());
        assert!(m.is_bond_fresh(t0));
        assert!(!m.bond_expired(t0));
        assert!(!m.forget_stale_bond(t0));
        assert!(m.is_bonded());
        // 29 dias: fresco; 30 dias: expirado.
        assert!(m.is_bond_fresh(t0 + 29 * DAY_MS));
        assert!(!m.is_bond_fresh(t0 + 30 * DAY_MS));
        assert!(m.bond_expired(t0 + 30 * DAY_MS));
        assert!(m.forget_stale_bond(t0 + 30 * DAY_MS));
        assert!(!m.is_bonded());
        assert!(!m.is_bond_fresh(t0 + 30 * DAY_MS));
        // Re-parear re-arma o timestamp.
        m.on_button_level(true, t0 + 30 * DAY_MS + 1);
        m.on_button_level(true, t0 + 30 * DAY_MS + 1 + LONG_PRESS_MS);
        assert!(m.complete_pairing(true, t0 + 30 * DAY_MS + 1 + LONG_PRESS_MS + 5));
        assert!(m.is_bond_fresh(t0 + 30 * DAY_MS + 1 + LONG_PRESS_MS + 5));
    }

    #[test]
    fn janela_60s_intacta_com_expiracao() {
        // A validade do bond nao altera a janela de pareamento.
        let mut m = PairingManager::new();
        m.on_button_level(true, 0);
        m.on_button_level(true, LONG_PRESS_MS);
        assert!(m.is_pairing_window_open(LONG_PRESS_MS + 1));
        m.tick(LONG_PRESS_MS + PAIRING_WINDOW_MS);
        assert!(!m.is_pairing_window_open(LONG_PRESS_MS + PAIRING_WINDOW_MS));
    }
}
