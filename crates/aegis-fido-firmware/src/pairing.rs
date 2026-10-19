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
}

impl PairingManager {
    /// Cria em `Idle`, sem bonding.
    pub fn new() -> Self {
        Self {
            state: PairingState::Idle,
            bonded: false,
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
                if now_ms >= expires_ms => {
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
        self.state = PairingState::Idle;
        true
    }

    /// Trava manual (erro/timeout reportado pelo transporte).
    pub fn lock(&mut self) {
        self.state = PairingState::Locked;
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
}
