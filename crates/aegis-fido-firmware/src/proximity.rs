//! Proximidade pura por RSSI (sem BLE real, sem relogio real).
//!
//! - Trava (`Away`) apos `lock_secs` acumulados abaixo de `lock_rssi_dbm`.
//! - `Locked` somente via [`ProximityMonitor::confirm_lock`] (nunca automatico).
//! - Volta a `Near` somente acima de `lock_rssi_dbm + hysteresis_db`.
//! - `update` nunca sai de `Locked` sozinho: exige presenca+PIN via [`ProximityMonitor::unlock`].
//! - `no_std` compativel: sem alloc, sem I/O, tempo injetado (`elapsed_secs`).
//! - RSSI nunca e fator de auth: apenas sinaliza ausencia para o chamador travar.
//!
//! Limites padrao ([`ProximityConfig::default`]): trava abaixo de -75 dBm por
//! 10 s, com histerese de 5 dB (retorno somente acima de -70 dBm).

/// Maximo de segundos aceitos por chamada de `update` (anti-DoS).
const MAX_ELAPSED_SECS_PER_UPDATE: u32 = 60;

/// Configuracao da politica de proximidade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProximityConfig {
    /// Trava quando RSSI fica abaixo deste valor (dBm, ex. -75).
    pub lock_rssi_dbm: i16,
    /// Segundos acumulados abaixo do threshold para ir a `Away`.
    pub lock_secs: u32,
    /// Histerese em dB para voltar a `Near` (ex. 5 => retorna acima de -70).
    pub hysteresis_db: u8,
}

impl Default for ProximityConfig {
    /// Padrao: trava < -75 dBm por 10 s, histerese 5 dB.
    fn default() -> Self {
        Self {
            lock_rssi_dbm: -75,
            lock_secs: 10,
            hysteresis_db: 5,
        }
    }
}

/// Estado de proximidade do autenticador.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProximityState {
    /// Perto: RSSI acima do threshold.
    Near,
    /// Longe: ausente por `lock_secs`; aguardando confirmacao de trava.
    Away,
    /// Travado: exige presenca+PIN para voltar a `Near`.
    Locked,
}

/// Monitor de proximidade com relogio injetado (testavel no host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProximityMonitor {
    config: ProximityConfig,
    state: ProximityState,
    below_secs: u32,
}

impl ProximityMonitor {
    /// Cria em `Near`, sem tempo acumulado.
    pub fn new(config: ProximityConfig) -> Self {
        Self {
            config,
            state: ProximityState::Near,
            below_secs: 0,
        }
    }

    /// Estado atual (copia, sem borrow).
    pub fn state(&self) -> ProximityState {
        self.state
    }

    /// Configuracao atual (copia, sem borrow).
    pub fn config(&self) -> ProximityConfig {
        self.config
    }

    /// Atualiza o estado a partir de uma amostra de RSSI e do tempo decorrido.
    ///
    /// - `None` (sem leitura) conta como sinal fraco (conservador: tende a travar).
    /// - Fraco (`rssi < lock_rssi_dbm`) acumula `elapsed_secs`; ao atingir
    ///   `lock_secs`, transita para `Away`.
    /// - Bom (`rssi >= lock_rssi_dbm + hysteresis_db`) zera o acumulado e, se
    ///   em `Away`, volta a `Near`.
    /// - Banda de histerese (entre os dois limites) congela tudo: anti-flap.
    /// - Em `Locked`, nunca muda sozinho (nem com RSSI bom); use [`Self::unlock`].
    pub fn update(&mut self, rssi_dbm: Option<i16>, elapsed_secs: u32) -> ProximityState {
        if self.state == ProximityState::Locked {
            return ProximityState::Locked;
        }
        // Clamp anti-DoS: uma amostra nao pode injetar tempo arbitrario.
        let elapsed_secs = elapsed_secs.min(MAX_ELAPSED_SECS_PER_UPDATE);
        let release_dbm = self
            .config
            .lock_rssi_dbm
            .saturating_add(self.config.hysteresis_db as i16);
        match rssi_dbm {
            // Sinal bom: reseta acumulado; Away volta a Near.
            Some(rssi) if rssi >= release_dbm => {
                self.below_secs = 0;
                if self.state == ProximityState::Away {
                    self.state = ProximityState::Near;
                }
            }
            // Sinal fraco (ou sem leitura): acumula; Near vira Away no limite.
            Some(rssi) if rssi < self.config.lock_rssi_dbm => {
                self.below_secs = self.below_secs.saturating_add(elapsed_secs);
                if self.below_secs >= self.config.lock_secs {
                    self.state = ProximityState::Away;
                }
            }
            None => {
                self.below_secs = self.below_secs.saturating_add(elapsed_secs);
                if self.below_secs >= self.config.lock_secs {
                    self.state = ProximityState::Away;
                }
            }
            // Banda de histerese: mantem estado e acumulado (anti-flap).
            Some(_) => {}
        }
        self.state
    }

    /// Confirma a trava: `Away` vira `Locked`. Nos demais estados, sem efeito.
    pub fn confirm_lock(&mut self) -> ProximityState {
        if self.state == ProximityState::Away {
            self.state = ProximityState::Locked;
        }
        self.state
    }

    /// Destrava somente de `Locked` com presenca fisica E PIN valido.
    ///
    /// Retorna `true` se destravou (volta a `Near` com acumulado zerado).
    pub fn unlock(&mut self, presence: bool, pin_ok: bool) -> bool {
        if self.state == ProximityState::Locked && presence && pin_ok {
            self.state = ProximityState::Near;
            self.below_secs = 0;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Arrange
    fn monitor() -> ProximityMonitor {
        ProximityMonitor::new(ProximityConfig::default())
    }

    #[test]
    fn should_lock_away_when_weak_for_10s() {
        // Arrange
        let mut m = monitor();
        // Act
        let st = m.update(Some(-80), 10);
        // Assert
        assert_eq!(st, ProximityState::Away);
    }

    #[test]
    fn should_not_lock_before_10s() {
        // Arrange
        let mut m = monitor();
        // Act
        let st = m.update(Some(-80), 9);
        // Assert
        assert_eq!(st, ProximityState::Near);
    }

    #[test]
    fn should_hold_away_inside_hysteresis_band() {
        // Arrange: -75 threshold, histerese 5 => banda [-75, -70)
        let mut m = monitor();
        // Act
        m.update(Some(-80), 10);
        let st = m.update(Some(-72), 5);
        // Assert: anti-flap, continua Away
        assert_eq!(st, ProximityState::Away);
    }

    #[test]
    fn should_never_auto_unlock_from_locked_on_good_rssi() {
        // Arrange
        let mut m = monitor();
        // Act
        m.update(Some(-80), 10);
        m.confirm_lock();
        let st = m.update(Some(-50), 30);
        // Assert
        assert_eq!(st, ProximityState::Locked);
    }

    #[test]
    fn should_return_to_near_above_threshold_plus_hysteresis() {
        // Arrange: Away apos 10 s fraco
        let mut m = monitor();
        // Act
        m.update(Some(-80), 10);
        let st = m.update(Some(-65), 1);
        // Assert: -65 >= -75 + 5 (-70) => Near
        assert_eq!(st, ProximityState::Near);
    }

    #[test]
    fn should_need_confirm_to_reach_locked() {
        // Arrange
        let mut m = monitor();
        // Act: fraco por muito tempo nunca trava sozinho
        let st = m.update(Some(-80), 60);
        // Assert
        assert_eq!(st, ProximityState::Away);
        // Act: confirmacao leva a Locked
        let st = m.confirm_lock();
        // Assert
        assert_eq!(st, ProximityState::Locked);
    }

    #[test]
    fn should_unlock_only_with_presence_and_pin() {
        // Arrange
        let mut m = monitor();
        // Act
        m.update(Some(-80), 10);
        m.confirm_lock();
        // Assert: sem PIN nao destrava
        assert!(!m.unlock(true, false));
        assert_eq!(m.state(), ProximityState::Locked);
        // Assert: sem presenca nao destrava
        assert!(!m.unlock(false, true));
        assert_eq!(m.state(), ProximityState::Locked);
        // Act: presenca + PIN destrava para Near
        // Assert
        assert!(m.unlock(true, true));
        assert_eq!(m.state(), ProximityState::Near);
    }

    #[test]
    fn should_treat_missing_sample_as_weak() {
        // Arrange
        let mut m = monitor();
        // Act
        let st = m.update(None, 10);
        // Assert
        assert_eq!(st, ProximityState::Away);
    }

    #[test]
    fn should_clamp_huge_elapsed_to_60s() {
        // Arrange: 1 s acumulado, depois amostra gigante com sinal fraco
        let mut m = monitor();
        m.update(Some(-80), 1);
        // Act: u32::MAX deve clampar para 60 s, nao estourar o acumulado
        let st = m.update(Some(-80), u32::MAX);
        // Assert: ainda trava (1 + 60 >= 10) mas sem overflow/panico
        assert_eq!(st, ProximityState::Away);
        // Act: sinal bom reseta normalmente apos o clamp
        let st = m.update(Some(-65), 1);
        // Assert
        assert_eq!(st, ProximityState::Near);
    }
}
