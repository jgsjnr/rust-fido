//! Wave4 — renderer LED headless da jornada de pareamento.
//!
//! Mesma maquina de estados do `pairing.rs`, sem LCD:
//! - pisca rapido = arming (hold progressivo)
//! - respiracao azul = pairing (BLE/AP)
//! - verde solido = pareado (bonded, idle)
//! - vermelho solido = erro/timeout (locked)
//!
//! Sem alloc, sem I/O: funcao pura `PairingState -> LedEffect`.

use crate::led::{Color, LedEffect};
use crate::pairing::PairingState;

/// Efeito LED correspondente ao estado (headless).
pub fn effect_for_pairing_state(state: PairingState, bonded: bool) -> LedEffect {
    match state {
        PairingState::Idle => {
            if bonded {
                LedEffect::Solid(Color::GREEN)
            } else {
                LedEffect::Breathing {
                    color: Color::CYAN,
                    period_ms: 2000,
                }
            }
        }
        PairingState::Arming { .. } => LedEffect::PromptTouch,
        PairingState::PairingBle { .. } | PairingState::PairingAp { .. } => LedEffect::Breathing {
            color: Color::BLUE,
            period_ms: 1600,
        },
        PairingState::Locked => LedEffect::Solid(Color::RED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::PairingManager;

    #[test]
    fn headless_maps_all_states() {
        assert_eq!(
            effect_for_pairing_state(PairingState::Idle, false),
            LedEffect::Breathing {
                color: Color::CYAN,
                period_ms: 2000
            }
        );
        assert_eq!(
            effect_for_pairing_state(PairingState::Idle, true),
            LedEffect::Solid(Color::GREEN)
        );
        assert_eq!(
            effect_for_pairing_state(PairingState::Arming { start_ms: 0 }, false),
            LedEffect::PromptTouch
        );
        assert_eq!(
            effect_for_pairing_state(PairingState::PairingBle { expires_ms: 9 }, false),
            LedEffect::Breathing {
                color: Color::BLUE,
                period_ms: 1600
            }
        );
        assert_eq!(
            effect_for_pairing_state(PairingState::PairingAp { expires_ms: 9 }, false),
            LedEffect::Breathing {
                color: Color::BLUE,
                period_ms: 1600
            }
        );
        assert_eq!(
            effect_for_pairing_state(PairingState::Locked, false),
            LedEffect::Solid(Color::RED)
        );
    }

    #[test]
    fn manager_and_led_stay_in_sync() {
        let mut m = PairingManager::new();
        let e0 = effect_for_pairing_state(m.state(), m.is_bonded());
        assert!(matches!(e0, LedEffect::Breathing { .. }));
        m.lock();
        let e1 = effect_for_pairing_state(m.state(), m.is_bonded());
        assert_eq!(e1, LedEffect::Solid(Color::RED));
    }
}

// ---------------------------------------------------------------------------
// T-LED-HOLD: classificação pura de `TEST_LED_*` p/ o latch de diagnóstico.
//
// Contrato (test-mode only; release ignora a linha):
// - `TEST_LED_{RED,GREEN,BLUE,OFF}`: trava cor sólida p/ olhos. O latch
//   reaplicado no loop legado vale SÓ no idle livre (tela `IdleStandby` +
//   pairing `Idle` + sem bond); jornada (pairing > UP > BLE), telas
//   próprias (boot/sucesso/erro/TOTP) e o timeout vencem o hold — sem
//   vazar cor sobre o estado real e sem flicker (um escritor por vez).
// - `TEST_LED_ON` (compat HIL: o harness envia `test_led_state("ON")`):
//   só ack (`led_set TEST_LED_ON`), SEM travar cor em nenhum loop — sem
//   residual entre sessões. Aliasar ON a RED sólido mascarava o azul do
//   pairing e o âmbar do UP e deixava vermelho residual (regressão
//   fd/hil-usb-tests 24/10).
// - Comparação EXATA (sem `starts_with`): `TEST_LED_RELEASE` não casa
//   `TEST_LED_RED`, `TEST_LED_ONX` não casa `TEST_LED_ON`.
// ---------------------------------------------------------------------------

/// Decisão de latch p/ uma linha `TEST_LED_*` já aparada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "test-mode")]
pub enum TestLedLine {
    /// Trava cor sólida p/ olhos (idle livre, com expiração; RELEASE libera).
    Hold(LedEffect),
    /// Compat HIL: só ack, sem tocar no LED.
    PingAck,
    /// Não é comando de latch (outros fluxos decidem).
    Ignored,
}

/// Expiração do latch de diagnóstico: 60 s (= janela de pareamento
/// `PAIRING_WINDOW_MS`; o `led_probe.py` segura 2 s e solta explícito,
/// então nunca bate no teto; hold esquecido não vaza p/ a próxima sessão).
#[cfg(feature = "test-mode")]
pub const TEST_LED_HOLD_TIMEOUT_MS: u64 = 60_000;

/// Classifica a linha (comparação exata; fora de test-mode o chamador
/// nem compila este ramo — release ignora a linha).
#[cfg(feature = "test-mode")]
pub fn classify_test_led_line(cmd: &str) -> TestLedLine {
    match cmd {
        "TEST_LED_RED" => TestLedLine::Hold(LedEffect::Solid(Color::RED)),
        "TEST_LED_GREEN" => TestLedLine::Hold(LedEffect::Solid(Color::GREEN)),
        "TEST_LED_BLUE" => TestLedLine::Hold(LedEffect::Solid(Color::BLUE)),
        "TEST_LED_OFF" => TestLedLine::Hold(LedEffect::Off),
        "TEST_LED_ON" => TestLedLine::PingAck,
        _ => TestLedLine::Ignored,
    }
}

// T8: LED para a TrustFacade (unico ponto de efeito do pareamento).
//
// Delega para `effect_for_pairing_state`; proximidade `Locked` (quando a
// feature `proximity` esta ON e o monitor trava) forca vermelho solido
// (mesmo `Locked` do pareamento). Sem display/LCD: funcao pura.
// ---------------------------------------------------------------------------

/// Efeito LED do estado de confianca (pareamento + trava de proximidade).
///
/// `proximity_locked` so existe com a feature `proximity`; sem ela, e
/// sempre `false` (R12 mutavel: mesma assinatura nos dois builds).
pub fn effect_for_trust_state(
    state: PairingState,
    bonded: bool,
    #[cfg(feature = "proximity")] proximity_locked: bool,
) -> LedEffect {
    #[cfg(feature = "proximity")]
    if proximity_locked {
        return LedEffect::Solid(Color::RED);
    }
    effect_for_pairing_state(state, bonded)
}

#[cfg(test)]
mod pairing_led_trust_tests {
    use super::*;

    #[test]
    fn trust_delega_para_pareamento_sem_trava() {
        let e = effect_for_trust_state(
            PairingState::Idle,
            false,
            #[cfg(feature = "proximity")]
            false,
        );
        assert_eq!(e, effect_for_pairing_state(PairingState::Idle, false));
        let e = effect_for_trust_state(
            PairingState::Locked,
            false,
            #[cfg(feature = "proximity")]
            false,
        );
        assert_eq!(e, LedEffect::Solid(Color::RED));
    }

    #[cfg(feature = "proximity")]
    #[test]
    fn trust_forca_vermelho_com_proximidade_locked() {
        let e = effect_for_trust_state(PairingState::Idle, true, true);
        assert_eq!(e, LedEffect::Solid(Color::RED));
    }
}

#[cfg(all(test, feature = "test-mode"))]
mod test_led_line_tests {
    use super::*;

    #[test]
    fn primarias_travam_cor_exata() {
        assert_eq!(
            classify_test_led_line("TEST_LED_RED"),
            TestLedLine::Hold(LedEffect::Solid(Color::RED))
        );
        assert_eq!(
            classify_test_led_line("TEST_LED_GREEN"),
            TestLedLine::Hold(LedEffect::Solid(Color::GREEN))
        );
        assert_eq!(
            classify_test_led_line("TEST_LED_BLUE"),
            TestLedLine::Hold(LedEffect::Solid(Color::BLUE))
        );
        assert_eq!(
            classify_test_led_line("TEST_LED_OFF"),
            TestLedLine::Hold(LedEffect::Off)
        );
    }

    #[test]
    fn on_e_ping_sem_latch() {
        // Compat HIL: ack sem travar cor (sem vazar p/ boot/jornada/BLE e
        // sem residual). Regressão 24/10: ON aliado a RED sólido.
        assert_eq!(classify_test_led_line("TEST_LED_ON"), TestLedLine::PingAck);
    }

    #[test]
    fn sem_prefixo_sem_sufixo() {
        // `starts_with` casaria errado (ONX casaria ON, REDX casaria RED).
        // Comparação exata barra a classe inteira de falsos positivos.
        for cmd in [
            "TEST_LED_RELEASE",
            "TEST_LED_RED ",
            "TEST_LED_ONX",
            "TEST_LED_REDX",
            "TEST_LED_STATE",
            "TEST_UP",
            "[FREERTOS] tick 100.",
            "",
        ] {
            assert_eq!(classify_test_led_line(cmd), TestLedLine::Ignored, "{cmd}");
        }
    }

    #[test]
    fn timeout_iguala_janela_de_pareamento() {
        assert_eq!(TEST_LED_HOLD_TIMEOUT_MS, crate::config::PAIRING_WINDOW_MS);
    }
}
