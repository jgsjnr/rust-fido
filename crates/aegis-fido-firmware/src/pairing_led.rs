//! Wave4 — renderer LED headless da jornada de pareamento.
//!
//! Mesma maquina de estados do `pairing.rs`, sem LCD:
//! - pisca rapido = arming (hold progressivo)
//! - respiracao azul = pairing (BLE/AP)
//! - verde solido = pareado (bonded, idle)
//! - vermelho = erro/timeout (locked)
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
        PairingState::Locked => LedEffect::ErrorFlash,
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
            LedEffect::ErrorFlash
        );
    }

    #[test]
    fn manager_and_led_stay_in_sync() {
        let mut m = PairingManager::new();
        let e0 = effect_for_pairing_state(m.state(), m.is_bonded());
        assert!(matches!(e0, LedEffect::Breathing { .. }));
        m.lock();
        let e1 = effect_for_pairing_state(m.state(), m.is_bonded());
        assert_eq!(e1, LedEffect::ErrorFlash);
    }
}
