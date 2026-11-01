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
/// Efeito LED correspondente ao estado real do Secure Guard (0x3A..0x3E).
/// - Unprovisioned: Azul Ciano suave constante (R:0, G:40, B:60)
/// - Locked / RateLimited / RecoveryRequired: Âmbar/Laranja constante (R:60, G:25, B:0)
/// - Unlocked: Verde Esmeralda constante (R:0, G:60, B:15)
pub fn effect_for_secure_guard_state(
    state: aegis_fido_core::secure_guard::SecureGuardState,
) -> LedEffect {
    use aegis_fido_core::secure_guard::SecureGuardState;
    match state {
        SecureGuardState::Unprovisioned => LedEffect::Solid(Color::SECURE_GUARD_UNPROVISIONED),
        SecureGuardState::Unlocked => LedEffect::Solid(Color::SECURE_GUARD_UNLOCKED),
        _ => LedEffect::Solid(Color::SECURE_GUARD_LOCKED),
    }
}

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
    fn secure_guard_led_maps_all_states() {
        use aegis_fido_core::secure_guard::SecureGuardState;
        assert_eq!(
            effect_for_secure_guard_state(SecureGuardState::Unprovisioned),
            LedEffect::Solid(Color::SECURE_GUARD_UNPROVISIONED)
        );
        assert_eq!(
            effect_for_secure_guard_state(SecureGuardState::Unlocked),
            LedEffect::Solid(Color::SECURE_GUARD_UNLOCKED)
        );
        assert_eq!(
            effect_for_secure_guard_state(SecureGuardState::Locked),
            LedEffect::Solid(Color::SECURE_GUARD_LOCKED)
        );
        assert_eq!(
            effect_for_secure_guard_state(SecureGuardState::RateLimited),
            LedEffect::Solid(Color::SECURE_GUARD_LOCKED)
        );
        assert_eq!(
            effect_for_secure_guard_state(SecureGuardState::RecoveryRequired),
            LedEffect::Solid(Color::SECURE_GUARD_LOCKED)
        );
    }

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
