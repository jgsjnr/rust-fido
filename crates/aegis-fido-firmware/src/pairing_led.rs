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
/// Ops SOMENTE-LEITURA de polling (metadata/telemetria, sem mutacao).
///
/// - 0x22 KEY_LIST (ids/metadata, sem segredo)
/// - 0x25 OATH_LIST (metadata)
/// - 0x36 WALLET_LIST (metadata wallet)
/// - 0x37 WALLET_ADDR (endereco publico do slot)
/// - 0x38 FW_LOG (log ASCII, sem PII/segredos)
/// - 0x3A SECURE_GUARD_STATUS (telemetria de estado)
/// - 0x3F GET_CAPS (advertisement read-only)
/// - 0x45 PM_LIST (ids opacos, sem labels/segredos)
/// - 0x47 PM_STATUS (contagem/quota, sem segredos)
///
/// Fora: 0x26 OATH_CODE e 0x44 PM_GET liberam segredo (sensiveis);
/// GEN/PUT/DELETE/CONFIG/WIPE mutam estado (mutantes).
pub fn is_read_only_poll_op(op: u8) -> bool {
    matches!(
        op,
        0x22 | 0x25 | 0x36 | 0x37 | 0x38 | 0x3A | 0x3F | 0x45 | 0x47
    )
}

/// Efeito LED para op negada (op, status wire).
///
/// - 0x00 ok => None (mantem o pipeline).
/// - 0x36 Locked em op SOMENTE-LEITURA de polling => None (poll negado nao pisca).
/// - 0x36 em op mutante/sensivel ou 0x04 => Some(ErrorFlash) (efeito existente).
/// - Outro status => None (pipeline decide; sem spoof).
pub fn effect_for_sg_denial(op: u8, status: u8) -> Option<LedEffect> {
    if status == 0x00 {
        return None;
    }
    if status == 0x36 && is_read_only_poll_op(op) {
        return None;
    }
    match status {
        0x36 | 0x04 => Some(LedEffect::ErrorFlash),
        _ => None,
    }
}

/// Efeito LED para op Secure Guard (0x3A..=0x3E), compat.
///
/// Sem op, assume pior caso (mutante/sensivel). Com opcode, prefira effect_for_sg_denial.
pub fn effect_for_sg_status(status: u8) -> Option<LedEffect> {
    effect_for_sg_denial(0xFF, status)
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

#[cfg(test)]
mod sg_status_led_tests {
    use super::*;

    #[test]
    fn sg_ok_keeps_pipeline() {
        assert_eq!(effect_for_sg_status(0x00), None);
    }

    #[test]
    fn sg_error_class_flashes() {
        assert_eq!(effect_for_sg_status(0x36), Some(LedEffect::ErrorFlash));
        assert_eq!(effect_for_sg_status(0x04), Some(LedEffect::ErrorFlash));
    }

    #[test]
    fn sg_other_status_keeps_pipeline() {
        assert_eq!(effect_for_sg_status(0x33), None);
        assert_eq!(effect_for_sg_status(0xF0), None);
    }
}

#[cfg(test)]
mod sg_denial_led_tests {
    use super::*;

    #[test]
    fn poll_read_only_locked_denial_no_led() {
        let ops: [u8; 9] = [0x22, 0x25, 0x36, 0x37, 0x38, 0x3A, 0x3F, 0x45, 0x47];
        for op in ops {
            assert_eq!(effect_for_sg_denial(op, 0x36), None);
        }
    }

    #[test]
    fn poll_list_and_status_locked_denial_no_led() {
        assert_eq!(effect_for_sg_denial(0x22, 0x36), None);
        assert_eq!(effect_for_sg_denial(0x3A, 0x36), None);
    }

    #[test]
    fn mutant_locked_denial_still_flashes() {
        let ops: [u8; 8] = [0x20, 0x23, 0x24, 0x27, 0x35, 0x3D, 0x3E, 0x40];
        for op in ops {
            assert_eq!(effect_for_sg_denial(op, 0x36), Some(LedEffect::ErrorFlash));
        }
    }

    #[test]
    fn sensitive_read_locked_denial_still_flashes() {
        assert_eq!(
            effect_for_sg_denial(0x26, 0x36),
            Some(LedEffect::ErrorFlash)
        );
        assert_eq!(
            effect_for_sg_denial(0x44, 0x36),
            Some(LedEffect::ErrorFlash)
        );
    }

    #[test]
    fn real_error_on_read_only_still_flashes() {
        assert_eq!(
            effect_for_sg_denial(0x22, 0x04),
            Some(LedEffect::ErrorFlash)
        );
        assert_eq!(
            effect_for_sg_denial(0x3A, 0x04),
            Some(LedEffect::ErrorFlash)
        );
    }

    #[test]
    fn ok_keeps_pipeline() {
        assert_eq!(effect_for_sg_denial(0x22, 0x00), None);
        assert_eq!(effect_for_sg_denial(0x3D, 0x00), None);
    }

    #[test]
    fn is_read_only_poll_op_classifies() {
        assert!(is_read_only_poll_op(0x22));
        assert!(is_read_only_poll_op(0x3A));
        assert!(!is_read_only_poll_op(0x20));
        assert!(!is_read_only_poll_op(0x3D));
        assert!(!is_read_only_poll_op(0x26));
        assert!(!is_read_only_poll_op(0x44));
    }
}
