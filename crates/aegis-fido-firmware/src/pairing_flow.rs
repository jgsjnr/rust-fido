//! Phase8 - fluxo hold BOTAO: TOTP 2s vs pareamento 5s (sem I/O).
//!
//! - Corrige `PairingManager` orfao comido pelo branch OATH 2s no `main.rs`.
//! - `hold >= 5000ms` => `PairingReady` vence sempre (mesmo com TOTP pendente).
//! - TOTP so em `[2000ms, 5000ms)` E sem pareamento aberto.
//! - `no_std` compativel: funcao pura, relogio em ms injetado.

use crate::config::LONG_PRESS_MS;

/// Minimo do TOTP em ms (2s = `TOTP_LONG_PRESS_TICKS * 10`).
pub const TOTP_HOLD_MIN_MS: u64 = 2000;

/// Acao do hold do BOOT (GPIO0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldAction {
    /// Sem acao (hold curto ou soltou cedo).
    None,
    /// Mostra TOTP (2s..5s, sem pareamento).
    Totp,
    /// Entra/mantem pareamento (5s+, vence TOTP).
    PairingReady,
}

/// Classifica o hold: 5s vence, TOTP so em [2s,5s) sem pareamento.
pub fn classify_hold(held_ms: u64, pairing_open: bool) -> HoldAction {
    if held_ms >= LONG_PRESS_MS {
        return HoldAction::PairingReady;
    }
    if (TOTP_HOLD_MIN_MS..LONG_PRESS_MS).contains(&held_ms) && !pairing_open {
        return HoldAction::Totp;
    }
    HoldAction::None
}

/// Converte ticks de 10ms (base do `main.rs`) para ms saturantes.
pub fn held_ms_from_ticks(start_tick: u64, now_tick: u64) -> u64 {
    now_tick.saturating_sub(start_tick).saturating_mul(10)
}

/// `true` quando o TOTP deve ser suprimido (pareamento aberto).
pub fn suppress_totp_while_pairing(pairing_open: bool) -> bool {
    pairing_open
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_seconds_wins_over_totp() {
        assert_eq!(classify_hold(5000, false), HoldAction::PairingReady);
        assert_eq!(classify_hold(6000, false), HoldAction::PairingReady);
        assert_eq!(classify_hold(5000, true), HoldAction::PairingReady);
    }

    #[test]
    fn totp_only_in_window_without_pairing() {
        assert_eq!(classify_hold(1999, false), HoldAction::None);
        assert_eq!(classify_hold(2000, false), HoldAction::Totp);
        assert_eq!(classify_hold(4999, false), HoldAction::Totp);
        assert_eq!(classify_hold(2000, true), HoldAction::None);
        assert_eq!(classify_hold(4999, true), HoldAction::None);
    }

    #[test]
    fn short_hold_is_none() {
        assert_eq!(classify_hold(0, false), HoldAction::None);
        assert_eq!(classify_hold(100, false), HoldAction::None);
    }

    #[test]
    fn ticks_to_ms_saturates() {
        assert_eq!(held_ms_from_ticks(10, 210), 2000);
        assert_eq!(held_ms_from_ticks(10, 510), 5000);
        assert_eq!(held_ms_from_ticks(20, 10), 0);
    }

    #[test]
    fn pairing_suppresses_totp() {
        assert!(suppress_totp_while_pairing(true));
        assert!(!suppress_totp_while_pairing(false));
        assert_eq!(LONG_PRESS_MS, 5000);
        assert_eq!(TOTP_HOLD_MIN_MS, 2000);
    }
}
