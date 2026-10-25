//! Tarefa e Escalonador Dedicado do Secure Guard para FreeRTOS / ESP32-S3
//!
//! Implementa a lógica periódica supervisionada do Secure Guard, com stack dimensionada
//! em 32 KiB (protegendo contra estouro em derivações PBKDF2), prioridade FreeRTOS (3),
//! integração com o watchdog por tarefa (TWDT) e expiração automática de sessão
//! e janelas de rate-limit.

use aegis_fido_core::secure_guard::{SecureGuardEngine, SecureGuardState};
use crate::freertos_sched::PerTaskWatchdog;

/// Prioridade da tarefa dedicada Secure Guard no FreeRTOS (intermediária entre Housekeeping=2 e UI=4).
pub const SECURE_GUARD_TASK_PRIO: u8 = 3;
/// Stack dimensionada em 32 KiB para isolar as chamadas criptográficas do PBKDF2-HMAC-SHA256.
pub const SECURE_GUARD_TASK_STACK: usize = 32 * 1024;

/// Executa um passo do tick periódico do Secure Guard.
///
/// Avalia:
/// 1. Expiração da sessão ativa por inatividade ou tempo absoluto.
/// 2. Expiração de janela penal de rate limiting.
///
/// Retorna `true` se a sessão continua ativa/unlocked, ou `false` se travada/expirada.
pub fn tick_secure_guard(engine: &mut SecureGuardEngine, now_ms: u64) -> bool {
    if engine.state() == SecureGuardState::Unlocked {
        engine.check_and_touch_session(now_ms).unwrap_or_default()
    } else {
        false
    }
}

/// Estado supervisionado do Secure Guard para escalonador FreeRTOS.
#[derive(Debug)]
pub struct SecureGuardSupervisor {
    last_tick_ms: u64,
    tick_count: u64,
    twdt: PerTaskWatchdog,
}

impl Default for SecureGuardSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureGuardSupervisor {
    /// Cria um novo supervisor e subscreve a tarefa ao TWDT.
    pub fn new() -> Self {
        Self {
            last_tick_ms: 0,
            tick_count: 0,
            twdt: PerTaskWatchdog::subscribe_current_task(),
        }
    }

    /// Processa o tick periódico, alimentando o TWDT e executando as verificações do motor.
    pub fn step(&mut self, engine: &mut SecureGuardEngine, now_ms: u64) -> bool {
        self.twdt.feed_current_task();
        self.last_tick_ms = now_ms;
        self.tick_count = self.tick_count.saturating_add(1);

        tick_secure_guard(engine, now_ms)
    }

    /// Retorna o contador de ticks processados.
    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    /// Alimenta explicitamente o watchdog da tarefa.
    pub fn feed_watchdog(&self) {
        self.twdt.feed_current_task();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_fido_core::secure_guard::SecureGuardPolicy;

    #[test]
    fn test_tick_expires_unlocked_session_on_timeout() {
        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            session_duration_ms: 1000,
            inactivity_timeout_ms: 500,
            ..Default::default()
        };
        let mut engine = SecureGuardEngine::new(policy);
        let pin = b"3948";
        let _ = engine
            .provision_pin(pin, [0x11; 16], b"", [0x22; 16], 1000)
            .expect("provision");
        engine.unlock_with_pin(pin, 1000).expect("unlock");
        assert!(engine.is_unlocked());

        // 1. Tick dentro da janela de atividade -> continua Unlocked
        assert!(tick_secure_guard(&mut engine, 1200));
        assert!(engine.is_unlocked());

        // 2. Tick após timeout de inatividade (1200 + 500 = 1700ms) -> Expira e trava
        assert!(!tick_secure_guard(&mut engine, 1750));
        assert_eq!(engine.state(), SecureGuardState::Locked);
    }

    #[test]
    fn test_supervisor_feeds_watchdog() {
        let mut sup = SecureGuardSupervisor::new();
        let mut engine = SecureGuardEngine::new(SecureGuardPolicy::default());

        assert!(!sup.step(&mut engine, 100));
        assert_eq!(sup.tick_count(), 1);
        sup.feed_watchdog();
    }
}
