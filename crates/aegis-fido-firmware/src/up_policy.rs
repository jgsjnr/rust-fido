//! T-UI-01 UP vinculado a operacao (GEN-DEVICE, evento fisico).
//!
//! Motivo: UP sem vinculo permite que um toque autorize OUTRA operacao
//! (confused deputy); grant consumivel de uso unico fecha isso (secao 9).
//!
//! - `UpPolicy::issue` abre um grant para um `OperationHash` com janela.
//! - `authorize` exige mesma operacao, dentro da janela e nao consumido;
//!   ao autorizar, consome (replay do mesmo grant e negado).
//! - Nao edita `button.rs`: converte `UserPresenceError` via
//!   `from_button_err` para manter o mesmo vocabulario de negação.

use crate::button::UserPresenceError;

/// Janela padrao do grant (60 s) e teto absoluto (5 min).
pub const UP_DEFAULT_WINDOW_MS: u64 = 60_000;
pub const UP_MAX_WINDOW_MS: u64 = 300_000;

/// Identificador opaco da operacao (ex.: SHA-256 do desafio CTAP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperationHash(pub [u8; 32]);

/// Motivo da negativa. Sem dados sensiveis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpDeny {
    WrongOperation,
    Expired,
    Replayed,
    Cancelled,
    Timeout,
    HardwareFault,
    WindowTooLarge,
}

/// Grant de presenca: operacao + validade + consumo unico.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpGrant {
    op: OperationHash,
    granted_at_ms: u64,
    valid_ms: u64,
    consumed: bool,
}

/// Politica de UP vinculado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpPolicy {
    window_ms: u64,
}

impl UpPolicy {
    pub fn new(window_ms: u64) -> Result<Self, UpDeny> {
        if window_ms == 0 || window_ms > UP_MAX_WINDOW_MS {
            return Err(UpDeny::WindowTooLarge);
        }
        Ok(Self { window_ms })
    }

    pub fn with_default_window() -> Self {
        Self {
            window_ms: UP_DEFAULT_WINDOW_MS,
        }
    }

    /// Emite grant apos toque fisico confirmado para esta operacao.
    pub fn issue(&self, op: OperationHash, now_ms: u64) -> UpGrant {
        UpGrant {
            op,
            granted_at_ms: now_ms,
            valid_ms: self.window_ms,
            consumed: false,
        }
    }

    /// Autoriza uso unico: mesma operacao, dentro da janela, nao consumido.
    pub fn authorize(
        &self,
        grant: &mut UpGrant,
        op: OperationHash,
        now_ms: u64,
    ) -> Result<(), UpDeny> {
        let _ = self;
        if grant.consumed {
            return Err(UpDeny::Replayed);
        }
        if grant.op != op {
            return Err(UpDeny::WrongOperation);
        }
        if now_ms.saturating_sub(grant.granted_at_ms) > grant.valid_ms {
            return Err(UpDeny::Expired);
        }
        grant.consumed = true;
        Ok(())
    }

    /// Traduz o erro do botao fisico para o vocabulario da politica.
    pub fn from_button_err(e: UserPresenceError) -> UpDeny {
        match e {
            UserPresenceError::Timeout => UpDeny::Timeout,
            UserPresenceError::Cancelled => UpDeny::Cancelled,
            UserPresenceError::HardwareFault => UpDeny::HardwareFault,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(byte: u8) -> OperationHash {
        OperationHash([byte; 32])
    }

    #[test]
    fn happy_path_single_use() {
        let policy = UpPolicy::with_default_window();
        let mut grant = policy.issue(op(1), 1_000);
        policy
            .authorize(&mut grant, op(1), 1_500)
            .expect("UP valido");
        // Replay do mesmo grant e negado mesmo dentro da janela.
        assert_eq!(
            policy.authorize(&mut grant, op(1), 1_600),
            Err(UpDeny::Replayed)
        );
    }

    #[test]
    fn wrong_operation_denied() {
        let policy = UpPolicy::with_default_window();
        let mut grant = policy.issue(op(1), 1_000);
        assert_eq!(
            policy.authorize(&mut grant, op(2), 1_100),
            Err(UpDeny::WrongOperation)
        );
        // Grant nao consumido por tentativa errada continua valido.
        policy
            .authorize(&mut grant, op(1), 1_100)
            .expect("ainda valido");
    }

    #[test]
    fn expired_denied() {
        let policy = UpPolicy::new(1_000).unwrap();
        let mut grant = policy.issue(op(1), 5_000);
        assert_eq!(
            policy.authorize(&mut grant, op(1), 6_001),
            Err(UpDeny::Expired)
        );
    }

    #[test]
    fn window_limits_and_button_mapping() {
        assert_eq!(UpPolicy::new(0), Err(UpDeny::WindowTooLarge));
        assert_eq!(
            UpPolicy::new(UP_MAX_WINDOW_MS + 1),
            Err(UpDeny::WindowTooLarge)
        );
        assert_eq!(
            UpPolicy::from_button_err(UserPresenceError::Timeout),
            UpDeny::Timeout
        );
        assert_eq!(
            UpPolicy::from_button_err(UserPresenceError::Cancelled),
            UpDeny::Cancelled
        );
        assert_eq!(
            UpPolicy::from_button_err(UserPresenceError::HardwareFault),
            UpDeny::HardwareFault
        );
    }
}
