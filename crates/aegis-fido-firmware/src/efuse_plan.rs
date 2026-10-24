//! T-SF-01 Plano de gravacao eFuse (risco documentado, GEN-DEVICE).
//!
//! Motivo: eFuse e OTP irreversivel; gravar bloco errado ou sem protecao
//! bricka o device ou vaza a raiz (secao 6: plano antes de gravar).
//!
//! - Nao edita `efuse.rs`: consome as constantes de bloco/tamanho de la, de
//!   modo que qualquer deriva quebre a compilacao em vez do silicio.
//! - `EfusePlan::default_secure` so libera `can_burn` apos aceite explicito
//!   da irreversibilidade; re-gravacao e sempre proibida (OTP cola bit 0->1).
//!
//! Riscos catalogados (revisao pre-uso real):
//! 1. Bloco trocado (raiz no bloco do salt) = device inservivel.
//! 2. Gravar sem `write-protect` = raiz regravavel por falha futura.
//! 3. `burn` parcial por queda de energia = bloco hibrido, sem conserto.
//! 4. Logar raiz/salt = vazamento permanente (nunca em log, sem PII/segredo).

use crate::efuse::{EFUSE_DEVICE_SALT_BLOCK, EFUSE_KEY_LEN, EFUSE_MASTER_KEY_BLOCK};

/// Versao do plano (muda quando a politica mudar).
pub const PLAN_VERSION: u8 = 1;

/// Erros do plano. Sem material OTP nas variantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    WrongBlock,
    BadLength,
    MissingIrreversibleAck,
    ReprovisionForbidden,
    AlreadyProvisioned,
}

/// Plano de provisionamento OTP. Construa via `default_secure`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EfusePlan {
    pub master_block: u8,
    pub salt_block: u8,
    pub key_len: usize,
    pub require_write_protect: bool,
    pub operator_ack_irreversible: bool,
    pub allow_reprovision: bool,
}

impl EfusePlan {
    pub fn default_secure() -> Self {
        Self {
            master_block: EFUSE_MASTER_KEY_BLOCK,
            salt_block: EFUSE_DEVICE_SALT_BLOCK,
            key_len: EFUSE_KEY_LEN,
            require_write_protect: true,
            operator_ack_irreversible: false,
            allow_reprovision: false,
        }
    }

    /// Aceite explicito da irreversibilidade (operador/fabricante).
    pub fn acknowledge_irreversible(mut self) -> Self {
        self.operator_ack_irreversible = true;
        self
    }

    /// Valida o plano sem tocar o silicio.
    pub fn validate(&self) -> Result<(), PlanError> {
        if self.master_block != EFUSE_MASTER_KEY_BLOCK || self.salt_block != EFUSE_DEVICE_SALT_BLOCK
        {
            return Err(PlanError::WrongBlock);
        }
        if self.key_len != EFUSE_KEY_LEN {
            return Err(PlanError::BadLength);
        }
        if self.allow_reprovision {
            return Err(PlanError::ReprovisionForbidden);
        }
        if !self.operator_ack_irreversible {
            return Err(PlanError::MissingIrreversibleAck);
        }
        Ok(())
    }

    /// Libera a queima: plano valido, protecao exigida e bloco ainda virgem.
    pub fn can_burn(&self, already_provisioned: bool) -> Result<(), PlanError> {
        self.validate()?;
        if !self.require_write_protect {
            return Err(PlanError::MissingIrreversibleAck);
        }
        if already_provisioned {
            return Err(PlanError::AlreadyProvisioned);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_requires_ack() {
        let plan = EfusePlan::default_secure();
        assert_eq!(plan.validate(), Err(PlanError::MissingIrreversibleAck));
        assert_eq!(plan.acknowledge_irreversible().validate(), Ok(()));
    }

    #[test]
    fn rejects_wrong_block_and_length() {
        let mut plan = EfusePlan::default_secure().acknowledge_irreversible();
        plan.master_block = 4;
        assert_eq!(plan.validate(), Err(PlanError::WrongBlock));
        plan.master_block = EFUSE_MASTER_KEY_BLOCK;
        plan.salt_block = 9;
        assert_eq!(plan.validate(), Err(PlanError::WrongBlock));
        plan.salt_block = EFUSE_DEVICE_SALT_BLOCK;
        plan.key_len = 16;
        assert_eq!(plan.validate(), Err(PlanError::BadLength));
    }

    #[test]
    fn forbids_reprovision_and_double_burn() {
        let mut plan = EfusePlan::default_secure().acknowledge_irreversible();
        plan.allow_reprovision = true;
        assert_eq!(plan.validate(), Err(PlanError::ReprovisionForbidden));
        let plan = EfusePlan::default_secure().acknowledge_irreversible();
        assert_eq!(plan.can_burn(false), Ok(()));
        assert_eq!(plan.can_burn(true), Err(PlanError::AlreadyProvisioned));
    }

    #[test]
    fn write_protect_is_mandatory() {
        let mut plan = EfusePlan::default_secure().acknowledge_irreversible();
        plan.require_write_protect = false;
        assert_eq!(plan.can_burn(false), Err(PlanError::MissingIrreversibleAck));
    }
}
