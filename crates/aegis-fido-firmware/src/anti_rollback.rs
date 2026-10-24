//! T-SF-02 Contador anti-rollback de versao de firmware (GEN-DEVICE).
//!
//! Motivo: sem versao monotona persistida, um atacante com acesso fisico
//! reinstala firmware antigo vulneravel (downgrade); secao 6 exige negar.
//!
//! - Registro `fw/anti_rollback` (8 B: magica `AR01` + versao u32 BE) no
//!   envelope AEGN via `SecureStorage` (mesma fronteira de `pin_uv`).
//! - Regra: `commit` so aceita versao MAIOR que a atual; igual ou menor =
//!   `DowngradeDenied`. Versao 0 e reservada (dispositivo virgem le 0 e
//!   qualquer `commit >= 1` e upgrade valido).
//! - Power-loss: verify-after-write por leitura de volta; divergencia vira
//!   `Storage` sem apagar o registro antigo (o contador nunca regride por
//!   falha de escrita; proximo boot rele a versao anterior intacta).
//! - Registro corrompido (tamanho/magica) = `Corrupt` fail-closed: nenhum
//!   `commit` passa sem antes resolver a corrupcao (nunca assume 0).
//! - Sem relogio, sem rede, sem segredo: so um u32 monotono.

extern crate alloc;

use crate::persistence::{FlashStorageBackend, SecureStorage, StorageError};

/// Chave NVS do contador anti-rollback.
pub const ANTI_ROLLBACK_KEY: &str = "fw/anti_rollback";
/// Magica do registro (4 B).
pub const ANTI_ROLLBACK_MAGIC: [u8; 4] = [0x41, 0x52, 0x30, 0x31];
/// Tamanho do registro (magica 4 + versao u32 BE).
pub const ANTI_ROLLBACK_RECORD_LEN: usize = 8;

/// Erros do anti-rollback. Sem versao sensivel em log alem do fato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiRollbackError {
    /// Versao 0 (reservada p/ dispositivo virgem; nunca comitavel).
    BadVersion,
    /// Versao menor ou igual a atual (downgrade/replay negado).
    DowngradeDenied,
    /// Registro com tamanho/magica invalidos.
    Corrupt,
    /// Falha de storage / verify-after-write.
    Storage,
}

impl core::fmt::Display for AntiRollbackError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadVersion => write!(f, "bad firmware version"),
            Self::DowngradeDenied => write!(f, "firmware downgrade denied"),
            Self::Corrupt => write!(f, "anti-rollback record corrupt"),
            Self::Storage => write!(f, "anti-rollback storage failure"),
        }
    }
}

impl From<StorageError> for AntiRollbackError {
    fn from(_: StorageError) -> Self {
        Self::Storage
    }
}

fn encode(version: u32) -> [u8; ANTI_ROLLBACK_RECORD_LEN] {
    let mut out = [0u8; ANTI_ROLLBACK_RECORD_LEN];
    out[..4].copy_from_slice(&ANTI_ROLLBACK_MAGIC);
    out[4..].copy_from_slice(&version.to_be_bytes());
    out
}

fn decode(raw: &[u8]) -> Result<u32, AntiRollbackError> {
    if raw.len() != ANTI_ROLLBACK_RECORD_LEN || raw[..4] != ANTI_ROLLBACK_MAGIC {
        return Err(AntiRollbackError::Corrupt);
    }
    let mut v = [0u8; 4];
    v.copy_from_slice(&raw[4..]);
    Ok(u32::from_be_bytes(v))
}

/// Le a versao atual; dispositivo virgem (sem registro) = 0.
pub fn current_version<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
) -> Result<u32, AntiRollbackError> {
    match storage.load(ANTI_ROLLBACK_KEY) {
        Ok(raw) => decode(&raw),
        Err(StorageError::KeyNotFound) => Ok(0),
        Err(e) => Err(e.into()),
    }
}

/// Comita `new` se maior que a atual; verify-after-write sem apagar o antigo.
pub fn commit_version<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    new: u32,
) -> Result<(), AntiRollbackError> {
    if new == 0 {
        return Err(AntiRollbackError::BadVersion);
    }
    let cur = current_version(storage)?;
    if new <= cur {
        return Err(AntiRollbackError::DowngradeDenied);
    }
    let record = encode(new);
    storage.store(ANTI_ROLLBACK_KEY, &record, &[0u8; 12])?;
    let back = storage
        .load(ANTI_ROLLBACK_KEY)
        .map_err(|_| AntiRollbackError::Storage)?;
    if back.as_slice() != record.as_slice() {
        // Torn write: mantem o registro (possivelmente antigo) e falha.
        // Nunca apaga: apagar abriria janela p/ releitura 0 + downgrade.
        return Err(AntiRollbackError::Storage);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x66u8; 32], &[0x77u8; 32])
    }

    #[test]
    fn virgem_le_zero_e_primeiro_commit_passa() {
        let mut st = test_storage();
        assert_eq!(current_version(&st), Ok(0));
        commit_version(&mut st, 1).unwrap();
        assert_eq!(current_version(&st), Ok(1));
    }

    #[test]
    fn downgrade_e_replay_negados() {
        let mut st = test_storage();
        commit_version(&mut st, 5).unwrap();
        assert_eq!(
            commit_version(&mut st, 5),
            Err(AntiRollbackError::DowngradeDenied)
        );
        assert_eq!(
            commit_version(&mut st, 4),
            Err(AntiRollbackError::DowngradeDenied)
        );
        assert_eq!(
            commit_version(&mut st, 0),
            Err(AntiRollbackError::BadVersion)
        );
        assert_eq!(current_version(&st), Ok(5));
        commit_version(&mut st, 6).unwrap();
        assert_eq!(current_version(&st), Ok(6));
    }

    #[test]
    fn registro_corrompido_falha_fechado() {
        let mut st = test_storage();
        commit_version(&mut st, 7).unwrap();
        st.store(ANTI_ROLLBACK_KEY, b"\xff\xfe-lixo", &[0u8; 12])
            .unwrap();
        assert_eq!(current_version(&st), Err(AntiRollbackError::Corrupt));
        // Corrompido nao e zerado: commit nao assume 0 para passar.
        assert_eq!(commit_version(&mut st, 8), Err(AntiRollbackError::Corrupt));
        assert_eq!(commit_version(&mut st, 1), Err(AntiRollbackError::Corrupt));
    }

    /// Backend que confirma mas perde writes da chave (queda de energia).
    #[derive(Clone)]
    struct DropKeyWrites {
        inner: MockFlashBackend,
        drop: alloc::rc::Rc<core::cell::Cell<bool>>,
    }

    impl FlashStorageBackend for DropKeyWrites {
        fn read_raw(&self, key: &str) -> Result<Vec<u8>, StorageError> {
            self.inner.read_raw(key)
        }
        fn write_raw(&mut self, key: &str, data: &[u8]) -> Result<(), StorageError> {
            if self.drop.get() && key == ANTI_ROLLBACK_KEY {
                return Ok(());
            }
            self.inner.write_raw(key, data)
        }
        fn delete_raw(&mut self, key: &str) -> Result<(), StorageError> {
            self.inner.delete_raw(key)
        }
        fn exists(&self, key: &str) -> bool {
            self.inner.exists(key)
        }
    }

    #[test]
    fn power_loss_torn_write_preserva_versao() {
        let drop = alloc::rc::Rc::new(core::cell::Cell::new(false));
        let backend = DropKeyWrites {
            inner: MockFlashBackend::new(),
            drop: drop.clone(),
        };
        let mut st = SecureStorage::new(backend, &[0x66u8; 32], &[0x77u8; 32]);
        commit_version(&mut st, 3).unwrap();
        drop.set(true);
        assert_eq!(commit_version(&mut st, 4), Err(AntiRollbackError::Storage));
        // Versao anterior intacta: downgrade continua negado.
        assert_eq!(current_version(&st), Ok(3));
        assert_eq!(
            commit_version(&mut st, 2),
            Err(AntiRollbackError::DowngradeDenied)
        );
        drop.set(false);
        commit_version(&mut st, 4).unwrap();
        assert_eq!(current_version(&st), Ok(4));
    }
}
