//! Persistência Atômica do Secure Guard na NVS/Flash
//!
//! Gerencia o salvamento e carregamento do `SecureGuardPersistentRecord` (256 bytes)
//! na partição cifrada AES-256-GCM (`SecureStorage`).
//! Segue a política fail-closed: na ausência de registro prévio, inicia Unprovisioned;
//! sob qualquer sinal de corrupção ou erro de integridade, transiciona determinística
//! para `ErrorLocked`.

use crate::persistence::{FlashStorageBackend, SecureStorage, StorageError};
use aegis_fido_core::secure_guard::{SecureGuardEngine, SecureGuardPolicy, PERSISTENT_RECORD_SIZE};

/// Chave NVS para o registro persistido do Secure Guard (≤15 caracteres per ESP-IDF).
pub const NVS_SECURE_GUARD_RECORD: &str = "sg_record_v1";

/// Salva atomicamente o registro do Secure Guard no armazenamento criptografado.
pub fn save_secure_guard_record<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    engine: &SecureGuardEngine,
) -> Result<(), StorageError> {
    let record = engine.to_persistent_record();
    let bytes = record.to_bytes();
    let nonce = [0u8; 12];
    storage.store(NVS_SECURE_GUARD_RECORD, &bytes, &nonce)
}

/// Carrega o motor do Secure Guard a partir do armazenamento criptografado.
///
/// - Se não houver registro (KeyNotFound), inicia em `Unprovisioned`.
/// - Se o registro for lido com sucesso, inicializa respeitando as regras de reboot
///   (sempre inicia em `Locked` se provisionado, preservando rate limit e contadores).
/// - Se houver corrupção ou falha de descriptografia, inicializa em `ErrorLocked`.
pub fn load_secure_guard_record<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    now_ms: u64,
) -> SecureGuardEngine {
    match storage.load(NVS_SECURE_GUARD_RECORD) {
        Ok(raw) => {
            if raw.len() == PERSISTENT_RECORD_SIZE {
                let mut bytes = [0u8; PERSISTENT_RECORD_SIZE];
                bytes.copy_from_slice(&raw);
                SecureGuardEngine::from_persisted_bytes(&bytes, now_ms)
            } else {
                log::error!(
                    "[SECURE_GUARD] Registro NVS com tamanho inválido ({}), iniciando ErrorLocked",
                    raw.len()
                );
                let corrupted = [0xFFu8; PERSISTENT_RECORD_SIZE];
                SecureGuardEngine::from_persisted_bytes(&corrupted, now_ms)
            }
        }
        Err(StorageError::KeyNotFound) => {
            log::info!("[SECURE_GUARD] Nenhum registro encontrado na NVS; iniciando Unprovisioned");
            SecureGuardEngine::new(SecureGuardPolicy::default())
        }
        Err(err) => {
            log::error!(
                "[SECURE_GUARD] Falha ao carregar registro da NVS ({:?}); iniciando ErrorLocked",
                err
            );
            let corrupted = [0xFFu8; PERSISTENT_RECORD_SIZE];
            SecureGuardEngine::from_persisted_bytes(&corrupted, now_ms)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;
    use aegis_fido_core::secure_guard::SecureGuardState;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x42; 32], &[0x99; 32])
    }

    #[test]
    fn test_unprovisioned_when_not_found() {
        let storage = test_storage();
        let engine = load_secure_guard_record(&storage, 1000);
        assert_eq!(engine.state(), SecureGuardState::Unprovisioned);
        assert!(!engine.is_provisioned());
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let mut storage = test_storage();
        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..Default::default()
        };
        let mut engine = SecureGuardEngine::new(policy);
        let pin = b"2846";
        let rec = engine
            .provision_pin(pin, [0x11; 16], b"", [0x22; 16], 1000)
            .expect("provision");
        assert_eq!(rec.len(), 16);

        // Salva na NVS
        save_secure_guard_record(&mut storage, &engine).expect("save");

        // Carrega da NVS
        let loaded = load_secure_guard_record(&storage, 1500);
        assert_eq!(loaded.state(), SecureGuardState::Locked);
        assert!(loaded.is_provisioned());
        assert_eq!(loaded.failed_attempts(), 0);
    }

    #[test]
    fn test_corrupted_storage_enters_error_locked() {
        let mut storage = test_storage();
        // Grava dados inválidos na chave
        let nonce = [0u8; 12];
        storage
            .store(NVS_SECURE_GUARD_RECORD, b"corrupted-invalid-bytes", &nonce)
            .expect("store corrupted");

        let loaded = load_secure_guard_record(&storage, 2000);
        assert_eq!(loaded.state(), SecureGuardState::ErrorLocked);
    }
}
