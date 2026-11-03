//! Persistência Atômica do Secure Guard na NVS/Flash
//!
//! Gerencia o salvamento e carregamento do `SecureGuardPersistentRecord` (256 bytes)
//! na partição cifrada AES-256-GCM (`SecureStorage`).
//! Segue a política fail-closed: na ausência de registro prévio, inicia Unprovisioned;
//! sob qualquer sinal de corrupção ou erro de integridade, transiciona determinística
//! para `ErrorLocked`.

use crate::persistence::{
    delete_recovery_envelope, load_recovery_envelope, save_recovery_envelope, FlashStorageBackend,
    SecureStorage, StorageError,
};
use aegis_fido_core::secure_guard::{
    SecureGuardEngine, SecureGuardError, SecureGuardPolicy, SecureGuardState,
    RECOVERY_ENVELOPE_SIZE, PERSISTENT_RECORD_SIZE,
};
use zeroize::Zeroize;

/// Chave NVS para o registro persistido do Secure Guard (≤15 caracteres per ESP-IDF).
pub const NVS_SECURE_GUARD_RECORD: &str = "sg_record_v1";

/// Salva atomicamente o registro do Secure Guard no armazenamento criptografado.
///
/// Persiste tambem o envelope de recuperacao (`sg_recovery_v1`, plaintext fora
/// do envelope AES) sempre que o engine tiver um em cache: o provisionamento
/// sela o envelope e a rotacao via `recover_with_code` o re-sela, de modo que
/// este `save` cobre provisionamento E rotacao sem revistas no caminho.
///
/// GAP documentado (nao inventado): `change_pin` nao re-sela o envelope (o
/// codigo de recuperacao nao existe no payload do exec layer), entao apos uma
/// troca de PIN este `save` re-persiste o envelope ANTERIOR, que ainda resgata
/// o PIN pre-troca. A proxima rotacao (op recover) re-sela com o material novo.
pub fn save_secure_guard_record<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    engine: &SecureGuardEngine,
) -> Result<(), StorageError> {
    let record = engine.to_persistent_record();
    let bytes = record.to_bytes();
    let nonce = [0u8; 12];
    storage.store(NVS_SECURE_GUARD_RECORD, &bytes, &nonce)?;
    if let Some(envelope) = engine.recovery_envelope_bytes() {
        save_recovery_envelope(storage, &envelope)?;
    }
    Ok(())
}

/// Destroi o blob do envelope de recuperacao (`sg_recovery_v1`). Idempotente.
///
/// Caminhos de wipe/factory DEVEM chamar isto: o engine ja descarta o envelope
/// em cache no wipe, e um blob remanescente na NVS ressuscitaria credenciais
/// apagadas via `recover_error_locked_with_envelope`.
pub fn destroy_recovery_envelope<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
) -> Result<(), StorageError> {
    delete_recovery_envelope(storage)
}

/// Resgata um engine `ErrorLocked` via o envelope fora do envelope AES.
///
/// Caminho do reboot DEV: apos rotacao das chaves de dispositivo o
/// `sg_record_v1` nao abre e o boot cai em `ErrorLocked` com verificadores
/// zerados. Com o codigo de recuperacao capturado no provisionamento + o blob
/// `sg_recovery_v1` (legivel sem chave de dispositivo), re-autentica o codigo,
/// restaura o material do provisionamento e volta a `Locked` -- o PIN original
/// destrava a sessao. Nao enfraquece o KDF; codigo errado ou blob adulterado
/// falham fechados (`InvalidRecoveryCode` / `PersistenceCorrupted`) sem
/// transicao de estado. Em sucesso, re-salva o registro sob a chave de
/// dispositivo ATUAL para o proximo boot carregar normalmente.
pub fn recover_error_locked_with_envelope<B: FlashStorageBackend>(
    engine: &mut SecureGuardEngine,
    storage: &mut SecureStorage<B>,
    recovery_code: &[u8],
    now_ms: u64,
) -> Result<SecureGuardState, SecureGuardError> {
    if engine.state() != SecureGuardState::ErrorLocked {
        return Err(SecureGuardError::InvalidStateForOperation {
            current: engine.state(),
            expected: "ErrorLocked",
        });
    }
    let raw = load_recovery_envelope(storage).map_err(|e| match e {
        StorageError::KeyNotFound => {
            SecureGuardError::PersistenceCorrupted("recovery envelope blob missing")
        }
        _ => SecureGuardError::PersistenceCorrupted("recovery envelope blob unreadable"),
    })?;
    if raw.len() != RECOVERY_ENVELOPE_SIZE {
        return Err(SecureGuardError::PersistenceCorrupted(
            "recovery envelope blob bad length",
        ));
    }
    let mut envelope_bytes = [0u8; RECOVERY_ENVELOPE_SIZE];
    envelope_bytes.copy_from_slice(&raw);
    let res = engine.recover_with_envelope(recovery_code, &envelope_bytes, now_ms);
    envelope_bytes.zeroize();
    let state = res?;
    save_secure_guard_record(storage, engine)
        .map_err(|_| SecureGuardError::PersistenceCorrupted("envelope rescue re-save failed"))?;
    Ok(state)
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
    use crate::persistence::RECOVERY_ENVELOPE_NVS_KEY;
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

    const REBOOT_PIN: &[u8] = b"2846";
    const REBOOT_CODE: &[u8] = b"0123456789abcdef";

    fn provisioned_storage() -> (SecureGuardEngine, SecureStorage<MockFlashBackend>, [u8; 16]) {
        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..Default::default()
        };
        let mut engine = SecureGuardEngine::new(policy);
        let rec_code = engine
            .provision_pin(REBOOT_PIN, [0x11; 16], REBOOT_CODE, [0x33; 16], 1000)
            .expect("provision");
        assert_eq!(rec_code, {
            let mut c = [0u8; 16];
            c.copy_from_slice(REBOOT_CODE);
            c
        });
        let mut storage = SecureStorage::new(MockFlashBackend::new(), &[0x42; 32], &[0x99; 32]);
        save_secure_guard_record(&mut storage, &engine).expect("save");
        (engine, storage, rec_code)
    }

    /// Reboot simulado pelo storage layer do firmware: registro+envelope sob a
    /// chave A, rotacao para a chave B, load => ErrorLocked, resgate via
    /// envelope => Locked, unlock com o PIN original. Sem chaves de dispositivo.
    #[test]
    fn reboot_simulation_envelope_rescue_through_storage_layer() {
        let (_engine, storage_a, rec_code) = provisioned_storage();

        // O blob do envelope e plaintext FORA do envelope AES, com magica intacta.
        let raw_env = storage_a
            .backend()
            .read_raw(RECOVERY_ENVELOPE_NVS_KEY)
            .expect("envelope blob persisted");
        assert_eq!(raw_env.len(), RECOVERY_ENVELOPE_SIZE);
        assert_eq!(&raw_env[0..8], b"AEGSGR01");

        // Reboot com chaves de dispositivo novas (TRNG efemero do DEV): o
        // registro cifrado nao abre mais sob a chave B...
        let backend_b = storage_a.backend().clone();
        let mut storage_b = SecureStorage::new(backend_b, &[0xABu8; 32], &[0xCDu8; 32]);
        assert!(storage_b.load(NVS_SECURE_GUARD_RECORD).is_err());
        // ...mas o blob do envelope sobrevive (nenhuma chave de dispositivo).
        let env_b = storage_b
            .backend()
            .read_raw(RECOVERY_ENVELOPE_NVS_KEY)
            .expect("envelope survives key rotation");
        assert_eq!(env_b, raw_env);

        let mut rebooted = load_secure_guard_record(&storage_b, 2000);
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);
        // Sem verificadores, nem o PIN correto destrava.
        assert!(rebooted.unlock_with_pin(REBOOT_PIN, 2100).is_err());

        // Codigo errado falha fechado, sem transicao de estado.
        assert_eq!(
            recover_error_locked_with_envelope(
                &mut rebooted,
                &mut storage_b,
                b"wrong-code-000000",
                2200
            ),
            Err(SecureGuardError::InvalidRecoveryCode)
        );
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);

        // Codigo correto resgata para Locked SEM chaves de dispositivo.
        let st = recover_error_locked_with_envelope(&mut rebooted, &mut storage_b, &rec_code, 2300)
            .expect("envelope rescue");
        assert_eq!(st, SecureGuardState::Locked);
        assert_eq!(rebooted.state(), SecureGuardState::Locked);
        // O PIN original destrava a sessao.
        rebooted
            .unlock_with_pin(REBOOT_PIN, 2400)
            .expect("original PIN works after rescue");
        assert_eq!(rebooted.state(), SecureGuardState::Unlocked);
        // O resgate re-salvou o registro sob a chave B: proximo boot e Locked direto.
        let reloaded = load_secure_guard_record(&storage_b, 2500);
        assert_eq!(reloaded.state(), SecureGuardState::Locked);
    }

    /// Blob adulterado falha fechado: sem resgate, sem transicao de estado.
    #[test]
    fn envelope_rescue_tampered_blob_fails_closed() {
        let (_engine, storage_a, rec_code) = provisioned_storage();
        let backend_b = storage_a.backend().clone();
        let mut storage_b = SecureStorage::new(backend_b, &[0xABu8; 32], &[0xCDu8; 32]);
        let mut rebooted = load_secure_guard_record(&storage_b, 2000);
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);

        let mut raw = storage_b
            .backend()
            .read_raw(RECOVERY_ENVELOPE_NVS_KEY)
            .expect("envelope blob");
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        storage_b
            .backend_mut()
            .write_raw(RECOVERY_ENVELOPE_NVS_KEY, &raw)
            .expect("tamper write");

        let res =
            recover_error_locked_with_envelope(&mut rebooted, &mut storage_b, &rec_code, 2100);
        assert!(res.is_err());
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);
        // Nem o PIN original destrava um engine nao resgatado.
        assert!(rebooted.unlock_with_pin(REBOOT_PIN, 2200).is_err());
    }

    /// Blob ausente falha fechado: sem resgate, sem transicao de estado.
    #[test]
    fn envelope_rescue_missing_blob_fails_closed() {
        let mut storage = SecureStorage::new(MockFlashBackend::new(), &[0xABu8; 32], &[0xCDu8; 32]);
        // Registro cifrado valido sob a chave B, mas nenhum blob de envelope.
        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..Default::default()
        };
        let mut engine = SecureGuardEngine::new(policy);
        engine
            .provision_pin(REBOOT_PIN, [0x11; 16], REBOOT_CODE, [0x33; 16], 1000)
            .expect("provision");
        // Salva SÓ o registro (sem envelope): simula firmware anterior ao recurso.
        let record = engine.to_persistent_record();
        storage
            .store(NVS_SECURE_GUARD_RECORD, &record.to_bytes(), &[0u8; 12])
            .expect("record only");
        drop(engine);

        // Corrompe o registro para forcar o caminho ErrorLocked no load.
        let mut raw = storage
            .backend()
            .read_raw(NVS_SECURE_GUARD_RECORD)
            .expect("record");
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        storage
            .backend_mut()
            .write_raw(NVS_SECURE_GUARD_RECORD, &raw)
            .expect("corrupt write");

        let mut rebooted = load_secure_guard_record(&storage, 2000);
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);
        assert_eq!(
            recover_error_locked_with_envelope(&mut rebooted, &mut storage, REBOOT_CODE, 2100),
            Err(SecureGuardError::PersistenceCorrupted(
                "recovery envelope blob missing"
            ))
        );
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);
    }

    /// O helper de resgate exige ErrorLocked (fail-closed fora do caminho de reboot).
    #[test]
    fn envelope_rescue_rejects_non_error_locked() {
        let (_engine, mut storage, _rec_code) = provisioned_storage();
        let mut locked = load_secure_guard_record(&storage, 1500);
        assert_eq!(locked.state(), SecureGuardState::Locked);
        assert!(matches!(
            recover_error_locked_with_envelope(&mut locked, &mut storage, REBOOT_CODE, 1600),
            Err(SecureGuardError::InvalidStateForOperation { .. })
        ));
    }

    /// Wipe/factory destroem o blob: sem ressurreicao apos apagar.
    #[test]
    fn wipe_destroys_envelope_blob_no_resurrection() {
        let (_engine, mut storage, rec_code) = provisioned_storage();
        assert!(storage
            .backend()
            .read_raw(RECOVERY_ENVELOPE_NVS_KEY)
            .is_ok());
        destroy_recovery_envelope(&mut storage).expect("destroy");
        assert!(storage
            .backend()
            .read_raw(RECOVERY_ENVELOPE_NVS_KEY)
            .is_err());
        // Idempotente: segunda chamada segue Ok.
        destroy_recovery_envelope(&mut storage).expect("destroy idempotent");

        let backend_b = storage.backend().clone();
        let mut storage_b = SecureStorage::new(backend_b, &[0xABu8; 32], &[0xCDu8; 32]);
        let mut rebooted = load_secure_guard_record(&storage_b, 2000);
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);
        assert_eq!(
            recover_error_locked_with_envelope(&mut rebooted, &mut storage_b, &rec_code, 2100),
            Err(SecureGuardError::PersistenceCorrupted(
                "recovery envelope blob missing"
            ))
        );
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);
    }
}
