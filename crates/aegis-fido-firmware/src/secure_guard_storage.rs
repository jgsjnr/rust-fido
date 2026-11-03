//! Persistência Atômica do Secure Guard na NVS/Flash
//!
//! Gerencia o salvamento e carregamento do `SecureGuardPersistentRecord` (256 bytes)
//! na partição cifrada AES-256-GCM (`SecureStorage`).
//! Segue a política fail-closed: na ausência de registro prévio, inicia Unprovisioned;
//! sob qualquer sinal de corrupção ou erro de integridade, transiciona determinística
//! para `ErrorLocked`.

#[cfg(feature = "test-mode")]
use crate::persistence::{
    delete_dev_recovery_code, load_dev_recovery_code, save_dev_recovery_code,
};
use crate::persistence::{
    delete_recovery_envelope, load_recovery_envelope, save_recovery_envelope, FlashStorageBackend,
    SecureStorage, StorageError,
};
#[cfg(feature = "test-mode")]
use aegis_fido_core::secure_guard::dev_recovery_cache::DEV_RECOVERY_CODE_BLOB_SIZE;
use aegis_fido_core::secure_guard::{
    SecureGuardEngine, SecureGuardError, SecureGuardPolicy, SecureGuardState,
    PERSISTENT_RECORD_SIZE, RECOVERY_ENVELOPE_SIZE,
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
    // DEV-only: persist the last recovery CODE next to the envelope, written
    // ONLY at provision / rotation / recovery inside test-mode builds (the
    // engine seals the code blob whenever a fresh code is in hand; absent
    // cache simply leaves the stored blob untouched). Release builds contain
    // no such path.
    #[cfg(feature = "test-mode")]
    if let Some(code_blob) = engine.dev_recovery_code_blob_bytes() {
        save_dev_recovery_code(storage, &code_blob)?;
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
    delete_recovery_envelope(storage)?;
    // DEV-only cache dies with the envelope: a lingering code blob would
    // resurrect wiped credentials through the DEV auto-recover path.
    // Release builds contain no such path.
    #[cfg(feature = "test-mode")]
    delete_dev_recovery_code(storage)?;
    Ok(())
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

/// DEV-ONLY load with single-attempt automatic recovery from the on-device code cache.
///
/// Compiled ONLY under `test-mode`; release builds contain no such path (any
/// release reference is a compile error). NEVER enable outside `test-mode`:
/// release uses eFuse-provisioned keys and eFuse burns require an explicit
/// owner ceremony. This function performs NO eFuse operation of any kind.
///
/// Behaves exactly like [`load_secure_guard_record`], except that an
/// `ErrorLocked` engine triggers ONE automatic `try_dev_auto_recover` using
/// the cached DEV code blob (`sg_dev_code_v1`) plus the envelope blob
/// (`sg_recovery_v1`), audit-logged as dev-auto-recovery. A missing, wrong,
/// or tampered cache fails closed to normal `ErrorLocked` with no retry loop.
/// On success the record is re-saved under the CURRENT device key so the next
/// boot loads `Locked` directly.
///
/// Boot wiring contract (firmware run-loop lane): test-mode boot should call
/// this instead of `load_secure_guard_record` to get DEV reboot resilience.
#[cfg(feature = "test-mode")]
pub fn load_secure_guard_record_with_dev_auto_recovery<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    now_ms: u64,
) -> SecureGuardEngine {
    let mut engine = load_secure_guard_record(storage, now_ms);
    if engine.state() != SecureGuardState::ErrorLocked {
        return engine;
    }
    // Single attempt, no retry loop. Absent/unreadable blobs (never cached)
    // return the engine untouched without auditing; parse/crypto failures are
    // audit-logged inside `try_dev_auto_recover` and stay `ErrorLocked`.
    let code_raw = match load_dev_recovery_code(storage) {
        Ok(raw) => raw,
        Err(_) => return engine,
    };
    if code_raw.len() != DEV_RECOVERY_CODE_BLOB_SIZE {
        return engine;
    }
    let env_raw = match load_recovery_envelope(storage) {
        Ok(raw) => raw,
        Err(_) => return engine,
    };
    if env_raw.len() != RECOVERY_ENVELOPE_SIZE {
        return engine;
    }
    let mut code_blob = [0u8; DEV_RECOVERY_CODE_BLOB_SIZE];
    code_blob.copy_from_slice(&code_raw);
    let mut envelope_bytes = [0u8; RECOVERY_ENVELOPE_SIZE];
    envelope_bytes.copy_from_slice(&env_raw);
    let res = engine.try_dev_auto_recover(&code_blob, &envelope_bytes, now_ms);
    code_blob.zeroize();
    envelope_bytes.zeroize();
    if res.is_ok() {
        let _ = save_secure_guard_record(storage, &engine);
    }
    engine
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
        // DEV-only: o blob do codigo cai junto com o envelope no wipe.
        #[cfg(feature = "test-mode")]
        assert!(storage
            .backend()
            .read_raw(crate::persistence::DEV_RECOVERY_CODE_NVS_KEY)
            .is_ok());
        destroy_recovery_envelope(&mut storage).expect("destroy");
        assert!(storage
            .backend()
            .read_raw(RECOVERY_ENVELOPE_NVS_KEY)
            .is_err());
        #[cfg(feature = "test-mode")]
        assert!(storage
            .backend()
            .read_raw(crate::persistence::DEV_RECOVERY_CODE_NVS_KEY)
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

    /// DEV reboot -> auto-recover -> unlocked com o PIN original (test-mode only).
    ///
    /// Provisionamento persiste envelope + blob do codigo fora do envelope
    /// AES; reboot com chaves de dispositivo novas cai em `ErrorLocked`; o
    /// load DEV faz UMA tentativa automatica com o codigo em cache, volta a
    /// `Locked` (auditado como dev-auto-recovery) e o PIN original destrava.
    /// Nenhuma operacao eFuse em nenhum passo.
    #[cfg(feature = "test-mode")]
    #[test]
    fn dev_auto_recovery_reboot_unlocks_with_original_pin() {
        use aegis_fido_core::secure_guard::dev_recovery_cache::DEV_RECOVERY_CODE_BLOB_SIZE;
        use aegis_fido_core::secure_guard::SecureGuardAuditEventType;

        let (_engine, storage_a, _rec_code) = provisioned_storage();

        // Blob do codigo DEV persistido em plaintext, com magica intacta.
        let code_raw = storage_a
            .backend()
            .read_raw(crate::persistence::DEV_RECOVERY_CODE_NVS_KEY)
            .expect("dev code blob persisted");
        assert_eq!(code_raw.len(), DEV_RECOVERY_CODE_BLOB_SIZE);
        assert_eq!(&code_raw[0..8], b"AEGSGD01");

        let backend_b = storage_a.backend().clone();
        let mut storage_b = SecureStorage::new(backend_b, &[0xABu8; 32], &[0xCDu8; 32]);

        // Sanidade: o load puro (sem auto) segue ErrorLocked.
        let plain = load_secure_guard_record(&storage_b, 2000);
        assert_eq!(plain.state(), SecureGuardState::ErrorLocked);

        // Load DEV: tentativa unica automatica -> Locked...
        let mut rebooted = load_secure_guard_record_with_dev_auto_recovery(&mut storage_b, 2100);
        assert_eq!(rebooted.state(), SecureGuardState::Locked);
        assert!(matches!(
            rebooted.audit_log().last().map(|e| &e.event_type),
            Some(SecureGuardAuditEventType::DevAutoRecovery { success: true })
        ));

        // ...e o PIN ORIGINAL destrava a sessao.
        rebooted
            .unlock_with_pin(REBOOT_PIN, 2200)
            .expect("original PIN works after DEV auto-recovery");
        assert_eq!(rebooted.state(), SecureGuardState::Unlocked);

        // O resgate re-salvou sob a chave B: proximo boot e Locked direto.
        let reloaded = load_secure_guard_record(&storage_b, 2300);
        assert_eq!(reloaded.state(), SecureGuardState::Locked);
    }

    /// Cache DEV adulterado/ausente: permanece `ErrorLocked`, sem retry.
    #[cfg(feature = "test-mode")]
    #[test]
    fn dev_auto_recovery_tampered_cache_stays_error_locked() {
        let (_engine, storage_a, _rec_code) = provisioned_storage();
        let backend_b = storage_a.backend().clone();
        let mut storage_b = SecureStorage::new(backend_b, &[0xABu8; 32], &[0xCDu8; 32]);

        // Adultera o blob do codigo (CRC quebrado, sem correcao).
        let mut raw = storage_b
            .backend()
            .read_raw(crate::persistence::DEV_RECOVERY_CODE_NVS_KEY)
            .expect("dev blob");
        raw[12] ^= 0xFF;
        storage_b
            .backend_mut()
            .write_raw(crate::persistence::DEV_RECOVERY_CODE_NVS_KEY, &raw)
            .expect("tamper write");

        let mut rebooted = load_secure_guard_record_with_dev_auto_recovery(&mut storage_b, 2000);
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);
        // Nem o PIN original destrava um engine nao resgatado.
        assert!(rebooted.unlock_with_pin(REBOOT_PIN, 2100).is_err());

        // Blob ausente tambem falha fechado, sem retry.
        storage_b
            .backend_mut()
            .delete_raw(crate::persistence::DEV_RECOVERY_CODE_NVS_KEY)
            .expect("delete dev blob");
        let rebooted2 = load_secure_guard_record_with_dev_auto_recovery(&mut storage_b, 2200);
        assert_eq!(rebooted2.state(), SecureGuardState::ErrorLocked);
    }

    /// Release (sem test-mode): sem cache, sem auto-recovery; tentativa sem
    /// codigo falha fechado e nunca sai de `ErrorLocked`.
    #[cfg(not(feature = "test-mode"))]
    #[test]
    fn release_has_no_dev_auto_recovery_without_code_fails_closed() {
        let (_engine, storage_a, _rec_code) = provisioned_storage();
        let backend_b = storage_a.backend().clone();
        let mut storage_b = SecureStorage::new(backend_b, &[0xABu8; 32], &[0xCDu8; 32]);

        let mut rebooted = load_secure_guard_record(&storage_b, 2000);
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);
        assert_eq!(
            recover_error_locked_with_envelope(&mut rebooted, &mut storage_b, b"", 2100),
            Err(SecureGuardError::InvalidRecoveryCode)
        );
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);
        assert!(rebooted.unlock_with_pin(REBOOT_PIN, 2200).is_err());
    }
}
