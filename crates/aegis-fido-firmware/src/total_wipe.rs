//! Wipe total firmware-side: chaves + senhas (decisao do dono fd/finalizacao-linux).
//!
//! Todo caminho de wipe total passa por [`wipe_pm_vault`], que apaga o blob
//! PM selado da NVS (idempotente; FIDO2/OATH intactos) e registra auditoria.
//! O vault PM vive transiente por chamada sem cache RAM persistente.
//! Sem PII/segredo em nenhuma linha.
//!
//! Diet (`cap-fido-only`/`cap-fido-totp`): PM responde `UNSUPPORTED_FEATURE`.
//! REGRA PRINCIPAL N1: sem eFuse/secure-boot neste arquivo.

use crate::persistence::{FlashStorageBackend, SecureStorage};

/// Apaga o vault PM selado como parte de todo wipe total (0x2B/0x3E/em-5).
///
/// Idempotente (ausente = sucesso). FIDO2 (`vault/`, `key_slots_v1`, ...) e
/// OATH (`oath6/`) nunca sao tocados aqui - escopo e so `vault-pm/`.
/// Chamar SOMENTE em caminho de wipe total confirmado (sem retorno).
pub fn wipe_pm_vault<B: FlashStorageBackend>(storage: &mut SecureStorage<B>) {
    #[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
    crate::pm_store::pm_blob_wipe(storage);
    #[cfg(any(feature = "cap-fido-only", feature = "cap-fido-totp"))]
    let _ = storage;
    crate::ltrace!(
        crate::lifetime_trace::LifetimeCategory::Oath,
        crate::lifetime_trace::LifetimeEvent::OathDelete,
        "pm-blob"
    );
    log::warn!("[WIPE] vault PM apagado (wipe total cobre chaves + senhas)");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    #[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
    #[test]
    fn wipe_pm_vault_drops_blob_and_keeps_fido2_oath() {
        use crate::config::DeviceConfig;
        use crate::oath_store::{oath_store_get, oath_store_put};
        use crate::pm_store::{pm_blob_load, pm_blob_save, PmStoreError};
        use crate::vault_store::{vault_store_get, vault_store_put};
        let mut st = test_storage();
        let cfg = DeviceConfig::default();
        vault_store_put(&mut st, &cfg, "fido-label", b"fido-blob").expect("fido put");
        oath_store_put(&mut st, "GitHub:alice", b"oath-blob").expect("oath put");
        pm_blob_save(&mut st, b"pm-sealed").expect("pm save");
        // Idempotente mesmo com blob presente; segunda chamada sem blob tambem ok.
        wipe_pm_vault(&mut st);
        wipe_pm_vault(&mut st);
        assert_eq!(pm_blob_load(&st), Err(PmStoreError::NotFound));
        assert_eq!(
            vault_store_get(&st, "fido-label").expect("fido survives"),
            b"fido-blob"
        );
        assert_eq!(
            oath_store_get(&st, "GitHub:alice").expect("oath survives"),
            b"oath-blob"
        );
    }
}
