//! T-ST-01 Camada AEAD fim-a-fim sobre o vault (GEN-DEVICE).
//!
//! Motivo: `vault_store` cifra no envelope AEGN da particao, mas nao prova
//! AEAD por slot com chave do chamador nem vinculo ao rotulo; sem esta
//! camada, um slot copiado para outro rotulo abriria igual (secao 9).
//!
//! - Nao edita `vault_store.rs`: so consome `vault_store_put/get/delete` e
//!   `validate_vault_label` (reuso, sem duplicar quota nem envelope).
//! - Layout do blob selado: `NONCE(12) || CT+TAG(16)`; AAD = dominio fixo +
//!   rotulo, entao o slot so abre sob o mesmo rotulo (anti-copia).
//! - Chave (DEK 32 B) via parametro; HW via `AeadBackend` (`EspAead` ancora
//!   o GCM do S3, `SoftwareAead` no host). Nonce via `HrngSource` injetado.
//! - Power-loss: verify-after-write por leitura de volta; divergencia apaga
//!   o slot e falha fechada. Torn write no indice vira `Storage` (herdado do
//!   `vault_store`, sem quota corrompida).
//! - Segredo nunca em log: erros sem chave/nonce/claro; buffers zerados.
//! - Limites: claro <= 484 B (slot 512 - nonce 12 - tag 16).

extern crate alloc;

use alloc::vec::Vec;
use zeroize::Zeroize;

use crate::config::DeviceConfig;
use crate::crypto_aead::{AeadAlgorithm, AeadBackend, AeadError, NONCE_LEN, TAG_LEN};
use crate::crypto_hrng::{HrngError, HrngSource};
use crate::persistence::{FlashStorageBackend, SecureStorage};
use crate::vault_store::{
    validate_vault_label, vault_store_delete, vault_store_get, vault_store_put, VaultStoreError,
    VAULT_STORE_MAX_BYTES,
};

/// Dominio do AAD (separa esta camada de outros envelopes do device).
pub const VAULT_AEAD_DOMAIN: &[u8] = b"aegis-vault-aead-v1:";
/// Claro maximo por slot (512 do slot - 12 nonce - 16 tag).
pub const VAULT_AEAD_MAX_PLAINTEXT: usize = VAULT_STORE_MAX_BYTES - NONCE_LEN - TAG_LEN;

/// Erros da camada AEAD. Sem chave, nonce, rotulo sensivel ou claro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultAeadError {
    /// Rotulo fora de 1..32 B utf8 (ou reservado `index`).
    BadLabel,
    /// Claro acima de 484 B.
    TooLarge,
    /// Quota `max_vault_slots` atingida.
    QuotaExceeded,
    /// Slot ausente.
    NotFound,
    /// Falha de storage / verify-after-write / indice corrompido.
    Storage,
    /// Falha de abertura autenticada (adulterado, DEK ou rotulo errado).
    Decrypt,
    /// HRNG indisponivel para o nonce.
    Rng,
}

impl core::fmt::Display for VaultAeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadLabel => write!(f, "bad vault label"),
            Self::TooLarge => write!(f, "vault plaintext too large"),
            Self::QuotaExceeded => write!(f, "vault quota exceeded"),
            Self::NotFound => write!(f, "vault slot not found"),
            Self::Storage => write!(f, "vault storage failure"),
            Self::Decrypt => write!(f, "vault decrypt failure"),
            Self::Rng => write!(f, "vault rng failure"),
        }
    }
}

impl From<HrngError> for VaultAeadError {
    fn from(_: HrngError) -> Self {
        Self::Rng
    }
}

impl From<AeadError> for VaultAeadError {
    fn from(e: AeadError) -> Self {
        match e {
            AeadError::DecryptFailed => Self::Decrypt,
            AeadError::UnsupportedAlgorithm => Self::Decrypt,
            AeadError::InvalidKey => Self::Decrypt,
            AeadError::TooLarge => Self::TooLarge,
            AeadError::EncryptFailed => Self::Storage,
        }
    }
}

fn map_store(e: VaultStoreError) -> VaultAeadError {
    match e {
        VaultStoreError::BadLabel => VaultAeadError::BadLabel,
        VaultStoreError::TooLarge => VaultAeadError::TooLarge,
        VaultStoreError::QuotaExceeded => VaultAeadError::QuotaExceeded,
        VaultStoreError::NotFound => VaultAeadError::NotFound,
        VaultStoreError::Storage => VaultAeadError::Storage,
    }
}

/// AAD = dominio + rotulo (liga o selo ao slot; copia entre rotulos nega).
fn aad_for(label: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(VAULT_AEAD_DOMAIN.len() + label.len());
    aad.extend_from_slice(VAULT_AEAD_DOMAIN);
    aad.extend_from_slice(label.as_bytes());
    aad
}

/// Sela `plaintext` sob `dek` no slot `label` (put + verify-after-write).
pub fn vault_aead_seal<B, A, R>(
    storage: &mut SecureStorage<B>,
    cfg: &DeviceConfig,
    rng: &mut R,
    label: &str,
    dek: &[u8; 32],
    plaintext: &[u8],
) -> Result<(), VaultAeadError>
where
    B: FlashStorageBackend,
    A: AeadBackend,
    R: HrngSource,
{
    validate_vault_label(label).map_err(map_store)?;
    if plaintext.len() > VAULT_AEAD_MAX_PLAINTEXT {
        return Err(VaultAeadError::TooLarge);
    }
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce)?;
    let aad = aad_for(label);
    let mut body = A::seal(AeadAlgorithm::Aes256Gcm, dek, &nonce, &aad, plaintext)?;
    let mut blob = Vec::with_capacity(NONCE_LEN + body.len());
    blob.extend_from_slice(&nonce);
    blob.append(&mut body);
    nonce.zeroize();
    let res = (|| -> Result<(), VaultAeadError> {
        vault_store_put(storage, cfg, label, &blob).map_err(map_store)?;
        let back = vault_store_get(storage, label).map_err(map_store)?;
        if back.as_slice() != blob.as_slice() {
            let _ = vault_store_delete(storage, label);
            return Err(VaultAeadError::Storage);
        }
        Ok(())
    })();
    blob.zeroize();
    res
}

/// Abre o slot `label` sob `dek`; adulteracao/DEK errada = `Decrypt`.
pub fn vault_aead_open<B, A>(
    storage: &SecureStorage<B>,
    label: &str,
    dek: &[u8; 32],
) -> Result<Vec<u8>, VaultAeadError>
where
    B: FlashStorageBackend,
    A: AeadBackend,
{
    validate_vault_label(label).map_err(map_store)?;
    let blob = vault_store_get(storage, label).map_err(map_store)?;
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(VaultAeadError::Decrypt);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[..NONCE_LEN]);
    let aad = aad_for(label);
    let mut pt = A::open(
        AeadAlgorithm::Aes256Gcm,
        dek,
        &nonce,
        &aad,
        &blob[NONCE_LEN..],
    )?;
    nonce.zeroize();
    if pt.len() > VAULT_AEAD_MAX_PLAINTEXT {
        pt.zeroize();
        return Err(VaultAeadError::Decrypt);
    }
    Ok(pt)
}

/// Apaga o slot `label` (ausente = `NotFound`, sem silently-ok).
pub fn vault_aead_delete<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    label: &str,
) -> Result<(), VaultAeadError> {
    validate_vault_label(label).map_err(map_store)?;
    vault_store_delete(storage, label).map_err(map_store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_aead::{EspAead, SoftwareAead};
    use crate::persistence::{MockFlashBackend, StorageError};

    const DEK: [u8; 32] = [0x33u8; 32];
    const OTHER_DEK: [u8; 32] = [0x44u8; 32];

    /// HRNG deterministico de teste (xorshift; so p/ nonce em teste).
    struct TestRng(u64);

    impl HrngSource for TestRng {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), HrngError> {
            if dest.is_empty() {
                return Err(HrngError::TooShort);
            }
            for b in dest.iter_mut() {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *b = (self.0 & 0xFF) as u8;
            }
            Ok(())
        }
    }

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    fn rng() -> TestRng {
        TestRng(0x12345678_9ABCDEF1)
    }

    #[test]
    fn seal_open_roundtrip() {
        let mut st = test_storage();
        let cfg = DeviceConfig::default();
        vault_aead_seal::<_, SoftwareAead, _>(&mut st, &cfg, &mut rng(), "k", &DEK, b"segredo")
            .unwrap();
        let pt = vault_aead_open::<_, SoftwareAead>(&st, "k", &DEK).unwrap();
        assert_eq!(pt.as_slice(), b"segredo");
        vault_aead_delete(&mut st, "k").unwrap();
        assert_eq!(
            vault_aead_open::<_, SoftwareAead>(&st, "k", &DEK),
            Err(VaultAeadError::NotFound)
        );
    }

    #[test]
    fn tamper_e_dek_errada_negam() {
        let mut st = test_storage();
        let cfg = DeviceConfig::default();
        vault_aead_seal::<_, SoftwareAead, _>(&mut st, &cfg, &mut rng(), "a", &DEK, b"dado")
            .unwrap();
        // DEK errada.
        assert_eq!(
            vault_aead_open::<_, SoftwareAead>(&st, "a", &OTHER_DEK),
            Err(VaultAeadError::Decrypt)
        );
        // Bit flip no corpo selado (envelope valido, CT adulterado).
        let blob = vault_store_get(&st, "a").unwrap();
        let mut forged = blob.clone();
        forged[NONCE_LEN] ^= 0x01;
        vault_store_put(&mut st, &cfg, "a", &forged).unwrap();
        assert_eq!(
            vault_aead_open::<_, SoftwareAead>(&st, "a", &DEK),
            Err(VaultAeadError::Decrypt)
        );
        // Erro nao vaza segredo: Debug/Display sem claro.
        let e = alloc::format!("{:?}", VaultAeadError::Decrypt);
        assert!(!e.contains("dado"));
        assert_eq!(
            alloc::format!("{}", VaultAeadError::Decrypt),
            "vault decrypt failure"
        );
    }

    #[test]
    fn limites_label_e_tamanho() {
        let mut st = test_storage();
        let cfg = DeviceConfig::default();
        assert_eq!(
            vault_aead_seal::<_, SoftwareAead, _>(&mut st, &cfg, &mut rng(), "", &DEK, b"x"),
            Err(VaultAeadError::BadLabel)
        );
        assert_eq!(
            vault_aead_seal::<_, SoftwareAead, _>(&mut st, &cfg, &mut rng(), "index", &DEK, b"x"),
            Err(VaultAeadError::BadLabel)
        );
        let big = alloc::vec![0x41u8; VAULT_AEAD_MAX_PLAINTEXT + 1];
        assert_eq!(
            vault_aead_seal::<_, SoftwareAead, _>(&mut st, &cfg, &mut rng(), "a", &DEK, &big),
            Err(VaultAeadError::TooLarge)
        );
        // Teto exato passa; abertura confere o mesmo claro.
        let max = alloc::vec![0x42u8; VAULT_AEAD_MAX_PLAINTEXT];
        vault_aead_seal::<_, SoftwareAead, _>(&mut st, &cfg, &mut rng(), "m", &DEK, &max).unwrap();
        assert_eq!(
            vault_aead_open::<_, SoftwareAead>(&st, "m", &DEK).unwrap(),
            max
        );
        assert_eq!(
            vault_aead_open::<_, SoftwareAead>(&st, "", &DEK),
            Err(VaultAeadError::BadLabel)
        );
        assert_eq!(
            vault_aead_delete(&mut st, "ausente"),
            Err(VaultAeadError::NotFound)
        );
    }

    #[test]
    fn quota_respeitada() {
        let mut st = test_storage();
        let cfg = DeviceConfig::new(50, 512, 4, 8, 3, 32, 64, 1).expect("cfg 1 slot");
        vault_aead_seal::<_, SoftwareAead, _>(&mut st, &cfg, &mut rng(), "a", &DEK, b"um").unwrap();
        assert_eq!(
            vault_aead_seal::<_, SoftwareAead, _>(&mut st, &cfg, &mut rng(), "b", &DEK, b"dois"),
            Err(VaultAeadError::QuotaExceeded)
        );
        assert_eq!(
            vault_aead_open::<_, SoftwareAead>(&st, "b", &DEK),
            Err(VaultAeadError::NotFound)
        );
    }

    /// Backend que confirma mas perde writes do indice (torn write).
    #[derive(Clone)]
    struct DropIndexWrites {
        inner: MockFlashBackend,
        drop: alloc::rc::Rc<core::cell::Cell<bool>>,
    }

    impl FlashStorageBackend for DropIndexWrites {
        fn read_raw(&self, key: &str) -> Result<Vec<u8>, StorageError> {
            self.inner.read_raw(key)
        }
        fn write_raw(&mut self, key: &str, data: &[u8]) -> Result<(), StorageError> {
            if self.drop.get() && key == crate::vault_store::VAULT_INDEX_KEY {
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
    fn power_loss_torn_index_falha_fechada() {
        let drop = alloc::rc::Rc::new(core::cell::Cell::new(false));
        let backend = DropIndexWrites {
            inner: MockFlashBackend::new(),
            drop: drop.clone(),
        };
        let mut st = SecureStorage::new(backend, &[0x55u8; 32], &[0xAAu8; 32]);
        let cfg = DeviceConfig::new(50, 512, 4, 8, 3, 32, 64, 2).expect("cfg 2 slots");
        vault_aead_seal::<_, SoftwareAead, _>(&mut st, &cfg, &mut rng(), "a", &DEK, b"um").unwrap();
        drop.set(true);
        assert_eq!(
            vault_aead_seal::<_, SoftwareAead, _>(&mut st, &cfg, &mut rng(), "b", &DEK, b"dois"),
            Err(VaultAeadError::Storage)
        );
        // Slot parcial nao abre; indice intacto preserva `a`.
        assert_eq!(
            vault_aead_open::<_, SoftwareAead>(&st, "b", &DEK),
            Err(VaultAeadError::NotFound)
        );
        assert!(st.exists(crate::vault_store::VAULT_INDEX_KEY));
        assert_eq!(
            vault_aead_open::<_, SoftwareAead>(&st, "a", &DEK).unwrap(),
            b"um"
        );
        drop.set(false);
        vault_aead_delete(&mut st, "a").unwrap();
        vault_aead_seal::<_, SoftwareAead, _>(&mut st, &cfg, &mut rng(), "b", &DEK, b"dois")
            .unwrap();
        assert_eq!(
            vault_aead_open::<_, SoftwareAead>(&st, "b", &DEK).unwrap(),
            b"dois"
        );
    }

    #[test]
    fn esp_backend_delega_e_rng_falha_fechada() {
        let mut st = test_storage();
        let cfg = DeviceConfig::default();
        vault_aead_seal::<_, EspAead, _>(&mut st, &cfg, &mut rng(), "e", &DEK, b"hw").unwrap();
        assert_eq!(
            vault_aead_open::<_, EspAead>(&st, "e", &DEK).unwrap(),
            b"hw"
        );
        struct DeadRng;
        impl HrngSource for DeadRng {
            fn fill(&mut self, _: &mut [u8]) -> Result<(), HrngError> {
                Err(HrngError::Unsupported)
            }
        }
        assert_eq!(
            vault_aead_seal::<_, SoftwareAead, _>(&mut st, &cfg, &mut DeadRng, "f", &DEK, b"x"),
            Err(VaultAeadError::Rng)
        );
        assert_eq!(
            vault_aead_open::<_, SoftwareAead>(&st, "f", &DEK),
            Err(VaultAeadError::NotFound)
        );
    }
}
