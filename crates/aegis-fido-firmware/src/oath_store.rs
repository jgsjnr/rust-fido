//! Fase6 Step3 - oath_store NVS para credenciais OATH sobre BLE.
//!
//! - Aditivo: namespaces oath6/ via oath6_key, bounds via validate_v6_label.
//! - TLV total <=512B; verify-after-write no put (igual migrations).
//! - Reusa SecureStorage store/load/delete; sem nova cripto, sem getter de segredo
//!   fora do envelope cifrado (secret nunca sai em claro, 9.7).

extern crate alloc;

use alloc::vec::Vec;

use crate::migrations::keys_oath_v6::{oath6_key, validate_v6_label};
use crate::persistence::{FlashStorageBackend, SecureStorage, StorageError};
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};

/// Limite do blob OATH por slot (9.3 TLV total <=512B).
pub const OATH_STORE_MAX_BYTES: usize = 512;
/// Nonce placeholder (ignorado, TRNG dentro de store).
const IGNORED_NONCE: [u8; 12] = [0u8; 12];

/// Erro tipado do oath_store (sem panics, sem stringly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OathStoreError {
    /// Label fora de 1..32B utf8.
    BadLabel,
    /// Blob acima de 512B.
    TooLarge,
    /// Slot ausente.
    NotFound,
    /// Falha de storage ou verify-after-write.
    Storage,
}

impl core::fmt::Display for OathStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadLabel => write!(f, "bad oath label"),
            Self::TooLarge => write!(f, "oath blob too large"),
            Self::NotFound => write!(f, "oath slot not found"),
            Self::Storage => write!(f, "oath storage failure"),
        }
    }
}

impl From<StorageError> for OathStoreError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::KeyNotFound => Self::NotFound,
            _ => Self::Storage,
        }
    }
}

/// Grava blob OATH em oath6/<label> com verify-after-write.
pub fn oath_store_put<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    label: &str,
    blob: &[u8],
) -> Result<(), OathStoreError> {
    validate_v6_label(label).map_err(|_| OathStoreError::BadLabel)?;
    if blob.len() > OATH_STORE_MAX_BYTES {
        return Err(OathStoreError::TooLarge);
    }
    let key = oath6_key(label);
    storage.store(&key, blob, &IGNORED_NONCE)?;
    let back = storage.load(&key)?;
    if back != blob {
        let _ = storage.delete(&key);
        return Err(OathStoreError::Storage);
    }
    crate::ltrace!(LtCat::Oath, LtEvt::OathPut, label);
    Ok(())
}

/// Le blob OATH de oath6/<label> (envelope cifrado; NotFound se ausente).
pub fn oath_store_get<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    label: &str,
) -> Result<Vec<u8>, OathStoreError> {
    validate_v6_label(label).map_err(|_| OathStoreError::BadLabel)?;
    let key = oath6_key(label);
    let blob = storage.load(&key)?;
    crate::ltrace!(LtCat::Oath, LtEvt::OathCode, label);
    Ok(blob)
}

/// Apaga oath6/<label>; ausente vira NotFound (sem silently-ok).
pub fn oath_store_delete<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    label: &str,
) -> Result<(), OathStoreError> {
    validate_v6_label(label).map_err(|_| OathStoreError::BadLabel)?;
    let key = oath6_key(label);
    if !storage.exists(&key) {
        return Err(OathStoreError::NotFound);
    }
    storage.delete(&key)?;
    crate::ltrace!(LtCat::Oath, LtEvt::OathDelete, label);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn test_storage() -> SecureStorage<crate::persistence::MockFlashBackend> {
        SecureStorage::new(
            crate::persistence::MockFlashBackend::new(),
            &[0x55u8; 32],
            &[0xAAu8; 32],
        )
    }

    #[test]
    fn put_get_delete_roundtrip() {
        let mut st = test_storage();
        oath_store_put(&mut st, "GitHub:alice", b"oath-blob").unwrap();
        assert_eq!(oath_store_get(&st, "GitHub:alice").unwrap(), b"oath-blob");
        oath_store_delete(&mut st, "GitHub:alice").unwrap();
        assert_eq!(
            oath_store_get(&st, "GitHub:alice"),
            Err(OathStoreError::NotFound)
        );
    }

    #[test]
    fn rejects_bad_label_and_too_large() {
        let mut st = test_storage();
        assert_eq!(
            oath_store_put(&mut st, "", b"x"),
            Err(OathStoreError::BadLabel)
        );
        let big = alloc::string::String::from_utf8(vec![0x78u8; 33]).unwrap();
        assert_eq!(
            oath_store_put(&mut st, &big, b"x"),
            Err(OathStoreError::BadLabel)
        );
        assert_eq!(oath_store_get(&st, ""), Err(OathStoreError::BadLabel));
        let huge = vec![0x41u8; OATH_STORE_MAX_BYTES + 1];
        assert_eq!(
            oath_store_put(&mut st, "a", &huge),
            Err(OathStoreError::TooLarge)
        );
    }

    #[test]
    fn delete_absent_is_notfound() {
        let mut st = test_storage();
        assert_eq!(
            oath_store_delete(&mut st, "nope"),
            Err(OathStoreError::NotFound)
        );
    }

    #[test]
    fn overwrite_keeps_verify() {
        let mut st = test_storage();
        oath_store_put(&mut st, "k", b"v1").unwrap();
        oath_store_put(&mut st, "k", b"v2").unwrap();
        assert_eq!(oath_store_get(&st, "k").unwrap(), b"v2");
    }
}