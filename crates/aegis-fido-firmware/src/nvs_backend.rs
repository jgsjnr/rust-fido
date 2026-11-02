//! Backend NVS real (ESP-IDF) + chave-dev persistente (test-mode only).
//!
//! CI-GREP: TEST-HOOK (test-mode only; absent in release).
//!
//! - `PlatformFlashBackend`: enum NVS/RAM. NVS (`namespace "aegis"`, blobs)
//!   persiste entre reboots; RAM (`MockFlashBackend`) é o fallback
//!   fail-operational se a partição NVS falhar.
//! - `load_or_create_dev_keys` (SÓ `test-mode`): na primeira boot sem eFuse,
//!   gera TRNG e grava em `namespace "aegisdev"` (`dev_master_key`,
//!   `dev_salt`); nos boots seguintes reutiliza. Sem burn de eFuse, com
//!   persistência p/ teste. Release sem `test-mode` NEM COMPILA este
//!   caminho (`check-release-clean.py` prova).
//!
//! Limites NVS: chaves ≤15 chars (todas as `*_NVS_KEY` cabem), blobs
//! pequenos (credenciais/binding/PIN). Staging OTA de imagens grandes =
//! follow-up (esquema de partição).

extern crate alloc;

use alloc::vec::Vec;

#[cfg(any(test, not(target_os = "espidf")))]
use crate::persistence::MockFlashBackend;
use crate::persistence::{FlashStorageBackend, StorageError};

/// OTA staging/dispatch canonico em `stores::ota_store` (re-export de compat).
pub use crate::stores::ota_store::*;

/// Teto de leitura por blob (envelopes SecureStorage são pequenos).
pub(crate) const NVS_READ_MAX: usize = 8192;

#[cfg(target_os = "espidf")]
fn map_esp_err(e: esp_idf_sys::EspError) -> StorageError {
    use esp_idf_sys::{ESP_ERR_NVS_NOT_FOUND, ESP_ERR_NVS_NO_FREE_PAGES};
    let _ = e;
    let code = e.code();
    if code == ESP_ERR_NVS_NOT_FOUND {
        StorageError::KeyNotFound
    } else if code == ESP_ERR_NVS_NO_FREE_PAGES {
        StorageError::FlashWriteError
    } else {
        StorageError::FlashWriteError
    }
}

/// Partição `storage` (896 KiB) compartilhada: NVS default (24 KiB) não
/// aguenta staging OTA. Take único por boot + clones (take duplo falha).
#[cfg(target_os = "espidf")]
static STORAGE_PART: std::sync::OnceLock<
    esp_idf_svc::nvs::EspNvsPartition<esp_idf_svc::nvs::NvsCustom>,
> = std::sync::OnceLock::new();

#[cfg(target_os = "espidf")]
fn storage_partition(
) -> Result<esp_idf_svc::nvs::EspNvsPartition<esp_idf_svc::nvs::NvsCustom>, StorageError> {
    use esp_idf_svc::nvs::{EspNvsPartition, NvsCustom};
    if let Some(p) = STORAGE_PART.get() {
        return Ok(p.clone());
    }
    let p =
        EspNvsPartition::<NvsCustom>::take("storage").map_err(|_| StorageError::FlashWriteError)?;
    let _ = STORAGE_PART.set(p.clone());
    Ok(p)
}

/// Backend de plataforma: NVS real no device, RAM no host/fallback.
pub enum PlatformFlashBackend {
    #[cfg(target_os = "espidf")]
    Nvs(esp_idf_svc::nvs::EspNvs<esp_idf_svc::nvs::NvsCustom>),
    #[cfg(any(test, not(target_os = "espidf")))]
    Ram(MockFlashBackend),
}

impl PlatformFlashBackend {
    /// Abre o NVS (`namespace "aegis"`); falha = fail-closed no device (panic), RAM so em host/test.
    pub fn new() -> Self {
        #[cfg(target_os = "espidf")]
        {
            match Self::open_nvs() {
                Ok(nvs) => return Self::Nvs(nvs),
                // Fail-operational no host/teste: sem NVS, RAM (sem persistência).
                // O chamador loga via kprintln (aqui sem acesso a ele).
                #[cfg(any(test, not(target_os = "espidf")))]
                Err(e) => {
                    // Fail-closed no device (R15/R16): sem fallback silencioso
                    // para RAM, sem mock; `new() -> Self` nao comporta erro
                    // tipado, entao aborta aqui. Sem segredo em log.
                    let _ = e;
                    #[cfg(any(test, not(target_os = "espidf")))]
                    return Self::Ram(MockFlashBackend::new());
                    #[cfg(not(any(test, not(target_os = "espidf"))))]
                    panic!("nvs: open failed (fail-closed)");
                }
                // Device (espidf, sem teste): só NVS real; sem fallback RAM
                // (`MockFlashBackend` usa `std`, ausente no device `no_std`).
                #[cfg(not(any(test, not(target_os = "espidf"))))]
                Err(_) => panic!("NVS partition unavailable"),
            }
        }
        #[cfg(not(target_os = "espidf"))]
        {
            Self::Ram(MockFlashBackend::new())
        }
    }

    /// `true` quando o NVS real está por trás (p/ log de boot).
    pub fn is_persistent(&self) -> bool {
        match self {
            #[cfg(target_os = "espidf")]
            Self::Nvs(_) => true,
            #[cfg(any(test, not(target_os = "espidf")))]
            Self::Ram(_) => false,
        }
    }

    #[cfg(target_os = "espidf")]
    fn open_nvs() -> Result<esp_idf_svc::nvs::EspNvs<esp_idf_svc::nvs::NvsCustom>, StorageError> {
        use esp_idf_svc::nvs::EspNvs;
        let part = storage_partition()?;
        EspNvs::new(part, "aegis", true).map_err(|_| StorageError::FlashWriteError)
    }
}

impl Default for PlatformFlashBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FlashStorageBackend for PlatformFlashBackend {
    fn read_raw(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        match self {
            #[cfg(target_os = "espidf")]
            Self::Nvs(nvs) => {
                let mut buf = alloc::vec![0u8; NVS_READ_MAX];
                match nvs.get_blob(key, &mut buf).map_err(map_esp_err)? {
                    Some(slice) => Ok(slice.to_vec()),
                    None => Err(StorageError::KeyNotFound),
                }
            }
            #[cfg(any(test, not(target_os = "espidf")))]
            Self::Ram(ram) => ram.read_raw(key),
        }
    }

    fn write_raw(&mut self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        if data.len() > NVS_READ_MAX {
            return Err(StorageError::BufferOverflow);
        }
        match self {
            #[cfg(target_os = "espidf")]
            Self::Nvs(nvs) => nvs.set_blob(key, data).map_err(map_esp_err),
            #[cfg(any(test, not(target_os = "espidf")))]
            Self::Ram(ram) => ram.write_raw(key, data),
        }
    }

    fn delete_raw(&mut self, key: &str) -> Result<(), StorageError> {
        match self {
            #[cfg(target_os = "espidf")]
            Self::Nvs(nvs) => {
                // `remove` em chave ausente = Ok(false): idempotente.
                nvs.remove(key).map_err(map_esp_err)?;
                Ok(())
            }
            #[cfg(any(test, not(target_os = "espidf")))]
            Self::Ram(ram) => ram.delete_raw(key),
        }
    }

    fn exists(&self, key: &str) -> bool {
        match self {
            #[cfg(target_os = "espidf")]
            Self::Nvs(nvs) => nvs.contains(key).unwrap_or(false),
            #[cfg(any(test, not(target_os = "espidf")))]
            Self::Ram(ram) => ram.exists(key),
        }
    }
}

/// Chave-dev persistente em flash (SÓ test-mode; sem burn de eFuse).
///
/// Namespace separado `"aegisdev"` (fora do `SecureStorage`, que ainda não
/// existe no boot). Primeira boot: TRNG + grava; seguintes: reutiliza.
/// Release não compila este símbolo (`#[cfg]` + release-clean check).
#[cfg(all(target_os = "espidf", feature = "test-mode"))]
pub fn load_or_create_dev_keys() -> Result<([u8; 32], [u8; 32]), StorageError> {
    use esp_idf_svc::nvs::EspNvs;
    use rand_core::Rng;

    const NS: &str = "aegisdev";
    const K_MASTER: &str = "dev_master_key";
    const K_SALT: &str = "dev_salt";

    let part = storage_partition()?;
    let mut nvs = EspNvs::new(part, NS, true).map_err(|_| StorageError::FlashWriteError)?;

    let read_one = |nvs: &esp_idf_svc::nvs::EspNvs<esp_idf_svc::nvs::NvsCustom>,
                    key: &str|
     -> Option<[u8; 32]> {
        let mut buf = [0u8; 32];
        match nvs.get_blob(key, &mut buf) {
            Ok(Some(slice)) if slice.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(slice);
                Some(out)
            }
            _ => None,
        }
    };

    if let (Some(m), Some(s)) = (read_one(&nvs, K_MASTER), read_one(&nvs, K_SALT)) {
        return Ok((m, s));
    }
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let mut m = [0u8; 32];
    let mut s = [0u8; 32];
    rng.fill_bytes(&mut m);
    rng.fill_bytes(&mut s);
    nvs.set_blob(K_MASTER, &m)
        .map_err(|_| StorageError::FlashWriteError)?;
    nvs.set_blob(K_SALT, &s)
        .map_err(|_| StorageError::FlashWriteError)?;
    Ok((m, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plataforma_host_e_ram_roundtrip() {
        let mut b = PlatformFlashBackend::new();
        assert!(!b.is_persistent());
        assert!(!b.exists("k"));
        b.write_raw("k", b"v").expect("write");
        assert!(b.exists("k"));
        assert_eq!(b.read_raw("k").expect("read"), b"v");
        b.delete_raw("k").expect("delete");
        assert_eq!(b.read_raw("k"), Err(StorageError::KeyNotFound));
    }
}
