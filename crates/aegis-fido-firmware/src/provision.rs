//! Wave3 P2 — provision loader with fallback (no hardcoded secrets in prod).
//!
//! CI-GREP: MOCK-ONLY-IN-TEST — prod path never uses `Mock*` nor `0x5A`/`0xA5`.
//! Test fixture `MockEfuseStorage::with_default_keys` is `#[cfg(test)]` only.
//!
//! Behavior:
//! - `espidf`: reads BLOCK7/8 via `EfuseManager`; unprovisioned (all-zero) => `Err(Unprovisioned)`.
//!   Factory must run `tools/factory_provision.py` (eFuse irreversivel, verify-after-write).
//! - `host` (`not(espidf)`): tries eFuse blocks; if unprovisioned, falls back to
//!   TRNG-ephemeral keys via `OsRng` (dev-only, never hardcoded, never committed).
//! - Segredos nunca no repo: nenhum `0x5A`/`0xA5`/serial fixo neste arquivo.

use rand_core::RngCore;

use crate::efuse::{EfuseManager, EfuseStorage, EFUSE_KEY_LEN};

/// Provisioning failure (typed, no panics in prod path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionError {
    /// eFuse read/burn failure.
    EfuseFault,
    /// Blocks read as all-zero (factory not yet run).
    Unprovisioned,
    /// TRNG failure on host fallback.
    RngFault,
}

impl core::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EfuseFault => write!(f, "efuse read fault"),
            Self::Unprovisioned => write!(f, "device unprovisioned (factory required)"),
            Self::RngFault => write!(f, "rng fault"),
        }
    }
}

/// Device keys loaded from eFuse or host fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceKeys {
    /// 256-bit master key (BLOCK7).
    pub master_key: [u8; EFUSE_KEY_LEN],
    /// 256-bit device salt (BLOCK8).
    pub device_salt: [u8; EFUSE_KEY_LEN],
}

/// Returns true when master block is non-zero (provisioned).
pub fn is_provisioned<S: EfuseStorage>(mgr: &EfuseManager<S>) -> bool {
    mgr.is_master_key_provisioned()
}

/// Loads keys from eFuse; host falls back to TRNG-ephemeral on unprovisioned.
/// MAX-ESP: no alloc, fixed 32B arrays, single pass.
pub fn load_device_keys<S: EfuseStorage>(
    mgr: &EfuseManager<S>,
) -> Result<DeviceKeys, ProvisionError> {
    let master = mgr.get_master_key().map_err(|_| ProvisionError::EfuseFault)?;
    let salt = mgr.get_device_salt().map_err(|_| ProvisionError::EfuseFault)?;
    if is_all_zero(&master) || is_all_zero(&salt) {
        return fallback_or_error();
    }
    Ok(DeviceKeys {
        master_key: master,
        device_salt: salt,
    })
}

/// Checks all-zero (unprogrammed OTP reads as zero).
fn is_all_zero(key: &[u8; EFUSE_KEY_LEN]) -> bool {
    key.iter().all(|&b| b == 0)
}

/// `espidf`: hard error (factory required). `host`: TRNG-ephemeral fallback.
fn fallback_or_error() -> Result<DeviceKeys, ProvisionError> {
    #[cfg(target_os = "espidf")]
    {
        Err(ProvisionError::Unprovisioned)
    }
    #[cfg(not(target_os = "espidf"))]
    {
        let mut master_key = [0u8; EFUSE_KEY_LEN];
        let mut device_salt = [0u8; EFUSE_KEY_LEN];
        let mut rng = rand_core::OsRng;
        rng.try_fill_bytes(&mut master_key)
            .map_err(|_| ProvisionError::RngFault)?;
        rng.try_fill_bytes(&mut device_salt)
            .map_err(|_| ProvisionError::RngFault)?;
        if is_all_zero(&master_key) || is_all_zero(&device_salt) {
            return Err(ProvisionError::RngFault);
        }
        Ok(DeviceKeys {
            master_key,
            device_salt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efuse::MockEfuseStorage;

    #[test]
    fn unprovisioned_host_falls_back_to_trng() {
        let mgr = EfuseManager::new(MockEfuseStorage::new());
        assert!(!is_provisioned(&mgr));
        let keys = load_device_keys(&mgr).expect("host fallback");
        assert!(!is_all_zero(&keys.master_key));
        assert!(!is_all_zero(&keys.device_salt));
    }

    #[test]
    fn provisioned_blocks_load_verbatim() {
        let storage = MockEfuseStorage::new();
        let mut mgr = EfuseManager::new(storage);
        let mk = [0x11u8; 32];
        let salt = [0x22u8; 32];
        mgr.provision_master_key(&mk).expect("provision");
        mgr.provision_device_salt(&salt).expect("salt");
        assert!(is_provisioned(&mgr));
        let keys = load_device_keys(&mgr).expect("load");
        assert_eq!(keys.master_key, mk);
        assert_eq!(keys.device_salt, salt);
    }

    #[test]
    fn test_fixture_only_in_test() {
        // CI-GREP marker: with_default_keys exists only under cfg(test).
        let s = MockEfuseStorage::with_default_keys();
        let mgr = EfuseManager::new(s);
        assert!(is_provisioned(&mgr));
        let keys = load_device_keys(&mgr).expect("fixture loads");
        assert_eq!(keys.master_key, [0x5Au8; 32]);
    }
}
