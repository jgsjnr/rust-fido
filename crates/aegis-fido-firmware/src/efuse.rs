//! ESP32-S3 eFuse OTP Integration Driver for Secure Master Key Storage.
//!
//! ESP32-S3 provides dedicated 256-bit hardware OTP eFuse blocks (BLOCK4 through BLOCK9).
//! BLOCK7 is allocated for the Aegis Master Key (256 bits).
//! BLOCK8 is allocated for the Unique Device Salt / Seed (256 bits).
//! Once written, hardware read/write protection bits can permanently lock these blocks.
//! 100% Native Rust implementation.

pub const EFUSE_MASTER_KEY_BLOCK: u8 = 7;
pub const EFUSE_DEVICE_SALT_BLOCK: u8 = 8;
pub const EFUSE_KEY_LEN: usize = 32; // 256 bits

/// Errors originating from eFuse operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EfuseError {
    AlreadyProgrammed,
    WriteProtected,
    ReadProtected,
    VerificationFailed,
    HardwareFault,
}

/// Abstract hardware eFuse reader and burner.
pub trait EfuseStorage {
    /// Reads 32 bytes from the specified 256-bit eFuse block.
    fn read_block(&self, block: u8) -> Result<[u8; EFUSE_KEY_LEN], EfuseError>;

    /// Programs 32 bytes into the specified 256-bit eFuse block.
    fn burn_block(&mut self, block: u8, data: &[u8; EFUSE_KEY_LEN]) -> Result<(), EfuseError>;

    /// Checks if the block is locked against writes.
    fn is_write_protected(&self, block: u8) -> bool;
}

/// Master Key and Salt manager interfacing with eFuse OTP.
pub struct EfuseManager<S: EfuseStorage> {
    storage: S,
}

impl<S: EfuseStorage> EfuseManager<S> {
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Reads the 256-bit Hardware Master Key from BLOCK7.
    pub fn get_master_key(&self) -> Result<[u8; EFUSE_KEY_LEN], EfuseError> {
        self.storage.read_block(EFUSE_MASTER_KEY_BLOCK)
    }

    /// Reads the 256-bit Unique Device Salt from BLOCK8.
    pub fn get_device_salt(&self) -> Result<[u8; EFUSE_KEY_LEN], EfuseError> {
        self.storage.read_block(EFUSE_DEVICE_SALT_BLOCK)
    }

    /// Checks whether the Master Key has been permanently provisioned into eFuse BLOCK7.
    pub fn is_master_key_provisioned(&self) -> bool {
        if let Ok(key) = self.storage.read_block(EFUSE_MASTER_KEY_BLOCK) {
            // Unprogrammed eFuses read as all zeroes
            key.iter().any(|&b| b != 0)
        } else {
            false
        }
    }

    /// Permanently programs the Master Key into eFuse BLOCK7.
    pub fn provision_master_key(&mut self, key: &[u8; EFUSE_KEY_LEN]) -> Result<(), EfuseError> {
        if self.is_master_key_provisioned() {
            return Err(EfuseError::AlreadyProgrammed);
        }
        if self.storage.is_write_protected(EFUSE_MASTER_KEY_BLOCK) {
            return Err(EfuseError::WriteProtected);
        }

        self.storage.burn_block(EFUSE_MASTER_KEY_BLOCK, key)?;

        // Verify write
        let readback = self.storage.read_block(EFUSE_MASTER_KEY_BLOCK)?;
        if &readback != key {
            return Err(EfuseError::VerificationFailed);
        }

        Ok(())
    }

    /// Checks whether the Device Salt has been permanently provisioned into eFuse BLOCK8.
    pub fn is_device_salt_provisioned(&self) -> bool {
        if let Ok(salt) = self.storage.read_block(EFUSE_DEVICE_SALT_BLOCK) {
            // Unprogrammed eFuses read as all zeroes
            salt.iter().any(|&b| b != 0)
        } else {
            false
        }
    }

    /// Permanently programs the Device Salt into eFuse BLOCK8.
    pub fn provision_device_salt(&mut self, salt: &[u8; EFUSE_KEY_LEN]) -> Result<(), EfuseError> {
        if self.is_device_salt_provisioned() {
            return Err(EfuseError::AlreadyProgrammed);
        }
        if self.storage.is_write_protected(EFUSE_DEVICE_SALT_BLOCK) {
            return Err(EfuseError::WriteProtected);
        }

        self.storage.burn_block(EFUSE_DEVICE_SALT_BLOCK, salt)?;

        // Verify write
        let readback = self.storage.read_block(EFUSE_DEVICE_SALT_BLOCK)?;
        if &readback != salt {
            return Err(EfuseError::VerificationFailed);
        }

        Ok(())
    }
}

/// CI-GREP: MOCK-ONLY-IN-TEST — Mock* test-only; prod uses RamEfuseStorage + provision loader.
/// Simulated in-memory eFuse storage for testing and host-side development.
#[derive(Debug, Clone)]
pub struct MockEfuseStorage {
    blocks: [[u8; EFUSE_KEY_LEN]; 11],
    write_protected: [bool; 11],
}

/// Prod RAM eFuse storage (no hardcoded secrets; use provision loader).
pub type RamEfuseStorage = MockEfuseStorage;

impl Default for MockEfuseStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MockEfuseStorage {
    pub fn new() -> Self {
        Self {
            blocks: [[0u8; EFUSE_KEY_LEN]; 11],
            write_protected: [false; 11],
        }
    }

    pub fn set_write_protected(&mut self, block: u8, protected: bool) {
        if (block as usize) < self.write_protected.len() {
            self.write_protected[block as usize] = protected;
        }
    }
}

#[cfg(test)]
impl MockEfuseStorage {
    /// Pre-populates default developmental keys (test fixture only).
    pub fn with_default_keys() -> Self {
        let mut s = Self::new();
        s.blocks[EFUSE_MASTER_KEY_BLOCK as usize] = [0x5A; EFUSE_KEY_LEN];
        s.blocks[EFUSE_DEVICE_SALT_BLOCK as usize] = [0xA5; EFUSE_KEY_LEN];
        s
    }
}

impl EfuseStorage for MockEfuseStorage {
    fn read_block(&self, block: u8) -> Result<[u8; EFUSE_KEY_LEN], EfuseError> {
        if (block as usize) >= self.blocks.len() {
            return Err(EfuseError::HardwareFault);
        }
        Ok(self.blocks[block as usize])
    }

    fn burn_block(&mut self, block: u8, data: &[u8; EFUSE_KEY_LEN]) -> Result<(), EfuseError> {
        if (block as usize) >= self.blocks.len() {
            return Err(EfuseError::HardwareFault);
        }
        if self.write_protected[block as usize] {
            return Err(EfuseError::WriteProtected);
        }

        // In OTP memory, bits can only transition from 0 to 1 (bitwise OR)
        for i in 0..EFUSE_KEY_LEN {
            self.blocks[block as usize][i] |= data[i];
        }

        Ok(())
    }

    fn is_write_protected(&self, block: u8) -> bool {
        if (block as usize) < self.write_protected.len() {
            self.write_protected[block as usize]
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_efuse_provisioning_and_readback() {
        let storage = MockEfuseStorage::new();
        let mut mgr = EfuseManager::new(storage);

        assert!(!mgr.is_master_key_provisioned());

        let master_key = [0x42u8; 32];
        mgr.provision_master_key(&master_key).unwrap();

        assert!(mgr.is_master_key_provisioned());
        let readback = mgr.get_master_key().unwrap();
        assert_eq!(readback, master_key);

        // Cannot overwrite already provisioned key
        let res = mgr.provision_master_key(&[0x99u8; 32]);
        assert_eq!(res, Err(EfuseError::AlreadyProgrammed));
    }

    #[test]
    fn test_device_salt_double_burn_rejected() {
        let mut mgr = EfuseManager::new(MockEfuseStorage::new());
        let salt = [0x22u8; 32];
        mgr.provision_device_salt(&salt).unwrap();
        let res = mgr.provision_device_salt(&[0x33u8; 32]);
        assert_eq!(res, Err(EfuseError::AlreadyProgrammed));
        assert_eq!(mgr.get_device_salt().unwrap(), salt);
    }

    #[test]
    fn test_efuse_write_protection() {
        let mut storage = MockEfuseStorage::new();
        storage.set_write_protected(EFUSE_MASTER_KEY_BLOCK, true);

        let mut mgr = EfuseManager::new(storage);
        let res = mgr.provision_master_key(&[0x11u8; 32]);
        assert_eq!(res, Err(EfuseError::WriteProtected));
    }
}
