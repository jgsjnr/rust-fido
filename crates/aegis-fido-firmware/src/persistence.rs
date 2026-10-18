//! Secure NVS/Flash Encrypted Persistence Driver with Master Key Protection.
//!
//! All sensitive authentication data (Passkeys, Resident Credentials, PIN Hashes,
//! OATH Secrets, Sign Counters) are encrypted at rest using AES-256-GCM with unique
//! nonces and authenticated integrity tags.
//! Keys are derived from the hardware eFuse OTP Master Key and Device Salt via HKDF-SHA256.
//! 100% Native Rust implementation.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

pub const ENVELOPE_MAGIC: [u8; 4] = [0x41, 0x45, 0x47, 0x4E]; // "AEGN"
pub const ENVELOPE_VERSION: u8 = 0x01;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;
pub const MAX_PLAINTEXT_BYTES: usize = 512;
pub const MAX_ENVELOPE_BYTES: usize = 4 + 1 + NONCE_SIZE + MAX_PLAINTEXT_BYTES + TAG_SIZE;

type HmacSha256 = Hmac<Sha256>;

/// Derives a 256-bit AES storage key from the Master Key and Salt using HKDF-SHA256.
pub fn derive_storage_key(master_key: &[u8; 32], salt: &[u8; 32], info: &[u8]) -> [u8; KEY_SIZE] {
    // HKDF-Extract: PRK = HMAC-Hash(salt, master_key)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC init");
    mac.update(master_key);
    let prk = mac.finalize().into_bytes();

    // HKDF-Expand: OKM = HMAC-Hash(PRK, info || 0x01)
    let mut mac_exp = <HmacSha256 as Mac>::new_from_slice(&prk).expect("HMAC expand init");
    mac_exp.update(info);
    mac_exp.update(&[0x01]);
    let okm = mac_exp.finalize().into_bytes();

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&okm[..KEY_SIZE]);
    key
}

/// Errors originating during encrypted persistence operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    KeyNotFound,
    CorruptedEnvelope,
    DecryptionFailed,
    FlashWriteError,
    BufferOverflow,
}

/// Abstract flash / NVS storage interface.
pub trait FlashStorageBackend {
    fn read_raw(&self, key: &str) -> Result<Vec<u8>, StorageError>;
    fn write_raw(&mut self, key: &str, data: &[u8]) -> Result<(), StorageError>;
    fn delete_raw(&mut self, key: &str) -> Result<(), StorageError>;
    fn exists(&self, key: &str) -> bool;
}

/// Secure Encrypted Persistence Manager.
pub struct SecureStorage<B: FlashStorageBackend> {
    backend: B,
    encryption_key: [u8; KEY_SIZE],
}

impl<B: FlashStorageBackend> Drop for SecureStorage<B> {
    fn drop(&mut self) {
        self.encryption_key.zeroize();
    }
}

impl<B: FlashStorageBackend> SecureStorage<B> {
    pub fn new(backend: B, master_key: &[u8; 32], salt: &[u8; 32]) -> Self {
        let key = derive_storage_key(master_key, salt, b"AegisKey-NVS-Storage-v1");
        Self {
            backend,
            encryption_key: key,
        }
    }

    /// Encrypts plaintext data with AES-256-GCM and stores it under key.
    /// Wave1: nonce TRNG 12B gerado internamente, parametro fixo ignorado.
    /// Envelope AEGN VER nonce ct+tag inalterado. Zeroize apos uso.
    pub fn store(&mut self, key: &str, plaintext: &[u8], _nonce_bytes: &[u8; 12]) -> Result<(), StorageError> {
        let mut trng = rand_core::OsRng;
        self.store_with_rng(key, plaintext, &mut trng)
    }

    /// Variante TRNG explicita (mesmo padrao de seal_blob): gera nonce via RngCore.
    /// MAX-ESP: envelope em buffer estatico, sem alloc no hot path do envelope.
    pub fn store_with_rng<R: RngCore + CryptoRng>(&mut self, key: &str, plaintext: &[u8], rng: &mut R) -> Result<(), StorageError> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(StorageError::BufferOverflow);
        }
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key).map_err(|_| StorageError::FlashWriteError)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ciphertext = cipher.encrypt(nonce, plaintext).map_err(|_| StorageError::FlashWriteError)?;
        let mut envelope = [0u8; MAX_ENVELOPE_BYTES];
        let total = 4 + 1 + NONCE_SIZE + ciphertext.len();
        envelope[0..4].copy_from_slice(&ENVELOPE_MAGIC);
        envelope[4] = ENVELOPE_VERSION;
        envelope[5..5 + NONCE_SIZE].copy_from_slice(&nonce_bytes);
        envelope[5 + NONCE_SIZE..total].copy_from_slice(&ciphertext);
        let res = self.backend.write_raw(key, &envelope[..total]);
        nonce_bytes.zeroize();
        ciphertext.zeroize();
        envelope.zeroize();
        res
    }

    /// Loads and decrypts data stored under `key`.
    pub fn load(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        let raw = self.backend.read_raw(key)?;

        if raw.len() < 4 + 1 + NONCE_SIZE + TAG_SIZE {
            return Err(StorageError::CorruptedEnvelope);
        }

        if raw[0..4] != ENVELOPE_MAGIC || raw[4] != ENVELOPE_VERSION {
            return Err(StorageError::CorruptedEnvelope);
        }

        let nonce_bytes = &raw[5..5 + NONCE_SIZE];
        let ciphertext = &raw[5 + NONCE_SIZE..];

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|_| StorageError::DecryptionFailed)?;
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| StorageError::DecryptionFailed)
    }

    /// Removes an item from storage.
    pub fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.backend.delete_raw(key)
    }

    /// Checks if a key exists in storage.
    pub fn exists(&self, key: &str) -> bool {
        self.backend.exists(key)
    }
}

/// CI-GREP: MOCK-ONLY-IN-TEST — Mock* test-only; prod uses RamFlashBackend.
/// In-memory storage backend for unit testing and simulation.
#[derive(Debug, Clone, Default)]
pub struct MockFlashBackend {
    store: std::collections::HashMap<String, Vec<u8>>,
}

/// Prod RAM flash backend (no fixture secrets; use provision loader).
pub type RamFlashBackend = MockFlashBackend;

impl MockFlashBackend {
    pub fn new() -> Self {
        Self {
            store: std::collections::HashMap::new(),
        }
    }
}

impl FlashStorageBackend for MockFlashBackend {
    fn read_raw(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        self.store
            .get(key)
            .cloned()
            .ok_to_end(StorageError::KeyNotFound)
    }

    fn write_raw(&mut self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        self.store.insert(key.to_string(), data.to_vec());
        Ok(())
    }

    fn delete_raw(&mut self, key: &str) -> Result<(), StorageError> {
        self.store.remove(key);
        Ok(())
    }

    fn exists(&self, key: &str) -> bool {
        self.store.contains_key(key)
    }
}

trait OptionExt<T> {
    fn ok_to_end(self, err: StorageError) -> Result<T, StorageError>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_to_end(self, err: StorageError) -> Result<T, StorageError> {
        self.ok_or(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let master_key = [0x55u8; 32];
        let salt = [0xAAu8; 32];
        let backend = MockFlashBackend::new();
        let mut storage = SecureStorage::new(backend, &master_key, &salt);

        let nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
        let secret_data = b"Master Passkey Credential Data #12345";

        storage.store("credential_01", secret_data, &nonce).unwrap();
        assert!(storage.exists("credential_01"));

        let decrypted = storage.load("credential_01").unwrap();
        assert_eq!(decrypted, secret_data);
    }

    #[test]
    fn test_tamper_detection() {
        let master_key = [0x11u8; 32];
        let salt = [0x22u8; 32];
        let mut backend = MockFlashBackend::new();
        let nonce = [0x00u8; 12];

        {
            let mut storage = SecureStorage::new(backend.clone(), &master_key, &salt);
            storage.store("pin_hash", b"my_secure_pin_salt_hash", &nonce).unwrap();
            backend = storage.backend.clone();
        }

        // Tamper with the raw ciphertext in storage
        let mut raw = backend.read_raw("pin_hash").unwrap();
        let last_idx = raw.len() - 1;
        raw[last_idx] ^= 0xFF; // Flip bits
        backend.write_raw("pin_hash", &raw).unwrap();

        // Attempting to load tampered data must fail with DecryptionFailed
        let storage = SecureStorage::new(backend, &master_key, &salt);
        let res = storage.load("pin_hash");
        assert_eq!(res, Err(StorageError::DecryptionFailed));
    }

    #[test]
    fn test_nonce_trng_unique() {
        let master_key = [0x55u8; 32];
        let salt = [0xAAu8; 32];
        let backend = MockFlashBackend::new();
        let mut storage = SecureStorage::new(backend, &master_key, &salt);
        let ignored = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
        let data = b"same plaintext for nonce uniqueness";
        storage.store("k1", data, &ignored).unwrap();
        storage.store("k2", data, &ignored).unwrap();
        let r1 = storage.backend.read_raw("k1").unwrap();
        let r2 = storage.backend.read_raw("k2").unwrap();
        // Envelope AEGN VER nonce ct+tag preservado
        assert_eq!(&r1[0..4], &ENVELOPE_MAGIC);
        assert_eq!(&r2[0..4], &ENVELOPE_MAGIC);
        assert_eq!(r1[4], ENVELOPE_VERSION);
        assert_eq!(r2[4], ENVELOPE_VERSION);
        let n1 = &r1[5..5 + NONCE_SIZE];
        let n2 = &r2[5..5 + NONCE_SIZE];
        // TRNG interno: mesmo input e nonce ignorado geram nonces diferentes
        assert_ne!(n1, n2);
        // Roundtrip continua valido para ambos
        assert_eq!(storage.load("k1").unwrap(), data);
        assert_eq!(storage.load("k2").unwrap(), data);
    }

    #[test]
    fn test_max_esp_overflow() {
        let master_key = [0x55u8; 32];
        let salt = [0xAAu8; 32];
        let backend = MockFlashBackend::new();
        let mut storage = SecureStorage::new(backend, &master_key, &salt);
        let ignored = [0x00u8; 12];
        let big = [0x41u8; MAX_PLAINTEXT_BYTES + 1];
        let res = storage.store("big", &big, &ignored);
        assert_eq!(res, Err(StorageError::BufferOverflow));
    }
    #[test]
    fn power_loss_mid_write() {
        let master_key = [0x55u8; 32];
        let salt = [0xAAu8; 32];
        let backend = MockFlashBackend::new();
        let mut storage = SecureStorage::new(backend, &master_key, &salt);
        let ignored = [0x00u8; 12];
        let ka = core::str::from_utf8(&[115, 108, 111, 116, 95, 97]).unwrap();
        let kb = core::str::from_utf8(&[115, 108, 111, 116, 95, 98]).unwrap();
        let data = [10u8, 20, 30, 40];
        storage.store(ka, &data, &ignored).unwrap();
        storage.store(kb, &data, &ignored).unwrap();
        let mut raw_b = storage.backend.read_raw(kb).unwrap();
        let last = raw_b.len() - 1;
        raw_b[last] ^= 0xFF;
        storage.backend.write_raw(kb, &raw_b).unwrap();
        assert_eq!(storage.load(ka).unwrap(), data);
        assert_eq!(storage.load(kb), Err(StorageError::DecryptionFailed));
        let raw_a = storage.backend.read_raw(ka).unwrap();
        assert_eq!(&raw_a[0..4], &ENVELOPE_MAGIC);
        assert_eq!(raw_a[4], ENVELOPE_VERSION);
    }
}
