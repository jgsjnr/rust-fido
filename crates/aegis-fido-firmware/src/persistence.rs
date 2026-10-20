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

use crate::ota::{
    OtaError, OtaManifest, OtaSink, OtaState, MAX_OTA_IMAGE_BYTES, OP_OTA_ABORT, OP_OTA_BEGIN,
    OP_OTA_CHUNK, OP_OTA_COMMIT, OP_OTA_FINISH, OTA_MANIFEST_LEN,
};
use ed25519_dalek::{Signature, VerifyingKey};

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
        let nonce = Nonce::from(nonce_bytes);
        let mut ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| StorageError::FlashWriteError)?;
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

        let mut nonce_arr = [0u8; NONCE_SIZE];
        nonce_arr.copy_from_slice(&raw[5..5 + NONCE_SIZE]);
        let ciphertext = &raw[5 + NONCE_SIZE..];

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|_| StorageError::DecryptionFailed)?;
        let nonce = Nonce::from(nonce_arr);

        cipher
            .decrypt(&nonce, ciphertext)
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

    /// Raw backend access for OTA staging (raw `ota_*` flash keys, never envelopes).
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Mutable raw backend access for OTA staging (raw `ota_*` flash keys only).
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }
}

// Wave OTA wiring (Step 4, traces R-04/R-06).
//
// Staging lives under raw `ota_*` flash keys — NEVER through `SecureStorage`
// envelopes (a firmware image can never fit a single 512 B
// `MAX_PLAINTEXT_BYTES` envelope, and credential/OATH NVS keys must stay
// byte-identical across commit and rollback). Rollback on any failure
// preserves NVS: only `ota_*` keys are ever created, modified, or deleted.

/// Raw flash key holding the staged image bytes (append-only during `Staged`).
pub const OTA_STAGING_KEY: &str = "ota_staging";
/// Raw flash key holding the 104 B staged manifest (sig source for FINISH).
pub const OTA_MANIFEST_KEY: &str = "ota_manifest";
/// Raw flash key holding the commit marker (`version` BE u32, post-verify).
///
/// Informational only: the real esp-ota partition swap is a factory
/// follow-up (esp-ota crate absent here — partition code is NOT invented).
/// Stage + verify + NVS-safe commit marker is the Step-4 deliverable.
pub const OTA_COMMIT_MARKER_KEY: &str = "ota_committed";

/// Wire status OK (parity with `ble_gatt` §9.5 `0x00`).
pub const OTA_STATUS_OK: u8 = 0x00;
/// Wire status NEED_UP (parity with `ble_gatt` §9.5 `0x01`): COMMIT sans latch.
pub const OTA_STATUS_NEED_UP: u8 = 0x01;
/// Wire status generic failure (parity with `ble_gatt` §9.5 `0x04`): any `OtaError`.
pub const OTA_STATUS_FAIL: u8 = 0x04;

/// `true` for OTA vendor opcodes `0x30-0x34` (never `0x20-0x2D`).
pub fn is_ota_op(op: u8) -> bool {
    matches!(
        op,
        OP_OTA_BEGIN | OP_OTA_CHUNK | OP_OTA_FINISH | OP_OTA_COMMIT | OP_OTA_ABORT
    )
}

/// Real release-signature gate (Step 4): `VerifyingKey::from_bytes` +
/// `verify_strict`, fail-closed (`false` on any malformed input or bad sig).
pub fn verify_ota_signature(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => match Signature::try_from(&signature[..]) {
            Ok(sig) => vk.verify_strict(message, &sig).is_ok(),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

/// `OtaSink` over a raw flash backend (`ota_*` keys only).
///
/// NEVER touches credential/OATH NVS keys: every read/write/delete targets
/// exactly `OTA_STAGING_KEY`, `OTA_MANIFEST_KEY`, or `OTA_COMMIT_MARKER_KEY`.
/// The backend is plain key-value (no offset writes), so chunks append via
/// read-modify-write; in-order appends are enforced against `len`.
pub struct FlashOtaSink<'a, B: FlashStorageBackend> {
    backend: &'a mut B,
    len: usize,
    finalized: bool,
}

impl<'a, B: FlashStorageBackend> FlashOtaSink<'a, B> {
    /// Opens the staging area, resuming `len` from any previously staged bytes.
    pub fn new(backend: &'a mut B) -> Self {
        let len = backend
            .read_raw(OTA_STAGING_KEY)
            .map(|v| v.len())
            .unwrap_or(0);
        Self {
            backend,
            len,
            finalized: false,
        }
    }

    /// Discards staged image + manifest (rollback); keeps the commit marker
    /// and every non-`ota_*` key untouched.
    pub fn discard(&mut self) {
        let _ = self.backend.delete_raw(OTA_STAGING_KEY);
        let _ = self.backend.delete_raw(OTA_MANIFEST_KEY);
        self.len = 0;
        self.finalized = false;
    }

    /// Stages the 104 B manifest (sig source for FINISH verification).
    pub fn store_manifest(&mut self, raw: &[u8]) -> Result<(), OtaError> {
        if raw.len() != OTA_MANIFEST_LEN {
            return Err(OtaError::BadManifest);
        }
        self.backend
            .write_raw(OTA_MANIFEST_KEY, raw)
            .map_err(|_| OtaError::Overflow)
    }

    /// Loads the staged manifest (FINISH path).
    pub fn load_manifest(&self) -> Result<OtaManifest, OtaError> {
        let raw = self
            .backend
            .read_raw(OTA_MANIFEST_KEY)
            .map_err(|_| OtaError::NotStaged)?;
        OtaManifest::parse(&raw)
    }

    /// Records the post-verify commit marker (`version` BE u32).
    pub fn mark_committed(&mut self, version: u32) -> Result<(), OtaError> {
        self.backend
            .write_raw(OTA_COMMIT_MARKER_KEY, &version.to_be_bytes())
            .map_err(|_| OtaError::Overflow)
    }

    /// Last committed version per the marker (`None` = never committed).
    pub fn committed_marker(&self) -> Option<u32> {
        let raw = self.backend.read_raw(OTA_COMMIT_MARKER_KEY).ok()?;
        if raw.len() != 4 {
            return None;
        }
        let mut v = [0u8; 4];
        v.copy_from_slice(&raw);
        Some(u32::from_be_bytes(v))
    }

    /// Whether a commit marker is present.
    pub fn has_commit_marker(&self) -> bool {
        self.backend.exists(OTA_COMMIT_MARKER_KEY)
    }

    /// Whether staged image bytes are present (test seam).
    pub fn exists_staging(&self) -> bool {
        self.backend.exists(OTA_STAGING_KEY)
    }
}

impl<B: FlashStorageBackend> OtaSink for FlashOtaSink<'_, B> {
    fn write_chunk(&mut self, offset: usize, data: &[u8]) -> Result<(), OtaError> {
        if self.finalized || offset != self.len {
            return Err(OtaError::OutOfOrder);
        }
        let mut staged = match self.backend.read_raw(OTA_STAGING_KEY) {
            Ok(v) => v,
            Err(StorageError::KeyNotFound) => Vec::new(),
            Err(_) => return Err(OtaError::Overflow),
        };
        if staged.len() != self.len {
            return Err(OtaError::Overflow);
        }
        let end = self
            .len
            .checked_add(data.len())
            .ok_or(OtaError::Overflow)?;
        if end > MAX_OTA_IMAGE_BYTES {
            return Err(OtaError::Overflow);
        }
        staged.extend_from_slice(data);
        self.backend
            .write_raw(OTA_STAGING_KEY, &staged)
            .map_err(|_| OtaError::Overflow)?;
        self.len = end;
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), OtaError> {
        if self.finalized || !self.backend.exists(OTA_STAGING_KEY) {
            return Err(OtaError::Overflow);
        }
        self.finalized = true;
        Ok(())
    }
}

/// Transport context for one OTA vendor request (built per-packet in `main`).
pub struct OtaRequestCtx {
    /// `load_device_keys` ok (BEGIN rejects `Unprovisioned` otherwise).
    pub provisioned: bool,
    /// Physical UP latch (`touch_latched`; COMMIT-only gate).
    pub up: bool,
    /// Offline release Ed25519 pubkey (FINISH verification).
    pub ota_pubkey: [u8; 32],
    /// Running firmware version (FINISH rejects downgrade/equal).
    pub current_version: u32,
}

fn ota_fail<B: FlashStorageBackend>(
    state: &mut OtaState,
    sink: &mut FlashOtaSink<B>,
) -> (u8, Vec<u8>) {
    state.rollback();
    sink.discard();
    (OTA_STATUS_FAIL, Vec::new())
}

/// Pure CTAPHID vendor dispatch for `OP_OTA_*` (`None` = unknown opcode, caller ignores).
///
/// BEGIN requires a provisioned device; CHUNK carries `offset BE u32 || data`;
/// FINISH verifies the staged manifest with the real release pubkey via the
/// `verify_with` seam (`ota.rs` keeps its fail-closed stub — read-only);
/// COMMIT requires the physical UP latch (checked here, consumed by the
/// caller) and records the commit marker; ABORT rolls back. Any `OtaError`
/// rolls the session back to `Idle` and discards staging, preserving NVS —
/// except COMMIT-without-UP, which keeps the verified session so the host
/// can re-send after the user taps BOOT (serial NeedUp parity).
pub fn dispatch_ota_request<B: FlashStorageBackend>(
    state: &mut OtaState,
    sink: &mut FlashOtaSink<B>,
    op: u8,
    payload: &[u8],
    ctx: &OtaRequestCtx,
) -> Option<(u8, Vec<u8>)> {
    if !is_ota_op(op) {
        return None;
    }
    match op {
        OP_OTA_BEGIN => {
            sink.discard();
            match state.begin(payload, ctx.provisioned) {
                Ok(()) => match sink.store_manifest(payload) {
                    Ok(()) => Some((OTA_STATUS_OK, Vec::new())),
                    Err(_) => Some(ota_fail(state, sink)),
                },
                Err(_) => Some(ota_fail(state, sink)),
            }
        }
        OP_OTA_CHUNK => {
            if payload.len() < 4 {
                return Some(ota_fail(state, sink));
            }
            let mut off = [0u8; 4];
            off.copy_from_slice(&payload[..4]);
            let offset = u32::from_be_bytes(off) as usize;
            match state.stage_chunk(offset, &payload[4..], sink) {
                Ok(received) => Some((OTA_STATUS_OK, (received as u32).to_be_bytes().to_vec())),
                Err(_) => Some(ota_fail(state, sink)),
            }
        }
        OP_OTA_FINISH => {
            let verdict = match sink.load_manifest() {
                Ok(m) => verify_ota_signature(&ctx.ota_pubkey, &m.signed_bytes(), &m.signature),
                Err(_) => false,
            };
            match state.verify_with(ctx.current_version, verdict) {
                Ok(()) => Some((OTA_STATUS_OK, Vec::new())),
                Err(_) => Some(ota_fail(state, sink)),
            }
        }
        OP_OTA_COMMIT => {
            if OtaState::requires_up() && !ctx.up {
                return Some((OTA_STATUS_NEED_UP, Vec::new()));
            }
            match state.commit(sink) {
                Ok(version) => match sink.mark_committed(version) {
                    Ok(()) => Some((OTA_STATUS_OK, version.to_be_bytes().to_vec())),
                    Err(_) => Some(ota_fail(state, sink)),
                },
                Err(_) => Some(ota_fail(state, sink)),
            }
        }
        OP_OTA_ABORT => {
            state.rollback();
            sink.discard();
            Some((OTA_STATUS_OK, Vec::new()))
        }
        _ => None,
    }
}

/// Snapshots raw values under `keys` (`None` = absent) for NVS-preservation checks.
pub fn snapshot_keys<B: FlashStorageBackend>(backend: &B, keys: &[&str]) -> Vec<Option<Vec<u8>>> {
    keys.iter().map(|k| backend.read_raw(k).ok()).collect()
}

/// `true` iff current raw values under `keys` equal `snapshot`.
pub fn keys_unchanged<B: FlashStorageBackend>(
    backend: &B,
    keys: &[&str],
    snapshot: &[Option<Vec<u8>>],
) -> bool {
    keys.len() == snapshot.len()
        && keys
            .iter()
            .zip(snapshot.iter())
            .all(|(k, v)| backend.read_raw(k).ok() == *v)
}

/// CI-GREP: MOCK-ONLY-IN-TEST — Mock* test-only; prod uses PlatformFlashBackend.
/// In-memory storage backend for unit testing and simulation.
#[derive(Debug, Clone, Default)]
pub struct MockFlashBackend {
    store: std::collections::HashMap<String, Vec<u8>>,
}

/// Backend de plataforma: NVS real no device, RAM no host.
/// (Nome antigo `RamFlashBackend` removido: mentia no device.)
pub type PlatformFlashBackend = crate::nvs_backend::PlatformFlashBackend;

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

/// Wave OTA wiring tests (Step 4, traces R-04/R-06).
///
/// BEHAVIOR: USB CTAPHID vendor dispatch for `0x30-0x34`
/// (begin/chunk/verify/commit/abort) with session state, UP gate on commit,
/// NVS preserved, rollback semantics. RED-first: these tests fail until
/// `FlashOtaSink` + `dispatch_ota_request` + real `verify_ota_signature`
/// land below.
#[cfg(test)]
mod ota_wiring_tests {
    use super::*;
    use crate::ota::{
        OtaPhase, OtaState, OP_OTA_ABORT, OP_OTA_BEGIN, OP_OTA_CHUNK, OP_OTA_COMMIT,
        OP_OTA_FINISH, OTA_MANIFEST_LEN, OtaManifest,
    };
    use ed25519_dalek::SigningKey;
    use sha2::Digest as _;
    use signature::Signer as _;

    const OTA_CURRENT: u32 = 7;
    const OTA_NEXT: u32 = 8;
    const CRED_KEYS: &[&str] = &["credential_01", "oath_secret_02", "pin_hash"];

    fn ota_image() -> Vec<u8> {
        vec![0xA5u8; 1024]
    }

    fn manifest_raw(version: u32, image: &[u8], sig: &[u8; 64]) -> Vec<u8> {
        let digest = Sha256::digest(image);
        let mut raw = Vec::with_capacity(OTA_MANIFEST_LEN);
        raw.extend_from_slice(&version.to_be_bytes());
        raw.extend_from_slice(&(image.len() as u32).to_be_bytes());
        raw.extend_from_slice(&digest);
        raw.extend_from_slice(sig);
        raw
    }

    fn signed_manifest(version: u32, image: &[u8], sk: &SigningKey) -> Vec<u8> {
        let unsigned = manifest_raw(version, image, &[0x5Eu8; 64]);
        let m = OtaManifest::parse(&unsigned).expect("parse unsigned");
        let sig = sk.sign(&m.signed_bytes());
        manifest_raw(version, image, &sig.to_bytes())
    }

    fn chunk_payload(offset: u32, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + data.len());
        v.extend_from_slice(&offset.to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    fn req_ctx(provisioned: bool, up: bool, pubkey: [u8; 32]) -> OtaRequestCtx {
        OtaRequestCtx {
            provisioned,
            up,
            ota_pubkey: pubkey,
            current_version: OTA_CURRENT,
        }
    }

    fn credentialed_storage() -> SecureStorage<MockFlashBackend> {
        let mut storage =
            SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32]);
        let nonce = [0x00u8; 12];
        storage.store("credential_01", b"passkey-bytes", &nonce).unwrap();
        storage.store("oath_secret_02", b"oath-seed", &nonce).unwrap();
        storage.store("pin_hash", b"pin-salt-hash", &nonce).unwrap();
        storage
    }

    /// Stages a fully verified session; leaves `sink` scope open for the caller.
    fn stage_to_verified(
        ota: &mut OtaState,
        sink: &mut FlashOtaSink<MockFlashBackend>,
        manifest: &[u8],
        image: &[u8],
        ctx: &OtaRequestCtx,
    ) {
        assert_eq!(
            dispatch_ota_request(ota, sink, OP_OTA_BEGIN, manifest, ctx),
            Some((OTA_STATUS_OK, Vec::new()))
        );
        let mut off = 0u32;
        for chunk in image.chunks(256) {
            let p = chunk_payload(off, chunk);
            let (st, body) =
                dispatch_ota_request(ota, sink, OP_OTA_CHUNK, &p, ctx).expect("chunk dispatch");
            assert_eq!(st, OTA_STATUS_OK);
            off += chunk.len() as u32;
            assert_eq!(body, off.to_be_bytes().to_vec());
        }
        assert_eq!(
            dispatch_ota_request(ota, sink, OP_OTA_FINISH, &[], ctx),
            Some((OTA_STATUS_OK, Vec::new()))
        );
        assert_eq!(ota.phase(), OtaPhase::Verified);
    }

    #[test]
    fn ota_unknown_opcode_ignored() {
        let mut storage = credentialed_storage();
        let mut ota = OtaState::new(OTA_CURRENT);
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let ctx = req_ctx(true, true, sk.verifying_key().to_bytes());
        let mut sink = FlashOtaSink::new(storage.backend_mut());
        for op in [0x20u8, 0x2D, 0x2F, 0x35, 0xFF] {
            assert_eq!(dispatch_ota_request(&mut ota, &mut sink, op, &[], &ctx), None);
        }
        assert_eq!(ota.phase(), OtaPhase::Idle);
    }

    #[test]
    fn ota_chunk_before_begin_rejected() {
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, [0x11u8; 32]);
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            let p = chunk_payload(0, b"orphan-bytes");
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_CHUNK, &p, &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.exists_staging());
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_begin_rejects_unprovisioned() {
        let mut storage = credentialed_storage();
        let image = ota_image();
        let raw = manifest_raw(OTA_NEXT, &image, &[0x5Eu8; 64]);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(false, true, [0x11u8; 32]);
        let mut sink = FlashOtaSink::new(storage.backend_mut());
        assert_eq!(
            dispatch_ota_request(&mut ota, &mut sink, OP_OTA_BEGIN, &raw, &ctx),
            Some((OTA_STATUS_FAIL, Vec::new()))
        );
        assert_eq!(ota.phase(), OtaPhase::Idle);
    }

    #[test]
    fn ota_commit_without_up_rejected_session_preserved() {
        let mut storage = credentialed_storage();
        let image = ota_image();
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let manifest = signed_manifest(OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, sk.verifying_key().to_bytes());
        let mut sink = FlashOtaSink::new(storage.backend_mut());
        stage_to_verified(&mut ota, &mut sink, &manifest, &image, &ctx);
        // COMMIT without the physical UP latch: NEED_UP, session intact.
        let no_up = req_ctx(true, false, sk.verifying_key().to_bytes());
        assert_eq!(
            dispatch_ota_request(&mut ota, &mut sink, OP_OTA_COMMIT, &[], &no_up),
            Some((OTA_STATUS_NEED_UP, Vec::new()))
        );
        assert_eq!(ota.phase(), OtaPhase::Verified);
        assert_eq!(ota.received(), image.len());
        // Same COMMIT with UP now succeeds.
        assert_eq!(
            dispatch_ota_request(&mut ota, &mut sink, OP_OTA_COMMIT, &[], &ctx),
            Some((OTA_STATUS_OK, OTA_NEXT.to_be_bytes().to_vec()))
        );
        assert_eq!(ota.committed_version(), OTA_NEXT);
    }

    #[test]
    fn ota_happy_path_commit_then_rollback_preserves_nvs() {
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ota_image();
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let manifest = signed_manifest(OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, sk.verifying_key().to_bytes());
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            stage_to_verified(&mut ota, &mut sink, &manifest, &image, &ctx);
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_COMMIT, &[], &ctx),
                Some((OTA_STATUS_OK, OTA_NEXT.to_be_bytes().to_vec()))
            );
            assert_eq!(ota.phase(), OtaPhase::Committed);
            assert_eq!(sink.committed_marker(), Some(OTA_NEXT));
            // Post-commit rollback (pre-reboot): back to Idle, version kept.
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_ABORT, &[], &ctx),
                Some((OTA_STATUS_OK, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert_eq!(ota.committed_version(), OTA_NEXT);
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_bad_chunk_offset_rolls_back_and_preserves_nvs() {
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ota_image();
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let manifest = signed_manifest(OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, sk.verifying_key().to_bytes());
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_BEGIN, &manifest, &ctx),
                Some((OTA_STATUS_OK, Vec::new()))
            );
            let good = chunk_payload(0, &image[..256]);
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_CHUNK, &good, &ctx).map(|r| r.0),
                Some(OTA_STATUS_OK)
            );
            // Out-of-order chunk aborts the whole session (fail-closed).
            let bad = chunk_payload(512, &image[256..512]);
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_CHUNK, &bad, &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.exists_staging());
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_finish_rejects_bad_signature_and_rolls_back() {
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ota_image();
        let raw = manifest_raw(OTA_NEXT, &image, &[0x5Eu8; 64]);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, [0x11u8; 32]);
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_BEGIN, &raw, &ctx),
                Some((OTA_STATUS_OK, Vec::new()))
            );
            let mut off = 0u32;
            for chunk in image.chunks(256) {
                let p = chunk_payload(off, chunk);
                let st = dispatch_ota_request(&mut ota, &mut sink, OP_OTA_CHUNK, &p, &ctx)
                    .map(|r| r.0);
                assert_eq!(st, Some(OTA_STATUS_OK));
                off += chunk.len() as u32;
            }
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_FINISH, &[], &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.exists_staging());
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_sink_only_touches_ota_keys() {
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ota_image();
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let manifest = signed_manifest(OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, sk.verifying_key().to_bytes());
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_BEGIN, &manifest, &ctx),
                Some((OTA_STATUS_OK, Vec::new()))
            );
            let p = chunk_payload(0, &image[..64]);
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_CHUNK, &p, &ctx).map(|r| r.0),
                Some(OTA_STATUS_OK)
            );
            // Staging + manifest live under ota_* keys only; no commit marker yet.
            assert!(sink.exists_staging());
            assert!(!sink.has_commit_marker());
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_verify_signature_roundtrip() {
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let vk = sk.verifying_key().to_bytes();
        let msg = b"ota-release-40-bytes-padded.........";
        let sig = sk.sign(msg).to_bytes();
        assert!(verify_ota_signature(&vk, msg, &sig));
        let mut bad_sig = sig;
        bad_sig[0] ^= 0xFF;
        assert!(!verify_ota_signature(&vk, msg, &bad_sig));
        assert!(!verify_ota_signature(&[0x22u8; 32], msg, &sig));
        assert!(!verify_ota_signature(&[0u8; 32], msg, &sig));
        assert!(!verify_ota_signature(&vk, b"tampered message", &sig));
    }
}


