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
use rand_core::CryptoRng;
use sha2::Sha256;
use zeroize::Zeroize;

pub const ENVELOPE_MAGIC: [u8; 4] = [0x41, 0x45, 0x47, 0x4E]; // "AEGN"
pub const ENVELOPE_VERSION: u8 = 0x01;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;
/// Teto fail-closed do plaintext por `store` (auditoria device-side T13):
/// `export_state` do `KeyManager` = 3 B de header (`ver` + `n u16BE`) +
/// 21 B fixos/slot (`id`+`alg i32BE`+`uso`+`created u64BE`+`sign u32BE`+
/// `llen`+`slen u16BE`) + label ≤32 (`MAX_KEY_LABEL_BYTES`) + segredo ≤66
/// (maior curva, P-521/ES512) → pior caso 32 slots =
/// `3 + 32×(21+32+66) = 3811 ≤ 4096` (margem 285 B); provado no device
/// (T13 GEN `0x00` com estado de 534 B falha com teto 512). Envelope máx
/// 4129 B < `NVS_READ_MAX` 8192 e < limite de blob NVS (~508 kB na
/// partição storage 896 KiB).
pub const MAX_PLAINTEXT_BYTES: usize = 4096;
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

/// NVS key for the device-key-INDEPENDENT Secure Guard recovery envelope
/// blob (`sg_recovery_v1`, 14 chars within the 15-char ESP-IDF NVS limit).
///
/// Plaintext on purpose (internal CRC32 + KEK-bound HMAC inside the envelope;
/// without the recovery code it reveals nothing): it MUST live OUTSIDE the
/// AES-GCM `SecureStorage` envelope so a device-key rotation (fresh ephemeral
/// TRNG keys on DEV boards without eFuse provisioning) cannot take the rescue
/// path down with the encrypted `sg_record_v1`. Never route this key through
/// `SecureStorage::store` / `NamespacedStore` (both encrypt); use the raw
/// helpers below, which bypass the AES envelope via the raw backend.
pub const RECOVERY_ENVELOPE_NVS_KEY: &str = "sg_recovery_v1";

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
    pub fn store(
        &mut self,
        key: &str,
        plaintext: &[u8],
        _nonce_bytes: &[u8; 12],
    ) -> Result<(), StorageError> {
        let mut trng = rand_core::UnwrapErr(getrandom::SysRng);
        self.store_with_rng(key, plaintext, &mut trng)
    }

    /// Variante TRNG explicita (mesmo padrao de seal_blob): gera nonce via RngCore.
    /// MAX-ESP: envelope em heap (`Vec`), nunca na stack — a main do boot roda
    /// com stack crítica (~116 B livres no build com hang) e 545 B na stack
    /// aqui + AES/HKDF sem yield estourava em silêncio (TWDT). Heap move o
    /// custo p/ a DRAM; `zeroize` antes do drop preserva o segredo.
    pub fn store_with_rng<R: CryptoRng>(
        &mut self,
        key: &str,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<(), StorageError> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(StorageError::BufferOverflow);
        }
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|_| StorageError::FlashWriteError)?;
        let nonce = Nonce::from(nonce_bytes);
        let mut ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| StorageError::FlashWriteError)?;
        // Heap: 545 B fora da stack da chamadora (main pré-yield tem ~116 B).
        let mut envelope = vec![0u8; MAX_ENVELOPE_BYTES];
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

// T5 (modular-solid-atomic): `NamespacedStore` — put/get/delete unificado.
//
// `oath_store` / `vault_store` / `piv_store` repetiam o mesmo padrão NVS
// (prefixo + verify-after-write + quota via índice CBOR); este tipo é o
// ponto único desse padrão. Preserva: envelope AEGN v1 (via
// `SecureStorage::store/load`), `NVS_READ_MAX` 8192 (teto do backend),
// fail-closed em corrupção (mismatch de verify apaga só o slot; índice
// de quota NUNCA é apagado em falha — falhar fecha, não abre quota).
// Sem cripto nova, sem `unwrap`/`expect` fora de `#[cfg(test)]`;
// R12 mutável (`&mut` em put/delete), R13 sem novas dependências,
// R14 HW-first (TRNG/AES via `SecureStorage`, mesma fronteira de antes).
// `no_std`-compatível (`alloc`-only); zeroize após uso.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use ciborium::value::Value;

/// Writes the recovery envelope blob as PLAINTEXT via the raw backend,
/// bypassing the AES-GCM `SecureStorage` envelope.
///
/// The caller (Secure Guard storage layer) passes the fixed-size
/// `RECOVERY_ENVELOPE_SIZE` wire form with internal CRC32; this helper
/// performs no framing of its own so the blob stays readable after a
/// device-key rotation that invalidates every encrypted record.
pub fn save_recovery_envelope<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    envelope_bytes: &[u8],
) -> Result<(), StorageError> {
    storage
        .backend_mut()
        .write_raw(RECOVERY_ENVELOPE_NVS_KEY, envelope_bytes)
}

/// Reads the plaintext recovery envelope blob (raw backend, no device key).
///
/// `KeyNotFound` = never provisioned with envelope support; any other error
/// (or a short blob, checked by the caller) fails closed upstream.
pub fn load_recovery_envelope<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
) -> Result<Vec<u8>, StorageError> {
    storage.backend().read_raw(RECOVERY_ENVELOPE_NVS_KEY)
}

/// Destroys the recovery envelope blob. Idempotent (absent = `Ok`).
///
/// Wipe/factory paths MUST call this: the engine already drops its cached
/// envelope on wipe, and a lingering NVS blob would resurrect wiped
/// credentials through the envelope rescue path.
pub fn delete_recovery_envelope<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
) -> Result<(), StorageError> {
    match storage.backend_mut().delete_raw(RECOVERY_ENVELOPE_NVS_KEY) {
        Ok(()) | Err(StorageError::KeyNotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// DEV-ONLY on-device recovery-code cache NVS key (`sg_dev_code_v1`).
///
/// Compiled ONLY under `test-mode` (see crate feature `test-mode`, which
/// propagates `aegis-secure-guard/test-mode`). Release builds contain no such
/// key and no code referencing it.
///
/// The task-assigned full name `sg_dev_recovery_code` exceeds the 15-char
/// ESP-IDF NVS key limit, so the on-wire key is the 14-char truncation
/// `sg_dev_code_v1`. Plaintext on purpose (DEV-only downgrade, same rationale
/// as `sg_recovery_v1`): it MUST live OUTSIDE the AES-GCM envelope via the raw
/// backend so a device-key rotation cannot take the DEV rescue path down with
/// the encrypted `sg_record_v1`. NEVER enable outside `test-mode`; release
/// uses eFuse-provisioned keys and eFuse burns require an explicit owner
/// ceremony. No eFuse operation is performed here (read-only audit: this file
/// contains no `efuse`/`burn`/`BLOCK7` call site).
#[cfg(feature = "test-mode")]
pub const DEV_RECOVERY_CODE_NVS_KEY: &str = "sg_dev_code_v1";

/// Writes the DEV recovery-code cache blob as PLAINTEXT via the raw backend.
///
/// Compiled ONLY under `test-mode`. Called ONLY at provision / rotation /
/// recovery inside test-mode builds (see `secure_guard_storage`). No framing
/// of its own; the blob carries internal magic + version + CRC32.
#[cfg(feature = "test-mode")]
pub fn save_dev_recovery_code<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    blob: &[u8; aegis_fido_core::secure_guard::dev_recovery_cache::DEV_RECOVERY_CODE_BLOB_SIZE],
) -> Result<(), StorageError> {
    storage
        .backend_mut()
        .write_raw(DEV_RECOVERY_CODE_NVS_KEY, blob)
}

/// Reads the DEV recovery-code cache blob (raw backend, no device key).
///
/// Compiled ONLY under `test-mode`. `KeyNotFound` = never cached; any other
/// error (or a bad length, checked by the caller) fails closed upstream.
#[cfg(feature = "test-mode")]
pub fn load_dev_recovery_code<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
) -> Result<Vec<u8>, StorageError> {
    storage.backend().read_raw(DEV_RECOVERY_CODE_NVS_KEY)
}

/// Destroys the DEV recovery-code cache blob. Idempotent (absent = `Ok`).
///
/// Compiled ONLY under `test-mode`. Wipe/factory paths MUST call this (via
/// `destroy_recovery_envelope`): a lingering code blob would resurrect wiped
/// credentials through the DEV auto-recover path.
#[cfg(feature = "test-mode")]
pub fn delete_dev_recovery_code<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
) -> Result<(), StorageError> {
    match storage.backend_mut().delete_raw(DEV_RECOVERY_CODE_NVS_KEY) {
        Ok(()) | Err(StorageError::KeyNotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Teto por slot dos namespaces com orçamento (OATH/vault: TLV total <=512B).
pub const NAMESPACED_SLOT_MAX_BYTES: usize = 512;

/// Falha tipada do `NamespacedStore` (sem panics, sem stringly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespacedStoreError {
    /// Label fora do gate do namespace.
    BadLabel,
    /// Blob acima do orçamento do slot.
    TooLarge,
    /// Quota `max_slots` do índice já atingida por labels distintos.
    QuotaExceeded,
    /// Slot ausente.
    NotFound,
    /// Falha de storage, mismatch de verify-after-write ou índice corrupto.
    Storage,
}

impl core::fmt::Display for NamespacedStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadLabel => write!(f, "bad namespaced label"),
            Self::TooLarge => write!(f, "namespaced blob too large"),
            Self::QuotaExceeded => write!(f, "namespaced quota exceeded"),
            Self::NotFound => write!(f, "namespaced slot not found"),
            Self::Storage => write!(f, "namespaced storage failure"),
        }
    }
}

impl From<StorageError> for NamespacedStoreError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::KeyNotFound => Self::NotFound,
            _ => Self::Storage,
        }
    }
}

/// Config estática de um namespace sobre `SecureStorage`.
///
/// - `prefix`: prefixo NVS (`"oath6/"`, `"vault/"`, `""` p/ registros crus).
/// - `max_bytes`: `Some` = orçamento por slot; `None` = só o teto do
///   envelope (`MAX_PLAINTEXT_BYTES`, fail-closed no `store`).
/// - `quota_index_key`: `Some` = quota via lista CBOR cifrada (fail-closed);
///   `None` = sem quota.
/// - `delete_absent_ok`: PIV-compat (delete idempotente); OATH/vault negam.
/// - `strict_index_reads`: com quota, leituras também exigem índice íntegro.
/// - `validate`: gate do label (1..32B, reserva de `"index"`, ou sempre-ok).
#[derive(Debug, Clone, Copy)]
pub struct NamespacedStore {
    /// Prefixo NVS anteposto ao label.
    pub prefix: &'static str,
    /// Orçamento por slot (`None` = só o teto do envelope).
    pub max_bytes: Option<usize>,
    /// Chave do índice CBOR de quota (`None` = sem quota).
    pub quota_index_key: Option<&'static str>,
    /// Máximo de labels distintos (só com quota).
    pub max_slots: usize,
    /// Delete em ausente = ok (PIV) em vez de `NotFound`.
    pub delete_absent_ok: bool,
    /// Com quota, get/delete exigem índice íntegro antes de tudo.
    pub strict_index_reads: bool,
    /// Gate do label.
    pub validate: fn(&str) -> bool,
}

impl NamespacedStore {
    /// Chave NVS `prefix + label` (label já validado pelo chamador).
    pub fn key(&self, label: &str) -> String {
        let mut s = String::from(self.prefix);
        s.push_str(label);
        s
    }

    /// Gate do label do namespace.
    fn check_label(&self, label: &str) -> Result<(), NamespacedStoreError> {
        if (self.validate)(label) {
            Ok(())
        } else {
            Err(NamespacedStoreError::BadLabel)
        }
    }

    /// Grava o slot com verify-after-write; label novo consome quota.
    pub fn put<B: FlashStorageBackend>(
        &self,
        storage: &mut SecureStorage<B>,
        label: &str,
        blob: &[u8],
    ) -> Result<(), NamespacedStoreError> {
        self.put_impl(storage, label, blob, true)
    }

    /// Como `put`, mas mismatch de verify NAO apaga o slot (mantem o valor
    /// antigo legivel; chamador nao deve emitir nada derivado em `Storage`).
    ///
    /// Para contadores monotonicos (HOTP `next`): apagar no torn write
    /// resetaria o contador (replay). Credenciais usam `put` (apaga o slot).
    pub fn put_keep_on_mismatch<B: FlashStorageBackend>(
        &self,
        storage: &mut SecureStorage<B>,
        label: &str,
        blob: &[u8],
    ) -> Result<(), NamespacedStoreError> {
        self.put_impl(storage, label, blob, false)
    }

    /// Núcleo do `put`/`put_keep_on_mismatch`.
    fn put_impl<B: FlashStorageBackend>(
        &self,
        storage: &mut SecureStorage<B>,
        label: &str,
        blob: &[u8],
        delete_on_mismatch: bool,
    ) -> Result<(), NamespacedStoreError> {
        self.check_label(label)?;
        if let Some(max) = self.max_bytes {
            if blob.len() > max {
                return Err(NamespacedStoreError::TooLarge);
            }
        }
        let mut index = self.load_index_opt(storage)?;
        let known = index.iter().any(|l| l.as_str() == label);
        if !known && self.quota_index_key.is_some() && index.len() >= self.max_slots {
            return Err(NamespacedStoreError::QuotaExceeded);
        }
        let key = self.key(label);
        storage.store(&key, blob, &[0u8; 12])?;
        let mut back = storage.load(&key)?;
        let ok = back.as_slice() == blob;
        back.zeroize();
        if !ok {
            if delete_on_mismatch {
                let _ = storage.delete(&key);
            }
            return Err(NamespacedStoreError::Storage);
        }
        if !known && self.quota_index_key.is_some() {
            index.push(String::from(label));
            if self.save_index(storage, &index).is_err() {
                let _ = storage.delete(&key);
                return Err(NamespacedStoreError::Storage);
            }
        }
        Ok(())
    }

    /// Lê o slot (com quota estrita, índice corrupto nega até a leitura).
    pub fn get<B: FlashStorageBackend>(
        &self,
        storage: &SecureStorage<B>,
        label: &str,
    ) -> Result<Vec<u8>, NamespacedStoreError> {
        self.check_label(label)?;
        if self.strict_index_reads && self.quota_index_key.is_some() {
            let _ = self.load_index_opt(storage)?;
        }
        Ok(storage.load(&self.key(label))?)
    }

    /// Apaga o slot e libera a quota; ausente conforme `delete_absent_ok`.
    ///
    /// Fail-closed: com quota estrita o índice é carregado antes do
    /// `exists`, então índice corrupto responde `Storage`, nunca `NotFound`.
    pub fn delete<B: FlashStorageBackend>(
        &self,
        storage: &mut SecureStorage<B>,
        label: &str,
    ) -> Result<(), NamespacedStoreError> {
        self.check_label(label)?;
        let mut index = if self.strict_index_reads {
            self.load_index_opt(storage)?
        } else {
            Vec::new()
        };
        let key = self.key(label);
        if !storage.exists(&key) {
            if self.delete_absent_ok {
                return Ok(());
            }
            return Err(NamespacedStoreError::NotFound);
        }
        storage.delete(&key)?;
        if self.quota_index_key.is_some() {
            if !self.strict_index_reads {
                index = self.load_index_opt(storage)?;
            }
            index.retain(|l| l.as_str() != label);
            self.save_index(storage, &index)?;
        }
        Ok(())
    }

    /// Une labels ao índice de quota (migração: sem truncar, sem checar
    /// quota — a união pode exceder `max_slots`; puts futuros fecham).
    pub fn index_union_add<B: FlashStorageBackend>(
        &self,
        storage: &mut SecureStorage<B>,
        new_labels: &[String],
    ) -> Result<(), NamespacedStoreError> {
        if self.quota_index_key.is_none() {
            return Err(NamespacedStoreError::Storage);
        }
        for label in new_labels {
            self.check_label(label)?;
        }
        let mut index = self.load_index_opt(storage)?;
        for label in new_labels {
            if !index.iter().any(|l| l == label) {
                index.push(label.clone());
            }
        }
        self.save_index(storage, &index)
    }

    /// Índice de quota (`None` = lista vazia, sem acesso ao storage).
    fn load_index_opt<B: FlashStorageBackend>(
        &self,
        storage: &SecureStorage<B>,
    ) -> Result<Vec<String>, NamespacedStoreError> {
        match self.quota_index_key {
            None => Ok(Vec::new()),
            Some(index_key) => {
                let mut bytes = match storage.load(index_key) {
                    Ok(b) => b,
                    Err(StorageError::KeyNotFound) => return Ok(Vec::new()),
                    Err(_) => return Err(NamespacedStoreError::Storage),
                };
                let res = decode_ns_index(&bytes);
                bytes.zeroize();
                res
            }
        }
    }

    /// Grava o índice com verify-after-write.
    ///
    /// Fail-closed (M2): em mismatch de verify o índice NUNCA é apagado
    /// (apagar resetaria a quota e falharia aberto); o chamador desfaz só
    /// o próprio slot de dados.
    fn save_index<B: FlashStorageBackend>(
        &self,
        storage: &mut SecureStorage<B>,
        labels: &[String],
    ) -> Result<(), NamespacedStoreError> {
        let index_key = self.quota_index_key.ok_or(NamespacedStoreError::Storage)?;
        let mut plain = encode_ns_index(labels)?;
        let res = (|| -> Result<(), NamespacedStoreError> {
            storage.store(index_key, &plain, &[0u8; 12])?;
            let mut back = storage.load(index_key)?;
            let ok = back.as_slice() == plain.as_slice();
            back.zeroize();
            if !ok {
                return Err(NamespacedStoreError::Storage);
            }
            Ok(())
        })();
        plain.zeroize();
        res
    }
}

/// Codifica labels como array CBOR de texto (plaintext do índice de quota).
fn encode_ns_index(labels: &[String]) -> Result<Vec<u8>, NamespacedStoreError> {
    let items: Vec<Value> = labels.iter().map(|s| Value::Text(s.clone())).collect();
    let mut buf = Vec::new();
    ciborium::into_writer(&Value::Array(items), &mut buf)
        .map_err(|_| NamespacedStoreError::Storage)?;
    Ok(buf)
}

/// Decodifica array CBOR de texto em labels (lixo = `Storage`, fail-closed).
fn decode_ns_index(bytes: &[u8]) -> Result<Vec<String>, NamespacedStoreError> {
    let value: Value = ciborium::from_reader(bytes).map_err(|_| NamespacedStoreError::Storage)?;
    match value {
        Value::Array(items) => items
            .into_iter()
            .map(|item| match item {
                Value::Text(s) => Ok(s),
                _ => Err(NamespacedStoreError::Storage),
            })
            .collect(),
        _ => Err(NamespacedStoreError::Storage),
    }
}

// OTA canonico em ota_store (corte auditoria): main.rs importa de la direto;
// persistence NAO reexporta OTA.

/// CI-GREP: MOCK-ONLY-IN-TEST — Mock* test-only; prod uses PlatformFlashBackend.
/// In-memory storage backend for unit testing and host simulation.
/// Ausente no device (`target_os = "espidf"` sem `cfg(test)`): prod usa NVS.
#[cfg(any(test, not(target_os = "espidf")))]
#[derive(Debug, Clone, Default)]
pub struct MockFlashBackend {
    store: std::collections::HashMap<String, Vec<u8>>,
}

/// Backend de plataforma: NVS real no device, RAM no host.
/// (Nome antigo `RamFlashBackend` removido: mentia no device.)
pub type PlatformFlashBackend = crate::nvs_backend::PlatformFlashBackend;

#[cfg(any(test, not(target_os = "espidf")))]
impl MockFlashBackend {
    pub fn new() -> Self {
        Self {
            store: std::collections::HashMap::new(),
        }
    }
}

#[cfg(any(test, not(target_os = "espidf")))]
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

#[cfg(any(test, not(target_os = "espidf")))]
trait OptionExt<T> {
    fn ok_to_end(self, err: StorageError) -> Result<T, StorageError>;
}

#[cfg(any(test, not(target_os = "espidf")))]
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

        let nonce = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
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
            storage
                .store("pin_hash", b"my_secure_pin_salt_hash", &nonce)
                .unwrap();
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
        let ignored = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
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

    /// Regressão do hang de boot (main com ~116 B livres): o frame de
    /// `store_with_rng` + as maiores structs de boot ficam abaixo do teto de
    /// 8 KiB, e o `store` no teto (`MAX_PLAINTEXT_BYTES`) funciona via Mock.
    /// Nada aqui depende de device (host-only, `MockFlashBackend`).
    #[test]
    fn boot_stack_budget_store_heap_e_teto() {
        // Teto documentado: 8 KiB p/ todo o caminho de `store` no boot.
        const BOOT_STACK_BUDGET_BYTES: usize = 8 * 1024;
        // O teto antigo `<= 1024` estava errado diante do `MAX_PLAINTEXT_BYTES`
        // de 4096 (envelope máx 4129 B, provado no device T13): o invariante
        // correto é o envelope caber no `NVS_READ_MAX` (8192), não em 1 KiB.
        // Se o plaintext crescer de novo, este teste quebra antes da placa
        // travar — sem rebaixar o teto funcional.
        const { assert!(MAX_ENVELOPE_BYTES < crate::nvs_backend::NVS_READ_MAX) };
        assert!(
            core::mem::size_of::<SecureStorage<MockFlashBackend>>() < 2048,
            "SecureStorage grande demais p/ stack crítica do boot"
        );
        assert!(
            MAX_ENVELOPE_BYTES + core::mem::size_of::<SecureStorage<MockFlashBackend>>()
                < BOOT_STACK_BUDGET_BYTES,
            "orçamento de stack do boot excedido"
        );
        // Roundtrip no teto atual (4096 B): prova que o caminho heap cobre o
        // pior caso real sem tocar na stack da main.
        let master_key = [0x55u8; 32];
        let salt = [0xAAu8; 32];
        let backend = MockFlashBackend::new();
        let mut storage = SecureStorage::new(backend, &master_key, &salt);
        let ignored = [0x00u8; 12];
        let max = vec![0x41u8; MAX_PLAINTEXT_BYTES];
        storage.store("boot_ceiling", &max, &ignored).unwrap();
        assert_eq!(storage.load("boot_ceiling").unwrap(), max);
    }
    /// Teto funcional auditado: 3 B de header + 32 slots × (21 B fixos +
    /// label ≤32 + segredo ≤66, maior curva P-521/ES512) = 3811 ≤ 4096
    /// (margem 285 B); envelope máx 4129 B < `NVS_READ_MAX` 8192.
    /// FALHARIA com o teto antigo de 512 B (3811 > 512); o fail-closed
    /// acima do teto segue coberto por `test_max_esp_overflow`.
    #[test]
    fn teto_cobre_pior_caso_32_slots() {
        const PIOR_CASO_BYTES: usize = 3 + 32 * (21 + 32 + 66);
        const { assert!(PIOR_CASO_BYTES == 3811) };
        const { assert!(PIOR_CASO_BYTES <= MAX_PLAINTEXT_BYTES) };
        const { assert!(MAX_ENVELOPE_BYTES < crate::nvs_backend::NVS_READ_MAX) };
        // Roundtrip opaco de 3811 B (pior caso real) via Mock.
        let master_key = [0x55u8; 32];
        let salt = [0xAAu8; 32];
        let backend = MockFlashBackend::new();
        let mut storage = SecureStorage::new(backend, &master_key, &salt);
        let ignored = [0x00u8; 12];
        let max = vec![0x42u8; PIOR_CASO_BYTES];
        storage.store("pior_caso_32_slots", &max, &ignored).unwrap();
        assert_eq!(storage.load("pior_caso_32_slots").unwrap(), max);
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
