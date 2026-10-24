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

use crate::ota::{
    OtaError, OtaManifest, OtaSink, OtaState, MAX_OTA_IMAGE_BYTES, OP_OTA_ABORT, OP_OTA_BEGIN,
    OP_OTA_CHUNK, OP_OTA_COMMIT, OP_OTA_FINISH, OTA_MANIFEST_LEN,
};
#[cfg(any(test, not(target_os = "espidf")))]
use crate::persistence::MockFlashBackend;
use crate::persistence::{FlashStorageBackend, StorageError};
use alloc::string::String;
use ed25519_dalek::{Signature, VerifyingKey};

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
    /// Abre o NVS (`namespace "aegis"`); falha → RAM com aviso do chamador.
    pub fn new() -> Self {
        #[cfg(target_os = "espidf")]
        {
            match Self::open_nvs() {
                Ok(nvs) => return Self::Nvs(nvs),
                // Fail-operational no host/teste: sem NVS, RAM (sem persistência).
                // O chamador loga via kprintln (aqui sem acesso a ele).
                #[cfg(any(test, not(target_os = "espidf")))]
                Err(e) => {
                    let _ = e;
                    return Self::Ram(MockFlashBackend::new());
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
    use rand_core::RngCore;

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
    let mut rng = rand_core::OsRng;
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

// T5 (modular-solid-atomic): staging OTA sobre flash cru (`ota_*` keys).
//
// Movido de `persistence` p/ quebrar a inversão `persistence -> ota`:
// `OtaSink` (trait) vive em `ota`; aqui só a implementação sobre o backend
// cru + `dispatch_ota_request` (máquina `OtaState` via trait, sem envelopes
// `SecureStorage` — imagem nunca caberia num envelope). Casa canônica futura:
// `ota` (fora do escopo desta lane); `persistence` reexporta p/ compat.

// Wave OTA wiring (Step 4, traces R-04/R-06; F5 chunked NVS staging).
//
// Staging lives under raw `ota_*` flash keys — NEVER through `SecureStorage`
// envelopes (a firmware image can never fit a single `MAX_PLAINTEXT_BYTES`
// envelope, and credential/OATH NVS keys must stay
// byte-identical across commit and rollback). Rollback on any failure
// preserves NVS: only `ota_*` keys are ever created, modified, or deleted.
// F5: o blob único virou família chunked (`ota_stage_len` + `ota_cNNNNNN`
// de 8 KiB) — NVS não aguenta blob de 2 MiB; o layout é transparente p/
// `dispatch_ota_request` e testes.

/// Raw flash key holding the staged image bytes (append-only during `Staged`).
///
/// Legado F4-: blob único. F5+: só leitura de compat (migra p/ chunked no
/// primeiro append). Novo código NUNCA escreve aqui.
pub const OTA_STAGING_KEY: &str = "ota_staging";
/// Total de bytes stageados (u32 BE) — fonte da verdade F5+.
pub const OTA_STAGE_LEN_KEY: &str = "ota_stage_len";
/// Prefixo das chaves de chunk (`ota_c` + 6 dígitos, 8 KiB cada).
pub const OTA_CHUNK_PREFIX: &str = "ota_c";
/// Tamanho de cada chunk NVS (cabe folgado no blob NVS).
pub const OTA_CHUNK_LEN: usize = 8192;
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
/// `ota_stage_len`, `ota_cNNNNNN`, `OTA_MANIFEST_KEY`, or
/// `OTA_COMMIT_MARKER_KEY` (legado `OTA_STAGING_KEY` só leitura p/ migração).
/// Appends in-order contra `len`; chunks de 8 KiB (NVS-safe).
pub struct FlashOtaSink<'a, B: FlashStorageBackend> {
    backend: &'a mut B,
    len: usize,
    finalized: bool,
}

fn chunk_key(index: usize) -> String {
    // "ota_c" + 6 dígitos (sempre ≤15 chars p/ NVS).
    format!("ota_c{:06}", index % 1_000_000)
}

fn read_len(backend: &impl FlashStorageBackend) -> usize {
    match backend.read_raw(OTA_STAGE_LEN_KEY) {
        Ok(v) if v.len() == 4 => u32::from_be_bytes([v[0], v[1], v[2], v[3]]) as usize,
        _ => {
            // Migração: blob único legado vira len (conteúdo migrado no
            // primeiro append; descarte limpa os dois formatos).
            backend
                .read_raw(OTA_STAGING_KEY)
                .map(|v| v.len())
                .unwrap_or(0)
        }
    }
}

impl<'a, B: FlashStorageBackend> FlashOtaSink<'a, B> {
    /// Opens the staging area, resuming `len` from any previously staged bytes.
    pub fn new(backend: &'a mut B) -> Self {
        let len = read_len(backend);
        Self {
            backend,
            len,
            finalized: false,
        }
    }

    /// Discards staged image + manifest (rollback); keeps the commit marker
    /// and every non-`ota_*` key untouched. Limpa os dois formatos (chunked F5+
    /// e blob legado), para nunca deixar lixo atrás.
    pub fn discard(&mut self) {
        let chunks = self.len.div_ceil(OTA_CHUNK_LEN).max(
            self.backend
                .read_raw(OTA_STAGING_KEY)
                .map(|v| v.len().div_ceil(OTA_CHUNK_LEN))
                .unwrap_or(0),
        );
        for i in 0..chunks {
            let _ = self.backend.delete_raw(&chunk_key(i));
        }
        let _ = self.backend.delete_raw(OTA_STAGE_LEN_KEY);
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
        self.len > 0
    }
}

impl<'a, B: FlashStorageBackend> FlashOtaSink<'a, B> {
    /// Anexa bytes na posição absoluta `pos` (tail read-modify-write +
    /// chunks cheios). Não toca em `self.len` (chamador gerencia).
    fn append_at(&mut self, mut pos: usize, mut data: &[u8]) -> Result<(), OtaError> {
        while !data.is_empty() {
            let idx = pos / OTA_CHUNK_LEN;
            let off = pos % OTA_CHUNK_LEN;
            let take = (OTA_CHUNK_LEN - off).min(data.len());
            let key = chunk_key(idx);
            let mut chunk = match self.backend.read_raw(&key) {
                Ok(v) => v,
                Err(StorageError::KeyNotFound) => Vec::new(),
                Err(_) => return Err(OtaError::Overflow),
            };
            if chunk.len() != off {
                return Err(OtaError::Overflow);
            }
            chunk.extend_from_slice(&data[..take]);
            self.backend
                .write_raw(&key, &chunk)
                .map_err(|_| OtaError::Overflow)?;
            pos += take;
            data = &data[take..];
        }
        Ok(())
    }
}

impl<B: FlashStorageBackend> OtaSink for FlashOtaSink<'_, B> {
    fn write_chunk(&mut self, offset: usize, data: &[u8]) -> Result<(), OtaError> {
        if self.finalized || offset != self.len {
            return Err(OtaError::OutOfOrder);
        }
        let end = self.len.checked_add(data.len()).ok_or(OtaError::Overflow)?;
        if end > MAX_OTA_IMAGE_BYTES {
            return Err(OtaError::Overflow);
        }
        // Migração preguiçosa: boot com blob legado espalha o conteúdo nos
        // chunks uma vez (len acompanha; descarte limpa os dois formatos).
        if self.len == 0 {
            if let Ok(legacy) = self.backend.read_raw(OTA_STAGING_KEY) {
                if !legacy.is_empty() {
                    self.append_at(0, &legacy)?;
                    self.len = legacy.len();
                }
            }
        }
        self.append_at(self.len, data)?;
        self.len = end;
        self.backend
            .write_raw(OTA_STAGE_LEN_KEY, &(end as u32).to_be_bytes())
            .map_err(|_| OtaError::Overflow)?;
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), OtaError> {
        if self.finalized || self.len == 0 {
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
        OtaManifest, OtaPhase, OtaState, OP_OTA_ABORT, OP_OTA_BEGIN, OP_OTA_CHUNK, OP_OTA_COMMIT,
        OP_OTA_FINISH, OTA_MANIFEST_LEN,
    };
    use crate::persistence::SecureStorage;
    use ed25519_dalek::SigningKey;
    use sha2::Digest as _;
    use sha2::Sha256;
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
        let mut storage = SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32]);
        let nonce = [0x00u8; 12];
        storage
            .store("credential_01", b"passkey-bytes", &nonce)
            .unwrap();
        storage
            .store("oath_secret_02", b"oath-seed", &nonce)
            .unwrap();
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
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, op, &[], &ctx),
                None
            );
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
    fn ota_multichunk_staging_acima_de_8k() {
        // F5: imagem de 20 KiB atravessa 3 chunks NVS e verifica ponta a ponta.
        let mut storage = credentialed_storage();
        let image: Vec<u8> = (0..20 * 1024).map(|i| (i % 251) as u8).collect();
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let manifest = signed_manifest(OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, sk.verifying_key().to_bytes());
        let staged_len = {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            stage_to_verified(&mut ota, &mut sink, &manifest, &image, &ctx);
            assert_eq!(ota.received(), image.len());
            sink.len
        };
        // Chunks reais no backend (nenhum blob único gigante).
        assert!(storage.backend().exists("ota_c000000"));
        assert!(storage.backend().exists("ota_c000001"));
        assert!(storage.backend().exists("ota_c000002"));
        assert!(!storage.backend().exists("ota_staging"));
        // Reabre o sink (resume pelo len) e confirma NVS intacto.
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let staged_len2 = {
            let sink2 = FlashOtaSink::new(storage.backend_mut());
            sink2.len
        };
        assert_eq!(staged_len2, staged_len);
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
                let st =
                    dispatch_ota_request(&mut ota, &mut sink, OP_OTA_CHUNK, &p, &ctx).map(|r| r.0);
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
