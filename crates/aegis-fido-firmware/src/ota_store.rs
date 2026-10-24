//! OTA flash staging + dispatch (`ota_*` keys, `OP_OTA_*`).
//!
//! Extracted verbatim from `nvs_backend` (modulos-novos): `nvs_backend` keeps
//! only `PlatformFlashBackend`; this module owns the flash staging
//! (`FlashOtaSink`, chunked `ota_cNNNNNN` + `ota_stage_len`), the CTAPHID
//! vendor dispatch (`dispatch_ota_request`, `OtaRequestCtx`), the wire gates
//! (`is_ota_op`, `verify_ota_signature`, `OTA_STATUS_*`) and the NVS
//! preservation helpers (`snapshot_keys`, `keys_unchanged`).
//!
//! Semantics preserved (R15/R16, COMMS-map S9): fail-closed on every branch,
//! no false success; only `ota_*` keys are ever created, modified or deleted.
//! `nvs_backend` re-exporta daqui p/ compat externa; `main.rs` importa `ota_store`
//! direto (`persistence` NAO reexporta OTA - cadeia colapsada).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::ota::{
    OtaError, OtaKeyProvider, OtaManifest, OtaProvider, OtaSink, MAX_OTA_IMAGE_BYTES, OP_OTA_ABORT,
    OP_OTA_BEGIN, OP_OTA_CHUNK, OP_OTA_COMMIT, OP_OTA_FINISH, OTA_MANIFEST_LEN,
};
use crate::persistence::{FlashStorageBackend, StorageError};
use ed25519_dalek::{Signature, VerifyingKey};

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
/// Teto efetivo do staging na partição `storage` (896 KiB) — fail-closed.
///
/// R14: o staging vive em flash NVS real (partição `storage`
/// compartilhada, 896 KiB), nunca em RAM de imagem; o teto de protocolo
/// (2 MiB, `MAX_OTA_IMAGE_BYTES` em `ota`) continua valendo no fio, mas o
/// sink nega (`Overflow` + rollback, sem sucesso falso) qualquer byte além
/// deste teto. `BEGIN` com manifesto acima do teto falha rápido antes de
/// abrir sessão; o sink reforça por chunk (defesa em profundidade).
pub const OTA_STORAGE_BUDGET_BYTES: usize = 896 * 1024;
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
        // Teto duplo fail-closed: protocolo (2 MiB) + flash real `storage`
        // (896 KiB, `OTA_STORAGE_BUDGET_BYTES`). O menor vence; estourar
        // nega `Overflow` e o dispatcher desfaz o staging (sem sucesso falso).
        if end > MAX_OTA_IMAGE_BYTES || end > OTA_STORAGE_BUDGET_BYTES {
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

fn ota_fail<P: OtaProvider, B: FlashStorageBackend>(
    state: &mut P,
    sink: &mut FlashOtaSink<B>,
) -> (u8, Vec<u8>) {
    state.rollback();
    sink.discard();
    (OTA_STATUS_FAIL, Vec::new())
}

/// Pure CTAPHID vendor dispatch for `OP_OTA_*` (`None` = unknown opcode, caller ignores).
///
/// Fase 2 (SOLID/DIP): generic over [`OtaProvider`] — the dispatcher never
/// names [`crate::ota::OtaState`]; callers pass `&mut OtaState` unchanged.
/// R14: USB and serial build the identical [`OtaRequestCtx`] in `main.rs` and
/// share this exact function, so every gate below applies equally on both
/// transports (serial nega sem vínculo fail-closed por construção, sem
/// ramo próprio na serial).
///
/// BEGIN requires a provisioned device and a manifest within the 896 KiB
/// `storage` budget (fail-fast); CHUNK carries `offset BE u32 || data`;
/// FINISH denies a denied (all-zeros) key before verifying, then verifies the
/// staged manifest with the real release pubkey via the `verify_with` seam;
/// COMMIT denies a denied key before anything, then requires the physical UP
/// latch (checked here, consumed by the caller) and records the commit
/// marker — NUNCA COMMIT sem chave válida (fail-closed documentado);
/// ABORT rolls back. Any `OtaError` rolls the session back to `Idle` and
/// discards staging, preserving NVS — except COMMIT-without-UP, which keeps
/// the verified session so the host can re-send after the user taps BOOT
/// (serial NeedUp parity).
pub fn dispatch_ota_request<P: OtaProvider, B: FlashStorageBackend>(
    state: &mut P,
    sink: &mut FlashOtaSink<B>,
    op: u8,
    payload: &[u8],
    ctx: &OtaRequestCtx,
) -> Option<(u8, Vec<u8>)> {
    if !is_ota_op(op) {
        return None;
    }
    // Provision gate on every mutating op (ABORT is always-allowed cleanup):
    // an unprovisioned device (no factory eFuse BLOCK7/BLOCK8, R-06) denies
    // before any byte is staged or verified, on USB and serial alike.
    if !ctx.provisioned && op != OP_OTA_ABORT {
        return Some(ota_fail(state, sink));
    }
    match op {
        OP_OTA_BEGIN => {
            sink.discard();
            // Storage fail-fast: manifests declaring more than the real
            // `storage` partition holds never open a session (the sink
            // re-enforces per chunk; defense in depth, no false success).
            let over_budget = OtaManifest::parse(payload)
                .map(|m| m.size as usize > OTA_STORAGE_BUDGET_BYTES)
                .unwrap_or(false);
            if over_budget {
                return Some(ota_fail(state, sink));
            }
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
            // NUNCA verifica contra chave negada: zeros fail-closed antes de
            // qualquer Ed25519 (o `verify_with` abaixo negaria de todo modo;
            // este guarda documenta a invariante e falha rápido).
            if OtaKeyProvider::is_denied(&ctx.ota_pubkey) {
                return Some(ota_fail(state, sink));
            }
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
            // NUNCA COMMIT sem chave válida: mesmo uma sessão `Verified`
            // não comita sob chave negada (rollback + FAIL, sem marcador).
            if OtaKeyProvider::is_denied(&ctx.ota_pubkey) {
                return Some(ota_fail(state, sink));
            }
            if P::requires_up() && !ctx.up {
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
    use crate::persistence::{MockFlashBackend, SecureStorage};
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
    fn ota_begin_rejects_manifest_over_storage_budget() {
        // Fail-fast: manifesto dentro do teto de protocolo (2 MiB) mas acima
        // do flash real `storage` (896 KiB) nunca abre sessão.
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ota_image();
        let mut raw = manifest_raw(OTA_NEXT, &image, &[0x5Eu8; 64]);
        let over = (OTA_STORAGE_BUDGET_BYTES as u32) + 1;
        assert!(over < MAX_OTA_IMAGE_BYTES as u32);
        raw[4..8].copy_from_slice(&over.to_be_bytes());
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, [0x11u8; 32]);
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_BEGIN, &raw, &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.exists_staging());
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_unprovisioned_denies_every_op_serial_parity() {
        // Paridade serial/USB: os dois transportes montam o mesmo ctx em
        // `main.rs` e dividem este dispatch, logo o dispositivo sem vínculo
        // de fábrica (não provisionado, R-02/R-06) nega em todo op
        // mutante — serial nega sem vínculo, fail-closed. ABORT segue OK
        // (limpeza idempotente nunca nega).
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ota_image();
        let raw = manifest_raw(OTA_NEXT, &image, &[0x5Eu8; 64]);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(false, true, [0x11u8; 32]);
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_BEGIN, &raw, &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            let p = chunk_payload(0, &image[..64]);
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_CHUNK, &p, &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_FINISH, &[], &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_COMMIT, &[], &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.exists_staging());
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_ABORT, &[], &ctx),
                Some((OTA_STATUS_OK, Vec::new()))
            );
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_finish_and_commit_deny_denied_key() {
        // NUNCA COMMIT/verify sem chave válida: staging sob chave real,
        // FINISH/COMMIT sob zeros negam + rollback, sem marcador, NVS intacta.
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ota_image();
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let manifest = signed_manifest(OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(OTA_CURRENT);
        let real = req_ctx(true, true, sk.verifying_key().to_bytes());
        let denied = req_ctx(true, true, OtaKeyProvider::RELEASE_PUBKEY);
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            let stage = |ota: &mut OtaState,
                         sink: &mut FlashOtaSink<'_, MockFlashBackend>,
                         ctx: &OtaRequestCtx| {
                assert_eq!(
                    dispatch_ota_request(ota, sink, OP_OTA_BEGIN, &manifest, ctx),
                    Some((OTA_STATUS_OK, Vec::new()))
                );
                let mut off = 0u32;
                for chunk in image.chunks(256) {
                    let p = chunk_payload(off, chunk);
                    assert_eq!(
                        dispatch_ota_request(ota, sink, OP_OTA_CHUNK, &p, ctx).map(|r| r.0),
                        Some(OTA_STATUS_OK)
                    );
                    off += chunk.len() as u32;
                }
            };
            stage(&mut ota, &mut sink, &real);
            // FINISH sob zeros: FAIL + rollback, mesmo com imagem íntegra.
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_FINISH, &[], &denied),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.exists_staging());
            // Re-estagia, verifica sob chave real...
            stage(&mut ota, &mut sink, &real);
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_FINISH, &[], &real),
                Some((OTA_STATUS_OK, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Verified);
            // ...mas COMMIT sob zeros: FAIL + rollback, sem marcador.
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_COMMIT, &[], &denied),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.has_commit_marker());
            assert_eq!(sink.committed_marker(), None);
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_sink_enforces_storage_budget_standalone() {
        // O sink sozinho nega além de 896 KiB (defesa em profundidade além
        // do fail-fast do BEGIN): preenche exatamente até o teto com chunks
        // NVS de 8 KiB e prova que o próximo byte nega `Overflow`.
        let mut backend = MockFlashBackend::new();
        let full = vec![0xA5u8; OTA_CHUNK_LEN];
        let mut sink = FlashOtaSink::new(&mut backend);
        let mut written = 0usize;
        while written < OTA_STORAGE_BUDGET_BYTES {
            sink.write_chunk(written, &full).expect("in-budget chunk");
            written += OTA_CHUNK_LEN;
        }
        assert_eq!(written, OTA_STORAGE_BUDGET_BYTES);
        assert_eq!(sink.write_chunk(written, &[0x01]), Err(OtaError::Overflow));
        assert!(backend.exists(&chunk_key(0)));
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
