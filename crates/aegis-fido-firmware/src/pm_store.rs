//! F-PM1 firmware side - NVS-backed opaque PM blob store (DIP persistence).
//!
//! - SRP: this module persists **opaque AEAD blobs only** (never policy,
//!   never record shapes). Quota/gates/record types live in `aegis-pm-vault`
//!   (`PmPolicy`/`PmGateState`/`PmVault`); the phone is a blind transport.
//! - Slots: single canonical blob at `vault-pm/blob` (prefix `vault-pm/`,
//!   disjoint from FIDO2 `vault/` + OATH `oath6/` + `key_slots_v1` -
//!   **no migration of FIDO2/OATH**, scoped wipe preserves them).
//! - AEAD: sem cripto nova - ponto unico `NamespacedStore` (T5) sobre o
//!   envelope AEGN v1 do `SecureStorage` (nonce TRNG dentro do `store`,
//!   verify-after-write no save, decrypt autenticado no load), o mesmo de
//!   `oath_store`/`vault_store`. Sem KDF, sem eFuse/Secure Boot/
//!   flash-encryption (REGRA PRINCIPAL N1: este arquivo nao tem call site
//!   de `efuse`/`burn`/BLOCK7).
//! - Gates (binding -> UP -> PIN -> 60 s window) live in [`authorize_pm_op`],
//!   reusing the frozen BLE vocabulary (`NeedBinding`/`PresenceRequired`/
//!   `PinRequired` from `ble::gatt_core`; window expiry closes fail-closed
//!   as `PresenceRequired`, walk-away closes the viewer).
//! - OLED confirm is **code-only** ([`render_pm_confirm`]): a generic
//!   `PM RELEASE` + `[TOUCH CONFIRM]` frame. It takes **no secret input**
//!   (no label/user/password/share parameter exists), so nothing sensitive
//!   can reach the display or the logs. Physical presence comes from the
//!   existing GPIO 0 BOOT button (`BootButton`, active-low); this module
//!   only consumes the resulting `presence_confirmed` bit via the gate.
//! - `no_std`-compatible (`alloc`-only). `zeroize` after use. Fail-closed,
//!   typed errors, no panics, no `unwrap`/`expect` outside `#[cfg(test)]`.
//!
//! DIP adapter: [`NvsPmStore`] exposes the exact `PmStore` method shapes
//! (`save_blob`/`load_blob`/`wipe`) over `SecureStorage` without depending
//! on `aegis-pm-vault` here (workspace wiring stays untouched). Binding the
//! vault trait later is a one-line `impl` with no logic change.

extern crate alloc;

use alloc::vec::Vec;

use crate::ble::gatt_core::BleGattError;
use crate::oled_ssd1306_code_only::VirtualOledDisplayBuffer;
use crate::persistence::{
    FlashStorageBackend, NamespacedStore, NamespacedStoreError, SecureStorage, StorageError,
};

/// NVS prefix owned by the password manager (disjoint from `vault/`,
/// `oath6/`, `key_slots_v1`, ... - scoped wipe never touches those).
pub const PM_STORE_PREFIX: &str = "vault-pm/";
/// Canonical opaque-blob slot (`vault-pm/<id>` with `id = "blob"`).
/// 13 chars, inside the ESP-IDF NVS key budget like the other short keys.
pub const PM_BLOB_NVS_KEY: &str = "vault-pm/blob";
/// Binding window in ms: releases past this age fail closed (walk-away
/// closes the viewer). Anchored in `config::PAIRING_WINDOW_MS` (os mesmos 60 s
/// das ceremonias de pareamento BLE); espelha `aegis-pm-vault`
/// `PM_BINDING_WINDOW_MS` sem depender daquele crate aqui.
pub const PM_BINDING_WINDOW_MS: u64 = crate::config::PAIRING_WINDOW_MS;
/// UP freshness window in ms: every PM op requires presence confirmed
/// within this window. All funnels deliver UP as a single-shot latch
/// consumed by the op itself (serial: `touch_latched`/`up_latched` cleared
/// on dispatch; BLE: latch cleared when the complete message is taken),
/// so the age observed here is always `0` on honest funnels; any caller
/// presenting a stale age fails closed with `PresenceRequired`.
/// Same 60 s anchor as [`PM_BINDING_WINDOW_MS`].
pub const PM_UP_WINDOW_MS: u64 = crate::config::PAIRING_WINDOW_MS;
/// Whole-vault sealed-blob budget: the `SecureStorage` envelope ceiling
/// (single blob holds N records, unlike 512 B per-item `vault/` slots).
pub const PM_BLOB_MAX_BYTES: usize = crate::persistence::MAX_PLAINTEXT_BYTES;

/// PM put: store (or replace) one login record (device seals on receipt).
pub const OP_PM_PUT: u8 = 0x43;
/// PM get: fetch one sealed record by opaque id (gated release).
pub const OP_PM_GET: u8 = 0x44;
/// PM list: page over opaque record ids (no labels cross the edge).
pub const OP_PM_LIST: u8 = 0x45;
/// PM delete: remove one record by opaque id.
pub const OP_PM_DELETE: u8 = 0x46;
/// PM status: entry-count / quota telemetry (no secrets).
pub const OP_PM_STATUS: u8 = 0x47;
/// First PM opcode (first free byte after BLE OOB `0x42`).
pub const PM_OP_MIN: u8 = OP_PM_PUT;
/// Last PM opcode.
pub const PM_OP_MAX: u8 = OP_PM_STATUS;

/// `true` for the PM opcode family `0x43..=0x47`.
///
/// Neighbours stay frozen: `0x20..=0x27` vendor keys/OATH, `0x28..=0x2D`
/// bind-mgmt, `0x30..=0x34` OTA, `0x35..=0x37` wallet, `0x3A..=0x3E`
/// Secure Guard, `0x3F` GET_CAPS, `0x40` SET_UP_POLICY, `0x41` VENDOR_SIGN,
/// `0x42` BLE OOB. Anything outside `0x43..=0x47` is `InvalidOpcode`
/// fail-closed here (never routed to FIDO2/OATH paths).
pub fn is_pm_op(op: u8) -> bool {
    (PM_OP_MIN..=PM_OP_MAX).contains(&op)
}

/// Snapshot of the session gates for one PM operation.
///
/// The phone is a blind transport: it carries the attestation, the device
/// decides. `bound_within_ms` is the age of the binding authorization;
/// `up_within_ms` is the age of the presence confirmation (single-shot
/// latch consumed by the op; funnels pass `0`). Releases past either
/// window fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmGateState {
    /// A bonded phone owns this session (BLE bonding / CTAPHID session).
    pub binding_bound: bool,
    /// Physical user presence confirmed (GPIO 0 BOOT + OLED summary).
    pub presence_confirmed: bool,
    /// PIN/UV authenticated for this session.
    pub pin_authenticated: bool,
    /// Milliseconds since binding authorization (walk-away timer).
    pub bound_within_ms: u64,
    /// Milliseconds since presence confirmation (fresh-UP timer).
    pub up_within_ms: u64,
}

impl PmGateState {
    /// Fully authorized session (tests / firmware after all checks).
    pub fn authorized() -> Self {
        Self {
            binding_bound: true,
            presence_confirmed: true,
            pin_authenticated: true,
            bound_within_ms: 0,
            up_within_ms: 0,
        }
    }
}

/// Gate normativo PM na ordem canonica: binding -> UP -> PIN -> janela 60 s.
///
/// - `!is_pm_op(op)` -> `InvalidOpcode` (outra familia; FIDO2/OATH intactos).
/// - `!binding_bound` -> `NeedBinding` (`0x05`, BLE-only, nunca USB).
/// - `!presence_confirmed` -> `PresenceRequired` (`0x01`, GPIO 0 + OLED).
/// - `!pin_authenticated` -> `PinRequired` (`0x02`).
/// - `bound_within_ms > 60_000` -> `PresenceRequired` (walk-away fecha o
///   viewer; reusa o vocabulario 9.5 existente, sem codigo novo no fio).
/// - `up_within_ms > 60_000` -> `PresenceRequired` (UP velho reutilizado
///   nega; todo funil entrega UP single-shot consumido pela propria op).
///
/// Sem I/O, sem alloc. Reuso de `authorize_vendor_op` por vocabulario:
/// os mesmos `BleGattError` que o transporte BLE/serial ja traduz no fio.
pub fn authorize_pm_op(op: u8, gate: &PmGateState) -> Result<(), BleGattError> {
    if !is_pm_op(op) {
        return Err(BleGattError::InvalidOpcode);
    }
    if !gate.binding_bound {
        return Err(BleGattError::NeedBinding);
    }
    if !gate.presence_confirmed {
        return Err(BleGattError::PresenceRequired);
    }
    if !gate.pin_authenticated {
        return Err(BleGattError::PinRequired);
    }
    if gate.bound_within_ms > PM_BINDING_WINDOW_MS {
        return Err(BleGattError::PresenceRequired);
    }
    if gate.up_within_ms > PM_UP_WINDOW_MS {
        return Err(BleGattError::PresenceRequired);
    }
    Ok(())
}

/// Consecutive authenticated PM failures before the backoff arms.
pub const PM_MAX_CONSEC_FAIL: u8 = 5;
/// Backoff window applied after the failure budget is spent (fail-closed
/// `0x04` on every PM op until it lapses; success resets the budget).
pub const PM_BACKOFF_MS: u64 = 30_000;

/// Per-transport backoff state for PM ops (RAM only, never persisted,
/// never logged with payloads).
///
/// Only *authenticated* failures spend the budget (`NotFound` `0x03` /
/// generic `0x04` after the gates passed: oracle de enumeracao e
/// martelamento de cofre). Gate denials (`0x01`/`0x02`/`0x05`) carry no
/// oracle and neither spend nor reset the budget; success (`0x00`)
/// resets it. No I/O, no alloc, `no_std`-compatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmRateLimiter {
    consec_fail: u8,
    backoff_until_ms: u64,
}

impl PmRateLimiter {
    /// Fresh limiter: full budget, no backoff armed.
    pub fn new() -> Self {
        Self {
            consec_fail: 0,
            backoff_until_ms: 0,
        }
    }

    /// Fail-closed during backoff: `Err(0x04)` generic wire status
    /// (vocabulario 9.5 congelado; o host trata `0x04` repetido como
    /// "aguarde 30 s e reapresente UP+PIN").
    pub fn poll(&self, now_ms: u64) -> Result<(), u8> {
        if now_ms < self.backoff_until_ms {
            return Err(0x04);
        }
        Ok(())
    }

    /// Records one authenticated outcome (`0x00` resets the budget;
    /// `0x03`/`0x04` spend one unit and arm the backoff at the budget
    /// edge; gate denials are ignored).
    pub fn record(&mut self, status: u8, now_ms: u64) {
        match status {
            0x00 => {
                self.consec_fail = 0;
            }
            0x03 | 0x04 => {
                self.consec_fail = self.consec_fail.saturating_add(1);
                if self.consec_fail >= PM_MAX_CONSEC_FAIL {
                    self.consec_fail = 0;
                    self.backoff_until_ms = now_ms.saturating_add(PM_BACKOFF_MS);
                }
            }
            _ => {}
        }
    }

    /// `true` while a backoff window is armed (diagnostics only).
    pub fn in_backoff(&self, now_ms: u64) -> bool {
        now_ms < self.backoff_until_ms
    }
}

impl Default for PmRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::ble_gatt::PmBackoffGate for PmRateLimiter {
    fn poll(&self, now_ms: u64) -> Result<(), u8> {
        PmRateLimiter::poll(self, now_ms)
    }
    fn record(&mut self, status: u8, now_ms: u64) {
        PmRateLimiter::record(self, status, now_ms)
    }
}

/// Secret-free PM audit event: opcode + wire status only.
///
/// By construction there is no payload field, so user data (labels,
/// usernames, secrets, URLs, opaque ids) can never reach logs through
/// this type. Every PM dispatch emits exactly one line via `log`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmAuditEvent {
    /// PM opcode (`0x43..=0x47`).
    pub op: u8,
    /// Wire status answered (`0x00`/`0x01`/`0x02`/`0x03`/`0x04`/`0x05`).
    pub status: u8,
}

impl core::fmt::Display for PmAuditEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "[PM-AUDIT] op=0x{:02X} st=0x{:02X}",
            self.op, self.status
        )
    }
}

/// Typed PM persistence failure (no panics, no stringly errors, no secret
/// payload in any variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmStoreError {
    /// Blob larger than [`PM_BLOB_MAX_BYTES`].
    TooLarge,
    /// Slot absent.
    NotFound,
    /// Storage failure, verify-after-write mismatch, or corrupt envelope.
    Storage,
}

impl core::fmt::Display for PmStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "pm blob too large"),
            Self::NotFound => write!(f, "pm blob not found"),
            Self::Storage => write!(f, "pm storage failure"),
        }
    }
}

impl From<StorageError> for PmStoreError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::KeyNotFound => Self::NotFound,
            _ => Self::Storage,
        }
    }
}

/// NVS key of the canonical PM blob (always [`PM_BLOB_NVS_KEY`]).
pub fn pm_blob_key() -> &'static str {
    PM_BLOB_NVS_KEY
}

/// Canonical PM label inside the `vault-pm/` namespace (single-blob
/// `PmStore` semantics: `vault-pm/<id>` with `id = "blob"`).
pub const PM_BLOB_LABEL: &str = "blob";

/// Gate do label PM como predicado do namespace (so o blob canonico).
fn pm_label_ok(label: &str) -> bool {
    label == PM_BLOB_LABEL
}

/// Maps the shared namespace failure onto the PM vocabulary (fail-closed;
/// `BadLabel`/`QuotaExceeded` sao inalcancaveis aqui - label fixo, sem quota).
fn pm_ns_err(e: NamespacedStoreError) -> PmStoreError {
    match e {
        NamespacedStoreError::TooLarge => PmStoreError::TooLarge,
        NamespacedStoreError::NotFound => PmStoreError::NotFound,
        NamespacedStoreError::BadLabel
        | NamespacedStoreError::QuotaExceeded
        | NamespacedStoreError::Storage => PmStoreError::Storage,
    }
}

/// Namespace `vault-pm/`: slot unico `blob`, teto do envelope
/// ([`PM_BLOB_MAX_BYTES`]), sem quota, delete estrito - mesmo ponto T5 de
/// `oath_store`/`vault_store` (prefixo + verify-after-write + AEGN v1).
fn pm_ns() -> NamespacedStore {
    NamespacedStore {
        prefix: PM_STORE_PREFIX,
        max_bytes: Some(PM_BLOB_MAX_BYTES),
        quota_index_key: None,
        max_slots: 0,
        delete_absent_ok: false,
        strict_index_reads: false,
        validate: pm_label_ok,
    }
}

/// Saves the opaque sealed vault blob (delega ao `NamespacedStore`
/// compartilhado: prefixo + verify-after-write, como `oath_store`).
///
/// Overwrites any previous blob (single-blob `PmStore` semantics: the vault
/// seals all records into one AEAD envelope; this layer never inspects it).
/// `TooLarge` stores nothing. Verify mismatch deletes the torn slot and
/// reports `Storage` (fail-closed; the caller keeps the RAM copy).
pub fn pm_blob_save<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    blob: &[u8],
) -> Result<(), PmStoreError> {
    pm_ns()
        .put(storage, PM_BLOB_LABEL, blob)
        .map_err(pm_ns_err)?;
    crate::ltrace!(
        crate::lifetime_trace::LifetimeCategory::Oath,
        crate::lifetime_trace::LifetimeEvent::OathPut,
        "pm-blob"
    );
    Ok(())
}

/// Loads the opaque sealed vault blob via the shared namespace
/// (envelope decrypt; absent = `NotFound`).
pub fn pm_blob_load<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
) -> Result<Vec<u8>, PmStoreError> {
    let blob = pm_ns().get(storage, PM_BLOB_LABEL).map_err(pm_ns_err)?;
    crate::ltrace!(
        crate::lifetime_trace::LifetimeCategory::Oath,
        crate::lifetime_trace::LifetimeEvent::OathCode,
        "pm-blob"
    );
    Ok(blob)
}

/// Loads the blob, or `None` when the vault was never saved.
///
/// Corrupt envelopes also yield `None` (fail-closed; the vault layer then
/// reports a sealed-open failure without ever exposing plaintext). Never
/// logs blob contents.
pub fn pm_blob_load_opt<B: FlashStorageBackend>(storage: &SecureStorage<B>) -> Option<Vec<u8>> {
    pm_ns().get(storage, PM_BLOB_LABEL).ok()
}

/// Scoped wipe: erases ONLY the `vault-pm/` slots.
///
/// Idempotent (absent = success). FIDO2 (`vault/`, `key_slots_v1`, ...),
/// OATH (`oath6/`), binding, and PIN slots are never touched here.
pub fn pm_blob_wipe<B: FlashStorageBackend>(storage: &mut SecureStorage<B>) {
    let _ = pm_ns().delete(storage, PM_BLOB_LABEL);
}

/// DIP adapter: NVS-backed opaque-blob holder with the `PmStore` shapes.
///
/// Holds a short borrow of the encrypted storage; `save_blob` /
/// `load_blob` / `wipe` mirror `aegis-pm-vault` `PmStore` one-to-one so the
/// trait impl later is a single delegation line with no logic change.
/// Blob bytes are ciphertext: this type never logs, caches, or echoes them.
pub struct NvsPmStore<'a, B: FlashStorageBackend> {
    storage: &'a mut SecureStorage<B>,
}

impl<'a, B: FlashStorageBackend> NvsPmStore<'a, B> {
    /// Borrows the encrypted storage for one PM transaction.
    pub fn new(storage: &'a mut SecureStorage<B>) -> Self {
        Self { storage }
    }

    /// Persists one opaque sealed blob (replacing any previous blob).
    pub fn save_blob(&mut self, blob: &[u8]) -> Result<(), PmStoreError> {
        pm_blob_save(self.storage, blob)
    }

    /// Loads the last persisted blob, or `None` when never saved
    /// (corrupt envelopes also yield `None`, fail-closed).
    pub fn load_blob(&self) -> Option<Vec<u8>> {
        pm_blob_load_opt(self.storage)
    }

    /// Irreversibly erases the PM blob (scoped; FIDO2/OATH untouched).
    pub fn wipe(&mut self) {
        pm_blob_wipe(self.storage);
    }
}

/// Renders the code-only OLED confirmation frame for a PM release.
///
/// Generic summary (`PM RELEASE` + `[TOUCH CONFIRM]`): takes **no**
/// label/username/secret parameter by design, so user data can never reach
/// the display, the logs, or the screenshots. The caller obtains
/// `presence_confirmed` from the physical GPIO 0 BOOT button
/// (`BootButton`, active-low with debounce) while this frame is shown.
pub fn render_pm_confirm(buffer: &mut VirtualOledDisplayBuffer) {
    buffer.clear();
    buffer.draw_text(2, 2, "PM RELEASE");
    buffer.draw_hline(0, 127, 11);
    buffer.draw_text(2, 24, "SHOW SECRET?");
    buffer.draw_hline(0, 127, 53);
    buffer.draw_text(6, 55, "[TOUCH CONFIRM]");
}

/// Builds a fresh OLED confirmation frame (generic, secret-free).
pub fn pm_confirm_frame() -> VirtualOledDisplayBuffer {
    let mut buf = VirtualOledDisplayBuffer::new();
    render_pm_confirm(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;
    use alloc::vec;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    /// Backend that flips envelope bytes on reads of the PM blob key
    /// (emulates tampered flash; TRNG writes themselves stay intact).
    #[derive(Clone)]
    struct CorruptPmReads {
        inner: MockFlashBackend,
        corrupt: alloc::rc::Rc<core::cell::Cell<bool>>,
    }

    impl FlashStorageBackend for CorruptPmReads {
        fn read_raw(&self, key: &str) -> Result<Vec<u8>, StorageError> {
            let mut raw = self.inner.read_raw(key)?;
            if self.corrupt.get() && key == PM_BLOB_NVS_KEY {
                if let Some(last) = raw.last_mut() {
                    *last ^= 0xFF;
                }
            }
            Ok(raw)
        }
        fn write_raw(&mut self, key: &str, data: &[u8]) -> Result<(), StorageError> {
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
    fn pm_opcodes_claim_first_free_range_after_oob() {
        assert_eq!(
            (OP_PM_PUT, OP_PM_GET, OP_PM_LIST, OP_PM_DELETE, OP_PM_STATUS),
            (0x43, 0x44, 0x45, 0x46, 0x47)
        );
        assert_eq!((PM_OP_MIN, PM_OP_MAX), (0x43, 0x47));
        for op in PM_OP_MIN..=PM_OP_MAX {
            assert!(is_pm_op(op), "pm op 0x{op:02X}");
        }
        // Neighbours frozen elsewhere: vendor/OATH, bind-mgmt, OOB, Secure Guard.
        for op in [0x20u8, 0x27, 0x28, 0x2D, 0x3A, 0x3E, 0x41, 0x42, 0x48, 0x00] {
            assert!(!is_pm_op(op), "neighbour 0x{op:02X} not a PM op");
        }
        assert_eq!(PM_BINDING_WINDOW_MS, 60_000);
    }

    #[test]
    fn gates_deny_without_binding_up_pin_or_window() {
        let base = PmGateState::authorized();
        let denied = [
            (
                PmGateState {
                    binding_bound: false,
                    ..base
                },
                BleGattError::NeedBinding,
            ),
            (
                PmGateState {
                    presence_confirmed: false,
                    ..base
                },
                BleGattError::PresenceRequired,
            ),
            (
                PmGateState {
                    pin_authenticated: false,
                    ..base
                },
                BleGattError::PinRequired,
            ),
            (
                PmGateState {
                    bound_within_ms: PM_BINDING_WINDOW_MS + 1,
                    ..base
                },
                BleGattError::PresenceRequired,
            ),
        ];
        for op in PM_OP_MIN..=PM_OP_MAX {
            for (gate, want) in denied {
                assert_eq!(authorize_pm_op(op, &gate), Err(want), "op 0x{op:02X}");
            }
            // Authorized passes on every PM op; window edge is inclusive.
            assert!(authorize_pm_op(op, &base).is_ok());
            let edge = PmGateState {
                bound_within_ms: PM_BINDING_WINDOW_MS,
                ..base
            };
            assert!(authorize_pm_op(op, &edge).is_ok());
        }
        // Outside the family: fail-closed InvalidOpcode (FIDO2/OATH untouched).
        assert_eq!(
            authorize_pm_op(0x22, &base),
            Err(BleGattError::InvalidOpcode)
        );
        assert_eq!(
            authorize_pm_op(0x42, &base),
            Err(BleGattError::InvalidOpcode)
        );
    }

    #[test]
    fn gate_order_is_binding_first() {
        let all_missing = PmGateState {
            binding_bound: false,
            presence_confirmed: false,
            pin_authenticated: false,
            bound_within_ms: PM_BINDING_WINDOW_MS + 1,
            up_within_ms: PM_UP_WINDOW_MS + 1,
        };
        // Binding denial wins even when everything else is also missing.
        assert_eq!(
            authorize_pm_op(OP_PM_GET, &all_missing),
            Err(BleGattError::NeedBinding)
        );
        // Wire mapping preserves 9.5: 0x05 / 0x01 / 0x02.
        assert_eq!(BleGattError::NeedBinding.to_vendor_status(), 0x05);
        assert_eq!(BleGattError::PresenceRequired.to_vendor_status(), 0x01);
        assert_eq!(BleGattError::PinRequired.to_vendor_status(), 0x02);
    }

    #[test]
    fn save_load_roundtrip_through_adapter() {
        let mut st = test_storage();
        // Never saved: typed NotFound on the strict path, None on the opt path.
        assert_eq!(pm_blob_load(&st), Err(PmStoreError::NotFound));
        let blob = vec![0xA5u8; 64];
        let blob2 = vec![0x5Au8; 128];
        {
            let mut store = NvsPmStore::new(&mut st);
            assert!(store.load_blob().is_none());
            store.save_blob(&blob).expect("save ok");
            assert_eq!(store.load_blob().expect("load some"), blob);
        }
        assert_eq!(pm_blob_load(&st).expect("strict load"), blob);
        // Overwrite replaces (single-blob semantics).
        {
            let mut store = NvsPmStore::new(&mut st);
            store.save_blob(&blob2).expect("overwrite ok");
            assert_eq!(store.load_blob().expect("load v2"), blob2);
        }
    }

    #[test]
    fn rejects_blob_over_envelope_ceiling() {
        let mut st = test_storage();
        let huge = vec![0x41u8; PM_BLOB_MAX_BYTES + 1];
        assert_eq!(pm_blob_save(&mut st, &huge), Err(PmStoreError::TooLarge));
        assert_eq!(pm_blob_load(&st), Err(PmStoreError::NotFound));
        assert!(pm_blob_load_opt(&st).is_none());
    }

    #[test]
    fn tampered_blob_fails_closed() {
        let flag = alloc::rc::Rc::new(core::cell::Cell::new(false));
        let backend = CorruptPmReads {
            inner: MockFlashBackend::new(),
            corrupt: flag.clone(),
        };
        let mut st = SecureStorage::new(backend, &[0x55u8; 32], &[0xAAu8; 32]);
        pm_blob_save(&mut st, b"sealed-blob").expect("save ok");
        flag.set(true);
        // Tampered envelope fails authenticated decrypt (strict + opt paths).
        assert_eq!(pm_blob_load(&st), Err(PmStoreError::Storage));
        assert!(pm_blob_load_opt(&st).is_none());
        flag.set(false);
        assert_eq!(pm_blob_load(&st).expect("healed"), b"sealed-blob");
    }

    #[test]
    fn reboot_preserves_blob_via_mock_nvs() {
        let mut st = test_storage();
        pm_blob_save(&mut st, b"vault-sealed-v1").expect("save ok");
        // Simulated reboot: brand-new engine over the persisted backend image.
        let backend_clone = st.backend().clone();
        let rebooted = SecureStorage::new(backend_clone, &[0x55u8; 32], &[0xAAu8; 32]);
        assert_eq!(
            pm_blob_load(&rebooted).expect("reboot load"),
            b"vault-sealed-v1"
        );
        assert_eq!(
            pm_blob_load_opt(&rebooted).expect("reboot opt"),
            b"vault-sealed-v1"
        );
    }

    #[test]
    fn wipe_scoped_preserves_fido2_and_oath() {
        use crate::oath_store::{oath_store_get, oath_store_put};
        use crate::vault_store::{vault_store_get, vault_store_put};
        let mut st = test_storage();
        let cfg = crate::config::DeviceConfig::default();
        vault_store_put(&mut st, &cfg, "fido-label", b"fido-blob").expect("fido put");
        oath_store_put(&mut st, "GitHub:alice", b"oath-blob").expect("oath put");
        pm_blob_save(&mut st, b"pm-sealed").expect("pm save");
        // Scoped wipe drops only the PM blob; second wipe is idempotent.
        pm_blob_wipe(&mut st);
        pm_blob_wipe(&mut st);
        assert_eq!(pm_blob_load(&st), Err(PmStoreError::NotFound));
        let mut store = NvsPmStore::new(&mut st);
        assert!(store.load_blob().is_none());
        store.wipe();
        // FIDO2 + OATH slots survive untouched.
        assert_eq!(
            vault_store_get(&st, "fido-label").expect("fido survives"),
            b"fido-blob"
        );
        assert_eq!(
            oath_store_get(&st, "GitHub:alice").expect("oath survives"),
            b"oath-blob"
        );
    }

    #[test]
    fn oled_confirm_renders_without_secrets() {
        // Code-only frame: no secret-typed input exists on the API surface.
        let frame = pm_confirm_frame();
        let lit: usize = frame
            .as_bytes()
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum();
        assert!(lit > 50, "confirm frame must draw pixels");
        // Re-render into an existing buffer (caller-owned, no secret alloc).
        let mut buf = VirtualOledDisplayBuffer::new();
        render_pm_confirm(&mut buf);
        assert_eq!(buf.as_bytes(), frame.as_bytes());
    }

    #[test]
    fn stale_up_age_denies_every_op() {
        let base = PmGateState::authorized();
        // Fresh UP passes; edge of the window is inclusive.
        assert!(authorize_pm_op(OP_PM_GET, &base).is_ok());
        let edge = PmGateState {
            up_within_ms: PM_UP_WINDOW_MS,
            ..base
        };
        assert!(authorize_pm_op(OP_PM_GET, &edge).is_ok());
        // Stale UP denies even with the latch bit set (no latch reuse).
        let stale = PmGateState {
            up_within_ms: PM_UP_WINDOW_MS + 1,
            ..base
        };
        for op in PM_OP_MIN..=PM_OP_MAX {
            assert_eq!(
                authorize_pm_op(op, &stale),
                Err(BleGattError::PresenceRequired),
                "stale UP must deny op 0x{op:02X}"
            );
        }
        // Order preserved: missing UP bit still denies before the age check.
        let no_up = PmGateState {
            presence_confirmed: false,
            up_within_ms: PM_UP_WINDOW_MS + 1,
            ..base
        };
        assert_eq!(
            authorize_pm_op(OP_PM_DELETE, &no_up),
            Err(BleGattError::PresenceRequired)
        );
    }

    #[test]
    fn rate_limiter_backoff_locks_out_then_lapses() {
        let mut lim = PmRateLimiter::new();
        assert!(lim.poll(0).is_ok());
        assert!(!lim.in_backoff(0));
        // Gate denials carry no oracle: ignored, budget untouched.
        for st in [0x01u8, 0x02, 0x05, 0x06] {
            lim.record(st, 1_000);
        }
        assert!(lim.poll(1_000).is_ok());
        // Four authenticated failures: still open.
        for _ in 0..PM_MAX_CONSEC_FAIL - 1 {
            lim.record(0x03, 2_000);
        }
        assert!(lim.poll(2_000).is_ok());
        // Fifth spends the budget: backoff arms for PM_BACKOFF_MS.
        lim.record(0x04, 2_000);
        assert!(lim.in_backoff(2_000));
        assert_eq!(lim.poll(2_000), Err(0x04));
        assert_eq!(lim.poll(2_000 + PM_BACKOFF_MS - 1), Err(0x04));
        assert!(lim.poll(2_000 + PM_BACKOFF_MS).is_ok());
        // After the window lapses the limiter is usable again, and a
        // success resets the budget (fresh burst allowed).
        let after = 2_000 + PM_BACKOFF_MS;
        assert!(lim.poll(after).is_ok());
        lim.record(0x00, after);
        for _ in 0..PM_MAX_CONSEC_FAIL - 1 {
            lim.record(0x04, after);
        }
        assert!(lim.poll(after).is_ok());
    }

    #[test]
    fn audit_event_carries_no_secret_surface() {
        // Exact wire-facing shape: opcode + status, nothing else.
        let ev = PmAuditEvent {
            op: OP_PM_GET,
            status: 0x00,
        };
        assert_eq!(alloc::format!("{ev}"), "[PM-AUDIT] op=0x44 st=0x00");
        // The type has no payload field by construction: even adversarial
        // bodies cannot be formatted through it.
        let dbg = alloc::format!("{:?}", ev);
        assert!(dbg.contains("0x44") || dbg.contains("68"));
        assert!(!dbg.contains("s3cr3t"));
        assert!(!dbg.contains("alice"));
        assert_eq!(PM_BACKOFF_MS, 30_000);
        assert_eq!(PM_UP_WINDOW_MS, 60_000);
    }
    #[test]
    fn errors_carry_no_secret_payload() {
        // Typed errors are unit variants: Debug/Display never echo blob bytes.
        let dbg = alloc::format!("{:?}", PmStoreError::Storage);
        assert!(!dbg.contains("sealed"));
        let disp = alloc::format!("{}", PmStoreError::NotFound);
        assert_eq!(disp, "pm blob not found");
        assert_eq!(pm_blob_key(), "vault-pm/blob");
        assert_eq!(
            alloc::format!("{}{}", PM_STORE_PREFIX, PM_BLOB_LABEL),
            PM_BLOB_NVS_KEY
        );
        assert!(pm_blob_key().starts_with(PM_STORE_PREFIX));
    }
}
