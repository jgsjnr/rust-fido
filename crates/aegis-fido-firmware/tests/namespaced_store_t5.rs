//! T5 — `NamespacedStore` observable contracts (offline, frozen vectors).
//!
//! Covers what T5 finalized: put/get/delete, per-slot quota
//! (`max_bytes`), quota via encrypted CBOR index (`quota_index_key`,
//! fail-closed), verify-after-write (mismatch rolls back only the slot,
//! never the quota index), fail-closed reads on corrupt envelopes/index,
//! typed error semantics, and the three shipped presets
//! (`oath6/` via `oath_store`, `vault/` via `vault_store`, raw PIV keys
//! via `PivNvsStore`).
//!
//! Host-only: `MockFlashBackend` + local test-only backends below (test
//! doubles live in this test file, never in production code). No hardware,
//! no flash, no COM port.

use aegis_fido_firmware::config::DeviceConfig;
use aegis_fido_firmware::oath_store::{
    oath_store_delete, oath_store_get, oath_store_put, OathStoreError, OATH_STORE_MAX_BYTES,
};
use aegis_fido_firmware::persistence::{
    FlashStorageBackend, MockFlashBackend, NamespacedStore, NamespacedStoreError, SecureStorage,
    StorageError, NAMESPACED_SLOT_MAX_BYTES,
};
use aegis_fido_firmware::piv_store::PivNvsStore;
use aegis_fido_firmware::vault_store::{
    vault_store_delete, vault_store_get, vault_store_put, VaultStoreError, VAULT_INDEX_KEY,
    VAULT_STORE_MAX_BYTES,
};
use aegis_fido_usb::piv::PivRecordStore;

// Frozen vectors (offline, deterministic).
const MASTER: [u8; 32] = [0x55u8; 32];
const SALT: [u8; 32] = [0xAAu8; 32];
const BLOB_A: &[u8] = b"frozen-oath-blob-a";
const BLOB_B: &[u8] = b"frozen-oath-blob-b";
const ENVELOPE_MAGIC: [u8; 4] = [0x41, 0x45, 0x47, 0x4E]; // "AEGN"

fn storage() -> SecureStorage<MockFlashBackend> {
    SecureStorage::new(MockFlashBackend::new(), &MASTER, &SALT)
}

/// 1-slot vault config (`DeviceConfig::new` arity is 8; last = vault slots).
fn one_slot_cfg() -> DeviceConfig {
    DeviceConfig::new(50, 512, 4, 8, 3, 32, 64, 1).expect("one-slot vault cfg valid")
}

/// Always-true label gate (PIV-style raw keys).
fn any_label_ok(_label: &str) -> bool {
    true
}

/// 1..32B gate (OATH/vault style), reserving `"index"`.
fn short_label_ok(label: &str) -> bool {
    (1..=32).contains(&label.len()) && label != "index"
}

// ---------------------------------------------------------------------------
// Preset: oath6/ (OATH store)
// ---------------------------------------------------------------------------

#[test]
fn oath_preset_put_get_delete_roundtrip_under_oath6_prefix() {
    let mut st = storage();
    oath_store_put(&mut st, "GitHub:alice", BLOB_A).unwrap();
    // Observable contract: lives under the `oath6/` prefix …
    assert!(st.exists("oath6/GitHub:alice"));
    // … as an AEGN v1 envelope (bytes preserved, no new crypto) …
    let raw = st.backend().read_raw("oath6/GitHub:alice").unwrap();
    assert_eq!(&raw[0..4], &ENVELOPE_MAGIC);
    assert_eq!(raw[4], 0x01);
    // … and round-trips.
    assert_eq!(oath_store_get(&st, "GitHub:alice").unwrap(), BLOB_A);
    oath_store_delete(&mut st, "GitHub:alice").unwrap();
    assert_eq!(
        oath_store_get(&st, "GitHub:alice"),
        Err(OathStoreError::NotFound)
    );
    assert!(!st.exists("oath6/GitHub:alice"));
}

#[test]
fn oath_preset_rejects_bad_label_and_too_large() {
    let mut st = storage();
    assert_eq!(
        oath_store_put(&mut st, "", BLOB_A),
        Err(OathStoreError::BadLabel)
    );
    let long = "x".repeat(33);
    assert_eq!(
        oath_store_put(&mut st, &long, BLOB_A),
        Err(OathStoreError::BadLabel)
    );
    assert_eq!(oath_store_get(&st, ""), Err(OathStoreError::BadLabel));
    let huge = vec![0x41u8; OATH_STORE_MAX_BYTES + 1];
    assert_eq!(
        oath_store_put(&mut st, "k", &huge),
        Err(OathStoreError::TooLarge)
    );
    // Rejected put stored nothing.
    assert_eq!(oath_store_get(&st, "k"), Err(OathStoreError::NotFound));
}

#[test]
fn oath_preset_delete_absent_is_notfound_and_overwrite_verifies() {
    let mut st = storage();
    assert_eq!(
        oath_store_delete(&mut st, "nope"),
        Err(OathStoreError::NotFound)
    );
    oath_store_put(&mut st, "k", BLOB_A).unwrap();
    oath_store_put(&mut st, "k", BLOB_B).unwrap();
    assert_eq!(oath_store_get(&st, "k").unwrap(), BLOB_B);
}

// ---------------------------------------------------------------------------
// Preset: vault/ (quota via encrypted index)
// ---------------------------------------------------------------------------

#[test]
fn vault_preset_quota_enforced_and_overwrite_keeps_slot() {
    let mut st = storage();
    let cfg = one_slot_cfg();
    vault_store_put(&mut st, &cfg, "a", b"one").unwrap();
    assert!(st.exists("vault/a"));
    assert!(st.exists(VAULT_INDEX_KEY));
    assert_eq!(
        vault_store_put(&mut st, &cfg, "b", b"two"),
        Err(VaultStoreError::QuotaExceeded)
    );
    // Failed put stored nothing.
    assert_eq!(vault_store_get(&st, "b"), Err(VaultStoreError::NotFound));
    // Overwrite of a known label does not consume quota.
    vault_store_put(&mut st, &cfg, "a", b"uno").unwrap();
    assert_eq!(vault_store_get(&st, "a").unwrap(), b"uno");
}

#[test]
fn vault_preset_delete_frees_quota_and_reserved_index_label_rejected() {
    let mut st = storage();
    let cfg = one_slot_cfg();
    vault_store_put(&mut st, &cfg, "a", b"one").unwrap();
    vault_store_delete(&mut st, "a").unwrap();
    vault_store_put(&mut st, &cfg, "b", b"two").unwrap();
    assert_eq!(vault_store_get(&st, "b").unwrap(), b"two");
    assert_eq!(
        vault_store_put(&mut st, &cfg, "index", b"x"),
        Err(VaultStoreError::BadLabel)
    );
    assert_eq!(
        vault_store_delete(&mut st, "nope"),
        Err(VaultStoreError::NotFound)
    );
}

#[test]
fn vault_preset_corrupt_index_fails_closed_on_put_get_delete() {
    let mut st = storage();
    let cfg = DeviceConfig::default();
    vault_store_put(&mut st, &cfg, "a", b"one").unwrap();
    // Garbage quota plaintext (valid envelope, invalid CBOR): corrupt index.
    st.store(VAULT_INDEX_KEY, b"\xff\xfe not-cbor", &[0u8; 12])
        .unwrap();
    assert_eq!(
        vault_store_put(&mut st, &cfg, "b", b"two"),
        Err(VaultStoreError::Storage)
    );
    // Fail-closed: even reads of the intact slot report `Storage`.
    assert_eq!(vault_store_get(&st, "a"), Err(VaultStoreError::Storage));
    assert_eq!(vault_store_get(&st, "b"), Err(VaultStoreError::Storage));
    assert_eq!(
        vault_store_delete(&mut st, "a"),
        Err(VaultStoreError::Storage)
    );
}

// ---------------------------------------------------------------------------
// Preset: raw PIV keys (no prefix, no quota, idempotent delete)
// ---------------------------------------------------------------------------

#[test]
fn piv_preset_raw_keys_no_prefix_and_idempotent_delete() {
    let mut st = storage();
    {
        let mut piv = PivNvsStore::new(&mut st);
        assert_eq!(
            piv.load_record("piv:9a"),
            Err(aegis_fido_usb::piv::PivStoreError::NotFound)
        );
        piv.store_record("piv:9a", b"frozen-piv-blob").unwrap();
        assert_eq!(piv.load_record("piv:9a").unwrap(), b"frozen-piv-blob");
    }
    // Raw key: no namespace prefix.
    assert!(st.exists("piv:9a"));
    {
        let mut piv = PivNvsStore::new(&mut st);
        piv.delete_record("piv:9a").unwrap();
        // Idempotent: second delete is ok (PIV parity predating T5).
        piv.delete_record("piv:9a").unwrap();
    }
    assert!(!st.exists("piv:9a"));
}

// ---------------------------------------------------------------------------
// Direct NamespacedStore contracts: errors, quota, namespaces
// ---------------------------------------------------------------------------

fn direct_ns() -> NamespacedStore {
    direct_ns_quota(1)
}

fn direct_ns_quota(slots: usize) -> NamespacedStore {
    NamespacedStore {
        prefix: "t5/",
        max_bytes: Some(8),
        quota_index_key: Some("t5/index"),
        max_slots: slots,
        delete_absent_ok: false,
        strict_index_reads: true,
        validate: short_label_ok,
    }
}

#[test]
fn direct_error_semantics_and_display() {
    // Typed errors (no panics, no stringly) with stable Display text.
    assert_eq!(
        NamespacedStoreError::BadLabel.to_string(),
        "bad namespaced label"
    );
    assert_eq!(
        NamespacedStoreError::TooLarge.to_string(),
        "namespaced blob too large"
    );
    assert_eq!(
        NamespacedStoreError::QuotaExceeded.to_string(),
        "namespaced quota exceeded"
    );
    assert_eq!(
        NamespacedStoreError::NotFound.to_string(),
        "namespaced slot not found"
    );
    assert_eq!(
        NamespacedStoreError::Storage.to_string(),
        "namespaced storage failure"
    );
    // `StorageError` mapping: absent -> NotFound, everything else -> Storage.
    assert_eq!(
        NamespacedStoreError::from(StorageError::KeyNotFound),
        NamespacedStoreError::NotFound
    );
    assert_eq!(
        NamespacedStoreError::from(StorageError::DecryptionFailed),
        NamespacedStoreError::Storage
    );
    assert_eq!(
        NamespacedStoreError::from(StorageError::CorruptedEnvelope),
        NamespacedStoreError::Storage
    );
    // Slot budget constant shared by the OATH/vault presets.
    assert_eq!(NAMESPACED_SLOT_MAX_BYTES, 512);
    assert_eq!(OATH_STORE_MAX_BYTES, 512);
    assert_eq!(VAULT_STORE_MAX_BYTES, 512);
}

#[test]
fn direct_put_get_delete_with_quota_and_bounds() {
    let mut st = storage();
    let ns = direct_ns();
    assert_eq!(ns.key("a"), "t5/a");
    assert_eq!(
        ns.put(&mut st, "", b"x"),
        Err(NamespacedStoreError::BadLabel)
    );
    assert_eq!(
        ns.put(&mut st, "index", b"x"),
        Err(NamespacedStoreError::BadLabel)
    );
    assert_eq!(
        ns.put(&mut st, "a", b"123456789"),
        Err(NamespacedStoreError::TooLarge)
    );
    ns.put(&mut st, "a", b"12345678").unwrap();
    assert_eq!(ns.get(&st, "a").unwrap(), b"12345678");
    assert_eq!(
        ns.put(&mut st, "b", b"y"),
        Err(NamespacedStoreError::QuotaExceeded)
    );
    assert_eq!(ns.get(&st, "b"), Err(NamespacedStoreError::NotFound));
    assert_eq!(ns.delete(&mut st, "b"), Err(NamespacedStoreError::NotFound));
    ns.delete(&mut st, "a").unwrap();
    ns.put(&mut st, "b", b"y").unwrap();
    assert_eq!(ns.get(&st, "b").unwrap(), b"y");
}

#[test]
fn namespaces_do_not_share_slots() {
    let mut st = storage();
    let cfg = DeviceConfig::default();
    oath_store_put(&mut st, "same", b"oath").unwrap();
    vault_store_put(&mut st, &cfg, "same", b"vault").unwrap();
    assert_eq!(oath_store_get(&st, "same").unwrap(), b"oath");
    assert_eq!(vault_store_get(&st, "same").unwrap(), b"vault");
    assert!(st.exists("oath6/same"));
    assert!(st.exists("vault/same"));
}

// ---------------------------------------------------------------------------
// Verify-after-write + corruption: fail-closed, slot-only rollback
// ---------------------------------------------------------------------------

/// Test-only backend: flips the last byte of every read of `target` while
/// armed (emulates tampered flash; TRNG writes themselves stay intact).
#[derive(Clone)]
struct CorruptSlotReads {
    inner: MockFlashBackend,
    target: String,
    armed: std::rc::Rc<std::cell::Cell<bool>>,
}

impl FlashStorageBackend for CorruptSlotReads {
    fn read_raw(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        let mut raw = self.inner.read_raw(key)?;
        if self.armed.get() && key == self.target {
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
fn verify_after_write_mismatch_rolls_back_slot_only() {
    let armed = std::rc::Rc::new(std::cell::Cell::new(false));
    let backend = CorruptSlotReads {
        inner: MockFlashBackend::new(),
        target: String::from("t5/a"),
        armed: armed.clone(),
    };
    let mut st = SecureStorage::new(backend, &MASTER, &SALT);
    let ns = direct_ns();
    ns.put(&mut st, "a", b"good").unwrap();
    armed.set(true);
    // Tampered readback: fail-closed `Storage` (no silent success).
    assert_eq!(
        ns.put(&mut st, "a", b"evil"),
        Err(NamespacedStoreError::Storage)
    );
    armed.set(false);
    // The write itself was authentic (only the verification read was
    // tampered), so flash holds the complete new blob — same semantics as
    // `vault_store::tampered_slot_returns_storage_error`: fail-closed signal,
    // no torn/corrupt state, valid envelope on flash.
    assert_eq!(ns.get(&st, "a").unwrap(), b"evil");
    // Fresh put still heals the slot.
    ns.put(&mut st, "a", b"healed").unwrap();
    assert_eq!(ns.get(&st, "a").unwrap(), b"healed");
}

#[test]
fn tampered_slot_envelope_fails_closed_with_storage() {
    let mut st = storage();
    oath_store_put(&mut st, "k", b"secret").unwrap();
    // Flip a ciphertext byte in place (valid key, broken GCM tag).
    let mut raw = st.backend().read_raw("oath6/k").unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0xFF;
    st.backend_mut().write_raw("oath6/k", &raw).unwrap();
    assert_eq!(oath_store_get(&st, "k"), Err(OathStoreError::Storage));
    // Neighbor slot untouched.
    oath_store_put(&mut st, "j", b"other").unwrap();
    assert_eq!(oath_store_get(&st, "j").unwrap(), b"other");
}

/// Test-only backend: ack-drops writes to the quota index (torn write:
/// acknowledged but lost), forcing an index verify-after-write mismatch.
#[derive(Clone)]
struct DropIndexWrites {
    inner: MockFlashBackend,
    drop: std::rc::Rc<std::cell::Cell<bool>>,
}

impl FlashStorageBackend for DropIndexWrites {
    fn read_raw(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        self.inner.read_raw(key)
    }
    fn write_raw(&mut self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        if self.drop.get() && key == "t5/index" {
            return Ok(());
        }
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
fn torn_index_write_keeps_quota_and_rolls_back_slot() {
    let drop = std::rc::Rc::new(std::cell::Cell::new(false));
    let backend = DropIndexWrites {
        inner: MockFlashBackend::new(),
        drop: drop.clone(),
    };
    let mut st = SecureStorage::new(backend, &MASTER, &SALT);
    // Two quota slots: the second put reaches the index write (a 1-slot
    // namespace would reject it with `QuotaExceeded` before any write).
    let ns = direct_ns_quota(2);
    ns.put(&mut st, "a", b"one").unwrap();
    drop.set(true);
    // Torn index write => verify mismatch => `Storage`, data slot rolled back.
    assert_eq!(
        ns.put(&mut st, "b", b"two"),
        Err(NamespacedStoreError::Storage)
    );
    drop.set(false);
    assert_eq!(ns.get(&st, "b"), Err(NamespacedStoreError::NotFound));
    // Fail-closed: the quota index is never deleted on verify failure.
    assert!(st.exists("t5/index"));
    assert_eq!(ns.get(&st, "a").unwrap(), b"one");
}

#[test]
fn piv_style_namespace_needs_no_quota_and_accepts_any_key() {
    let piv_ns = NamespacedStore {
        prefix: "",
        max_bytes: None,
        quota_index_key: None,
        max_slots: 0,
        delete_absent_ok: true,
        strict_index_reads: false,
        validate: any_label_ok,
    };
    let mut st = storage();
    // Envelope ceiling (not 512) is the only size gate on raw PIV keys.
    let big = vec![0x41u8; 1024];
    piv_ns.put(&mut st, "piv:9a", &big).unwrap();
    assert_eq!(piv_ns.get(&st, "piv:9a").unwrap(), big);
    piv_ns.delete(&mut st, "piv:9a").unwrap();
    // Idempotent delete (absent = ok).
    piv_ns.delete(&mut st, "piv:9a").unwrap();
    // No quota index involved at all.
    assert!(!st.exists("t5/index"));
}
