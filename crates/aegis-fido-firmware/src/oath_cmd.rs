//! T-OT-02 HOTP dispatcher over oath_store: atomic counter + power-loss (GEN-DEVICE).
//!
//! Why: oath_store keeps credential blobs but proves no per-label HOTP
//! counter; without an atomic increment-before-use gate, a crash between
//! code display and counter persist reuses the same counter (replay hole,
//! section 9). This module owns the counter lifecycle only.
//!
//! - Does NOT edit oath_store.rs: it only calls oath_store_get/put as the
//!   credential backend (existence + label gate) and keeps counters under a
//!   separate NVS namespace `oath6ctr/` (8-byte big-endian `next` counter).
//! - Increment-before-use: inputs validados antes de consumir (falha de
//!   validacao nao queima contador); o contador e persistido (com
//!   verify-after-write) BEFORE the code is computed, so a crash can only
//!   skip a counter (tolerated by the HOTP look-ahead window), never reuse
//!   one. A torn write fails closed with Storage and keeps the old counter
//!   (sem delete: reset seria replay).
//! - Forward-only resync: hotp_resync only moves the counter forward
//!   (backward or equal is rejected), so a resync can never replay codes.
//! - UP/binding order (binding -> UP -> PIN) stays in the transport layer;
//!   code display (USO) requires UP there, never inside this module.
//! - No secret in logs: errors carry no seed, code, or counter bytes.
//! - Limits (section 9): label 1..=32 B (via oath_store gate), secret
//!   10..=128 B and digits 6..=8 (via totp gate), counter u64 (overflow is
//!   fail-closed, never wraps).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use aegis_fido_core::oath::OathAlgorithm;

use crate::oath_store::{oath_store_get, OathStoreError};
use crate::persistence::{
    FlashStorageBackend, NamespacedStore, NamespacedStoreError, SecureStorage,
};
use crate::totp::{
    hotp_code, TotpError, OTP_MAX_DIGITS, OTP_MAX_SECRET_LEN, OTP_MIN_DIGITS, OTP_MIN_SECRET_LEN,
};

/// NVS namespace for HOTP counters (separate from oath6/ credential blobs).
pub const OATH_CTR_PREFIX: &str = "oath6ctr/";

/// Namespace dos contadores HOTP: blobs fixos de 8 B big-endian (`next`),
/// sem quota, ponto unico de put/get + prefixo + verify-after-write
/// (antes manual em `store_next`).
fn oath_ctr_ns() -> NamespacedStore {
    NamespacedStore {
        prefix: OATH_CTR_PREFIX,
        max_bytes: Some(8),
        quota_index_key: None,
        max_slots: 0,
        delete_absent_ok: false,
        strict_index_reads: false,
        validate: oath_ctr_label_ok,
    }
}

/// Gate do label do contador (o vinculo com a credencial e checado antes,
/// via `require_credential`, que aplica o gate do `oath_store`).
fn oath_ctr_label_ok(label: &str) -> bool {
    !label.is_empty() && label.len() <= 64
}

/// HOTP code just consumed (code is public: shown on display / typed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotpCode {
    /// Zero-padded code string (6..=8 chars).
    pub code: String,
    /// Counter the code was computed for.
    pub counter: u64,
}

/// Typed HOTP dispatcher errors. No variant carries seed, code, or counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OathCmdError {
    /// Label outside 1..=32 B.
    BadLabel,
    /// No credential stored under this label.
    NotFound,
    /// Seed outside 10..=128 B.
    BadSecret,
    /// Digits outside 6..=8.
    BadDigits,
    /// Resync target not strictly forward.
    InvalidCounter,
    /// Counter at u64::MAX (never wraps).
    CounterOverflow,
    /// Backend failure or verify-after-write mismatch.
    Storage,
}

impl core::fmt::Display for OathCmdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadLabel => write!(f, "bad oath label"),
            Self::NotFound => write!(f, "oath credential not found"),
            Self::BadSecret => write!(f, "bad hotp secret length"),
            Self::BadDigits => write!(f, "bad hotp digits"),
            Self::InvalidCounter => write!(f, "hotp resync must move forward"),
            Self::CounterOverflow => write!(f, "hotp counter exhausted"),
            Self::Storage => write!(f, "hotp storage failure"),
        }
    }
}

fn map_store(e: OathStoreError) -> OathCmdError {
    match e {
        OathStoreError::BadLabel => OathCmdError::BadLabel,
        OathStoreError::NotFound => OathCmdError::NotFound,
        OathStoreError::TooLarge | OathStoreError::Storage | OathStoreError::NeedBinding => {
            OathCmdError::Storage
        }
    }
}

fn map_totp(e: TotpError) -> OathCmdError {
    match e {
        TotpError::BadSecret => OathCmdError::BadSecret,
        TotpError::BadDigits => OathCmdError::BadDigits,
        // hotp_code never returns clock errors; fail closed if it ever does.
        TotpError::ClockNotTrusted | TotpError::ClockRollback => OathCmdError::Storage,
    }
}

/// Proves the credential slot exists (label gate included). Returns its blob.
fn require_credential<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    label: &str,
) -> Result<Vec<u8>, OathCmdError> {
    oath_store_get(storage, label).map_err(map_store)
}

/// Loads the `next` counter; absent means 0. Malformed bytes fail closed
/// (never reset to 0: that would reuse counters).
fn load_next<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    label: &str,
) -> Result<u64, OathCmdError> {
    match oath_ctr_ns().get(storage, label) {
        Ok(raw) => {
            if raw.len() != 8 {
                return Err(OathCmdError::Storage);
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&raw);
            Ok(u64::from_be_bytes(b))
        }
        Err(NamespacedStoreError::NotFound) => Ok(0),
        Err(_) => Err(OathCmdError::Storage),
    }
}

/// Persists `next` with verify-after-write (dentro do `put`). Mismatch
/// fails closed and keeps the old counter readable (caller must not emit
/// a code on Storage; sem delete: reset seria replay).
fn store_next<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    label: &str,
    next: u64,
) -> Result<(), OathCmdError> {
    oath_ctr_ns()
        .put_keep_on_mismatch(storage, label, &next.to_be_bytes())
        .map_err(|_| OathCmdError::Storage)
}

/// Generates the HOTP code for `label` and atomically consumes its counter.
///
/// Consume order (power-loss safe): load `next`, persist `next + 1` with
/// verify, then compute the code for `next`. A crash can only skip a
/// counter, never reuse one.
pub fn hotp_next<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    label: &str,
    seed: &[u8],
    algo: OathAlgorithm,
    digits: u8,
) -> Result<HotpCode, OathCmdError> {
    let _cred = require_credential(storage, label)?;
    // Validacao antes de consumir: entrada invalida nao queima contador
    // (limites da secao 9, mesmos de `hotp_code`; sem duplicar numeros).
    if !(OTP_MIN_SECRET_LEN..=OTP_MAX_SECRET_LEN).contains(&seed.len()) {
        return Err(OathCmdError::BadSecret);
    }
    if !(OTP_MIN_DIGITS..=OTP_MAX_DIGITS).contains(&digits) {
        return Err(OathCmdError::BadDigits);
    }
    let next = load_next(storage, label)?;
    if next == u64::MAX {
        return Err(OathCmdError::CounterOverflow);
    }
    store_next(storage, label, next + 1)?;
    let code = hotp_code(seed, algo, next, digits).map_err(map_totp)?;
    Ok(HotpCode {
        code,
        counter: next,
    })
}

/// Peeks at the `next` counter without consuming it.
pub fn hotp_peek<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    label: &str,
) -> Result<u64, OathCmdError> {
    let _cred = require_credential(storage, label)?;
    load_next(storage, label)
}

/// Moves the counter forward to `next` (recovery after host desync).
/// Backward or equal targets are rejected (replay-safe).
pub fn hotp_resync<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    label: &str,
    next: u64,
) -> Result<(), OathCmdError> {
    let _cred = require_credential(storage, label)?;
    let cur = load_next(storage, label)?;
    if next <= cur {
        return Err(OathCmdError::InvalidCounter);
    }
    store_next(storage, label, next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oath_store::oath_store_put;
    use crate::persistence::MockFlashBackend;
    use crate::persistence::StorageError;

    const SHA1_SECRET: &[u8] = b"12345678901234567890";

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    fn provisioned(label: &str) -> SecureStorage<MockFlashBackend> {
        let mut st = test_storage();
        oath_store_put(&mut st, label, b"hotp-cred-ref").unwrap();
        st
    }

    #[test]
    fn rfc4226_sequence_consumes_counters() {
        let mut st = provisioned("hotp-a");
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (i, &exp) in expected.iter().enumerate() {
            let got = hotp_next(&mut st, "hotp-a", SHA1_SECRET, OathAlgorithm::Sha1, 6).unwrap();
            assert_eq!(got.code, exp, "HOTP counter {i}");
            assert_eq!(got.counter, i as u64);
        }
        assert_eq!(hotp_peek(&st, "hotp-a").unwrap(), 10);
    }

    #[test]
    fn rejects_invalid_inputs() {
        let mut st = provisioned("hotp-b");
        assert_eq!(
            hotp_next(&mut st, "", SHA1_SECRET, OathAlgorithm::Sha1, 6),
            Err(OathCmdError::BadLabel)
        );
        assert_eq!(
            hotp_next(&mut st, "hotp-b", b"short", OathAlgorithm::Sha1, 6),
            Err(OathCmdError::BadSecret)
        );
        assert_eq!(
            hotp_next(&mut st, "hotp-b", SHA1_SECRET, OathAlgorithm::Sha1, 5),
            Err(OathCmdError::BadDigits)
        );
        assert_eq!(
            hotp_next(&mut st, "nope", SHA1_SECRET, OathAlgorithm::Sha1, 6),
            Err(OathCmdError::NotFound)
        );
        assert_eq!(hotp_peek(&st, "nope"), Err(OathCmdError::NotFound));
        // The untouched label still starts at counter 0.
        let got = hotp_next(&mut st, "hotp-b", SHA1_SECRET, OathAlgorithm::Sha1, 6).unwrap();
        assert_eq!(got.counter, 0);
        assert_eq!(got.code, "755224");
    }

    #[test]
    fn resync_forward_only() {
        let mut st = provisioned("hotp-c");
        hotp_resync(&mut st, "hotp-c", 41).unwrap();
        assert_eq!(hotp_peek(&st, "hotp-c").unwrap(), 41);
        // Backward and equal are rejected.
        assert_eq!(
            hotp_resync(&mut st, "hotp-c", 41),
            Err(OathCmdError::InvalidCounter)
        );
        assert_eq!(
            hotp_resync(&mut st, "hotp-c", 7),
            Err(OathCmdError::InvalidCounter)
        );
        // Generation continues at 41 (cross-checked against totp directly).
        let want = hotp_code(SHA1_SECRET, OathAlgorithm::Sha1, 41, 6).unwrap();
        let got = hotp_next(&mut st, "hotp-c", SHA1_SECRET, OathAlgorithm::Sha1, 6).unwrap();
        assert_eq!(got.code, want);
        assert_eq!(hotp_peek(&st, "hotp-c").unwrap(), 42);
        // Unknown label cannot resync.
        assert_eq!(hotp_resync(&mut st, "nope", 9), Err(OathCmdError::NotFound));
    }

    #[test]
    fn counter_max_never_wraps() {
        let mut st = provisioned("hotp-d");
        hotp_resync(&mut st, "hotp-d", u64::MAX).unwrap();
        assert_eq!(
            hotp_next(&mut st, "hotp-d", SHA1_SECRET, OathAlgorithm::Sha1, 6),
            Err(OathCmdError::CounterOverflow)
        );
        assert_eq!(hotp_peek(&st, "hotp-d").unwrap(), u64::MAX);
    }

    /// Backend that acknowledges counter writes without persisting them.
    #[derive(Clone)]
    struct DropCtrWrites {
        inner: MockFlashBackend,
        drop: alloc::rc::Rc<core::cell::Cell<bool>>,
    }

    impl FlashStorageBackend for DropCtrWrites {
        fn read_raw(&self, key: &str) -> Result<Vec<u8>, StorageError> {
            self.inner.read_raw(key)
        }
        fn write_raw(&mut self, key: &str, data: &[u8]) -> Result<(), StorageError> {
            if self.drop.get() && key.starts_with(OATH_CTR_PREFIX) {
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
    fn torn_write_fails_closed_and_keeps_counter() {
        let drop = alloc::rc::Rc::new(core::cell::Cell::new(false));
        let backend = DropCtrWrites {
            inner: MockFlashBackend::new(),
            drop: drop.clone(),
        };
        let mut st = SecureStorage::new(backend, &[0x55u8; 32], &[0xAAu8; 32]);
        oath_store_put(&mut st, "hotp-e", b"hotp-cred-ref").unwrap();
        let first = hotp_next(&mut st, "hotp-e", SHA1_SECRET, OathAlgorithm::Sha1, 6).unwrap();
        assert_eq!(first.counter, 0);
        drop.set(true);
        assert_eq!(
            hotp_next(&mut st, "hotp-e", SHA1_SECRET, OathAlgorithm::Sha1, 6),
            Err(OathCmdError::Storage)
        );
        // Old counter survived: no silent skip, no reuse after heal.
        drop.set(false);
        assert_eq!(hotp_peek(&st, "hotp-e").unwrap(), 1);
        let second = hotp_next(&mut st, "hotp-e", SHA1_SECRET, OathAlgorithm::Sha1, 6).unwrap();
        assert_eq!(second.counter, 1);
        assert_eq!(second.code, "287082");
    }

    #[test]
    fn corrupted_counter_fails_closed() {
        let mut st = provisioned("hotp-f");
        // Envelope-valid write with a malformed 3-byte counter body.
        st.store(&oath_ctr_ns().key("hotp-f"), b"bad", &[0u8; 12])
            .unwrap();
        assert_eq!(hotp_peek(&st, "hotp-f"), Err(OathCmdError::Storage));
        assert_eq!(
            hotp_next(&mut st, "hotp-f", SHA1_SECRET, OathAlgorithm::Sha1, 6),
            Err(OathCmdError::Storage)
        );
    }
}
