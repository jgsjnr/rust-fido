//! F5 — sealed wallet-seed persistence (NVS via existing infra; no eFuse).
//!
//! Persists the [`SeedCeremony`](aegis_fido_core::wallet::SeedCeremony) output
//! as one atomic bundle over the existing encrypted [`SecureStorage`]:
//! the routing table ([`WalletStore::export_routing`](aegis_fido_core::wallet::WalletStore::export_routing))
//! under [`WALLET_SEED_ROUTE_KEY`] plus the PIN-bound sealed entropy envelope
//! ([`SeedCeremony::export_sealed`](aegis_fido_core::wallet::SeedCeremony::export_sealed))
//! under [`WALLET_SEED_ENVELOPE_KEY`]. Both keys stay within the 15-char
//! ESP-IDF NVS limit and travel through a single [`NamespacedStore`]
//! (raw keys, no quota — same shape as `vendor_store`), so every write gets
//! verify-after-write for free.
//!
//! Atomicity: [`save_seed_bundle`] snapshots the previous bundle first and
//! rolls it back if any write fails — including the
//! [`NamespacedStore`] delete-on-verify-mismatch path, which would otherwise
//! destroy the old slot. [`load_seed_bundle`] treats a partial bundle
//! (exactly one half present) or undecodable bytes as
//! [`WalletSeedError::Storage`]: partial NVS is corruption, never a
//! half-state to boot from. Absent-on-both-sides is
//! [`WalletSeedError::NotFound`] (never provisioned). [`wipe_wallet_seed`]
//! deletes both halves idempotently; total-wipe paths call it alongside the
//! existing vault/credential wipes.
//!
//! No hardware-root operation here (read-only audit: this file contains no
//! one-time-programmable key-block call site), no new crypto, no JSON, no new wire
//! status and no new opcode: F5 reuses the frozen ranges (§9
//! backward-compat; old decoders never see these NVS keys).

use aegis_fido_core::vault::VAULT_ENVELOPE_MIN_LEN;
use aegis_fido_core::wallet::WalletStore;
use zeroize::Zeroize;

use crate::persistence::{
    FlashStorageBackend, NamespacedStore, NamespacedStoreError, SecureStorage,
};

/// NVS key holding the `export_routing()` bytes (12 chars, ESP-IDF ≤15).
pub const WALLET_SEED_ROUTE_KEY: &str = "wallet_route";
/// NVS key holding the PIN-bound sealed entropy envelope (11 chars, ≤15).
pub const WALLET_SEED_ENVELOPE_KEY: &str = "wallet_seed";

/// Routing table ceiling: 32 slots × 2 B (`[slot, discriminant]` pairs).
const MAX_ROUTE_BYTES: usize = 64;
/// Sealed envelope ceiling: AEGN envelope over 32 B entropy
/// (`4 + 1 + 12 + 32 + 16 = 65`) with headroom, fail-closed above.
const MAX_SEALED_BYTES: usize = 128;

/// Fail-closed persistence errors (no secrets, no panics).
///
/// `NotFound` = never provisioned (both halves absent). Anything else —
/// partial bundle, undecodable routing, short envelope, backend failure — is
/// `Storage`: the caller fails closed and never boots a half-state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletSeedError {
    /// No bundle persisted (both NVS halves absent).
    NotFound,
    /// Backend failure, verify-after-write mismatch, or corrupt/partial
    /// bundle (fail-closed).
    Storage,
}

impl core::fmt::Display for WalletSeedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => write!(f, "wallet seed never provisioned"),
            Self::Storage => write!(f, "wallet seed storage failure"),
        }
    }
}

impl From<NamespacedStoreError> for WalletSeedError {
    fn from(_: NamespacedStoreError) -> Self {
        Self::Storage
    }
}

/// Sealed bundle as loaded from NVS (opaque bytes; the ceremony owns the
/// interpretation — routing via `WalletStore::import_routing`, entropy via
/// `SeedCeremony::import_sealed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedBundle {
    /// `WalletStore::export_routing()` bytes.
    pub route: Vec<u8>,
    /// `SeedCeremony::export_sealed()` (AEGN PIN-bound envelope) bytes.
    pub sealed_entropy: Vec<u8>,
}

fn wallet_seed_key_ok(label: &str) -> bool {
    label == WALLET_SEED_ROUTE_KEY || label == WALLET_SEED_ENVELOPE_KEY
}

/// Single namespace for the two bundle halves (raw NVS keys, no quota,
/// envelope verify-after-write, idempotent delete — same shape as the
/// vendor F2/F3 namespace).
fn wallet_seed_ns() -> NamespacedStore {
    NamespacedStore {
        prefix: "",
        max_bytes: None,
        quota_index_key: None,
        max_slots: 0,
        delete_absent_ok: true,
        strict_index_reads: false,
        validate: wallet_seed_key_ok,
    }
}

fn snapshot_half<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    key: &str,
) -> Result<Option<Vec<u8>>, WalletSeedError> {
    match wallet_seed_ns().get(storage, key) {
        Ok(v) => Ok(Some(v)),
        Err(NamespacedStoreError::NotFound) => Ok(None),
        Err(_) => Err(WalletSeedError::Storage),
    }
}

fn restore_half<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    key: &str,
    previous: Option<Vec<u8>>,
) {
    match previous {
        Some(bytes) => {
            let _ = wallet_seed_ns().put(storage, key, &bytes);
        }
        None => {
            let _ = wallet_seed_ns().delete(storage, key);
        }
    }
}

/// Persists the ceremony bundle atomically (snapshot + rollback).
///
/// Fail-closed: oversized inputs are rejected before touching NVS; if any
/// write (or its verify-after-write) fails, the previous bundle is restored
/// — or both halves removed when nothing was provisioned before — so a
/// power cut mid-save can only ever leave the old bundle or nothing, never
/// a mix of new route + old envelope.
pub fn save_seed_bundle<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    route: &[u8],
    sealed_entropy: &[u8],
) -> Result<(), WalletSeedError> {
    if route.len() > MAX_ROUTE_BYTES || !route.len().is_multiple_of(2) {
        return Err(WalletSeedError::Storage);
    }
    if sealed_entropy.len() < VAULT_ENVELOPE_MIN_LEN || sealed_entropy.len() > MAX_SEALED_BYTES {
        return Err(WalletSeedError::Storage);
    }
    let ns = wallet_seed_ns();
    let mut old_route = snapshot_half(storage, WALLET_SEED_ROUTE_KEY)?;
    let mut old_sealed = snapshot_half(storage, WALLET_SEED_ENVELOPE_KEY)?;
    let res = (|| -> Result<(), WalletSeedError> {
        ns.put(storage, WALLET_SEED_ROUTE_KEY, route)?;
        ns.put(storage, WALLET_SEED_ENVELOPE_KEY, sealed_entropy)?;
        Ok(())
    })();
    match res {
        Ok(()) => {
            if let Some(v) = old_route.as_mut() {
                v.zeroize();
            }
            if let Some(v) = old_sealed.as_mut() {
                v.zeroize();
            }
            Ok(())
        }
        Err(e) => {
            restore_half(storage, WALLET_SEED_ROUTE_KEY, old_route);
            restore_half(storage, WALLET_SEED_ENVELOPE_KEY, old_sealed);
            Err(e)
        }
    }
}

/// Loads the persisted bundle (fail-closed).
///
/// Both halves absent → [`WalletSeedError::NotFound`]. Exactly one half
/// present, undecodable routing (`WalletStore::import_routing` probe on an
/// ephemeral store), or a short envelope → [`WalletSeedError::Storage`]:
/// partial NVS is corruption, never a half-state.
pub fn load_seed_bundle<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
) -> Result<SeedBundle, WalletSeedError> {
    let ns = wallet_seed_ns();
    let route = match ns.get(storage, WALLET_SEED_ROUTE_KEY) {
        Ok(v) => Some(v),
        Err(NamespacedStoreError::NotFound) => None,
        Err(_) => return Err(WalletSeedError::Storage),
    };
    let sealed_entropy = match ns.get(storage, WALLET_SEED_ENVELOPE_KEY) {
        Ok(v) => Some(v),
        Err(NamespacedStoreError::NotFound) => None,
        Err(_) => return Err(WalletSeedError::Storage),
    };
    match (route, sealed_entropy) {
        (None, None) => Err(WalletSeedError::NotFound),
        (Some(route), Some(sealed_entropy)) => {
            let mut probe = WalletStore::new();
            if probe.import_routing(&route).is_err() {
                return Err(WalletSeedError::Storage);
            }
            if sealed_entropy.len() < VAULT_ENVELOPE_MIN_LEN {
                return Err(WalletSeedError::Storage);
            }
            Ok(SeedBundle {
                route,
                sealed_entropy,
            })
        }
        // NVS parcial = corrompido: nunca meio-estado.
        (Some(_), None) | (None, Some(_)) => Err(WalletSeedError::Storage),
    }
}

/// Destroys the persisted bundle. Idempotent (absent = `Ok`): total-wipe
/// paths call this so no sealed entropy survives a factory reset.
pub fn wipe_wallet_seed<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
) -> Result<(), WalletSeedError> {
    let ns = wallet_seed_ns();
    ns.delete(storage, WALLET_SEED_ROUTE_KEY)?;
    ns.delete(storage, WALLET_SEED_ENVELOPE_KEY)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;

    fn storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    fn sample_bundle() -> (Vec<u8>, Vec<u8>) {
        (Vec::from([3u8, 0x01, 7, 0x03]), vec![0x41u8; 65])
    }

    #[test]
    fn nvs_keys_fit_esp_idf_limit() {
        assert!(WALLET_SEED_ROUTE_KEY.len() <= 15);
        assert!(WALLET_SEED_ENVELOPE_KEY.len() <= 15);
    }

    #[test]
    fn fresh_storage_reports_not_found_and_wipe_is_idempotent() {
        let mut st = storage();
        assert_eq!(
            load_seed_bundle(&st).unwrap_err(),
            WalletSeedError::NotFound
        );
        wipe_wallet_seed(&mut st).unwrap();
        assert_eq!(
            load_seed_bundle(&st).unwrap_err(),
            WalletSeedError::NotFound
        );
    }

    #[test]
    fn save_load_roundtrip_and_overwrite() {
        let mut st = storage();
        let (route, sealed) = sample_bundle();
        save_seed_bundle(&mut st, &route, &sealed).unwrap();
        let bundle = load_seed_bundle(&st).unwrap();
        assert_eq!(bundle.route, route);
        assert_eq!(bundle.sealed_entropy, sealed);
        let route2 = Vec::from([1u8, 0x02]);
        save_seed_bundle(&mut st, &route2, &sealed).unwrap();
        assert_eq!(load_seed_bundle(&st).unwrap().route, route2);
        wipe_wallet_seed(&mut st).unwrap();
        assert_eq!(
            load_seed_bundle(&st).unwrap_err(),
            WalletSeedError::NotFound
        );
    }

    #[test]
    fn oversized_inputs_rejected_before_touching_nvs() {
        let mut st = storage();
        let (route, sealed) = sample_bundle();
        save_seed_bundle(&mut st, &route, &sealed).unwrap();
        assert_eq!(
            save_seed_bundle(&mut st, &[0u8; 65], &sealed).unwrap_err(),
            WalletSeedError::Storage
        );
        assert_eq!(
            save_seed_bundle(&mut st, &[0x01], &sealed).unwrap_err(),
            WalletSeedError::Storage
        );
        assert_eq!(
            save_seed_bundle(&mut st, &route, &[0u8; 129]).unwrap_err(),
            WalletSeedError::Storage
        );
        // Previous bundle untouched by the rejected writes.
        assert_eq!(load_seed_bundle(&st).unwrap().route, route);
    }

    #[test]
    fn undecodable_routing_loads_as_storage() {
        let mut st = storage();
        // Unknown discriminant (zeroed flash) passes the backend but must
        // fail the routing probe at load.
        let bad_route = Vec::from([1u8, 0x00]);
        save_seed_bundle(&mut st, &bad_route, &sample_bundle().1).unwrap();
        assert_eq!(load_seed_bundle(&st).unwrap_err(), WalletSeedError::Storage);
    }
}
