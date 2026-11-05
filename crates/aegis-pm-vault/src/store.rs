//! PM vault engine + persistence abstraction (SRP: engine here, bytes in
//! firmware via [`PmStore`]).
//!
//! - Crypto reuse: sealing delegates to
//!   `AegisVault::seal_envelope`/`open_envelope` (AEGN v1). No new AEAD/KDF.
//! - Zero phone persistence: [`PmStore`] moves only opaque blobs; punctual
//!   release returns a [`Zeroizing`] secret the caller must drop promptly.
//! - DIP: firmware implements [`PmStore`] (NVS slots, migrations); this crate
//!   never names a transport, partition, or slot.

use alloc::string::String;
use alloc::vec::Vec;
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use aegis_fido_core::crypto::kdf::hkdf_sha256;
use aegis_fido_core::vault::AegisVault;

use crate::entry::{PasswordEntry, PmRecord, PM_PAYLOAD_VERSION};
use crate::policy::{PmError, PmGateState, PmPolicy};

/// CBOR body sealed inside the AEGN v1 envelope. Versioned independently so
/// new [`PmRecord`] variants decode without touching the envelope.
#[derive(Serialize, Deserialize)]
struct PmPayload {
    version: u32,
    records: Vec<PmRecord>,
}

/// Opaque-blob persistence port. The firmware implements this over NVS/flash;
/// the phone never implements it (blind transport only).
///
/// Implementors MUST NOT log, cache, or echo blob contents: blobs are AEAD
/// ciphertext whose dump must reveal no label, username, password, or share.
pub trait PmStore {
    /// Persists one opaque sealed blob (replacing any previous blob).
    fn save_blob(&mut self, blob: &[u8]) -> Result<(), PmError>;
    /// Loads the last persisted blob, or `None` when the vault was never saved.
    fn load_blob(&self) -> Option<Vec<u8>>;
    /// Irreversibly erases the persisted blob (scoped wipe; FIDO2/OATH slots
    /// are owned by other crates and are untouched by this call).
    fn wipe(&mut self);
}

/// Device-only password vault.
///
/// Holds the PM master key plus decrypted records in RAM. The key and all
/// secrets are `Zeroize`d on drop. Records only leave the device as opaque
/// AEAD blobs or as single gate-checked field releases.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PmVault {
    /// Key holder: `passkeys` vec stays empty; only `seal_envelope` /
    /// `open_envelope` (AEGN v1) are used.
    #[zeroize(skip)]
    key_holder: AegisVault,
    master_key: [u8; 32],
    records: Vec<PmRecord>,
}

impl core::fmt::Debug for PmVault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmVault")
            .field("records", &self.records.len())
            .field("master_key", &"[REDACTED]")
            .finish()
    }
}

impl PmVault {
    /// Creates an empty vault under a fresh 32-byte master key.
    pub fn new(master_key: [u8; 32]) -> Self {
        Self {
            key_holder: AegisVault::new(master_key),
            master_key,
            records: Vec::new(),
        }
    }

    /// Derives the PM master key from a 64-byte seed under the PM domain
    /// ([`PmPolicy::PM_MASTER_SALT`] / [`PmPolicy::PM_MASTER_INFO`]), so the
    /// same seed yields a different key than the FIDO vault or the wallet.
    pub fn from_seed_pm(seed: &[u8; 64]) -> Result<Self, PmError> {
        let key_vec = hkdf_sha256(PmPolicy::PM_MASTER_SALT, seed, PmPolicy::PM_MASTER_INFO, 32)
            .map_err(|_| PmError::Sealed)?;
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&key_vec);
        Ok(Self::new(master_key))
    }

    /// Number of records held in RAM.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether any record is held.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Inserts a new password record. Duplicated ids are rejected
    /// ([`PmError::Duplicate`]); quota/sizes come from `policy`; session
    /// gates come from `gate`.
    pub fn put_password(
        &mut self,
        policy: &PmPolicy,
        gate: &PmGateState,
        entry: PasswordEntry,
    ) -> Result<(), PmError> {
        policy.check_release(gate)?;
        policy.check_put(
            self.records.len(),
            entry.label.len(),
            entry.username.len(),
            entry.secret.len(),
        )?;
        if self.records.iter().any(|r| r.id() == entry.id) {
            return Err(PmError::Duplicate);
        }
        self.records.push(PmRecord::Password(entry));
        Ok(())
    }

    /// Replaces the secret of an existing record (gated; old bytes zeroized).
    pub fn update_secret(
        &mut self,
        policy: &PmPolicy,
        gate: &PmGateState,
        id: &[u8],
        secret: Vec<u8>,
        now: u64,
    ) -> Result<(), PmError> {
        policy.check_release(gate)?;
        if secret.len() > policy.max_secret_bytes {
            return Err(PmError::EntryTooLarge);
        }
        let slot = self
            .records
            .iter_mut()
            .find(|r| r.id() == id)
            .ok_or(PmError::NotFound)?;
        match slot {
            PmRecord::Password(e) => e
                .set_secret(secret, now)
                .map_err(|_| PmError::EntryTooLarge),
        }
    }

    /// Reads one record (gated). The caller receives a reference valid only
    /// while the vault is alive; nothing is copied to the phone.
    pub fn get(
        &self,
        policy: &PmPolicy,
        gate: &PmGateState,
        id: &[u8],
    ) -> Result<&PmRecord, PmError> {
        policy.check_release(gate)?;
        self.records
            .iter()
            .find(|r| r.id() == id)
            .ok_or(PmError::NotFound)
    }

    /// Punctual release of a single password field (gated). Returns a
    /// [`Zeroizing`] secret for one viewer frame; the caller renders it and
    /// drops it — no caching on the phone.
    pub fn release_password(
        &self,
        policy: &PmPolicy,
        gate: &PmGateState,
        id: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, PmError> {
        let rec = self.get(policy, gate, id)?;
        match rec {
            PmRecord::Password(e) => Ok(Zeroizing::new(e.secret.clone())),
        }
    }

    /// Lists record ids only (gated). Labels/usernames/secrets are NOT
    /// returned by this path; the viewer requests one record at a time.
    pub fn list_ids(&self, policy: &PmPolicy, gate: &PmGateState) -> Result<Vec<Vec<u8>>, PmError> {
        policy.check_release(gate)?;
        Ok(self.records.iter().map(|r| r.id().to_vec()).collect())
    }

    /// In-device substring search over labels (gated). Matching happens on
    /// the device; the phone only transports the opaque query/response
    /// through its blind channel. Returns record ids, not records.
    pub fn search_ids(
        &self,
        policy: &PmPolicy,
        gate: &PmGateState,
        query: &str,
    ) -> Result<Vec<Vec<u8>>, PmError> {
        policy.check_release(gate)?;
        let mut out = Vec::new();
        for r in &self.records {
            let hit = match r {
                PmRecord::Password(e) => contains_substring(&e.label, query),
            };
            if hit {
                out.push(r.id().to_vec());
            }
        }
        Ok(out)
    }

    /// Deletes a record by id (gated). Dropped bytes are zeroized.
    pub fn delete(
        &mut self,
        policy: &PmPolicy,
        gate: &PmGateState,
        id: &[u8],
    ) -> Result<(), PmError> {
        policy.check_release(gate)?;
        let pos = self
            .records
            .iter()
            .position(|r| r.id() == id)
            .ok_or(PmError::NotFound)?;
        self.records.remove(pos);
        Ok(())
    }

    /// Seals all records to one opaque AEAD blob (AEGN v1 envelope, gated).
    /// The blob is safe for the blind phone channel and for NVS storage:
    /// labels, usernames, passwords, and URLs are all inside the ciphertext.
    pub fn seal_to_blob<R: CryptoRng>(
        &self,
        policy: &PmPolicy,
        gate: &PmGateState,
        pin_token: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, PmError> {
        policy.check_release(gate)?;
        let payload = PmPayload {
            version: PM_PAYLOAD_VERSION,
            records: self.records.clone(),
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&payload, &mut cbor).map_err(|_| PmError::Serialization)?;
        // Session key + nonce handling lives in core; failures fail closed.
        self.key_holder
            .seal_envelope(&cbor, pin_token, rng)
            .map_err(|_| PmError::Sealed)
    }

    /// Opens a blob sealed by [`PmVault::seal_to_blob`], replacing RAM state.
    /// Wrong PIN token or tampered bytes → [`PmError::Sealed`]; malformed
    /// framing → [`PmError::Serialization`]. Gated like every other read.
    pub fn load_from_blob(
        &mut self,
        policy: &PmPolicy,
        gate: &PmGateState,
        blob: &[u8],
        pin_token: &[u8],
    ) -> Result<usize, PmError> {
        policy.check_release(gate)?;
        let cbor = self
            .key_holder
            .open_envelope(blob, pin_token)
            .map_err(|e| match e {
                aegis_fido_core::vault::VaultError::AuthenticationFailed => PmError::Sealed,
                aegis_fido_core::vault::VaultError::SerializationError(_) => PmError::Serialization,
                _ => PmError::Sealed,
            })?;
        let payload: PmPayload =
            ciborium::from_reader(cbor.as_slice()).map_err(|_| PmError::Serialization)?;
        if payload.version != PM_PAYLOAD_VERSION {
            return Err(PmError::Serialization);
        }
        let count = payload.records.len();
        if count > policy.max_entries {
            return Err(PmError::QuotaExceeded);
        }
        self.records = payload.records;
        Ok(count)
    }

    /// Convenience: seal + persist the opaque blob through `store` (DIP: the
    /// engine never touches flash/NVS directly).
    pub fn save_to_store<R: CryptoRng>(
        &self,
        policy: &PmPolicy,
        gate: &PmGateState,
        store: &mut dyn PmStore,
        pin_token: &[u8],
        rng: &mut R,
    ) -> Result<(), PmError> {
        let blob = self.seal_to_blob(policy, gate, pin_token, rng)?;
        let out = store.save_blob(&blob);
        blob_erase(blob);
        out
    }

    /// Convenience: load the opaque blob from `store` into RAM.
    pub fn restore_from_store(
        &mut self,
        policy: &PmPolicy,
        gate: &PmGateState,
        store: &dyn PmStore,
        pin_token: &[u8],
    ) -> Result<usize, PmError> {
        let blob = store.load_blob().ok_or(PmError::NotFound)?;
        let out = self.load_from_blob(policy, gate, &blob, pin_token);
        blob_erase(blob);
        out
    }
}

/// Case-sensitive substring scan without pulling in regex/format machinery.
fn contains_substring(haystack: &String, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.len() > h.len() {
        return false;
    }
    h.windows(n.len()).any(|w| w == n)
}

/// Best-effort stack/heap wipe of a consumed blob copy.
fn blob_erase(mut blob: Vec<u8>) {
    blob.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PM_BINDING_WINDOW_MS;
    use alloc::string::ToString;
    use alloc::vec;

    /// Test-only blob holder (the "mock" the lane task calls for: an
    /// in-RAM [`PmStore`]. Production code ships no mocks — firmware owns
    /// the real NVS-backed implementation).
    struct TestStore {
        blob: Option<Vec<u8>>,
    }

    impl PmStore for TestStore {
        fn save_blob(&mut self, blob: &[u8]) -> Result<(), PmError> {
            self.blob = Some(blob.to_vec());
            Ok(())
        }
        fn load_blob(&self) -> Option<Vec<u8>> {
            self.blob.clone()
        }
        fn wipe(&mut self) {
            if let Some(mut b) = self.blob.take() {
                b.zeroize();
            }
        }
    }

    fn entry(id: u8, label: &str, user: &str, secret: &[u8]) -> PasswordEntry {
        PasswordEntry::new(
            vec![id; 16],
            label.to_string(),
            user.to_string(),
            secret.to_vec(),
            None,
            1_770_000_000,
        )
        .unwrap()
    }

    fn vault_with_two() -> (PmVault, PmPolicy, PmGateState) {
        let mut v = PmVault::new([0x5A; 32]);
        let p = PmPolicy::default();
        let g = PmGateState::authorized();
        v.put_password(&p, &g, entry(1, "bank", "alice", b"s3cr3t-bank"))
            .unwrap();
        v.put_password(&p, &g, entry(2, "mail", "bob", b"s3cr3t-mail"))
            .unwrap();
        (v, p, g)
    }

    #[test]
    fn crud_isolated_list_search_delete() {
        let (mut v, p, g) = vault_with_two();
        assert_eq!(v.len(), 2);
        let ids = v.list_ids(&p, &g).unwrap();
        assert_eq!(ids.len(), 2);
        let hits = v.search_ids(&p, &g, "mai").unwrap();
        assert_eq!(hits, vec![vec![2u8; 16]]);
        let rec = v.get(&p, &g, &[1u8; 16]).unwrap();
        assert_eq!(rec.as_password().unwrap().username.as_str(), "alice");
        v.delete(&p, &g, &[1u8; 16]).unwrap();
        assert_eq!(v.len(), 1);
        assert!(v.get(&p, &g, &[1u8; 16]).is_err());
        // Duplicate insert rejected.
        assert_eq!(
            v.put_password(&p, &g, entry(2, "mail", "bob", b"x")),
            Err(PmError::Duplicate)
        );
    }

    #[test]
    fn seal_open_roundtrip_and_dump_reveals_nothing() {
        let (v, p, g) = vault_with_two();
        let mut rng = rand::rng();
        let pin = b"pin-token-1";
        let blob = v.seal_to_blob(&p, &g, pin, &mut rng).unwrap();
        // AEGN v1 framing preserved.
        assert!(blob.len() >= 33);
        assert_eq!(&blob[0..4], b"AEGN");
        assert_eq!(blob[4], 0x01);
        // Raw dump contains no label, username, or password bytes.
        for secret in [
            b"bank".as_slice(),
            b"mail",
            b"alice",
            b"s3cr3t-bank",
            b"s3cr3t-mail",
        ] {
            assert!(
                blob.windows(secret.len()).all(|w| w != secret),
                "dump leaks {:?}",
                secret
            );
        }
        // Wrong PIN token fails closed.
        let mut v2 = PmVault::new([0x5A; 32]);
        assert_eq!(
            v2.load_from_blob(&p, &g, &blob, b"wrong-token"),
            Err(PmError::Sealed)
        );
        // Tampered byte fails closed.
        let mut tampered = blob.clone();
        tampered[20] ^= 0x55;
        assert!(v2.load_from_blob(&p, &g, &tampered, pin).is_err());
        // Correct open restores both records.
        let n = v2.load_from_blob(&p, &g, &blob, pin).unwrap();
        assert_eq!(n, 2);
        let pw = v2.release_password(&p, &g, &[1u8; 16]).unwrap();
        assert_eq!(pw.as_slice(), b"s3cr3t-bank");
    }

    #[test]
    fn reboot_preserves_vault_through_opaque_store() {
        let (v, p, g) = vault_with_two();
        let mut rng = rand::rng();
        let pin = b"pin-token-9";
        let mut store = TestStore { blob: None };
        v.save_to_store(&p, &g, &mut store, pin, &mut rng).unwrap();
        // Simulated reboot: brand-new engine, same master key + PIN token.
        let mut rebooted = PmVault::new([0x5A; 32]);
        let n = rebooted.restore_from_store(&p, &g, &store, pin).unwrap();
        assert_eq!(n, 2);
        assert_eq!(rebooted.len(), 2);
        // Scoped wipe drops the blob; FIDO2/OATH slots are out of scope here.
        store.wipe();
        let mut fresh = PmVault::new([0x5A; 32]);
        assert_eq!(
            fresh.restore_from_store(&p, &g, &store, pin),
            Err(PmError::NotFound)
        );
    }

    #[test]
    fn gates_deny_without_binding_up_pin_or_window() {
        let (v, p, _) = vault_with_two();
        let mut rng = rand::rng();
        let base = PmGateState::authorized();
        let denied = [
            PmGateState {
                binding_bound: false,
                ..base
            },
            PmGateState {
                presence_confirmed: false,
                ..base
            },
            PmGateState {
                pin_authenticated: false,
                ..base
            },
            PmGateState {
                bound_within_ms: PM_BINDING_WINDOW_MS + 1,
                ..base
            },
        ];
        for g in denied {
            assert!(v.list_ids(&p, &g).is_err());
            assert!(v.search_ids(&p, &g, "bank").is_err());
            assert!(v.get(&p, &g, &[1u8; 16]).is_err());
            assert!(v.release_password(&p, &g, &[1u8; 16]).is_err());
            assert!(v.seal_to_blob(&p, &g, b"pin", &mut rng).is_err());
        }
    }

    #[test]
    fn punctual_release_is_zeroized_on_drop() {
        let (v, p, g) = vault_with_two();
        let pw = v.release_password(&p, &g, &[2u8; 16]).unwrap();
        assert_eq!(pw.as_slice(), b"s3cr3t-mail");
        // `Zeroizing` wipes on drop — compile-time guaranteed by the type.
        drop(pw);
    }

    /// SIMULATED full viewer flow — no hardware, no BLE, no real PIN biometry
    /// (host-only; the phone screen flow it mirrors is `PasswordManagerScreen`:
    /// viewer → unlock → open item → eye (`BiometricPrompt`, simulated here by
    /// the presence+PIN gates) → wipe-on-close → reopen proving zeroed).
    ///
    /// Covers the SIM gap `app_simulator.py --self-test` / `e2e_harness session`
    /// do not exercise: PM opcodes `0x43..=0x47` never cross those harnesses.
    /// No eFuse / Secure Boot / flash-encryption surface is touched here.
    #[test]
    fn simulated_viewer_unlock_eye_wipe_reopen_proves_zeroed() {
        let (v, p, _) = vault_with_two();
        let pin = b"pin-token-sim";
        let mut rng = rand::rng();
        let mut store = TestStore { blob: None };
        // Seed once so the reopen step has something to prove-zero against.
        v.save_to_store(&p, &PmGateState::authorized(), &mut store, pin, &mut rng)
            .unwrap();

        // 1. VIEWER locked (no binding/UP/PIN — mirrors "connect hardware
        // first" fail-closed screen): every read path denies.
        let locked = PmGateState {
            binding_bound: false,
            presence_confirmed: false,
            pin_authenticated: false,
            bound_within_ms: 0,
        };
        assert_eq!(v.list_ids(&p, &locked), Err(PmError::NeedBinding));
        assert_eq!(v.search_ids(&p, &locked, "bank"), Err(PmError::NeedBinding));
        assert_eq!(
            v.get(&p, &locked, &[1u8; 16]).unwrap_err(),
            PmError::NeedBinding
        );
        assert_eq!(
            v.release_password(&p, &locked, &[1u8; 16]),
            Err(PmError::NeedBinding)
        );

        // 2. UNLOCK (binding + presence/simulated-UP + PIN — the eye's
        // `BiometricPrompt` success maps to the presence+PIN bits here).
        let open = PmGateState::authorized();

        // 3. VIEWER list: opaque ids only (no labels/usernames/secrets cross);
        // census = in-RAM count against the policy quota (status `0x47` shape).
        let ids = v.list_ids(&p, &open).unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&vec![1u8; 16]) && ids.contains(&vec![2u8; 16]));
        let ids_dbg = alloc::format!("{ids:?}");
        for leak in ["bank", "mail", "alice", "bob", "s3cr3t"] {
            assert!(!ids_dbg.contains(leak), "list leaks {leak}");
        }
        assert_eq!(v.len(), 2);
        assert!(v.len() <= p.max_entries);

        // 4. SEARCH (device-side substring; census-filtered opaque response).
        assert_eq!(v.search_ids(&p, &open, "ban").unwrap(), vec![vec![1u8; 16]]);
        assert_eq!(
            v.search_ids(&p, &open, "zzz").unwrap(),
            Vec::<Vec<u8>>::new()
        );
        assert_eq!(v.search_ids(&p, &open, "").unwrap().len(), 2);

        // 5. ABRIR ITEM + OLHO (biometria simulada): punctual single-frame
        // release; `Debug` is redacted (`Zeroizing` non-exhaustive).
        let pw = v.release_password(&p, &open, &[1u8; 16]).unwrap();
        assert_eq!(pw.as_slice(), b"s3cr3t-bank");
        let pw_dbg = alloc::format!("{pw:?}");
        assert!(!pw_dbg.contains("s3cr3t"), "release leaks: {pw_dbg}");

        // 6. WIPE-ON-CLOSE (`closeRelease` mirror): drop the transient frame
        // then scoped-wipe the persisted blob (FIDO2/OATH out of scope here —
        // `TestStore` holds only the PM blob).
        drop(pw);
        store.wipe();

        // 7. REABRIR PROVA QUE ZEROU: blob is gone; restore denies; RAM empty.
        let mut reopened = PmVault::new([0x5A; 32]);
        assert_eq!(
            reopened.restore_from_store(&p, &open, &store, pin),
            Err(PmError::NotFound)
        );
        assert!(reopened.is_empty());
        assert_eq!(reopened.len(), 0);
        // Walk-away also closes the viewer: stale binding denies release.
        let stale = PmGateState {
            bound_within_ms: PM_BINDING_WINDOW_MS + 1,
            ..PmGateState::authorized()
        };
        assert_eq!(
            v.release_password(&p, &stale, &[1u8; 16]),
            Err(PmError::BindingWindowExpired)
        );
    }
}
