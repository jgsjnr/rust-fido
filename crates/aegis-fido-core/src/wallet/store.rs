//! WalletStore: thin delegation over a dedicated KeyManager (B1).
//!
//! BEHAVIOR: owns a private [`KeyManager`](crate::credential::KeyManager)
//! (never shared, never leaked) plus a slot-id -> [`CryptoNetwork`] routing
//! table (ES256K is ambiguous between Bitcoin and EthereumEvm, so the network
//! cannot be recovered from the slot's COSE alg alone). Every key operation
//! delegates; UP (generate/sign/list/address/get/public_cose) and UP+PIN
//! (import/delete) gates are inherited from KeyManager — no gate logic here,
//! no OTP path, no global lock. Labels are prefixed with [`WALLET_LABEL_PREFIX`]
//! (B1 audit marker); overlong labels and out-of-range ids surface the
//! KeyManager bounds as `BadEnvelope`. Import takes the caller-declared
//! [`CoseAlgorithm`] and refuses (`BadEnvelope`, slot untouched) when it
//! disagrees with the network's curve, so a host cannot silently reinterpret
//! envelope bytes under the wrong curve.

use alloc::string::String;
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

use super::address::address_for_public_key;
use super::types::{CryptoNetwork, WalletRecord};
use super::WalletError;
use crate::credential::{KeyManager, KEY_USE_SIGN};
use crate::crypto::{CoseAlgorithm, PublicKey};
use crate::vault::AegisVault;

/// B1 audit marker enforced on every slot label the store creates.
pub const WALLET_LABEL_PREFIX: &str = "wallet:";

/// Crypto-wallet store. Holds no private material itself: secrets live in
/// the owned [`KeyManager`](crate::credential::KeyManager), which zeroizes
/// on drop; this struct only adds network routing metadata.
#[derive(Debug)]
pub struct WalletStore {
    manager: KeyManager,
    networks: Vec<(u8, CryptoNetwork)>,
}

impl WalletStore {
    /// Creates an empty store with a dedicated (B1) KeyManager.
    pub fn new() -> Self {
        Self {
            manager: KeyManager::new(),
            networks: Vec::new(),
        }
    }

    /// Number of occupied wallet slots.
    pub fn len(&self) -> usize {
        self.manager.len()
    }

    /// Whether any wallet slot is occupied.
    pub fn is_empty(&self) -> bool {
        self.manager.is_empty()
    }

    fn prefixed_label(label: &str) -> String {
        alloc::format!("{WALLET_LABEL_PREFIX}{label}")
    }

    fn network_of(&self, slot_id: u8) -> Result<CryptoNetwork, WalletError> {
        self.networks
            .iter()
            .find(|(id, _)| *id == slot_id)
            .map(|(_, network)| *network)
            .ok_or(WalletError::NoSlot)
    }

    fn record_for(
        &self,
        slot_id: u8,
        presence_confirmed: bool,
    ) -> Result<WalletRecord, WalletError> {
        let slots = self.manager.list(presence_confirmed)?;
        let slot = slots
            .iter()
            .find(|s| s.id == slot_id)
            .ok_or(WalletError::NoSlot)?;
        let network = self.network_of(slot_id)?;
        let cose = self.manager.public_cose(slot_id, presence_confirmed)?;
        let pubkey =
            PublicKey::from_cose_cbor(&cose).map_err(|_| WalletError::BadEnvelope)?;
        let address = address_for_public_key(&pubkey, network)?;
        Ok(WalletRecord {
            slot_id,
            network,
            address,
            label: slot.label.clone(),
        })
    }

    /// GEN (gate UP, inherited): generates an on-device key under the
    /// network's curve and returns its metadata record with derived address.
    pub fn generate<R: RngCore + CryptoRng>(
        &mut self,
        network: CryptoNetwork,
        slot_id: u8,
        label: &str,
        created: u64,
        presence_confirmed: bool,
        rng: &mut R,
    ) -> Result<WalletRecord, WalletError> {
        let slot = self.manager.generate(
            slot_id,
            network.cose_algorithm(),
            Self::prefixed_label(label),
            KEY_USE_SIGN,
            created,
            presence_confirmed,
            rng,
        )?;
        // Routing entry is pushed before record_for (which needs it for
        // network_of) and rolled back if record_for fails, so a failed
        // generate never leaves an orphan routing entry behind.
        let routing_len = self.networks.len();
        self.networks.push((slot_id, network));
        match self.record_for(slot.id, presence_confirmed) {
            Ok(record) => Ok(record),
            Err(e) => {
                self.networks.truncate(routing_len);
                Err(e)
            }
        }
    }

    /// IMPORT (gate UP+PIN, inherited): opens the AEGN envelope with the
    /// PIN-bound vault key and stores the bytes under the network's curve.
    /// The declared `alg` must agree with the network or nothing is stored.
    #[allow(clippy::too_many_arguments)]
    // Mirrors KeyManager::import's explicit delegation args (same rationale).
    pub fn import(
        &mut self,
        network: CryptoNetwork,
        alg: CoseAlgorithm,
        slot_id: u8,
        label: &str,
        created: u64,
        envelope: &[u8],
        pin_token: &[u8],
        presence_confirmed: bool,
        pin_authenticated: bool,
        vault: &AegisVault,
    ) -> Result<WalletRecord, WalletError> {
        if alg != network.cose_algorithm() {
            return Err(WalletError::BadEnvelope);
        }
        let slot = self.manager.import(
            slot_id,
            alg,
            Self::prefixed_label(label),
            KEY_USE_SIGN,
            created,
            envelope,
            pin_token,
            presence_confirmed,
            pin_authenticated,
            vault,
        )?;
        // Same rollback contract as generate: no orphan routing entry when
        // record_for fails (network_of needs the entry, so push-then-rollback
        // instead of push-after).
        let routing_len = self.networks.len();
        self.networks.push((slot_id, network));
        match self.record_for(slot.id, presence_confirmed) {
            Ok(record) => Ok(record),
            Err(e) => {
                self.networks.truncate(routing_len);
                Err(e)
            }
        }
    }

    /// GET (gate UP, inherited): metadata record with derived address.
    pub fn get(
        &self,
        slot_id: u8,
        presence_confirmed: bool,
    ) -> Result<WalletRecord, WalletError> {
        self.record_for(slot_id, presence_confirmed)
    }

    /// ADDRESS (gate UP, inherited): derived address for one slot.
    pub fn address(
        &self,
        slot_id: u8,
        presence_confirmed: bool,
    ) -> Result<String, WalletError> {
        Ok(self.record_for(slot_id, presence_confirmed)?.address)
    }

    /// PUBLIC COSE (gate UP, inherited): CBOR public key only, for the
    /// protocol layer to serve; never private bytes.
    pub fn public_cose(
        &self,
        slot_id: u8,
        presence_confirmed: bool,
    ) -> Result<Vec<u8>, WalletError> {
        Ok(self.manager.public_cose(slot_id, presence_confirmed)?)
    }

    /// SIGN (gate UP, inherited): signs a message (storage + message-sign
    /// only — no transactions are constructed here).
    pub fn sign(
        &mut self,
        slot_id: u8,
        message: &[u8],
        presence_confirmed: bool,
    ) -> Result<Vec<u8>, WalletError> {
        Ok(self.manager.sign(slot_id, message, presence_confirmed)?)
    }

    /// LIST (gate UP, inherited): metadata records only, never private bytes.
    pub fn list(&self, presence_confirmed: bool) -> Result<Vec<WalletRecord>, WalletError> {
        let slots = self.manager.list(presence_confirmed)?;
        let mut out = Vec::with_capacity(slots.len());
        for slot in &slots {
            out.push(self.record_for(slot.id, presence_confirmed)?);
        }
        Ok(out)
    }

    /// DELETE (gate UP+PIN, inherited): removes the slot, zeroizes the key
    /// via the manager, and drops the routing entry.
    pub fn delete(
        &mut self,
        slot_id: u8,
        presence_confirmed: bool,
        pin_authenticated: bool,
    ) -> Result<(), WalletError> {
        self.manager
            .delete(slot_id, presence_confirmed, pin_authenticated)?;
        self.networks.retain(|(id, _)| *id != slot_id);
        Ok(())
    }
}

impl Default for WalletStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{KeyManager, KEY_USE_SIGN};
    use crate::crypto::curves::CoseAlgorithm;
    use crate::crypto::{KeyPair, PublicKey};
    use crate::vault::AegisVault;

    const PIN: &[u8] = b"wallet-test-pin-token";
    const MSG: &[u8] = b"wallet message-sign assertion";

    fn btc_store() -> WalletStore {
        WalletStore::new()
    }

    #[test]
    fn should_generate_wallet_record_with_prefixed_label_and_address() {
        let mut rng = rand::rngs::OsRng;
        let mut store = btc_store();
        let rec = store
            .generate(CryptoNetwork::Bitcoin, 0, "savings", 1, true, &mut rng)
            .unwrap();
        assert_eq!(rec.slot_id, 0);
        assert_eq!(rec.network, CryptoNetwork::Bitcoin);
        assert_eq!(rec.label, "wallet:savings");
        assert!(rec.address.starts_with("bc1q"));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn should_never_touch_non_wallet_slots() {
        // B1: wallet owns a DEDICATED KeyManager; a foreign manager holding
        // FIDO2 slots must be bit-identical after wallet operations.
        let mut rng = rand::rngs::OsRng;
        let mut foreign = KeyManager::new();
        foreign
            .generate(0, CoseAlgorithm::ES256, String::from("fido"), KEY_USE_SIGN, 0, true, &mut rng)
            .unwrap();
        let mut store = btc_store();
        for id in 0..3u8 {
            store
                .generate(CryptoNetwork::Bitcoin, id, "w", 0, true, &mut rng)
                .unwrap();
        }
        assert_eq!(foreign.len(), 1);
        assert_eq!(foreign.list(true).unwrap()[0].label, String::from("fido"));
        assert!(foreign.sign(0, MSG, true).is_ok());
        for rec in store.list(true).unwrap() {
            assert!(rec.label.starts_with("wallet:"));
        }
    }

    #[test]
    fn should_require_up_for_generate_sign_list_get_and_address() {
        let mut rng = rand::rngs::OsRng;
        assert!(WalletStore::default().is_empty());
        let mut store = btc_store();
        assert_eq!(
            store
                .generate(CryptoNetwork::Bitcoin, 0, "x", 0, false, &mut rng)
                .unwrap_err(),
            WalletError::NeedUp
        );
        assert_eq!(store.list(false).unwrap_err(), WalletError::NeedUp);
        assert_eq!(store.get(0, false).unwrap_err(), WalletError::NeedUp);
        assert_eq!(store.address(0, false).unwrap_err(), WalletError::NeedUp);
        store
            .generate(CryptoNetwork::Bitcoin, 0, "x", 0, true, &mut rng)
            .unwrap();
        assert_eq!(
            store.sign(0, MSG, false).unwrap_err(),
            WalletError::NeedUp
        );
        assert_eq!(
            store.public_cose(0, false).unwrap_err(),
            WalletError::NeedUp
        );
    }

    #[test]
    fn should_require_up_and_pin_for_import_and_delete() {
        let mut rng = rand::rngs::OsRng;
        let vault = AegisVault::new([0x5Au8; 32]);
        let kp = KeyPair::generate(CoseAlgorithm::EdDSA, &mut rng).unwrap();
        let env = vault
            .seal_envelope(&kp.private_key_bytes(), PIN, &mut rng)
            .unwrap();
        let mut store = WalletStore::new();
        assert_eq!(
            store
                .import(CryptoNetwork::Solana, CoseAlgorithm::EdDSA, 0, "s", 0, &env, PIN, false, true, &vault)
                .unwrap_err(),
            WalletError::NeedUp
        );
        assert_eq!(
            store
                .import(CryptoNetwork::Solana, CoseAlgorithm::EdDSA, 0, "s", 0, &env, PIN, true, false, &vault)
                .unwrap_err(),
            WalletError::NeedPin
        );
        store
            .import(CryptoNetwork::Solana, CoseAlgorithm::EdDSA, 0, "s", 0, &env, PIN, true, true, &vault)
            .unwrap();
        assert_eq!(
            store.delete(0, true, false).unwrap_err(),
            WalletError::NeedPin
        );
        assert_eq!(
            store.delete(0, false, true).unwrap_err(),
            WalletError::NeedUp
        );
    }

    #[test]
    fn should_import_envelope_and_reject_wrong_pin_and_tampered() {
        let mut rng = rand::rngs::OsRng;
        let vault = AegisVault::new([0x5Au8; 32]);
        let kp = KeyPair::generate(CoseAlgorithm::EdDSA, &mut rng).unwrap();
        let env = vault
            .seal_envelope(&kp.private_key_bytes(), PIN, &mut rng)
            .unwrap();
        let mut store = WalletStore::new();
        assert_eq!(
            store
                .import(CryptoNetwork::Solana, CoseAlgorithm::EdDSA, 0, "s", 0, &env, b"wrong-pin", true, true, &vault)
                .unwrap_err(),
            WalletError::BadEnvelope
        );
        let mut tampered = env.clone();
        tampered[20] ^= 0x55;
        assert_eq!(
            store
                .import(CryptoNetwork::Solana, CoseAlgorithm::EdDSA, 1, "t", 0, &tampered, PIN, true, true, &vault)
                .unwrap_err(),
            WalletError::BadEnvelope
        );
        let rec = store
            .import(CryptoNetwork::Solana, CoseAlgorithm::EdDSA, 2, "s", 0, &env, PIN, true, true, &vault)
            .unwrap();
        assert_eq!(rec.slot_id, 2);
        assert_eq!(rec.network, CryptoNetwork::Solana);
        assert!(!rec.address.is_empty());
        // Declared alg disagreeing with the network stores nothing.
        assert_eq!(
            store
                .import(CryptoNetwork::Bitcoin, CoseAlgorithm::EdDSA, 3, "b", 0, &env, PIN, true, true, &vault)
                .unwrap_err(),
            WalletError::BadEnvelope
        );
        assert_eq!(store.get(3, true).unwrap_err(), WalletError::NoSlot);
    }

    #[test]
    fn should_fail_slot_exhaustion_at_32() {
        let mut rng = rand::rngs::OsRng;
        let mut store = WalletStore::new();
        for id in 0..32u8 {
            store
                .generate(CryptoNetwork::EthereumEvm, id, "e", 0, true, &mut rng)
                .unwrap();
        }
        assert_eq!(store.len(), 32);
        // No free id left: every in-range slot is occupied.
        assert_eq!(
            store
                .generate(CryptoNetwork::EthereumEvm, 0, "full", 0, true, &mut rng)
                .unwrap_err(),
            WalletError::NoSlot
        );
        // Out-of-range id rejected at the KeySlot bounds.
        assert_eq!(
            store
                .generate(CryptoNetwork::EthereumEvm, 32, "oob", 0, true, &mut rng)
                .unwrap_err(),
            WalletError::BadEnvelope
        );
    }

    #[test]
    fn should_sign_message_and_verify_with_derived_pubkey() {
        let mut rng = rand::rngs::OsRng;
        let mut store = WalletStore::new();
        store
            .generate(CryptoNetwork::EthereumEvm, 5, "sig", 0, true, &mut rng)
            .unwrap();
        let sig = store.sign(5, MSG, true).unwrap();
        assert!(!sig.is_empty());
        let cose = store.public_cose(5, true).unwrap();
        let pubkey = PublicKey::from_cose_cbor(&cose).unwrap();
        assert_eq!(pubkey.algorithm(), CoseAlgorithm::ES256K);
        assert!(pubkey.verify(MSG, &sig).is_ok());
        assert_eq!(store.get(5, true).unwrap().slot_id, 5);
    }

    #[test]
    fn should_delete_with_up_and_pin_and_free_the_slot() {
        let mut rng = rand::rngs::OsRng;
        let mut store = WalletStore::new();
        store
            .generate(CryptoNetwork::Solana, 9, "tmp", 0, true, &mut rng)
            .unwrap();
        store.delete(9, true, true).unwrap();
        assert!(store.is_empty());
        assert_eq!(store.get(9, true).unwrap_err(), WalletError::NoSlot);
        assert_eq!(store.sign(9, MSG, true).unwrap_err(), WalletError::NoSlot);
        // Slot is reusable after delete.
        let rec = store
            .generate(CryptoNetwork::Solana, 9, "again", 0, true, &mut rng)
            .unwrap();
        assert_eq!(rec.label, "wallet:again");
    }

    #[test]
    fn should_list_metadata_only_and_reject_overlong_label() {
        let mut rng = rand::rngs::OsRng;
        let mut store = WalletStore::new();
        store
            .generate(CryptoNetwork::Bitcoin, 0, "a", 0, true, &mut rng)
            .unwrap();
        store
            .generate(CryptoNetwork::Solana, 1, "b", 0, true, &mut rng)
            .unwrap();
        let items = store.list(true).unwrap();
        assert_eq!(items.len(), 2);
        assert!(items[0].address.starts_with("bc1"));
        assert!(!items[1].address.is_empty());
        let dbg = alloc::format!("{:?}", store);
        assert!(!dbg.contains("private"));
        // 26-char user label + 7-char "wallet:" prefix = 33 > 32B bound.
        let long = "01234567890123456789012345";
        assert_eq!(long.len(), 26);
        assert_eq!(
            store
                .generate(CryptoNetwork::Bitcoin, 2, long, 0, true, &mut rng)
                .unwrap_err(),
            WalletError::BadEnvelope
        );
    }
}
