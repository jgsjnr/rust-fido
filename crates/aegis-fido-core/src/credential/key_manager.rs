//! Fase6 -- KeyManager: thin in-RAM key-slot manager (BLE-protocol appendix 9).
//!
//! Only delegates to existing primitives, no new crypto:
//! - KeyPair::generate / from_private_key_bytes (5 curves)
//! - KeySlot::new bounds (9.2: label 1..32B, uso != 0)
//! - AegisVault::seal_envelope / open_envelope (AEGN envelope, PIN-bound)
//! - UpOnly / UpAndPin gates (9.4: GEN/LIST/SIGN = UP, IMPORT/DELETE = UP+PIN)
//! - saturating sign_count (existing journal pattern)
//!
//! Private bytes never appear in Debug output nor in LIST metadata (9.7).

use alloc::string::String;
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::credential::store::KeySlot;
use crate::crypto::curves::{CoseAlgorithm, KeyPair};
use crate::policy::{PolicyError, UpAndPin, UpOnly, UpPolicy};
use crate::vault::AegisVault;
#[cfg(feature = "debug-terminal")]
use crate::lifetime::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};

/// 9.5 closed status set (response wire [op:1, status:1, TLV...]).
pub const STATUS_OK: u8 = 0x00;
pub const STATUS_NEED_UP: u8 = 0x01;
pub const STATUS_NEED_PIN: u8 = 0x02;
pub const STATUS_NO_SLOT: u8 = 0x03;
pub const STATUS_BAD_ENVELOPE: u8 = 0x04;

/// KeyManager errors, one-to-one with the 9.5 statuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyManagerError {
    NeedUp,
    NeedPin,
    NoSlot,
    BadEnvelope,
}

impl KeyManagerError {
    /// Maps the error to its 9.5 wire status byte.
    pub fn status(self) -> u8 {
        match self {
            Self::NeedUp => STATUS_NEED_UP,
            Self::NeedPin => STATUS_NEED_PIN,
            Self::NoSlot => STATUS_NO_SLOT,
            Self::BadEnvelope => STATUS_BAD_ENVELOPE,
        }
    }
}

impl core::fmt::Display for KeyManagerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NeedUp => write!(f, "user presence required"),
            Self::NeedPin => write!(f, "PIN authentication required"),
            Self::NoSlot => write!(f, "key slot unavailable"),
            Self::BadEnvelope => write!(f, "bad key envelope"),
        }
    }
}

impl From<PolicyError> for KeyManagerError {
    fn from(e: PolicyError) -> Self {
        match e {
            PolicyError::PresenceRequired => Self::NeedUp,
            PolicyError::PinRequired => Self::NeedPin,
        }
    }
}

/// Stored private material, paired 1:1 with a KeySlot by slot id.
#[derive(Zeroize, ZeroizeOnDrop)]
struct KeyEntry {
    slot_id: u8,
    #[zeroize(skip)]
    alg: i32,
    private_key: Vec<u8>,
}

/// Thin key-slot manager. All crypto and policy decisions delegate.
pub struct KeyManager {
    slots: Vec<KeySlot>,
    secrets: Vec<KeyEntry>,
}

impl Drop for KeyManager {
    fn drop(&mut self) {
        crate::ltrace!(LtCat::KeySlot, LtEvt::KeyWipe, self.secrets.len());
        for s in self.secrets.iter_mut() {
            s.private_key.zeroize();
        }
    }
}

impl core::fmt::Debug for KeyManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyManager")
            .field("slots", &self.slots)
            .field("secrets_count", &self.secrets.len())
            .finish()
    }
}

impl KeyManager {
    /// Creates an empty manager.
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            secrets: Vec::new(),
        }
    }

    /// Number of occupied slots.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether any slot is occupied.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    fn slot_pos(&self, slot_id: u8) -> Option<usize> {
        self.slots.iter().position(|s| s.id == slot_id)
    }

    fn secret_pos(&self, slot_id: u8) -> Option<usize> {
        self.secrets.iter().position(|s| s.slot_id == slot_id)
    }

    /// GEN (gate UP): generates an on-device key, stores the private bytes,
    /// returns a metadata clone (never private).
    #[allow(clippy::too_many_arguments)]
    // Seven explicit delegation args kept visible at the call site.
    pub fn generate<R: RngCore + CryptoRng>(
        &mut self,
        slot_id: u8,
        alg: CoseAlgorithm,
        label: String,
        uso: u8,
        created: u64,
        presence_confirmed: bool,
        rng: &mut R,
    ) -> Result<KeySlot, KeyManagerError> {
        UpOnly.check_up(false, presence_confirmed)?;
        if self.slot_pos(slot_id).is_some() {
            return Err(KeyManagerError::NoSlot);
        }
        let slot = KeySlot::new(slot_id, alg.to_i32(), label, uso, created)
            .map_err(|_| KeyManagerError::BadEnvelope)?;
        let kp = KeyPair::generate(alg, rng).map_err(|_| KeyManagerError::BadEnvelope)?;
        self.slots.push(slot.clone());
        self.secrets.push(KeyEntry {
            slot_id,
            alg: alg.to_i32(),
            private_key: kp.private_key_bytes(),
        });
        crate::ltrace!(LtCat::KeySlot, LtEvt::KeyCreate, slot_id);
        Ok(slot)
    }

    /// IMPORT (gate UP+PIN): opens the AEGN envelope with the PIN-bound vault
    /// key, validates the private bytes against alg, stores, returns metadata.
    /// Unknown alg, bad label/uso, wrong PIN and tampered bytes all surface
    /// as BadEnvelope; occupied slot surfaces as NoSlot.
    #[allow(clippy::too_many_arguments)]
    // Ten explicit delegation args kept so gates/envelope/slot stay visible
    // at the call site instead of hiding behind a new params struct.
    pub fn import(
        &mut self,
        slot_id: u8,
        alg: CoseAlgorithm,
        label: String,
        uso: u8,
        created: u64,
        envelope: &[u8],
        pin_token: &[u8],
        presence_confirmed: bool,
        pin_authenticated: bool,
        vault: &AegisVault,
    ) -> Result<KeySlot, KeyManagerError> {
        UpAndPin.check_up(pin_authenticated, presence_confirmed)?;
        if self.slot_pos(slot_id).is_some() {
            return Err(KeyManagerError::NoSlot);
        }
        let mut plain = vault
            .open_envelope(envelope, pin_token)
            .map_err(|_| KeyManagerError::BadEnvelope)?;
        let kp = KeyPair::from_private_key_bytes(alg, &plain)
            .map_err(|_| KeyManagerError::BadEnvelope)?;
        plain.zeroize();
        let slot = KeySlot::new(slot_id, alg.to_i32(), label, uso, created)
            .map_err(|_| KeyManagerError::BadEnvelope)?;
        self.slots.push(slot.clone());
        self.secrets.push(KeyEntry {
            slot_id,
            alg: alg.to_i32(),
            private_key: kp.private_key_bytes(),
        });
        crate::ltrace!(LtCat::KeySlot, LtEvt::KeyCreate, slot_id);
        Ok(slot)
    }

    /// LIST (gate UP): metadata clones only, never private bytes.
    pub fn list(&self, presence_confirmed: bool) -> Result<Vec<KeySlot>, KeyManagerError> {
        UpOnly.check_up(false, presence_confirmed)?;
        Ok(self.slots.clone())
    }

    /// DELETE (gate UP+PIN): removes the slot and zeroizes private bytes.
    pub fn delete(
        &mut self,
        slot_id: u8,
        presence_confirmed: bool,
        pin_authenticated: bool,
    ) -> Result<(), KeyManagerError> {
        UpAndPin.check_up(pin_authenticated, presence_confirmed)?;
        let pos = self.slot_pos(slot_id).ok_or(KeyManagerError::NoSlot)?;
        self.slots.remove(pos);
        if let Some(spos) = self.secret_pos(slot_id) {
            self.secrets[spos].private_key.zeroize();
            self.secrets.remove(spos);
        }
        crate::ltrace!(LtCat::KeySlot, LtEvt::KeyDelete, slot_id);
        Ok(())
    }

    /// SIGN (gate UP): signs with the slot key, saturating sign_count bump.
    pub fn sign(
        &mut self,
        slot_id: u8,
        message: &[u8],
        presence_confirmed: bool,
    ) -> Result<Vec<u8>, KeyManagerError> {
        UpOnly.check_up(false, presence_confirmed)?;
        let spos = self.secret_pos(slot_id).ok_or(KeyManagerError::NoSlot)?;
        let alg = CoseAlgorithm::from_i32(self.secrets[spos].alg)
            .ok_or(KeyManagerError::BadEnvelope)?;
        let kp = KeyPair::from_private_key_bytes(alg, &self.secrets[spos].private_key)
            .map_err(|_| KeyManagerError::BadEnvelope)?;
        let sig = kp.sign(message).map_err(|_| KeyManagerError::BadEnvelope)?;
        if let Some(slot) = self.slots.iter_mut().find(|s| s.id == slot_id) {
            slot.increment_sign_count();
        }
        crate::ltrace!(LtCat::KeySlot, LtEvt::KeyUse, slot_id);
        Ok(sig)
    }

    /// Public COSE metadata (9.2 tag 0x03, gate UP): CBOR public key only.
    pub fn public_cose(
        &self,
        slot_id: u8,
        presence_confirmed: bool,
    ) -> Result<Vec<u8>, KeyManagerError> {
        UpOnly.check_up(false, presence_confirmed)?;
        let spos = self.secret_pos(slot_id).ok_or(KeyManagerError::NoSlot)?;
        let alg = CoseAlgorithm::from_i32(self.secrets[spos].alg)
            .ok_or(KeyManagerError::BadEnvelope)?;
        let kp = KeyPair::from_private_key_bytes(alg, &self.secrets[spos].private_key)
            .map_err(|_| KeyManagerError::BadEnvelope)?;
        Ok(kp.to_cose_cbor())
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::store::KEY_USE_SIGN;
    use crate::crypto::curves::PublicKey;

    const PIN: &[u8] = b"fase6-pin-token";
    const MSG: &[u8] = b"Fase6 KeyManager assertion 2026";

    fn five_curves() -> [CoseAlgorithm; 5] {
        [
            CoseAlgorithm::ES256,
            CoseAlgorithm::ES384,
            CoseAlgorithm::ES512,
            CoseAlgorithm::ES256K,
            CoseAlgorithm::EdDSA,
        ]
    }

    #[test]
    fn status_codes_match_spec_9_5() {
        assert_eq!(STATUS_OK, 0x00);
        assert_eq!(KeyManagerError::NeedUp.status(), STATUS_NEED_UP);
        assert_eq!(KeyManagerError::NeedPin.status(), STATUS_NEED_PIN);
        assert_eq!(KeyManagerError::NoSlot.status(), STATUS_NO_SLOT);
        assert_eq!(KeyManagerError::BadEnvelope.status(), STATUS_BAD_ENVELOPE);
        assert_eq!(KeyManagerError::NeedUp.status(), 0x01);
        assert_eq!(KeyManagerError::NeedPin.status(), 0x02);
        assert_eq!(KeyManagerError::NoSlot.status(), 0x03);
        assert_eq!(KeyManagerError::BadEnvelope.status(), 0x04);
    }

    #[test]
    fn gen_all_five_curves_and_sign() {
        let mut rng = rand::rngs::OsRng;
        let mut mgr = KeyManager::new();
        assert!(mgr.is_empty());
        for (i, &alg) in five_curves().iter().enumerate() {
            let label = alloc::format!("k{}", i);
            let slot = mgr
                .generate(i as u8, alg, label, KEY_USE_SIGN, i as u64, true, &mut rng)
                .unwrap();
            assert_eq!(slot.id, i as u8);
            assert_eq!(slot.alg, alg.to_i32());
        }
        assert_eq!(mgr.len(), 5);
        assert_eq!(mgr.list(true).unwrap().len(), 5);
        for (i, &alg) in five_curves().iter().enumerate() {
            let sig = mgr.sign(i as u8, MSG, true).unwrap();
            assert!(!sig.is_empty());
            let cose = mgr.public_cose(i as u8, true).unwrap();
            let pubkey = PublicKey::from_cose_cbor(&cose).unwrap();
            assert_eq!(pubkey.algorithm(), alg);
            assert!(pubkey.verify(MSG, &sig).is_ok());
        }
        for s in mgr.list(true).unwrap() {
            assert_eq!(s.sign_count, 1);
        }
    }

    #[test]
    fn import_ok_and_fail_pin() {
        let mut rng = rand::rngs::OsRng;
        let vault = AegisVault::new([0x5Au8; 32]);
        let kp = KeyPair::generate(CoseAlgorithm::ES256, &mut rng).unwrap();
        let env = vault
            .seal_envelope(&kp.private_key_bytes(), PIN, &mut rng)
            .unwrap();
        assert!(env.len() >= 33);
        let mut mgr = KeyManager::new();
        assert_eq!(
            mgr.import(0, CoseAlgorithm::ES256, String::from("imp"), KEY_USE_SIGN, 0, &env, PIN, false, true, &vault)
                .unwrap_err(),
            KeyManagerError::NeedUp
        );
        assert_eq!(
            mgr.import(0, CoseAlgorithm::ES256, String::from("imp"), KEY_USE_SIGN, 0, &env, PIN, true, false, &vault)
                .unwrap_err(),
            KeyManagerError::NeedPin
        );
        let slot = mgr
            .import(0, CoseAlgorithm::ES256, String::from("imp"), KEY_USE_SIGN, 0, &env, PIN, true, true, &vault)
            .unwrap();
        assert_eq!(slot.id, 0);
        assert_eq!(mgr.len(), 1);
        let sig = mgr.sign(0, MSG, true).unwrap();
        let cose = mgr.public_cose(0, true).unwrap();
        let pubkey = PublicKey::from_cose_cbor(&cose).unwrap();
        assert!(pubkey.verify(MSG, &sig).is_ok());
        let mut mgr2 = KeyManager::new();
        let err = mgr2
            .import(1, CoseAlgorithm::ES256, String::from("x"), KEY_USE_SIGN, 0, &env, b"wrong-pin-token", true, true, &vault)
            .unwrap_err();
        assert_eq!(err, KeyManagerError::BadEnvelope);
        assert_eq!(err.status(), STATUS_BAD_ENVELOPE);
        let mut tampered = env.clone();
        tampered[20] ^= 0x55;
        assert_eq!(
            mgr2.import(2, CoseAlgorithm::ES256, String::from("y"), KEY_USE_SIGN, 0, &tampered, PIN, true, true, &vault)
                .unwrap_err(),
            KeyManagerError::BadEnvelope
        );
        assert_eq!(
            mgr.import(0, CoseAlgorithm::ES256, String::from("dup"), KEY_USE_SIGN, 0, &env, PIN, true, true, &vault)
                .unwrap_err(),
            KeyManagerError::NoSlot
        );
    }

    #[test]
    fn delete_wipes_and_gates() {
        let mut rng = rand::rngs::OsRng;
        let mut mgr = KeyManager::new();
        mgr.generate(3, CoseAlgorithm::EdDSA, String::from("del"), KEY_USE_SIGN, 0, true, &mut rng)
            .unwrap();
        assert_eq!(mgr.len(), 1);
        assert_eq!(mgr.delete(3, true, false).unwrap_err(), KeyManagerError::NeedPin);
        assert_eq!(mgr.delete(3, false, true).unwrap_err(), KeyManagerError::NeedUp);
        assert_eq!(mgr.len(), 1);
        mgr.delete(3, true, true).unwrap();
        assert!(mgr.is_empty());
        assert_eq!(mgr.list(true).unwrap().len(), 0);
        assert_eq!(mgr.sign(3, MSG, true).unwrap_err(), KeyManagerError::NoSlot);
        assert_eq!(mgr.delete(3, true, true).unwrap_err(), KeyManagerError::NoSlot);
    }

    #[test]
    fn list_returns_metadata_only_and_requires_up() {
        let mut rng = rand::rngs::OsRng;
        let mut mgr = KeyManager::new();
        assert_eq!(mgr.list(false).unwrap_err(), KeyManagerError::NeedUp);
        assert_eq!(
            mgr.generate(0, CoseAlgorithm::ES256, String::from("k0"), KEY_USE_SIGN, 0, false, &mut rng)
                .unwrap_err(),
            KeyManagerError::NeedUp
        );
        mgr.generate(0, CoseAlgorithm::ES256, String::from("k0"), KEY_USE_SIGN, 0, true, &mut rng)
            .unwrap();
        let items = mgr.list(true).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, 0);
        assert_eq!(items[0].label, String::from("k0"));
        assert_eq!(items[0].alg, CoseAlgorithm::ES256.to_i32());
        let dbg = alloc::format!("{:?}", mgr);
        assert!(dbg.contains("k0"));
        assert!(!dbg.contains("private_key"));
    }
}