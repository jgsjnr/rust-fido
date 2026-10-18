extern crate alloc;

use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::oath::presence::{PresenceError, PresenceVerifier};

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotIndex {
    Slot1 = 1,
    Slot2 = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeResponseError {
    SlotNotConfigured,
    TouchRequired,
    TouchTimeout,
    InvalidChallengeLength,
    CryptoError,
}

/// Configuration for a YubiKey Challenge-Response slot
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeResponseSlot {
    pub key: Vec<u8>,
    pub require_touch: bool,
    pub is_configured: bool,
}

impl Default for ChallengeResponseSlot {
    fn default() -> Self {
        Self {
            key: Vec::new(),
            require_touch: false,
            is_configured: false,
        }
    }
}

impl ChallengeResponseSlot {
    pub fn new(key: &[u8], require_touch: bool) -> Self {
        Self {
            key: key.to_vec(),
            require_touch,
            is_configured: true,
        }
    }

    /// Process a challenge and return the 20-byte HMAC-SHA1 response
    pub fn calculate<P: PresenceVerifier>(
        &self,
        challenge: &[u8],
        presence: &mut P,
    ) -> Result<[u8; 20], ChallengeResponseError> {
        if !self.is_configured {
            return Err(ChallengeResponseError::SlotNotConfigured);
        }

        if self.require_touch {
            match presence.wait_for_presence(3000) {
                Ok(true) => {}
                Ok(false) => return Err(ChallengeResponseError::TouchRequired),
                Err(PresenceError::Timeout) => return Err(ChallengeResponseError::TouchTimeout),
                Err(_) => return Err(ChallengeResponseError::TouchRequired),
            }
        }

        let mut mac = HmacSha1::new_from_slice(&self.key)
            .map_err(|_| ChallengeResponseError::CryptoError)?;
        mac.update(challenge);
        let result = mac.finalize().into_bytes();

        let mut resp = [0u8; 20];
        resp.copy_from_slice(&result);
        Ok(resp)
    }
}

/// Dual-slot Challenge-Response Manager (Slot 1 & Slot 2)
#[derive(Debug, Clone, Default)]
pub struct ChallengeResponseManager {
    pub slot1: ChallengeResponseSlot,
    pub slot2: ChallengeResponseSlot,
}

impl ChallengeResponseManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn configure_slot(&mut self, slot: SlotIndex, key: &[u8], require_touch: bool) {
        let slot_ref = match slot {
            SlotIndex::Slot1 => &mut self.slot1,
            SlotIndex::Slot2 => &mut self.slot2,
        };
        *slot_ref = ChallengeResponseSlot::new(key, require_touch);
    }

    pub fn clear_slot(&mut self, slot: SlotIndex) {
        let slot_ref = match slot {
            SlotIndex::Slot1 => &mut self.slot1,
            SlotIndex::Slot2 => &mut self.slot2,
        };
        *slot_ref = ChallengeResponseSlot::default();
    }

    pub fn process_challenge<P: PresenceVerifier>(
        &self,
        slot: SlotIndex,
        challenge: &[u8],
        presence: &mut P,
    ) -> Result<[u8; 20], ChallengeResponseError> {
        match slot {
            SlotIndex::Slot1 => self.slot1.calculate(challenge, presence),
            SlotIndex::Slot2 => self.slot2.calculate(challenge, presence),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oath::presence::{AlwaysPresentVerifier, NeverPresentVerifier};

    #[test]
    fn test_challenge_response_hmac_sha1() {
        let mut manager = ChallengeResponseManager::new();
        let key = b"01234567890123456789"; // 20-byte key
        manager.configure_slot(SlotIndex::Slot1, key, false);

        let challenge = b"test_challenge_123";
        let mut presence = AlwaysPresentVerifier;

        let resp = manager
            .process_challenge(SlotIndex::Slot1, challenge, &mut presence)
            .unwrap();

        // Verify against independent HMAC-SHA1 calculation
        let mut mac = HmacSha1::new_from_slice(key).unwrap();
        mac.update(challenge);
        let expected = mac.finalize().into_bytes();
        assert_eq!(&resp[..], &expected[..]);
    }

    #[test]
    fn test_challenge_response_touch_required() {
        let mut manager = ChallengeResponseManager::new();
        let key = b"secret_key_slot2_test";
        manager.configure_slot(SlotIndex::Slot2, key, true); // require touch

        let challenge = b"challenge_payload";
        let mut no_touch = NeverPresentVerifier;

        // Fails when touch is not satisfied
        let res = manager.process_challenge(SlotIndex::Slot2, challenge, &mut no_touch);
        assert_eq!(res, Err(ChallengeResponseError::TouchTimeout));

        // Succeeds when touch is confirmed
        let mut touch = AlwaysPresentVerifier;
        let res2 = manager.process_challenge(SlotIndex::Slot2, challenge, &mut touch);
        assert!(res2.is_ok());
    }
}
