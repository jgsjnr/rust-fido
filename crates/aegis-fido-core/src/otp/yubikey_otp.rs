extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;

use super::modhex;

pub const CRC_OK_RESIDUE: u16 = 0xF0B8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YubiOtpError {
    InvalidLength,
    InvalidModhex,
    InvalidCrc,
    InvalidUid,
    ReplayDetected,
    DecryptionError,
}

/// Compute ISO 13239 / YubiKey CRC-16
pub fn calculate_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// YubiKey OTP Decrypted Payload (16 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YubiOtpPayload {
    pub uid: [u8; 6],
    pub use_counter: u16,
    pub timestamp_low: u16,
    pub timestamp_high: u8,
    pub session_counter: u8,
    pub random_number: u16,
    pub crc: u16,
}

impl YubiOtpPayload {
    pub fn new(
        uid: [u8; 6],
        use_counter: u16,
        timestamp_low: u16,
        timestamp_high: u8,
        session_counter: u8,
        random_number: u16,
    ) -> Self {
        let mut payload = Self {
            uid,
            use_counter,
            timestamp_low,
            timestamp_high,
            session_counter,
            random_number,
            crc: 0,
        };
        let bytes_14 = payload.to_bytes_unchecksummed();
        let crc = calculate_crc(&bytes_14);
        payload.crc = !crc;
        payload
    }

    fn to_bytes_unchecksummed(&self) -> [u8; 14] {
        let mut b = [0u8; 14];
        b[0..6].copy_from_slice(&self.uid);
        b[6..8].copy_from_slice(&self.use_counter.to_le_bytes());
        b[8..10].copy_from_slice(&self.timestamp_low.to_le_bytes());
        b[10] = self.timestamp_high;
        b[11] = self.session_counter;
        b[12..14].copy_from_slice(&self.random_number.to_le_bytes());
        b
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..14].copy_from_slice(&self.to_bytes_unchecksummed());
        b[14..16].copy_from_slice(&self.crc.to_le_bytes());
        b
    }

    pub fn from_bytes(bytes: &[u8; 16]) -> Result<Self, YubiOtpError> {
        if calculate_crc(bytes) != CRC_OK_RESIDUE {
            return Err(YubiOtpError::InvalidCrc);
        }

        let mut uid = [0u8; 6];
        uid.copy_from_slice(&bytes[0..6]);

        let use_counter = u16::from_le_bytes([bytes[6], bytes[7]]);
        let timestamp_low = u16::from_le_bytes([bytes[8], bytes[9]]);
        let timestamp_high = bytes[10];
        let session_counter = bytes[11];
        let random_number = u16::from_le_bytes([bytes[12], bytes[13]]);
        let crc = u16::from_le_bytes([bytes[14], bytes[15]]);

        Ok(Self {
            uid,
            use_counter,
            timestamp_low,
            timestamp_high,
            session_counter,
            random_number,
            crc,
        })
    }
}

/// YubiKey OTP Generator State
#[derive(Debug, Clone)]
pub struct YubiOtpGenerator {
    pub public_id: Vec<u8>,
    pub private_id: [u8; 6],
    pub aes_key: [u8; 16],
    pub use_counter: u16,
    pub session_counter: u8,
    pub timestamp_low: u16,
    pub timestamp_high: u8,
}

impl YubiOtpGenerator {
    pub fn new(public_id: &[u8], private_id: [u8; 6], aes_key: [u8; 16]) -> Self {
        Self {
            public_id: public_id.to_vec(),
            private_id,
            aes_key,
            use_counter: 1,
            session_counter: 0,
            timestamp_low: 0,
            timestamp_high: 0,
        }
    }

    /// Advance the timer tick (8Hz internal clock)
    pub fn advance_timer(&mut self, ticks: u32) {
        let current = ((self.timestamp_high as u32) << 16) | (self.timestamp_low as u32);
        let next = current.wrapping_add(ticks);
        self.timestamp_low = (next & 0xFFFF) as u16;
        self.timestamp_high = ((next >> 16) & 0xFF) as u8;
    }

    /// Increment boot/power cycle use counter
    pub fn increment_use_counter(&mut self) {
        self.use_counter = self.use_counter.saturating_add(1);
        self.session_counter = 0;
    }

    /// Generate next YubiKey OTP token string (Modhex public ID + Modhex encrypted token)
    pub fn generate_token(&mut self, random_nonce: u16) -> String {
        self.session_counter = self.session_counter.wrapping_add(1);

        let payload = YubiOtpPayload::new(
            self.private_id,
            self.use_counter,
            self.timestamp_low,
            self.timestamp_high,
            self.session_counter,
            random_nonce,
        );

        let payload_bytes = payload.to_bytes();
        let cipher = Aes128::new(GenericArray::from_slice(&self.aes_key));
        let mut block = GenericArray::clone_from_slice(&payload_bytes);
        cipher.encrypt_block(&mut block);

        let mut token = modhex::encode(&self.public_id);
        token.push_str(&modhex::encode(&block[..]));
        token
    }

    /// Decrypt and validate an OTP token string with this generator's key
    pub fn verify_token(
        &self,
        token: &str,
        expected_public_id: Option<&[u8]>,
    ) -> Result<YubiOtpPayload, YubiOtpError> {
        if token.len() < 32 {
            return Err(YubiOtpError::InvalidLength);
        }

        let prefix_len = token.len() - 32;
        let (prefix_str, ciphertext_str) = token.split_at(prefix_len);

        if let Some(exp_pub) = expected_public_id {
            let actual_pub = modhex::decode(prefix_str).map_err(|_| YubiOtpError::InvalidModhex)?;
            if actual_pub != exp_pub {
                return Err(YubiOtpError::InvalidUid);
            }
        }

        let cipher_bytes = modhex::decode(ciphertext_str).map_err(|_| YubiOtpError::InvalidModhex)?;
        if cipher_bytes.len() != 16 {
            return Err(YubiOtpError::InvalidLength);
        }

        let cipher = Aes128::new(GenericArray::from_slice(&self.aes_key));
        let mut block = GenericArray::clone_from_slice(&cipher_bytes);
        cipher.decrypt_block(&mut block);

        let mut payload_bytes = [0u8; 16];
        payload_bytes.copy_from_slice(&block[..]);

        let payload = YubiOtpPayload::from_bytes(&payload_bytes)?;
        if payload.uid != self.private_id {
            return Err(YubiOtpError::InvalidUid);
        }

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yubikey_otp_generation_and_verification() {
        let public_id = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]; // 6 bytes
        let private_id = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let aes_key = [0x42u8; 16];

        let mut generator = YubiOtpGenerator::new(&public_id, private_id, aes_key);
        generator.advance_timer(256);

        let token = generator.generate_token(0x1234);
        assert_eq!(token.len(), 12 + 32); // 44 chars

        // Verify valid token
        let verified = generator.verify_token(&token, Some(&public_id)).unwrap();
        assert_eq!(verified.uid, private_id);
        assert_eq!(verified.use_counter, 1);
        assert_eq!(verified.session_counter, 1);
        assert_eq!(verified.random_number, 0x1234);

        // Verification with wrong key fails
        let wrong_gen = YubiOtpGenerator::new(&public_id, private_id, [0x00; 16]);
        assert!(wrong_gen.verify_token(&token, Some(&public_id)).is_err());
    }
}
