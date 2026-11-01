//! Secure End-to-End Channel for PIN and Vendor Commands (`GAP-02`)
//!
//! Hardened ephemeral ECDH P-256 + HKDF-SHA256 + Authenticated Stream Cipher channel
//! ensuring the Secure Guard PIN (`0x3B`) and sensitive credentials never travel in plaintext
//! across USB CDC, UART, or BLE transports.
//!
//! # Cryptographic Design
//! 1. **Ephemeral Key Agreement**: Device and host each generate ephemeral P-256 keypairs (`device_pub_key_sec1`, `host_pub_key_sec1`).
//! 2. **Shared Secret Derivation**: `shared_secret = ECDH(sk, pk_peer)` (32 bytes).
//! 3. **Key Expansion**: HKDF-SHA256 expands `shared_secret` into:
//!    - `enc_key` (32 bytes): Keystream generator for stream encryption.
//!    - `mac_key` (32 bytes): Key for HMAC-SHA256 authentication tag.
//! 4. **Authenticated Framing**: Every payload carries `nonce` (12 bytes), monotonic `counter` (4 bytes),
//!    and a 32-byte authentication tag verified strictly in constant time (`constant_time_eq_32`).
//! 5. **Anti-Replay**: Monotonic counter enforces strictly increasing sequence numbers.
//! 6. **Zeroization**: All ephemeral keys, shared secrets, and session keys are scrubbed with `Zeroize` on drop.

use alloc::vec::Vec;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ecdh::diffie_hellman, PublicKey, SecretKey};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::crypto::kdf::hkdf_sha256;
use crate::secure_guard::crypto::{constant_time_eq_32, hmac_sha256};
use crate::secure_guard::error::SecureGuardError;

/// Domain separation salt for Secure Guard ECDH session key derivation.
pub const SECURE_CHANNEL_HKDF_SALT: &[u8] = b"AegisKey-SecureGuard-EcdhChannel-v1";
/// Context information for HKDF-Expand.
pub const SECURE_CHANNEL_HKDF_INFO: &[u8] = b"pin-payload-encryption-and-mac";

/// Structure representing a sealed, authenticated PIN payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPinPayload {
    /// Encrypted ciphertext payload.
    pub ciphertext: Vec<u8>,
    /// 32-byte HMAC-SHA256 authentication tag.
    pub tag: [u8; 32],
    /// 12-byte initialization nonce.
    pub nonce: [u8; 12],
    /// Monotonic sequence counter.
    pub counter: u32,
}

/// Ephemeral ECDH Secure Channel for PIN and Vendor Commands (`GAP-02`).
pub struct SecureGuardEcdhChannel {
    private_key: SecretKey,
    public_key_sec1: [u8; 65],
    enc_key: [u8; 32],
    mac_key: [u8; 32],
    is_established: bool,
    last_seen_counter: u32,
}

impl core::fmt::Debug for SecureGuardEcdhChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecureGuardEcdhChannel")
            .field("public_key_sec1", &self.public_key_sec1)
            .field("is_established", &self.is_established)
            .field("last_seen_counter", &self.last_seen_counter)
            .finish()
    }
}

impl Drop for SecureGuardEcdhChannel {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
        self.public_key_sec1.zeroize();
    }
}

impl SecureGuardEcdhChannel {
    /// Generates a new ephemeral channel for the device side.
    pub fn new_device<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let private_key = SecretKey::random(rng);
        let public_key = private_key.public_key();
        let sec1 = Self::encode_public_key_sec1(&public_key);

        Self {
            private_key,
            public_key_sec1: sec1,
            enc_key: [0u8; 32],
            mac_key: [0u8; 32],
            is_established: false,
            last_seen_counter: 0,
        }
    }

    /// Generates a new ephemeral channel for the host side (used in clients, tests, or bridge).
    pub fn new_host<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::new_device(rng)
    }

    /// Creates an instance with an explicit 32-byte private key scalar (for deterministic bench tests).
    pub fn from_private_bytes(bytes: &[u8; 32]) -> Result<Self, SecureGuardError> {
        let private_key =
            SecretKey::from_slice(bytes).map_err(|_| SecureGuardError::InvalidEcdhKey)?;
        let public_key = private_key.public_key();
        let sec1 = Self::encode_public_key_sec1(&public_key);

        Ok(Self {
            private_key,
            public_key_sec1: sec1,
            enc_key: [0u8; 32],
            mac_key: [0u8; 32],
            is_established: false,
            last_seen_counter: 0,
        })
    }

    /// Encodes a P-256 public key into uncompressed 65-byte SEC1 format (`0x04 || X || Y`).
    fn encode_public_key_sec1(pubkey: &PublicKey) -> [u8; 65] {
        let point = pubkey.to_encoded_point(false);
        let bytes = point.as_bytes();
        let mut out = [0u8; 65];
        if bytes.len() == 65 {
            out.copy_from_slice(bytes);
        } else if let (Some(x), Some(y)) = (point.x(), point.y()) {
            out[0] = 0x04;
            out[1..33].copy_from_slice(x.as_ref());
            out[33..65].copy_from_slice(y.as_ref());
        }
        out
    }

    /// Returns the local ephemeral public key in 65-byte uncompressed SEC1 format.
    pub fn local_public_key_sec1(&self) -> [u8; 65] {
        self.public_key_sec1
    }

    /// Checks if the channel handshake has completed and session keys are established.
    pub fn is_established(&self) -> bool {
        self.is_established
    }

    /// Completes the ECDH key exchange with the peer's 65-byte SEC1 uncompressed public key.
    ///
    /// Derives `enc_key` (32 bytes) and `mac_key` (32 bytes) via HKDF-SHA256.
    pub fn complete_handshake(&mut self, peer_pub_key_sec1: &[u8; 65]) -> Result<(), SecureGuardError> {
        let peer_pub = PublicKey::from_sec1_bytes(peer_pub_key_sec1)
            .map_err(|_| SecureGuardError::InvalidEcdhKey)?;

        let shared = diffie_hellman(self.private_key.to_nonzero_scalar(), peer_pub.as_affine());
        let raw_secret = shared.raw_secret_bytes();
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(raw_secret.as_ref());

        // Derive 64 bytes: 32 bytes enc_key + 32 bytes mac_key
        let okm = hkdf_sha256(
            SECURE_CHANNEL_HKDF_SALT,
            &shared_secret,
            SECURE_CHANNEL_HKDF_INFO,
            64,
        )
        .map_err(|_| SecureGuardError::SecureChannelAuthFailed)?;

        self.enc_key.copy_from_slice(&okm[0..32]);
        self.mac_key.copy_from_slice(&okm[32..64]);
        self.is_established = true;
        self.last_seen_counter = 0;

        shared_secret.zeroize();
        Ok(())
    }

    /// Computes deterministic keystream for block index.
    fn compute_keystream_block(&self, nonce: &[u8; 12], counter: u32, block_index: u32) -> [u8; 32] {
        let mut data = [0u8; 20];
        data[0..12].copy_from_slice(nonce);
        data[12..16].copy_from_slice(&counter.to_be_bytes());
        data[16..20].copy_from_slice(&block_index.to_be_bytes());
        hmac_sha256(&self.enc_key, &data)
    }

    /// Encrypts or decrypts a buffer using authenticated stream XOR keystream.
    fn xor_stream(&self, input: &[u8], nonce: &[u8; 12], counter: u32) -> Vec<u8> {
        let mut output = Vec::with_capacity(input.len());
        for (i, chunk) in input.chunks(32).enumerate() {
            let keystream = self.compute_keystream_block(nonce, counter, i as u32);
            for (byte, key_byte) in chunk.iter().zip(keystream.iter()) {
                output.push(byte ^ key_byte);
            }
        }
        output
    }

    /// Computes 32-byte HMAC-SHA256 authentication tag over Associated Data:
    /// `nonce (12B) || counter (4B) || ciphertext`.
    fn compute_tag(&self, nonce: &[u8; 12], counter: u32, ciphertext: &[u8]) -> [u8; 32] {
        let mut ad = Vec::with_capacity(16 + ciphertext.len());
        ad.extend_from_slice(nonce);
        ad.extend_from_slice(&counter.to_be_bytes());
        ad.extend_from_slice(ciphertext);
        hmac_sha256(&self.mac_key, &ad)
    }

    /// Seals a PIN payload into ciphertext and authentication tag.
    ///
    /// # Arguments
    /// * `plaintext` - Secret PIN bytes (e.g. b"123456")
    /// * `nonce` - 12-byte cryptographic nonce
    /// * `counter` - Monotonically increasing sequence number
    pub fn seal_pin_payload(
        &mut self,
        plaintext: &[u8],
        nonce: &[u8; 12],
        counter: u32,
    ) -> Result<SealedPinPayload, SecureGuardError> {
        if !self.is_established {
            return Err(SecureGuardError::NoActiveSession);
        }

        // Anti-replay check
        if counter <= self.last_seen_counter && self.last_seen_counter != 0 {
            return Err(SecureGuardError::ReplayCounterInvalid);
        }
        self.last_seen_counter = counter;

        let ciphertext = self.xor_stream(plaintext, nonce, counter);
        let tag = self.compute_tag(nonce, counter, &ciphertext);

        Ok(SealedPinPayload {
            ciphertext,
            tag,
            nonce: *nonce,
            counter,
        })
    }

    /// Opens an encrypted PIN payload, validating the authentication tag in constant time.
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted PIN bytes
    /// * `tag` - 32-byte authentication tag
    /// * `nonce` - 12-byte cryptographic nonce
    /// * `counter` - Monotonically increasing sequence number
    pub fn open_pin_payload(
        &mut self,
        ciphertext: &[u8],
        tag: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
    ) -> Result<Vec<u8>, SecureGuardError> {
        if !self.is_established {
            return Err(SecureGuardError::NoActiveSession);
        }

        // Anti-replay check
        if counter <= self.last_seen_counter && self.last_seen_counter != 0 {
            return Err(SecureGuardError::ReplayCounterInvalid);
        }

        // Constant-time tag verification
        let expected_tag = self.compute_tag(nonce, counter, ciphertext);
        if !constant_time_eq_32(&expected_tag, tag) {
            return Err(SecureGuardError::SecureChannelAuthFailed);
        }

        self.last_seen_counter = counter;
        let plaintext = self.xor_stream(ciphertext, nonce, counter);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_ecdh_channel_handshake_and_roundtrip() {
        let mut rng = OsRng;

        // 1. Instantiate Device and Host channels
        let mut device_chan = SecureGuardEcdhChannel::new_device(&mut rng);
        let mut host_chan = SecureGuardEcdhChannel::new_host(&mut rng);

        let dev_pub = device_chan.local_public_key_sec1();
        let host_pub = host_chan.local_public_key_sec1();

        assert_eq!(dev_pub[0], 0x04);
        assert_eq!(host_pub[0], 0x04);

        // 2. Perform ECDH key exchange
        device_chan.complete_handshake(&host_pub).expect("device handshake");
        host_chan.complete_handshake(&dev_pub).expect("host handshake");

        assert!(device_chan.is_established());
        assert!(host_chan.is_established());
        assert_eq!(device_chan.enc_key, host_chan.enc_key);
        assert_eq!(device_chan.mac_key, host_chan.mac_key);

        // 3. Host seals PIN payload
        let pin = b"948201";
        let nonce = [0x77u8; 12];
        let counter = 1;
        let sealed = host_chan
            .seal_pin_payload(pin, &nonce, counter)
            .expect("host seal");

        assert_ne!(sealed.ciphertext.as_slice(), pin);
        assert_eq!(sealed.ciphertext.len(), pin.len());

        // 4. Device opens PIN payload
        let opened = device_chan
            .open_pin_payload(&sealed.ciphertext, &sealed.tag, &sealed.nonce, sealed.counter)
            .expect("device open");

        assert_eq!(opened.as_slice(), pin);
    }

    #[test]
    fn test_ecdh_channel_rejects_tampered_tag() {
        let mut rng = OsRng;
        let mut device_chan = SecureGuardEcdhChannel::new_device(&mut rng);
        let mut host_chan = SecureGuardEcdhChannel::new_host(&mut rng);

        device_chan.complete_handshake(&host_chan.local_public_key_sec1()).unwrap();
        host_chan.complete_handshake(&device_chan.local_public_key_sec1()).unwrap();

        let pin = b"123456";
        let nonce = [0x55u8; 12];
        let mut sealed = host_chan.seal_pin_payload(pin, &nonce, 1).unwrap();

        // Tamper with tag
        sealed.tag[0] ^= 0xFF;

        let err = device_chan.open_pin_payload(&sealed.ciphertext, &sealed.tag, &sealed.nonce, sealed.counter);
        assert_eq!(err, Err(SecureGuardError::SecureChannelAuthFailed));
    }

    #[test]
    fn test_ecdh_channel_rejects_replay() {
        let mut rng = OsRng;
        let mut device_chan = SecureGuardEcdhChannel::new_device(&mut rng);
        let mut host_chan = SecureGuardEcdhChannel::new_host(&mut rng);

        device_chan.complete_handshake(&host_chan.local_public_key_sec1()).unwrap();
        host_chan.complete_handshake(&device_chan.local_public_key_sec1()).unwrap();

        let pin = b"123456";
        let nonce = [0x55u8; 12];

        // First message with counter = 10
        let sealed1 = host_chan.seal_pin_payload(pin, &nonce, 10).unwrap();
        assert!(device_chan.open_pin_payload(&sealed1.ciphertext, &sealed1.tag, &sealed1.nonce, sealed1.counter).is_ok());

        // Replay of counter = 10 or lower must fail
        let sealed_replay = host_chan.seal_pin_payload(pin, &nonce, 5);
        assert_eq!(sealed_replay, Err(SecureGuardError::ReplayCounterInvalid));
    }
}
