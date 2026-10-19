//! Aegis Vault (Passkey Vault) Engine
//!
//! 100% Native Rust implementation for ESP32-S3:
//! - Secure Resident & Discoverable Passkey management
//! - Hardware-backed sealing via AES-256-GCM
//! - Authenticated Import & Export Protocol:
//!   * Ephemeral P-256 ECDH key agreement
//!   * Session key derivation via HKDF-SHA256 bound to PIN token
//!   * Authenticated payload envelope with AES-256-GCM and strict AAD validation
//! - Zeroize memory clearing for master keys and private scalar material

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{PublicKey as P256PublicKey, EncodedPoint as P256EncodedPoint};

pub mod policy;
pub mod secrets;
pub mod store;
pub use policy::VaultPolicy;
pub use secrets::VaultSecrets;
pub use store::VaultStore;
use crate::crypto::aead::{aes_256_gcm_decrypt, aes_256_gcm_encrypt, open_blob, seal_blob, AeadError};
use crate::crypto::curves::{CoseAlgorithm, CryptoError, KeyPair, PublicKey};
use crate::crypto::kdf::{hkdf_sha256, KdfError};

/// Fase6 -- PIN-bound envelope constants (BLE-protocol 5: AEGN|0x01|NONCE12|CT+TAG, min 33B; 9.2 tag 0x04 opaco).
pub const VAULT_ENVELOPE_MAGIC: [u8; 4] = [0x41, 0x45, 0x47, 0x4E];
pub const VAULT_ENVELOPE_VERSION: u8 = 0x01;
pub const VAULT_ENVELOPE_MIN_LEN: usize = 4 + 1 + 12 + 16;
pub const VAULT_ENVELOPE_INFO: &[u8] = b"Aegis-Vault-Envelope-v1";
pub const VAULT_ENVELOPE_AAD: &[u8] = b"Aegis-Vault-Envelope-v1";

#[derive(Debug)]
pub enum VaultError {
    CryptoError(CryptoError),
    AeadError(AeadError),
    KdfError(KdfError),
    SerializationError(String),
    AuthenticationFailed,
    InvalidPublicKey,
    PasskeyNotFound,
    DuplicatePasskey,
    InvalidPayload,
}

impl core::fmt::Display for VaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CryptoError(e) => write!(f, "Crypto error: {}", e),
            Self::AeadError(e) => write!(f, "AEAD error: {}", e),
            Self::KdfError(e) => write!(f, "KDF error: {}", e),
            Self::SerializationError(s) => write!(f, "Serialization error: {}", s),
            Self::AuthenticationFailed => write!(f, "Vault authentication failed (tag mismatch or invalid PIN token)"),
            Self::InvalidPublicKey => write!(f, "Invalid P-256 public key for ECDH agreement"),
            Self::PasskeyNotFound => write!(f, "Passkey credential ID not found"),
            Self::DuplicatePasskey => write!(f, "Passkey with this credential ID already exists"),
            Self::InvalidPayload => write!(f, "Invalid vault envelope payload format"),
        }
    }
}

impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        Self::CryptoError(e)
    }
}

impl From<AeadError> for VaultError {
    fn from(e: AeadError) -> Self {
        Self::AeadError(e)
    }
}

impl From<KdfError> for VaultError {
    fn from(e: KdfError) -> Self {
        Self::KdfError(e)
    }
}

/// Represents a single stored Passkey in the Aegis Vault.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultPasskey {
    #[zeroize(skip)]
    pub credential_id: Vec<u8>,
    #[zeroize(skip)]
    pub rp_id: String,
    #[zeroize(skip)]
    pub rp_name: Option<String>,
    #[zeroize(skip)]
    pub user_id: Vec<u8>,
    #[zeroize(skip)]
    pub user_name: String,
    #[zeroize(skip)]
    pub user_display_name: String,
    #[zeroize(skip)]
    pub algorithm: i32,
    pub private_key: Vec<u8>,
    #[zeroize(skip)]
    pub sign_count: u32,
    #[zeroize(skip)]
    pub created_at: u64,
    #[zeroize(skip)]
    pub uv_required: bool,
    #[zeroize(skip)]
    pub backup_eligible: bool,
    #[zeroize(skip)]
    pub backup_state: bool,
}

impl core::fmt::Debug for VaultPasskey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultPasskey")
            .field("credential_id", &hex::encode(&self.credential_id))
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("algorithm", &self.algorithm)
            .field("sign_count", &self.sign_count)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl VaultPasskey {
    /// Reconstructs the cryptographic KeyPair for signing.
    pub fn key_pair(&self) -> Result<KeyPair, CryptoError> {
        let alg = CoseAlgorithm::from_i32(self.algorithm)
            .ok_or(CryptoError::UnsupportedAlgorithm(self.algorithm))?;
        KeyPair::from_private_key_bytes(alg, &self.private_key)
    }

    /// Derives the public key.
    pub fn public_key(&self) -> Result<PublicKey, CryptoError> {
        self.key_pair().map(|kp| kp.public_key())
    }

    /// Signs an assertion payload and increments the sign counter.
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let kp = self.key_pair()?;
        let sig = kp.sign(message)?;
        self.sign_count = self.sign_count.saturating_add(1);
        Ok(sig)
    }
}

/// Serialized payload container for passkeys import / export.
#[derive(Serialize, Deserialize)]
pub struct VaultPayload {
    pub version: u32,
    pub export_timestamp: u64,
    pub passkeys: Vec<VaultPasskey>,
}

/// Authenticated Export Package returned to client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultExportPackage {
    pub auth_ephemeral_pubkey: Vec<u8>,
    pub nonce: [u8; 12],
    pub ciphertext_and_tag: Vec<u8>,
}

/// Aegis Passkey Vault Engine.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AegisVault {
    master_key: [u8; 32],
    #[zeroize(skip)]
    passkeys: Vec<VaultPasskey>,
}

impl core::fmt::Debug for AegisVault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AegisVault")
            .field("passkeys_count", &self.passkeys.len())
            .field("master_key", &"[REDACTED]")
            .finish()
    }
}

impl AegisVault {
    /// Initializes a new vault with a given 256-bit master key.
    pub fn new(master_key: [u8; 32]) -> Self {
        Self {
            master_key,
            passkeys: Vec::new(),
        }
    }

    /// Initializes vault deriving master key from a 512-bit (64 bytes) BIP-39 seed.
    pub fn from_master_seed(seed: &[u8; 64]) -> Result<Self, VaultError> {
        let salt = b"AegisKey-Vault-Master-Salt-v1";
        let info = b"AegisKey-Vault-Master-Key-v1";
        let key_vec = hkdf_sha256(salt, seed, info, 32)?;
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&key_vec);
        Ok(Self::new(master_key))
    }

    /// Returns the number of passkeys stored in the vault.
    pub fn len(&self) -> usize {
        self.passkeys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.passkeys.is_empty()
    }

    /// Stores a new passkey. Replaces existing passkey if credential ID matches.
    pub fn put(&mut self, passkey: VaultPasskey) {
        if let Some(pos) = self.passkeys.iter().position(|p| p.credential_id == passkey.credential_id) {
            self.passkeys[pos] = passkey;
        } else {
            self.passkeys.push(passkey);
        }
    }

    /// Retrieves a passkey reference by credential ID.
    pub fn get(&self, credential_id: &[u8]) -> Option<&VaultPasskey> {
        self.passkeys.iter().find(|p| p.credential_id == credential_id)
    }

    /// Retrieves a mutable passkey reference by credential ID.
    pub fn get_mut(&mut self, credential_id: &[u8]) -> Option<&mut VaultPasskey> {
        self.passkeys.iter_mut().find(|p| p.credential_id == credential_id)
    }

    /// Deletes a passkey by credential ID. Returns true if found and removed.
    pub fn delete(&mut self, credential_id: &[u8]) -> bool {
        if let Some(pos) = self.passkeys.iter().position(|p| p.credential_id == credential_id) {
            self.passkeys.remove(pos);
            true
        } else {
            false
        }
    }

    /// Finds all passkeys matching a Relying Party ID.
    pub fn find_by_rp(&self, rp_id: &str) -> Vec<&VaultPasskey> {
        self.passkeys.iter().filter(|p| p.rp_id == rp_id).collect()
    }

    /// Seals the entire vault storage to an encrypted blob using master key.
    pub fn seal_to_blob<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Vec<u8>, VaultError> {
        let payload = VaultPayload {
            version: 1,
            export_timestamp: 0,
            passkeys: self.passkeys.clone(),
        };

        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&payload, &mut cbor_bytes)
            .map_err(|e| VaultError::SerializationError(format!("{:?}", e)))?;

        let aad = b"Aegis-Vault-Storage-v1";
        let blob = seal_blob(&self.master_key, &cbor_bytes, aad, rng)?;
        Ok(blob)
    }

    /// Loads vault storage from a sealed blob, decrypting with master key.
    pub fn load_from_blob(&mut self, blob: &[u8]) -> Result<usize, VaultError> {
        let aad = b"Aegis-Vault-Storage-v1";
        let cbor_bytes = open_blob(&self.master_key, blob, aad)?;

        let payload: VaultPayload = ciborium::from_reader(cbor_bytes.as_slice())
            .map_err(|e| VaultError::SerializationError(format!("{:?}", e)))?;

        let count = payload.passkeys.len();
        self.passkeys = payload.passkeys;
        Ok(count)
    }

    /// Authenticated Export Protocol:
    /// 1. Client provides their ephemeral P-256 public key (SEC1 65 bytes uncompressed).
    /// 2. Vault generates its ephemeral P-256 key pair.
    /// 3. Computes ECDH shared secret: Z = ECDH(sk_auth, pk_client).
    /// 4. Derives session encryption key: K_enc = HKDF-SHA256(salt = pin_token, IKM = Z, info = "Aegis-Vault-Export-v1", 32).
    /// 5. Encrypts CBOR serialized passkeys with AES-256-GCM using K_enc and random nonce.
    /// 6. Returns VaultExportPackage containing auth public key, nonce, and ciphertext+tag.
    pub fn export_authenticated<R: RngCore + CryptoRng>(
        &self,
        client_pubkey_sec1: &[u8],
        pin_token: &[u8],
        export_timestamp: u64,
        rng: &mut R,
    ) -> Result<VaultExportPackage, VaultError> {
        // Parse client ephemeral public key
        let client_point = P256EncodedPoint::from_bytes(client_pubkey_sec1)
            .map_err(|_| VaultError::InvalidPublicKey)?;
        let client_pub = Option::<P256PublicKey>::from(P256PublicKey::from_encoded_point(&client_point))
            .ok_or(VaultError::InvalidPublicKey)?;

        // Generate authenticator ephemeral P-256 key pair
        let auth_secret = p256::ecdh::EphemeralSecret::random(rng);
        let auth_pub = auth_secret.public_key();
        let auth_pub_bytes = auth_pub.to_encoded_point(false).as_bytes().to_vec();

        // Perform ECDH key agreement
        let shared_secret = auth_secret.diffie_hellman(&client_pub);
        let z = shared_secret.raw_secret_bytes();

        // Derive session key via HKDF-SHA256 bound to pin_token
        let salt = pin_token;
        let info = b"Aegis-Vault-Export-Session-v1";
        let session_key_vec = hkdf_sha256(salt, z.as_slice(), info, 32)?;
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&session_key_vec);

        // Serialize passkeys payload to CBOR
        let payload = VaultPayload {
            version: 1,
            export_timestamp,
            passkeys: self.passkeys.clone(),
        };
        let mut cbor_data = Vec::new();
        ciborium::into_writer(&payload, &mut cbor_data)
            .map_err(|e| VaultError::SerializationError(format!("{:?}", e)))?;

        // Encrypt with AES-256-GCM using AAD bound to both public keys
        let mut aad = Vec::new();
        aad.extend_from_slice(b"Aegis-Vault-Auth-v1:");
        aad.extend_from_slice(&auth_pub_bytes);
        aad.extend_from_slice(client_pubkey_sec1);

        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);

        let ciphertext_and_tag = aes_256_gcm_encrypt(&session_key, &nonce, &cbor_data, &aad)
            .map_err(|_| VaultError::AuthenticationFailed)?;

        session_key.zeroize();

        Ok(VaultExportPackage {
            auth_ephemeral_pubkey: auth_pub_bytes,
            nonce,
            ciphertext_and_tag,
        })
    }

    /// Authenticated Import Protocol:
    /// 1. Client provides VaultExportPackage (auth ephemeral public key, nonce, ciphertext+tag)
    ///    plus client's ephemeral secret key and pin_token.
    /// 2. Performs ECDH(client_sk, auth_pk).
    /// 3. Derives identical K_enc via HKDF-SHA256.
    /// 4. Decrypts and validates AES-256-GCM envelope in constant time.
    /// 5. Deserializes passkeys and merges into vault.
    pub fn import_authenticated(
        &mut self,
        package: &VaultExportPackage,
        client_secret: &p256::ecdh::EphemeralSecret,
        client_pubkey_sec1: &[u8],
        pin_token: &[u8],
    ) -> Result<usize, VaultError> {
        // Parse authenticator ephemeral public key
        let auth_point = P256EncodedPoint::from_bytes(&package.auth_ephemeral_pubkey)
            .map_err(|_| VaultError::InvalidPublicKey)?;
        let auth_pub = Option::<P256PublicKey>::from(P256PublicKey::from_encoded_point(&auth_point))
            .ok_or(VaultError::InvalidPublicKey)?;

        // Compute ECDH shared secret
        let shared_secret = client_secret.diffie_hellman(&auth_pub);
        let z = shared_secret.raw_secret_bytes();

        // Derive session key
        let salt = pin_token;
        let info = b"Aegis-Vault-Export-Session-v1";
        let session_key_vec = hkdf_sha256(salt, z.as_slice(), info, 32)?;
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&session_key_vec);

        // Reconstruct AAD
        let mut aad = Vec::new();
        aad.extend_from_slice(b"Aegis-Vault-Auth-v1:");
        aad.extend_from_slice(&package.auth_ephemeral_pubkey);
        aad.extend_from_slice(client_pubkey_sec1);

        // Decrypt AES-256-GCM envelope
        let decrypted_cbor = aes_256_gcm_decrypt(&session_key, &package.nonce, &package.ciphertext_and_tag, &aad)
            .map_err(|_| VaultError::AuthenticationFailed)?;

        session_key.zeroize();

        // Parse CBOR payload
        let payload: VaultPayload = ciborium::from_reader(decrypted_cbor.as_slice())
            .map_err(|e| VaultError::SerializationError(format!("{:?}", e)))?;

        let imported_count = payload.passkeys.len();
        for passkey in payload.passkeys {
            self.put(passkey);
        }

        Ok(imported_count)
    }

    /// Fase6 -- PIN-bound envelope seal (AEGN|0x01|NONCE12|CT+TAG, min 33B).
    ///
    /// Derives K_enc = HKDF-SHA256(salt = pin_token, IKM = master_key,
    /// info = VAULT_ENVELOPE_INFO, 32) and seals plaintext with AES-256-GCM
    /// (AAD = VAULT_ENVELOPE_AAD). Session key is zeroized before return.
    pub fn seal_envelope<R: RngCore + CryptoRng>(
        &self,
        plaintext: &[u8],
        pin_token: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, VaultError> {
        let session_vec = hkdf_sha256(pin_token, &self.master_key, VAULT_ENVELOPE_INFO, 32)?;
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&session_vec);
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        let ct = aes_256_gcm_encrypt(&session_key, &nonce, plaintext, VAULT_ENVELOPE_AAD)
            .map_err(|_| VaultError::AuthenticationFailed)?;
        session_key.zeroize();
        let mut env = Vec::with_capacity(4 + 1 + 12 + ct.len());
        env.extend_from_slice(&VAULT_ENVELOPE_MAGIC);
        env.push(VAULT_ENVELOPE_VERSION);
        env.extend_from_slice(&nonce);
        env.extend_from_slice(&ct);
        Ok(env)
    }

    /// Fase6 -- PIN-bound envelope open. Validates magic AEGN, version 0x01
    /// and minimum length 33B, then derives the same K_enc and decrypts.
    /// Wrong PIN or tampered bytes map to AuthenticationFailed; malformed
    /// envelope maps to InvalidPayload. Session key zeroized.
    pub fn open_envelope(
        &self,
        envelope: &[u8],
        pin_token: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        if envelope.len() < VAULT_ENVELOPE_MIN_LEN {
            return Err(VaultError::InvalidPayload);
        }
        if envelope[0..4] != VAULT_ENVELOPE_MAGIC || envelope[4] != VAULT_ENVELOPE_VERSION {
            return Err(VaultError::InvalidPayload);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&envelope[5..17]);
        let ct = &envelope[17..];
        let session_vec = hkdf_sha256(pin_token, &self.master_key, VAULT_ENVELOPE_INFO, 32)?;
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&session_vec);
        let pt = aes_256_gcm_decrypt(&session_key, &nonce, ct, VAULT_ENVELOPE_AAD)
            .map_err(|_| VaultError::AuthenticationFailed)?;
        session_key.zeroize();
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aegis_vault_full_lifecycle() {
        let mut rng = rand::rngs::OsRng;

        // 1. Initialize vault from 64-byte master seed
        let seed = [0xa5u8; 64];
        let mut vault = AegisVault::from_master_seed(&seed).unwrap();
        assert_eq!(vault.len(), 0);

        // 2. Add passkeys for each of the 5 curves
        let test_curves = [
            CoseAlgorithm::ES256,
            CoseAlgorithm::ES384,
            CoseAlgorithm::ES512,
            CoseAlgorithm::ES256K,
            CoseAlgorithm::EdDSA,
        ];

        for (idx, &curve) in test_curves.iter().enumerate() {
            let kp = KeyPair::generate(curve, &mut rng).unwrap();
            let cred_id = alloc::format!("cred-id-{:?}-{}", curve, idx).into_bytes();

            let passkey = VaultPasskey {
                credential_id: cred_id.clone(),
                rp_id: "aegiskey.dev".to_string(),
                rp_name: Some("AegisKey Security".to_string()),
                user_id: alloc::vec![idx as u8, 0x01, 0x02],
                user_name: alloc::format!("user_{}", idx),
                user_display_name: alloc::format!("User {}", idx),
                algorithm: curve.to_i32(),
                private_key: kp.private_key_bytes(),
                sign_count: 0,
                created_at: 1770000000 + idx as u64,
                uv_required: true,
                backup_eligible: true,
                backup_state: true,
            };

            vault.put(passkey);
        }

        assert_eq!(vault.len(), 5);

        // 3. Test find by RP
        let aegis_passkeys = vault.find_by_rp("aegiskey.dev");
        assert_eq!(aegis_passkeys.len(), 5);

        // 4. Test sign and counter increment
        let test_msg = b"WebAuthn Assertion Authentication 2026";
        let cred0_id = b"cred-id-ES256-0".to_vec();
        let passkey0 = vault.get_mut(&cred0_id).expect("Cred0 must exist");
        assert_eq!(passkey0.sign_count, 0);

        let sig = passkey0.sign(test_msg).expect("Signing must succeed");
        assert_eq!(passkey0.sign_count, 1);
        let pubkey = passkey0.public_key().expect("Public key");
        assert!(pubkey.verify(test_msg, &sig).is_ok());

        // 5. Test Vault storage sealing and opening
        let sealed_blob = vault.seal_to_blob(&mut rng).expect("Seal to blob");
        assert!(!sealed_blob.is_empty());

        let mut restored_vault = AegisVault::from_master_seed(&seed).unwrap();
        let loaded_count = restored_vault.load_from_blob(&sealed_blob).expect("Load blob");
        assert_eq!(loaded_count, 5);
        assert_eq!(restored_vault.len(), 5);

        // 6. Test Authenticated ECDH / HKDF / AES-GCM Export & Import
        let pin_token = b"secure_user_pin_token_123456";
        let client_secret = p256::ecdh::EphemeralSecret::random(&mut rng);
        let client_pub = client_secret.public_key();
        let client_pub_sec1 = client_pub.to_encoded_point(false).as_bytes().to_vec();

        // Export from original vault
        let export_package = vault
            .export_authenticated(&client_pub_sec1, pin_token, 1770000000, &mut rng)
            .expect("Authenticated export must succeed");

        assert_eq!(export_package.auth_ephemeral_pubkey.len(), 65);
        assert_eq!(export_package.nonce.len(), 12);
        assert!(!export_package.ciphertext_and_tag.is_empty());

        // Import into a fresh new vault
        let mut new_vault = AegisVault::new([0x77u8; 32]);
        assert_eq!(new_vault.len(), 0);

        let imported_count = new_vault
            .import_authenticated(&export_package, &client_secret, &client_pub_sec1, pin_token)
            .expect("Authenticated import must succeed");

        assert_eq!(imported_count, 5);
        assert_eq!(new_vault.len(), 5);

        // Verify imported passkeys are intact and functional
        let imported_passkey0 = new_vault.get(&cred0_id).expect("Imported passkey0");
        assert_eq!(imported_passkey0.user_name, "user_0");
        let imported_kp = imported_passkey0.key_pair().expect("Imported keypair");
        let imported_sig = imported_kp.sign(test_msg).expect("Sign with imported key");
        assert!(pubkey.verify(test_msg, &imported_sig).is_ok());

        // 7. Negative test: Tampering with pin_token must fail authentication
        let wrong_pin_token = b"wrong_pin_token_bad_attacker";
        let mut tampered_vault = AegisVault::new([0x88u8; 32]);
        let import_tampered = tampered_vault.import_authenticated(
            &export_package,
            &client_secret,
            &client_pub_sec1,
            wrong_pin_token,
        );
        assert!(matches!(import_tampered, Err(VaultError::AuthenticationFailed)));

        // 8. Negative test: Tampering with ciphertext must fail authentication
        let mut tampered_package = export_package.clone();
        tampered_package.ciphertext_and_tag[10] ^= 0x55;
        let import_corrupted = tampered_vault.import_authenticated(
            &tampered_package,
            &client_secret,
            &client_pub_sec1,
            pin_token,
        );
        assert!(matches!(import_corrupted, Err(VaultError::AuthenticationFailed)));
    }
}

