//! Multi-Curve Elliptic Cryptography Engine for Aegis FIDO2.
//!
//! 100% Native Rust implementation supporting:
//! - SECP256R1 (NIST P-256 / ES256, COSE alg -7) via `p256`
//! - SECP384R1 (NIST P-384 / ES384, COSE alg -35) via `p384`
//! - SECP521R1 (NIST P-521 / ES512, COSE alg -36) via `p521`
//! - SECP256K1 (Koblitz / ES256K, COSE alg -47) via `k256`
//! - Ed25519 (EdDSA, COSE alg -8) via `ed25519-dalek`

use alloc::vec::Vec;
use alloc::string::String;
use alloc::format;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use signature::{Signer, Verifier};

use crate::crypto::cose::{
    CoseKey, COSE_ALG_EDDSA, COSE_ALG_ES256, COSE_ALG_ES256K, COSE_ALG_ES384, COSE_ALG_ES512,
    COSE_CRV_ED25519, COSE_CRV_P256, COSE_CRV_P384, COSE_CRV_P521, COSE_CRV_SECP256K1,
    COSE_KTY_EC2, COSE_KTY_OKP,
};

/// Supported FIDO2 / COSE signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CoseAlgorithm {
    ES256 = COSE_ALG_ES256,   // -7
    EdDSA = COSE_ALG_EDDSA,   // -8
    ES384 = COSE_ALG_ES384,   // -35
    ES512 = COSE_ALG_ES512,   // -36
    ES256K = COSE_ALG_ES256K, // -47
}

impl CoseAlgorithm {
    pub fn from_i32(val: i32) -> Option<Self> {
        match val {
            COSE_ALG_ES256 => Some(Self::ES256),
            COSE_ALG_EDDSA => Some(Self::EdDSA),
            COSE_ALG_ES384 => Some(Self::ES384),
            COSE_ALG_ES512 => Some(Self::ES512),
            COSE_ALG_ES256K => Some(Self::ES256K),
            _ => None,
        }
    }

    pub fn to_i32(self) -> i32 {
        self as i32
    }

    pub fn kty(self) -> i64 {
        match self {
            Self::ES256 | Self::ES384 | Self::ES512 | Self::ES256K => COSE_KTY_EC2,
            Self::EdDSA => COSE_KTY_OKP,
        }
    }

    pub fn crv(self) -> i64 {
        match self {
            Self::ES256 => COSE_CRV_P256,
            Self::ES384 => COSE_CRV_P384,
            Self::ES512 => COSE_CRV_P521,
            Self::ES256K => COSE_CRV_SECP256K1,
            Self::EdDSA => COSE_CRV_ED25519,
        }
    }
}

#[derive(Debug)]
pub enum CryptoError {
    InvalidKeyLength,
    InvalidSignature,
    SigningFailed(String),
    VerificationFailed,
    SerializationError(String),
    UnsupportedAlgorithm(i32),
    RandomGeneratorError,
    EcdhError,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKeyLength => write!(f, "Invalid key length"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::SigningFailed(s) => write!(f, "Signing failed: {}", s),
            Self::VerificationFailed => write!(f, "Signature verification failed"),
            Self::SerializationError(s) => write!(f, "Serialization error: {}", s),
            Self::UnsupportedAlgorithm(a) => write!(f, "Unsupported COSE algorithm: {}", a),
            Self::RandomGeneratorError => write!(f, "RNG failure"),
            Self::EcdhError => write!(f, "ECDH key agreement failed"),
        }
    }
}

/// Unified Private/Public KeyPair supporting all 5 elliptic curves.
#[derive(Clone)]
pub enum KeyPair {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(p521::ecdsa::SigningKey),
    K256(k256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

impl KeyPair {
    /// Generates a new cryptographic key pair using the specified algorithm and RNG.
    pub fn generate<R: RngCore + CryptoRng>(alg: CoseAlgorithm, rng: &mut R) -> Result<Self, CryptoError> {
        match alg {
            CoseAlgorithm::ES256 => {
                let sk = p256::ecdsa::SigningKey::random(rng);
                Ok(Self::P256(sk))
            }
            CoseAlgorithm::ES384 => {
                let sk = p384::ecdsa::SigningKey::random(rng);
                Ok(Self::P384(sk))
            }
            CoseAlgorithm::ES512 => {
                let sk = p521::ecdsa::SigningKey::random(rng);
                Ok(Self::P521(sk))
            }
            CoseAlgorithm::ES256K => {
                let sk = k256::ecdsa::SigningKey::random(rng);
                Ok(Self::K256(sk))
            }
            CoseAlgorithm::EdDSA => {
                let sk = ed25519_dalek::SigningKey::generate(rng);
                Ok(Self::Ed25519(sk))
            }
        }
    }

    /// Reconstructs a KeyPair from raw private scalar/seed bytes.
    pub fn from_private_key_bytes(alg: CoseAlgorithm, bytes: &[u8]) -> Result<Self, CryptoError> {
        match alg {
            CoseAlgorithm::ES256 => {
                let sk = p256::ecdsa::SigningKey::from_slice(bytes)
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                Ok(Self::P256(sk))
            }
            CoseAlgorithm::ES384 => {
                let sk = p384::ecdsa::SigningKey::from_slice(bytes)
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                Ok(Self::P384(sk))
            }
            CoseAlgorithm::ES512 => {
                let sk = p521::ecdsa::SigningKey::from_slice(bytes)
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                Ok(Self::P521(sk))
            }
            CoseAlgorithm::ES256K => {
                let sk = k256::ecdsa::SigningKey::from_slice(bytes)
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                Ok(Self::K256(sk))
            }
            CoseAlgorithm::EdDSA => {
                if bytes.len() != 32 {
                    return Err(CryptoError::InvalidKeyLength);
                }
                let mut b = [0u8; 32];
                b.copy_from_slice(bytes);
                let sk = ed25519_dalek::SigningKey::from_bytes(&b);
                b.zeroize();
                Ok(Self::Ed25519(sk))
            }
        }
    }

    /// Returns the algorithm identifier.
    pub fn algorithm(&self) -> CoseAlgorithm {
        match self {
            Self::P256(_) => CoseAlgorithm::ES256,
            Self::P384(_) => CoseAlgorithm::ES384,
            Self::P521(_) => CoseAlgorithm::ES512,
            Self::K256(_) => CoseAlgorithm::ES256K,
            Self::Ed25519(_) => CoseAlgorithm::EdDSA,
        }
    }

    /// Exports raw private key bytes (zeroizable).
    pub fn private_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(sk) => sk.to_bytes().to_vec(),
            Self::P384(sk) => sk.to_bytes().to_vec(),
            Self::P521(sk) => sk.to_bytes().to_vec(),
            Self::K256(sk) => sk.to_bytes().to_vec(),
            Self::Ed25519(sk) => sk.to_bytes().to_vec(),
        }
    }

    /// Derives the corresponding Public Key.
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::P256(sk) => PublicKey::P256(*sk.verifying_key()),
            Self::P384(sk) => PublicKey::P384(*sk.verifying_key()),
            Self::P521(sk) => PublicKey::P521(p521::ecdsa::VerifyingKey::from(sk)),
            Self::K256(sk) => PublicKey::K256(*sk.verifying_key()),
            Self::Ed25519(sk) => PublicKey::Ed25519(sk.verifying_key()),
        }
    }

    /// Returns the COSE Key representation of the public key.
    pub fn to_cose_key(&self) -> CoseKey {
        self.public_key().to_cose_key()
    }

    /// Encodes the public key as canonical CBOR COSE_Key bytes.
    pub fn to_cose_cbor(&self) -> Vec<u8> {
        self.public_key().to_cose_cbor()
    }

    /// Generates a digital signature for `message` in FIDO2 / CTAP2 format:
    /// - ASN.1 DER for ECDSA (P-256, P-384, P-521, K-256)
    /// - Raw 64 bytes for Ed25519
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::P256(sk) => {
                let sig: p256::ecdsa::Signature = sk.sign(message);
                Ok(sig.to_der().as_bytes().to_vec())
            }
            Self::P384(sk) => {
                let sig: p384::ecdsa::Signature = sk.sign(message);
                Ok(sig.to_der().as_bytes().to_vec())
            }
            Self::P521(sk) => {
                let sig: p521::ecdsa::Signature = sk.sign(message);
                Ok(sig.to_der().as_bytes().to_vec())
            }
            Self::K256(sk) => {
                let sig: k256::ecdsa::Signature = sk.sign(message);
                Ok(sig.to_der().as_bytes().to_vec())
            }
            Self::Ed25519(sk) => {
                use ed25519_dalek::Signer;
                let sig = sk.sign(message);
                Ok(sig.to_bytes().to_vec())
            }
        }
    }

    /// Verifies a digital signature against `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        self.public_key().verify(message, signature)
    }
}

/// Unified Public Key supporting all 5 elliptic curves.
#[derive(Clone)]
pub enum PublicKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
    K256(k256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey({:?})", self.algorithm())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_cose_key() == other.to_cose_key()
    }
}

impl Eq for PublicKey {}

impl PublicKey {
    pub fn algorithm(&self) -> CoseAlgorithm {
        match self {
            Self::P256(_) => CoseAlgorithm::ES256,
            Self::P384(_) => CoseAlgorithm::ES384,
            Self::P521(_) => CoseAlgorithm::ES512,
            Self::K256(_) => CoseAlgorithm::ES256K,
            Self::Ed25519(_) => CoseAlgorithm::EdDSA,
        }
    }

    pub fn to_cose_key(&self) -> CoseKey {
        match self {
            Self::P256(vk) => {
                let pt = vk.to_encoded_point(false);
                let x = pt.x().expect("valid x coordinate").to_vec();
                let y = pt.y().expect("valid y coordinate").to_vec();
                CoseKey::p256(x, y)
            }
            Self::P384(vk) => {
                let pt = vk.to_encoded_point(false);
                let x = pt.x().expect("valid x coordinate").to_vec();
                let y = pt.y().expect("valid y coordinate").to_vec();
                CoseKey::p384(x, y)
            }
            Self::P521(vk) => {
                let pt = vk.to_encoded_point(false);
                let x = pt.x().expect("valid x coordinate").to_vec();
                let y = pt.y().expect("valid y coordinate").to_vec();
                CoseKey::p521(x, y)
            }
            Self::K256(vk) => {
                let pt = vk.to_encoded_point(false);
                let x = pt.x().expect("valid x coordinate").to_vec();
                let y = pt.y().expect("valid y coordinate").to_vec();
                CoseKey::secp256k1(x, y)
            }
            Self::Ed25519(vk) => {
                CoseKey::ed25519(vk.to_bytes().to_vec())
            }
        }
    }

    pub fn to_cose_cbor(&self) -> Vec<u8> {
        self.to_cose_key().to_cbor_bytes()
    }

    pub fn from_cose_key(cose: &CoseKey) -> Result<Self, CryptoError> {
        match cose {
            CoseKey::Ec2 { alg, crv, x, y } => {
                match (*alg, *crv) {
                    (COSE_ALG_ES256, COSE_CRV_P256) => {
                        let pt = p256::EncodedPoint::from_affine_coordinates(
                            x.as_slice().into(),
                            y.as_slice().into(),
                            false,
                        );
                        let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&pt)
                            .map_err(|_| CryptoError::InvalidKeyLength)?;
                        Ok(Self::P256(vk))
                    }
                    (COSE_ALG_ES384, COSE_CRV_P384) => {
                        let pt = p384::EncodedPoint::from_affine_coordinates(
                            x.as_slice().into(),
                            y.as_slice().into(),
                            false,
                        );
                        let vk = p384::ecdsa::VerifyingKey::from_encoded_point(&pt)
                            .map_err(|_| CryptoError::InvalidKeyLength)?;
                        Ok(Self::P384(vk))
                    }
                    (COSE_ALG_ES512, COSE_CRV_P521) => {
                        let pt = p521::EncodedPoint::from_affine_coordinates(
                            x.as_slice().into(),
                            y.as_slice().into(),
                            false,
                        );
                        let vk = p521::ecdsa::VerifyingKey::from_encoded_point(&pt)
                            .map_err(|_| CryptoError::InvalidKeyLength)?;
                        Ok(Self::P521(vk))
                    }
                    (COSE_ALG_ES256K, COSE_CRV_SECP256K1) => {
                        let pt = k256::EncodedPoint::from_affine_coordinates(
                            x.as_slice().into(),
                            y.as_slice().into(),
                            false,
                        );
                        let vk = k256::ecdsa::VerifyingKey::from_encoded_point(&pt)
                            .map_err(|_| CryptoError::InvalidKeyLength)?;
                        Ok(Self::K256(vk))
                    }
                    _ => Err(CryptoError::UnsupportedAlgorithm(*alg)),
                }
            }
            CoseKey::Okp { alg, crv, x } => {
                if *alg == COSE_ALG_EDDSA && *crv == COSE_CRV_ED25519 {
                    if x.len() != 32 {
                        return Err(CryptoError::InvalidKeyLength);
                    }
                    let mut b = [0u8; 32];
                    b.copy_from_slice(x);
                    let vk = ed25519_dalek::VerifyingKey::from_bytes(&b)
                        .map_err(|_| CryptoError::InvalidKeyLength)?;
                    Ok(Self::Ed25519(vk))
                } else {
                    Err(CryptoError::UnsupportedAlgorithm(*alg))
                }
            }
        }
    }

    pub fn from_cose_cbor(cbor: &[u8]) -> Result<Self, CryptoError> {
        let cose = CoseKey::from_cbor_bytes(cbor)
            .map_err(|e| CryptoError::SerializationError(format!("{:?}", e)))?;
        Self::from_cose_key(&cose)
    }

    /// Verifies a signature (supports both ASN.1 DER and raw signature formats).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::P256(vk) => {
                let sig = p256::ecdsa::Signature::from_der(signature)
                    .or_else(|_| p256::ecdsa::Signature::from_slice(signature))
                    .map_err(|_| CryptoError::InvalidSignature)?;
                vk.verify(message, &sig)
                    .map_err(|_| CryptoError::VerificationFailed)
            }
            Self::P384(vk) => {
                let sig = p384::ecdsa::Signature::from_der(signature)
                    .or_else(|_| p384::ecdsa::Signature::from_slice(signature))
                    .map_err(|_| CryptoError::InvalidSignature)?;
                vk.verify(message, &sig)
                    .map_err(|_| CryptoError::VerificationFailed)
            }
            Self::P521(vk) => {
                let sig = p521::ecdsa::Signature::from_der(signature)
                    .or_else(|_| p521::ecdsa::Signature::from_slice(signature))
                    .map_err(|_| CryptoError::InvalidSignature)?;
                vk.verify(message, &sig)
                    .map_err(|_| CryptoError::VerificationFailed)
            }
            Self::K256(vk) => {
                let sig = k256::ecdsa::Signature::from_der(signature)
                    .or_else(|_| k256::ecdsa::Signature::from_slice(signature))
                    .map_err(|_| CryptoError::InvalidSignature)?;
                vk.verify(message, &sig)
                    .map_err(|_| CryptoError::VerificationFailed)
            }
            Self::Ed25519(vk) => {
                use ed25519_dalek::Verifier;
                if signature.len() != 64 {
                    return Err(CryptoError::InvalidSignature);
                }
                let mut b = [0u8; 64];
                b.copy_from_slice(signature);
                let sig = ed25519_dalek::Signature::from_bytes(&b);
                vk.verify(message, &sig)
                    .map_err(|_| CryptoError::VerificationFailed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_five_curves_lifecycle() {
        let mut rng = rand::rngs::OsRng;
        let test_message = b"AegisKey FIDO2 Multi-Curve Cryptographic Assertion";

        let curves = [
            CoseAlgorithm::ES256,
            CoseAlgorithm::ES384,
            CoseAlgorithm::ES512,
            CoseAlgorithm::ES256K,
            CoseAlgorithm::EdDSA,
        ];

        for &curve in &curves {
            // 1. Key pair generation
            let kp = KeyPair::generate(curve, &mut rng)
                .expect("KeyPair generation must succeed");
            assert_eq!(kp.algorithm(), curve);

            // 2. Public key derivation and COSE export
            let pubkey = kp.public_key();
            assert_eq!(pubkey.algorithm(), curve);

            let cose_cbor = kp.to_cose_cbor();
            assert!(!cose_cbor.is_empty());

            // 3. Re-import public key from CBOR
            let imported_pub = PublicKey::from_cose_cbor(&cose_cbor)
                .expect("Importing COSE CBOR must succeed");
            assert_eq!(imported_pub.algorithm(), curve);

            // 4. Digital signing
            let sig = kp.sign(test_message).expect("Signing must succeed");
            assert!(!sig.is_empty());

            // 5. Digital signature verification
            assert!(
                pubkey.verify(test_message, &sig).is_ok(),
                "Signature verification failed for {:?}",
                curve
            );
            assert!(
                imported_pub.verify(test_message, &sig).is_ok(),
                "Verification with imported pubkey failed for {:?}",
                curve
            );

            // 6. Verification with corrupted message must fail
            let mut corrupted_msg = test_message.to_vec();
            corrupted_msg[0] ^= 0xff;
            assert!(
                pubkey.verify(&corrupted_msg, &sig).is_err(),
                "Corrupted message should fail verification"
            );

            // 7. Private key export and re-import
            let priv_bytes = kp.private_key_bytes();
            let reimported_kp = KeyPair::from_private_key_bytes(curve, &priv_bytes)
                .expect("Re-importing private key must succeed");
            assert_eq!(reimported_kp.algorithm(), curve);

            let sig2 = reimported_kp.sign(test_message).expect("Signing with re-imported key");
            assert!(pubkey.verify(test_message, &sig2).is_ok());
        }
    }
}
