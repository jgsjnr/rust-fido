use crate::crypto::cose::{
    CoseKey, COSE_ALG_EDDSA, COSE_ALG_ES256, COSE_ALG_ES256K, COSE_ALG_ES384, COSE_ALG_ES512,
};
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

#[derive(Clone)]
pub enum FidoKeyPair {
    Es256(p256::ecdsa::SigningKey),
    Es384(p384::ecdsa::SigningKey),
    Es512(p521::ecdsa::SigningKey),
    Es256k(k256::ecdsa::SigningKey),
    EdDsa(ed25519_dalek::SigningKey),
}

impl FidoKeyPair {
    /// Generates a new key pair for the requested COSE algorithm
    pub fn generate<R: RngCore + CryptoRng>(alg: i32, rng: &mut R) -> Result<Self, &'static str> {
        match alg {
            COSE_ALG_ES256 => {
                let sk = p256::ecdsa::SigningKey::random(rng);
                Ok(Self::Es256(sk))
            }
            COSE_ALG_ES384 => {
                let sk = p384::ecdsa::SigningKey::random(rng);
                Ok(Self::Es384(sk))
            }
            COSE_ALG_ES512 => {
                let sk = p521::ecdsa::SigningKey::random(rng);
                Ok(Self::Es512(sk))
            }
            COSE_ALG_ES256K => {
                let sk = k256::ecdsa::SigningKey::random(rng);
                Ok(Self::Es256k(sk))
            }
            COSE_ALG_EDDSA => {
                let sk = ed25519_dalek::SigningKey::generate(rng);
                Ok(Self::EdDsa(sk))
            }
            _ => Err("Unsupported COSE algorithm"),
        }
    }

    /// Serializes the private key bytes
    pub fn private_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::Es256(sk) => sk.to_bytes().to_vec(),
            Self::Es384(sk) => sk.to_bytes().to_vec(),
            Self::Es512(sk) => sk.to_bytes().to_vec(),
            Self::Es256k(sk) => sk.to_bytes().to_vec(),
            Self::EdDsa(sk) => sk.to_bytes().to_vec(),
        }
    }

    /// Reconstructs a key pair from algorithm and private key bytes
    pub fn from_private_bytes(alg: i32, bytes: &[u8]) -> Result<Self, &'static str> {
        match alg {
            COSE_ALG_ES256 => {
                let sk =
                    p256::ecdsa::SigningKey::from_slice(bytes).map_err(|_| "Invalid ES256 key")?;
                Ok(Self::Es256(sk))
            }
            COSE_ALG_ES384 => {
                let sk =
                    p384::ecdsa::SigningKey::from_slice(bytes).map_err(|_| "Invalid ES384 key")?;
                Ok(Self::Es384(sk))
            }
            COSE_ALG_ES512 => {
                let sk =
                    p521::ecdsa::SigningKey::from_slice(bytes).map_err(|_| "Invalid ES512 key")?;
                Ok(Self::Es512(sk))
            }
            COSE_ALG_ES256K => {
                let sk =
                    k256::ecdsa::SigningKey::from_slice(bytes).map_err(|_| "Invalid ES256K key")?;
                Ok(Self::Es256k(sk))
            }
            COSE_ALG_EDDSA => {
                if bytes.len() != 32 {
                    return Err("Invalid EdDSA key length");
                }
                let mut b = [0u8; 32];
                b.copy_from_slice(bytes);
                let sk = ed25519_dalek::SigningKey::from_bytes(&b);
                Ok(Self::EdDsa(sk))
            }
            _ => Err("Unsupported COSE algorithm"),
        }
    }

    /// Returns the public key encoded in COSE format
    pub fn to_cose_key(&self) -> CoseKey {
        match self {
            Self::Es256(sk) => {
                let vk = sk.verifying_key();
                let pt = vk.to_encoded_point(false);
                let x = pt.x().expect("x").to_vec();
                let y = pt.y().expect("y").to_vec();
                CoseKey::p256(x, y)
            }
            Self::Es384(sk) => {
                let vk = sk.verifying_key();
                let pt = vk.to_encoded_point(false);
                let x = pt.x().expect("x").to_vec();
                let y = pt.y().expect("y").to_vec();
                CoseKey::p384(x, y)
            }
            Self::Es512(sk) => {
                let vk = p521::ecdsa::VerifyingKey::from(sk);
                let pt = vk.to_encoded_point(false);
                let x = pt.x().expect("x").to_vec();
                let y = pt.y().expect("y").to_vec();
                CoseKey::p521(x, y)
            }
            Self::Es256k(sk) => {
                let vk = sk.verifying_key();
                let pt = vk.to_encoded_point(false);
                let x = pt.x().expect("x").to_vec();
                let y = pt.y().expect("y").to_vec();
                CoseKey::secp256k1(x, y)
            }
            Self::EdDsa(sk) => {
                let vk = sk.verifying_key();
                CoseKey::ed25519(vk.to_bytes().to_vec())
            }
        }
    }

    /// Signs message and returns signature formatted for CTAP2 / WebAuthn
    /// (DER for ECDSA, raw 64 bytes for Ed25519)
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        match self {
            Self::Es256(sk) => {
                let sig: p256::ecdsa::Signature = sk.sign(message);
                sig.to_der().as_bytes().to_vec()
            }
            Self::Es384(sk) => {
                let sig: p384::ecdsa::Signature = sk.sign(message);
                sig.to_der().as_bytes().to_vec()
            }
            Self::Es512(sk) => {
                let sig: p521::ecdsa::Signature = sk.sign(message);
                sig.to_der().as_bytes().to_vec()
            }
            Self::Es256k(sk) => {
                let sig: k256::ecdsa::Signature = sk.sign(message);
                sig.to_der().as_bytes().to_vec()
            }
            Self::EdDsa(sk) => {
                use ed25519_dalek::Signer;
                let sig = sk.sign(message);
                sig.to_bytes().to_vec()
            }
        }
    }

    pub fn algorithm(&self) -> i32 {
        match self {
            Self::Es256(_) => COSE_ALG_ES256,
            Self::Es384(_) => COSE_ALG_ES384,
            Self::Es512(_) => COSE_ALG_ES512,
            Self::Es256k(_) => COSE_ALG_ES256K,
            Self::EdDsa(_) => COSE_ALG_EDDSA,
        }
    }
}
