use crate::crypto::cose::CoseKey;
use alloc::vec::Vec;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ecdh::diffie_hellman, PublicKey, SecretKey};
use rand_core::{CryptoRng, RngCore};

#[derive(Clone)]
pub struct EcdhKeyAgreement {
    private_key: SecretKey,
    public_key: PublicKey,
}

impl core::fmt::Debug for EcdhKeyAgreement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EcdhKeyAgreement")
            .field("public_key", &self.to_cose_key())
            .finish()
    }
}

impl EcdhKeyAgreement {
    /// Generates a new ephemeral P-256 key pair for ECDH
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let private_key = SecretKey::random(rng);
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }

    /// Creates an instance from raw 32-byte private key scalar
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let private_key = SecretKey::from_slice(bytes).map_err(|_| "Invalid P-256 private key")?;
        let public_key = private_key.public_key();
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Returns public key as COSE structure
    pub fn to_cose_key(&self) -> CoseKey {
        let point = self.public_key.to_encoded_point(false);
        let x = point.x().expect("x coordinate missing").to_vec();
        let y = point.y().expect("y coordinate missing").to_vec();
        CoseKey::p256(x, y)
    }

    /// Performs ECDH with peer's P-256 public key and returns 32-byte shared secret Z_x
    pub fn compute_shared_secret(&self, peer_cose_key: &CoseKey) -> Result<[u8; 32], &'static str> {
        let (x, y) = match peer_cose_key {
            CoseKey::Ec2 { x, y, .. } => (x, y),
            _ => return Err("Peer key must be EC2 P-256"),
        };

        if x.len() != 32 || y.len() != 32 {
            return Err("Invalid coordinate length for P-256");
        }

        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(x);
        sec1.extend_from_slice(y);

        let peer_pub =
            PublicKey::from_sec1_bytes(&sec1).map_err(|_| "Invalid peer public key point")?;

        let shared = diffie_hellman(self.private_key.to_nonzero_scalar(), peer_pub.as_affine());
        let raw_secret = shared.raw_secret_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(raw_secret.as_ref());
        Ok(out)
    }
}
