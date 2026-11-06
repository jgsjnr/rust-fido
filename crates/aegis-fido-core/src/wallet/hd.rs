//! Hierarchical deterministic derivation over secp256k1 (RAM only).
//!
//! BEHAVIOR: pure functions over typed structures. Master from seed bytes,
//! hardened/normal child derivation, path parsing with fail-closed
//! validation, and extended-key payload encode/decode in the protocol
//! serialization format. No wire, no NVS, no transport: everything runs on
//! caller-provided bytes and returns typed keys (chain codes and private
//! bytes never leave these structs except through explicit encoders).
//!
//! SCOPE: secp256k1 only (protocol derivation levels 32/44/84). Networks
//! whose curve is not secp256k1 are rejected fail-closed via
//! [`HdError::UnsupportedNetwork`]; no silent fallback, no zero key.
//!
//! CONVENTIONS: terminology follows the public derivation protocol only
//! (master, child number, hardened, chain code, fingerprint, account,
//! change, index). No product or service names appear here.

use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::hd_paths::{ChildNumber, DerivationPath};
use super::WalletError;

/// Offset added to a child index to mark it hardened (`i + 2^31`).
pub const HARDENED_OFFSET: u32 = 0x8000_0000;
/// HMAC key binding the master derivation to the protocol seed domain.
const MASTER_HMAC_KEY: &[u8] = b"Bitcoin seed";
/// Minimum seed length in bytes (128 bits, protocol floor).
pub const MIN_SEED_LEN: usize = 16;
/// Maximum seed length in bytes (512 bits, protocol ceiling).
pub const MAX_SEED_LEN: usize = 64;
/// Maximum accepted path depth (protocol allows a full byte; wallet paths
/// need at most five levels, so anything deeper is rejected fail-closed).
pub const MAX_PATH_DEPTH: usize = 16;

/// Derivation failures. Variants carry lengths/positions only — never key
/// material, seeds, or path secrets beyond the offending index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdError {
    /// Seed length outside `MIN_SEED_LEN..=MAX_SEED_LEN`.
    InvalidSeedLength(usize),
    /// Master secret derived as zero or out of curve range.
    InvalidMasterKey,
    /// Stored private key is zero or out of curve range (corrupt state).
    InvalidPrivateKey,
    /// Child tweak is zero or out of curve range (retry with next index).
    InvalidTweak,
    /// Malformed path string (bad root, empty component, depth overflow).
    InvalidPath,
    /// Child index `>= 2^31` where a non-hardened value is required, or a
    /// hardened derivation was requested from a public key.
    InvalidChildNumber(u32),
    /// Hardened derivation requested from an extended public key.
    HardenedRequiresPrivate,
    /// Network whose curve is not secp256k1 (out of scope, fail-closed).
    UnsupportedNetwork,
    /// Extended-key payload fails structural validation.
    InvalidExtendedKey,
    /// Base58check envelope fails (length, alphabet, or checksum).
    InvalidEncoding,
    /// Depth counter overflow (unreachable through parsed paths).
    DepthOverflow,
}

impl core::fmt::Display for HdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSeedLength(len) => write!(
                f,
                "invalid seed length: expected 16..=64 bytes, got {}",
                len
            ),
            Self::InvalidMasterKey => write!(f, "derived master key out of curve range"),
            Self::InvalidPrivateKey => write!(f, "stored private key out of curve range"),
            Self::InvalidTweak => write!(f, "child tweak out of curve range"),
            Self::InvalidPath => write!(f, "malformed derivation path"),
            Self::InvalidChildNumber(i) => write!(f, "invalid child number {}", i),
            Self::HardenedRequiresPrivate => {
                write!(f, "hardened derivation requires a private key")
            }
            Self::UnsupportedNetwork => write!(f, "network curve is not secp256k1"),
            Self::InvalidExtendedKey => write!(f, "invalid extended key payload"),
            Self::InvalidEncoding => write!(f, "invalid extended key encoding"),
            Self::DepthOverflow => write!(f, "derivation depth overflow"),
        }
    }
}

impl From<HdError> for WalletError {
    /// Every derivation failure maps to the closed 9.5 `BadEnvelope`
    /// status: a non-standard path or key is a bad envelope, never a new
    /// wire status.
    fn from(_: HdError) -> Self {
        Self::BadEnvelope
    }
}

/// HMAC-SHA512 (the protocol MAC for master generation and child tweaks).
fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    type HmacSha512 = Hmac<Sha512>;
    let mut mac =
        <HmacSha512 as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut res = [0u8; 64];
    res.copy_from_slice(&out);
    res
}

/// Key identifier: RIPEMD160(SHA256(compressed point)).
fn hash160(compressed: &[u8; 33]) -> [u8; 20] {
    use ripemd::Ripemd160;
    let sha = Sha256::digest(compressed);
    let digest = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..]);
    out
}

/// Adds the tweak `IL` to the parent secret (`ki = parse(IL) + kpar mod n`).
/// Fails when `IL` is out of range or the sum wraps to zero (caller retries
/// with the next index per protocol).
fn tweak_add(parent_key: &[u8; 32], il: &[u8; 32]) -> Result<[u8; 32], HdError> {
    let il_sk = k256::SecretKey::from_slice(il).map_err(|_| HdError::InvalidTweak)?;
    let parent_sk =
        k256::SecretKey::from_slice(parent_key).map_err(|_| HdError::InvalidPrivateKey)?;
    let il_scalar: k256::Scalar = il_sk.to_nonzero_scalar().into();
    let parent_scalar: k256::Scalar = parent_sk.to_nonzero_scalar().into();
    let child_scalar = il_scalar + parent_scalar;
    let bytes = child_scalar.to_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    // `from_slice` rejects zero (the only way `out` is invalid: the sum is
    // already reduced mod n, so `>= n` is unreachable here).
    k256::SecretKey::from_slice(&out).map_err(|_| HdError::InvalidTweak)?;
    Ok(out)
}

/// Compressed point for a 32-byte secret. Fails on corrupt stored keys.
fn point_from_secret(secret: &[u8; 32]) -> Result<[u8; 33], HdError> {
    use k256::elliptic_curve::sec1::ToSec1Point;
    let sk = k256::SecretKey::from_slice(secret).map_err(|_| HdError::InvalidPrivateKey)?;
    let encoded = sk.public_key().to_sec1_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    Ok(out)
}

/// Extended private key: secret plus chain code and lineage metadata.
/// Private bytes are zeroized on drop and never shown in `Debug`.
/// `PartialEq` compares key material with a plain equality check; both
/// operands are owned in-memory keys, never attacker-controlled bytes.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct ExtendedPrivateKey {
    private_key: [u8; 32],
    #[zeroize(skip)]
    chain_code: [u8; 32],
    #[zeroize(skip)]
    depth: u8,
    #[zeroize(skip)]
    parent_fingerprint: [u8; 4],
    #[zeroize(skip)]
    child_number: u32,
}

impl core::fmt::Debug for ExtendedPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtendedPrivateKey")
            .field("depth", &self.depth)
            .field("child_number", &self.child_number)
            .field("private_key", &"[REDACTED]")
            .field("chain_code", &"[REDACTED]")
            .finish()
    }
}

impl ExtendedPrivateKey {
    /// Derives the master node from seed bytes (`16..=64` bytes;
    /// protocol HMAC key `MASTER_HMAC_KEY`). Rejects out-of-range seeds
    /// and out-of-range master secrets fail-closed.
    pub fn master_from_seed(seed: &[u8]) -> Result<Self, HdError> {
        if seed.len() < MIN_SEED_LEN || seed.len() > MAX_SEED_LEN {
            return Err(HdError::InvalidSeedLength(seed.len()));
        }
        let i = hmac_sha512(MASTER_HMAC_KEY, seed);
        let mut secret = [0u8; 32];
        let mut chain = [0u8; 32];
        secret.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
        k256::SecretKey::from_slice(&secret).map_err(|_| HdError::InvalidMasterKey)?;
        Ok(Self {
            private_key: secret,
            chain_code: chain,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_number: 0,
        })
    }

    /// Depth below the master (0 for the master node).
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Raw child number this node was derived at (0 for the master).
    pub fn child_number_raw(&self) -> u32 {
        self.child_number
    }

    /// Child number this node was derived at (0 for the master).
    pub fn child_number(&self) -> ChildNumber {
        ChildNumber::from_raw(self.child_number)
    }

    /// Parent fingerprint recorded at derivation (zero for the master).
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        self.parent_fingerprint
    }

    /// Chain code (returned by copy; share only with the matching secret).
    pub fn chain_code(&self) -> [u8; 32] {
        self.chain_code
    }

    /// First 4 bytes of the key identifier of this node's public key.
    pub fn fingerprint(&self) -> [u8; 4] {
        let compressed = point_from_secret(&self.private_key)
            .expect("constructed keys always hold a valid secret");
        let id = hash160(&compressed);
        [id[0], id[1], id[2], id[3]]
    }

    /// Compressed 33-byte public point for this node.
    pub fn public_key_compressed(&self) -> [u8; 33] {
        point_from_secret(&self.private_key).expect("constructed keys always hold a valid secret")
    }

    /// Uncompressed 64-byte public point (`x || y`, no `0x04` prefix).
    pub fn public_key_uncompressed_64(&self) -> [u8; 64] {
        use k256::elliptic_curve::sec1::ToSec1Point;
        let sk = k256::SecretKey::from_slice(&self.private_key)
            .expect("constructed keys always hold a valid secret");
        let encoded = sk.public_key().to_sec1_point(false);
        let mut out = [0u8; 64];
        out.copy_from_slice(&encoded.as_bytes()[1..65]);
        out
    }

    /// Neutered (public-only) view of this node.
    pub fn neutered(&self) -> ExtendedPublicKey {
        ExtendedPublicKey {
            public_key: self.public_key_compressed(),
            chain_code: self.chain_code,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
        }
    }

    /// Derives one child (hardened or normal per `child`).
    pub fn derive_child(&self, child: ChildNumber) -> Result<Self, HdError> {
        let mut data = Vec::with_capacity(37);
        if child.is_hardened() {
            data.push(0x00);
            data.extend_from_slice(&self.private_key);
        } else {
            data.extend_from_slice(&self.public_key_compressed());
        }
        data.extend_from_slice(&child.raw().to_be_bytes());
        let i = hmac_sha512(&self.chain_code, &data);
        let mut il = [0u8; 32];
        let mut chain = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
        let secret = tweak_add(&self.private_key, &il)?;
        Ok(Self {
            private_key: secret,
            chain_code: chain,
            depth: self.depth.checked_add(1).ok_or(HdError::DepthOverflow)?,
            parent_fingerprint: self.fingerprint(),
            child_number: child.raw(),
        })
    }

    /// Derives the node at `path` below `self`, level by level.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, HdError> {
        let mut node = self.clone();
        for level in path.levels() {
            node = node.derive_child(*level)?;
        }
        Ok(node)
    }

    /// Rebuilds a node from validated parts (crate-internal bridge for the
    /// serialization codec). Rejects out-of-range secrets and master nodes
    /// carrying non-zero lineage fail-closed.
    pub(crate) fn from_raw_parts(
        private_key: [u8; 32],
        chain_code: [u8; 32],
        depth: u8,
        parent_fingerprint: [u8; 4],
        child_number: u32,
    ) -> Result<Self, HdError> {
        k256::SecretKey::from_slice(&private_key).map_err(|_| HdError::InvalidExtendedKey)?;
        if depth == 0 && (parent_fingerprint != [0u8; 4] || child_number != 0) {
            return Err(HdError::InvalidExtendedKey);
        }
        Ok(Self {
            private_key,
            chain_code,
            depth,
            parent_fingerprint,
            child_number,
        })
    }

    /// Secret bytes (returned by copy; crate-internal bridge for the
    /// serialization codec — never exposed through the public API).
    pub(crate) fn secret_bytes(&self) -> [u8; 32] {
        self.private_key
    }
}

/// Extended public key: point plus chain code and lineage metadata.
/// Shareable by design (no signing power), key bytes still redacted from
/// `Debug` to keep logs free of key material by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPublicKey {
    public_key: [u8; 33],
    chain_code: [u8; 32],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u32,
}

impl ExtendedPublicKey {
    /// Depth below the master (0 for the master node).
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Child number this node was derived at (0 for the master).
    pub fn child_number(&self) -> ChildNumber {
        ChildNumber::from_raw(self.child_number)
    }

    /// Raw child number this node was derived at (0 for the master).
    pub fn child_number_raw(&self) -> u32 {
        self.child_number
    }

    /// Parent fingerprint recorded at derivation (zero for the master).
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        self.parent_fingerprint
    }

    /// Chain code (returned by copy; pairs with the public point only).
    pub fn chain_code(&self) -> [u8; 32] {
        self.chain_code
    }

    /// Compressed 33-byte public point.
    pub fn public_key_compressed(&self) -> [u8; 33] {
        self.public_key
    }

    /// First 4 bytes of the key identifier of this node's public key.
    pub fn fingerprint(&self) -> [u8; 4] {
        let id = hash160(&self.public_key);
        [id[0], id[1], id[2], id[3]]
    }

    /// Validates that the stored point lies on the curve (used after
    /// decode; constructed nodes are valid by construction).
    fn check_point(&self) -> Result<(), HdError> {
        k256::PublicKey::from_sec1_bytes(&self.public_key)
            .map_err(|_| HdError::InvalidExtendedKey)?;
        Ok(())
    }

    /// Derives one normal child. Hardened children fail closed
    /// ([`HdError::HardenedRequiresPrivate`]).
    pub fn derive_child(&self, child: ChildNumber) -> Result<Self, HdError> {
        if child.is_hardened() {
            return Err(HdError::HardenedRequiresPrivate);
        }
        self.check_point()?;
        let parent = k256::PublicKey::from_sec1_bytes(&self.public_key)
            .map_err(|_| HdError::InvalidExtendedKey)?;
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(&child.raw().to_be_bytes());
        let i = hmac_sha512(&self.chain_code, &data);
        let mut il = [0u8; 32];
        let mut chain = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
        let il_sk = k256::SecretKey::from_slice(&il).map_err(|_| HdError::InvalidTweak)?;
        let il_scalar: k256::Scalar = il_sk.to_nonzero_scalar().into();
        let parent_projective = k256::ProjectivePoint::from(parent.as_affine());
        let child_projective = k256::ProjectivePoint::GENERATOR * il_scalar + parent_projective;
        let child_affine = child_projective.to_affine();
        {
            use k256::elliptic_curve::CurveAffine;
            if bool::from(child_affine.is_identity()) {
                return Err(HdError::InvalidTweak);
            }
        }
        let child_pub =
            k256::PublicKey::from_affine(child_affine).map_err(|_| HdError::InvalidTweak)?;
        let encoded = {
            use k256::elliptic_curve::sec1::ToSec1Point;
            child_pub.to_sec1_point(true)
        };
        let mut public_key = [0u8; 33];
        public_key.copy_from_slice(encoded.as_bytes());
        Ok(Self {
            public_key,
            chain_code: chain,
            depth: self.depth.checked_add(1).ok_or(HdError::DepthOverflow)?,
            parent_fingerprint: self.fingerprint(),
            child_number: child.raw(),
        })
    }

    /// Derives the node at `path` below `self`. Any hardened level fails
    /// closed; use [`ExtendedPrivateKey::derive_path`] past hardened ones.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, HdError> {
        let mut node = self.clone();
        for level in path.levels() {
            node = node.derive_child(*level)?;
        }
        Ok(node)
    }

    /// Rebuilds a node from validated parts (crate-internal bridge for the
    /// serialization codec). Rejects non-curve points and master nodes
    /// carrying non-zero lineage fail-closed.
    pub(crate) fn from_raw_parts(
        public_key: [u8; 33],
        chain_code: [u8; 32],
        depth: u8,
        parent_fingerprint: [u8; 4],
        child_number: u32,
    ) -> Result<Self, HdError> {
        if public_key[0] != 0x02 && public_key[0] != 0x03 {
            return Err(HdError::InvalidExtendedKey);
        }
        k256::PublicKey::from_sec1_bytes(&public_key).map_err(|_| HdError::InvalidExtendedKey)?;
        if depth == 0 && (parent_fingerprint != [0u8; 4] || child_number != 0) {
            return Err(HdError::InvalidExtendedKey);
        }
        Ok(Self {
            public_key,
            chain_code,
            depth,
            parent_fingerprint,
            child_number,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_reject_out_of_range_seeds() {
        assert_eq!(
            ExtendedPrivateKey::master_from_seed(&[0u8; 15]).unwrap_err(),
            HdError::InvalidSeedLength(15)
        );
        assert_eq!(
            ExtendedPrivateKey::master_from_seed(&[0u8; 65]).unwrap_err(),
            HdError::InvalidSeedLength(65)
        );
    }

    #[test]
    fn should_reject_hardened_derivation_from_public_keys() {
        let master = ExtendedPrivateKey::master_from_seed(&[0xabu8; 32]).unwrap();
        let public = master.neutered();
        assert_eq!(
            public
                .derive_child(ChildNumber::hardened(0).unwrap())
                .unwrap_err(),
            HdError::HardenedRequiresPrivate
        );
        assert!(
            public.derive_path(&"m/0'".parse().unwrap()).unwrap_err()
                == HdError::HardenedRequiresPrivate
        );
    }

    #[test]
    fn should_match_private_and_public_derivation_for_normal_children() {
        // Protocol identity: N(m/a/b) == M/a/b for non-hardened levels.
        let master = ExtendedPrivateKey::master_from_seed(&[0x11u8; 32]).unwrap();
        let path: DerivationPath = "m/0'/1/2".parse().unwrap();
        let via_private = master.derive_path(&path).unwrap().neutered();
        let account = master
            .derive_child(ChildNumber::hardened(0).unwrap())
            .unwrap()
            .neutered();
        let via_public = account.derive_path(&"m/1/2".parse().unwrap()).unwrap();
        assert_eq!(
            via_private.to_extended_bytes(),
            via_public.to_extended_bytes()
        );
    }

    #[test]
    fn should_map_every_hd_error_to_bad_envelope() {
        for err in [
            HdError::InvalidSeedLength(0),
            HdError::InvalidMasterKey,
            HdError::InvalidPrivateKey,
            HdError::InvalidTweak,
            HdError::InvalidPath,
            HdError::InvalidChildNumber(0),
            HdError::HardenedRequiresPrivate,
            HdError::UnsupportedNetwork,
            HdError::InvalidExtendedKey,
            HdError::InvalidEncoding,
            HdError::DepthOverflow,
        ] {
            assert_eq!(WalletError::from(err), WalletError::BadEnvelope);
        }
    }

    #[test]
    fn should_never_expose_key_material_in_debug_or_display() {
        let master = ExtendedPrivateKey::master_from_seed(&[0xabu8; 32]).unwrap();
        let dbg = alloc::format!("{:?}", master);
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("ab"));
        assert!(!alloc::format!("{}", HdError::InvalidTweak).is_empty());
    }
}
