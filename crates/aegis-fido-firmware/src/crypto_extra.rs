//! T-CR-05 P-384 / X25519 / Ed25519 + teto de RAM (GEN-DEVICE parcial).
//!
//! Motivo: P-384 amplia interop (PIV/FIDO) e X25519/Ed25519 cobrem SSH/age;
//! sem teto de RAM o S3 estoura stack ao habilitar curvas maiores (secao 9).
//!
//! - Ed25519 real via `ed25519-dalek` (GEN-DEVICE, vetor RFC 8032 7.1).
//! - P-384 e X25519: sem crate nas deps -> `NotCompiled` fail-closed; a
//!   especificacao de tamanhos e o orcamento de RAM ja ficam validados aqui.
//! - `check_ram` barra a curva quando o dominio cripto nao tem folga.

use core::fmt;

use ed25519_dalek::VerifyingKey as EdVerifyingKey;
use ed25519_dalek::{Signature as EdSignature, SigningKey as EdSigningKey};
use signature::{Signer, Verifier};
use zeroize::Zeroize;

/// Curvas extras da matriz.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtraCurve {
    P384,
    X25519,
    Ed25519,
}

/// Erros das curvas extras. Sem segredo nas variantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtraError {
    BadSeed,
    BadPublicKey,
    BadSignature,
    BadLength,
    RamExceeded,
    NotCompiled,
}

/// Tamanhos de semente/chave (bytes).
pub const ED25519_SEED_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const P384_FIELD_LEN: usize = 48;
pub const X25519_KEY_LEN: usize = 32;
/// Teto de mensagem assinada/trocada neste modulo.
pub const EXTRA_MAX_MSG: usize = 1024;

/// Orcamento de stack por operacao (estimativa documentada, bytes).
pub const RAM_ED25519_SIGN: u32 = 2048;
pub const RAM_P384_SIGN: u32 = 6144;
pub const RAM_X25519_AGREE: u32 = 2048;
/// Teto do dominio cripto reservado no S3 para uma operacao.
pub const CRYPTO_RAM_BUDGET: u32 = 8192;

pub fn ram_for(curve: ExtraCurve) -> u32 {
    match curve {
        ExtraCurve::Ed25519 => RAM_ED25519_SIGN,
        ExtraCurve::P384 => RAM_P384_SIGN,
        ExtraCurve::X25519 => RAM_X25519_AGREE,
    }
}

/// Barra a curva quando a folga disponivel nao cobre o orcamento.
pub fn check_ram(curve: ExtraCurve, available: u32) -> Result<(), ExtraError> {
    if ram_for(curve) > available || available > CRYPTO_RAM_BUDGET * 4 {
        return Err(ExtraError::RamExceeded);
    }
    Ok(())
}

/// Semente Ed25519 em RAM. Apaga na queda; Debug redigido.
pub struct EdSecret {
    seed: [u8; ED25519_SEED_LEN],
}

impl EdSecret {
    pub fn from_seed(seed: [u8; ED25519_SEED_LEN]) -> Self {
        Self { seed }
    }

    fn signing(&self) -> EdSigningKey {
        EdSigningKey::from_bytes(&self.seed)
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing().verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> Result<[u8; ED25519_SIG_LEN], ExtraError> {
        if msg.len() > EXTRA_MAX_MSG {
            return Err(ExtraError::BadLength);
        }
        Ok(self.signing().sign(msg).to_bytes())
    }

    pub fn wipe(&mut self) {
        self.seed.zeroize();
    }
}

impl Drop for EdSecret {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl fmt::Debug for EdSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EdSecret(redacted)")
    }
}

/// Verifica Ed25519 (RFC 8032).
pub fn verify_ed25519(
    public_32: &[u8],
    msg: &[u8],
    sig_64: &[u8; ED25519_SIG_LEN],
) -> Result<(), ExtraError> {
    if msg.len() > EXTRA_MAX_MSG {
        return Err(ExtraError::BadLength);
    }
    let key_bytes: [u8; 32] = public_32.try_into().map_err(|_| ExtraError::BadPublicKey)?;
    let key = EdVerifyingKey::from_bytes(&key_bytes).map_err(|_| ExtraError::BadPublicKey)?;
    let sig = EdSignature::from_slice(sig_64).map_err(|_| ExtraError::BadSignature)?;
    key.verify(msg, &sig).map_err(|_| ExtraError::BadSignature)
}

/// P-384: sem crate `p384` nas deps -> fail-closed (GEN condicionado).
pub fn p384_sign(_seed48: &[u8], _msg: &[u8]) -> Result<[u8; 96], ExtraError> {
    Err(ExtraError::NotCompiled)
}

/// X25519: sem crate nas deps -> fail-closed (GEN condicionado).
pub fn x25519_agree(
    _secret32: &[u8; X25519_KEY_LEN],
    _peer32: &[u8],
) -> Result<[u8; 32], ExtraError> {
    Err(ExtraError::NotCompiled)
}

/// Valida tamanho de chave P-384/X25519 antes de qualquer backend.
pub fn check_key_len(curve: ExtraCurve, len: usize) -> Result<(), ExtraError> {
    let want = match curve {
        ExtraCurve::P384 => P384_FIELD_LEN,
        ExtraCurve::X25519 => X25519_KEY_LEN,
        ExtraCurve::Ed25519 => ED25519_SEED_LEN,
    };
    if len != want {
        return Err(ExtraError::BadLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex valido")
    }

    // RFC 8032 secao 7.1 TEST 1 (mensagem vazia).
    const TEST1_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const TEST1_PUB: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const TEST1_SIG: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    fn test1_seed() -> [u8; 32] {
        let v = h(TEST1_SEED);
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn ed25519_rfc8032_test1() {
        let sec = EdSecret::from_seed(test1_seed());
        assert_eq!(sec.public_bytes().as_slice(), h(TEST1_PUB).as_slice());
        let sig = sec.sign(b"").expect("msg vazia valida");
        assert_eq!(sig.as_slice(), h(TEST1_SIG).as_slice());
        verify_ed25519(&h(TEST1_PUB), b"", &sig).expect("vetor RFC verifica");
    }

    #[test]
    fn ed25519_rfc8032_test2() {
        // RFC 8032 secao 7.1 TEST 2 (mensagem de 1 byte 0x72).
        let seed = h("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&seed);
        let sec = EdSecret::from_seed(raw);
        assert_eq!(
            sec.public_bytes().as_slice(),
            h("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c").as_slice()
        );
        let sig = sec.sign(&[0x72]).expect("msg 1 byte valida");
        assert_eq!(
            sig.as_slice(),
            h("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00").as_slice()
        );
    }

    #[test]
    fn ed25519_roundtrip_and_tamper() {
        let sec = EdSecret::from_seed([7u8; 32]);
        let pk = sec.public_bytes();
        let sig = sec.sign(b"ssh-session").unwrap();
        verify_ed25519(&pk, b"ssh-session", &sig).unwrap();
        let mut bad = sig;
        bad[10] ^= 0x80;
        assert_eq!(
            verify_ed25519(&pk, b"ssh-session", &bad),
            Err(ExtraError::BadSignature)
        );
        assert_eq!(
            verify_ed25519(&pk, b"outra", &sig),
            Err(ExtraError::BadSignature)
        );
        let other = EdSecret::from_seed([9u8; 32]).public_bytes();
        assert_eq!(
            verify_ed25519(&other, b"ssh-session", &sig),
            Err(ExtraError::BadSignature)
        );
    }

    #[test]
    fn rejects_bad_lengths() {
        assert_eq!(
            verify_ed25519(&[0u8; 31], b"m", &[0u8; 64]),
            Err(ExtraError::BadPublicKey)
        );
        assert_eq!(
            check_key_len(ExtraCurve::P384, 32),
            Err(ExtraError::BadLength)
        );
        assert_eq!(check_key_len(ExtraCurve::P384, 48), Ok(()));
        assert_eq!(check_key_len(ExtraCurve::X25519, 32), Ok(()));
        let sec = EdSecret::from_seed([1u8; 32]);
        let big = std::vec![0u8; EXTRA_MAX_MSG + 1];
        assert_eq!(sec.sign(&big), Err(ExtraError::BadLength));
    }

    #[test]
    fn conditioned_curves_are_fail_closed() {
        assert_eq!(p384_sign(&[0u8; 48], b"m"), Err(ExtraError::NotCompiled));
        assert_eq!(
            x25519_agree(&[0u8; 32], &[0u8; 32]),
            Err(ExtraError::NotCompiled)
        );
    }

    #[test]
    fn ram_budget_enforced() {
        assert_eq!(check_ram(ExtraCurve::Ed25519, 8192), Ok(()));
        assert_eq!(check_ram(ExtraCurve::P384, 8192), Ok(()));
        // P-384 nao cabe em folga de 4 KiB; X25519 cabe.
        assert_eq!(
            check_ram(ExtraCurve::P384, 4096),
            Err(ExtraError::RamExceeded)
        );
        assert_eq!(check_ram(ExtraCurve::X25519, 4096), Ok(()));
        assert_eq!(
            check_ram(ExtraCurve::Ed25519, 0),
            Err(ExtraError::RamExceeded)
        );
    }

    #[test]
    fn debug_never_leaks_seed() {
        let sec = EdSecret::from_seed([0xABu8; 32]);
        let dbg = format!("{:?}", sec);
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("ab"));
    }
}
