//! T-CR-01 P-256 / ECDSA / ECDH (GEN-DEVICE).
//!
//! Motivo: FIDO2/CTAP assina desafios com ECDSA P-256; sem este modulo
//! provado por vetor o firmware nao pode alegar assinatura conforme (secao 9).
//!
//! - Chave privada nasce no device (GEN-DEVICE); nunca exportada em claro.
//! - ECDSA: sign/verify deterministicos (RFC 6979 via p256).
//! - ECDH: x do ponto compartilhado (fail-closed em ponto identidade).
//! - Hardware via trait `P256Backend` (R14); `EspP256` e o ponto de
//!   ancoragem do acelerador no ESP32-S3 (hoje delega ao software auditavel).
//! - Segredo nunca em log: `P256Secret` tem Debug redigido e apaga na queda.
//! - Sem mock falso: software executa a curva real; vetor P-256 G e Wycheproof.

use core::fmt;

use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ProjectivePoint, PublicKey, SecretKey};
use signature::{Signer, Verifier};
use zeroize::Zeroize;

/// Erros do dominio P-256. Nenhuma variante carrega material secreto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P256Error {
    InvalidSecret,
    InvalidPublicKey,
    InvalidSignature,
    IdentityPeer,
    EcdhFailed,
}

/// Backend P-256 (R14): software auditavel hoje, acelerador HW no device.
pub trait P256Backend {
    fn ecdh(secret: &[u8; 32], peer_sec1: &[u8]) -> Result<[u8; 32], P256Error>;
}

/// Implementacao software real (curva verdadeira, sem mock).
pub struct SoftwareP256;

impl P256Backend for SoftwareP256 {
    fn ecdh(secret: &[u8; 32], peer_sec1: &[u8]) -> Result<[u8; 32], P256Error> {
        ecdh_p256(secret, peer_sec1)
    }
}

/// Ancoragem ESP32-S3: hoje delega ao software; o acelerador ROM entra aqui.
pub struct EspP256;

impl P256Backend for EspP256 {
    fn ecdh(secret: &[u8; 32], peer_sec1: &[u8]) -> Result<[u8; 32], P256Error> {
        SoftwareP256::ecdh(secret, peer_sec1)
    }
}

/// Chave privada P-256 em RAM. Apaga na queda; Debug nunca expoe o segredo.
pub struct P256Secret {
    raw: [u8; 32],
}

impl P256Secret {
    /// Constroi a partir de 32 bytes big-endian; rejeita zero e >= n.
    pub fn from_bytes(raw: [u8; 32]) -> Result<Self, P256Error> {
        SigningKey::from_slice(&raw).map_err(|_| P256Error::InvalidSecret)?;
        Ok(Self { raw })
    }

    fn signing(&self) -> SigningKey {
        // Seguro: validado no construtor; from_slice e deterministico.
        SigningKey::from_slice(&self.raw).expect("P256Secret validado no construtor")
    }

    /// Chave publica comprimida SEC1 (33 bytes, prefixo 02/03 + x).
    pub fn public_compressed(&self) -> [u8; 33] {
        let verifying = VerifyingKey::from(self.signing());
        let point = verifying.to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Assina (RFC 6979, deterministico). Retorna r || s (64 bytes).
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let sig: Signature = self.signing().sign(msg);
        let mut out = [0u8; 64];
        copy_n(&sig.to_bytes(), &mut out);
        out
    }

    /// Apaga a chave da RAM imediatamente.
    pub fn wipe(&mut self) {
        self.raw.zeroize();
    }
}

impl Drop for P256Secret {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl fmt::Debug for P256Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("P256Secret(redacted)")
    }
}

/// Verifica ECDSA com chave publica SEC1 comprimida e assinatura r || s.
pub fn verify_p256(peer_sec1: &[u8], msg: &[u8], sig_raw: &[u8; 64]) -> Result<(), P256Error> {
    // Chave primeiro: erro de chave tem prioridade sobre erro de assinatura.
    let key = VerifyingKey::from_sec1_bytes(peer_sec1).map_err(|_| P256Error::InvalidPublicKey)?;
    let sig = Signature::from_slice(sig_raw).map_err(|_| P256Error::InvalidSignature)?;
    key.verify(msg, &sig)
        .map_err(|_| P256Error::InvalidSignature)
}

/// ECDH: coordenada x de [priv]pub_peer. Rejeita ponto identidade/invalido.
pub fn ecdh_p256(secret: &[u8; 32], peer_sec1: &[u8]) -> Result<[u8; 32], P256Error> {
    let sk = SecretKey::from_slice(secret).map_err(|_| P256Error::InvalidSecret)?;
    let peer = PublicKey::from_sec1_bytes(peer_sec1).map_err(|_| P256Error::InvalidPublicKey)?;
    let scalar = sk.to_nonzero_scalar();
    let shared = ProjectivePoint::from(*peer.as_affine()) * scalar.as_ref();
    let encoded = shared.to_affine().to_encoded_point(false);
    let x = encoded.x().ok_or(P256Error::IdentityPeer)?;
    let mut out = [0u8; 32];
    copy_n(x, &mut out);
    Ok(out)
}

/// Copia exata src->dst sem `as_slice` depreciado (generic-array 0.14).
fn copy_n<const N: usize>(src: &[u8], out: &mut [u8; N]) {
    assert_eq!(src.len(), N);
    for (d, s) in out.iter_mut().zip(src.iter()) {
        *d = *s;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex valido")
    }

    const G_COMPRESSED: &str = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const G_X: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";

    fn raw_one() -> [u8; 32] {
        let mut raw = [0u8; 32];
        raw[31] = 1;
        raw
    }

    fn secret_one() -> P256Secret {
        P256Secret::from_bytes(raw_one()).expect("1 e escalar valido")
    }

    #[test]
    fn kat_generator_matches_secret_one() {
        // Vetor CAVP: pub(1) == ponto gerador G (comprimido).
        let sec = secret_one();
        assert_eq!(
            sec.public_compressed().as_slice(),
            h(G_COMPRESSED).as_slice()
        );
    }

    #[test]
    fn ecdh_with_generator_returns_gx() {
        // Vetor ECDH: agree(1, G) == Gx.
        let gx = ecdh_p256(&raw_one(), &h(G_COMPRESSED)).expect("ecdh valido");
        assert_eq!(gx.as_slice(), h(G_X).as_slice());
    }

    #[test]
    fn ecdh_symmetry() {
        let mut a = [0u8; 32];
        a[31] = 3;
        let mut b = [0u8; 32];
        b[31] = 5;
        let pa = P256Secret::from_bytes(a).unwrap().public_compressed();
        let pb = P256Secret::from_bytes(b).unwrap().public_compressed();
        assert_eq!(ecdh_p256(&a, &pb).unwrap(), ecdh_p256(&b, &pa).unwrap());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sec = secret_one();
        let pk = sec.public_compressed();
        let sig = sec.sign(b"ctap challenge");
        verify_p256(&pk, b"ctap challenge", &sig).expect("assinatura valida");
    }

    #[test]
    fn rejects_tampered_and_wrong_key() {
        let sec = secret_one();
        let pk = sec.public_compressed();
        let mut sig = sec.sign(b"msg");
        sig[0] ^= 0x01;
        assert_eq!(
            verify_p256(&pk, b"msg", &sig),
            Err(P256Error::InvalidSignature)
        );
        let mut other = [0u8; 32];
        other[31] = 2;
        let pk2 = P256Secret::from_bytes(other).unwrap().public_compressed();
        let sig = sec.sign(b"msg");
        assert_eq!(
            verify_p256(&pk2, b"msg", &sig),
            Err(P256Error::InvalidSignature)
        );
        assert_eq!(
            verify_p256(&pk, b"outra msg", &sig),
            Err(P256Error::InvalidSignature)
        );
    }

    #[test]
    fn rejects_invalid_inputs() {
        // Wycheproof: escalar zero nao e chave.
        assert_eq!(
            P256Secret::from_bytes([0u8; 32]).unwrap_err(),
            P256Error::InvalidSecret
        );
        // Wycheproof: chave publica malformada/truncada.
        assert_eq!(
            verify_p256(&[0x02], b"m", &[0u8; 64]),
            Err(P256Error::InvalidPublicKey)
        );
        assert_eq!(
            ecdh_p256(&raw_one(), &[0x04]),
            Err(P256Error::InvalidPublicKey)
        );
        // Assinatura toda-zero nao e valida.
        let sec = secret_one();
        let pk = sec.public_compressed();
        assert_eq!(
            verify_p256(&pk, b"m", &[0u8; 64]),
            Err(P256Error::InvalidSignature)
        );
        // Mensagem vazia assina e verifica (CTAP assina bytes arbitrarios).
        let sig = sec.sign(b"");
        verify_p256(&pk, b"", &sig).expect("msg vazia valida");
    }

    #[test]
    fn backend_traits_agree() {
        let peer = h(G_COMPRESSED);
        assert_eq!(
            SoftwareP256::ecdh(&raw_one(), &peer).unwrap(),
            EspP256::ecdh(&raw_one(), &peer).unwrap()
        );
    }

    #[test]
    fn debug_never_leaks_secret() {
        let sec = secret_one();
        let dbg = format!("{:?}", sec);
        assert!(dbg.contains("redacted"));
        assert_eq!(dbg, "P256Secret(redacted)");
    }
}
