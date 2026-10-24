//! T-CR-03 SHA-2 / HMAC / HKDF / PBKDF2 (GEN-DEVICE).
//!
//! Motivo: PIN/UV, envelopes e backup derivam chaves de segredos; sem KDF
//! provada por vetor, derivacao vira elo fraco (secao 9).
//!
//! - SHA-256/384/512 e HMAC-SHA-256 via `sha2`/`hmac` (software real).
//! - HKDF-SHA-256 (RFC 5869) e PBKDF2-HMAC-SHA-256 (RFC 2898) escritos sobre
//!   o HMAC acima: sem crates novas, auditoria local, limites de DoS.
//! - Limites: PBKDF2 1..=600_000 iteracoes (teto OWASP SHA-256), dkLen<=64,
//!   HKDF info<=1024, saida<=255*32.

extern crate alloc;

use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};

type HmacSha256 = Hmac<Sha256>;

/// Comprimentos de saida.
pub const SHA256_LEN: usize = 32;
pub const SHA384_LEN: usize = 48;
pub const SHA512_LEN: usize = 64;
/// Teto de saida do HKDF-expand (255 blocos de 32 bytes, RFC 5869).
pub const HKDF_MAX_OKM: usize = 255 * 32;
/// Teto de entrada auxiliar do HKDF nesta firmware.
pub const HKDF_MAX_INFO: usize = 1024;
/// Teto de iteracoes do PBKDF2 (OWASP para HMAC-SHA-256).
pub const PBKDF2_MAX_ITER: u32 = 600_000;
/// Teto de saida do PBKDF2 (2 blocos de 32 bytes bastam para DEK + salt).
pub const PBKDF2_MAX_DKLEN: usize = 64;

/// Erros de hash/KDF. Sem material secreto nas variantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashError {
    BadLength,
    BadIterations,
    TooLarge,
}

pub fn sha256(data: &[u8]) -> [u8; SHA256_LEN] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha384(data: &[u8]) -> [u8; SHA384_LEN] {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha512(data: &[u8]) -> [u8; SHA512_LEN] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize().into()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; SHA256_LEN] {
    // new_from_slice so falha com erro de tamanho; HMAC aceita qualquer chave.
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC aceita qualquer chave");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// HKDF-Extract (RFC 5869 secao 2.2). Salt vazio vira 32 zeros.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Result<[u8; SHA256_LEN], HashError> {
    if ikm.is_empty() || ikm.len() > HKDF_MAX_INFO {
        return Err(HashError::BadLength);
    }
    if salt.len() > HKDF_MAX_INFO {
        return Err(HashError::BadLength);
    }
    let zero = [0u8; SHA256_LEN];
    let s = if salt.is_empty() { &zero[..] } else { salt };
    let mut m = HmacSha256::new_from_slice(s).expect("HMAC aceita qualquer chave");
    m.update(ikm);
    Ok(m.finalize().into_bytes().into())
}

/// HKDF-Expand (RFC 5869 secao 2.3). `len` em bytes, 1..=8160.
pub fn hkdf_expand(prk: &[u8; SHA256_LEN], info: &[u8], len: usize) -> Result<Vec<u8>, HashError> {
    if len == 0 || len > HKDF_MAX_OKM {
        return Err(HashError::BadLength);
    }
    if info.len() > HKDF_MAX_INFO {
        return Err(HashError::TooLarge);
    }
    let mut okm = Vec::new();
    let mut prev = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < len {
        let mut m = HmacSha256::new_from_slice(prk).expect("PRK tem 32 bytes");
        m.update(&prev);
        m.update(info);
        m.update(&[counter]);
        prev = m.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&prev);
        counter = counter.wrapping_add(1);
    }
    okm.truncate(len);
    Ok(okm)
}

/// HKDF completo conveniencia.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, HashError> {
    let prk = hkdf_extract(salt, ikm)?;
    hkdf_expand(&prk, info, len)
}

/// PBKDF2-HMAC-SHA-256 (RFC 2898). `out` recebe a chave derivada.
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<(), HashError> {
    if iterations == 0 || iterations > PBKDF2_MAX_ITER {
        return Err(HashError::BadIterations);
    }
    if out.is_empty() || out.len() > PBKDF2_MAX_DKLEN {
        return Err(HashError::BadLength);
    }
    if password.len() > 256 || salt.len() > 256 {
        return Err(HashError::TooLarge);
    }
    let blocks = out.len().div_ceil(SHA256_LEN);
    for (i, chunk) in out.chunks_mut(SHA256_LEN).enumerate() {
        let index = (i as u32 + 1).to_be_bytes();
        let mut mac = HmacSha256::new_from_slice(password).expect("senha cabe no HMAC");
        mac.update(salt);
        mac.update(&index);
        let mut u: [u8; SHA256_LEN] = mac.finalize().into_bytes().into();
        let mut acc = u;
        for _ in 1..iterations {
            let mut inner = HmacSha256::new_from_slice(password).expect("senha cabe no HMAC");
            inner.update(&u);
            u = inner.finalize().into_bytes().into();
            for (a, b) in acc.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }
        }
        let take = chunk.len().min(SHA256_LEN);
        chunk.copy_from_slice(&acc[..take]);
        let _ = blocks;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex valido")
    }

    #[test]
    fn sha2_kat() {
        assert_eq!(
            sha256(b"abc").as_slice(),
            h("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").as_slice()
        );
        assert_eq!(
            sha256(b"").as_slice(),
            h("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").as_slice()
        );
        assert_eq!(
            sha384(b"abc").as_slice(),
            h("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7").as_slice()
        );
        assert_eq!(
            sha512(b"abc").as_slice(),
            h("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f").as_slice()
        );
    }

    #[test]
    fn hmac_rfc4231() {
        // Caso 1 e 2 da RFC 4231.
        assert_eq!(
            hmac_sha256(&h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), b"Hi There").as_slice(),
            h("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").as_slice()
        );
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?").as_slice(),
            h("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843").as_slice()
        );
    }

    #[test]
    fn hkdf_rfc5869_caso1() {
        // RFC 5869 Ap. A caso 1 (SHA-256), PRK e OKM conferidos em Python/oraculo.
        let prk = hkdf_extract(
            &h("000102030405060708090a0b0c"),
            &h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        )
        .unwrap();
        assert_eq!(
            prk.as_slice(),
            h("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").as_slice()
        );
        let okm = hkdf_expand(&prk, &h("f0f1f2f3f4f5f6f7f8f9"), 42).unwrap();
        assert_eq!(
            okm.as_slice(),
            h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").as_slice()
        );
    }

    #[test]
    fn pbkdf2_rfc6070() {
        // Vetores RFC 6070 / RFC 2898 (conferidos em oraculo Python hashlib).
        let mut out = [0u8; 32];
        pbkdf2_hmac_sha256(b"password", b"salt", 1, &mut out).unwrap();
        assert_eq!(
            out.as_slice(),
            h("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b").as_slice()
        );
        pbkdf2_hmac_sha256(b"password", b"salt", 2, &mut out).unwrap();
        assert_eq!(
            out.as_slice(),
            h("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43").as_slice()
        );
        pbkdf2_hmac_sha256(b"password", b"salt", 4096, &mut out).unwrap();
        assert_eq!(
            out.as_slice(),
            h("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a").as_slice()
        );
    }

    #[test]
    fn rejects_invalid_truncated() {
        assert_eq!(hkdf_expand(&[0u8; 32], b"", 0), Err(HashError::BadLength));
        assert_eq!(
            hkdf_expand(&[0u8; 32], b"", HKDF_MAX_OKM + 1),
            Err(HashError::BadLength)
        );
        assert_eq!(hkdf_extract(b"s", b""), Err(HashError::BadLength));
        let mut out = [0u8; 32];
        assert_eq!(
            pbkdf2_hmac_sha256(b"p", b"s", 0, &mut out),
            Err(HashError::BadIterations)
        );
        assert_eq!(
            pbkdf2_hmac_sha256(b"p", b"s", PBKDF2_MAX_ITER + 1, &mut out),
            Err(HashError::BadIterations)
        );
        let mut empty = [];
        assert_eq!(
            pbkdf2_hmac_sha256(b"p", b"s", 1, &mut empty),
            Err(HashError::BadLength)
        );
        let mut huge = [0u8; PBKDF2_MAX_DKLEN + 1];
        assert_eq!(
            pbkdf2_hmac_sha256(b"p", b"s", 1, &mut huge),
            Err(HashError::BadLength)
        );
    }
}
