// T-ST-04 DKEK n-de-m: Shamir Secret Sharing sobre GF(256) (GEN-DEVICE).
//
// Motivo: o DKEK raiz e o DEK vivem em eFuse/NVS, mas nenhum modulo provava
// a fragmentacao n-de-m para custodia distribuida; sem este modulo, shares
// seriam copias manuais sem politica de quorum (secao 9).
//
// - GEN-DEVICE: split/recover executam no device; segredo e shares nunca
//   saem em log e buffers sensiveis sao zerados apos o uso.
// - Matematica: polinomio aleatorio de grau m-1 sobre GF(2^8) (polinomio
//   do AES, 0x11B); share x em 1..=n; reconstrucao por Lagrange em x = 0.
//   Multiplicacao por "peasant" (sem tabelas: cabe na RAM do S3).
// - Limites: segredo 1..=64 B (DEK tem 32); 2 <= m <= n <= 32.
// - Fail-closed: quorum incompleto nega (InsufficientShares) em vez de
//   devolver lixo; x duplicado/zero e comprimentos divergentes negam.
// - HW via trait: aleatoriedade por HrngSource (R14); o TRNG do S3 entra
//   pelo HrngSource do HW.
// - Power-loss: split/recover sao puros (sem estado parcial); quem persiste
//   shares usa verify-after-write da camada de cima.
// - Share::encode/decode: formato x || len || y para transporte; decode
//   rejeita truncado (fuzz) e x = 0.
// - Sem segredo em log: erros nao carregam bytes de segredo/share.

extern crate alloc;

use alloc::vec::Vec;
use zeroize::Zeroize;

use crate::crypto_hrng::{HrngError, HrngSource};

/// Teto do segredo (DEK de 32 B cabe com folga).
pub const DKEK_MAX_SECRET: usize = 64;
/// Teto de shares (cabe na RAM; quorum tipico e 2..5).
pub const DKEK_MAX_SHARES: u8 = 32;

/// Erros do DKEK. Nenhuma variante carrega segredo ou share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkekError {
    /// Parametros fora de 2 <= m <= n <= 32.
    BadParams,
    /// Segredo vazio.
    EmptySecret,
    /// Segredo acima de 64 B.
    TooLarge,
    /// Quorum menor que o limiar (fail-closed, sem lixo).
    InsufficientShares,
    /// Dois shares com o mesmo x.
    DuplicateX,
    /// Share com x = 0 (reservado ao segredo).
    ZeroX,
    /// Shares com comprimentos de y divergentes.
    LengthMismatch,
    /// Encoding x || len || y malformado ou truncado.
    BadEncoding,
    /// HRNG indisponivel para os coeficientes.
    Rng,
}

impl core::fmt::Display for DkekError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadParams => write!(f, "bad dkek params"),
            Self::EmptySecret => write!(f, "empty dkek secret"),
            Self::TooLarge => write!(f, "dkek secret too large"),
            Self::InsufficientShares => write!(f, "insufficient dkek shares"),
            Self::DuplicateX => write!(f, "duplicate dkek share"),
            Self::ZeroX => write!(f, "zero dkek share index"),
            Self::LengthMismatch => write!(f, "mismatched dkek share length"),
            Self::BadEncoding => write!(f, "bad dkek encoding"),
            Self::Rng => write!(f, "dkek rng failure"),
        }
    }
}

impl From<HrngError> for DkekError {
    fn from(_: HrngError) -> Self {
        Self::Rng
    }
}

/// Um share: abscissa nao-zero mais os bytes avaliados do polinomio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    x: u8,
    y: Vec<u8>,
}

impl Share {
    /// Constroi validando x e y (comprimento 1..=64).
    pub fn new(x: u8, y: Vec<u8>) -> Result<Self, DkekError> {
        if x == 0 {
            return Err(DkekError::ZeroX);
        }
        if y.is_empty() {
            return Err(DkekError::EmptySecret);
        }
        if y.len() > DKEK_MAX_SECRET {
            return Err(DkekError::TooLarge);
        }
        Ok(Self { x, y })
    }

    /// Abscissa do share.
    pub fn x(&self) -> u8 {
        self.x
    }

    /// Bytes do share (apoio a envelope; o chamador zera apos o uso).
    pub fn y(&self) -> &[u8] {
        &self.y
    }

    /// Serializa x || len || y (len cabe em 1 B: max 64).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.y.len());
        out.push(self.x);
        out.push(self.y.len() as u8);
        out.extend_from_slice(&self.y);
        out
    }

    /// Desserializa com rejeicao de truncado e de x = 0.
    pub fn decode(raw: &[u8]) -> Result<Self, DkekError> {
        if raw.len() < 3 {
            return Err(DkekError::BadEncoding);
        }
        let len = raw[1] as usize;
        if len == 0 || len > DKEK_MAX_SECRET || raw.len() != 2 + len {
            return Err(DkekError::BadEncoding);
        }
        Self::new(raw[0], raw[2..].to_vec())
    }

    /// Apaga os bytes do share.
    pub fn wipe(&mut self) {
        self.y.zeroize();
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

/// Soma em GF(256) = XOR.
#[inline]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplicacao em GF(256) mod 0x11B (peasant).
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

/// Potencia em GF(256).
fn gf_pow(mut a: u8, mut e: u8) -> u8 {
    let mut r: u8 = 1;
    while e != 0 {
        if e & 1 != 0 {
            r = gf_mul(r, a);
        }
        a = gf_mul(a, a);
        e >>= 1;
    }
    r
}

/// Inverso em GF(256) (a^254); zero nao tem inverso (nunca chamado com 0).
fn gf_inv(a: u8) -> u8 {
    gf_pow(a, 254)
}

fn check_params(secret_len: usize, n: u8, m: u8) -> Result<(), DkekError> {
    if secret_len == 0 {
        return Err(DkekError::EmptySecret);
    }
    if secret_len > DKEK_MAX_SECRET {
        return Err(DkekError::TooLarge);
    }
    if m < 2 || m > n || n > DKEK_MAX_SHARES {
        return Err(DkekError::BadParams);
    }
    Ok(())
}

/// Divide o segredo em n shares com limiar m (coeficientes via HRNG).
pub fn split<R: HrngSource>(
    rng: &mut R,
    secret: &[u8],
    n: u8,
    m: u8,
) -> Result<Vec<Share>, DkekError> {
    check_params(secret.len(), n, m)?;
    let degree = (m - 1) as usize;
    let mut coeffs = alloc::vec![0u8; degree * secret.len()];
    rng.fill(&mut coeffs)?;
    let mut out = Vec::with_capacity(n as usize);
    for xi in 1..=n {
        let mut y = Vec::with_capacity(secret.len());
        for (i, &s) in secret.iter().enumerate() {
            // Horner: y = s + c1*x + c2*x^2 + ...
            let mut acc = s;
            let mut xp: u8 = 1;
            for d in 0..degree {
                xp = gf_mul(xp, xi);
                acc = gf_add(acc, gf_mul(coeffs[d * secret.len() + i], xp));
            }
            y.push(acc);
        }
        out.push(Share { x: xi, y });
    }
    coeffs.zeroize();
    Ok(out)
}

/// Recompoe o segredo por Lagrange em x = 0 usando TODOS os shares dados.
///
/// O chamador passa exatamente o quorum que quer usar; quorum curto nega
/// com InsufficientShares (nunca devolve lixo parcial).
pub fn recover(shares: &[Share], m: u8) -> Result<Vec<u8>, DkekError> {
    if m < 2 {
        return Err(DkekError::BadParams);
    }
    if shares.len() < m as usize {
        return Err(DkekError::InsufficientShares);
    }
    let len = shares[0].y.len();
    if len == 0 || len > DKEK_MAX_SECRET {
        return Err(DkekError::BadEncoding);
    }
    for s in shares.iter() {
        if s.x == 0 {
            return Err(DkekError::ZeroX);
        }
        if s.y.len() != len {
            return Err(DkekError::LengthMismatch);
        }
    }
    for (i, a) in shares.iter().enumerate() {
        for b in shares.iter().skip(i + 1) {
            if a.x == b.x {
                return Err(DkekError::DuplicateX);
            }
        }
    }
    let mut secret = alloc::vec![0u8; len];
    for j in shares.iter() {
        // L_j(0) = prod x_k / (x_j - x_k); subtracao = XOR.
        let mut num: u8 = 1;
        let mut den: u8 = 1;
        for k in shares.iter() {
            if k.x == j.x {
                continue;
            }
            num = gf_mul(num, k.x);
            den = gf_mul(den, gf_add(j.x, k.x));
        }
        let lj = gf_mul(num, gf_inv(den));
        for (i, out) in secret.iter_mut().enumerate() {
            *out = gf_add(*out, gf_mul(j.y[i], lj));
        }
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HRNG deterministico de teste (xorshift64; so p/ coeficientes).
    struct TestRng(u64);

    impl HrngSource for TestRng {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), HrngError> {
            if dest.is_empty() {
                return Err(HrngError::TooShort);
            }
            for b in dest.iter_mut() {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *b = (self.0 & 0xFF) as u8;
            }
            Ok(())
        }
    }

    #[test]
    fn gf_vetores_fips197() {
        // FIPS-197 secao 4.2: 0x57 . 0x13 = 0xFE e 0x57 . 0x83 = 0xC1.
        assert_eq!(gf_mul(0x57, 0x13), 0xFE);
        assert_eq!(gf_mul(0x57, 0x83), 0xC1);
        // Exemplo do S-box: inverso de 0x53 e 0xCA.
        assert_eq!(gf_inv(0x53), 0xCA);
        assert_eq!(gf_mul(0x53, 0xCA), 0x01);
        assert_eq!(gf_mul(0x00, 0xA5), 0x00);
        assert_eq!(gf_mul(0x01, 0xA5), 0xA5);
        assert_eq!(gf_add(0xFF, 0xFF), 0x00);
    }

    #[test]
    fn vetor_recomposicao_manual() {
        // f(x) = 0x42 + 0x01*x (limiar 2), calculado a mao:
        // f(1) = 0x42 ^ 0x01 = 0x43; f(2) = 0x42 ^ 0x02 = 0x40.
        let s1 = Share::new(1, alloc::vec![0x43]).unwrap();
        let s2 = Share::new(2, alloc::vec![0x40]).unwrap();
        assert_eq!(recover(&[s1, s2], 2).unwrap(), alloc::vec![0x42]);
        // Dois bytes, a = [0x01, 0x03]: f(1) = [0x43, 0x13];
        // f(2): 0x03*0x02 = xtime(0x03) = 0x06, 0x10 ^ 0x06 = 0x16.
        let t1 = Share::new(1, alloc::vec![0x43, 0x13]).unwrap();
        let t2 = Share::new(2, alloc::vec![0x40, 0x16]).unwrap();
        assert_eq!(recover(&[t1, t2], 2).unwrap(), alloc::vec![0x42, 0x10]);
    }

    #[test]
    fn split_recover_roundtrip() {
        let secret = b"DEK-de-32-bytes-para-o-AegisKey!";
        assert_eq!(secret.len(), 32);
        for (n, m) in [(2, 2), (3, 2), (5, 3), (5, 5)] {
            let mut rng = TestRng(0x1234_5678_9ABC_DEF0);
            let shares = split(&mut rng, secret, n, m).unwrap();
            assert_eq!(shares.len() as u8, n);
            let quorum = shares[..m as usize].to_vec();
            assert_eq!(recover(&quorum, m).unwrap(), secret.to_vec());
            let tail = shares[(n - m) as usize..].to_vec();
            assert_eq!(recover(&tail, m).unwrap(), secret.to_vec());
            // Quorum curto nega, sem lixo.
            assert_eq!(
                recover(&shares[..(m - 1) as usize], m),
                Err(DkekError::InsufficientShares)
            );
        }
    }

    #[test]
    fn deterministico_com_mesmo_rng() {
        let mut a = TestRng(0xAA);
        let mut b = TestRng(0xAA);
        let sa = split(&mut a, b"segredo", 3, 2).unwrap();
        let sb = split(&mut b, b"segredo", 3, 2).unwrap();
        assert_eq!(sa, sb);
    }

    #[test]
    fn share_adulterado_nao_recompoe() {
        let mut rng = TestRng(0x55);
        let shares = split(&mut rng, b"0123456789ABCDEF", 3, 2).unwrap();
        let mut bad = shares[..2].to_vec();
        bad[0].y[0] ^= 0x01;
        assert_ne!(recover(&bad, 2).unwrap(), b"0123456789ABCDEF".to_vec());
    }

    #[test]
    fn rejeita_quorum_invalido() {
        let ok1 = Share::new(1, alloc::vec![0x43]).unwrap();
        let ok2 = Share::new(2, alloc::vec![0x40]).unwrap();
        let dup = Share::new(1, alloc::vec![0x00]).unwrap();
        assert_eq!(recover(&[ok1.clone(), dup], 2), Err(DkekError::DuplicateX));
        let dif = Share::new(3, alloc::vec![0x00, 0x01]).unwrap();
        assert_eq!(
            recover(&[ok1.clone(), dif], 2),
            Err(DkekError::LengthMismatch)
        );
        assert_eq!(recover(&[ok1, ok2], 1), Err(DkekError::BadParams));
    }

    #[test]
    fn limites_e_encoding() {
        let mut rng = TestRng(1);
        assert_eq!(split(&mut rng, b"", 3, 2), Err(DkekError::EmptySecret));
        assert_eq!(split(&mut rng, &[0u8; 65], 3, 2), Err(DkekError::TooLarge));
        assert_eq!(split(&mut rng, b"s", 3, 1), Err(DkekError::BadParams));
        assert_eq!(split(&mut rng, b"s", 2, 3), Err(DkekError::BadParams));
        assert_eq!(split(&mut rng, b"s", 33, 2), Err(DkekError::BadParams));
        assert_eq!(Share::new(0, alloc::vec![0x01]), Err(DkekError::ZeroX));
        assert_eq!(Share::new(1, Vec::new()), Err(DkekError::EmptySecret));
        let s = Share::new(7, alloc::vec![0xDE, 0xAD]).unwrap();
        let enc = s.encode();
        assert_eq!(enc, alloc::vec![7, 2, 0xDE, 0xAD]);
        assert_eq!(Share::decode(&enc).unwrap(), s);
        assert_eq!(Share::decode(&enc[..3]), Err(DkekError::BadEncoding));
        assert_eq!(Share::decode(&enc[..2]), Err(DkekError::BadEncoding));
        assert_eq!(Share::decode(&[0, 1, 0xFF]), Err(DkekError::ZeroX));
        let mut with_extra = enc.clone();
        with_extra.push(0x00);
        assert_eq!(Share::decode(&with_extra), Err(DkekError::BadEncoding));
    }
}
