// T-ST-03 HD SLIP-0010: derivacao ed25519 + nist256p1-hardened (GEN-DEVICE).
//
// Motivo: a matriz exige HD BIP32/SLIP-0010 com vetores, mas nenhum modulo
// provava derivacao hierarquica; sem este modulo, chaves HD viriam de
// construcao ad-hoc sem vetor oficial (secao 9).
//
// - GEN-DEVICE: master e filhas derivam no device a partir da semente;
//   a privada nunca sai em log e intermediarios sao zerados.
// - Escopo atomico: SLIP-0010 (salt por curva). ed25519 e curve25519 usam
//   so HMAC-SHA512 (sem EC na derivacao); nist256p1 usa soma mod-n manual.
//   Derivacao nao-hardened exige ponto EC e e negada (fail-closed,
//   UnsupportedDerivation); BIP32/secp256k1 de cadeia publica tambem fica
//   de fora (sem crate secp no firmware: NotCompiled honesto).
// - Retry fiel a SLIP-0010: master invalido refaz com S := I; filho
//   nist invalido refaz com 0x01 || IR || ser32(i); teto de 64 voltas.
// - Limites: semente 16..=64 B; caminho ate 16 indices; so hardened.
// - Power-loss: derivacao e pura (sem estado parcial); nada a corromper;
//   determinismo total e testado (derivar 2x = igual).
// - Vetores: SLIP-0010 oficiais (ed25519 v1/v2, nist256p1 v1 + retries).

extern crate alloc;

use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

/// Semente minima (128 bits) e maxima (512 bits) da SLIP-0010.
pub const SEED_MIN: usize = 16;
/// Semente maxima (512 bits).
pub const SEED_MAX: usize = 64;
/// Bit de hardened nos indices.
pub const HARDENED: u32 = 0x8000_0000;
/// Teto de profundidade do caminho (limite de API, sem custo de RAM).
pub const MAX_PATH: usize = 16;
/// Teto de voltas do retry SLIP-0010 (prob. de estourar < 2^-500).
pub const MAX_RETRY: u8 = 64;

/// Sal HMAC da master por curva (SLIP-0010, secao "Master key generation").
pub const SALT_ED25519: &[u8] = b"ed25519 seed";
/// Sal HMAC da master nist256p1.
pub const SALT_NIST256P1: &[u8] = b"Nist256p1 seed";

/// Ordem n da P-256 (big-endian), p/ soma mod-n do CKD hardened.
const P256_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// Curvas com derivacao implementada neste modulo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdCurve {
    /// ed25519 via SLIP-0010 (so hardened, sem EC na derivacao).
    Ed25519,
    /// NIST P-256 via SLIP-0010 (so hardened; soma mod-n manual).
    Nist256p1,
}

/// Erros da HD. Nenhuma variante carrega semente ou privada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdError {
    /// Semente fora de 16..=64 B.
    BadSeed,
    /// Indice sem bit hardened (ed25519/nist aqui so aceitam hardened).
    NotHardened,
    /// Derivacao nao-hardened (exige ponto EC; nao compilado aqui).
    UnsupportedDerivation,
    /// Chave invalida (>= n ou zero apos retry).
    InvalidKey,
    /// Retry SLIP-0010 estourou o teto (praticamente impossivel).
    ChainExhausted,
    /// Caminho acima de 16 indices.
    PathTooDeep,
    /// Falha interna do HMAC (inatingivel; fail-closed sem panic).
    Internal,
}

impl core::fmt::Display for HdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadSeed => write!(f, "bad hd seed length"),
            Self::NotHardened => write!(f, "hd index not hardened"),
            Self::UnsupportedDerivation => write!(f, "hd non-hardened unsupported"),
            Self::InvalidKey => write!(f, "invalid hd key"),
            Self::ChainExhausted => write!(f, "hd retry exhausted"),
            Self::PathTooDeep => write!(f, "hd path too deep"),
            Self::Internal => write!(f, "hd internal failure"),
        }
    }
}

/// Chave estendida privada (32 B chave + 32 B chain code).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XPriv {
    key: [u8; 32],
    chain: [u8; 32],
}

impl XPriv {
    /// Chave privada (32 B).
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Chain code (32 B).
    pub fn chain(&self) -> &[u8; 32] {
        &self.chain
    }

    /// Apaga chave e chain.
    pub fn wipe(&mut self) {
        self.key.zeroize();
        self.chain.zeroize();
    }
}

impl Drop for XPriv {
    fn drop(&mut self) {
        self.wipe();
    }
}

fn hmac512(key: &[u8], data: &[u8]) -> Result<[u8; 64], HdError> {
    let mut m = Hmac::<Sha512>::new_from_slice(key).map_err(|_| HdError::Internal)?;
    m.update(data);
    let out = m.finalize().into_bytes();
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&out);
    Ok(buf)
}

fn cmp_be(a: &[u8; 32], b: &[u8; 32]) -> core::cmp::Ordering {
    a.cmp(b)
}

fn is_zero(a: &[u8; 32]) -> bool {
    a.iter().all(|&b| b == 0)
}

/// (a + b) mod n da P-256; bytes big-endian.
fn add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut sum = [0u8; 32];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let s = a[i] as u16 + b[i] as u16 + carry;
        sum[i] = (s & 0xFF) as u8;
        carry = s >> 8;
    }
    if carry != 0 || cmp_be(&sum, &P256_N) != core::cmp::Ordering::Less {
        // sum -= n (sum >= n garantido aqui).
        let mut borrow: i16 = 0;
        for i in (0..32).rev() {
            let d = sum[i] as i16 - P256_N[i] as i16 - borrow;
            sum[i] = (d & 0xFF) as u8;
            borrow = if d < 0 { 1 } else { 0 };
        }
    }
    sum
}

fn check_seed(seed: &[u8]) -> Result<(), HdError> {
    if (SEED_MIN..=SEED_MAX).contains(&seed.len()) {
        Ok(())
    } else {
        Err(HdError::BadSeed)
    }
}

/// Master SLIP-0010 (com retry p/ curvas com ordem: nist256p1).
pub fn master(seed: &[u8], curve: HdCurve) -> Result<XPriv, HdError> {
    check_seed(seed)?;
    let salt = match curve {
        HdCurve::Ed25519 => SALT_ED25519,
        HdCurve::Nist256p1 => SALT_NIST256P1,
    };
    let mut s: Vec<u8> = seed.to_vec();
    for _ in 0..MAX_RETRY {
        let i = hmac512(salt, &s)?;
        let mut key = [0u8; 32];
        let mut chain = [0u8; 32];
        key.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
        s.zeroize();
        match curve {
            HdCurve::Ed25519 => return Ok(XPriv { key, chain }),
            HdCurve::Nist256p1 => {
                // Retry da spec: IL == 0 ou >= n refaz com S := I.
                if !is_zero(&key) && cmp_be(&key, &P256_N) == core::cmp::Ordering::Less {
                    return Ok(XPriv { key, chain });
                }
                key.zeroize();
                chain.zeroize();
                s = i.to_vec();
            }
        }
    }
    s.zeroize();
    Err(HdError::ChainExhausted)
}

/// Filha hardened a partir de pai privado (ed25519 ou nist256p1).
pub fn child_hardened(parent: &XPriv, index: u32, curve: HdCurve) -> Result<XPriv, HdError> {
    if index < HARDENED {
        return Err(HdError::NotHardened);
    }
    // Dado do HMAC: 0x00 || ser256(kpar) || ser32(i).
    let mut data = [0u8; 37];
    data[1..33].copy_from_slice(parent.key());
    data[33..37].copy_from_slice(&index.to_be_bytes());
    let mut i = hmac512(parent.chain(), &data)?;
    data.zeroize();
    for _ in 0..MAX_RETRY {
        let mut il = [0u8; 32];
        let mut chain = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
        match curve {
            HdCurve::Ed25519 => {
                i.zeroize();
                return Ok(XPriv { key: il, chain });
            }
            HdCurve::Nist256p1 => {
                // Spec passo 5: IL >= n ou IL + kpar == 0 refaz com
                // 0x01 || IR || ser32(i).
                let bad_il = is_zero(&il) || cmp_be(&il, &P256_N) != core::cmp::Ordering::Less;
                let ki = add_mod_n(&il, parent.key());
                il.zeroize();
                if !bad_il && !is_zero(&ki) {
                    i.zeroize();
                    return Ok(XPriv { key: ki, chain });
                }
                let mut retry = [0u8; 37];
                retry[0] = 0x01;
                retry[1..33].copy_from_slice(&i[32..]);
                retry[33..37].copy_from_slice(&index.to_be_bytes());
                i.zeroize();
                i = hmac512(parent.chain(), &retry)?;
                retry.zeroize();
            }
        }
    }
    i.zeroize();
    Err(HdError::ChainExhausted)
}

/// Deriva o caminho (todos os indices hardened) a partir da semente.
pub fn derive_path(seed: &[u8], curve: HdCurve, path: &[u32]) -> Result<XPriv, HdError> {
    if path.len() > MAX_PATH {
        return Err(HdError::PathTooDeep);
    }
    let mut cur = master(seed, curve)?;
    for &index in path {
        let next = child_hardened(&cur, index, curve)?;
        cur.wipe();
        cur = next;
    }
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex do vetor")
    }

    fn hx(b: &[u8]) -> Vec<u8> {
        b.to_vec()
    }

    const H: u32 = HARDENED;

    #[test]
    fn slip10_ed25519_vetor1_cadeia() {
        let seed = h("000102030405060708090a0b0c0d0e0f");
        let m = master(&seed, HdCurve::Ed25519).unwrap();
        assert_eq!(
            hx(m.key()),
            h("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")
        );
        assert_eq!(
            hx(m.chain()),
            h("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb")
        );
        // Chave publica confere com ed25519-dalek (0x00 || ENC do vetor).
        let sk = ed25519_dalek::SigningKey::from_bytes(m.key());
        assert_eq!(
            sk.verifying_key().to_bytes().to_vec(),
            h("a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed")
        );
        let c0 = child_hardened(&m, H, HdCurve::Ed25519).unwrap();
        assert_eq!(
            hx(c0.key()),
            h("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3")
        );
        assert_eq!(
            hx(c0.chain()),
            h("8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69")
        );
        let full = derive_path(
            &seed,
            HdCurve::Ed25519,
            &[H, H + 1, H + 2, H + 2, H + 1_000_000_000],
        )
        .unwrap();
        assert_eq!(
            hx(full.key()),
            h("8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793")
        );
        assert_eq!(
            hx(full.chain()),
            h("68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230")
        );
        // Prefixo m/0H/1H/2H do mesmo vetor.
        let mid = derive_path(&seed, HdCurve::Ed25519, &[H, H + 1, H + 2]).unwrap();
        assert_eq!(
            hx(mid.key()),
            h("92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9")
        );
        assert_eq!(
            hx(mid.chain()),
            h("2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c")
        );
    }

    #[test]
    fn slip10_ed25519_vetor2_master_e_filha() {
        let seed = h("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
        let m = master(&seed, HdCurve::Ed25519).unwrap();
        assert_eq!(
            hx(m.key()),
            h("171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012")
        );
        assert_eq!(
            hx(m.chain()),
            h("ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b")
        );
        let c0 = child_hardened(&m, H, HdCurve::Ed25519).unwrap();
        assert_eq!(
            hx(c0.key()),
            h("1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635")
        );
        assert_eq!(
            hx(c0.chain()),
            h("0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d")
        );
    }

    #[test]
    fn slip10_nist256p1_vetor1_master_e_hardened() {
        let seed = h("000102030405060708090a0b0c0d0e0f");
        let m = master(&seed, HdCurve::Nist256p1).unwrap();
        assert_eq!(
            hx(m.key()),
            h("612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2")
        );
        assert_eq!(
            hx(m.chain()),
            h("beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea")
        );
        let c0 = child_hardened(&m, H, HdCurve::Nist256p1).unwrap();
        assert_eq!(
            hx(c0.key()),
            h("6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c")
        );
        assert_eq!(
            hx(c0.chain()),
            h("3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11")
        );
        // Vetor de retry de derivacao: m/28578H.
        let r = child_hardened(&m, H + 28578, HdCurve::Nist256p1).unwrap();
        assert_eq!(
            hx(r.key()),
            h("06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669")
        );
        assert_eq!(
            hx(r.chain()),
            h("e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2")
        );
    }

    #[test]
    fn slip10_nist256p1_seed_retry() {
        // Semente cuja master direta e invalida: retry com S := I.
        let seed = h("a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446");
        let m = master(&seed, HdCurve::Nist256p1).unwrap();
        assert_eq!(
            hx(m.key()),
            h("3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f")
        );
        assert_eq!(
            hx(m.chain()),
            h("7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c")
        );
    }

    #[test]
    fn rejeita_nao_hardened_e_limites() {
        let seed = h("000102030405060708090a0b0c0d0e0f");
        let m = master(&seed, HdCurve::Ed25519).unwrap();
        // Indice sem bit H nega nas duas curvas.
        assert_eq!(
            child_hardened(&m, 1, HdCurve::Ed25519),
            Err(HdError::NotHardened)
        );
        let mn = master(&seed, HdCurve::Nist256p1).unwrap();
        assert_eq!(
            child_hardened(&mn, 0, HdCurve::Nist256p1),
            Err(HdError::NotHardened)
        );
        // Sementes fora de 16..=64 B.
        assert_eq!(master(&h("00"), HdCurve::Ed25519), Err(HdError::BadSeed));
        assert_eq!(
            master(&alloc::vec![0u8; 65], HdCurve::Ed25519),
            Err(HdError::BadSeed)
        );
        // Caminho acima de 16.
        let long = [H; 17];
        assert_eq!(
            derive_path(&seed, HdCurve::Ed25519, &long),
            Err(HdError::PathTooDeep)
        );
        // Caminho vazio = master.
        assert_eq!(derive_path(&seed, HdCurve::Ed25519, &[]).unwrap(), m);
    }

    #[test]
    fn determinismo_power_loss_safe() {
        // Derivacao pura: derivar 2x apos "quedas" da o mesmo (nada parcial).
        let seed = h("000102030405060708090a0b0c0d0e0f");
        let a = derive_path(&seed, HdCurve::Ed25519, &[H, H + 1]).unwrap();
        let b = derive_path(&seed, HdCurve::Ed25519, &[H, H + 1]).unwrap();
        assert_eq!(a, b);
        let c = derive_path(&seed, HdCurve::Nist256p1, &[H]).unwrap();
        let d = derive_path(&seed, HdCurve::Nist256p1, &[H]).unwrap();
        assert_eq!(c, d);
    }

    #[test]
    fn soma_mod_n_borda() {
        // (n-1) + 1 = 0 mod n; n + 0 = 0 (reduz); 1 + 1 = 2.
        let mut nm1 = P256_N;
        nm1[31] = nm1[31].wrapping_sub(1);
        let one = [0u8; 31]
            .iter()
            .cloned()
            .chain([1u8].iter().cloned())
            .collect::<Vec<u8>>();
        let mut o = [0u8; 32];
        o.copy_from_slice(&one);
        assert_eq!(add_mod_n(&nm1, &o), [0u8; 32]);
        assert_eq!(add_mod_n(&P256_N, &[0u8; 32]), [0u8; 32]);
        assert_eq!(add_mod_n(&o, &o)[31], 2);
    }
}
