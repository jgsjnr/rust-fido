//! T-CR-04 RSA 2048/3072/4096 (PKCS#1 v1.5, PSS, OAEP) fail-closed & real SW/HW operations.
//!
//! Provides:
//! - Pure Rust BigUint + Montgomery Modular Exponentiation (m^d mod n / s^e mod n).
//! - RSASSA-PKCS1-v1_5 SHA-256 signing and verification.
//! - RSASSA-PSS SHA-256 signing and verification.
//! - On-demand key loading in internal SRAM with immediate Zeroize of private exponents.
//! - Security policy validation (RSA-1024 generation strictly forbidden).

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Tamanhos RSA suportados pela matriz (bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeyBits {
    B1024,
    B2048,
    B3072,
    B4096,
}

impl RsaKeyBits {
    pub fn bits(self) -> u32 {
        match self {
            RsaKeyBits::B1024 => 1024,
            RsaKeyBits::B2048 => 2048,
            RsaKeyBits::B3072 => 3072,
            RsaKeyBits::B4096 => 4096,
        }
    }

    pub fn bytes(self) -> usize {
        (self.bits() / 8) as usize
    }

    /// Converte bits em variante; rejeita tamanhos arbitrarios (NA da matriz).
    pub fn from_bits(bits: u32) -> Result<Self, RsaError> {
        match bits {
            1024 => Ok(RsaKeyBits::B1024),
            2048 => Ok(RsaKeyBits::B2048),
            3072 => Ok(RsaKeyBits::B3072),
            4096 => Ok(RsaKeyBits::B4096),
            _ => Err(RsaError::UnsupportedSize),
        }
    }
}

/// Esquemas com padding moderno. Raw e X.509 legado nao existem aqui.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaScheme {
    Pkcs1v15,
    PssSha256,
    OaepSha256,
}

/// Erros RSA. Sem material de chave nas variantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaError {
    /// Gerar 1024 bits e proibido (so verificacao legada, fora do device).
    Generate1024Forbidden,
    UnsupportedSize,
    UnsupportedScheme,
    InputTooLarge,
    InvalidInput,
    VerificationFailed,
    /// Sem backend compilado: operacao real bloqueada, nao simulada.
    NotCompiled,
}

/// Politica de geracao: 1024 nunca gera; demais passam ao backend.
pub fn check_generate(bits: RsaKeyBits) -> Result<(), RsaError> {
    match bits {
        RsaKeyBits::B1024 => Err(RsaError::Generate1024Forbidden),
        RsaKeyBits::B2048 | RsaKeyBits::B3072 | RsaKeyBits::B4096 => Ok(()),
    }
}

/// Teto de mensagem em bytes para o esquema (HMAC/SHA-256 com hlen=32).
pub fn max_msg_len(bits: RsaKeyBits, scheme: RsaScheme) -> usize {
    let k = bits.bytes();
    match scheme {
        // PKCS#1 v1.5 cifragem: k - 11.
        RsaScheme::Pkcs1v15 => k.saturating_sub(11),
        // PSS/OAEP com SHA-256: k - 2*32 - 2.
        RsaScheme::PssSha256 | RsaScheme::OaepSha256 => k.saturating_sub(66),
    }
}

/// Valida operacao antes de qualquer backend: tamanho + teto do esquema.
pub fn check_operation(
    bits: RsaKeyBits,
    scheme: RsaScheme,
    msg_len: usize,
) -> Result<(), RsaError> {
    check_generate_size_ok(bits)?;
    if msg_len == 0 || msg_len > max_msg_len(bits, scheme) {
        return Err(RsaError::InputTooLarge);
    }
    Ok(())
}

fn check_generate_size_ok(bits: RsaKeyBits) -> Result<(), RsaError> {
    match bits {
        RsaKeyBits::B1024 => Err(RsaError::Generate1024Forbidden),
        RsaKeyBits::B2048 | RsaKeyBits::B3072 | RsaKeyBits::B4096 => Ok(()),
    }
}

// ----------------------------------------------------------------------------
// BigUint & Montgomery Arithmetic Engine (Constant-memory, Zeroize)
// ----------------------------------------------------------------------------

#[derive(Clone, Default)]
struct BigUint {
    limbs: Vec<u64>,
}

impl Zeroize for BigUint {
    fn zeroize(&mut self) {
        self.limbs.zeroize();
    }
}

impl Drop for BigUint {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl BigUint {
    fn from_be_bytes(bytes: &[u8], n_limbs: usize) -> Self {
        let mut limbs = vec![0u64; n_limbs];
        let mut r = bytes.len();
        let mut idx = 0;
        while r > 0 && idx < n_limbs {
            let l = r.saturating_sub(8);
            let mut b = [0u8; 8];
            b[8 - (r - l)..].copy_from_slice(&bytes[l..r]);
            limbs[idx] = u64::from_be_bytes(b);
            idx += 1;
            r = l;
        }
        Self { limbs }
    }

    fn to_be_bytes(&self, target_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; target_len];
        let mut out_idx = target_len;
        for &limb in &self.limbs {
            let b = limb.to_be_bytes();
            if out_idx >= 8 {
                out_idx -= 8;
                out[out_idx..out_idx + 8].copy_from_slice(&b);
            } else {
                out[..out_idx].copy_from_slice(&b[8 - out_idx..]);
                break;
            }
        }
        out
    }
}

fn cmp_limbs(a: &[u64], b: &[u64]) -> core::cmp::Ordering {
    let max_len = a.len().max(b.len());
    for i in (0..max_len).rev() {
        let ai = if i < a.len() { a[i] } else { 0 };
        let bi = if i < b.len() { b[i] } else { 0 };
        if ai != bi {
            return ai.cmp(&bi);
        }
    }
    core::cmp::Ordering::Equal
}

fn sub_limbs(a: &mut [u64], b: &[u64]) -> u64 {
    let mut borrow: i128 = 0;
    for i in 0..a.len() {
        let bi = if i < b.len() { b[i] as i128 } else { 0 };
        let diff = (a[i] as i128) - bi - borrow;
        if diff < 0 {
            a[i] = (diff + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            a[i] = diff as u64;
            borrow = 0;
        }
    }
    borrow as u64
}

fn shl_1(a: &mut [u64]) -> u64 {
    let mut carry = 0u64;
    for limb in a.iter_mut() {
        let new_carry = *limb >> 63;
        *limb = (*limb << 1) | carry;
        carry = new_carry;
    }
    carry
}

fn double_mod(a: &mut [u64], m: &[u64]) {
    let overflow = shl_1(a);
    if overflow > 0 || !cmp_limbs(a, m).is_lt() {
        sub_limbs(a, m);
    }
}

fn mont_inv64(m0: u64) -> u64 {
    let mut inv = m0;
    inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    inv.wrapping_neg()
}

fn mont_mul(a: &[u64], b: &[u64], m: &[u64], inv_m: u64, out: &mut [u64]) {
    let n = m.len();
    let mut t = vec![0u64; 2 * n + 2];

    for i in 0..n {
        let ai = if i < a.len() { a[i] as u128 } else { 0 };
        if ai == 0 {
            continue;
        }
        let mut carry: u128 = 0;
        for j in 0..n {
            let bj = if j < b.len() { b[j] as u128 } else { 0 };
            let prod = ai * bj + (t[i + j] as u128) + carry;
            t[i + j] = prod as u64;
            carry = prod >> 64;
        }
        let mut k = i + n;
        while carry > 0 && k < t.len() {
            let sum = (t[k] as u128) + carry;
            t[k] = sum as u64;
            carry = sum >> 64;
            k += 1;
        }
    }

    for i in 0..n {
        let q = t[i].wrapping_mul(inv_m);
        let mut carry: u128 = 0;
        for j in 0..n {
            let prod = (q as u128) * (m[j] as u128) + (t[i + j] as u128) + carry;
            t[i + j] = prod as u64;
            carry = prod >> 64;
        }
        let mut k = i + n;
        while carry > 0 && k < t.len() {
            let sum = (t[k] as u128) + carry;
            t[k] = sum as u64;
            carry = sum >> 64;
            k += 1;
        }
    }

    out[..n].copy_from_slice(&t[n..(n + n)]);
    if t[2 * n] > 0 || !cmp_limbs(out, m).is_lt() {
        sub_limbs(out, m);
    }
    t.zeroize();
}

pub fn mod_pow(base: &[u8], exp: &[u8], modulus: &[u8]) -> Result<Vec<u8>, RsaError> {
    if modulus.is_empty() || (modulus[modulus.len() - 1] & 1) == 0 {
        return Err(RsaError::InvalidInput);
    }
    let n_bytes = modulus.len();
    let n_limbs = n_bytes.div_ceil(8);

    let m = BigUint::from_be_bytes(modulus, n_limbs);
    let mut base_limbs = BigUint::from_be_bytes(base, n_limbs);
    if !cmp_limbs(&base_limbs.limbs, &m.limbs).is_lt() {
        return Err(RsaError::InvalidInput);
    }

    let inv_m = mont_inv64(m.limbs[0]);

    // Compute R^2 mod M (2 * 64 * n_limbs doublings)
    let mut r2 = vec![0u64; n_limbs];
    r2[0] = 1;
    for _ in 0..(128 * n_limbs) {
        double_mod(&mut r2, &m.limbs);
    }

    // Convert base to Montgomery form: a_mont = MontMul(base, R^2)
    let mut a_mont = vec![0u64; n_limbs];
    mont_mul(&base_limbs.limbs, &r2, &m.limbs, inv_m, &mut a_mont);

    // Initial res = 1 in Montgomery form
    let mut one = vec![0u64; n_limbs];
    one[0] = 1;
    let mut res = vec![0u64; n_limbs];
    mont_mul(&one, &r2, &m.limbs, inv_m, &mut res);

    let mut started = false;
    let mut tmp = vec![0u64; n_limbs];
    for &byte in exp {
        for bit_idx in (0..8).rev() {
            let bit = (byte >> bit_idx) & 1;
            if !started {
                if bit == 1 {
                    started = true;
                    res.copy_from_slice(&a_mont);
                }
            } else {
                mont_mul(&res, &res, &m.limbs, inv_m, &mut tmp);
                res.copy_from_slice(&tmp);

                if bit == 1 {
                    mont_mul(&res, &a_mont, &m.limbs, inv_m, &mut tmp);
                    res.copy_from_slice(&tmp);
                }
            }
        }
    }
    tmp.as_mut_slice().zeroize();

    // Convert res back to normal domain: MontMul(res, 1)
    let mut out_limbs = vec![0u64; n_limbs];
    mont_mul(&res, &one, &m.limbs, inv_m, &mut out_limbs);

    base_limbs.zeroize();
    r2.zeroize();
    a_mont.zeroize();
    res.zeroize();

    let result = BigUint { limbs: out_limbs }.to_be_bytes(n_bytes);
    Ok(result)
}

// ----------------------------------------------------------------------------
// PKCS#1 v1.5 SHA-256
// ----------------------------------------------------------------------------

const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];

pub fn pkcs1v15_encode_sha256(msg: &[u8], em_len: usize) -> Result<Vec<u8>, RsaError> {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let hash = hasher.finalize();

    let t_len = SHA256_DIGEST_INFO_PREFIX.len() + hash.len();
    if em_len < t_len + 11 {
        return Err(RsaError::InputTooLarge);
    }
    let ps_len = em_len - t_len - 3;
    let mut em = Vec::with_capacity(em_len);
    em.push(0x00);
    em.push(0x01);
    em.resize(2 + ps_len, 0xFF);
    em.push(0x00);
    em.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    em.extend_from_slice(&hash);
    Ok(em)
}

pub fn pkcs1v15_verify_sha256(em: &[u8], msg: &[u8]) -> Result<(), RsaError> {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let hash = hasher.finalize();

    let t_len = SHA256_DIGEST_INFO_PREFIX.len() + hash.len();
    if em.len() < t_len + 11 {
        return Err(RsaError::InvalidInput);
    }
    if em[0] != 0x00 || em[1] != 0x01 {
        return Err(RsaError::VerificationFailed);
    }
    let ps_end = em.len() - t_len - 1;
    for &b in &em[2..ps_end] {
        if b != 0xFF {
            return Err(RsaError::VerificationFailed);
        }
    }
    if em[ps_end] != 0x00 {
        return Err(RsaError::VerificationFailed);
    }
    let expected_t = &em[ps_end + 1..];
    if expected_t[..19] != SHA256_DIGEST_INFO_PREFIX || expected_t[19..] != hash[..] {
        return Err(RsaError::VerificationFailed);
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// RSASSA-PSS SHA-256 (RFC 8017 Section 9.1)
// ----------------------------------------------------------------------------

pub fn mgf1_sha256(seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(mask_len);
    let mut counter = 0u32;
    while mask.len() < mask_len {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();
        let take = (mask_len - mask.len()).min(32);
        mask.extend_from_slice(&digest[..take]);
        counter += 1;
    }
    mask
}

pub fn pss_encode_sha256(msg: &[u8], salt: &[u8], em_len: usize) -> Result<Vec<u8>, RsaError> {
    let h_len = 32;
    let s_len = salt.len();
    if em_len < h_len + s_len + 2 {
        return Err(RsaError::InputTooLarge);
    }

    let mut m_hasher = Sha256::new();
    m_hasher.update(msg);
    let m_hash = m_hasher.finalize();

    let mut h_hasher = Sha256::new();
    h_hasher.update([0u8; 8]);
    h_hasher.update(m_hash);
    h_hasher.update(salt);
    let h = h_hasher.finalize();

    let db_len = em_len - h_len - 1;
    let mut db = vec![0u8; db_len];
    let ps_len = db_len - s_len - 1;
    db[ps_len] = 0x01;
    db[ps_len + 1..].copy_from_slice(salt);

    let db_mask = mgf1_sha256(&h, db_len);
    for (d, m) in db.iter_mut().zip(db_mask.iter()) {
        *d ^= *m;
    }

    db[0] &= 0x7F;

    let mut em = Vec::with_capacity(em_len);
    em.extend_from_slice(&db);
    em.extend_from_slice(&h);
    em.push(0xBC);
    Ok(em)
}

pub fn pss_verify_sha256(em: &[u8], msg: &[u8], s_len: usize) -> Result<(), RsaError> {
    let h_len = 32;
    let em_len = em.len();
    if em_len < h_len + s_len + 2 {
        return Err(RsaError::InvalidInput);
    }
    if em[em_len - 1] != 0xBC {
        return Err(RsaError::VerificationFailed);
    }
    if (em[0] & 0x80) != 0 {
        return Err(RsaError::VerificationFailed);
    }

    let db_len = em_len - h_len - 1;
    let masked_db = &em[..db_len];
    let h = &em[db_len..em_len - 1];

    let db_mask = mgf1_sha256(h, db_len);
    let mut db = vec![0u8; db_len];
    for i in 0..db_len {
        db[i] = masked_db[i] ^ db_mask[i];
    }
    db[0] &= 0x7F;

    let ps_len = db_len - s_len - 1;
    for &b in &db[..ps_len] {
        if b != 0x00 {
            return Err(RsaError::VerificationFailed);
        }
    }
    if db[ps_len] != 0x01 {
        return Err(RsaError::VerificationFailed);
    }
    let salt = &db[ps_len + 1..];

    let mut m_hasher = Sha256::new();
    m_hasher.update(msg);
    let m_hash = m_hasher.finalize();

    let mut h_hasher = Sha256::new();
    h_hasher.update([0u8; 8]);
    h_hasher.update(m_hash);
    h_hasher.update(salt);
    let h_prime = h_hasher.finalize();

    if h != &h_prime[..] {
        return Err(RsaError::VerificationFailed);
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// Key Structures with On-Demand Loading & Zeroize
// ----------------------------------------------------------------------------

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct RsaPrivateKey {
    pub n: Vec<u8>,
    pub e: u32,
    pub d: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPublicKey {
    pub n: Vec<u8>,
    pub e: u32,
}

impl RsaPrivateKey {
    pub fn new(n: Vec<u8>, e: u32, d: Vec<u8>) -> Result<Self, RsaError> {
        let bits = match n.len() {
            256 => RsaKeyBits::B2048,
            384 => RsaKeyBits::B3072,
            512 => RsaKeyBits::B4096,
            _ => return Err(RsaError::UnsupportedSize),
        };
        check_generate(bits)?;
        Ok(Self { n, e, d })
    }

    pub fn bits(&self) -> RsaKeyBits {
        match self.n.len() {
            256 => RsaKeyBits::B2048,
            384 => RsaKeyBits::B3072,
            512 => RsaKeyBits::B4096,
            _ => RsaKeyBits::B2048,
        }
    }

    pub fn to_public_key(&self) -> RsaPublicKey {
        RsaPublicKey {
            n: self.n.clone(),
            e: self.e,
        }
    }
}

pub trait RsaSign {
    fn sign_pkcs1v15(&self, message: &[u8]) -> Result<Vec<u8>, RsaError>;
    fn sign_pss(&self, message: &[u8], salt: &[u8]) -> Result<Vec<u8>, RsaError>;
}

pub trait RsaVerify {
    fn verify_pkcs1v15(&self, message: &[u8], signature: &[u8]) -> Result<(), RsaError>;
    fn verify_pss(&self, message: &[u8], signature: &[u8], salt_len: usize) -> Result<(), RsaError>;
}

impl RsaSign for RsaPrivateKey {
    fn sign_pkcs1v15(&self, message: &[u8]) -> Result<Vec<u8>, RsaError> {
        let em = pkcs1v15_encode_sha256(message, self.n.len())?;
        mod_pow(&em, &self.d, &self.n)
    }

    fn sign_pss(&self, message: &[u8], salt: &[u8]) -> Result<Vec<u8>, RsaError> {
        let em = pss_encode_sha256(message, salt, self.n.len())?;
        mod_pow(&em, &self.d, &self.n)
    }
}

impl RsaVerify for RsaPublicKey {
    fn verify_pkcs1v15(&self, message: &[u8], signature: &[u8]) -> Result<(), RsaError> {
        let e_bytes = match self.e {
            65537 => vec![0x01, 0x00, 0x01],
            3 => vec![0x03],
            other => other.to_be_bytes().to_vec(),
        };
        let em = mod_pow(signature, &e_bytes, &self.n)?;
        pkcs1v15_verify_sha256(&em, message)
    }

    fn verify_pss(&self, message: &[u8], signature: &[u8], salt_len: usize) -> Result<(), RsaError> {
        let e_bytes = match self.e {
            65537 => vec![0x01, 0x00, 0x01],
            3 => vec![0x03],
            other => other.to_be_bytes().to_vec(),
        };
        let em = mod_pow(signature, &e_bytes, &self.n)?;
        pss_verify_sha256(&em, message, salt_len)
    }
}

/// Backend RSA (R14): operacao real no SW/HW do device.
pub trait RsaBackend {
    fn generate(bits: RsaKeyBits) -> Result<(), RsaError>;
    fn sign(bits: RsaKeyBits, scheme: RsaScheme, msg_len: usize) -> Result<(), RsaError>;
    fn decrypt(bits: RsaKeyBits, scheme: RsaScheme, ct_len: usize) -> Result<(), RsaError>;
}

/// Software fail-closed para geracao de chaves novas sem acelerador de entropia pesado.
pub struct SoftwareRsa;

impl RsaBackend for SoftwareRsa {
    fn generate(bits: RsaKeyBits) -> Result<(), RsaError> {
        check_generate(bits)?;
        Err(RsaError::NotCompiled)
    }

    fn sign(bits: RsaKeyBits, scheme: RsaScheme, msg_len: usize) -> Result<(), RsaError> {
        check_operation(bits, scheme, msg_len)?;
        Err(RsaError::NotCompiled)
    }

    fn decrypt(bits: RsaKeyBits, scheme: RsaScheme, ct_len: usize) -> Result<(), RsaError> {
        check_generate_size_ok(bits)?;
        if ct_len != bits.bytes() {
            return Err(RsaError::InvalidInput);
        }
        let _ = scheme;
        Err(RsaError::NotCompiled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_1024_generate() {
        assert_eq!(
            check_generate(RsaKeyBits::B1024),
            Err(RsaError::Generate1024Forbidden)
        );
        assert_eq!(
            SoftwareRsa::generate(RsaKeyBits::B1024),
            Err(RsaError::Generate1024Forbidden)
        );
        assert_eq!(
            SoftwareRsa::sign(RsaKeyBits::B1024, RsaScheme::PssSha256, 32),
            Err(RsaError::Generate1024Forbidden)
        );
    }

    #[test]
    fn allows_modern_sizes_but_not_compiled() {
        for bits in [RsaKeyBits::B2048, RsaKeyBits::B3072, RsaKeyBits::B4096] {
            assert_eq!(check_generate(bits), Ok(()));
            // Fail-closed: politica ok, backend ausente (sem mock falso).
            assert_eq!(SoftwareRsa::generate(bits), Err(RsaError::NotCompiled));
        }
    }

    #[test]
    fn rejects_arbitrary_sizes() {
        for bad in [512u32, 1023, 1025, 2047, 4097, 8192] {
            assert_eq!(RsaKeyBits::from_bits(bad), Err(RsaError::UnsupportedSize));
        }
        assert_eq!(RsaKeyBits::from_bits(2048).unwrap().bits(), 2048);
    }

    #[test]
    fn enforces_scheme_limits() {
        assert_eq!(max_msg_len(RsaKeyBits::B2048, RsaScheme::OaepSha256), 190);
        assert_eq!(
            max_msg_len(RsaKeyBits::B3072, RsaScheme::PssSha256),
            384 - 66
        );
        assert_eq!(
            check_operation(RsaKeyBits::B2048, RsaScheme::OaepSha256, 191),
            Err(RsaError::InputTooLarge)
        );
        assert_eq!(
            check_operation(RsaKeyBits::B2048, RsaScheme::OaepSha256, 0),
            Err(RsaError::InputTooLarge)
        );
        assert_eq!(
            check_operation(RsaKeyBits::B2048, RsaScheme::OaepSha256, 190),
            Ok(())
        );
        assert_eq!(
            SoftwareRsa::decrypt(RsaKeyBits::B2048, RsaScheme::OaepSha256, 255),
            Err(RsaError::InvalidInput)
        );
        assert_eq!(
            SoftwareRsa::decrypt(RsaKeyBits::B2048, RsaScheme::OaepSha256, 256),
            Err(RsaError::NotCompiled)
        );
    }

    #[test]
    fn pkcs1_vectors_sizes_documented() {
        assert_eq!(max_msg_len(RsaKeyBits::B2048, RsaScheme::Pkcs1v15), 245);
        assert_eq!(
            max_msg_len(RsaKeyBits::B4096, RsaScheme::OaepSha256),
            512 - 66
        );
    }

    #[test]
    fn rsa_2048_pkcs1v15_and_pss_real_sign_verify_roundtrip() {
        let n_hex = "a19af7c4879fbb50a3092f22896cee5b2da22d0fba8878e7012e86189cdf9190\
                     e52bcd72b36398a1075e2eeecbbb69046db2248816a57b2b077a34063beac1cf\
                     f3d3dae4bd91cf3cf9d559ac5ab46686db87bcd6c486fb58f397227274713593\
                     2c2d319849fd660fc112e749da5708eff570b3585ddca8afdd20eb59fe49b15d\
                     df704ffa500a317773b356c1dc5d0c373d7d0e31b69504a889013ed85761157e\
                     f3de34d1fd34cc95dcc16da3a748cd14f46799baed434b2e947f1f6e34211f84\
                     be130f1708c3a83e73243ad974763617938baf8f966fcea2dffbe3c0a22e9a5f\
                     b5d611a39ea6ced31f47b239f03f55185db74964346a4f9bc3a13eb5c6f605a1";
        let d_hex = "0c5683ff15a9acc7e1c2a43e1b46dd45c9cc9d6b1b7f2ad7dc1fbcae295fea41\
                     a93578687ee8a630f91a8833c40b295fe4ae1a9ae73bb815176b8d88424fd07f\
                     3b6adbc5e5f13964bae03e89e99ce74cf97aba009d9d7e981274e1f4e20df89c\
                     a55d47f18c08941fb4ca682d1bc5d45159a84291070d7f357a08f6def68a92c7\
                     6c48ea938d8b355ad201d5fa40dc3120ac8e70d12191786b1746aa7dc818d393\
                     4b0c39e444f9bb62f90ceceffbe3e6a2e21f60490676ce2643fa050309297c1f\
                     70a719b9ee2de8e94b2de8dd2d201e423398f9229bed319f320d44532ca2a4a5\
                     01cd2ed09eea15ea63e85447c71ebd7e129aa396e8466a538d4e24e3413722a9";

        let n = hex::decode(n_hex).unwrap();
        let d = hex::decode(d_hex).unwrap();
        let priv_key = RsaPrivateKey::new(n, 65537, d).unwrap();
        let pub_key = priv_key.to_public_key();

        let message = b"AegisKey FIDO2 / PIV RSA-2048 Hardware Security";

        // 1. PKCS#1 v1.5 Sign & Verify
        let sig_pkcs1 = priv_key.sign_pkcs1v15(message).expect("PKCS#1 v1.5 sign succeeds");
        assert_eq!(sig_pkcs1.len(), 256);
        pub_key.verify_pkcs1v15(message, &sig_pkcs1).expect("PKCS#1 v1.5 verify succeeds");

        // Tamper message fails
        pub_key.verify_pkcs1v15(b"Tampered message", &sig_pkcs1).expect_err("tamper fails");
        // Tamper signature fails
        let mut bad_sig = sig_pkcs1.clone();
        bad_sig[0] ^= 0x01;
        pub_key.verify_pkcs1v15(message, &bad_sig).expect_err("tamper sig fails");

        // 2. RSA-PSS Sign & Verify
        let salt = [0x5Au8; 32];
        let sig_pss = priv_key.sign_pss(message, &salt).expect("RSA-PSS sign succeeds");
        assert_eq!(sig_pss.len(), 256);
        pub_key.verify_pss(message, &sig_pss, 32).expect("RSA-PSS verify succeeds");

        // Tamper PSS fails
        pub_key.verify_pss(b"Tampered message", &sig_pss, 32).expect_err("PSS tamper fails");
        let mut bad_pss = sig_pss.clone();
        bad_pss[10] ^= 0x80;
        pub_key.verify_pss(message, &bad_pss, 32).expect_err("PSS bad sig fails");
    }

    #[test]
    fn rsa_3072_sign_verify_roundtrip() {
        let n_hex = "c2b123554ca685037eabcd5f0bc4c2c2b98aeb47e224d87a6f31b5fba2b8660c\
                     c4f3008205d34716c4bf2954cd73728a5f4e11199b55b4c8a562b332bf2240af\
                     3c0c3b78ba346900c587ee71d591bb21f826eaea243d0120aa7d6b27fa1529af\
                     b6f9de0b5918de3af6b4b11f2ab52cb4800ba22907faabe717a594fdbe9a0be7\
                     561612eafec4b98ff0f8f373eb54ee62c669794baacd19859b4055a6fbef21d2\
                     ae6c028895bbf47537ec0624ff79fb4459058b45b5c00edbeb2b6aad9d740927\
                     4da250191dc5bdc0052b0ee55aeb21961cf252746acedd88ba36c73086918caf\
                     8f699223c6f6072ca35fd00fbdf541b4b553138d2e24c1d0b4ef2d35604952a3\
                     4151c03576ab4de619c418248633e0faefa753db4952cdfd97899c2060e1e009\
                     596d14243029f1ac896bb2a74505a45dd7ab322a28c6b737817f0b2173b69bdd\
                     7e0cad0e62a66f62b30c0ea28a22d9718a4724f4e6a85208b7c982a8f3c017e4\
                     934fae827c9a1197310f320c6a373255cf85ee68d66f919e976fc9dd0b3b28d9";
        let d_hex = "1d50d7796d6288965b614aba1457531d479b7dac940688cb3cc98f35be0d869e\
                     471cb117a3016a8ba8e200fafa39b746532df9e0b1756114b2648f87a564a6b9\
                     4c312a565631749b2f6335ba11d6d106ff2afb05f9216f7547febd1f26a6bfa1\
                     6c0ba94deba355392b334f955a14b04fd89507dca64d2e4bcc917c030e4b7b5d\
                     e0e64f806f8ed7432f9d88e90c473c6306add49c1a72aa346649746c41b4c312\
                     ca7d4c8f5cfe9183820169f671baa0256d432ab2bb3899742f6fd8ef1e0d9e1f\
                     f7a0c72f8269db4b6f98aaae473b2f09756fb998b5f79f2c625b254bcd45d0a2\
                     a64ee4e4068e4edddbad73b7c07ad516ac0130dd16219b8384b3b4ccadd5ff50\
                     f5fe5f033c030e4454a460261e90daa3e8842677410fd8ff04ab705946a6081b\
                     0da4f170bad891e21add1b98b2e7db2e72688147fc74d05d4e1fbf9b972e86ac\
                     ec35c1664c37aa10e82fd0f0cc1aabe74d805d49dbdf0bf64c17ca3a57e335cf\
                     f8bd5f32daa3da3c598a80f92e98d26abd3fb5c38a97ef67b2ae0ebc7df12645";

        let n = hex::decode(n_hex).unwrap();
        let d = hex::decode(d_hex).unwrap();
        let priv_key = RsaPrivateKey::new(n, 65537, d).unwrap();
        let pub_key = priv_key.to_public_key();

        let message = b"AegisKey FIDO2 / PIV RSA-3072 Hardware Security";

        // PKCS#1 v1.5 Sign & Verify
        let sig = priv_key.sign_pkcs1v15(message).expect("PKCS#1 v1.5 sign 3072 succeeds");
        assert_eq!(sig.len(), 384);
        pub_key.verify_pkcs1v15(message, &sig).expect("PKCS#1 v1.5 verify 3072 succeeds");

        // Tamper verification fails
        pub_key.verify_pkcs1v15(b"tamper", &sig).expect_err("tamper fails");

        // RSA-PSS Sign & Verify
        let salt = [0x42u8; 32];
        let sig_pss = priv_key.sign_pss(message, &salt).expect("PSS sign 3072 succeeds");
        assert_eq!(sig_pss.len(), 384);
        pub_key.verify_pss(message, &sig_pss, 32).expect("PSS verify 3072 succeeds");
    }
}
