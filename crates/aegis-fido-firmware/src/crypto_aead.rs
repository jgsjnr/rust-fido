//! T-CR-02 AEAD: AES-256/128-GCM and ChaCha20-Poly1305 (RFC 8439) real; CCM fail-closed.
//!
//! Motivo: persistencia cifrada e envelopes exigem AEAD com prova de vetor;
//! sem este modulo, `persistence.rs` nao teria cifra autenticada fim-a-fim.
//!
//! - GEN-DEVICE: selo/abertura executam no device; chave nunca sai em claro.
//! - AES-GCM via `aes-gcm` (alloc); ChaCha20-Poly1305 via RFC 8439 pura em Rust com Zeroize.
//! - CCM sem suporte retorna `UnsupportedAlgorithm` (fail-closed, sem mock falso).
//! - Limite de 4096 bytes por operacao (teto de memoria, secao 9).
//! - Hardware via trait `AeadBackend` (R14); `EspAead` ancora o HW do S3.

extern crate alloc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use alloc::vec::Vec;
use zeroize::Zeroize;

/// Tamanho do nonce GCM / ChaCha20-Poly1305 (96 bits).
pub const NONCE_LEN: usize = 12;
/// Tamanho da tag GCM / Poly1305 (128 bits).
pub const TAG_LEN: usize = 16;
/// Teto por operacao (bloco arbitrario de 4 KiB da matriz funcional).
pub const MAX_AEAD_BYTES: usize = 4096;

/// Algoritmos AEAD da matriz.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    Aes256Gcm,
    Aes128Gcm,
    Aes128Ccm,
    ChaCha20Poly1305,
}

/// Erros AEAD. Nenhuma variante carrega chave, nonce ou claro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    UnsupportedAlgorithm,
    InvalidKey,
    TooLarge,
    EncryptFailed,
    DecryptFailed,
}

// ----------------------------------------------------------------------------
// RFC 8439 ChaCha20 and Poly1305 Implementation (pure Rust, constant time, Zeroize)
// ----------------------------------------------------------------------------

#[inline(always)]
fn chacha20_qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [
        0x61707865,
        0x3320646e,
        0x79622d32,
        0x6b206574,
        u32::from_le_bytes(key[0..4].try_into().unwrap()),
        u32::from_le_bytes(key[4..8].try_into().unwrap()),
        u32::from_le_bytes(key[8..12].try_into().unwrap()),
        u32::from_le_bytes(key[12..16].try_into().unwrap()),
        u32::from_le_bytes(key[16..20].try_into().unwrap()),
        u32::from_le_bytes(key[20..24].try_into().unwrap()),
        u32::from_le_bytes(key[24..28].try_into().unwrap()),
        u32::from_le_bytes(key[28..32].try_into().unwrap()),
        counter,
        u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
        u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
        u32::from_le_bytes(nonce[8..12].try_into().unwrap()),
    ];

    let mut working = state;
    for _ in 0..10 {
        chacha20_qr(&mut working, 0, 4, 8, 12);
        chacha20_qr(&mut working, 1, 5, 9, 13);
        chacha20_qr(&mut working, 2, 6, 10, 14);
        chacha20_qr(&mut working, 3, 7, 11, 15);
        chacha20_qr(&mut working, 0, 5, 10, 15);
        chacha20_qr(&mut working, 1, 6, 11, 12);
        chacha20_qr(&mut working, 2, 7, 8, 13);
        chacha20_qr(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let val = working[i].wrapping_add(state[i]);
        out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
    state.zeroize();
    working.zeroize();
    out
}

fn chacha20_crypt(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut c = counter;
    for chunk in data.chunks_mut(64) {
        let mut ks = chacha20_block(key, c, nonce);
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= *k;
        }
        ks.zeroize();
        c = c.wrapping_add(1);
    }
}

#[derive(Clone, Copy)]
struct Poly1305State {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
}

impl Poly1305State {
    fn new(key: &[u8; 32]) -> Self {
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[0..16]);
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;

        let t0 = u32::from_le_bytes(r_bytes[0..4].try_into().unwrap());
        let t1 = u32::from_le_bytes(r_bytes[4..8].try_into().unwrap());
        let t2 = u32::from_le_bytes(r_bytes[8..12].try_into().unwrap());
        let t3 = u32::from_le_bytes(r_bytes[12..16].try_into().unwrap());

        let r = [
            t0 & 0x03ffffff,
            ((t0 >> 26) | (t1 << 6)) & 0x03ffffff,
            ((t1 >> 20) | (t2 << 12)) & 0x03ffffff,
            ((t2 >> 14) | (t3 << 18)) & 0x03ffffff,
            (t3 >> 8) & 0x03ffffff,
        ];

        let pad = [
            u32::from_le_bytes(key[16..20].try_into().unwrap()),
            u32::from_le_bytes(key[20..24].try_into().unwrap()),
            u32::from_le_bytes(key[24..28].try_into().unwrap()),
            u32::from_le_bytes(key[28..32].try_into().unwrap()),
        ];

        r_bytes.zeroize();
        Self { r, h: [0; 5], pad }
    }

    fn update_padded_16(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            self.block_16(&block);
        }
    }

    fn block_16(&mut self, block: &[u8; 16]) {
        let r0 = self.r[0] as u64;
        let r1 = self.r[1] as u64;
        let r2 = self.r[2] as u64;
        let r3 = self.r[3] as u64;
        let r4 = self.r[4] as u64;

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let mut h0 = self.h[0] as u64;
        let mut h1 = self.h[1] as u64;
        let mut h2 = self.h[2] as u64;
        let mut h3 = self.h[3] as u64;
        let mut h4 = self.h[4] as u64;

        let t0 = u32::from_le_bytes(block[0..4].try_into().unwrap());
        let t1 = u32::from_le_bytes(block[4..8].try_into().unwrap());
        let t2 = u32::from_le_bytes(block[8..12].try_into().unwrap());
        let t3 = u32::from_le_bytes(block[12..16].try_into().unwrap());

        h0 += (t0 & 0x03ffffff) as u64;
        h1 += (((t0 >> 26) | (t1 << 6)) & 0x03ffffff) as u64;
        h2 += (((t1 >> 20) | (t2 << 12)) & 0x03ffffff) as u64;
        h3 += (((t2 >> 14) | (t3 << 18)) & 0x03ffffff) as u64;
        h4 += ((t3 >> 8) as u64) | (1u64 << 24);

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c: u64 = d0 >> 26;
        h0 = d0 & 0x03ffffff;
        let mut d = d1 + c;
        c = d >> 26;
        h1 = d & 0x03ffffff;
        d = d2 + c;
        c = d >> 26;
        h2 = d & 0x03ffffff;
        d = d3 + c;
        c = d >> 26;
        h3 = d & 0x03ffffff;
        d = d4 + c;
        c = d >> 26;
        h4 = d & 0x03ffffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x03ffffff;
        h1 += c;

        self.h = [h0 as u32, h1 as u32, h2 as u32, h3 as u32, h4 as u32];
    }

    fn finish(mut self) -> [u8; 16] {
        let mut c: u64 = (self.h[0] >> 26) as u64;
        self.h[0] &= 0x03ffffff;
        self.h[1] += c as u32;
        c = (self.h[1] >> 26) as u64;
        self.h[1] &= 0x03ffffff;
        self.h[2] += c as u32;
        c = (self.h[2] >> 26) as u64;
        self.h[2] &= 0x03ffffff;
        self.h[3] += c as u32;
        c = (self.h[3] >> 26) as u64;
        self.h[3] &= 0x03ffffff;
        self.h[4] += c as u32;
        c = (self.h[4] >> 26) as u64;
        self.h[4] &= 0x03ffffff;
        self.h[0] += (c * 5) as u32;
        c = (self.h[0] >> 26) as u64;
        self.h[0] &= 0x03ffffff;
        self.h[1] += c as u32;

        let mut g0 = self.h[0].wrapping_add(5);
        c = (g0 >> 26) as u64;
        g0 &= 0x03ffffff;
        let mut g1 = self.h[1].wrapping_add(c as u32);
        c = (g1 >> 26) as u64;
        g1 &= 0x03ffffff;
        let mut g2 = self.h[2].wrapping_add(c as u32);
        c = (g2 >> 26) as u64;
        g2 &= 0x03ffffff;
        let mut g3 = self.h[3].wrapping_add(c as u32);
        c = (g3 >> 26) as u64;
        g3 &= 0x03ffffff;
        let g4 = self.h[4].wrapping_add(c as u32).wrapping_sub(1 << 26);

        let mask = (g4 >> 31).wrapping_sub(1);
        let g0 = (g0 & mask) | (self.h[0] & !mask);
        let g1 = (g1 & mask) | (self.h[1] & !mask);
        let g2 = (g2 & mask) | (self.h[2] & !mask);
        let g3 = (g3 & mask) | (self.h[3] & !mask);
        let g4 = (g4 & mask) | (self.h[4] & !mask);

        let t0 = g0 | (g1 << 26);
        let t1 = (g1 >> 6) | (g2 << 20);
        let t2 = (g2 >> 12) | (g3 << 14);
        let t3 = (g3 >> 18) | (g4 << 8);

        let mut out = [0u8; 16];
        let mut c64: u64 = (t0 as u64) + (self.pad[0] as u64);
        out[0..4].copy_from_slice(&(c64 as u32).to_le_bytes());
        c64 = (t1 as u64) + (self.pad[1] as u64) + (c64 >> 32);
        out[4..8].copy_from_slice(&(c64 as u32).to_le_bytes());
        c64 = (t2 as u64) + (self.pad[2] as u64) + (c64 >> 32);
        out[8..12].copy_from_slice(&(c64 as u32).to_le_bytes());
        c64 = (t3 as u64) + (self.pad[3] as u64) + (c64 >> 32);
        out[12..16].copy_from_slice(&(c64 as u32).to_le_bytes());

        self.r.zeroize();
        self.h.zeroize();
        self.pad.zeroize();

        out
    }
}

fn chacha20_poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    // 1. One-time poly1305 key from chacha20 block 0
    let mut otk_block = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&otk_block[0..32]);
    otk_block.zeroize();

    let mut poly = Poly1305State::new(&poly_key);
    poly_key.zeroize();

    // 2. Encrypt plaintext starting at counter 1
    let mut ciphertext = plaintext.to_vec();
    chacha20_crypt(key, 1, nonce, &mut ciphertext);

    // 3. Poly1305 over AAD (padded to 16 bytes)
    poly.update_padded_16(aad);

    // 4. Poly1305 over ciphertext (padded to 16 bytes)
    poly.update_padded_16(&ciphertext);

    // 5. Length block: u64 LE AAD len + u64 LE ciphertext len
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    len_block[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly.block_16(&len_block);

    let tag = poly.finish();
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

fn chacha20_poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if ciphertext_and_tag.len() < TAG_LEN {
        return Err(AeadError::DecryptFailed);
    }
    let ct_len = ciphertext_and_tag.len() - TAG_LEN;
    let ciphertext = &ciphertext_and_tag[..ct_len];
    let tag = &ciphertext_and_tag[ct_len..];

    // 1. One-time key
    let mut otk_block = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&otk_block[0..32]);
    otk_block.zeroize();

    let mut poly = Poly1305State::new(&poly_key);
    poly_key.zeroize();

    poly.update_padded_16(aad);
    poly.update_padded_16(ciphertext);

    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    len_block[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly.block_16(&len_block);

    let expected_tag = poly.finish();

    // Constant-time tag check
    let mut diff = 0u8;
    for (a, b) in tag.iter().zip(expected_tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(AeadError::DecryptFailed);
    }

    // Decrypt
    let mut plaintext = ciphertext.to_vec();
    chacha20_crypt(key, 1, nonce, &mut plaintext);
    Ok(plaintext)
}

// ----------------------------------------------------------------------------
// Backend Interface
// ----------------------------------------------------------------------------

/// Backend AEAD (R14): software auditavel; `EspAead` ancora o HW.
pub trait AeadBackend {
    fn seal(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce12: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError>;

    fn open(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce12: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, AeadError>;
}

/// Implementacao software real (AES-GCM e ChaCha20-Poly1305 verdadeiros).
pub struct SoftwareAead;

impl AeadBackend for SoftwareAead {
    fn seal(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce12: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        check_args(alg, key, plaintext.len())?;
        match alg {
            AeadAlgorithm::Aes256Gcm => {
                let nonce = Nonce::from(*nonce12);
                let payload = Payload {
                    msg: plaintext,
                    aad,
                };
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
                cipher
                    .encrypt(&nonce, payload)
                    .map_err(|_| AeadError::EncryptFailed)
            }
            AeadAlgorithm::Aes128Gcm => {
                let nonce = Nonce::from(*nonce12);
                let payload = Payload {
                    msg: plaintext,
                    aad,
                };
                let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
                cipher
                    .encrypt(&nonce, payload)
                    .map_err(|_| AeadError::EncryptFailed)
            }
            AeadAlgorithm::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                let res = chacha20_poly1305_seal(&k, nonce12, aad, plaintext);
                k.zeroize();
                res
            }
            AeadAlgorithm::Aes128Ccm => Err(AeadError::UnsupportedAlgorithm),
        }
    }

    fn open(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce12: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        check_args(alg, key, ciphertext_and_tag.len())?;
        if ciphertext_and_tag.len() < TAG_LEN {
            return Err(AeadError::DecryptFailed);
        }
        match alg {
            AeadAlgorithm::Aes256Gcm => {
                let nonce = Nonce::from(*nonce12);
                let payload = Payload {
                    msg: ciphertext_and_tag,
                    aad,
                };
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
                cipher
                    .decrypt(&nonce, payload)
                    .map_err(|_| AeadError::DecryptFailed)
            }
            AeadAlgorithm::Aes128Gcm => {
                let nonce = Nonce::from(*nonce12);
                let payload = Payload {
                    msg: ciphertext_and_tag,
                    aad,
                };
                let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
                cipher
                    .decrypt(&nonce, payload)
                    .map_err(|_| AeadError::DecryptFailed)
            }
            AeadAlgorithm::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                let res = chacha20_poly1305_open(&k, nonce12, aad, ciphertext_and_tag);
                k.zeroize();
                res
            }
            AeadAlgorithm::Aes128Ccm => Err(AeadError::UnsupportedAlgorithm),
        }
    }
}

/// Ancoragem ESP32-S3: delega ao software; acelerador GCM entra aqui.
pub struct EspAead;

impl AeadBackend for EspAead {
    fn seal(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce12: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        SoftwareAead::seal(alg, key, nonce12, aad, plaintext)
    }

    fn open(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce12: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        SoftwareAead::open(alg, key, nonce12, aad, ciphertext_and_tag)
    }
}

fn check_args(alg: AeadAlgorithm, key: &[u8], body_len: usize) -> Result<(), AeadError> {
    let want = match alg {
        AeadAlgorithm::Aes256Gcm | AeadAlgorithm::ChaCha20Poly1305 => 32,
        AeadAlgorithm::Aes128Gcm => 16,
        AeadAlgorithm::Aes128Ccm => return Err(AeadError::UnsupportedAlgorithm),
    };
    if key.len() != want {
        return Err(AeadError::InvalidKey);
    }
    if body_len > MAX_AEAD_BYTES + TAG_LEN {
        return Err(AeadError::TooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_128: [u8; 16] = [0u8; 16];
    const ZERO_256: [u8; 32] = [0u8; 32];
    const ZERO_NONCE: [u8; NONCE_LEN] = [0u8; NONCE_LEN];

    fn nonce_of(hex_str: &str) -> [u8; NONCE_LEN] {
        let v = hex::decode(hex_str).expect("hex valido");
        let mut out = [0u8; NONCE_LEN];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn gcm_cavs_kat() {
        let k128 = hex::decode("11754cd72aec309bf52f7687212e8957").unwrap();
        let n128 = nonce_of("3c819d9a9bed087615030b65");
        let ct = SoftwareAead::seal(AeadAlgorithm::Aes128Gcm, &k128, &n128, b"", b"")
            .expect("vetor CAVS 128");
        assert_eq!(
            ct.as_slice(),
            hex::decode("250327c674aaf477aef2675748cf6971")
                .unwrap()
                .as_slice()
        );
        let pt = SoftwareAead::open(AeadAlgorithm::Aes128Gcm, &k128, &n128, b"", &ct)
            .expect("abre CAVS 128");
        assert!(pt.is_empty());

        let k256 = hex::decode("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4")
            .unwrap();
        let n256 = nonce_of("516c33929df5a3284ff463d7");
        let ct = SoftwareAead::seal(AeadAlgorithm::Aes256Gcm, &k256, &n256, b"", b"")
            .expect("vetor CAVS 256");
        assert_eq!(
            ct.as_slice(),
            hex::decode("bdc1ac884d332457a1d2664f168c76f0")
                .unwrap()
                .as_slice()
        );
        let pt = SoftwareAead::open(AeadAlgorithm::Aes256Gcm, &k256, &n256, b"", &ct)
            .expect("abre CAVS 256");
        assert!(pt.is_empty());
    }

    #[test]
    fn roundtrip_payload_and_aad() {
        let ct = SoftwareAead::seal(
            AeadAlgorithm::Aes256Gcm,
            &ZERO_256,
            &ZERO_NONCE,
            b"header",
            b"credencial",
        )
        .expect("selo");
        assert_eq!(ct.len(), b"credencial".len() + TAG_LEN);
        let pt = SoftwareAead::open(
            AeadAlgorithm::Aes256Gcm,
            &ZERO_256,
            &ZERO_NONCE,
            b"header",
            &ct,
        )
        .expect("abre");
        assert_eq!(pt.as_slice(), b"credencial");
    }

    #[test]
    fn chacha20_poly1305_rfc8439_kat_and_roundtrip() {
        // RFC 8439 Section 2.8.2 Test Vector
        let key_bytes =
            hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap();
        let nonce_bytes = hex::decode("070000004041424344454647").unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext = hex::decode(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
             73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
             6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
             637265656e20776f756c642062652069742e",
        )
        .unwrap();

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);

        let ct = SoftwareAead::seal(
            AeadAlgorithm::ChaCha20Poly1305,
            &key_bytes,
            &nonce,
            &aad,
            &plaintext,
        )
        .expect("ChaCha20-Poly1305 seal succeeds");

        let expected_tag = hex::decode("1ae10b594f09e26a7e902ecbd0600691").unwrap();
        let expected_ct = hex::decode(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        )
        .unwrap();
        assert_eq!(
            &ct[..ct.len() - 16],
            expected_ct.as_slice(),
            "Ciphertext matches RFC 8439 Section 2.8.2 KAT"
        );
        let tag = &ct[ct.len() - 16..];
        assert_eq!(
            tag,
            expected_tag.as_slice(),
            "Tag matches RFC 8439 Section 2.8.2 KAT"
        );

        let pt = SoftwareAead::open(
            AeadAlgorithm::ChaCha20Poly1305,
            &key_bytes,
            &nonce,
            &aad,
            &ct,
        )
        .expect("ChaCha20-Poly1305 open succeeds");
        assert_eq!(pt.as_slice(), plaintext);

        // Tampering fails
        let mut tampered = ct.clone();
        tampered[0] ^= 0x01;
        assert_eq!(
            SoftwareAead::open(
                AeadAlgorithm::ChaCha20Poly1305,
                &key_bytes,
                &nonce,
                &aad,
                &tampered
            ),
            Err(AeadError::DecryptFailed)
        );
    }

    #[test]
    fn poly1305_rfc8439_standalone_kat() {
        // RFC 8439 Section 2.5.2
        let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .unwrap();
        let msg = b"Cryptographic Forum Research Group";
        let expected_tag = hex::decode("a8061dc1305136c6c22b8baf0c0127a9").unwrap();

        let mut k = [0u8; 32];
        k.copy_from_slice(&key);
        let mut poly = Poly1305State::new(&k);
        // In Section 2.5.2, msg is 34 bytes (2 full 16B blocks + 1 chunk of 2B with pad 0x01 at byte 2)
        for chunk in msg.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            if chunk.len() == 16 {
                poly.block_16(&block);
            } else {
                block[chunk.len()] = 1;
                // Block with bit 1 at chunk.len()
                let t0 = u32::from_le_bytes(block[0..4].try_into().unwrap());
                let t1 = u32::from_le_bytes(block[4..8].try_into().unwrap());
                let t2 = u32::from_le_bytes(block[8..12].try_into().unwrap());
                let t3 = u32::from_le_bytes(block[12..16].try_into().unwrap());
                let h = [
                    t0 & 0x03ffffff,
                    ((t0 >> 26) | (t1 << 6)) & 0x03ffffff,
                    ((t1 >> 20) | (t2 << 12)) & 0x03ffffff,
                    ((t2 >> 14) | (t3 << 18)) & 0x03ffffff,
                    (t3 >> 8) & 0x03ffffff,
                ];
                // add to poly
                let r0 = poly.r[0] as u64;
                let r1 = poly.r[1] as u64;
                let r2 = poly.r[2] as u64;
                let r3 = poly.r[3] as u64;
                let r4 = poly.r[4] as u64;
                let s1 = r1 * 5;
                let s2 = r2 * 5;
                let s3 = r3 * 5;
                let s4 = r4 * 5;
                let mut h0 = (poly.h[0] + h[0]) as u64;
                let mut h1 = (poly.h[1] + h[1]) as u64;
                let mut h2 = (poly.h[2] + h[2]) as u64;
                let mut h3 = (poly.h[3] + h[3]) as u64;
                let mut h4 = (poly.h[4] + h[4]) as u64;
                let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
                let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
                let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
                let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
                let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
                let mut c: u64 = d0 >> 26;
                h0 = d0 & 0x03ffffff;
                let mut d = d1 + c;
                c = d >> 26;
                h1 = d & 0x03ffffff;
                d = d2 + c;
                c = d >> 26;
                h2 = d & 0x03ffffff;
                d = d3 + c;
                c = d >> 26;
                h3 = d & 0x03ffffff;
                d = d4 + c;
                c = d >> 26;
                h4 = d & 0x03ffffff;
                h0 += c * 5;
                c = h0 >> 26;
                h0 &= 0x03ffffff;
                h1 += c;
                poly.h = [h0 as u32, h1 as u32, h2 as u32, h3 as u32, h4 as u32];
            }
        }
        let tag = poly.finish();
        assert_eq!(tag.as_slice(), expected_tag.as_slice());
    }

    #[test]
    fn rejects_tampered_truncated_wrong_key() {
        let ct = SoftwareAead::seal(
            AeadAlgorithm::Aes256Gcm,
            &ZERO_256,
            &ZERO_NONCE,
            b"aad",
            b"dados",
        )
        .unwrap();
        let mut bit = ct.clone();
        bit[0] ^= 0x01;
        assert_eq!(
            SoftwareAead::open(
                AeadAlgorithm::Aes256Gcm,
                &ZERO_256,
                &ZERO_NONCE,
                b"aad",
                &bit
            ),
            Err(AeadError::DecryptFailed)
        );
        assert_eq!(
            SoftwareAead::open(
                AeadAlgorithm::Aes256Gcm,
                &ZERO_256,
                &ZERO_NONCE,
                b"aad",
                &ct[..ct.len() - 1]
            ),
            Err(AeadError::DecryptFailed)
        );
        assert_eq!(
            SoftwareAead::open(
                AeadAlgorithm::Aes256Gcm,
                &ZERO_256,
                &ZERO_NONCE,
                b"aad",
                &[]
            ),
            Err(AeadError::DecryptFailed)
        );
        assert_eq!(
            SoftwareAead::open(
                AeadAlgorithm::Aes256Gcm,
                &ZERO_256,
                &ZERO_NONCE,
                b"outro",
                &ct
            ),
            Err(AeadError::DecryptFailed)
        );
        let mut wrong = ZERO_256;
        wrong[0] = 1;
        assert_eq!(
            SoftwareAead::open(AeadAlgorithm::Aes256Gcm, &wrong, &ZERO_NONCE, b"aad", &ct),
            Err(AeadError::DecryptFailed)
        );
    }

    #[test]
    fn rejects_limits_and_unsupported() {
        let big = alloc::vec![0xA5u8; MAX_AEAD_BYTES + TAG_LEN + 1];
        assert_eq!(
            SoftwareAead::seal(AeadAlgorithm::Aes256Gcm, &ZERO_256, &ZERO_NONCE, b"", &big),
            Err(AeadError::TooLarge)
        );
        assert_eq!(
            SoftwareAead::seal(AeadAlgorithm::Aes256Gcm, &[0u8; 31], &ZERO_NONCE, b"", b"x"),
            Err(AeadError::InvalidKey)
        );
        // Only Aes128Ccm remains unsupported
        assert_eq!(
            SoftwareAead::seal(AeadAlgorithm::Aes128Ccm, &ZERO_128, &ZERO_NONCE, b"", b"x"),
            Err(AeadError::UnsupportedAlgorithm)
        );
        assert_eq!(
            SoftwareAead::open(
                AeadAlgorithm::Aes128Ccm,
                &ZERO_128,
                &ZERO_NONCE,
                b"",
                &[0u8; 16]
            ),
            Err(AeadError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn esp_backend_delegates() {
        let ct = EspAead::seal(
            AeadAlgorithm::Aes128Gcm,
            &ZERO_128,
            &ZERO_NONCE,
            b"",
            b"ping",
        )
        .unwrap();
        let pt = EspAead::open(AeadAlgorithm::Aes128Gcm, &ZERO_128, &ZERO_NONCE, b"", &ct).unwrap();
        assert_eq!(pt.as_slice(), b"ping");

        // EspAead also delegates ChaCha20Poly1305
        let ct_chacha = EspAead::seal(
            AeadAlgorithm::ChaCha20Poly1305,
            &ZERO_256,
            &ZERO_NONCE,
            b"header",
            b"chacha-esp",
        )
        .unwrap();
        let pt_chacha = EspAead::open(
            AeadAlgorithm::ChaCha20Poly1305,
            &ZERO_256,
            &ZERO_NONCE,
            b"header",
            &ct_chacha,
        )
        .unwrap();
        assert_eq!(pt_chacha.as_slice(), b"chacha-esp");
    }
}
