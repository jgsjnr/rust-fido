//! Proximity crypto puro (D6 split from `proximity`, single owner).
//!
//! AES-128-ECB (primitiva) + CBC-MAC do AES-CCM + `proximity_tag` +
//! `verify_proximity_tag` (tempo constante). Sem radio, sem NVS: o dono
//! `proximity` guarda `prox_k` e o radio; este modulo so computa.
//!
//! Contract (R15/R16): move-only; vetores CCM provados nos testes do dono.
use aes::cipher::{BlockEncrypt, KeyInit};
use zeroize::Zeroize;

/// Tamanho do K_prox (AES-128) em bytes.
pub const PROXIMITY_KEY_LEN: usize = 16;
/// Tamanho do fob_short_id (endereco BLE de 6 B) em bytes.
pub const PROXIMITY_FOB_ID_LEN: usize = 6;
/// Bytes da tag autenticada (AES-CCM-128 truncada em 32 b).
pub const PROXIMITY_BEACON_TAG_LEN: usize = 4;

/// Um bloco AES-128-ECB (primitiva do AES-CCM abaixo).
///
/// allow(deprecated): arvore presa no generic-array 0.14 via aes 0.8 (no_std,
/// sem novas deps); a API de bloco e a unica peca usada aqui.
#[allow(deprecated)]
fn aes128_encrypt_block(key: &[u8; PROXIMITY_KEY_LEN], block: &mut [u8; 16]) {
    use aes::cipher::generic_array::GenericArray;
    let cipher = aes::Aes128::new_from_slice(key).expect("K_prox tem 16 bytes");
    let mut b = GenericArray::clone_from_slice(block as &[u8]);
    cipher.encrypt_block(&mut b);
    block.copy_from_slice(b.as_slice());
}

/// CBC-MAC do AES-CCM (T = 4, L = 4, mensagem vazia, AAD autenticado).
///
/// B0 = [0x4B] || nonce(11) || qlen (4 zeros); depois AAD com prefixo de
/// comprimento BE u16 e pad de zeros ate multiplo de 16.
fn ccm_cbc_mac(key: &[u8; PROXIMITY_KEY_LEN], nonce: &[u8; 11], aad: &[u8]) -> [u8; 16] {
    let mut x = [0u8; 16];
    x[0] = 0x4B;
    x[1..12].copy_from_slice(nonce);
    aes128_encrypt_block(key, &mut x);
    let aad_len = aad.len().min(0xFF00);
    let mut block = [0u8; 16];
    block[0] = ((aad_len >> 8) & 0xFF) as u8;
    block[1] = (aad_len & 0xFF) as u8;
    let head = aad_len.min(14);
    block[2..2 + head].copy_from_slice(&aad[..head]);
    for (a, b) in x.iter_mut().zip(block.iter()) {
        *a ^= *b;
    }
    aes128_encrypt_block(key, &mut x);
    let mut off = head;
    while off < aad_len {
        block = [0u8; 16];
        let take = (aad_len - off).min(16);
        block[..take].copy_from_slice(&aad[off..off + take]);
        for (a, b) in x.iter_mut().zip(block.iter()) {
            *a ^= *b;
        }
        aes128_encrypt_block(key, &mut x);
        off += take;
    }
    x
}

/// TAG = AES-CCM-128(K_prox, nonce, AAD, mensagem vazia) truncada em 4 B.
///
/// nonce (11 B) = VER || CTR_LE || fob_short_id; AAD (5 B) = VER || CTR_LE.
/// O fob_short_id e o endereco BLE de 6 B do fob bonded (injetado pelo
/// chamador a partir do peer real; nunca inventado aqui).
pub fn proximity_tag(
    key: &[u8; PROXIMITY_KEY_LEN],
    ver: u8,
    ctr: u32,
    fob_id: &[u8; PROXIMITY_FOB_ID_LEN],
) -> [u8; PROXIMITY_BEACON_TAG_LEN] {
    let mut nonce = [0u8; 11];
    nonce[0] = ver;
    nonce[1..5].copy_from_slice(&ctr.to_le_bytes());
    nonce[5..11].copy_from_slice(fob_id);
    let mut aad = [0u8; 5];
    aad[0] = ver;
    aad[1..5].copy_from_slice(&ctr.to_le_bytes());
    let mut mac = ccm_cbc_mac(key, &nonce, &aad);
    let mut s0 = [0u8; 16];
    s0[0] = 0x03;
    s0[1..12].copy_from_slice(&nonce);
    aes128_encrypt_block(key, &mut s0);
    let mut tag = [0u8; PROXIMITY_BEACON_TAG_LEN];
    for ((d, m), s) in tag.iter_mut().zip(mac.iter()).zip(s0.iter()) {
        *d = m ^ s;
    }
    mac.zeroize();
    s0.zeroize();
    tag
}

/// Comparacao em tempo constante da TAG (falso nao revela posicao).
pub fn verify_proximity_tag(
    key: &[u8; PROXIMITY_KEY_LEN],
    ver: u8,
    ctr: u32,
    fob_id: &[u8; PROXIMITY_FOB_ID_LEN],
    tag: &[u8; PROXIMITY_BEACON_TAG_LEN],
) -> bool {
    let expect = proximity_tag(key, ver, ctr, fob_id);
    let diff: u8 = expect
        .iter()
        .zip(tag.iter())
        .fold(0, |acc, (a, b)| acc | (a ^ b));
    diff == 0
}
