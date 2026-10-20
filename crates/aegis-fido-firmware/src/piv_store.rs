//! Backend PIV on-device (F4): store NVS + chaves via `KeyManager`.
//!
//! - `PivNvsStore`: `PivRecordStore` sobre `SecureStorage` (AEGN v1).
//! - `PivFwBackend`: `PivKeyBackend` sobre `KeyManager` (slots reservados
//!   24-27 p/ 9A/9C/9D/9E; colisão com slot vendor ocupado falha `NoSlot`,
//!   nunca sobrescreve). EC P-256 (`0x11`) e P-384 (`0x14`); RSA = `BadAlg`
//!   (sem RSA neste device). Resposta ECDSA em R||S cru (DER→raw aqui).
//! - Presença: o applet já exige PIN verificado; passa `presence=true`
//!   (PIN = presença p/ PIV, documentado; UP físico continua nos fluxos CTAP).

extern crate alloc;

use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::credential::{KEY_USE_AUTH, KEY_USE_SIGN};
use aegis_fido_core::crypto::curves::CoseAlgorithm;
use aegis_fido_usb::piv::{
    PivCryptoError, PivKeyBackend, PivRecordStore, PivSlot, PivStoreError,
};
use alloc::vec::Vec;

use crate::persistence::{FlashStorageBackend, SecureStorage, StorageError};

/// Slots `KeyManager` reservados p/ PIV (longe do uso típico 0-23).
pub const PIV_SLOT_BASE: u8 = 24;

fn piv_key_slot(slot: PivSlot) -> u8 {
    PIV_SLOT_BASE
        + match slot {
            PivSlot::Auth9A => 0,
            PivSlot::Sign9C => 1,
            PivSlot::Mgmt9D => 2,
            PivSlot::Card9E => 3,
        }
}

fn piv_label(slot: PivSlot) -> &'static str {
    match slot {
        PivSlot::Auth9A => "piv:9a",
        PivSlot::Sign9C => "piv:9c",
        PivSlot::Mgmt9D => "piv:9d",
        PivSlot::Card9E => "piv:9e",
    }
}

/// Alg PIV (byte `80`) → COSE. Só EC suportado (sem RSA no device).
fn piv_alg(alg: u8) -> Result<(CoseAlgorithm, usize), PivCryptoError> {
    match alg {
        0x11 => Ok((CoseAlgorithm::ES256, 32)),
        0x14 => Ok((CoseAlgorithm::ES384, 48)),
        _ => Err(PivCryptoError::BadAlg),
    }
}

/// Store PIV sobre `SecureStorage` (chaves `piv_*` + `piv_cert_*`, ≤15 chars).
pub struct PivNvsStore<'a, B: FlashStorageBackend> {
    storage: &'a mut SecureStorage<B>,
}

impl<'a, B: FlashStorageBackend> PivNvsStore<'a, B> {
    /// Envolve o storage (empréstimo curto, por APDU).
    pub fn new(storage: &'a mut SecureStorage<B>) -> Self {
        Self { storage }
    }
}

impl<B: FlashStorageBackend> PivRecordStore for PivNvsStore<'_, B> {
    fn load_record(&self, key: &str) -> Result<Vec<u8>, PivStoreError> {
        match self.storage.load(key) {
            Ok(v) => Ok(v),
            Err(StorageError::KeyNotFound) => Err(PivStoreError::NotFound),
            Err(_) => Err(PivStoreError::Io),
        }
    }

    fn store_record(&mut self, key: &str, value: &[u8]) -> Result<(), PivStoreError> {
        self.storage
            .store(key, value, &[0u8; 12])
            .map_err(|_| PivStoreError::Io)
    }

    fn delete_record(&mut self, key: &str) -> Result<(), PivStoreError> {
        // Idempotente: ausente = ok.
        match self.storage.delete(key) {
            Ok(()) => Ok(()),
            Err(StorageError::KeyNotFound) => Ok(()),
            Err(_) => Err(PivStoreError::Io),
        }
    }
}

/// Backend cripto PIV sobre `KeyManager` (+ NVS via `PivNvsStore` p/ certs,
/// que o applet gerencia sozinho; aqui só chaves).
pub struct PivFwBackend<'a> {
    keys: &'a mut KeyManager,
    created: u64,
}

impl<'a> PivFwBackend<'a> {
    /// Envolve o gerenciador de chaves (`created` = relógio p/ GEN).
    pub fn new(keys: &'a mut KeyManager, created: u64) -> Self {
        Self { keys, created }
    }
}

impl PivKeyBackend for PivFwBackend<'_> {
    fn generate(&mut self, slot: PivSlot, alg: u8) -> Result<Vec<u8>, PivCryptoError> {
        let (cose, coord) = piv_alg(alg)?;
        let id = piv_key_slot(slot);
        let mut rng = rand_core::OsRng;
        // Presença: applet já exigiu PIN verificado (documentado no módulo).
        self.keys
            .generate(id, cose, piv_label(slot).into(), KEY_USE_SIGN | KEY_USE_AUTH, self.created, true, &mut rng)
            .map_err(|_| PivCryptoError::Failed)?;
        let raw = self
            .keys
            .public_sec1(id, true)
            .map_err(|_| PivCryptoError::Failed)?;
        // Sanidade: 04||x||y no tamanho da curva (nunca vazio/TRUNCADO).
        if raw.len() != 1 + 2 * coord || raw.first() != Some(&0x04) {
            return Err(PivCryptoError::Failed);
        }
        Ok(raw)
    }

    fn authenticate(
        &mut self,
        slot: PivSlot,
        alg: u8,
        challenge: &[u8],
    ) -> Result<Vec<u8>, PivCryptoError> {
        let (cose, coord) = piv_alg(alg)?;
        let _ = cose;
        let id = piv_key_slot(slot);
        let der = self
            .keys
            .sign(id, challenge, true)
            .map_err(|_| PivCryptoError::Failed)?;
        der_to_raw(&der, coord).ok_or(PivCryptoError::Failed)
    }
}

/// DER ECDSA → R||S cru (`coord` bytes por coordenada). Fail-closed.
fn der_to_raw(der: &[u8], coord: usize) -> Option<Vec<u8>> {
    if der.len() < 8 || der[0] != 0x30 {
        return None;
    }
    let mut pos = 1 + der_len_size(&der[1..])?;
    if der.get(pos) != Some(&0x02) {
        return None;
    }
    pos += 1;
    let (rlen, lb) = read_der_len(&der[pos..])?;
    pos += lb;
    let r = der.get(pos..pos + rlen)?;
    pos += rlen;
    if der.get(pos) != Some(&0x02) {
        return None;
    }
    pos += 1;
    let (slen, lb) = read_der_len(&der[pos..])?;
    pos += lb;
    let s = der.get(pos..pos + slen)?;
    pos += slen;
    if pos != der.len() {
        return None;
    }
    let mut out = Vec::with_capacity(2 * coord);
    let rp = left_pad_trim(r, coord)?;
    let sp = left_pad_trim(s, coord)?;
    out.extend_from_slice(&rp[64 - coord..]);
    out.extend_from_slice(&sp[64 - coord..]);
    Some(out)
}

/// Lê comprimento DER curto/longo. Retorna (valor, bytes de cabeçalho).
fn read_der_len(b: &[u8]) -> Option<(usize, usize)> {
    let first = *b.first()?;
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x81 {
        Some((*b.get(1)? as usize, 2))
    } else if first == 0x82 {
        Some(
            (((*b.get(1)? as usize) << 8) | (*b.get(2)? as usize), 3),
        )
    } else {
        None
    }
}

/// Tamanho do cabeçalho de comprimento DER no ponto.
fn der_len_size(b: &[u8]) -> Option<usize> {
    read_der_len(b).map(|(_, lb)| lb)
}

/// Ajusta inteiro DER (com/sem zero à esquerda) p/ `coord` bytes fixos.
/// Retorna os bytes alinhados ao FIM do array (fatia `[64-coord..]`).
fn left_pad_trim(v: &[u8], coord: usize) -> Option<[u8; 64]> {
    let mut out = [0u8; 64];
    if coord == 0 || coord > 64 || v.len() > coord + 1 {
        return None;
    }
    let t = if v.len() == coord + 1 && v[0] == 0x00 {
        &v[1..]
    } else {
        v
    };
    if t.len() > coord {
        return None;
    }
    out[64 - t.len()..64].copy_from_slice(t);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x11u8; 32], &[0x22u8; 32])
    }

    #[test]
    fn store_roundtrip_e_idempotente() {
        let mut st = test_storage();
        let mut s = PivNvsStore::new(&mut st);
        assert_eq!(s.load_record("piv_pin_hash"), Err(PivStoreError::NotFound));
        s.store_record("piv_pin_hash", b"h".repeat(16).as_slice()).expect("store");
        assert_eq!(s.load_record("piv_pin_hash").expect("load").len(), 16);
        s.delete_record("piv_pin_hash").expect("delete");
        s.delete_record("piv_pin_hash").expect("re-delete ok");
        assert_eq!(s.load_record("piv_pin_hash"), Err(PivStoreError::NotFound));
    }

    #[test]
    fn backend_gen_auth_p256_roundtrip() {
        let mut km = KeyManager::new();
        let mut be = PivFwBackend::new(&mut km, 1);
        let pubraw = be.generate(PivSlot::Auth9A, 0x11).expect("gen");
        assert_eq!(pubraw.len(), 65);
        assert_eq!(pubraw[0], 0x04);
        // Assina e confere a resposta crua (verificação P-256 local).
        let chal = b"desafio-piv-f4-teste-1234567890";
        let resp = be.authenticate(PivSlot::Auth9A, 0x11, chal).expect("auth");
        assert_eq!(resp.len(), 64);
        let vk = {
            use aegis_fido_core::crypto::cose::CoseKey;
            use aegis_fido_core::crypto::curves::PublicKey;
            let x: [u8; 32] = pubraw[1..33].try_into().expect("x");
            let y: [u8; 32] = pubraw[33..65].try_into().expect("y");
            PublicKey::from_cose_key(&CoseKey::p256(x.to_vec(), y.to_vec())).expect("vk")
        };
        // Recompõe DER e verifica (prova: R||S casa com a pública).
        let der = raw_to_der(&resp);
        assert!(vk.verify(chal, &der).is_ok());
        // RSA indisponível; slot duplicado falha sem sobrescrever.
        assert_eq!(be.generate(PivSlot::Auth9A, 0x11).unwrap_err(), PivCryptoError::Failed);
        assert_eq!(be.generate(PivSlot::Sign9C, 0x06).unwrap_err(), PivCryptoError::BadAlg);
    }

    /// R||S cru → DER (só p/ teste; inverso de `der_to_raw`).
    fn raw_to_der(raw: &[u8]) -> Vec<u8> {
        assert_eq!(raw.len() % 2, 0);
        let n = raw.len() / 2;
        fn enc(v: &[u8]) -> Vec<u8> {
            let t = {
                let i = v.iter().position(|b| *b != 0).unwrap_or(v.len().saturating_sub(1));
                &v[i..]
            };
            let t: &[u8] = if t.is_empty() { &[0u8] } else { t };
            let mut o = vec![0x02];
            if t[0] & 0x80 != 0 {
                o.push((t.len() + 1) as u8);
                o.push(0x00);
            } else {
                o.push(t.len() as u8);
            }
            o.extend_from_slice(t);
            o
        }
        let re = enc(&raw[..n]);
        let se = enc(&raw[n..]);
        let mut o = vec![0x30, (re.len() + se.len()) as u8];
        o.extend_from_slice(&re);
        o.extend_from_slice(&se);
        o
    }

    #[test]
    fn der_to_raw_rejeita_lixo() {
        assert!(der_to_raw(b"", 32).is_none());
        assert!(der_to_raw(b"\x30\x03\x02\x01\x01", 32).is_none());
        // DER real P-256 (70-72B) deve dar 64B.
        let mut rng = rand_core::OsRng;
        let kp = aegis_fido_core::crypto::curves::KeyPair::generate(
            CoseAlgorithm::ES256,
            &mut rng,
        )
        .expect("kp");
        let der = kp.sign(b"m").expect("sign");
        let raw = der_to_raw(&der, 32).expect("raw");
        assert_eq!(raw.len(), 64);
    }
}
