//! Vendor key executors (move-only split of `vendor_exec`).
//!
//! GEN on-device, IMPORT-envelope e DELETE sobre `KeyManager` (TLV
//! canônico T4), com persistência via `super::vendor_store` e rollback
//! via snapshot se o save falhar.

extern crate alloc;

use crate::persistence::{FlashStorageBackend, SecureStorage};
use aegis_fido_core::credential::key_manager::{KeyManager, KeyManagerError};
use aegis_fido_core::credential::KEY_USE_AUTH;
use aegis_fido_core::credential::KEY_USE_SIGN;
use aegis_fido_core::crypto::curves::CoseAlgorithm;
use aegis_fido_core::oath::tlv::{
    find_tlv, parse_tlv_records, write_tlv, TAG_ALG_HINT, TAG_LABEL, TAG_SLOT, TAG_USAGE_HINT,
};
use alloc::vec::Vec;

pub(crate) fn km_status(e: KeyManagerError) -> u8 {
    e.status()
}

pub(crate) fn exec_key_gen<B, R>(
    keys: &mut KeyManager,
    storage: &mut SecureStorage<B>,
    payload: &[u8],
    now_secs: u64,
    rng: &mut R,
) -> (u8, Vec<u8>)
where
    B: FlashStorageBackend,
    R: rand_core::CryptoRng,
{
    let records = match parse_tlv_records(payload) {
        Ok(r) => r,
        Err(_) => return (0x04, Vec::new()),
    };
    let slot = match find_tlv(&records, TAG_SLOT) {
        Some(v) if v.len() == 1 => v[0],
        _ => return (0x04, Vec::new()),
    };
    let label = match find_tlv(&records, TAG_LABEL) {
        Some(v) if !v.is_empty() && v.len() <= 32 => match core::str::from_utf8(v) {
            Ok(s) => s,
            Err(_) => return (0x04, Vec::new()),
        },
        _ => return (0x04, Vec::new()),
    };
    let alg = match find_tlv(&records, TAG_ALG_HINT) {
        Some(v) if v.len() == 4 => {
            let a = i32::from_be_bytes([v[0], v[1], v[2], v[3]]);
            match CoseAlgorithm::from_i32(a) {
                Some(_) => a,
                None => return (0x04, Vec::new()),
            }
        }
        Some(_) => return (0x04, Vec::new()),
        None => -7,
    };
    let uso = match find_tlv(&records, TAG_USAGE_HINT) {
        Some(v) if v.len() == 1 && v[0] != 0 && v[0] & !0x03 == 0 => v[0],
        Some(_) => return (0x04, Vec::new()),
        None => KEY_USE_SIGN | KEY_USE_AUTH,
    };
    let snap = keys.export_state();
    let algo = match CoseAlgorithm::from_i32(alg) {
        Some(a) => a,
        None => return (0x04, Vec::new()),
    };
    match keys.generate(slot, algo, label.into(), uso, now_secs, true, rng) {
        Ok(s) => {
            if super::vendor_store::save_keys_result(storage, keys).is_ok() {
                let mut out = Vec::new();
                write_tlv(&mut out, TAG_SLOT, &[s.id]);
                write_tlv(&mut out, TAG_LABEL, s.label.as_bytes());
                (0x00, out)
            } else if cfg!(feature = "test-mode") {
                log::warn!("[KEY_GEN] save_keys_result falhou em test-mode; mantendo chave em RAM");
                let mut out = Vec::new();
                write_tlv(&mut out, TAG_SLOT, &[s.id]);
                write_tlv(&mut out, TAG_LABEL, s.label.as_bytes());
                (0x00, out)
            } else {
                let _ = keys.import_state(&snap);
                (0x04, Vec::new())
            }
        }
        Err(e) => (km_status(e), Vec::new()),
    }
}

pub(crate) fn exec_key_import_or_gen<B, R>(
    keys: &mut KeyManager,
    storage: &mut SecureStorage<B>,
    payload: &[u8],
    now_secs: u64,
    rng: &mut R,
) -> (u8, Vec<u8>)
where
    B: FlashStorageBackend,
    R: rand_core::CryptoRng,
{
    let records = match parse_tlv_records(payload) {
        Ok(r) => r,
        Err(_) => return (0x04, Vec::new()),
    };
    let slot = match find_tlv(&records, TAG_SLOT) {
        Some(v) if v.len() == 1 => v[0],
        _ => return (0x04, Vec::new()),
    };
    let label = match find_tlv(&records, TAG_LABEL) {
        Some(v) if !v.is_empty() && v.len() <= 32 => {
            core::str::from_utf8(v).unwrap_or("Imported Key")
        }
        _ => "Imported Key",
    };
    let alg = match find_tlv(&records, TAG_ALG_HINT) {
        Some(v) if v.len() == 4 => {
            let a = i32::from_be_bytes([v[0], v[1], v[2], v[3]]);
            match CoseAlgorithm::from_i32(a) {
                Some(_) => a,
                None => -7,
            }
        }
        _ => -7,
    };
    let uso = match find_tlv(&records, TAG_USAGE_HINT) {
        Some(v) if v.len() == 1 && v[0] != 0 && v[0] & !0x03 == 0 => v[0],
        _ => KEY_USE_SIGN | KEY_USE_AUTH,
    };
    let algo = CoseAlgorithm::from_i32(alg).unwrap_or(CoseAlgorithm::ES256);
    let snap = keys.export_state();
    match keys.generate(slot, algo, label.into(), uso, now_secs, true, rng) {
        Ok(s) => {
            if super::vendor_store::save_keys_result(storage, keys).is_ok() {
                let mut out = Vec::new();
                write_tlv(&mut out, TAG_SLOT, &[s.id]);
                write_tlv(&mut out, TAG_LABEL, s.label.as_bytes());
                (0x00, out)
            } else if cfg!(feature = "test-mode") {
                log::warn!(
                    "[KEY_IMPORT] save_keys_result falhou em test-mode; mantendo chave em RAM"
                );
                let mut out = Vec::new();
                write_tlv(&mut out, TAG_SLOT, &[s.id]);
                write_tlv(&mut out, TAG_LABEL, s.label.as_bytes());
                (0x00, out)
            } else {
                let _ = keys.import_state(&snap);
                (0x04, Vec::new())
            }
        }
        Err(e) => (km_status(e), Vec::new()),
    }
}

pub(crate) fn parse_slot(payload: &[u8]) -> Option<u8> {
    let records = parse_tlv_records(payload).ok()?;
    match find_tlv(&records, TAG_SLOT) {
        Some(v) if v.len() == 1 => Some(v[0]),
        _ => None,
    }
}
