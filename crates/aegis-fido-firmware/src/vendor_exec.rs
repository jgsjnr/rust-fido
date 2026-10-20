//! Executor vendor keys/OATH on-device (F2).
//!
//! Gates idênticos ao BLE/serial (`authorize_vendor_op`, ordem
//! binding -> UP -> PIN); executor real sobre `KeyManager`/`OathApplet`
//! com persistência NVS (snapshot + rollback se o save falhar).
//! IMPORT (`0x21`) segue gate-ok `0x04` (envelope AEGN + vault = F2b).
//! Sem PII/segredos no wire: só metadados e códigos (§9.7).

extern crate alloc;

use aegis_fido_core::credential::key_manager::{KeyManager, KeyManagerError};
use aegis_fido_core::credential::KEY_USE_AUTH;
use aegis_fido_core::credential::KEY_USE_SIGN;
use aegis_fido_core::crypto::curves::CoseAlgorithm;
use aegis_fido_core::oath::applet::{OathApplet, OathDeviceError};
use aegis_fido_core::oath::tlv::{find_tlv, parse_tlv_records, write_tlv};
use alloc::vec::Vec;

use crate::ble_gatt::{
    authorize_vendor_op, OP_KEY_DELETE, OP_KEY_GEN_ONDEVICE, OP_KEY_LIST,
    OP_OATH_CODE, OP_OATH_DELETE, OP_OATH_LIST, OP_OATH_PUT,
};
use crate::persistence::{FlashStorageBackend, SecureStorage};

/// Chaves NVS (≤15 chars) dos blobs de estado F2.
pub const NVS_KEYS_SLOTS: &str = "key_slots_v1";
pub const NVS_KEYS_OATH: &str = "oath_creds_v1";

/// Tags do pedido GEN (espelho `VendorOps` do app).
const TAG_SLOT: u8 = 0x01;
const TAG_LABEL: u8 = 0x02;
const TAG_ALG_HINT: u8 = 0x05;
const TAG_USAGE_HINT: u8 = 0x06;
/// Tag OATH de resposta CODE (espelho `VendorOps.TAG_OATH_RESPONSE`).
const TAG_OATH_NAME: u8 = 0x71;
const TAG_OATH_RESPONSE: u8 = 0x75;

fn km_status(e: KeyManagerError) -> u8 {
    e.status()
}

fn oath_status(e: OathDeviceError) -> u8 {
    e.code()
}

/// Persiste o estado; `false` se o save falhar (chamador faz rollback).
fn save_keys<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    keys: &KeyManager,
) -> bool {
    storage.store(NVS_KEYS_SLOTS, &keys.export_state(), &[0u8; 12]).is_ok()
}

fn save_oath<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    oath: &OathApplet,
) -> bool {
    storage.store(NVS_KEYS_OATH, &oath.export_state(), &[0u8; 12]).is_ok()
}

/// Carrega estados do NVS no boot (ausente = vazio; corrompido = vazio +
/// `false` p/ WARN do chamador).
pub fn load_states<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    keys: &mut KeyManager,
    oath: &mut OathApplet,
) -> bool {
    let mut ok = true;
    match storage.load(NVS_KEYS_SLOTS) {
        Ok(blob) => {
            if keys.import_state(&blob).is_err() {
                ok = false;
            }
        }
        Err(crate::persistence::StorageError::KeyNotFound) => {}
        Err(_) => ok = false,
    }
    match storage.load(NVS_KEYS_OATH) {
        Ok(blob) => {
            if oath.import_state(&blob).is_err() {
                ok = false;
            }
        }
        Err(crate::persistence::StorageError::KeyNotFound) => {}
        Err(_) => ok = false,
    }
    ok
}

/// Executa uma op vendor `0x20-0x27` (gates + persistência).
/// Retorna `(wire_status, body)` status-first como o BLE.
#[allow(clippy::too_many_arguments)]
pub fn exec_vendor_op<B, R>(
    keys: &mut KeyManager,
    oath: &mut OathApplet,
    storage: &mut SecureStorage<B>,
    op: u8,
    payload: &[u8],
    binding_ok: bool,
    pin_ok: bool,
    up: bool,
    now_secs: u64,
    rng: &mut R,
) -> (u8, Vec<u8>)
where
    B: FlashStorageBackend,
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    if let Err(e) = authorize_vendor_op(op, binding_ok, pin_ok, up) {
        return (e.to_vendor_status(), Vec::new());
    }
    match op {
        OP_KEY_GEN_ONDEVICE => exec_key_gen(keys, storage, payload, now_secs, rng),
        OP_KEY_LIST => {
            let mut out = Vec::new();
            match keys.list(true) {
                Ok(slots) => {
                    for s in &slots {
                        write_tlv(&mut out, TAG_SLOT, &[s.id]);
                        write_tlv(&mut out, TAG_LABEL, s.label.as_bytes());
                    }
                    (0x00, out)
                }
                Err(e) => (km_status(e), Vec::new()),
            }
        }
        OP_KEY_DELETE => {
            let slot = match parse_slot(payload) {
                Some(s) => s,
                None => return (0x04, Vec::new()),
            };
            let snap = keys.export_state();
            match keys.delete(slot, true, pin_ok) {
                Ok(()) => {
                    if save_keys(storage, keys) {
                        (0x00, Vec::new())
                    } else {
                        let _ = keys.import_state(&snap);
                        (0x04, Vec::new())
                    }
                }
                Err(e) => (km_status(e), Vec::new()),
            }
        }
        OP_OATH_PUT => {
            let snap = oath.export_state();
            match oath.device_put(payload, pin_ok, true) {
                Ok(()) => {
                    if save_oath(storage, oath) {
                        (0x00, Vec::new())
                    } else {
                        let _ = oath.import_state(&snap);
                        (0x04, Vec::new())
                    }
                }
                Err(e) => (oath_status(e), Vec::new()),
            }
        }
        OP_OATH_LIST => match oath.device_list(false, true) {
            Ok(slots) => {
                let mut out = Vec::new();
                for s in &slots {
                    let mut val = Vec::with_capacity(1 + s.label.len());
                    val.push((s.tipo as u8) | (s.hmac as u8));
                    val.extend_from_slice(s.label.as_bytes());
                    write_tlv(&mut out, TAG_OATH_NAME, &val);
                }
                (0x00, out)
            }
            Err(e) => (oath_status(e), Vec::new()),
        },
        OP_OATH_CODE => match oath.device_code(payload, false, true) {
            Ok(res) => {
                // HOTP avança contador: persiste (rollback não faz sentido;
                // WARN via status só se o save falhar em nova leitura).
                let _ = save_oath(storage, oath);
                let mut out = Vec::new();
                write_tlv(&mut out, TAG_OATH_RESPONSE, res.code.as_bytes());
                (0x00, out)
            }
            Err(e) => (oath_status(e), Vec::new()),
        },
        OP_OATH_DELETE => {
            let snap = oath.export_state();
            match oath.device_delete(payload, pin_ok, true) {
                Ok(()) => {
                    if save_oath(storage, oath) {
                        (0x00, Vec::new())
                    } else {
                        let _ = oath.import_state(&snap);
                        (0x04, Vec::new())
                    }
                }
                Err(e) => (oath_status(e), Vec::new()),
            }
        }
        // IMPORT (0x21): envelope AEGN + vault = F2b; gate já passou.
        _ => (0x04, Vec::new()),
    }
}

fn exec_key_gen<B, R>(
    keys: &mut KeyManager,
    storage: &mut SecureStorage<B>,
    payload: &[u8],
    now_secs: u64,
    rng: &mut R,
) -> (u8, Vec<u8>)
where
    B: FlashStorageBackend,
    R: rand_core::RngCore + rand_core::CryptoRng,
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
            if save_keys(storage, keys) {
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

fn parse_slot(payload: &[u8]) -> Option<u8> {
    let records = parse_tlv_records(payload).ok()?;
    match find_tlv(&records, TAG_SLOT) {
        Some(v) if v.len() == 1 => Some(v[0]),
        _ => None,
    }
}
