//! Vendor OATH executors (move-only split of `vendor_exec`).
//!
//! PUT/LIST/CODE/DELETE sobre `OathApplet`, com persistência via
//! `super::vendor_store` e rollback via snapshot se o save falhar.
//!
//! Diet (`cap-fido-only` sem `cap-fido-totp`): fora da capability — o
//! dispatcher responde `UNSUPPORTED_FEATURE` sem chamar este módulo.

#![cfg(any(
    feature = "cap-fido-totp",
    not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))
))]

extern crate alloc;

use crate::persistence::{FlashStorageBackend, SecureStorage};
use aegis_fido_core::oath::applet::{OathApplet, OathDeviceError};
use aegis_fido_core::oath::tlv::{write_tlv, TAG_OATH_NAME, TAG_OATH_RESPONSE};
use alloc::vec::Vec;

pub(crate) fn oath_status(e: OathDeviceError) -> u8 {
    e.code()
}

pub(crate) fn exec_oath_put<B: FlashStorageBackend>(
    oath: &mut OathApplet,
    storage: &mut SecureStorage<B>,
    payload: &[u8],
    pin_ok: bool,
) -> (u8, Vec<u8>) {
    let snap = oath.export_state();
    match oath.device_put(payload, pin_ok, true) {
        Ok(()) => {
            if super::vendor_store::save_oath_result(storage, oath).is_ok() {
                (0x00, Vec::new())
            } else {
                let _ = oath.import_state(&snap);
                (0x04, Vec::new())
            }
        }
        Err(e) => (oath_status(e), Vec::new()),
    }
}

pub(crate) fn exec_oath_list(oath: &mut OathApplet) -> (u8, Vec<u8>) {
    match oath.device_list(false, true) {
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
    }
}

pub(crate) fn exec_oath_code<B: FlashStorageBackend>(
    oath: &mut OathApplet,
    storage: &mut SecureStorage<B>,
    payload: &[u8],
) -> (u8, Vec<u8>) {
    match oath.device_code(payload, false, true) {
        Ok(res) => {
            // HOTP avança contador: persiste (rollback não faz sentido;
            // WARN via status só se o save falhar em nova leitura).
            let _ = super::vendor_store::save_oath_result(storage, oath);
            let mut out = Vec::new();
            write_tlv(&mut out, TAG_OATH_RESPONSE, res.code.as_bytes());
            (0x00, out)
        }
        Err(e) => (oath_status(e), Vec::new()),
    }
}

pub(crate) fn exec_oath_delete<B: FlashStorageBackend>(
    oath: &mut OathApplet,
    storage: &mut SecureStorage<B>,
    payload: &[u8],
    pin_ok: bool,
) -> (u8, Vec<u8>) {
    let snap = oath.export_state();
    match oath.device_delete(payload, pin_ok, true) {
        Ok(()) => {
            if super::vendor_store::save_oath_result(storage, oath).is_ok() {
                (0x00, Vec::new())
            } else {
                let _ = oath.import_state(&snap);
                (0x04, Vec::new())
            }
        }
        Err(e) => (oath_status(e), Vec::new()),
    }
}
