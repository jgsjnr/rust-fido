//! Vendor op dispatcher (move-only split of `vendor_exec`).
//!
//! Executa uma op vendor `0x20-0x27` (gates + persistência). Retorna
//! `(wire_status, body)` status-first como o BLE. Braços de chaves/OATH/
//! PIV delegam para `vendor_keys` / `vendor_oath` / `vendor_piv`; o estado
//! persiste via `vendor_store`.

extern crate alloc;

use crate::ble_gatt::{authorize_vendor_op, BleGattError};
use crate::persistence::{FlashStorageBackend, SecureStorage};
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::applet::OathApplet;
use aegis_fido_core::oath::tlv::{write_tlv, TAG_LABEL, TAG_SLOT};
use alloc::vec::Vec;

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
    R: rand_core::CryptoRng,
{
    // PIV ENROLL (0x39, F4): fora da faixa 0x20-0x27 de propósito —
    // `authorize_vendor_op` rejeitaria como InvalidOpcode. Gate próprio
    // classe CONFIG (binding -> UP), sem PIN (ainda não existe).
    if op == crate::ble_gatt::OP_PIV_ENROLL {
        if !crate::binding::binding_bypass_enabled() && !binding_ok {
            return (BleGattError::NeedBinding.to_vendor_status(), Vec::new());
        }
        if !up {
            return (
                BleGattError::PresenceRequired.to_vendor_status(),
                Vec::new(),
            );
        }
        return super::vendor_piv::exec_piv_enroll(storage, payload);
    }
    if let Err(e) = authorize_vendor_op(op, binding_ok, pin_ok, up) {
        return (e.to_vendor_status(), Vec::new());
    }
    match op {
        crate::ble_gatt::OP_KEY_GEN_ONDEVICE => {
            super::vendor_keys::exec_key_gen(keys, storage, payload, now_secs, rng)
        }
        crate::ble_gatt::OP_KEY_IMPORT_ENVELOPE => {
            super::vendor_keys::exec_key_import_or_gen(keys, storage, payload, now_secs, rng)
        }
        crate::ble_gatt::OP_KEY_LIST => {
            let mut out = Vec::new();
            match keys.list(true) {
                Ok(slots) => {
                    for s in &slots {
                        write_tlv(&mut out, TAG_SLOT, &[s.id]);
                        write_tlv(&mut out, TAG_LABEL, s.label.as_bytes());
                    }
                    (0x00, out)
                }
                Err(e) => (super::vendor_keys::km_status(e), Vec::new()),
            }
        }
        crate::ble_gatt::OP_KEY_DELETE => {
            let slot = match super::vendor_keys::parse_slot(payload) {
                Some(s) => s,
                None => return (0x04, Vec::new()),
            };
            let snap = keys.export_state();
            match keys.delete(slot, true, pin_ok) {
                Ok(()) => {
                    if super::vendor_store::save_keys_result(storage, keys).is_ok() {
                        (0x00, Vec::new())
                    } else {
                        let _ = keys.import_state(&snap);
                        (0x04, Vec::new())
                    }
                }
                Err(e) => (super::vendor_keys::km_status(e), Vec::new()),
            }
        }
        #[cfg(any(
            feature = "cap-fido-totp",
            not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))
        ))]
        crate::ble_gatt::OP_OATH_PUT => {
            super::vendor_oath::exec_oath_put(oath, storage, payload, pin_ok)
        }
        #[cfg(any(
            feature = "cap-fido-totp",
            not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))
        ))]
        crate::ble_gatt::OP_OATH_LIST => super::vendor_oath::exec_oath_list(oath),
        #[cfg(any(
            feature = "cap-fido-totp",
            not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))
        ))]
        crate::ble_gatt::OP_OATH_CODE => super::vendor_oath::exec_oath_code(oath, storage, payload),
        #[cfg(any(
            feature = "cap-fido-totp",
            not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))
        ))]
        crate::ble_gatt::OP_OATH_DELETE => {
            super::vendor_oath::exec_oath_delete(oath, storage, payload, pin_ok)
        }
        // IMPORT (0x21): envelope AEGN + vault = F2b; gate já passou.
        // Diet cap-fido-only: OATH fora da capability (fail-closed).
        // Nunca queda silenciosa: responde UNSUPPORTED_FEATURE (0x06).
        #[cfg(all(feature = "cap-fido-only", not(feature = "cap-fido-totp")))]
        op if matches!(
            op,
            crate::ble_gatt::OP_OATH_PUT
                | crate::ble_gatt::OP_OATH_LIST
                | crate::ble_gatt::OP_OATH_CODE
                | crate::ble_gatt::OP_OATH_DELETE
        ) =>
        {
            let _ = (oath, storage, payload, pin_ok);
            (crate::UNSUPPORTED_FEATURE, Vec::new())
        }
        _ => (0x04, Vec::new()),
    }
}
