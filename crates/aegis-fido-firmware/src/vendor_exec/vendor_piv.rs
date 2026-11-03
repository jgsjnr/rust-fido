//! Vendor PIV enrollment (move-only split of `vendor_exec`).
//!
//! Enrollment PIV (`0x39`, F4): grava PIN+PUK iniciais via `provision_pin`
//! Enrollment PIV (`0x39`, F4): grava PIN+PUK iniciais via `provision_pin`
//! (verify-after-write interno). Req: `pin_len(1) || pin(6-8B) || puk(8B)`.
//! `0x00` ok; qualquer falha = `0x04` fail-closed (sem oráculo).

use crate::persistence::{FlashStorageBackend, SecureStorage};
use crate::piv_store::PivNvsStore;

pub(crate) fn exec_piv_enroll<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    payload: &[u8],
) -> (u8, Vec<u8>) {
    let pin_len = match payload.first() {
        Some(&n) if (6..=8).contains(&n) => n as usize,
        _ => return (0x04, Vec::new()),
    };
    if payload.len() != 1 + pin_len + 8 {
        return (0x04, Vec::new());
    }
    let pin = &payload[1..1 + pin_len];
    let puk = &payload[1 + pin_len..];
    let mut store = PivNvsStore::new(storage);
    match aegis_fido_usb::piv::provision_pin(&mut store, pin, puk) {
        Ok(()) => (0x00, Vec::new()),
        Err(_) => (0x04, Vec::new()),
    }
}
