//! Vendor executor PIV-enroll gate tests.

use super::super::exec_vendor_op;
use super::test_storage;
use crate::persistence::{MockFlashBackend, SecureStorage};
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::applet::OathApplet;

fn enroll_req(pin: &[u8], puk: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + pin.len() + puk.len());
    v.push(pin.len() as u8);
    v.extend_from_slice(pin);
    v.extend_from_slice(puk);
    v
}

fn exec_enroll(
    storage: &mut SecureStorage<MockFlashBackend>,
    payload: &[u8],
    binding_ok: bool,
    up: bool,
) -> (u8, Vec<u8>) {
    let mut keys = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    exec_vendor_op(
        &mut keys,
        &mut oath,
        storage,
        crate::ble_gatt::OP_PIV_ENROLL,
        payload,
        binding_ok,
        false,
        up,
        0,
        &mut rng,
    )
}

#[test]
fn piv_enroll_ok_e_segunda_tentativa_nega() {
    let mut st = test_storage();
    let req = enroll_req(b"123456", b"12345678");
    assert_eq!(exec_enroll(&mut st, &req, true, true).0, 0x00);
    // Já provisionado: fail-closed sem oráculo.
    assert_eq!(exec_enroll(&mut st, &req, true, true).0, 0x04);
}

#[test]
fn piv_enroll_exige_up_e_binding() {
    let mut st = test_storage();
    let req = enroll_req(b"123456", b"12345678");
    assert_eq!(exec_enroll(&mut st, &req, true, false).0, 0x01);
    if crate::binding::binding_bypass_enabled() {
        // test-mode: bypass de vínculo documentado (binding.rs); sem
        // vínculo mas com UP, o enroll prossegue e provisiona (0x00).
        assert_eq!(exec_enroll(&mut st, &req, false, true).0, 0x00);
    } else {
        assert_eq!(exec_enroll(&mut st, &req, false, true).0, 0x05);
    }
}

#[test]
fn piv_enroll_rejeita_geometria_invalida() {
    let mut st = test_storage();
    // pin_len mente / puk curto / vazio.
    assert_eq!(exec_enroll(&mut st, &[8, 1, 2, 3], true, true).0, 0x04);
    assert_eq!(
        exec_enroll(&mut st, &enroll_req(b"123", b"12345678"), true, true).0,
        0x04
    );
    assert_eq!(
        exec_enroll(&mut st, &enroll_req(b"123456", b"1234"), true, true).0,
        0x04
    );
    assert_eq!(exec_enroll(&mut st, &[], true, true).0, 0x04);
}
