//! Vendor executor PIN-state tests.

use super::super::{load_pin_state, save_pin_state};
use super::test_storage;
use aegis_fido_core::ctap::client_pin::ClientPinState;

#[test]
fn pin_state_roundtrip_e_ausente_e_padrao() {
    let mut st = test_storage();
    let mut pin = ClientPinState::default();
    // Ausente: padrão (sem PIN, 8 retries), ok=true.
    assert!(load_pin_state(&st, &mut pin));
    assert_eq!(pin.pin_hash, None);
    assert_eq!(pin.pin_retries, 8);
    // Salva hash+retries e recarrega.
    let pin_set = ClientPinState {
        pin_hash: Some([0xABu8; 16]),
        pin_retries: 5,
        ..Default::default()
    };
    assert!(save_pin_state(&mut st, &pin_set));
    let mut pin2 = ClientPinState::default();
    assert!(load_pin_state(&st, &mut pin2));
    assert_eq!(pin2.pin_hash, Some([0xABu8; 16]));
    assert_eq!(pin2.pin_retries, 5);
    // Limpa hash (reset): volta a None.
    let pin_clear = ClientPinState {
        pin_hash: None,
        ..Default::default()
    };
    assert!(save_pin_state(&mut st, &pin_clear));
    let mut pin3 = ClientPinState {
        pin_hash: Some([0u8; 16]),
        ..Default::default()
    };
    assert!(load_pin_state(&st, &mut pin3));
    assert_eq!(pin3.pin_hash, None);
}
