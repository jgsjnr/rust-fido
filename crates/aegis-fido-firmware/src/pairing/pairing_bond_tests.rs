//! Bond-expiry tests (move-only split of `pairing::bond_expiry_tests`).

use super::*;

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

fn bonded_at(t: u64) -> PairingManager {
    let mut m = PairingManager::new();
    m.on_button_level(true, 0);
    m.on_button_level(true, LONG_PRESS_MS);
    assert!(m.complete_pairing(true, t));
    m
}

#[test]
fn teto_conservador_30_dias() {
    assert_eq!(BLE_BOND_MAX_AGE_MS, 30 * DAY_MS);
    assert!(!ble_bond_expired(1_000, 1_000 + BLE_BOND_MAX_AGE_MS - 1));
    assert!(ble_bond_expired(1_000, 1_000 + BLE_BOND_MAX_AGE_MS));
    assert!(ble_bond_expired(0, u64::MAX));
    // Skew (now < bonded_at): nunca expira por skew.
    assert!(!ble_bond_expired(9_000, 1_000));
}

#[test]
fn par_fresco_expira_e_esquece() {
    let mut m = bonded_at(LONG_PRESS_MS + 10);
    let t0 = LONG_PRESS_MS + 10;
    assert!(m.is_bonded());
    assert!(m.is_bond_fresh(t0));
    assert!(!m.bond_expired(t0));
    assert!(!m.forget_stale_bond(t0));
    assert!(m.is_bonded());
    // 29 dias: fresco; 30 dias: expirado.
    assert!(m.is_bond_fresh(t0 + 29 * DAY_MS));
    assert!(!m.is_bond_fresh(t0 + 30 * DAY_MS));
    assert!(m.bond_expired(t0 + 30 * DAY_MS));
    assert!(m.forget_stale_bond(t0 + 30 * DAY_MS));
    assert!(!m.is_bonded());
    assert!(!m.is_bond_fresh(t0 + 30 * DAY_MS));
    // Re-parear re-arma o timestamp.
    m.on_button_level(true, t0 + 30 * DAY_MS + 1);
    m.on_button_level(true, t0 + 30 * DAY_MS + 1 + LONG_PRESS_MS);
    assert!(m.complete_pairing(true, t0 + 30 * DAY_MS + 1 + LONG_PRESS_MS + 5));
    assert!(m.is_bond_fresh(t0 + 30 * DAY_MS + 1 + LONG_PRESS_MS + 5));
}

#[test]
fn janela_60s_intacta_com_expiracao() {
    // A validade do bond nao altera a janela de pareamento.
    let mut m = PairingManager::new();
    m.on_button_level(true, 0);
    m.on_button_level(true, LONG_PRESS_MS);
    assert!(m.is_pairing_window_open(LONG_PRESS_MS + 1));
    m.tick(LONG_PRESS_MS + PAIRING_WINDOW_MS);
    assert!(!m.is_pairing_window_open(LONG_PRESS_MS + PAIRING_WINDOW_MS));
}
