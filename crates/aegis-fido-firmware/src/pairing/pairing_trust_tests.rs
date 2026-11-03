//! Trust-gate tests (move-only split of `pairing::pairing_trust_tests`).

use super::*;

#[test]
fn gate_espelha_janela_60s() {
    let mut m = PairingManager::new();
    assert!(!pairing_gate_for_trust(&m, 0));
    m.open_host_window(1000);
    assert!(pairing_gate_for_trust(&m, 1000));
    assert!(pairing_gate_for_trust(&m, 1000 + PAIRING_WINDOW_MS - 1));
    m.tick(1000 + PAIRING_WINDOW_MS);
    assert!(!pairing_gate_for_trust(&m, 1000 + PAIRING_WINDOW_MS));
}
