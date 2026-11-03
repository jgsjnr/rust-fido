//! Pairing journey tests (move-only split of `pairing::tests`).

use super::*;

#[test]
fn hold_5s_enters_pairing_ble() {
    let mut m = PairingManager::new();
    assert_eq!(m.state(), PairingState::Idle);
    // Pressiona em t=1000, segura ate 1000+5000.
    m.on_button_level(true, 1000);
    assert!(matches!(m.state(), PairingState::Arming { .. }));
    // Meio do hold: 50%.
    assert_eq!(m.arming_progress_pct(3500), 50);
    m.on_button_level(true, 6000);
    assert!(m.is_pairing_window_open(6000));
    assert!(matches!(m.state(), PairingState::PairingBle { .. }));
}

#[test]
fn release_early_cancels_arming() {
    let mut m = PairingManager::new();
    m.on_button_level(true, 0);
    m.on_button_level(false, 1000);
    assert_eq!(m.state(), PairingState::Idle);
}

#[test]
fn timeout_locks_and_rehold_repairs() {
    let mut m = PairingManager::new();
    m.on_button_level(true, 0);
    m.on_button_level(true, LONG_PRESS_MS);
    assert!(m.is_pairing_window_open(LONG_PRESS_MS));
    m.tick(LONG_PRESS_MS + PAIRING_WINDOW_MS);
    assert_eq!(m.state(), PairingState::Locked);
    // Novo hold 5s a partir de Locked volta a parear.
    m.on_button_level(true, LONG_PRESS_MS + PAIRING_WINDOW_MS + 10);
    let t1 = LONG_PRESS_MS + PAIRING_WINDOW_MS + 10;
    m.on_button_level(true, t1 + LONG_PRESS_MS);
    assert!(m.is_pairing_window_open(t1 + LONG_PRESS_MS));
}

#[test]
fn complete_requires_presence_and_window() {
    let mut m = PairingManager::new();
    m.on_button_level(true, 0);
    m.on_button_level(true, LONG_PRESS_MS);
    assert!(!m.complete_pairing(false, LONG_PRESS_MS + 100));
    assert!(!m.is_bonded());
    assert!(m.complete_pairing(true, LONG_PRESS_MS + 100));
    assert!(m.is_bonded());
    assert_eq!(m.state(), PairingState::Idle);
}

#[test]
fn ap_mode_preserves_expiry() {
    let mut m = PairingManager::new();
    m.on_button_level(true, 0);
    m.on_button_level(true, LONG_PRESS_MS);
    m.enter_ap_mode();
    assert!(matches!(m.state(), PairingState::PairingAp { .. }));
    m.enter_ble_mode();
    assert!(matches!(m.state(), PairingState::PairingBle { .. }));
}

#[cfg(feature = "test-mode")]
#[test]
fn test_window_opens_same_60s_window_without_presence() {
    let mut m = PairingManager::new();
    m.open_test_window(1000);
    assert!(m.is_pairing_window_open(1000));
    assert!(m.is_pairing_window_open(1000 + PAIRING_WINDOW_MS - 1));
    // Software abre a janela, NAO confirma presenca nem bonding.
    assert!(!m.is_bonded());
    assert!(!m.complete_pairing(false, 1100));
    assert!(!m.is_bonded());
    // Expira em 60s igual ao hold: tick move para Locked.
    m.tick(1000 + PAIRING_WINDOW_MS);
    assert_eq!(m.state(), PairingState::Locked);
    assert!(!m.is_pairing_window_open(1000 + PAIRING_WINDOW_MS));
}

#[cfg(feature = "test-mode")]
#[test]
fn test_window_ltrace_marks_software_source() {
    use core::fmt::Write as _;
    let mut buf = [0u8; 64];
    let len = {
        let mut w = FmtBuf {
            buf: &mut buf,
            len: 0,
        };
        let _ = write!(w, "{}", SoftwareArming(1234));
        w.len
    };
    let text = core::str::from_utf8(&buf[..len]).expect("ascii");
    assert!(
        text.contains("software"),
        "audit must tell software apart from hold"
    );
    assert!(text.contains("1234"));
    assert_eq!(TEST_PAIRING_OPEN_CMD, "TEST_PAIRING_OPEN");
}

#[cfg(feature = "test-mode")]
#[test]
fn test_window_close_locks_and_reopen_works() {
    let mut m = PairingManager::new();
    m.open_test_window(1000);
    assert!(m.is_pairing_window_open(1000));
    m.close_test_window();
    assert_eq!(m.state(), PairingState::Locked);
    assert!(!m.is_pairing_window_open(1000));
    // Fechar nao confirma presenca nem bonding.
    assert!(!m.is_bonded());
    // Reabrir (60s) volta a funcionar sem reset.
    m.open_test_window(2000);
    assert!(m.is_pairing_window_open(2000));
    assert!(!m.is_bonded());
    // Reabrir (300s) tambem volta a funcionar; fechar encerra igual.
    m.close_test_window();
    assert!(!m.is_pairing_window_open(2100));
    m.open_test_window_secs(3000, TEST_PAIRING_OPEN_300_SECS);
    assert!(m.is_pairing_window_open(3000 + TEST_PAIRING_OPEN_300_SECS * 1000 - 1));
    assert!(!m.is_bonded());
    m.close_test_window();
    assert_eq!(m.state(), PairingState::Locked);
    assert!(!m.is_pairing_window_open(3000));
}

#[cfg(feature = "test-mode")]
struct FmtBuf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

#[cfg(feature = "test-mode")]
impl core::fmt::Write for FmtBuf<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let take = s.len().min(self.buf.len().saturating_sub(self.len));
        self.buf[self.len..self.len + take].copy_from_slice(&s.as_bytes()[..take]);
        self.len += take;
        Ok(())
    }
}

#[test]
fn host_window_opens_same_60s_without_presence() {
    let mut m = PairingManager::new();
    m.open_host_window(2000);
    assert!(m.is_pairing_window_open(2000));
    assert!(m.is_pairing_window_open(2000 + PAIRING_WINDOW_MS - 1));
    assert!(!m.is_bonded());
    assert!(!m.complete_pairing(false, 2100));
    m.tick(2000 + PAIRING_WINDOW_MS);
    assert!(!m.is_pairing_window_open(2000 + PAIRING_WINDOW_MS));
}

#[test]
fn host_pairing_msg_accepts_only_empty_0x2f() {
    assert!(is_host_pairing_msg(OP_HOST_PAIRING_OPEN, 0));
    assert_eq!(OP_HOST_PAIRING_OPEN, 0x2F);
    assert!(!is_host_pairing_msg(OP_HOST_PAIRING_OPEN, 1));
    assert!(!is_host_pairing_msg(0x2E, 0));
    assert!(!is_host_pairing_msg(0x30, 0));
    let text = format!("{}", HostArming(77));
    assert!(text.contains("host"));
    assert!(text.contains("77"));
}
