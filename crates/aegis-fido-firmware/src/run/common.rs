//! Shared init/poll helpers for the authenticator run loops (move-only).
//!
//! Extracted verbatim from `run_loop_legacy` + `run_loop_freertos`: both
//! loops call these; public entry points stay in `super`
//! (`run_authenticator` / `run_authenticator_freertos`).
//! Helpers borrow only what they touch so each loop keeps owning its
//! state (no behavior change; time arrives via args, never from a clock).
//! Station/mDNS/radio poll lives in `super::station_poll` (split to keep
//! this hub below the dep-track god-score gate).

use crate::display::{DisplayManager, UiScreen};
use crate::fw_log::FwLog;
use crate::led::LedOutput;
use crate::pairing::PairingManager;
use crate::persistence::PlatformFlashBackend;
use crate::transport_lock::{TransportKind, TransportLockReport};
use aegis_fido_core::ctap::client_pin::ClientPinState;
use aegis_fido_core::otp::rescue::RescueEngine;
use aegis_fido_core::secure_guard::SecureGuardEngine;

/// Step 3 init: NVS flash backend with persistence probe (shared boot line).
pub(crate) fn init_flash_backend() -> PlatformFlashBackend {
    let flash_backend = PlatformFlashBackend::new();
    if flash_backend.is_persistent() {
        kprintln!("[INIT] Flash NVS backend online (persiste entre reboots).");
    } else {
        kprintln!("[WARN] Flash NVS indisponivel; RAM volatil (sem persistencia).");
    }
    flash_backend
}

/// B2 hold transitions (physical BOOT hold; visible without display/LCD).
pub(crate) fn poll_pairing_hold_transitions(
    pairing_mgr: &mut PairingManager,
    pairing_arming_prev: &mut bool,
    pairing_arming_sec: &mut u64,
    pairing_open_now: bool,
    now_ms: u64,
) {
    use crate::pairing::PairingState;
    match pairing_mgr.state() {
        PairingState::Arming { start_ms } => {
            if !*pairing_arming_prev {
                kprintln!("[PAIRING] segurando BOOT... (mantenha 5s p/ abrir a janela).");
                *pairing_arming_prev = true;
                *pairing_arming_sec = 0;
            }
            let held = now_ms.saturating_sub(start_ms) / 1000;
            if held > *pairing_arming_sec && held < 60 {
                *pairing_arming_sec = held;
                kprintln!("[PAIRING] segurando... {}s.", held);
            }
        }
        _ => {
            if *pairing_arming_prev {
                *pairing_arming_prev = false;
                // Saiu do Arming sem janela = soltou cedo (o caso de
                // sucesso passa pela borda da janela com EV_PAIR_OPEN).
                if !pairing_open_now {
                    kprintln!("[PAIRING] solto cedo, sem janela (segure 5s).");
                }
            }
        }
    }
}

/// BLE bond prompt: secure link without UP (touch BOOT to confirm).
pub(crate) fn note_bond_denied_no_presence<L: LedOutput>(
    ble_bond_pending: &mut bool,
    display_mgr: &mut DisplayManager<L>,
) {
    *ble_bond_pending = true;
    kprintln!("[BLE] link seguro sem UP: toque no BOOT para confirmar.");
    display_mgr.set_screen(UiScreen::UserPresencePrompt {
        rp_id: "Pareamento BLE".into(),
        user_name: "App AegisKey".into(),
        operation: "Confirmar pareamento".into(),
        remaining_seconds: 25,
    });
}

/// BLE central disconnected: drop adv/bond latches (fail-closed).
pub(crate) fn note_ble_disconnected(ble_adv_active: &mut bool, ble_bond_pending: &mut bool) {
    kprintln!("[BLE] central desconectou.");
    *ble_adv_active = false;
    *ble_bond_pending = false;
}

/// Trava de sessao na perda do transporte ativo (USB/BLE/WiFi).
///
/// Involucro fino sobre transport_lock::lock_on_transport_loss para os dois
/// run loops (freertos + legado): nestes pontos nao ha scratch do chamador em
/// escopo, entao a lista vai vazia. Audita EV_TRANSPORT_LOCK no FwLog e
/// loga so o canal (sem segredo). Sem wipe/NVS-erase/eFuse, sem mudar o PIN.
pub(crate) fn lock_session_on_transport_loss(
    engine: &mut SecureGuardEngine,
    pin_state: &mut ClientPinState,
    rescue: &mut RescueEngine,
    fw_log: &mut FwLog,
    kind: TransportKind,
    now_ms: u64,
) -> TransportLockReport {
    let mut empty: [&mut [u8]; 0] = [];
    let report = crate::transport_lock::lock_on_transport_loss(
        engine, pin_state, rescue, &mut empty, fw_log, kind, now_ms,
    );
    kprintln!(
        "[SECURE_GUARD] Sessao trancada por perda de transporte ({}).",
        kind.name()
    );
    report
}
