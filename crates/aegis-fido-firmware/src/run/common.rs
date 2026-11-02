//! Shared init/poll helpers for the authenticator run loops (move-only).
//!
//! Extracted verbatim from `run_loop_legacy` + `run_loop_freertos`: both
//! loops call these; public entry points stay in `super`
//! (`run_authenticator` / `run_authenticator_freertos`).
//! Helpers borrow only what they touch so each loop keeps owning its
//! state (no behavior change; time arrives via args, never from a clock).

use crate::display::{DisplayManager, UiScreen};
use crate::led::LedOutput;
use crate::mdns::MdnsManager;
use crate::pairing::PairingManager;
use crate::persistence::{PlatformFlashBackend, SecureStorage};
use crate::wifi_station::WifiStationManager;

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

/// Station (+ mDNS + radio power-down) poll shared by both loops.
///
/// Station only outside pairing, with credentials and 60 s backoff; mDNS
/// follows station up; radio fully off when unused (battery). Time arrives
/// via `now_ms` (never from a host clock); credentials never hit the log.
#[allow(clippy::too_many_arguments)]
pub(crate) fn poll_wifi_station_radio(
    storage: &SecureStorage<PlatformFlashBackend>,
    sta_mgr: &mut WifiStationManager,
    mdns_mgr: &mut MdnsManager,
    mdns_active: &mut bool,
    wifi_ap_active: bool,
    wifi_radio_on: &mut bool,
    last_sta_attempt_ms: &mut Option<u64>,
    pairing_open_now: bool,
    ble_pairing_now: bool,
    has_creds: bool,
    now_ms: u64,
) {
    sta_mgr.update(pairing_open_now, has_creds, now_ms);
    let mut sta_radio = crate::wifi_station::esp_sta_state();
    if sta_radio == crate::wifi_station::STA_CONNECTED {
        if !sta_mgr.is_up() {
            sta_mgr.on_connected();
            let ip = crate::wifi_station::esp_sta_ip();
            kprintln!(
                "[WIFI] station conectada (DHCP {}.{}.{}.{}).",
                ip[0],
                ip[1],
                ip[2],
                ip[3]
            );
        }
    } else if sta_radio == crate::wifi_station::STA_FAILED {
        sta_mgr.on_failed();
    }
    if matches!(
        sta_mgr.state(),
        crate::wifi_station::WifiStationState::Connecting { .. }
    ) && sta_radio == crate::wifi_station::STA_OFF
        && !pairing_open_now
        && !ble_pairing_now
        && crate::wifi_station::sta_retry_due(now_ms, *last_sta_attempt_ms)
    {
        let got = storage.load(crate::wifi_station::WIFI_STA_SSID_NVS_KEY);
        let got_pass = storage.load(crate::wifi_station::WIFI_STA_PASS_NVS_KEY);
        match (got, got_pass) {
            (Ok(ssid_b), Ok(pass_b)) => {
                match (core::str::from_utf8(&ssid_b), core::str::from_utf8(&pass_b)) {
                    (Ok(ssid), Ok(pass)) => {
                        // Credenciais nunca vao para o log.
                        let rc = crate::wifi_station::esp_sta_start(ssid, pass);
                        *last_sta_attempt_ms = Some(now_ms);
                        if rc != 0 {
                            kprintln!("[WIFI] station start rc={}.", rc);
                            sta_mgr.on_failed();
                        }
                    }
                    _ => sta_mgr.on_failed(),
                }
            }
            _ => sta_mgr.on_failed(),
        }
    }
    if (pairing_open_now || ble_pairing_now || !has_creds)
        && sta_radio != crate::wifi_station::STA_OFF
    {
        let _ = crate::wifi_station::esp_sta_stop();
        sta_mgr.disconnect();
        // Local cache update; refreshed via esp_sta_state() below. Retained for readability (no behavior change).
        #[allow(unused_assignments)]
        {
            sta_radio = crate::wifi_station::STA_OFF;
        }
    }
    mdns_mgr.update(pairing_open_now || ble_pairing_now, sta_mgr.is_up());
    let mdns_want = mdns_mgr.is_active();
    if mdns_want != *mdns_active {
        if mdns_want {
            let host = crate::mdns::mdns_hostname_for_serial(
                crate::usb_descriptors::SERIAL_NUMBER_STRING,
            );
            let bare = crate::mdns::mdns_bare_hostname(&host);
            let rc = crate::mdns::esp_mdns_start(bare);
            if rc == 0 {
                *mdns_active = true;
                kprintln!("[WIFI] mDNS '{}' on.", host);
            } else {
                kprintln!("[WIFI] mDNS start rc={}.", rc);
            }
        } else {
            let _ = crate::mdns::esp_mdns_stop();
            *mdns_active = false;
        }
    }
    // Bateria: radio totalmente off fora de uso (nem AP, nem station).
    // Rele apos start/stop deste poll (evita off imediato).
    sta_radio = crate::wifi_station::esp_sta_state();
    let radio_in_use = wifi_ap_active || sta_radio != crate::wifi_station::STA_OFF;
    if !radio_in_use && *wifi_radio_on {
        let _ = crate::wifi_ap::esp_wifi_off();
        *wifi_radio_on = false;
        kprintln!("[WIFI] radio off (bateria).");
    } else if radio_in_use {
        *wifi_radio_on = true;
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
