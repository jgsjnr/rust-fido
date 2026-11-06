//! Station (+ mDNS + radio power-down) poll shared by both run loops.
//!
//! Extracted verbatim from `run::common`: station only outside pairing,
//! with credentials and 60 s backoff; mDNS follows station up; radio
//! fully off when unused (battery). Time arrives via `now_ms`
//! (never from a host clock); credentials never hit the log.

use crate::mdns::MdnsManager;
use crate::persistence::{PlatformFlashBackend, SecureStorage};
use crate::wifi_station::WifiStationManager;

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
            let host =
                crate::mdns::mdns_hostname_for_serial(crate::usb_descriptors::SERIAL_NUMBER_STRING);
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
