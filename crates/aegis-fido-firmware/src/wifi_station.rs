//! Phase8 - WiFi station (casca fina de compat; ver `net`).
//!
//! Conteudo movido para `net::station` sem mudanca de comportamento.
//! Testes `mod tests` ficam aqui.
pub use crate::net::station::*;
#[cfg(test)]
use crate::persistence::SecureStorage;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    #[test]
    fn ssid_password_bounds() {
        assert!(is_valid_sta_ssid("Casa-5G"));
        assert!(!is_valid_sta_ssid(""));
        assert!(!is_valid_sta_ssid(&"x".repeat(33)));
        assert!(is_valid_sta_password("senha-segura-123"));
        assert!(!is_valid_sta_password("curta"));
        assert!(!is_valid_sta_password(&"x".repeat(64)));
    }

    #[test]
    fn save_requires_up_pin_and_keeps_nvs_intact() {
        let mut st = test_storage();
        assert_eq!(
            save_station_credentials(&mut st, "Casa-5G", "senha-segura-123", false, true),
            Err(WifiStationError::Unauthorized)
        );
        assert_eq!(
            save_station_credentials(&mut st, "Casa-5G", "senha-segura-123", true, false),
            Err(WifiStationError::Unauthorized)
        );
        assert!(!has_station_credentials(&st));
        assert_eq!(
            save_station_credentials(&mut st, "", "senha-segura-123", true, true),
            Err(WifiStationError::InvalidSsid)
        );
        assert_eq!(
            save_station_credentials(&mut st, "Casa-5G", "curta", true, true),
            Err(WifiStationError::InvalidPassword)
        );
        save_station_credentials(&mut st, "Casa-5G", "senha-segura-123", true, true)
            .expect("save ok");
        assert!(has_station_credentials(&st));
        assert_eq!(st.load(WIFI_STA_SSID_NVS_KEY).expect("ssid"), b"Casa-5G");
    }

    #[test]
    fn clear_requires_up_pin() {
        let mut st = test_storage();
        save_station_credentials(&mut st, "Casa-5G", "senha-segura-123", true, true).expect("save");
        assert_eq!(
            clear_station_credentials(&mut st, false, true),
            Err(WifiStationError::Unauthorized)
        );
        assert!(has_station_credentials(&st));
        clear_station_credentials(&mut st, true, true).expect("clear ok");
        assert!(!has_station_credentials(&st));
    }

    #[test]
    fn station_only_outside_pairing_with_credentials() {
        let mut m = WifiStationManager::new();
        assert!(!m.is_up());
        m.update(false, false, 0);
        assert_eq!(m.state(), WifiStationState::Off);
        m.update(true, true, 0);
        assert_eq!(m.state(), WifiStationState::Off);
        m.update(false, true, 1000);
        assert!(matches!(m.state(), WifiStationState::Connecting { .. }));
        m.on_connected();
        assert!(m.is_up());
        m.update(true, true, 2000);
        assert_eq!(m.state(), WifiStationState::Off);
        assert!(!m.is_up());
    }

    #[test]
    fn host_shims_inertes() {
        assert_eq!(esp_sta_start("Casa-5G", "senha-segura-123"), 0);
        assert_eq!(esp_sta_stop(), 0);
        assert_eq!(esp_sta_state(), STA_OFF);
        assert_eq!(esp_sta_ip(), [0, 0, 0, 0]);
    }

    #[test]
    fn retry_backoff_poupanca_bateria() {
        assert!(sta_retry_due(0, None));
        assert!(!sta_retry_due(1_000, Some(0)));
        assert!(!sta_retry_due(WIFI_STA_RETRY_BACKOFF_MS - 1, Some(0)));
        assert!(sta_retry_due(WIFI_STA_RETRY_BACKOFF_MS, Some(0)));
        assert!(sta_retry_due(99_000, Some(0)));
        // Skew de relogio (now < last): nao tenta em loop.
        assert!(!sta_retry_due(0, Some(10_000)));
    }

    #[test]
    fn connecting_times_out_to_fallback_ap() {
        let mut m = WifiStationManager::new();
        m.update(false, true, 0);
        assert!(matches!(m.state(), WifiStationState::Connecting { .. }));
        m.update(false, true, WIFI_STA_CONNECT_TIMEOUT_MS);
        assert_eq!(m.state(), WifiStationState::Off);
        m.update(false, true, 99_000);
        m.on_failed();
        assert_eq!(m.state(), WifiStationState::Off);
        m.update(false, true, 100_000);
        m.disconnect();
        assert_eq!(m.state(), WifiStationState::Off);
    }
}
