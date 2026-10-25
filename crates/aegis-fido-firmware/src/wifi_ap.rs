//! Wave4 -- WiFi AP `AegisKey-XXXX` (casca fina de compat; ver `net`).
//!
//! Conteudo movido para `net::ap_core` + `net::password_policy`
//! sem mudanca de comportamento. Testes `mod tests` ficam aqui.
#[deprecated(note = "Use crate::net::ap_core instead.")]
pub use crate::net::ap_core::*;
#[deprecated(note = "Use crate::net::password_policy instead.")]
pub use crate::net::password_policy::*;
#[cfg(test)]
extern crate alloc;

#[cfg(test)]
mod net_wifi_tests {
    use crate::net::ap_core::*;
    use crate::persistence::{MockFlashBackend, SecureStorage};
    use aegis_fido_core::oath::OathAlgorithm;

    extern crate alloc;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct FakeRadio;
    impl WifiRadioBackend for FakeRadio {
        fn ap_start(_s: &str, _p: &str) -> i32 {
            0
        }
        fn ap_stop() -> i32 {
            0
        }
        fn sta_start(_s: &str, _p: &str) -> i32 {
            0
        }
        fn sta_stop() -> i32 {
            0
        }
        fn mdns_start(_h: &str) -> i32 {
            0
        }
        fn mdns_stop() -> i32 {
            0
        }
        fn wifi_off() -> i32 {
            0
        }
    }

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    fn ctap_env(op: u8, nonce: [u8; 12]) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::new();
        v.extend_from_slice(&[0x41, 0x45, 0x47, 0x4E, 0x01]);
        v.extend_from_slice(&nonce);
        v.push(op);
        v.extend_from_slice(&[0x55u8; 19]);
        v.extend_from_slice(&[0u8; 16]);
        v
    }

    #[test]
    fn http_config_preserva_aad_rota_op_nonce() {
        let mut h = HttpConfig::new();
        let nonce = [0x01u8; 12];
        let env = ctap_env(0x09, nonce);
        assert!(h.post_ctap(&env, "/ctap", 0x09, None).is_ok());
        assert_eq!(h.last_nonce(), Some(nonce));
        // Rota errada / op divergente / replay: rejeita (sem regredir AAD).
        assert_eq!(
            h.post_ctap(&env, "/config/wifi", 0x09, None),
            Err(WifiApError::InvalidEnvelope)
        );
        assert_eq!(
            h.post_ctap(&env, "/ctap", 0x0A, None),
            Err(WifiApError::InvalidEnvelope)
        );
        assert_eq!(
            h.post_ctap(&env, "/ctap", 0x09, Some(nonce)),
            Err(WifiApError::InvalidEnvelope)
        );
        // Nonce zerado: rejeita.
        let zero = ctap_env(0x09, [0u8; 12]);
        assert_eq!(
            h.post_ctap(&zero, "/ctap", 0x09, None),
            Err(WifiApError::InvalidEnvelope)
        );
    }

    #[test]
    fn http_config_wifi_e_oath_atras_do_trait() {
        let mut h = HttpConfig::new();
        let mut st = test_storage();
        // POST /config/wifi: sem binding+auth rejeita sem tocar na NVS.
        if crate::binding::binding_bypass_enabled() {
            assert_eq!(
                h.post_config_wifi(&mut st, "nova-senha-123", false, false, false),
                Err(WifiApError::Unauthorized)
            );
        } else {
            assert_eq!(
                h.post_config_wifi(&mut st, "nova-senha-123", false, false, false),
                Err(WifiApError::NeedBinding)
            );
        }
        // GET /oath/code: so codigo, sem secret, exige UP.
        let secret = b"12345678901234567890";
        let secrets: &[(&str, &[u8], OathAlgorithm, u8)] =
            &[("GitHub:alice", secret, OathAlgorithm::Sha1, 6)];
        assert_eq!(
            h.get_oath_code("GitHub:alice", secrets, 59, false),
            Err(WifiApError::Unauthorized)
        );
        let r = h
            .get_oath_code("GitHub:alice", secrets, 59, true)
            .expect("totp");
        assert_eq!(r.code, "287082");
    }

    #[cfg(feature = "wifi")]
    #[test]
    fn wifi_net_gates_ap_station_mdns() {
        let mut n = WifiNet::<FakeRadio>::new();
        // AP fora de pareamento/menu: rejeita.
        assert_eq!(
            n.ap_start(false, false, 0, "AegisKey-00AF", None),
            Err(WifiNetError::ApNotAllowed)
        );
        // AP em pareamento: ok.
        n.ap_start(true, false, 1000, "AegisKey-00AF", Some("senha-segura-123"))
            .expect("ap ok");
        assert!(n.ap().is_active(1000));
        n.ap_stop().expect("stop ok");
        assert!(!n.ap().is_active(1000));
        // Station em pareamento ou sem creds: rejeita.
        assert_eq!(
            n.station_join(true, true, 2000, "Casa-5G", "senha-segura-123"),
            Err(WifiNetError::StationNotAllowed)
        );
        assert_eq!(
            n.station_join(false, false, 2000, "Casa-5G", "senha-segura-123"),
            Err(WifiNetError::StationNotAllowed)
        );
        n.station_join(false, true, 2000, "Casa-5G", "senha-segura-123")
            .expect("sta ok");
        // mDNS em pareamento ou sem station: fallback (rejeita).
        assert_eq!(
            n.mdns_announce(true, true, "aegiskey-00af"),
            Err(WifiNetError::MdnsNotAllowed)
        );
        assert_eq!(
            n.mdns_announce(false, false, "aegiskey-00af"),
            Err(WifiNetError::MdnsNotAllowed)
        );
        n.mdns_announce(false, true, "aegiskey-00af")
            .expect("mdns ok");
        assert!(n.mdns().is_active());
        n.off().expect("off ok");
        assert!(!n.mdns().is_active());
    }

    #[cfg(not(feature = "wifi"))]
    #[test]
    fn wifi_net_off_sem_feature() {
        let mut n = WifiNet::<FakeRadio>::new();
        assert_eq!(
            n.ap_start(true, false, 0, "AegisKey-00AF", None),
            Err(WifiNetError::NotCompiled)
        );
        assert_eq!(n.ap_stop(), Err(WifiNetError::NotCompiled));
        assert_eq!(
            n.station_join(false, true, 0, "s", "p"),
            Err(WifiNetError::NotCompiled)
        );
        assert_eq!(
            n.mdns_announce(false, true, "aegiskey-00af"),
            Err(WifiNetError::NotCompiled)
        );
        assert_eq!(n.off(), Err(WifiNetError::NotCompiled));
    }
}

#[cfg(test)]
mod tests {
    use crate::net::{ap_core::*, password_policy::*};
    use crate::persistence::{MockFlashBackend, SecureStorage};
    use aegis_fido_core::oath::OathAlgorithm;
    use alloc::vec::Vec;

    extern crate alloc;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    #[test]
    fn ap_poll_action_sem_spam_de_stop() {
        use super::ApPollAction as A;
        // Idle: quieto.
        assert_eq!(super::ap_poll_action(false, false, false), A::None);
        // Janela sem BLE: liga uma vez, depois quieto.
        assert_eq!(super::ap_poll_action(true, false, false), A::Start);
        assert_eq!(super::ap_poll_action(true, false, true), A::None);
        // BLE assumiu com radio off: NENHUM stop (era o spam a cada poll).
        assert_eq!(super::ap_poll_action(true, true, false), A::None);
        // BLE assumiu com radio on: desliga UMA vez.
        assert_eq!(super::ap_poll_action(true, true, true), A::Stop);
        // Janela fechou com radio on: desliga UMA vez.
        assert_eq!(super::ap_poll_action(false, false, true), A::Stop);
    }

    #[test]
    fn ssid_derives_suffix() {
        assert_eq!(ap_ssid_for_serial("AEGIS-S3-00AF"), "AegisKey-00AF");
        assert_eq!(ap_ssid_for_serial("AEGIS-S3-0001"), "AegisKey-0001");
        assert_eq!(ap_ssid_for_serial("x"), "AegisKey-0001");
    }

    #[test]
    fn ap_only_in_pairing_or_menu() {
        let mut m = WifiApManager::new();
        assert!(!m.is_active(0));
        m.update(false, false, 0);
        assert!(!m.is_active(0));
        m.update(true, false, 1000);
        assert!(m.is_active(1000));
        m.update(false, false, 1000 + WIFI_AP_TIMEOUT_MS);
        assert!(!m.is_active(1000 + WIFI_AP_TIMEOUT_MS));
        m.update(false, true, 90000);
        assert!(m.is_active(90000));
        m.shutdown_after_config();
        assert!(!m.is_active(90000));
    }

    #[test]
    fn password_change_requires_up_pin() {
        let mut st = test_storage();
        // Sem auth: rejeita e nao grava.
        assert_eq!(
            change_ap_password(&mut st, "nova-senha-123", false, true),
            Err(WifiApError::Unauthorized)
        );
        assert_eq!(
            change_ap_password(&mut st, "nova-senha-123", true, false),
            Err(WifiApError::Unauthorized)
        );
        assert!(!st.exists(WIFI_PASS_NVS_KEY));
        // Curta: rejeita mesmo com auth.
        assert_eq!(
            change_ap_password(&mut st, "curta", true, true),
            Err(WifiApError::InvalidPassword)
        );
        // Ok: grava cifrado (roundtrip sem expor senha em claro no erro).
        change_ap_password(&mut st, "nova-senha-123", true, true).expect("troca ok");
        assert!(st.exists(WIFI_PASS_NVS_KEY));
        assert_eq!(st.load(WIFI_PASS_NVS_KEY).expect("load"), b"nova-senha-123");
    }

    #[test]
    fn ctap_envelope_validated() {
        let mut env = Vec::new();
        env.extend_from_slice(&[0x41, 0x45, 0x47, 0x4E, 0x01]);
        env.extend_from_slice(&[0u8; 12]);
        env.extend_from_slice(&[9u8; 20]);
        env.extend_from_slice(&[0u8; 16]);
        assert!(validate_ctap_envelope(&env).is_ok());
        assert_eq!(
            validate_ctap_envelope(b"lixo"),
            Err(WifiApError::InvalidEnvelope)
        );
        let mut bad = env.clone();
        bad[0] ^= 0xFF;
        assert_eq!(
            validate_ctap_envelope(&bad),
            Err(WifiApError::InvalidEnvelope)
        );
    }

    #[test]
    fn ctap_envelope_bound_binds_route_op_nonce() {
        // Envelope com nonce nao-zero e op 0x09.
        let mut nonce = [0x11u8; 12];
        nonce[0] = 0x01;
        let mut env = Vec::new();
        env.extend_from_slice(&[0x41, 0x45, 0x47, 0x4E, 0x01]);
        env.extend_from_slice(&nonce);
        env.push(0x09);
        env.extend_from_slice(&[0x55u8; 19]);
        env.extend_from_slice(&[0u8; 16]);
        // Rota/op/nonce corretos: ok.
        assert!(validate_ctap_envelope_for_request(&env, "/ctap", 0x09, None).is_ok());
        // Rota errada: rejeita (cross-rota).
        assert_eq!(
            validate_ctap_envelope_for_request(&env, "/config/wifi", 0x09, None),
            Err(WifiApError::InvalidEnvelope)
        );
        // Op divergente: rejeita.
        assert_eq!(
            validate_ctap_envelope_for_request(&env, "/ctap", 0x0A, None),
            Err(WifiApError::InvalidEnvelope)
        );
        // Replay (nonce repetido): rejeita.
        assert_eq!(
            validate_ctap_envelope_for_request(&env, "/ctap", 0x09, Some(nonce)),
            Err(WifiApError::InvalidEnvelope)
        );
        // Nonce zero: rejeita.
        let mut zero = Vec::new();
        zero.extend_from_slice(&[0x41, 0x45, 0x47, 0x4E, 0x01]);
        zero.extend_from_slice(&[0u8; 12]);
        zero.extend_from_slice(&[0x09u8; 20]);
        zero.extend_from_slice(&[0u8; 16]);
        assert_eq!(
            validate_ctap_envelope_for_request(&zero, "/ctap", 0x09, None),
            Err(WifiApError::InvalidEnvelope)
        );
        // Legacy sem AAD continua aceitando (compat), nonce extraivel.
        assert!(validate_ctap_envelope(&env).is_ok());
        assert_eq!(ctap_envelope_nonce(&env).expect("nonce"), nonce);
    }

    #[test]
    fn coex_usb_veta_wifi() {
        assert!(!wifi_ap_coex_allowed(true));
        assert!(wifi_ap_coex_allowed(false));
    }

    #[test]
    fn oath_response_has_code_only() {
        let secret = b"12345678901234567890";
        let secrets: &[(&str, &[u8], OathAlgorithm, u8)] =
            &[("GitHub:alice", secret, OathAlgorithm::Sha1, 6)];
        // Sem UP: rejeita.
        assert_eq!(
            handle_get_oath_code("GitHub:alice", secrets, 59, false),
            Err(WifiApError::Unauthorized)
        );
        // Com UP: codigo RFC6238 T=1 -> HOTP counter 1 = 287082.
        let r = handle_get_oath_code("GitHub:alice", secrets, 59, true).expect("totp");
        assert_eq!(r.code, "287082");
        assert_eq!(r.account, "GitHub:alice");
        // Nunca contem o secret.
        assert!(!r.code.as_bytes().windows(secret.len()).any(|w| w == secret));
        assert_eq!(
            handle_get_oath_code("unknown", secrets, 59, true),
            Err(WifiApError::UnknownAccount)
        );
    }

    #[test]
    fn host_shims_inertes() {
        assert_eq!(esp_ap_start("AegisKey-00AF", "senha-segura-123"), 0);
        assert_eq!(esp_ap_start("AegisKey-00AF", ""), 0);
        assert_eq!(esp_ap_stop(), 0);
        assert_eq!(esp_wifi_off(), 0);
    }

    #[test]
    fn ap_password_resolve_sem_expor() {
        assert_eq!(resolve_ap_password(None), None);
        assert_eq!(resolve_ap_password(Some(b"")), None);
        assert_eq!(resolve_ap_password(Some(b"curta")), None);
        assert_eq!(resolve_ap_password(Some(&[0xFF, 0xFE, 0x00])), None);
        assert_eq!(
            resolve_ap_password(Some(b"senha-segura-123")).as_deref(),
            Some("senha-segura-123")
        );
    }

    #[test]
    fn query_parsing() {
        assert_eq!(
            parse_oath_account_query("/oath/code?account=GitHub"),
            Some("GitHub")
        );
        assert_eq!(parse_oath_account_query("/oath/code"), None);
        assert_eq!(parse_oath_account_query("/oath/code?account="), None);
    }

    #[test]
    fn heap_guard_limiar_32kib() {
        assert_eq!(WIFI_AP_MIN_HEAP_LARGEST, 32 * 1024);
        assert!(!wifi_ap_start_allowed(0));
        assert!(!wifi_ap_start_allowed(WIFI_AP_MIN_HEAP_LARGEST - 1));
        assert!(wifi_ap_start_allowed(WIFI_AP_MIN_HEAP_LARGEST));
        assert!(wifi_ap_start_allowed(WIFI_AP_MIN_HEAP_LARGEST + 1));
    }

    #[test]
    fn close_cancela_ap_want_nunca_start_pos_close() {
        // Janela aberta liga o want; close (shutdown_after_config) cancela:
        // mesmo sem BLE pareando, o poll nunca pede Start depois do close.
        let mut m = WifiApManager::new();
        m.update(true, false, 1000);
        assert!(m.is_active(1000));
        assert_eq!(
            super::ap_poll_action(m.is_active(1000), false, false),
            super::ApPollAction::Start
        );
        // Close do pareamento: radio mudo no close.
        m.shutdown_after_config();
        assert!(!m.is_active(2000));
        assert_ne!(
            super::ap_poll_action(m.is_active(2000), false, false),
            super::ApPollAction::Start
        );
        assert_eq!(
            super::ap_poll_action(m.is_active(2000), false, false),
            super::ApPollAction::None
        );
        // Com radio ligado, o close vira Stop uma vez, depois quieto.
        assert_eq!(
            super::ap_poll_action(m.is_active(2000), false, true),
            super::ApPollAction::Stop
        );
    }
}
