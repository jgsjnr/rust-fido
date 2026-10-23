//! T10 — fachada net-wifi (offline, vetores congelados).
//!
//! Cobre o que T10 finalizou: gates AP (só pareamento/menu, com timeout e
//! desligamento), station (só fora de pareamento com credenciais, com
//! timeout de volta ao fallback AP), mDNS (só fora de pareamento com
//! station up), AAD `rota/op/nonce` do `POST /ctap` (cross-rota, op
//! divergente, replay e nonce zero rejeitam), `NotCompiled` sem a feature
//! `wifi` e fallback AP (pareamento ou sem station => AP).
//!
//! Host-only: radio atrás de trait com doubles só neste arquivo (nunca em
//! produção), senha/SSID congelados. Sem hardware, sem flash, sem COM,
//! sem rede. Rollback: deletar este arquivo.

use aegis_fido_core::oath::OathAlgorithm;
use aegis_fido_firmware::mdns::{
    is_valid_mdns_hostname, mdns_bare_hostname, mdns_fallback_to_ap, mdns_hostname_for_serial,
    MdnsManager, MDNS_PREFIX, MDNS_SUFFIX,
};
use aegis_fido_firmware::persistence::{MockFlashBackend, SecureStorage};
use aegis_fido_firmware::wifi_ap::{
    ap_poll_action, ap_ssid_for_serial, change_ap_password, ctap_envelope_nonce,
    validate_ctap_envelope, validate_ctap_envelope_for_request, wifi_ap_coex_allowed,
    wifi_ap_start_allowed, ApPollAction, HttpConfig, HttpConfigService, WifiApError, WifiApManager,
    WifiNet, WifiNetError, WifiRadioBackend, CTAP_ENVELOPE_NONCE_LEN, CTAP_ENVELOPE_OP_OFFSET,
    CTAP_HTTP_ROUTE, WIFI_AP_MIN_HEAP_LARGEST, WIFI_AP_TIMEOUT_MS, WIFI_NEED_BINDING_CODE,
};
use aegis_fido_firmware::wifi_station::{
    clear_station_credentials, has_station_credentials, save_station_credentials, sta_retry_due,
    WifiStationError, WifiStationManager, WIFI_STA_RETRY_BACKOFF_MS,
};

// ---------------------------------------------------------------------------
// Test double do radio (só neste arquivo de teste; produção usa o C real)
// ---------------------------------------------------------------------------

/// Backend de teste: radio sempre-OK atrás do trait (`TestRadio` só existe
/// neste arquivo; produção usa o C `aegis_wifi` via `esp_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct TestRadio;

impl WifiRadioBackend for TestRadio {
    fn ap_start(_ssid: &str, _pass: &str) -> i32 {
        0
    }
    fn ap_stop() -> i32 {
        0
    }
    fn sta_start(_ssid: &str, _pass: &str) -> i32 {
        0
    }
    fn sta_stop() -> i32 {
        0
    }
    fn mdns_start(_host: &str) -> i32 {
        0
    }
    fn mdns_stop() -> i32 {
        0
    }
    fn wifi_off() -> i32 {
        0
    }
}

fn storage() -> SecureStorage<MockFlashBackend> {
    SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
}

/// Envelope `POST /ctap` congelado: magic AEGN + ver + nonce + op + ct + tag.
fn ctap_env(op: u8, nonce: [u8; 12]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x41, 0x45, 0x47, 0x4E, 0x01]);
    v.extend_from_slice(&nonce);
    v.push(op);
    v.extend_from_slice(&[0x55u8; 19]);
    v.extend_from_slice(&[0u8; 16]);
    v
}

const NONCE_A: [u8; 12] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
];

// ---------------------------------------------------------------------------
// Fachada: NotCompiled sem feature wifi, gates com feature
// ---------------------------------------------------------------------------

#[test]
fn wifinet_sem_feature_compila_fechado_not_compiled() {
    let mut n = WifiNet::<TestRadio>::new();
    if cfg!(feature = "wifi") {
        // Com radio compilado os gates valem (radio de teste retorna 0).
        assert_eq!(
            n.ap_start(false, false, 0, "AegisKey-00AF", None),
            Err(WifiNetError::ApNotAllowed)
        );
        n.ap_start(true, false, 1000, "AegisKey-00AF", Some("senha-segura-123"))
            .expect("ap em pareamento");
        assert!(n.ap().is_active(1000));
        n.ap_stop().expect("stop ok");
        assert_eq!(
            n.station_join(true, true, 2000, "Casa-5G", "senha-segura-123"),
            Err(WifiNetError::StationNotAllowed)
        );
        assert_eq!(
            n.station_join(false, false, 2000, "Casa-5G", "senha-segura-123"),
            Err(WifiNetError::StationNotAllowed)
        );
        n.station_join(false, true, 2000, "Casa-5G", "senha-segura-123")
            .expect("station ok");
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
    } else {
        // Sem a feature `wifi` nenhum radio é compilado: tudo é NotCompiled.
        assert_eq!(
            n.ap_start(true, false, 0, "AegisKey-00AF", None),
            Err(WifiNetError::NotCompiled)
        );
        assert_eq!(n.ap_stop(), Err(WifiNetError::NotCompiled));
        assert_eq!(
            n.station_join(false, true, 0, "Casa-5G", "senha-segura-123"),
            Err(WifiNetError::NotCompiled)
        );
        assert_eq!(
            n.mdns_announce(false, true, "aegiskey-00af"),
            Err(WifiNetError::NotCompiled)
        );
        assert_eq!(n.off(), Err(WifiNetError::NotCompiled));
        assert_eq!(WifiNetError::NotCompiled.to_string(), "wifi not compiled");
    }
}

#[test]
fn wifinet_erro_fechado_e_display() {
    assert_eq!(
        WifiNetError::ApNotAllowed.to_string(),
        "ap allowed only in pairing/menu"
    );
    assert_eq!(
        WifiNetError::StationNotAllowed.to_string(),
        "station outside pairing with creds"
    );
    assert_eq!(
        WifiNetError::MdnsNotAllowed.to_string(),
        "mdns outside pairing with station up"
    );
    assert_eq!(WifiNetError::Radio(-4).to_string(), "wifi radio error (-4)");
    assert_eq!(
        WifiApError::NeedBinding.to_string(),
        "binding required (NEED_BINDING)"
    );
    assert_eq!(
        WifiStationError::NeedBinding.to_string(),
        "binding required (NEED_BINDING)"
    );
    assert_eq!(WIFI_NEED_BINDING_CODE, "NEED_BINDING");
}

// ---------------------------------------------------------------------------
// AP: só pareamento/menu, timeout, poll sem spam, coex, SSID, heap guard
// ---------------------------------------------------------------------------

#[test]
fn ap_so_pareamento_ou_menu_com_timeout_e_shutdown() {
    let mut m = WifiApManager::new();
    assert!(!m.is_active(0));
    m.update(false, false, 0);
    assert!(!m.is_active(0));
    m.update(true, false, 1000);
    assert!(m.is_active(1000));
    m.update(false, false, 1000 + WIFI_AP_TIMEOUT_MS);
    assert!(!m.is_active(1000 + WIFI_AP_TIMEOUT_MS));
    m.update(false, true, 90_000);
    assert!(m.is_active(90_000));
    m.shutdown_after_config();
    assert!(!m.is_active(90_000));
}

#[test]
fn ap_poll_action_sem_spam_de_stop() {
    assert_eq!(ap_poll_action(false, false, false), ApPollAction::None);
    assert_eq!(ap_poll_action(true, false, false), ApPollAction::Start);
    assert_eq!(ap_poll_action(true, false, true), ApPollAction::None);
    // BLE assumiu com radio off: nenhum stop (era o spam a cada poll).
    assert_eq!(ap_poll_action(true, true, false), ApPollAction::None);
    // BLE assumiu com radio on: desliga uma vez.
    assert_eq!(ap_poll_action(true, true, true), ApPollAction::Stop);
    // Janela fechou com radio on: desliga uma vez.
    assert_eq!(ap_poll_action(false, false, true), ApPollAction::Stop);
}

#[test]
fn ap_coex_ssid_heap_guard() {
    assert!(!wifi_ap_coex_allowed(true));
    assert!(wifi_ap_coex_allowed(false));
    assert_eq!(ap_ssid_for_serial("AEGIS-S3-00AF"), "AegisKey-00AF");
    assert_eq!(ap_ssid_for_serial("x"), "AegisKey-0001");
    assert_eq!(WIFI_AP_MIN_HEAP_LARGEST, 32 * 1024);
    assert!(!wifi_ap_start_allowed(0));
    assert!(!wifi_ap_start_allowed(WIFI_AP_MIN_HEAP_LARGEST - 1));
    assert!(wifi_ap_start_allowed(WIFI_AP_MIN_HEAP_LARGEST));
}

#[test]
fn ap_senha_troca_exige_up_pin_e_bounds() {
    let mut st = storage();
    assert_eq!(
        change_ap_password(&mut st, "nova-senha-123", false, true),
        Err(WifiApError::Unauthorized)
    );
    assert_eq!(
        change_ap_password(&mut st, "nova-senha-123", true, false),
        Err(WifiApError::Unauthorized)
    );
    assert_eq!(
        change_ap_password(&mut st, "curta", true, true),
        Err(WifiApError::InvalidPassword)
    );
    change_ap_password(&mut st, "nova-senha-123", true, true).expect("troca ok");
    assert_eq!(st.load("wifi_ap_pass").expect("load"), b"nova-senha-123");
}

// ---------------------------------------------------------------------------
// Station: só fora de pareamento com credenciais, timeout => fallback AP
// ---------------------------------------------------------------------------

#[test]
fn station_so_fora_de_pareamento_com_credenciais() {
    let mut m = WifiStationManager::new();
    assert!(!m.is_up());
    m.update(false, false, 0);
    assert!(!m.is_up());
    m.update(true, true, 0);
    assert!(!m.is_up());
    m.update(false, true, 1000);
    assert!(!m.is_up()); // connecting, ainda sem IP
    m.on_connected();
    assert!(m.is_up());
    m.update(true, true, 2000); // pareamento derruba a station
    assert!(!m.is_up());
}

#[test]
fn station_credenciais_exigem_up_pin_e_bounds() {
    let mut st = storage();
    assert_eq!(
        save_station_credentials(&mut st, "Casa-5G", "senha-segura-123", false, true),
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
    save_station_credentials(&mut st, "Casa-5G", "senha-segura-123", true, true).expect("save ok");
    assert!(has_station_credentials(&st));
    assert_eq!(st.load("wifi_sta_ssid").expect("ssid"), b"Casa-5G");
    assert_eq!(
        clear_station_credentials(&mut st, false, true),
        Err(WifiStationError::Unauthorized)
    );
    assert!(has_station_credentials(&st));
    clear_station_credentials(&mut st, true, true).expect("clear ok");
    assert!(!has_station_credentials(&st));
}

#[test]
fn station_timeout_e_backoff_voltam_ao_fallback_ap() {
    let mut m = WifiStationManager::new();
    m.update(false, true, 0);
    m.update(false, true, 15_000); // WIFI_STA_CONNECT_TIMEOUT_MS
    assert!(!m.is_up());
    m.on_failed();
    assert!(!m.is_up());
    m.disconnect();
    assert!(!m.is_up());
    // Backoff poupa bateria: 1ª tentativa sempre, depois só após 60s.
    assert!(sta_retry_due(0, None));
    assert!(!sta_retry_due(1_000, Some(0)));
    assert!(!sta_retry_due(WIFI_STA_RETRY_BACKOFF_MS - 1, Some(0)));
    assert!(sta_retry_due(WIFI_STA_RETRY_BACKOFF_MS, Some(0)));
    assert!(!sta_retry_due(0, Some(10_000))); // skew de relógio não tenta em loop
}

// ---------------------------------------------------------------------------
// mDNS: só fora de pareamento com station up; senão fallback AP
// ---------------------------------------------------------------------------

#[test]
fn mdns_so_fora_de_pareamento_com_station_up() {
    let mut m = MdnsManager::new();
    assert!(!m.is_active());
    m.update(false, false);
    assert!(!m.is_active());
    m.update(true, true);
    assert!(!m.is_active());
    m.update(false, true);
    assert!(m.is_active());
    m.update(true, true);
    assert!(!m.is_active());
    m.update(false, true);
    assert!(m.is_active());
    m.shutdown();
    assert!(!m.is_active());
}

#[test]
fn mdns_hostname_e_fallback_ap() {
    assert_eq!(
        mdns_hostname_for_serial("AEGIS-S3-00AF"),
        "aegiskey-00af.local"
    );
    assert_eq!(mdns_hostname_for_serial("x"), "aegiskey-0001.local");
    assert!(is_valid_mdns_hostname("aegiskey-00af.local"));
    assert!(!is_valid_mdns_hostname("AegisKey-00AF.local"));
    assert!(!is_valid_mdns_hostname("outro-00af.lan"));
    assert_eq!(mdns_bare_hostname("aegiskey-00af.local"), "aegiskey-00af");
    assert_eq!(MDNS_PREFIX, "aegiskey-");
    assert_eq!(MDNS_SUFFIX, ".local");
    // Fallback AP: pareamento ou sem station => AP; senão mDNS.
    assert!(mdns_fallback_to_ap(true, true));
    assert!(mdns_fallback_to_ap(true, false));
    assert!(mdns_fallback_to_ap(false, false));
    assert!(!mdns_fallback_to_ap(false, true));
}

#[test]
fn fallback_ap_assume_quando_station_cai_ou_pareamento_abre() {
    // Station caiu: mDNS apaga, fallback AP liga na janela de pareamento.
    let mut mdns = MdnsManager::new();
    mdns.update(false, true);
    assert!(mdns.is_active());
    mdns.update(false, false);
    assert!(!mdns.is_active());
    assert!(mdns_fallback_to_ap(false, false));
    let mut ap = WifiApManager::new();
    ap.update(true, false, 1000);
    assert!(ap.is_active(1000));
    assert_eq!(
        ap_poll_action(ap.is_active(1000), false, false),
        ApPollAction::Start
    );
    // Pareamento aberto derruba station e mDNS de uma vez.
    let mut sta = WifiStationManager::new();
    sta.update(false, true, 0);
    sta.on_connected();
    assert!(sta.is_up());
    sta.update(true, true, 2000);
    assert!(!sta.is_up());
    assert!(mdns_fallback_to_ap(true, false));
}

// ---------------------------------------------------------------------------
// AAD rota/op/nonce do POST /ctap
// ---------------------------------------------------------------------------

#[test]
fn aad_rota_op_nonce_vinculados() {
    assert_eq!(CTAP_HTTP_ROUTE, "/ctap");
    assert_eq!(CTAP_ENVELOPE_NONCE_LEN, 12);
    assert_eq!(CTAP_ENVELOPE_OP_OFFSET, 4 + 1 + CTAP_ENVELOPE_NONCE_LEN);
    let env = ctap_env(0x09, NONCE_A);
    // Rota/op/nonce corretos: ok, nonce extraível.
    assert!(validate_ctap_envelope_for_request(&env, "/ctap", 0x09, None).is_ok());
    assert_eq!(ctap_envelope_nonce(&env).expect("nonce"), NONCE_A);
    assert!(validate_ctap_envelope(&env).is_ok());
    // Cross-rota rejeita; op divergente rejeita; replay rejeita; zero rejeita.
    assert_eq!(
        validate_ctap_envelope_for_request(&env, "/config/wifi", 0x09, None),
        Err(WifiApError::InvalidEnvelope)
    );
    assert_eq!(
        validate_ctap_envelope_for_request(&env, "/ctap", 0x0A, None),
        Err(WifiApError::InvalidEnvelope)
    );
    assert_eq!(
        validate_ctap_envelope_for_request(&env, "/ctap", 0x09, Some(NONCE_A)),
        Err(WifiApError::InvalidEnvelope)
    );
    assert_eq!(
        validate_ctap_envelope_for_request(&ctap_env(0x09, [0u8; 12]), "/ctap", 0x09, None),
        Err(WifiApError::InvalidEnvelope)
    );
    // Envelope quebrado: curto, magic ruim, tag ausente.
    assert_eq!(
        validate_ctap_envelope(b"lixo"),
        Err(WifiApError::InvalidEnvelope)
    );
    let mut bad = env.clone();
    bad[0] ^= 0xFF;
    assert_eq!(
        validate_ctap_envelope_for_request(&bad, "/ctap", 0x09, None),
        Err(WifiApError::InvalidEnvelope)
    );
}

// ---------------------------------------------------------------------------
// HttpConfigService: POST /ctap, POST /config/wifi, GET /oath/code
// ---------------------------------------------------------------------------

#[test]
fn http_config_preserva_aad_com_anti_replay_local() {
    let mut h = HttpConfig::new();
    assert_eq!(h.last_nonce(), None);
    let env = ctap_env(0x09, NONCE_A);
    h.post_ctap(&env, "/ctap", 0x09, None).expect("ctap ok");
    assert_eq!(h.last_nonce(), Some(NONCE_A));
    // O nonce local vale como prev: repetir o envelope é replay.
    assert_eq!(
        h.post_ctap(&env, "/ctap", 0x09, None),
        Err(WifiApError::InvalidEnvelope)
    );
    assert_eq!(
        h.post_ctap(&env, "/config/wifi", 0x09, None),
        Err(WifiApError::InvalidEnvelope)
    );
    assert_eq!(
        h.post_ctap(&env, "/ctap", 0x0A, None),
        Err(WifiApError::InvalidEnvelope)
    );
    // Novo nonce avança; prev explícito divergente também avança.
    let other = [0x02u8; 12];
    h.post_ctap(&ctap_env(0x09, other), "/ctap", 0x09, Some(NONCE_A))
        .expect("novo nonce ok");
    assert_eq!(h.last_nonce(), Some(other));
}

#[test]
fn http_config_wifi_e_oath_atras_do_trait() {
    let mut h = HttpConfig::new();
    let mut st = storage();
    // POST /config/wifi sem auth rejeita sem tocar na NVS (gates preservados).
    assert_eq!(
        h.post_config_wifi(&mut st, "nova-senha-123", false, false, false),
        Err(WifiApError::NeedBinding)
    );
    assert_eq!(
        h.post_config_wifi(&mut st, "nova-senha-123", true, false, false),
        Err(WifiApError::Unauthorized)
    );
    assert!(!st.exists("wifi_ap_pass"));
    // GET /oath/code: só USO (sem vínculo), só UP, só código, vetor RFC 6238.
    let secret = b"12345678901234567890";
    let secrets: &[(&str, &[u8], OathAlgorithm, u8)] =
        &[("GitHub:alice", secret, OathAlgorithm::Sha1, 6)];
    assert_eq!(
        h.get_oath_code("GitHub:alice", secrets, 59, false),
        Err(WifiApError::Unauthorized)
    );
    assert_eq!(
        h.get_oath_code("desconhecida", secrets, 59, true),
        Err(WifiApError::UnknownAccount)
    );
    let r = h
        .get_oath_code("GitHub:alice", secrets, 59, true)
        .expect("totp");
    assert_eq!(r.code, "287082");
    assert_eq!(r.account, "GitHub:alice");
    assert!(!r.code.as_bytes().windows(secret.len()).any(|w| w == secret));
}

#[test]
fn radio_teste_nao_vaza_para_producao() {
    // O double vive só aqui: o backend real continua atrás dos `esp_*`
    // (shims inertes no host, C `aegis_wifi` no device).
    assert_eq!(
        aegis_fido_firmware::wifi_station::esp_sta_start("s", "p"),
        0
    );
    assert_eq!(aegis_fido_firmware::wifi_station::esp_sta_stop(), 0);
    assert_eq!(
        aegis_fido_firmware::mdns::esp_mdns_start("aegiskey-00af"),
        0
    );
    assert_eq!(aegis_fido_firmware::mdns::esp_mdns_stop(), 0);
    assert_eq!(TestRadio::ap_start("AegisKey-00AF", "pw"), 0);
    assert_eq!(TestRadio::sta_start("Casa-5G", "pw"), 0);
    assert_eq!(TestRadio::mdns_start("aegiskey-00af"), 0);
    // Fachada nasce com tudo desligado (estado inicial observável).
    let n = WifiNet::<TestRadio>::new();
    assert!(!n.ap().is_active(0));
    assert!(!n.sta().is_up());
    assert!(!n.mdns().is_active());
}
