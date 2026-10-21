//! Wave4 — WiFi AP `AegisKey-XXXX` (Etapa B: radio real via `aegis_wifi`).
//!
//! - SSID deriva do serial (`AegisKey-` + sufixo de 4).
//! - Senha default provisionada; TROCA so via app autenticado (UP+PIN),
//!   gravada em NVS cifrada (`SecureStorage`, mesma envelope AES-GCM).
//! - AP so liga em pareamento ou por menu; desliga apos config/timeout.
//! - HTTP minimo: `POST /ctap`, `POST /config/wifi`, `GET /oath/code?account=`.
//! - TOTP GERADO NO DEVICE: so o codigo 6-8 digitos sai, nunca o secret.
//! - Keys nunca saem do device.

extern crate alloc;

use alloc::string::String;
use alloc::format;
use aegis_fido_core::oath::{calculate_code, OathAlgorithm};
use aegis_fido_core::policy::{PolicyError, UpAndPin, UpPolicy};
use crate::persistence::{FlashStorageBackend, SecureStorage};
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};

/// Prefixo do AP.
pub const WIFI_AP_PREFIX: &str = "AegisKey-";
/// Chave NVS da senha do AP (envelope AES-GCM).
pub const WIFI_PASS_NVS_KEY: &str = "wifi_ap_pass";
/// Tamanho minimo da senha do AP.
pub const MIN_WIFI_PASS_LEN: usize = 8;
/// Tamanho maximo da senha do AP.
pub const MAX_WIFI_PASS_LEN: usize = 63;
/// Timeout do AP em ms (mesma janela de pareamento, 60s).
pub const WIFI_AP_TIMEOUT_MS: u64 = 60_000;

/// Erro tipado do AP/HTTP (sem panics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiApError {
    /// Sem autenticacao (UP+PIN exigidos).
    Unauthorized,
    /// Senha fora dos bounds.
    InvalidPassword,
    /// Envelope CTAP invalido.
    InvalidEnvelope,
    /// Conta OATH desconhecida.
    UnknownAccount,
    /// AP desligado.
    ApOff,
    /// Binding ausente/invalido (so o app vinculado gerencia o AP).
    NeedBinding,
}

impl core::fmt::Display for WifiApError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "unauthorized (UP+PIN required)"),
            Self::InvalidPassword => write!(f, "invalid wifi password"),
            Self::InvalidEnvelope => write!(f, "invalid ctap envelope"),
            Self::UnknownAccount => write!(f, "unknown oath account"),
            Self::ApOff => write!(f, "ap off"),
            Self::NeedBinding => write!(f, "binding required (NEED_BINDING)"),
        }
    }
}

impl From<PolicyError> for WifiApError {
    fn from(e: PolicyError) -> Self {
        match e {
            PolicyError::PresenceRequired | PolicyError::PinRequired => Self::Unauthorized,
        }
    }
}

/// Estado do AP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiApState {
    /// Desligado (default).
    Off,
    /// Ativo com expiracao.
    Active {
        /// Expiracao em ms monotonicos.
        expires_ms: u64,
    },
}

/// Deriva SSID `AegisKey-XXXX` do serial (ultimos 4 alfanumericos).
pub fn ap_ssid_for_serial(serial: &str) -> String {
    let tail: String = serial
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    let suffix = if tail.len() == 4 { tail } else { String::from("0001") };
    format!("{}{}", WIFI_AP_PREFIX, suffix)
}

/// Valida senha do AP (bounds WPA2).
pub fn is_valid_wifi_password(pass: &str) -> bool {
    let len = pass.len();
    (MIN_WIFI_PASS_LEN..=MAX_WIFI_PASS_LEN).contains(&len)
        && pass.is_ascii()
}

/// Gerente do AP (sem I/O; ESP liga o radio via `esp_ap_start`, componente C `aegis_wifi`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiApManager {
    state: WifiApState,
}

impl WifiApManager {
    /// Cria desligado.
    pub fn new() -> Self {
        Self {
            state: WifiApState::Off,
        }
    }

    /// Estado atual.
    pub fn state(&self) -> WifiApState {
        self.state
    }

    /// `true` quando o radio deve estar ligado.
    pub fn is_active(&self, now_ms: u64) -> bool {
        match self.state {
            WifiApState::Off => false,
            WifiApState::Active { expires_ms } => now_ms < expires_ms,
        }
    }

    /// Liga o AP somente em pareamento ou por menu; desliga apos timeout.
    /// `pairing_open`: janela 60s aberta; `menu_request`: item de menu.
    pub fn update(&mut self, pairing_open: bool, menu_request: bool, now_ms: u64) {
        if (pairing_open || menu_request) && !self.is_active(now_ms) {
            self.state = WifiApState::Active {
                expires_ms: now_ms.saturating_add(WIFI_AP_TIMEOUT_MS),
            };
            crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "wifi");
        }
        if let WifiApState::Active { expires_ms } = self.state {
            if now_ms >= expires_ms {
                self.state = WifiApState::Off;
                crate::ltrace!(LtCat::Transport, LtEvt::TpClose, "wifi");
            }
        }
    }

    /// Desliga apos configuracao concluida.
    pub fn shutdown_after_config(&mut self) {
        if self.state != WifiApState::Off {
            crate::ltrace!(LtCat::Transport, LtEvt::TpClose, "wifi");
        }
        self.state = WifiApState::Off;
    }
}

/// Acao do AP decidida uma vez por poll (chamador aplica e atualiza o cache).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApPollAction {
    /// Nada a fazer (inclui: BLE assumiu e AP ja estava off).
    None,
    /// Ligar o AP (janela/menu, sem BLE pareando, radio off).
    Start,
    /// Desligar UMA vez (janela fechou ou BLE assumiu com radio on).
    Stop,
}

/// Decisao pura do poll do AP: edge-triggered, sem spam de stop.
///
/// `ap_want` vem de `WifiApManager::is_active`; `ble_pairing_now` de
/// `should_advertise` (BLE e WiFi sao mutuamente exclusivos no S3);
/// `ap_active_cache` e o estado que o chamador acha que o radio tem.
pub fn ap_poll_action(
    ap_want: bool,
    ble_pairing_now: bool,
    ap_active_cache: bool,
) -> ApPollAction {
    if ap_want && !ble_pairing_now {
        if ap_active_cache {
            ApPollAction::None
        } else {
            ApPollAction::Start
        }
    } else if ap_active_cache {
        ApPollAction::Stop
    } else {
        ApPollAction::None
    }
}

impl Default for WifiApManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Troca a senha do AP: exige UP+PIN, grava em NVS cifrada.
/// Rejeita sem auth (`Unauthorized`) sem tocar na NVS.
pub fn change_ap_password<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    new_password: &str,
    pin_authenticated: bool,
    presence_confirmed: bool,
) -> Result<(), WifiApError> {
    UpAndPin.check_up(pin_authenticated, presence_confirmed)?;
    if !is_valid_wifi_password(new_password) {
        return Err(WifiApError::InvalidPassword);
    }
    let nonce = [0u8; 12];
    storage
        .store(WIFI_PASS_NVS_KEY, new_password.as_bytes(), &nonce)
        .map_err(|_| WifiApError::InvalidPassword)?;
    Ok(())
}

/// Valida envelope `POST /ctap` (mesmo `SecureStorage`: magic AEGN+versao).
/// Retorna tamanho do ciphertext quando valido (delega conteudo ao CtapService).
pub fn validate_ctap_envelope(envelope: &[u8]) -> Result<usize, WifiApError> {
    if envelope.len() < 4 + 1 + 12 + 16 {
        return Err(WifiApError::InvalidEnvelope);
    }
    if envelope[0..4] != [0x41, 0x45, 0x47, 0x4E] || envelope[4] != 0x01 {
        return Err(WifiApError::InvalidEnvelope);
    }
    Ok(envelope.len() - (4 + 1 + 12))
}

/// Extrai `account` de `GET /oath/code?account=<nome>`.
pub fn parse_oath_account_query(path: &str) -> Option<&str> {
    let q = path.split('?').nth(1)?;
    for pair in q.split('&') {
        if let Some(v) = pair.strip_prefix("account=") {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Resposta TOTP: so codigo, nunca secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpResponse {
    /// Nome da conta (eco).
    pub account: String,
    /// Codigo 6-8 digitos (zero-padded).
    pub code: String,
    /// Segundos restantes na janela de 30s.
    pub remaining_seconds: u32,
}

/// Gera codigo TOTP no device a partir do secret (secret nunca sai).
/// `unix_seconds`: relogio do device; janela 30s (T = t/30).
pub fn totp_code_for_secret(
    account: &str,
    secret: &[u8],
    algo: OathAlgorithm,
    digits: u8,
    unix_seconds: u64,
) -> TotpResponse {
    let digits_c = digits.clamp(6, 8);
    let counter = unix_seconds / 30;
    let code = calculate_code(algo, secret, counter, digits_c);
    let width = digits_c as usize;
    let mut s = format!("{:0>width$}", code, width = width);
    // Garante largura exata mesmo se modulo estourar (trunca a esquerda).
    if s.len() > width {
        s = s[s.len() - width..].to_string();
    }
    let remaining = 30 - (unix_seconds % 30) as u32;
    TotpResponse {
        account: String::from(account),
        code: s,
        remaining_seconds: remaining,
    }
}

/// Rota `GET /oath/code`: busca secret no mapa injetado (testes/host),
/// gera no device e retorna so o codigo. Secret nunca serializado.
pub fn handle_get_oath_code(
    account: &str,
    secrets: &[(&str, &[u8], OathAlgorithm, u8)],
    unix_seconds: u64,
    presence_confirmed: bool,
) -> Result<TotpResponse, WifiApError> {
    if !presence_confirmed {
        return Err(WifiApError::Unauthorized);
    }
    for (name, secret, algo, digits) in secrets {
        if *name == account {
            return Ok(totp_code_for_secret(account, secret, *algo, *digits, unix_seconds));
        }
    }
    Err(WifiApError::UnknownAccount)
}

// ---------------------------------------------------------------------------
// Radio real: FFI manual com o componente C `aegis_wifi`
// (mesmo padrao do `ble_nimble.rs` com `aegis_ble`; sem bindgen, sem novos
// deps, sem features do esp-idf-svc além de `binstart`).
// ---------------------------------------------------------------------------

#[cfg(target_os = "espidf")]
extern "C" {
    fn aegis_wifi_ap_start(ssid: *const u8, ssid_len: i32, pass: *const u8, pass_len: i32) -> i32;
    fn aegis_wifi_ap_stop() -> i32;
    fn aegis_wifi_off() -> i32;
}

/// Liga o AP real (`0` ok, negativo = erro do C).
/// `pass` vazia = rede aberta (bootstrap na janela curta de pareamento).
#[cfg(target_os = "espidf")]
pub fn esp_ap_start(ssid: &str, pass: &str) -> i32 {
    crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "wifi-ap");
    unsafe {
        aegis_wifi_ap_start(
            ssid.as_ptr(),
            ssid.len().min(i32::MAX as usize) as i32,
            pass.as_ptr(),
            pass.len().min(i32::MAX as usize) as i32,
        )
    }
}

/// Desliga o AP (rebaixa p/ station ou desliga o radio; `0` ok).
#[cfg(target_os = "espidf")]
pub fn esp_ap_stop() -> i32 {
    crate::ltrace!(LtCat::Transport, LtEvt::TpClose, "wifi-ap");
    unsafe { aegis_wifi_ap_stop() }
}

/// Power-down total do radio (bateria): chamar com AP off + station off.
/// Idempotente; `0` ok.
#[cfg(target_os = "espidf")]
pub fn esp_wifi_off() -> i32 {
    unsafe { aegis_wifi_off() }
}

// Shims inertes no host (sem radio; politica testada por unidade).
#[cfg(not(target_os = "espidf"))]
pub fn esp_ap_start(_ssid: &str, _pass: &str) -> i32 {
    0
}
#[cfg(not(target_os = "espidf"))]
pub fn esp_ap_stop() -> i32 {
    0
}
#[cfg(not(target_os = "espidf"))]
pub fn esp_wifi_off() -> i32 {
    0
}

/// Senha efetiva do AP a partir dos bytes da NVS (`WIFI_PASS_NVS_KEY`).
/// `None`/bytes invalidos => rede aberta (bootstrap na janela curta).
/// Nunca loga o conteudo: o chamador so repassa ao radio.
pub fn resolve_ap_password(stored: Option<&[u8]>) -> Option<String> {
    let bytes = stored?;
    if bytes.is_empty() {
        return None;
    }
    let pass = core::str::from_utf8(bytes).ok()?;
    if !is_valid_wifi_password(pass) {
        return None;
    }
    Some(String::from(pass))
}


// Gates de binding para o HTTP mgmt (`binding.rs`).
//
// - `POST /config/wifi` (troca de senha): binding + UP + PIN.
// - `GET /oath/code`: binding + UP (secret nunca sai, como antes).
// - Ordem canonica: binding -> UP -> PIN. HTTP responde `403 NEED_BINDING`
//   quando `NeedBinding`; USB/CTAP zero mudanca.

/// Codigo HTTP-body para binding ausente (app alheio ve este codigo).
pub const WIFI_NEED_BINDING_CODE: &str = "NEED_BINDING";

/// Barreira de binding para rotas mgmt CONFIG (`POST /config/wifi`).
/// `binding_ok`: `BindingManager::verify` passou (uso unico).
/// Release exige vinculo; teste faz bypass com ltrace (so UP+PIN).
pub fn require_bound_session(binding_ok: bool) -> Result<(), WifiApError> {
    if binding_ok {
        return Ok(());
    }
    if crate::binding::binding_bypass_enabled() {
        crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "binding-bypass");
        return Ok(());
    }
    Err(WifiApError::NeedBinding)
}

/// Troca a senha do AP com binding: binding + UP + PIN, grava em NVS cifrada.
/// Rejeita sem binding sem tocar na NVS (funcao sem binding preservada).
pub fn change_ap_password_bound<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    new_password: &str,
    binding_ok: bool,
    pin_authenticated: bool,
    presence_confirmed: bool,
) -> Result<(), WifiApError> {
    require_bound_session(binding_ok)?;
    change_ap_password(storage, new_password, pin_authenticated, presence_confirmed)
}

/// Rota `GET /oath/code` (USO): nunca exige vinculo, so UP; so o codigo sai.
///
/// Split uso/config (§11): CODE/LIST e USO (senao keypass nao funciona).
/// `binding_ok` ignorado de proposito (assinatura preservada para compat).
pub fn handle_get_oath_code_bound(
    account: &str,
    secrets: &[(&str, &[u8], OathAlgorithm, u8)],
    unix_seconds: u64,
    _binding_ok: bool,
    presence_confirmed: bool,
) -> Result<TotpResponse, WifiApError> {
    let _ = crate::binding::require_bound_usage(_binding_ok);
    handle_get_oath_code(account, secrets, unix_seconds, presence_confirmed)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use super::*;
    use crate::persistence::MockFlashBackend;

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
        assert_eq!(validate_ctap_envelope(b"lixo"), Err(WifiApError::InvalidEnvelope));
        let mut bad = env.clone();
        bad[0] ^= 0xFF;
        assert_eq!(validate_ctap_envelope(&bad), Err(WifiApError::InvalidEnvelope));
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
}


