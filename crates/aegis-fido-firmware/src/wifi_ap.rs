//! Wave4 — WiFi AP `AegisKey-XXXX` (feature `wifi`, host stub).
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
}

impl core::fmt::Display for WifiApError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "unauthorized (UP+PIN required)"),
            Self::InvalidPassword => write!(f, "invalid wifi password"),
            Self::InvalidEnvelope => write!(f, "invalid ctap envelope"),
            Self::UnknownAccount => write!(f, "unknown oath account"),
            Self::ApOff => write!(f, "ap off"),
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

/// Gerente do AP (sem I/O; ESP liga o radio via `start_ap_esp`).
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

/// Stub ESP: liga o radio (quando `target_os = espidf` usa esp-idf-svc).
pub fn start_ap_esp(_ssid: &str) -> Result<(), &'static str> {
    Ok(())
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
    fn query_parsing() {
        assert_eq!(
            parse_oath_account_query("/oath/code?account=GitHub"),
            Some("GitHub")
        );
        assert_eq!(parse_oath_account_query("/oath/code"), None);
        assert_eq!(parse_oath_account_query("/oath/code?account="), None);
    }
}


