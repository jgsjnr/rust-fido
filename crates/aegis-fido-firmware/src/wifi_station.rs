//! Phase8 - WiFi station (conecta no roteador, host stub + ESP station).
//!
//! - Credenciais em NVS cifrada (`SecureStorage`, envelope AES-GCM AEGN v1).
//! - Chaves NVS `wifi_sta_ssid` + `wifi_sta_pass` (par, nunca em claro no log).
//! - Save/limpeza exigem UP+PIN (`UpAndPin`); sem auth a NVS fica intacta.
//! - Station SO fora de pareamento; durante pareamento usa fallback AP.
//! - Nucleo sem I/O; ESP liga o radio via `start_station_esp`.

use aegis_fido_core::policy::{PolicyError, UpAndPin, UpPolicy};
use crate::persistence::{FlashStorageBackend, SecureStorage};
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};

/// Chave NVS do SSID da station (envelope AES-GCM).
pub const WIFI_STA_SSID_NVS_KEY: &str = "wifi_sta_ssid";
/// Chave NVS da senha da station (envelope AES-GCM).
pub const WIFI_STA_PASS_NVS_KEY: &str = "wifi_sta_pass";
/// Tamanho minimo do SSID.
pub const MIN_STA_SSID_LEN: usize = 1;
/// Tamanho maximo do SSID.
pub const MAX_STA_SSID_LEN: usize = 32;
/// Tamanho minimo da senha (WPA2).
pub const MIN_STA_PASS_LEN: usize = 8;
/// Tamanho maximo da senha (WPA2).
pub const MAX_STA_PASS_LEN: usize = 63;
/// Timeout de conexao em ms (15s).
pub const WIFI_STA_CONNECT_TIMEOUT_MS: u64 = 15_000;

/// Erro tipado da station (sem panics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiStationError {
    /// Sem autenticacao (UP+PIN exigidos).
    Unauthorized,
    /// SSID fora dos bounds.
    InvalidSsid,
    /// Senha fora dos bounds.
    InvalidPassword,
    /// Sem credenciais provisionadas.
    NotProvisioned,
    /// Binding ausente/invalido (so o app vinculado gerencia creds).
    NeedBinding,
}

impl core::fmt::Display for WifiStationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "unauthorized (UP+PIN required)"),
            Self::InvalidSsid => write!(f, "invalid station ssid"),
            Self::InvalidPassword => write!(f, "invalid station password"),
            Self::NotProvisioned => write!(f, "station not provisioned"),
            Self::NeedBinding => write!(f, "binding required (NEED_BINDING)"),
        }
    }
}

impl From<PolicyError> for WifiStationError {
    fn from(e: PolicyError) -> Self {
        match e {
            PolicyError::PresenceRequired | PolicyError::PinRequired => Self::Unauthorized,
        }
    }
}

/// Valida SSID (1..32 ascii).
pub fn is_valid_sta_ssid(ssid: &str) -> bool {
    let len = ssid.len();
    (MIN_STA_SSID_LEN..=MAX_STA_SSID_LEN).contains(&len) && ssid.is_ascii()
}

/// Valida senha WPA2 (8..63 ascii).
pub fn is_valid_sta_password(pass: &str) -> bool {
    let len = pass.len();
    (MIN_STA_PASS_LEN..=MAX_STA_PASS_LEN).contains(&len) && pass.is_ascii()
}

/// Salva credenciais da station: exige UP+PIN, grava par SSID+senha.
/// Rejeita sem auth sem tocar na NVS; valida bounds antes de gravar.
pub fn save_station_credentials<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    ssid: &str,
    password: &str,
    pin_authenticated: bool,
    presence_confirmed: bool,
) -> Result<(), WifiStationError> {
    UpAndPin.check_up(pin_authenticated, presence_confirmed)?;
    if !is_valid_sta_ssid(ssid) {
        return Err(WifiStationError::InvalidSsid);
    }
    if !is_valid_sta_password(password) {
        return Err(WifiStationError::InvalidPassword);
    }
    let nonce = [0u8; 12];
    storage
        .store(WIFI_STA_SSID_NVS_KEY, ssid.as_bytes(), &nonce)
        .map_err(|_| WifiStationError::InvalidSsid)?;
    storage
        .store(WIFI_STA_PASS_NVS_KEY, password.as_bytes(), &nonce)
        .map_err(|_| WifiStationError::InvalidPassword)?;
    Ok(())
}

/// `true` quando o par SSID+senha existe na NVS.
pub fn has_station_credentials<B: FlashStorageBackend>(storage: &SecureStorage<B>) -> bool {
    storage.exists(WIFI_STA_SSID_NVS_KEY) && storage.exists(WIFI_STA_PASS_NVS_KEY)
}

/// Apaga o par SSID+senha: exige UP+PIN.
pub fn clear_station_credentials<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    pin_authenticated: bool,
    presence_confirmed: bool,
) -> Result<(), WifiStationError> {
    UpAndPin.check_up(pin_authenticated, presence_confirmed)?;
    let _ = storage.delete(WIFI_STA_SSID_NVS_KEY);
    let _ = storage.delete(WIFI_STA_PASS_NVS_KEY);
    Ok(())
}

/// Estado da station.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiStationState {
    /// Desligada (default, ou durante pareamento).
    Off,
    /// Conectando com expiracao.
    Connecting {
        /// Expiracao em ms monotonicos.
        expires_ms: u64,
    },
    /// Conectada (station up, mDNS pode ligar).
    Connected,
}

/// Gerente da station (sem I/O; ESP liga via `start_station_esp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WifiStationManager {
    state: WifiStationState,
}

impl WifiStationManager {
    /// Cria desligada.
    pub fn new() -> Self {
        Self { state: WifiStationState::Off }
    }

    /// Estado atual.
    pub fn state(&self) -> WifiStationState {
        self.state
    }

    /// `true` quando conectada.
    pub fn is_up(&self) -> bool {
        self.state == WifiStationState::Connected
    }

    /// Tenta conectar SO fora de pareamento e com credenciais.
    pub fn update(&mut self, pairing_open: bool, has_credentials: bool, now_ms: u64) {
        if !pairing_open && has_credentials && self.state == WifiStationState::Off {
            self.state = WifiStationState::Connecting {
                expires_ms: now_ms.saturating_add(WIFI_STA_CONNECT_TIMEOUT_MS),
            };
            crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "station");
        }
        if pairing_open && self.state != WifiStationState::Off {
            self.state = WifiStationState::Off;
            crate::ltrace!(LtCat::Transport, LtEvt::TpClose, "station");
        }
        if let WifiStationState::Connecting { expires_ms } = self.state {
            if now_ms >= expires_ms {
                self.state = WifiStationState::Off;
                crate::ltrace!(LtCat::Transport, LtEvt::TpError, "station");
            }
        }
    }

    /// Marca conectada (radio reportou DHCP/IP).
    pub fn on_connected(&mut self) {
        if self.state != WifiStationState::Connected {
            crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "station");
        }
        self.state = WifiStationState::Connected;
    }

    /// Marca falha (volta para Off; fallback AP assume).
    pub fn on_failed(&mut self) {
        if self.state != WifiStationState::Off {
            crate::ltrace!(LtCat::Transport, LtEvt::TpError, "station");
        }
        self.state = WifiStationState::Off;
    }

    /// Desliga (fallback AP assumiu).
    pub fn disconnect(&mut self) {
        if self.state != WifiStationState::Off {
            crate::ltrace!(LtCat::Transport, LtEvt::TpClose, "station");
        }
        self.state = WifiStationState::Off;
    }
}

impl Default for WifiStationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Stub ESP: liga a station (quando `target_os = espidf` usa esp-idf-svc).
pub fn start_station_esp(_ssid: &str) -> Result<(), &str> {
    Ok(())
}


// Gates de binding para `/wifi/creds` (`binding.rs`).
//
// - Save/clear das credenciais station: binding + UP + PIN.
// - Ordem canonica: binding -> UP -> PIN. Sem binding a NVS fica intacta.

/// Barreira de binding para `/wifi/creds` (CONFIG).
/// Release exige vinculo; teste faz bypass com ltrace (so UP+PIN).
pub fn require_bound_station(binding_ok: bool) -> Result<(), WifiStationError> {
    if binding_ok {
        return Ok(());
    }
    if crate::binding::binding_bypass_enabled() {
        crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "binding-bypass");
        return Ok(());
    }
    Err(WifiStationError::NeedBinding)
}

/// Salva credenciais da station com binding: binding + UP + PIN.
pub fn save_station_credentials_bound<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    ssid: &str,
    password: &str,
    binding_ok: bool,
    pin_authenticated: bool,
    presence_confirmed: bool,
) -> Result<(), WifiStationError> {
    require_bound_station(binding_ok)?;
    save_station_credentials(storage, ssid, password, pin_authenticated, presence_confirmed)
}

/// Apaga credenciais da station com binding: binding + UP + PIN.
pub fn clear_station_credentials_bound<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    binding_ok: bool,
    pin_authenticated: bool,
    presence_confirmed: bool,
) -> Result<(), WifiStationError> {
    require_bound_station(binding_ok)?;
    clear_station_credentials(storage, pin_authenticated, presence_confirmed)
}

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
        save_station_credentials(&mut st, "Casa-5G", "senha-segura-123", true, true).expect("save ok");
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
