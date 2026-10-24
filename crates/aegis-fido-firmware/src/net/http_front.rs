//! F14: HTTP front of net-wifi (moved from `ap_core.rs`, move-only).
//!
//! - T10 facade: `POST /ctap` and `POST /config/wifi`, `GET /oath/code`,
//!   orchestrating station/mDNS through traits (`WifiRadioBackend`,
//!   `HttpConfigService`); radio C stays behind the trait, no unwraps.
//! - AP core (heap guard, `WifiApManager`, CTAP envelope, OATH bound,
//!   `esp_ap_*` shims) stays in `super::ap_core` and is imported here.
//! - `super::X` paths are unchanged: both modules are children of `net`.

use super::ap_core::{
    ctap_envelope_nonce, esp_ap_start, esp_ap_stop, esp_wifi_off, handle_get_oath_code_bound,
    validate_ctap_envelope_for_request, TotpResponse, WifiApError, WifiApManager,
};
use super::mdns::MdnsManager;
use super::password_policy::change_ap_password_bound;
use super::station::{WifiStationError, WifiStationManager};
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};
use crate::persistence::{FlashStorageBackend, SecureStorage};
use aegis_fido_core::oath::OathAlgorithm;

// ---------------------------------------------------------------------------
// T10 — fachada net-wifi (replica padrao NimBLE: politica pura + radio C
// atras de trait; `no_std`, sem unwrap, R6 zero, R7 gated via `ltrace!`).
//
// - `WifiNet<R>`: `ap_start/stop`, `station_join`, `mdns_announce`.
//   AP so em pareamento/menu; station+mDNS so fora de pareamento;
//   mDNS exige station up (fallback AP caso contrario).
// - `HttpConfig` + `HttpConfigService`: `POST /ctap` (AAD rota/op/nonce
//   preservado), `POST /config/wifi`, `GET /oath/code`.
// - Radio C atras de [`WifiRadioBackend`] (esp_* existentes viram impl);
//   sem feature `wifi` tudo vira [`WifiNetError::NotCompiled`].
// - R12/R13/R14: sem `burn`/provisionamento aqui; TRNG/AES pelo trait
//   existente; envelope validado antes de delegar conteudo.
// ---------------------------------------------------------------------------

/// Erro tipado da fachada (sem panics; R6 zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiNetError {
    /// Feature `wifi` desligada (sem radio compilado).
    NotCompiled,
    /// AP fora de pareamento/menu.
    ApNotAllowed,
    /// Station em pareamento ou sem credenciais.
    StationNotAllowed,
    /// mDNS em pareamento ou sem station up.
    MdnsNotAllowed,
    /// Radio C recusou (`rc` negativo do backend).
    Radio(i32),
    /// Erro do AP/HTTP.
    Ap(WifiApError),
    /// Erro da station.
    Station(WifiStationError),
}

impl core::fmt::Display for WifiNetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotCompiled => write!(f, "wifi not compiled"),
            Self::ApNotAllowed => write!(f, "ap allowed only in pairing/menu"),
            Self::StationNotAllowed => write!(f, "station outside pairing with creds"),
            Self::MdnsNotAllowed => write!(f, "mdns outside pairing with station up"),
            Self::Radio(rc) => write!(f, "wifi radio error ({})", rc),
            Self::Ap(e) => write!(f, "ap: {}", e),
            Self::Station(e) => write!(f, "station: {}", e),
        }
    }
}

impl From<WifiApError> for WifiNetError {
    fn from(e: WifiApError) -> Self {
        Self::Ap(e)
    }
}

impl From<WifiStationError> for WifiNetError {
    fn from(e: WifiStationError) -> Self {
        Self::Station(e)
    }
}

/// Radio C atras de trait (replica `ble_nimble.rs`: `extern "C"` manual vira
/// impl; politica 100% host-testavel via backend fake nos testes).
pub trait WifiRadioBackend {
    /// Liga o AP real (`0` ok, negativo = erro do C).
    fn ap_start(ssid: &str, pass: &str) -> i32;
    /// Desliga o AP (`0` ok).
    fn ap_stop() -> i32;
    /// Conecta a station (`0` ok, nao bloqueia).
    fn sta_start(ssid: &str, pass: &str) -> i32;
    /// Desconecta a station (`0` ok).
    fn sta_stop() -> i32;
    /// Liga o responder mDNS (`host` sem `.local`; `0` ok).
    fn mdns_start(host: &str) -> i32;
    /// Desliga o responder (`0` ok).
    fn mdns_stop() -> i32;
    /// Power-down total do radio (`0` ok).
    fn wifi_off() -> i32;
}

/// Backend real: delega aos `esp_*` existentes (C `aegis_wifi` no device,
/// shims inertes no host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealWifiRadio;

impl WifiRadioBackend for RealWifiRadio {
    fn ap_start(ssid: &str, pass: &str) -> i32 {
        esp_ap_start(ssid, pass)
    }
    fn ap_stop() -> i32 {
        esp_ap_stop()
    }
    fn sta_start(ssid: &str, pass: &str) -> i32 {
        super::station::esp_sta_start(ssid, pass)
    }
    fn sta_stop() -> i32 {
        super::station::esp_sta_stop()
    }
    fn mdns_start(host: &str) -> i32 {
        super::mdns::esp_mdns_start(host)
    }
    fn mdns_stop() -> i32 {
        super::mdns::esp_mdns_stop()
    }
    fn wifi_off() -> i32 {
        esp_wifi_off()
    }
}

/// HTTP mgmt atras de trait: `POST /ctap`, `POST /config/wifi`,
/// `GET /oath/code` (gates binding->UP->PIN preservados).
pub trait HttpConfigService {
    /// `POST /ctap`: valida AAD rota/op/nonce e retorna tamanho do ct.
    /// `prev_nonce`: ultimo nonce aceito (`Some` + igual = replay, rejeita).
    fn post_ctap(
        &mut self,
        envelope: &[u8],
        route: &str,
        op: u8,
        prev_nonce: Option<[u8; 12]>,
    ) -> Result<usize, WifiApError>;
    /// `POST /config/wifi`: binding + UP + PIN, senha em NVS cifrada.
    fn post_config_wifi<B: FlashStorageBackend>(
        &mut self,
        storage: &mut SecureStorage<B>,
        new_password: &str,
        binding_ok: bool,
        pin_authenticated: bool,
        presence_confirmed: bool,
    ) -> Result<(), WifiApError>;
    /// `GET /oath/code`: so USO (binding ignorado de proposito), so codigo.
    fn get_oath_code(
        &self,
        account: &str,
        secrets: &[(&str, &[u8], OathAlgorithm, u8)],
        unix_seconds: u64,
        presence_confirmed: bool,
    ) -> Result<TotpResponse, WifiApError>;
}

/// Estado do servico HTTP (guarda ultimo nonce p/ anti-replay local).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpConfig {
    last_nonce: Option<[u8; 12]>,
}

impl HttpConfig {
    /// Cria zerado (nenhum nonce aceito ainda).
    pub fn new() -> Self {
        Self { last_nonce: None }
    }

    /// Ultimo nonce aceito (para o chamador persistir entre polls).
    pub fn last_nonce(&self) -> Option<[u8; 12]> {
        self.last_nonce
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpConfigService for HttpConfig {
    fn post_ctap(
        &mut self,
        envelope: &[u8],
        route: &str,
        op: u8,
        prev_nonce: Option<[u8; 12]>,
    ) -> Result<usize, WifiApError> {
        // Ordem canonica: prev explicito vence; senao usa o nonce local.
        let prev = prev_nonce.or(self.last_nonce);
        let ct_len = validate_ctap_envelope_for_request(envelope, route, op, prev)?;
        let nonce = ctap_envelope_nonce(envelope)?;
        self.last_nonce = Some(nonce);
        Ok(ct_len)
    }

    fn post_config_wifi<B: FlashStorageBackend>(
        &mut self,
        storage: &mut SecureStorage<B>,
        new_password: &str,
        binding_ok: bool,
        pin_authenticated: bool,
        presence_confirmed: bool,
    ) -> Result<(), WifiApError> {
        change_ap_password_bound(
            storage,
            new_password,
            binding_ok,
            pin_authenticated,
            presence_confirmed,
        )
    }

    fn get_oath_code(
        &self,
        account: &str,
        secrets: &[(&str, &[u8], OathAlgorithm, u8)],
        unix_seconds: u64,
        presence_confirmed: bool,
    ) -> Result<TotpResponse, WifiApError> {
        // USO: sem vinculo (compat com `handle_get_oath_code_bound`).
        handle_get_oath_code_bound(account, secrets, unix_seconds, false, presence_confirmed)
    }
}

/// Fachada net-wifi: politicas AP/station/mDNS + radio atras de trait.
///
/// - `ap_start`: SO pareamento/menu (`pairing_open || menu_request`),
///   senha da NVS cifrada (via `resolve_ap_password` no chamador).
/// - `station_join`: SO fora de pareamento com credenciais.
/// - `mdns_announce`: SO fora de pareamento com station up; em pareamento
///   ou sem station o chamador cai no fallback AP.
/// - Sem feature `wifi`: tudo retorna [`WifiNetError::NotCompiled`].
#[derive(Debug)]
pub struct WifiNet<R: WifiRadioBackend> {
    ap: WifiApManager,
    sta: WifiStationManager,
    mdns: MdnsManager,
    _radio: core::marker::PhantomData<R>,
}

impl<R: WifiRadioBackend> WifiNet<R> {
    /// Cria com tudo desligado.
    pub fn new() -> Self {
        Self {
            ap: WifiApManager::new(),
            sta: WifiStationManager::new(),
            mdns: MdnsManager::new(),
            _radio: core::marker::PhantomData,
        }
    }

    /// Acesso aos gerentes (poll/decisao no chamador, ex. `main.rs`).
    pub fn ap(&self) -> &WifiApManager {
        &self.ap
    }
    /// Acesso a station.
    pub fn sta(&self) -> &WifiStationManager {
        &self.sta
    }
    /// Acesso ao mDNS.
    pub fn mdns(&self) -> &MdnsManager {
        &self.mdns
    }

    /// Liga o AP (janela/menu). `pass`: senha resolvida da NVS (`None` =
    /// rede aberta no bootstrap curto). Atualiza o `WifiApManager`.
    #[allow(clippy::needless_return)]
    pub fn ap_start(
        &mut self,
        pairing_open: bool,
        menu_request: bool,
        now_ms: u64,
        ssid: &str,
        pass: Option<&str>,
    ) -> Result<(), WifiNetError> {
        #[cfg(not(feature = "wifi"))]
        {
            let _ = (pairing_open, menu_request, now_ms, ssid, pass);
            return Err(WifiNetError::NotCompiled);
        }
        #[cfg(feature = "wifi")]
        {
            if !(pairing_open || menu_request) {
                return Err(WifiNetError::ApNotAllowed);
            }
            self.ap.update(true, false, now_ms);
            let pw = pass.unwrap_or("");
            let rc = R::ap_start(ssid, pw);
            if rc != 0 {
                return Err(WifiNetError::Radio(rc));
            }
            crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "wifi-net");
            Ok(())
        }
    }

    /// Desliga o AP (apos config/timeout; idempotente).
    #[allow(clippy::needless_return)]
    pub fn ap_stop(&mut self) -> Result<(), WifiNetError> {
        #[cfg(not(feature = "wifi"))]
        {
            return Err(WifiNetError::NotCompiled);
        }
        #[cfg(feature = "wifi")]
        {
            self.ap.shutdown_after_config();
            let rc = R::ap_stop();
            if rc != 0 {
                return Err(WifiNetError::Radio(rc));
            }
            Ok(())
        }
    }

    /// Conecta a station SO fora de pareamento e com credenciais.
    #[allow(clippy::needless_return)]
    pub fn station_join(
        &mut self,
        pairing_open: bool,
        has_credentials: bool,
        now_ms: u64,
        ssid: &str,
        pass: &str,
    ) -> Result<(), WifiNetError> {
        #[cfg(not(feature = "wifi"))]
        {
            let _ = (pairing_open, has_credentials, now_ms, ssid, pass);
            return Err(WifiNetError::NotCompiled);
        }
        #[cfg(feature = "wifi")]
        {
            if pairing_open || !has_credentials {
                return Err(WifiNetError::StationNotAllowed);
            }
            self.sta.update(false, true, now_ms);
            let rc = R::sta_start(ssid, pass);
            if rc != 0 {
                return Err(WifiNetError::Radio(rc));
            }
            Ok(())
        }
    }

    /// Anuncia mDNS SO fora de pareamento com station up; senão o chamador
    /// usa o fallback AP. `host`: sem `.local` (ex. `aegiskey-00af`).
    #[allow(clippy::needless_return)]
    pub fn mdns_announce(
        &mut self,
        pairing_open: bool,
        station_up: bool,
        host: &str,
    ) -> Result<(), WifiNetError> {
        #[cfg(not(feature = "wifi"))]
        {
            let _ = (pairing_open, station_up, host);
            return Err(WifiNetError::NotCompiled);
        }
        #[cfg(feature = "wifi")]
        {
            if pairing_open || !station_up {
                return Err(WifiNetError::MdnsNotAllowed);
            }
            self.mdns.update(false, true);
            let rc = R::mdns_start(host);
            if rc != 0 {
                return Err(WifiNetError::Radio(rc));
            }
            Ok(())
        }
    }

    /// Power-down total (AP off + station off; bateria).
    #[allow(clippy::needless_return)]
    pub fn off(&mut self) -> Result<(), WifiNetError> {
        #[cfg(not(feature = "wifi"))]
        {
            return Err(WifiNetError::NotCompiled);
        }
        #[cfg(feature = "wifi")]
        {
            self.ap.shutdown_after_config();
            self.sta.disconnect();
            self.mdns.shutdown();
            let rc = R::wifi_off();
            if rc != 0 {
                return Err(WifiNetError::Radio(rc));
            }
            Ok(())
        }
    }
}

impl<R: WifiRadioBackend> Default for WifiNet<R> {
    fn default() -> Self {
        Self::new()
    }
}
