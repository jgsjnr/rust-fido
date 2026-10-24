//! WiFi AP: senha em NVS cifrada (UP+PIN) - parte de `net` (ver `ap_core`).
//!
//! - Troca exige UP+PIN, grava em NVS cifrada (`SecureStorage`, envelope AES-GCM).
//! - Gate de binding (`NEED_BINDING`) p/ `POST /config/wifi`; ordem binding -> UP -> PIN.
//! - Segredo nunca entra em log; senha efetiva `None` = rede aberta (bootstrap curto).

extern crate alloc;

use super::ap_core::WifiApError;
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};
use crate::persistence::{FlashStorageBackend, SecureStorage};
use aegis_fido_core::policy::{UpAndPin, UpPolicy};
use alloc::string::String;

/// Chave NVS da senha do AP (envelope AES-GCM).
pub const WIFI_PASS_NVS_KEY: &str = "wifi_ap_pass";
/// Tamanho minimo da senha do AP.
pub const MIN_WIFI_PASS_LEN: usize = 8;
/// Tamanho maximo da senha do AP.
pub const MAX_WIFI_PASS_LEN: usize = 63;

/// Valida senha do AP (bounds WPA2).
pub fn is_valid_wifi_password(pass: &str) -> bool {
    let len = pass.len();
    (MIN_WIFI_PASS_LEN..=MAX_WIFI_PASS_LEN).contains(&len) && pass.is_ascii()
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
