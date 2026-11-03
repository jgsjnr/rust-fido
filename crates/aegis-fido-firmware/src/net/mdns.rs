//! Phase8 - mDNS `aegiskey-XXXX.local` (Etapa B: responder real via `aegis_wifi`).
//!
//! - Hostname deriva do serial (`aegiskey-` + sufixo de 4, lowercase).
//! - mDNS+station SO fora de pareamento; durante pareamento usa fallback AP.
//! - Nucleo sem I/O; ESP liga o responder via `start_mdns_esp`.
//! - `no_std` compativel: so `alloc`, relogio injetado pelo chamador.

extern crate alloc;

#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};
use alloc::format;
use alloc::string::String;

/// Prefixo do hostname mDNS (lowercase, RFC 6762).
pub const MDNS_PREFIX: &str = "aegiskey-";
/// Sufixo `.local` do mDNS.
pub const MDNS_SUFFIX: &str = ".local";
/// Sufixo quando o serial nao tem 4 alfanumericos.
pub const MDNS_FALLBACK_SUFFIX: &str = "0001";

/// Deriva `aegiskey-XXXX.local` do serial (ultimos 4 alfanumericos, lowercase).
pub fn mdns_hostname_for_serial(serial: &str) -> String {
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
    let suffix = if tail.len() == 4 {
        tail
    } else {
        String::from(MDNS_FALLBACK_SUFFIX)
    };
    format!(
        "{}{}{}",
        MDNS_PREFIX,
        suffix.to_ascii_lowercase(),
        MDNS_SUFFIX
    )
}

/// Valida hostname mDNS (`aegiskey-XXXX.local`, 1..64, ascii).
pub fn is_valid_mdns_hostname(host: &str) -> bool {
    if host.len() > 64 || host.is_empty() {
        return false;
    }
    if !host.starts_with(MDNS_PREFIX) || !host.ends_with(MDNS_SUFFIX) {
        return false;
    }
    let mid = &host[MDNS_PREFIX.len()..host.len() - MDNS_SUFFIX.len()];
    !mid.is_empty()
        && mid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == (45 as char))
}

/// Estado do responder mDNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdnsState {
    /// Desligado (default, ou durante pareamento).
    Off,
    /// Anunciando hostname `.local`.
    Active,
}

/// Gerente do mDNS (sem I/O; ESP liga via `esp_mdns_start`, componente C `aegis_wifi`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdnsManager {
    state: MdnsState,
}

impl MdnsManager {
    /// Cria desligado.
    pub fn new() -> Self {
        Self {
            state: MdnsState::Off,
        }
    }

    /// Estado atual.
    pub fn state(&self) -> MdnsState {
        self.state
    }

    /// `true` quando anunciando.
    pub fn is_active(&self) -> bool {
        self.state == MdnsState::Active
    }

    /// Liga SO fora de pareamento E com station up; desliga caso contrario.
    /// `pairing_open`: janela 60s aberta; `station_up`: station conectada.
    pub fn update(&mut self, pairing_open: bool, station_up: bool) {
        if !pairing_open && station_up {
            if self.state == MdnsState::Off {
                self.state = MdnsState::Active;
                crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "mdns");
            }
        } else if self.state == MdnsState::Active {
            self.state = MdnsState::Off;
            crate::ltrace!(LtCat::Transport, LtEvt::TpClose, "mdns");
        }
    }

    /// Desliga (fallback AP assumiu).
    pub fn shutdown(&mut self) {
        if self.state != MdnsState::Off {
            crate::ltrace!(LtCat::Transport, LtEvt::TpClose, "mdns");
        }
        self.state = MdnsState::Off;
    }
}

impl Default for MdnsManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Radio real: FFI manual com o componente C `aegis_wifi` (responder minimo
// sobre sockets lwIP; o IDF v5.3 nao tem `mdns` no core). Mesmo padrao do
// `ble_nimble.rs` com `aegis_ble`: sem bindgen, sem novos deps.
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "espidf", not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))))]
extern "C" {
    fn aegis_mdns_start(host: *const u8, host_len: i32) -> i32;
    fn aegis_mdns_stop() -> i32;
}

/// Liga o responder mDNS (`0` ok, negativo = erro do C).
/// `host` SEM o sufixo `.local` (ex.: `aegiskey-00af`).
#[cfg(all(target_os = "espidf", not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))))]
pub fn esp_mdns_start(host: &str) -> i32 {
    crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "mdns");
    unsafe { aegis_mdns_start(host.as_ptr(), host.len().min(i32::MAX as usize) as i32) }
}

/// Desliga o responder (`0` ok).
#[cfg(all(target_os = "espidf", not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))))]
pub fn esp_mdns_stop() -> i32 {
    crate::ltrace!(LtCat::Transport, LtEvt::TpClose, "mdns");
    unsafe { aegis_mdns_stop() }
}

// Shims inertes no host (sem radio; politica testada por unidade).
#[cfg(any(not(target_os = "espidf"), any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
pub fn esp_mdns_start(_host: &str) -> i32 {
    0
}
#[cfg(any(not(target_os = "espidf"), any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
pub fn esp_mdns_stop() -> i32 {
    0
}

/// Tira o sufixo `.local` p/ a FFI (`aegiskey-00af.local` -> `aegiskey-00af`).
pub fn mdns_bare_hostname(host: &str) -> &str {
    host.strip_suffix(MDNS_SUFFIX).unwrap_or(host)
}

/// T10 — politica de fallback do mDNS: anuncia SO fora de pareamento com
/// station up; em pareamento ou sem station o chamador usa o fallback AP.
pub fn mdns_fallback_to_ap(pairing_open: bool, station_up: bool) -> bool {
    pairing_open || !station_up
}
