//! Phase8 - mDNS `aegiskey-XXXX.local` (host stub + ESP mDNS).
//!
//! - Hostname deriva do serial (`aegiskey-` + sufixo de 4, lowercase).
//! - mDNS+station SO fora de pareamento; durante pareamento usa fallback AP.
//! - Nucleo sem I/O; ESP liga o responder via `start_mdns_esp`.
//! - `no_std` compativel: so `alloc`, relogio injetado pelo chamador.

extern crate alloc;

use alloc::string::String;
use alloc::format;
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};

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
    let suffix = if tail.len() == 4 { tail } else { String::from(MDNS_FALLBACK_SUFFIX) };
    format!("{}{}{}", MDNS_PREFIX, suffix.to_ascii_lowercase(), MDNS_SUFFIX)
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
    !mid.is_empty() && mid.chars().all(|c| c.is_ascii_alphanumeric() || c == (45 as char))
}

/// Estado do responder mDNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdnsState {
    /// Desligado (default, ou durante pareamento).
    Off,
    /// Anunciando hostname `.local`.
    Active,
}

/// Gerente do mDNS (sem I/O; ESP liga via `start_mdns_esp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdnsManager {
    state: MdnsState,
}

impl MdnsManager {
    /// Cria desligado.
    pub fn new() -> Self {
        Self { state: MdnsState::Off }
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

/// Stub ESP: liga o responder (quando `target_os = espidf` usa esp-idf-svc).
pub fn start_mdns_esp(_hostname: &str) -> Result<(), &str> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_derives_lowercase_suffix() {
        assert_eq!(mdns_hostname_for_serial("AEGIS-S3-00AF"), "aegiskey-00af.local");
        assert_eq!(mdns_hostname_for_serial("AEGIS-S3-0001"), "aegiskey-0001.local");
        assert_eq!(mdns_hostname_for_serial("x"), "aegiskey-0001.local");
    }

    #[test]
    fn hostname_validated() {
        assert!(is_valid_mdns_hostname("aegiskey-00af.local"));
        assert!(!is_valid_mdns_hostname("AegisKey-00AF.local"));
        assert!(!is_valid_mdns_hostname("aegiskey-00af.lan"));
        assert!(!is_valid_mdns_hostname("outro-00af.local"));
    }

    #[test]
    fn mdns_only_outside_pairing_with_station() {
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
    fn station_down_turns_mdns_off() {
        let mut m = MdnsManager::new();
        m.update(false, true);
        assert!(m.is_active());
        m.update(false, false);
        assert!(!m.is_active());
    }
}
