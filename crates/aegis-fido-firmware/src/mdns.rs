//! Phase8 - mDNS `aegiskey-XXXX.local` (casca fina de compat; ver `net`).
//!
//! Conteudo movido para `net::mdns` sem mudanca de comportamento.
//! Testes `mod tests` ficam aqui.
#[deprecated(note = "Use crate::net::mdns instead.")]
pub use crate::net::mdns::*;

#[cfg(test)]
mod tests {
    use crate::net::mdns::*;

    #[test]
    fn hostname_derives_lowercase_suffix() {
        assert_eq!(
            mdns_hostname_for_serial("AEGIS-S3-00AF"),
            "aegiskey-00af.local"
        );
        assert_eq!(
            mdns_hostname_for_serial("AEGIS-S3-0001"),
            "aegiskey-0001.local"
        );
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
    fn host_shims_inertes() {
        assert_eq!(esp_mdns_start("aegiskey-00af"), 0);
        assert_eq!(esp_mdns_stop(), 0);
    }

    #[test]
    fn bare_hostname_tira_suffix() {
        assert_eq!(mdns_bare_hostname("aegiskey-00af.local"), "aegiskey-00af");
        assert_eq!(mdns_bare_hostname("aegiskey-00af"), "aegiskey-00af");
    }

    #[test]
    fn station_down_turns_mdns_off() {
        let mut m = MdnsManager::new();
        m.update(false, true);
        assert!(m.is_active());
        m.update(false, false);
        assert!(!m.is_active());
    }

    #[test]
    fn mdns_fallback_ap_em_pareamento_ou_sem_station() {
        assert!(mdns_fallback_to_ap(true, true));
        assert!(mdns_fallback_to_ap(true, false));
        assert!(mdns_fallback_to_ap(false, false));
        assert!(!mdns_fallback_to_ap(false, true));
    }
}
