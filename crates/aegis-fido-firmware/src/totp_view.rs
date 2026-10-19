//! WAVE8 — visao TOTP real para o display LilyGO (ST7789 135x240).
//!
//! - Long-press calcula `CALCULATE` **no device** via
//!   `OathApplet::device_list` + `device_code` (UP exigido).
//! - Sem literais: sem contas → vetor vazio (chamador mostra "sem contas").
//! - Segredo nunca sai do applet: so `code` (6-8 digitos) chega a tela/log.
//! - Janela TOTP 30s (`T = unix_secs / 30`, countdown `30 - unix_secs % 30`).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use aegis_fido_core::oath::{write_tlv, OathApplet, OathType, TAG_CHALLENGE, TAG_NAME};

/// Periodo TOTP em segundos (RFC 6238).
pub const TOTP_PERIOD_SECS: u64 = 30;
/// Long-press de 2s em ticks de 10ms (mesma base do `main.rs`).
pub const TOTP_LONG_PRESS_TICKS: u64 = 200;
/// Display visivel por 15s (igual `VAULT_AUTO_CLEAR_SECS`).
pub const TOTP_SHOW_TICKS: u64 = 1500;
/// Mensagem da tela "sem contas" (nunca codigo falso).
pub const NO_ACCOUNTS_MSG: &str = "Sem contas OATH — adicione via app";

/// Uma linha de TOTP calculada no device (sem segredo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpEntry {
    /// Rotulo da conta (eco, sem segredo).
    pub account: String,
    /// Codigo 6-8 digitos calculado no device.
    pub code: String,
    /// Segundos restantes na janela de 30s.
    pub remaining_seconds: u32,
}

/// Challenge de 8B big-endian para `unix_secs` (`T = t / 30`).
pub fn totp_challenge_for_unix_secs(unix_secs: u64) -> [u8; 8] {
    (unix_secs / TOTP_PERIOD_SECS).to_be_bytes()
}

/// Countdown da janela de 30s (1..=30).
pub fn totp_remaining_secs(unix_secs: u64) -> u32 {
    (TOTP_PERIOD_SECS - (unix_secs % TOTP_PERIOD_SECS)) as u32
}

/// Monta o TLV `0x71 label + 0x74 challenge` para `device_code`.
pub fn build_totp_request_tlv(label: &str, challenge: &[u8; 8]) -> Vec<u8> {
    let mut tlv = Vec::new();
    write_tlv(&mut tlv, TAG_NAME, label.as_bytes());
    write_tlv(&mut tlv, TAG_CHALLENGE, challenge);
    tlv
}

/// Lista os TOTP reais do device (exige UP).
///
/// - `presence_confirmed = false` → vazio (chamador mostra erro "sem UP").
/// - Applet vazio → vazio (chamador mostra "sem contas").
/// - HOTP e ignorado aqui (sem janela 30s; via USB/CTAP apenas).
/// - Ordem = ordem do `device_list` (estavel por insercao).
pub fn collect_totp_codes(
    applet: &mut OathApplet,
    unix_secs: u64,
    presence_confirmed: bool,
) -> Vec<TotpEntry> {
    if !presence_confirmed {
        return Vec::new();
    }
    let slots = match applet.device_list(false, true) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let challenge = totp_challenge_for_unix_secs(unix_secs);
    let remaining = totp_remaining_secs(unix_secs);
    let mut out = Vec::new();
    for slot in slots.iter().filter(|s| s.tipo == OathType::Totp) {
        let tlv = build_totp_request_tlv(&slot.label, &challenge);
        if let Ok(res) = applet.device_code(&tlv, false, true) {
            out.push(TotpEntry {
                account: slot.label.clone(),
                code: res.code,
                remaining_seconds: remaining,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_fido_core::oath::{OathAlgorithm, TAG_KEY};

    fn put_totp(
        applet: &mut OathApplet,
        label: &str,
        secret: &[u8],
        algo: OathAlgorithm,
        digits: u8,
    ) {
        let type_algo = match algo {
            OathAlgorithm::Sha1 => 0x01,
            OathAlgorithm::Sha256 => 0x02,
            OathAlgorithm::Sha512 => 0x03,
        } | 0x20; // TOTP
        let mut key_val = alloc::vec![type_algo, digits];
        key_val.extend_from_slice(secret);
        let mut tlv = Vec::new();
        write_tlv(&mut tlv, TAG_NAME, label.as_bytes());
        write_tlv(&mut tlv, TAG_KEY, &key_val);
        applet.device_put(&tlv, true, true).expect("seed totp");
    }

    #[test]
    fn long_press_lists_real_rfc4226_code() {
        let mut applet = OathApplet::new();
        // Vetor RFC 4226 S5.4: secret ASCII 20B, counter 1 -> 287082.
        put_totp(
            &mut applet,
            "TestService:alice",
            b"12345678901234567890",
            OathAlgorithm::Sha1,
            6,
        );
        // unix 59s -> T = 1.
        let entries = collect_totp_codes(&mut applet, 59, true);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].account, "TestService:alice");
        assert_eq!(entries[0].code, "287082");
        assert_eq!(entries[0].remaining_seconds, 1);
    }

    #[test]
    fn rfc6238_sha256_8_digits() {
        let mut applet = OathApplet::new();
        put_totp(
            &mut applet,
            "SHA256:alice",
            b"12345678901234567890123456789012",
            OathAlgorithm::Sha256,
            8,
        );
        let entries = collect_totp_codes(&mut applet, 59, true);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].code, "46119246");
    }

    #[test]
    fn empty_applet_means_no_accounts_never_fake() {
        let mut applet = OathApplet::new();
        let entries = collect_totp_codes(&mut applet, 59, true);
        assert!(entries.is_empty());
    }

    #[test]
    fn without_presence_returns_empty() {
        let mut applet = OathApplet::new();
        put_totp(
            &mut applet,
            "TestService:alice",
            b"12345678901234567890",
            OathAlgorithm::Sha1,
            6,
        );
        assert!(collect_totp_codes(&mut applet, 59, false).is_empty());
    }

    #[test]
    fn display_never_receives_hardcoded_literal() {
        let mut applet = OathApplet::new();
        put_totp(
            &mut applet,
            "TestService:alice",
            b"12345678901234567890",
            OathAlgorithm::Sha1,
            6,
        );
        let entries = collect_totp_codes(&mut applet, 59, true);
        assert_eq!(entries.len(), 1);
        for banned in ["482 915", "720 184", "934 602", "482915", "720184", "934602"] {
            assert_ne!(entries[0].code, banned, "display recebeu literal!");
        }
        assert_eq!(entries[0].code, "287082");
    }

    #[test]
    fn hotp_is_skipped_on_display() {
        let mut applet = OathApplet::new();
        // HOTP: type 0x10.
        let mut key_val = alloc::vec![0x11u8, 6u8];
        key_val.extend_from_slice(b"12345678901234567890");
        let mut tlv = Vec::new();
        write_tlv(&mut tlv, TAG_NAME, b"Hotp:alice");
        write_tlv(&mut tlv, TAG_KEY, &key_val);
        applet.device_put(&tlv, true, true).expect("seed hotp");
        let entries = collect_totp_codes(&mut applet, 59, true);
        assert!(entries.is_empty());
    }

    #[test]
    fn remaining_counts_down_30s_window() {
        assert_eq!(totp_remaining_secs(0), 30);
        assert_eq!(totp_remaining_secs(59), 1);
        assert_eq!(totp_remaining_secs(60), 30);
        assert_eq!(totp_challenge_for_unix_secs(59), 1u64.to_be_bytes());
        assert_eq!(totp_challenge_for_unix_secs(60), 2u64.to_be_bytes());
    }

    #[test]
    fn request_tlv_roundtrips_label_and_challenge() {
        use aegis_fido_core::oath::{find_tlv, parse_tlv_records};
        let chal = 1u64.to_be_bytes();
        let tlv = build_totp_request_tlv("GitHub:alice", &chal);
        let recs = parse_tlv_records(&tlv).expect("tlv valido");
        assert_eq!(find_tlv(&recs, TAG_NAME).unwrap(), b"GitHub:alice");
        assert_eq!(find_tlv(&recs, TAG_CHALLENGE).unwrap(), &chal);
    }
}
