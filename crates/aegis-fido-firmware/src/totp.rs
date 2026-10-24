//! T-OT-01 TOTP/HOTP por vetor RFC 4226/6238 (GEN-DEVICE).
//!
//! Motivo: OTP exibido/digitado precisa de prova por vetor; sem este modulo
//! o firmware calcularia codigo sem referencia normativa (secao 9).
//!
//! - GEN-DEVICE: o codigo nasce no device a partir do segredo provisionado;
//!   este modulo so faz a matematica HOTP/TOTP sobre o segredo injetado.
//! - Reusa `aegis_fido_core::oath::calculate_code` (HMAC-SHA1/SHA256/SHA512
//!   real); aqui entram relogio injetado, limites e fail-closed.
//! - Relogio fail-closed: o chamador injeta `TotpClock`; `rtc_trusted = false`
//!   (RTC sem bateria / nao ajustado) nega o calculo em vez de emitir
//!   codigo de janela errada. `last_seen_secs` trava rollback de relogio:
//!   `now < last_seen` nega (sem RTC confiavel nao ha TOTP).
//! - Segredo nunca em log: nenhuma variante de erro carrega segredo, codigo
//!   ou contador; sem `Debug` em buffer sensivel.
//! - Limites (secao 9): segredo 10..=128 B, digitos 6..=8, periodo fixo 30 s.

extern crate alloc;

use aegis_fido_core::oath::{calculate_code, OathAlgorithm};
use alloc::string::String;

/// Periodo TOTP em segundos (RFC 6238, X = 30).
pub const TOTP_PERIOD_SECS: u64 = 30;
/// Segredo minimo (80 bits; abaixo disso HMAC vira forca bruta trivial).
pub const OTP_MIN_SECRET_LEN: usize = 10;
/// Segredo maximo (teto de memoria; HMAC aceita mais, firmware nao).
pub const OTP_MAX_SECRET_LEN: usize = 128;
/// Digitos minimos (Yubico/OATH interop).
pub const OTP_MIN_DIGITS: u8 = 6;
/// Digitos maximos (RFC 6238 usa 8).
pub const OTP_MAX_DIGITS: u8 = 8;

/// Relogio injetado pelo chamador (firmware nao le relogio host aqui).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpClock {
    /// Segundos Unix atuais (RTC do device, ja validado pelo chamador).
    pub now_unix_secs: u64,
    /// Falso = RTC sem bateria / nao ajustado: calculo negado.
    pub rtc_trusted: bool,
}

/// Codigo TOTP calculado (codigo e publico: vai p/ display/teclado).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCode {
    /// Digitos com zero a esquerda (6..=8 chars).
    pub code: String,
    /// Contador T usado (`now / 30`).
    pub counter: u64,
    /// Segundos restantes na janela (`30 - now % 30`, 1..=30).
    pub remaining_secs: u64,
}

/// Erros OTP. Nenhuma variante carrega segredo, codigo ou contador.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpError {
    /// Segredo fora de 10..=128 B.
    BadSecret,
    /// Digitos fora de 6..=8.
    BadDigits,
    /// RTC nao confiavel (sem bateria / nao ajustado).
    ClockNotTrusted,
    /// `now` regrediu contra o ultimo visto (rollback de relogio).
    ClockRollback,
}

impl core::fmt::Display for TotpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadSecret => write!(f, "bad otp secret length"),
            Self::BadDigits => write!(f, "bad otp digits"),
            Self::ClockNotTrusted => write!(f, "rtc not trusted"),
            Self::ClockRollback => write!(f, "clock rollback"),
        }
    }
}

fn check_secret(secret: &[u8]) -> Result<(), TotpError> {
    if secret.is_empty() || !(OTP_MIN_SECRET_LEN..=OTP_MAX_SECRET_LEN).contains(&secret.len()) {
        return Err(TotpError::BadSecret);
    }
    Ok(())
}

fn check_digits(digits: u8) -> Result<(), TotpError> {
    if !(OTP_MIN_DIGITS..=OTP_MAX_DIGITS).contains(&digits) {
        return Err(TotpError::BadDigits);
    }
    Ok(())
}

fn format_code(raw: u32, digits: u8) -> String {
    let width = digits as usize;
    let mut s = alloc::format!("{raw}");
    while s.len() < width {
        let mut z = String::from("0");
        z.push_str(&s);
        s = z;
    }
    s
}

/// HOTP (RFC 4226): codigo para `secret`/`counter` com `digits` digitos.
pub fn hotp_code(
    secret: &[u8],
    algo: OathAlgorithm,
    counter: u64,
    digits: u8,
) -> Result<String, TotpError> {
    check_secret(secret)?;
    check_digits(digits)?;
    Ok(format_code(
        calculate_code(algo, secret, counter, digits),
        digits,
    ))
}

/// TOTP (RFC 6238): `T = now / 30`; nega sem RTC confiavel ou com rollback.
pub fn totp_code(
    secret: &[u8],
    algo: OathAlgorithm,
    digits: u8,
    clock: &TotpClock,
    last_seen_secs: u64,
) -> Result<TotpCode, TotpError> {
    check_secret(secret)?;
    check_digits(digits)?;
    if !clock.rtc_trusted {
        return Err(TotpError::ClockNotTrusted);
    }
    if clock.now_unix_secs < last_seen_secs {
        return Err(TotpError::ClockRollback);
    }
    let counter = clock.now_unix_secs / TOTP_PERIOD_SECS;
    let code = format_code(calculate_code(algo, secret, counter, digits), digits);
    Ok(TotpCode {
        code,
        counter,
        remaining_secs: TOTP_PERIOD_SECS - (clock.now_unix_secs % TOTP_PERIOD_SECS),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA1_SECRET: &[u8] = b"12345678901234567890";
    const SHA256_SECRET: &[u8] = b"12345678901234567890123456789012";
    const SHA512_SECRET: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    fn clock(now: u64) -> TotpClock {
        TotpClock {
            now_unix_secs: now,
            rtc_trusted: true,
        }
    }

    #[test]
    fn hotp_rfc4226_dez_vetores() {
        let expected = [
            755224u32, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, &exp) in expected.iter().enumerate() {
            let got = hotp_code(SHA1_SECRET, OathAlgorithm::Sha1, counter as u64, 6).unwrap();
            assert_eq!(got, alloc::format!("{exp:06}"), "HOTP counter {counter}");
        }
    }

    #[test]
    fn totp_rfc6238_tabela_completa() {
        // RFC 6238 Apendice B, 8 digitos (T = t / 30).
        let cases: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for &(t, sha1, sha256, sha512) in cases {
            assert_eq!(
                totp_code(SHA1_SECRET, OathAlgorithm::Sha1, 8, &clock(t), 0)
                    .unwrap()
                    .code,
                sha1,
                "SHA1 t={t}"
            );
            assert_eq!(
                totp_code(SHA256_SECRET, OathAlgorithm::Sha256, 8, &clock(t), 0)
                    .unwrap()
                    .code,
                sha256,
                "SHA256 t={t}"
            );
            assert_eq!(
                totp_code(SHA512_SECRET, OathAlgorithm::Sha512, 8, &clock(t), 0)
                    .unwrap()
                    .code,
                sha512,
                "SHA512 t={t}"
            );
        }
    }

    #[test]
    fn totp_contador_e_janela() {
        let c = totp_code(SHA1_SECRET, OathAlgorithm::Sha1, 6, &clock(59), 0).unwrap();
        assert_eq!(c.counter, 1);
        assert_eq!(c.remaining_secs, 1);
        assert_eq!(c.code, "287082");
        let c = totp_code(SHA1_SECRET, OathAlgorithm::Sha1, 6, &clock(60), 0).unwrap();
        assert_eq!((c.counter, c.remaining_secs), (2, 30));
    }

    #[test]
    fn relogio_fail_closed() {
        // RTC nao confiavel: nega mesmo com segredo valido.
        let bad = TotpClock {
            now_unix_secs: 59,
            rtc_trusted: false,
        };
        assert_eq!(
            totp_code(SHA1_SECRET, OathAlgorithm::Sha1, 6, &bad, 0),
            Err(TotpError::ClockNotTrusted)
        );
        // Rollback: now menor que o ultimo visto.
        assert_eq!(
            totp_code(SHA1_SECRET, OathAlgorithm::Sha1, 6, &clock(100), 101),
            Err(TotpError::ClockRollback)
        );
        // Igual ao ultimo visto e valido (relogio parado nao e rollback).
        assert!(totp_code(SHA1_SECRET, OathAlgorithm::Sha1, 6, &clock(100), 100).is_ok());
    }

    #[test]
    fn rejeita_entradas_invalidas() {
        assert_eq!(
            hotp_code(b"curto", OathAlgorithm::Sha1, 0, 6),
            Err(TotpError::BadSecret)
        );
        assert_eq!(
            hotp_code(b"", OathAlgorithm::Sha1, 0, 6),
            Err(TotpError::BadSecret)
        );
        assert_eq!(
            hotp_code(
                &alloc::vec![0x41u8; OTP_MAX_SECRET_LEN + 1],
                OathAlgorithm::Sha1,
                0,
                6
            ),
            Err(TotpError::BadSecret)
        );
        assert_eq!(
            hotp_code(SHA1_SECRET, OathAlgorithm::Sha1, 0, 5),
            Err(TotpError::BadDigits)
        );
        assert_eq!(
            hotp_code(SHA1_SECRET, OathAlgorithm::Sha1, 0, 9),
            Err(TotpError::BadDigits)
        );
        assert_eq!(
            totp_code(SHA1_SECRET, OathAlgorithm::Sha1, 5, &clock(59), 0),
            Err(TotpError::BadDigits)
        );
    }
}
