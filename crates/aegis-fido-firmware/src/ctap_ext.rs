//! T-FD-05 extensoes CTAP2 sobre ctap_cmd (GEN-DEVICE).
//!
//! Purpose: evaluate the five credential extensions admitted by this
//! authenticator (`hmac-secret` + `hmac-secret-mc`, `minPinLength`,
//! `credProtect`, `credBlob`, `largeBlob`) on top of `ctap_cmd` without
//! editing it. Each evaluator enforces, fail-closed, in this order: wire
//! limits (via `PinUvGate::check_request`), input shape (lengths, value
//! ranges), then the UV predicate (PIN session or performed UV). Bound UP is
//! owned by the `ctap_cmd` admission that already ran; extensions never mint
//! their own grant.
//!
//! - hmac-secret: MC side only authorizes `credRandom` creation (caller
//!   generates it on-device via HRNG); GA side validates the salt shape
//!   (32 or 64 bytes) and requires UV, then `hmac_secret_prf` computes
//!   HMAC-SHA-256(credRandom, salt). Salt transport decrypt (saltEncr with
//!   the ClientPIN shared secret) stays with the session holder; only the
//!   PRF lives here, proven by an RFC-4231-anchored vector (key 32x0x00,
//!   salt "Hi There"+pad, computed with Python hashlib, cross-checked
//!   against RFC 4231 TC1 on the same run).
//! - minPinLength: pure report of the device minimum (floor 4, ceiling 63
//!   from `ctap_state`); out-of-range configuration fails closed.
//! - credProtect: parses 0x01/0x02/0x03; `Required` at creation demands
//!   `require_uv`, and at assertion demands performed UV or a live PIN
//!   session. The stored policy byte is caller-owned (credential record).
//! - credBlob: creation blob capped at 32 bytes; assertion-time read demands
//!   performed UV or a live PIN session. Bytes are caller-owned.
//! - largeBlob: 2048-byte array with offset/length checks; persistence is HW
//!   via the `LargeBlobStore` trait (board wires NVS; tests use a local RAM
//!   harness, never shipped). Reads validate before touching storage.
//! - No secret crosses a `Debug` impl (enums carry no material; `Vec<u8>`
//!   payloads are never formatted here) and nothing is logged.
//! - no_std compatible (alloc only for the largeBlob read buffer).

extern crate alloc;

use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::ctap_state::{CtapCommand, CtapError, PinUvGate, PIN_MAX_LEN, PIN_MIN_LEN};

type HmacSha256 = Hmac<Sha256>;

/// Salt length for a single hmac-secret salt (32 bytes).
pub const HMAC_SALT_LEN: usize = 32;
/// Salt length for a salt pair (salt1 || salt2).
pub const HMAC_SALT_PAIR_LEN: usize = 64;
/// Max bytes of a credBlob creation payload.
pub const CRED_BLOB_MAX: usize = 32;
/// Max bytes of the largeBlob array (LargeBlob 2048).
pub const LARGE_BLOB_MAX: usize = 2048;
/// Floor of the device minimum PIN length (mirrors `PIN_MIN_LEN`).
pub const MIN_PIN_FLOOR: u8 = PIN_MIN_LEN as u8;

/// Extension identifiers admitted by this authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extension {
    /// makeCredential `hmac-secret-mc` (bool): create credRandom.
    HmacSecretMc,
    /// getAssertion `hmac-secret` (saltEncr/saltAuth already opened).
    HmacSecret,
    /// ClientPIN `minPinLength` report.
    MinPinLength,
    /// `credProtect` creation/assertion policy.
    CredProtect,
    /// `credBlob` creation payload / assertion read.
    CredBlob,
    /// `largeBlob` array read/write (LargeBlobs command).
    LargeBlob,
}

/// Parse a wire extension identifier; unknown names fail closed with
/// `UnsupportedExtension` (CTAP 0x16) instead of being ignored.
pub fn parse_extension(name: &str) -> Result<Extension, CtapError> {
    match name {
        "hmac-secret-mc" => Ok(Extension::HmacSecretMc),
        "hmac-secret" => Ok(Extension::HmacSecret),
        "minPinLength" => Ok(Extension::MinPinLength),
        "credProtect" => Ok(Extension::CredProtect),
        "credBlob" => Ok(Extension::CredBlob),
        "largeBlob" => Ok(Extension::LargeBlob),
        _ => Err(CtapError::UnsupportedExtension),
    }
}

/// Authorize `hmac-secret-mc` at creation: returns whether the caller must
/// generate a fresh on-device `credRandom` (32 B via HRNG).
///
/// Demands performed UV or a live PIN session; anything else is `PinRequired`
/// (the secret capability is never created anonymously).
pub fn hmac_secret_mc(
    gate: &PinUvGate,
    encoded_len: usize,
    requested: bool,
    uv_performed: bool,
    pin_auth_ok: bool,
) -> Result<bool, CtapError> {
    gate.check_request(CtapCommand::MakeCredential.code(), encoded_len)?;
    if !requested {
        return Ok(false);
    }
    gate.check_uv_policy(true, uv_performed, pin_auth_ok)?;
    Ok(true)
}

/// Authorize `hmac-secret` at assertion: salt must be one 32-byte salt or a
/// 64-byte pair, and UV (performed or PIN session) is mandatory.
pub fn hmac_secret_ga(
    gate: &PinUvGate,
    encoded_len: usize,
    salt_len: usize,
    uv_performed: bool,
    pin_auth_ok: bool,
) -> Result<(), CtapError> {
    gate.check_request(CtapCommand::GetAssertion.code(), encoded_len)?;
    if salt_len != HMAC_SALT_LEN && salt_len != HMAC_SALT_PAIR_LEN {
        return Err(CtapError::InvalidParameter);
    }
    gate.check_uv_policy(true, uv_performed, pin_auth_ok)?;
    Ok(())
}

/// HMAC-SHA-256(credRandom, salt): the hmac-secret output primitive.
///
/// Both inputs are fixed 32-byte arrays; the caller owns storage and
/// zeroization. Never fails on valid input; the `Err` arm only covers a
/// construction fault, mapped fail-closed without exposing material.
pub fn hmac_secret_prf(
    cred_random: &[u8; HMAC_SALT_LEN],
    salt: &[u8; HMAC_SALT_LEN],
) -> Result<[u8; HMAC_SALT_LEN], CtapError> {
    let mut mac =
        HmacSha256::new_from_slice(&cred_random[..]).map_err(|_| CtapError::IntegrityFailure)?;
    mac.update(&salt[..]);
    Ok(mac.finalize().into_bytes().into())
}

/// Report the device minimum PIN length for `minPinLength`.
///
/// `configured_min` comes from device policy; below floor (4) or above
/// ceiling (63) fails closed as `IntegrityFailure` (misconfiguration, never
/// silently clamped).
pub fn min_pin_length(
    gate: &PinUvGate,
    encoded_len: usize,
    configured_min: u8,
) -> Result<u8, CtapError> {
    gate.check_request(CtapCommand::ClientPin.code(), encoded_len)?;
    if configured_min < MIN_PIN_FLOOR || configured_min > PIN_MAX_LEN as u8 {
        return Err(CtapError::IntegrityFailure);
    }
    Ok(configured_min)
}

/// credProtect policy values (CTAP 2.1 section 11.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredProtect {
    /// 0x01: UV optional.
    Optional = 0x01,
    /// 0x02: UV optional, enforce allow-list semantics.
    OptionalWithList = 0x02,
    /// 0x03: UV required for every use.
    Required = 0x03,
}

/// Parse a credProtect wire value; anything outside 0x01..=0x03 is
/// `InvalidParameter`.
pub fn parse_cred_protect(value: u8) -> Result<CredProtect, CtapError> {
    match value {
        0x01 => Ok(CredProtect::Optional),
        0x02 => Ok(CredProtect::OptionalWithList),
        0x03 => Ok(CredProtect::Required),
        _ => Err(CtapError::InvalidParameter),
    }
}

/// Enforce credProtect at creation: `Required` without `require_uv` is a
/// caller contradiction (`InvalidParameter`); the policy byte itself is
/// stored by the caller in the credential record.
pub fn cred_protect_mc(
    gate: &PinUvGate,
    encoded_len: usize,
    policy: CredProtect,
    require_uv: bool,
) -> Result<(), CtapError> {
    gate.check_request(CtapCommand::MakeCredential.code(), encoded_len)?;
    if policy == CredProtect::Required && !require_uv {
        return Err(CtapError::InvalidParameter);
    }
    Ok(())
}

/// Enforce credProtect at assertion against the stored policy: `Required`
/// without performed UV or a live PIN session is `PinRequired`.
pub fn cred_protect_ga(
    stored: CredProtect,
    uv_performed: bool,
    pin_auth_ok: bool,
) -> Result<(), CtapError> {
    if stored == CredProtect::Required && !uv_performed && !pin_auth_ok {
        return Err(CtapError::PinRequired);
    }
    Ok(())
}

/// Validate a credBlob creation payload: capped at 32 bytes, larger is
/// `RequestTooLarge`. Storage of the bytes is caller-owned.
pub fn cred_blob_mc(gate: &PinUvGate, encoded_len: usize, blob: &[u8]) -> Result<(), CtapError> {
    gate.check_request(CtapCommand::MakeCredential.code(), encoded_len)?;
    if blob.len() > CRED_BLOB_MAX {
        return Err(CtapError::RequestTooLarge);
    }
    Ok(())
}

/// Authorize a credBlob assertion-time read: performed UV or a live PIN
/// session, otherwise `PinRequired` (the blob is never released anonymously).
pub fn cred_blob_ga(uv_performed: bool, pin_auth_ok: bool) -> Result<(), CtapError> {
    if !uv_performed && !pin_auth_ok {
        return Err(CtapError::PinRequired);
    }
    Ok(())
}

/// Device persistence for the largeBlob array, wired by the board (NVS).
///
/// Implementations map HW faults to `CtapError` (typically
/// `IntegrityFailure`); validators below run before any storage access.
pub trait LargeBlobStore {
    /// Committed array length in bytes (0 when empty).
    fn stored_len(&self) -> Result<usize, CtapError>;
    /// Copy `out.len()` bytes at `offset` into `out`.
    fn read_into(&self, offset: usize, out: &mut [u8]) -> Result<(), CtapError>;
    /// Commit `data` at `offset` (overwrite/append within the 2048 cap).
    fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<(), CtapError>;
}

/// Write a largeBlob chunk: validates frame, 2048 cap, offset continuity
/// (no sparse holes), then commits. Empty writes are `MissingParameter`.
pub fn large_blob_write<S: LargeBlobStore>(
    gate: &PinUvGate,
    encoded_len: usize,
    store: &mut S,
    offset: usize,
    data: &[u8],
) -> Result<(), CtapError> {
    gate.check_request(CtapCommand::LargeBlobs.code(), encoded_len)?;
    if data.is_empty() {
        return Err(CtapError::MissingParameter);
    }
    let end = offset
        .checked_add(data.len())
        .ok_or(CtapError::RequestTooLarge)?;
    if end > LARGE_BLOB_MAX {
        return Err(CtapError::RequestTooLarge);
    }
    let current = store.stored_len()?;
    if current > LARGE_BLOB_MAX {
        return Err(CtapError::IntegrityFailure);
    }
    if offset > current {
        return Err(CtapError::InvalidParameter);
    }
    store.write_at(offset, data)
}

/// Read a largeBlob range into a fresh buffer: validates frame, range and cap
/// before touching storage. The caller must never log the returned bytes.
pub fn large_blob_read<S: LargeBlobStore>(
    gate: &PinUvGate,
    encoded_len: usize,
    store: &S,
    offset: usize,
    len: usize,
) -> Result<Vec<u8>, CtapError> {
    gate.check_request(CtapCommand::LargeBlobs.code(), encoded_len)?;
    if len == 0 {
        return Err(CtapError::MissingParameter);
    }
    if len > LARGE_BLOB_MAX {
        return Err(CtapError::RequestTooLarge);
    }
    let stored = store.stored_len()?;
    if stored > LARGE_BLOB_MAX {
        return Err(CtapError::IntegrityFailure);
    }
    let end = offset.checked_add(len).ok_or(CtapError::InvalidParameter)?;
    if end > stored {
        return Err(CtapError::InvalidParameter);
    }
    let mut out = alloc::vec![0u8; len];
    store.read_into(offset, &mut out)?;
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap_state::CTAP_MAX_MSG_LEN;

    fn gate() -> PinUvGate {
        PinUvGate::new(true)
    }

    /// RAM harness, SOMENTE fixture de teste; a placa real implementa
    /// `LargeBlobStore` sobre NVS.
    struct TestStore {
        buf: Vec<u8>,
        fail: bool,
    }

    impl TestStore {
        fn new() -> Self {
            Self {
                buf: Vec::new(),
                fail: false,
            }
        }
    }

    impl LargeBlobStore for TestStore {
        fn stored_len(&self) -> Result<usize, CtapError> {
            if self.fail {
                return Err(CtapError::IntegrityFailure);
            }
            Ok(self.buf.len())
        }

        fn read_into(&self, offset: usize, out: &mut [u8]) -> Result<(), CtapError> {
            if self.fail {
                return Err(CtapError::IntegrityFailure);
            }
            let end = offset + out.len();
            if end > self.buf.len() {
                return Err(CtapError::IntegrityFailure);
            }
            out.copy_from_slice(&self.buf[offset..end]);
            Ok(())
        }

        fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<(), CtapError> {
            if self.fail {
                return Err(CtapError::IntegrityFailure);
            }
            let end = offset + data.len();
            if self.buf.len() < end {
                self.buf.resize(end, 0);
            }
            self.buf[offset..end].copy_from_slice(data);
            Ok(())
        }
    }

    #[test]
    fn interop_identifiers_and_unknown() {
        assert_eq!(
            parse_extension("hmac-secret").unwrap(),
            Extension::HmacSecret
        );
        assert_eq!(
            parse_extension("hmac-secret-mc").unwrap(),
            Extension::HmacSecretMc
        );
        assert_eq!(
            parse_extension("minPinLength").unwrap(),
            Extension::MinPinLength
        );
        assert_eq!(
            parse_extension("credProtect").unwrap(),
            Extension::CredProtect
        );
        assert_eq!(parse_extension("credBlob").unwrap(), Extension::CredBlob);
        assert_eq!(parse_extension("largeBlob").unwrap(), Extension::LargeBlob);
        // Host pede extensao fora do catalogo: 0x16, sem ignorar silencioso.
        assert_eq!(
            parse_extension("payment").unwrap_err(),
            CtapError::UnsupportedExtension
        );
        assert_eq!(
            CtapError::UnsupportedExtension.code(),
            0x16,
            "wire value normativo"
        );
    }

    #[test]
    fn interop_hmac_secret_uv_and_salt_shape() {
        let g = gate();
        // Criacao sem UV nao cria credRandom.
        assert_eq!(
            hmac_secret_mc(&g, 64, true, false, false).unwrap_err(),
            CtapError::PinRequired
        );
        assert!(hmac_secret_mc(&g, 64, true, false, true).unwrap());
        assert!(!hmac_secret_mc(&g, 64, false, false, false).unwrap());
        // Sal com tamanho fora de 32/64 nega antes do predicado UV.
        assert_eq!(
            hmac_secret_ga(&g, 96, 16, true, false).unwrap_err(),
            CtapError::InvalidParameter
        );
        assert_eq!(
            hmac_secret_ga(&g, 96, 31, false, true).unwrap_err(),
            CtapError::InvalidParameter
        );
        // Sal valido sem UV nega.
        assert_eq!(
            hmac_secret_ga(&g, 96, 32, false, false).unwrap_err(),
            CtapError::PinRequired
        );
        hmac_secret_ga(&g, 96, 32, true, false).expect("sal1 + UV ok");
        hmac_secret_ga(&g, 96, 64, false, true).expect("par + sessao ok");
        // Quadro acima do teto nega antes de qualquer decisao.
        assert_eq!(
            hmac_secret_mc(&g, CTAP_MAX_MSG_LEN + 1, true, true, false).unwrap_err(),
            CtapError::LimitExceeded
        );
    }

    #[test]
    fn hmac_prf_matches_reference_vector() {
        // Vetor independente: Python hashlib na estacao (ancorado no RFC 4231
        // TC1, reproduzido na mesma execucao). Chave 32x0x00, sal
        // "Hi There"+24x0x00.
        let key = [0x00u8; HMAC_SALT_LEN];
        let mut salt = [0x00u8; HMAC_SALT_LEN];
        salt[..8].copy_from_slice(b"Hi There");
        let out = hmac_secret_prf(&key, &salt).expect("prf ok");
        let mut want = [0u8; 32];
        let hex = "da8728430f4cfe80e7f5f2d8d2394227e0e0ad3b645ce39b9c20c4e8add90c82";
        for (i, c) in hex.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(c).unwrap();
            want[i] = u8::from_str_radix(s, 16).unwrap();
        }
        assert_eq!(out, want);
        // Sensivel a chave e ao sal (PRF, nao constante).
        let mut other_key = key;
        other_key[31] = 1;
        assert_ne!(hmac_secret_prf(&other_key, &salt).unwrap(), out);
        let mut other_salt = salt;
        other_salt[0] ^= 0xFF;
        assert_ne!(hmac_secret_prf(&key, &other_salt).unwrap(), out);
    }

    #[test]
    fn interop_min_pin_length_report() {
        let g = gate();
        assert_eq!(min_pin_length(&g, 16, 4).unwrap(), 4);
        assert_eq!(min_pin_length(&g, 16, 8).unwrap(), 8);
        // Configuracao fora da faixa falha fechada, nunca clamp silencioso.
        assert_eq!(
            min_pin_length(&g, 16, 3).unwrap_err(),
            CtapError::IntegrityFailure
        );
        assert_eq!(
            min_pin_length(&g, 16, 64).unwrap_err(),
            CtapError::IntegrityFailure
        );
        assert_eq!(
            min_pin_length(&g, CTAP_MAX_MSG_LEN + 1, 4).unwrap_err(),
            CtapError::LimitExceeded
        );
    }

    #[test]
    fn interop_cred_protect_policy() {
        let g = gate();
        assert_eq!(parse_cred_protect(0x01).unwrap(), CredProtect::Optional);
        assert_eq!(
            parse_cred_protect(0x02).unwrap(),
            CredProtect::OptionalWithList
        );
        assert_eq!(parse_cred_protect(0x03).unwrap(), CredProtect::Required);
        assert_eq!(
            parse_cred_protect(0x00).unwrap_err(),
            CtapError::InvalidParameter
        );
        assert_eq!(
            parse_cred_protect(0x04).unwrap_err(),
            CtapError::InvalidParameter
        );
        // Required sem require_uv na criacao e contradicao do chamador.
        assert_eq!(
            cred_protect_mc(&g, 64, CredProtect::Required, false).unwrap_err(),
            CtapError::InvalidParameter
        );
        cred_protect_mc(&g, 64, CredProtect::Required, true).expect("uv ok");
        cred_protect_mc(&g, 64, CredProtect::Optional, false).expect("opt ok");
        // Assert sem UV sob Required nega; com UV ou sessao passa.
        assert_eq!(
            cred_protect_ga(CredProtect::Required, false, false).unwrap_err(),
            CtapError::PinRequired
        );
        cred_protect_ga(CredProtect::Required, true, false).expect("uv ok");
        cred_protect_ga(CredProtect::Required, false, true).expect("sessao ok");
        cred_protect_ga(CredProtect::Optional, false, false).expect("opt ok");
    }

    #[test]
    fn interop_cred_blob_limits_and_uv() {
        let g = gate();
        cred_blob_mc(&g, 64, &[0xABu8; CRED_BLOB_MAX]).expect("32 ok");
        cred_blob_mc(&g, 64, &[]).expect("ausente ok");
        assert_eq!(
            cred_blob_mc(&g, 64, &[0xABu8; CRED_BLOB_MAX + 1]).unwrap_err(),
            CtapError::RequestTooLarge
        );
        assert_eq!(
            cred_blob_ga(false, false).unwrap_err(),
            CtapError::PinRequired
        );
        cred_blob_ga(true, false).expect("uv ok");
        cred_blob_ga(false, true).expect("sessao ok");
    }

    #[test]
    fn interop_large_blob_roundtrip_and_limits() {
        let g = gate();
        let mut st = TestStore::new();
        large_blob_write(&g, 64, &mut st, 0, b"hello").expect("write ok");
        // Append continuo.
        large_blob_write(&g, 64, &mut st, 5, b" world").expect("append ok");
        let back = large_blob_read(&g, 64, &st, 0, 11).expect("read ok");
        assert_eq!(back, b"hello world");
        let part = large_blob_read(&g, 64, &st, 6, 5).expect("fatia ok");
        assert_eq!(part, b"world");
        // Buraco (offset alem do fim) nega.
        assert_eq!(
            large_blob_write(&g, 64, &mut st, 99, b"x").unwrap_err(),
            CtapError::InvalidParameter
        );
        // Leitura alem do fim nega.
        assert_eq!(
            large_blob_read(&g, 64, &st, 0, 12).unwrap_err(),
            CtapError::InvalidParameter
        );
        assert_eq!(
            large_blob_read(&g, 64, &st, 11, 1).unwrap_err(),
            CtapError::InvalidParameter
        );
        // Teto 2048: enche exato, uma a mais nega.
        let mut big = TestStore::new();
        let chunk = alloc::vec![0x5Au8; 512];
        for i in 0..4 {
            large_blob_write(&g, 700, &mut big, i * 512, &chunk).expect("fatia ok");
        }
        assert_eq!(big.buf.len(), LARGE_BLOB_MAX);
        assert_eq!(
            large_blob_write(&g, 700, &mut big, LARGE_BLOB_MAX, b"x").unwrap_err(),
            CtapError::RequestTooLarge
        );
        assert_eq!(
            large_blob_read(&g, 700, &big, 0, LARGE_BLOB_MAX + 1).unwrap_err(),
            CtapError::RequestTooLarge
        );
        // Vazio nega dos dois lados; quadro gigante nega primeiro.
        assert_eq!(
            large_blob_write(&g, 64, &mut st, 0, &[]).unwrap_err(),
            CtapError::MissingParameter
        );
        assert_eq!(
            large_blob_read(&g, 64, &st, 0, 0).unwrap_err(),
            CtapError::MissingParameter
        );
        assert_eq!(
            large_blob_write(&g, CTAP_MAX_MSG_LEN + 1, &mut st, 0, b"x").unwrap_err(),
            CtapError::LimitExceeded
        );
        // Falha de HW vira integridade, sem panico.
        let mut bad = TestStore::new();
        bad.fail = true;
        assert_eq!(
            large_blob_write(&g, 64, &mut bad, 0, b"x").unwrap_err(),
            CtapError::IntegrityFailure
        );
        assert_eq!(
            large_blob_read(&g, 64, &bad, 0, 1).unwrap_err(),
            CtapError::IntegrityFailure
        );
    }

    #[test]
    fn debug_never_leaks_secret() {
        // Enums nao carregam material; erro formata so nome+codigo.
        let e = format!("{:?}", CtapError::UnsupportedExtension);
        assert!(e.contains("0x16"));
        let p = format!("{:?}", CredProtect::Required);
        assert!(p.contains("Required"));
        let x = format!("{:?}", Extension::HmacSecret);
        assert!(x.contains("HmacSecret"));
        // Saida do PRF nunca passa por Debug aqui: so o tamanho e observavel.
        let out = hmac_secret_prf(&[0x11u8; 32], &[0x22u8; 32]).unwrap();
        assert_eq!(out.len(), HMAC_SALT_LEN);
    }
}
