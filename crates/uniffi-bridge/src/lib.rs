//! Manual JNI/JNA C-ABI bridge for the Android app (`aegis_bridge` cdylib).
//!
//! Strictly mirrors `docs/ble-protocol.md` (frozen) and re-exports
//! `aegis-fido-core` in a phone-safe shape:
//! - CBOR/COSE **parse-only** (returns key metadata, never key bytes);
//! - `AEGN` envelope AES-256-GCM seal/open with caller-provided transient
//!   key material (zeroized after use, never generated nor stored here);
//! - TOTP **display-only** verify: validates `GET /oath/code` JSON and code
//!   format (`6..8` ASCII digits). The bridge NEVER derives, generates or
//!   holds OATH secrets or device keys.

use aegis_fido_core::crypto::aead::{aes_256_gcm_decrypt, aes_256_gcm_encrypt};
use aegis_fido_core::crypto::cose::CoseKey;
use zeroize::Zeroize;

/// GATT service UUID16 (frozen, see `firmware/src/ble_gatt.rs`).
pub const BLE_SERVICE_UUID: u16 = 0xFFFD;
/// Control-point characteristic (write, fragmented request).
pub const CHAR_CONTROL_UUID: u16 = 0xFFF1;
/// Status characteristic (notify, keepalive).
pub const CHAR_STATUS_UUID: u16 = 0xFFF2;
/// Pending-length characteristic (read, u16 LE).
pub const CHAR_LEN_UUID: u16 = 0xFFF3;
/// Revision characteristic (read/write, accepts only `GATT_REVISION`).
pub const CHAR_REVISION_UUID: u16 = 0xFFF4;
/// CTAP2-BLE PING opcode (echo, no `CtapEngine`).
pub const OP_PING: u8 = 0x81;
/// CTAP2-BLE MSG opcode (`CtapEngine::process_packet`).
pub const OP_MSG: u8 = 0x83;
/// CTAP2-BLE CANCEL opcode (aborts active transaction).
pub const OP_CANCEL: u8 = 0xBE;
/// Frozen GATT revision.
pub const GATT_REVISION: u8 = 0x01;
/// Max bytes per FFF1 write (conservative MTU-3).
pub const MAX_FRAGMENT_BYTES: usize = 244;
/// Reassemble cap for the BLE GATT control point (transport-only, frozen
/// per `docs/ble-protocol.md`; NOT the `AEGN` envelope seal cap).
pub const CONTROL_POINT_LENGTH: usize = 512;
/// Binding mgmt fragment range over BLE (mirrors firmware
/// `ble::gatt_core::{BIND_MGMT_OP_MIN, BIND_MGMT_OP_MAX}`, Sec.11).
pub const BIND_MGMT_OP_MIN: u8 = 0x28;
/// Upper bound of the binding mgmt fragment range (see `BIND_MGMT_OP_MIN`).
pub const BIND_MGMT_OP_MAX: u8 = 0x2D;
/// OTA fragment range over BLE (mirrors firmware
/// `ble::gatt_core::{OTA_OP_MIN, OTA_OP_MAX}`).
///
/// `0x33` COMMIT framing is accepted here but executes USB-only
/// device-side (no execution branch in the BLE dispatcher); `0x2E`
/// rescue travels ONLY as `OP_MSG` payload and `0x2F` stays reserved,
/// both rejected below fail-closed.
pub const OTA_OP_MIN: u8 = 0x30;
/// Upper bound of the OTA fragment range (see `OTA_OP_MIN`).
pub const OTA_OP_MAX: u8 = 0x34;

/// `true` for opcodes that open a BLE control-point transaction: CTAP-BLE
/// (`0x81` PING / `0x83` MSG), bind-mgmt `0x28-0x2D` and OTA `0x30-0x34`.
///
/// `0xBE` CANCEL aborts and is rejected here (single-byte, never split);
/// `0x2E` rescue travels ONLY as `OP_MSG` payload, `0x2F` stays reserved.
fn is_ble_fragment_opcode(opcode: u8) -> bool {
    opcode == OP_PING
        || opcode == OP_MSG
        || (BIND_MGMT_OP_MIN..=BIND_MGMT_OP_MAX).contains(&opcode)
        || (OTA_OP_MIN..=OTA_OP_MAX).contains(&opcode)
}

/// `AEGN` envelope magic.
///
/// Canonical source: firmware `persistence.rs::ENVELOPE_MAGIC` (== SDK
/// `envelope::ENVELOPE_MAGIC`). Documented copy: this cdylib keeps no
/// SDK/firmware dependency; parity is enforced by
/// `envelope_cross_vector_matches_sdk_framing` (mirrors SDK
/// `aegn_cross_vector_matches_bridge_and_firmware`). Full delegation is
/// blocked by the ABI (UniFFI exposes only `Vec<u8>`; SDK seals opaque
/// `ct + tag` behind `AuthContext` + `ReplayWindow` and owns no AEAD).
pub const ENVELOPE_MAGIC: [u8; 4] = [0x41, 0x45, 0x47, 0x4E];
/// `AEGN` envelope version.
///
/// Canonical source: firmware `persistence.rs::ENVELOPE_VERSION` (== SDK
/// `envelope::ENVELOPE_VERSION`); see `ENVELOPE_MAGIC` for why this is a
/// copy and how parity is enforced.
pub const ENVELOPE_VERSION: u8 = 0x01;
/// `MAGIC[4] | VER[1] | NONCE[12] | TAG[16]` floor (empty ciphertext).
///
/// Equals SDK `envelope::MIN_ENVELOPE_LEN` (33) and firmware floor.
pub const MIN_ENVELOPE_LEN: usize = 33;
/// Max plaintext accepted by seal.
///
/// Canonical source: firmware `persistence.rs::MAX_PLAINTEXT_BYTES = 4096`
/// (== SDK `envelope::MAX_PLAINTEXT_BYTES`); bridge keeps a documented copy
/// only (no firmware dependency); parity enforced by the tests below.
pub const MAX_PLAINTEXT_BYTES: usize = 4096;
/// Max wire envelope (`HEADER[17] + plaintext[4096] + TAG[16]`).
///
/// Canonical source: firmware `persistence.rs::MAX_ENVELOPE_BYTES` (==
/// SDK `envelope::MAX_ENVELOPE_BYTES`); `envelope_validate` rejects longer
/// inputs fail-closed (mirrors SDK `TooLarge`, wire `0x04`).
pub const MAX_ENVELOPE_BYTES: usize = 4129;
/// WiFi AP password bounds (WPA2, ASCII).
pub const MIN_WIFI_PASS_LEN: usize = 8;
/// WiFi AP password upper bound.
pub const MAX_WIFI_PASS_LEN: usize = 63;

/// Typed bridge error (no payloads attached: never leaks secrets/PII).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeError {
    InvalidOpcode,
    Overflow,
    InvalidFragment,
    InvalidEnvelope,
    InvalidCose,
    InvalidOath,
    CryptoError,
    InvalidAddress,
    SecureGuardError,
}

impl core::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidOpcode => write!(f, "invalid opcode"),
            Self::Overflow => write!(f, "overflow control-point"),
            Self::InvalidFragment => write!(f, "invalid fragment"),
            Self::InvalidEnvelope => write!(f, "invalid ctap envelope"),
            Self::InvalidCose => write!(f, "invalid cose key"),
            Self::InvalidOath => write!(f, "invalid oath response"),
            Self::CryptoError => write!(f, "crypto operation failed"),
            Self::InvalidAddress => write!(f, "invalid wallet address input"),
            Self::SecureGuardError => write!(f, "secure guard operation failed"),
        }
    }
}

impl std::error::Error for BridgeError {}

/// Frozen BLE constants for the Kotlin side (single source of truth).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleInfo {
    pub service_uuid: u16,
    pub control_uuid: u16,
    pub status_uuid: u16,
    pub len_uuid: u16,
    pub revision_uuid: u16,
    pub gatt_revision: u8,
    pub op_ping: u8,
    pub op_msg: u8,
    pub op_cancel: u8,
    pub max_fragment_bytes: u32,
    pub control_point_length: u32,
}

/// TOTP code as returned by `GET /oath/code` (code only, never the secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OathCode {
    pub account: String,
    pub code: String,
    pub remaining_seconds: u32,
}

/// Parsed OATH OTPAuth input (URI or raw Base32 secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpAuthParsed {
    pub issuer: String,
    pub account_name: String,
    pub secret_base32: String,
    pub digits: u8,
    pub period: u32,
}

/// Returns the frozen BLE constants (`docs/ble-protocol.md` section 1-2).
pub fn ble_constants() -> BleInfo {
    BleInfo {
        service_uuid: BLE_SERVICE_UUID,
        control_uuid: CHAR_CONTROL_UUID,
        status_uuid: CHAR_STATUS_UUID,
        len_uuid: CHAR_LEN_UUID,
        revision_uuid: CHAR_REVISION_UUID,
        gatt_revision: GATT_REVISION,
        op_ping: OP_PING,
        op_msg: OP_MSG,
        op_cancel: OP_CANCEL,
        max_fragment_bytes: MAX_FRAGMENT_BYTES as u32,
        control_point_length: CONTROL_POINT_LENGTH as u32,
    }
}

/// Splits a BLE control-point payload into FFF1 fragments.
///
/// First fragment: `[opcode, len_hi, len_lo, data..]` (up to 241B of data);
/// continuations: `[seq, data..]` with `seq = 0, 1, ...` (up to 243B each),
/// matching `BleReassembler::feed`. `CANCEL` is single-byte and rejected here.
/// Accepted opcodes mirror the firmware transport: CTAP-BLE `0x81`/`0x83`,
/// bind-mgmt `0x28-0x2D` and OTA `0x30-0x34` (`0x33` COMMIT executes
/// USB-only device-side; `0x2E` rescue travels only as `OP_MSG` payload
/// and `0x2F` stays reserved, both rejected fail-closed).
pub fn ble_split_fragments(opcode: u8, payload: Vec<u8>) -> Result<Vec<Vec<u8>>, BridgeError> {
    if !is_ble_fragment_opcode(opcode) {
        return Err(BridgeError::InvalidOpcode);
    }
    if payload.len() > CONTROL_POINT_LENGTH {
        return Err(BridgeError::Overflow);
    }
    let total = payload.len();
    let first_capacity = (MAX_FRAGMENT_BYTES - 3).min(total);
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut first = Vec::with_capacity(3 + first_capacity);
    first.push(opcode);
    first.push(((total >> 8) & 0xFF) as u8);
    first.push((total & 0xFF) as u8);
    first.extend_from_slice(&payload[..first_capacity]);
    out.push(first);
    let mut offset = first_capacity;
    let mut seq: u8 = 0;
    while offset < total {
        let chunk = (MAX_FRAGMENT_BYTES - 1).min(total - offset);
        let mut frag = Vec::with_capacity(1 + chunk);
        frag.push(seq);
        frag.extend_from_slice(&payload[offset..offset + chunk]);
        out.push(frag);
        offset += chunk;
        seq = seq.wrapping_add(1);
    }
    Ok(out)
}

/// Validates a `POST /ctap` envelope (`AEGN` magic + version + lengths).
/// Returns the ciphertext length on success (content delegates to device).
///
/// Fail-closed mirror of SDK `open_envelope` framing (minus `AuthContext` /
/// replay, which stay device-side: this FFI surface is stateless by design
/// and each call carries its own transient key): rejects short, oversize
/// (`> MAX_ENVELOPE_BYTES`), bad magic/version, and all-zero nonces
/// (device TRNG never emits zero; mirrors SDK `ZeroNonce`).
pub fn envelope_validate(envelope: Vec<u8>) -> Result<u32, BridgeError> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(BridgeError::InvalidEnvelope);
    }
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(BridgeError::Overflow);
    }
    if envelope[0..4] != ENVELOPE_MAGIC || envelope[4] != ENVELOPE_VERSION {
        return Err(BridgeError::InvalidEnvelope);
    }
    if envelope[5..17] == [0u8; 12] {
        return Err(BridgeError::InvalidEnvelope);
    }
    Ok((envelope.len() - (4 + 1 + 12)) as u32)
}

/// Seals `plaintext` into an `AEGN` envelope with an explicit nonce.
///
/// `key` (32B) and `nonce` (12B) are transient caller buffers, zeroized
/// before return. Deterministic nonce keeps Rust tests reproducible;
/// the app must supply a fresh random nonce per seal (device TRNG guidance).
/// All-zero nonces are rejected fail-closed (mirrors SDK `ZeroNonce`;
/// device TRNG never emits zero). Replay windows stay device-side: this
/// stateless FFI cannot deduplicate across calls.
pub fn envelope_seal(
    mut key: Vec<u8>,
    plaintext: Vec<u8>,
    aad: Vec<u8>,
    mut nonce: Vec<u8>,
) -> Result<Vec<u8>, BridgeError> {
    if key.len() != 32 || nonce.len() != 12 {
        key.zeroize();
        nonce.zeroize();
        return Err(BridgeError::CryptoError);
    }
    if nonce.iter().all(|b| *b == 0) {
        key.zeroize();
        nonce.zeroize();
        return Err(BridgeError::CryptoError);
    }
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        key.zeroize();
        nonce.zeroize();
        return Err(BridgeError::Overflow);
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);
    let ct = aes_256_gcm_encrypt(&key_arr, &nonce_arr, &plaintext, &aad)
        .map_err(|_| BridgeError::CryptoError)?;
    key_arr.zeroize();
    key.zeroize();
    nonce.zeroize();
    let mut env = Vec::with_capacity(4 + 1 + 12 + ct.len());
    env.extend_from_slice(&ENVELOPE_MAGIC);
    env.push(ENVELOPE_VERSION);
    env.extend_from_slice(&nonce_arr);
    env.extend_from_slice(&ct);
    Ok(env)
}

/// Opens an `AEGN` envelope with a transient key (zeroized before return).
///
/// Framing (`magic | ver | len | zero-nonce`) is checked first via
/// `envelope_validate` (mirrors SDK `open_envelope` framing); AEAD opening
/// is the only crypto step here. Gates (`binding -> UP -> PIN`) and replay
/// stay device-side / SDK-typed-layer (this FFI is stateless).
pub fn envelope_open(
    mut key: Vec<u8>,
    envelope: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Vec<u8>, BridgeError> {
    envelope_validate(envelope.clone())?;
    if key.len() != 32 {
        key.zeroize();
        return Err(BridgeError::CryptoError);
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&envelope[5..17]);
    let ct = &envelope[17..];
    let pt = aes_256_gcm_decrypt(&key_arr, &nonce_arr, ct, &aad)
        .map_err(|_| BridgeError::CryptoError)?;
    key_arr.zeroize();
    key.zeroize();
    Ok(pt)
}

/// Parses COSE key CBOR (parse-only) and describes it without key bytes.
///
/// Returns e.g. `kty=EC2 crv=1 alg=-7 x_len=32 y_len=32`.
/// Coordinate material is measured, never rendered.
pub fn cose_key_info(cbor: Vec<u8>) -> Result<String, BridgeError> {
    let key = CoseKey::from_cbor_bytes(&cbor).map_err(|_| BridgeError::InvalidCose)?;
    match key {
        CoseKey::Ec2 { alg, crv, x, y } => Ok(format!(
            "kty=EC2 crv={} alg={} x_len={} y_len={}",
            crv,
            alg,
            x.len(),
            y.len()
        )),
        CoseKey::Okp { alg, crv, x } => {
            Ok(format!("kty=OKP crv={} alg={} x_len={}", crv, alg, x.len()))
        }
    }
}

/// `true` when `code` is a displayable TOTP code (6-8 ASCII digits).
pub fn oath_code_valid(code: String) -> bool {
    (6..=8).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_digit())
}

/// Seconds left in the 30s TOTP window (mirrors firmware `totp_code_for_secret`).
pub fn oath_remaining_seconds(unix_seconds: u64) -> u32 {
    30 - (unix_seconds % 30) as u32
}

/// Formats a 6..=8 digit numeric TOTP code for friendly display (e.g. "123456" -> "123 456", "12345678" -> "1234 5678").
/// Preserves non-matching input as-is.
pub fn totp_format_display(code: String) -> String {
    let clean: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if oath_code_valid(clean.clone()) {
        let mid = clean.len() / 2;
        format!("{} {}", &clean[..mid], &clean[mid..])
    } else {
        code
    }
}

/// PBKDF2-SHA1 iterations for the app lock verifier (mirrors OATH applet set-password behavior).
pub const APP_LOCK_PBKDF2_ITERATIONS: u32 = 1000;
/// Minimum app-lock salt length in bytes.
pub const APP_LOCK_SALT_MIN_LEN: usize = 16;
/// Maximum app-lock salt length in bytes.
pub const APP_LOCK_SALT_MAX_LEN: usize = 64;
/// App-lock verifier length in bytes.
pub const APP_LOCK_VERIFIER_LEN: usize = 32;

/// Derives the app-lock verifier with the existing PBKDF2-SHA1 primitive.
///
/// password is zeroized before return; salt must be 16..64B of app
/// randomness, password 1..128B. Errors carry no payload (never secrets).
pub fn app_lock_derive(mut password: Vec<u8>, salt: Vec<u8>) -> Result<Vec<u8>, BridgeError> {
    if password.is_empty()
        || password.len() > 128
        || salt.len() < APP_LOCK_SALT_MIN_LEN
        || salt.len() > APP_LOCK_SALT_MAX_LEN
    {
        password.zeroize();
        return Err(BridgeError::CryptoError);
    }
    let out = aegis_fido_core::oath::pbkdf2_sha1(
        &password,
        &salt,
        APP_LOCK_PBKDF2_ITERATIONS,
        APP_LOCK_VERIFIER_LEN,
    );
    password.zeroize();
    Ok(out)
}

/// True for WPA2-usable AP passwords (ASCII, 8-63 chars).
pub fn wifi_password_valid(password: String) -> bool {
    (MIN_WIFI_PASS_LEN..=MAX_WIFI_PASS_LEN).contains(&password.len()) && password.is_ascii()
}

/// Extracts `account` from `GET /oath/code?account=<nome>` (mirror of firmware).
pub fn oath_account_from_path(path: String) -> Option<String> {
    let query = path.split('?').nth(1)?;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("account=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let after_key = json.find(pattern.as_str())?;
    let rest = json[after_key + pattern.len()..]
        .split_once(':')?
        .1
        .trim_start();
    let body = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut escaped = false;
    for ch in body.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(out);
        } else {
            out.push(ch);
        }
    }
    None
}

fn extract_json_u32(json: &str, key: &str) -> Option<u32> {
    let pattern = format!("\"{key}\"");
    let after_key = json.find(pattern.as_str())?;
    let rest = json[after_key + pattern.len()..]
        .split_once(':')?
        .1
        .trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// Parses a `GET /oath/code` JSON body into display-only fields.
///
/// Rejects non-digit codes, empty accounts and `remaining_seconds > 30`.
/// Error carries no payload (account labels stay out of logs).
pub fn oath_parse_response(json: String) -> Result<OathCode, BridgeError> {
    let account = extract_json_string(&json, "account")
        .filter(|a| !a.is_empty() && a.len() <= 128)
        .ok_or(BridgeError::InvalidOath)?;
    let code = extract_json_string(&json, "code").ok_or(BridgeError::InvalidOath)?;
    if !oath_code_valid(code.clone()) {
        return Err(BridgeError::InvalidOath);
    }
    let remaining_seconds = extract_json_u32(&json, "remaining_seconds")
        .filter(|r| *r <= 30)
        .ok_or(BridgeError::InvalidOath)?;
    Ok(OathCode {
        account,
        code,
        remaining_seconds,
    })
}

fn clean_base32_secret(raw: &str) -> Option<String> {
    let clean: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let upper = clean.to_ascii_uppercase();
    let unpadded = upper.trim_end_matches('=');
    if unpadded.is_empty() {
        return None;
    }
    if unpadded.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')) {
        Some(unpadded.to_string())
    } else {
        None
    }
}

fn percent_decode(input: &str, plus_as_space: bool) -> String {
    let mut bytes = Vec::with_capacity(input.len());
    let b = input.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(hi), Some(lo)) = (
                (b[i + 1] as char).to_digit(16),
                (b[i + 2] as char).to_digit(16),
            ) {
                bytes.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        if plus_as_space && b[i] == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(b[i]);
        }
        i += 1;
    }
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Safely parses an `otpauth://totp/...` URI or a raw Base32 secret string.
///
/// Trims whitespace, cleans spaces and hyphens from the Base32 secret, and converts to uppercase.
/// On invalid URI or invalid Base32 secret, returns `Err(BridgeError::InvalidOath)`.
pub fn otpauth_extract_label_and_secret(input: String) -> Result<OtpAuthParsed, BridgeError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(BridgeError::InvalidOath);
    }

    if trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        let rest = &trimmed[10..];
        let (otp_type, after_type) = rest.split_once('/').ok_or(BridgeError::InvalidOath)?;
        let otp_type_lower = otp_type.trim().to_ascii_lowercase();
        if otp_type_lower != "totp" && otp_type_lower != "hotp" {
            return Err(BridgeError::InvalidOath);
        }

        let after_type_trimmed = after_type.trim_start_matches('/');
        let (raw_label, query_str) = match after_type_trimmed.split_once('?') {
            Some((l, q)) => (l, q),
            None => (after_type_trimmed, ""),
        };

        let decoded_label = percent_decode(raw_label, false);
        let (lbl_issuer, lbl_account) = match decoded_label.split_once(':') {
            Some((iss, acc)) => (iss.trim(), acc.trim()),
            None => ("", decoded_label.trim()),
        };

        let mut query_issuer = String::new();
        let mut raw_secret = String::new();
        let mut digits: u8 = 6;
        let mut period: u32 = 30;

        for pair in query_str.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = match pair.split_once('=') {
                Some((key, val)) => (key.trim().to_ascii_lowercase(), val.trim()),
                None => (pair.trim().to_ascii_lowercase(), ""),
            };
            let decoded_val = percent_decode(v, true);
            match k.as_str() {
                "secret" => {
                    raw_secret = decoded_val;
                }
                "issuer" => {
                    query_issuer = decoded_val.trim().to_string();
                }
                "digits" => {
                    if let Ok(d) = decoded_val.parse::<u8>() {
                        if (6..=8).contains(&d) {
                            digits = d;
                        }
                    }
                }
                "period" => {
                    if let Ok(p) = decoded_val.parse::<u32>() {
                        if p > 0 {
                            period = p;
                        }
                    }
                }
                _ => {}
            }
        }

        let secret_base32 = clean_base32_secret(&raw_secret).ok_or(BridgeError::InvalidOath)?;
        let issuer = if !query_issuer.is_empty() {
            query_issuer
        } else {
            lbl_issuer.to_string()
        };
        let account_name = lbl_account.to_string();

        Ok(OtpAuthParsed {
            issuer,
            account_name,
            secret_base32,
            digits,
            period,
        })
    } else {
        let secret_base32 = clean_base32_secret(trimmed).ok_or(BridgeError::InvalidOath)?;
        Ok(OtpAuthParsed {
            issuer: String::new(),
            account_name: String::new(),
            secret_base32,
            digits: 6,
            period: 30,
        })
    }
}

/// Derives a wallet address from a public key (public computation only).
///
/// Moved here from the firmware audit (`docs/firmware-fina.md` Step4c):
/// the app computes addresses locally from already-public keys, so the
/// device is never asked and the ESP binary links no encoding crates.
/// `network`: `bitcoin`/`btc`, `ethereum`/`evm`/`eth` or `solana`/`sol`
/// (case-insensitive). `pubkey_hex`: 33B compressed secp256k1 (bitcoin),
/// 64B uncompressed `x||y` without prefix (ethereum), or 32B Ed25519
/// (solana), hex-encoded. No private material crosses this interface.
pub fn wallet_address(network: String, pubkey_hex: String) -> Result<String, BridgeError> {
    use aegis_fido_core::wallet::address::{
        bitcoin_p2wpkh_address, ethereum_address, solana_address,
    };
    let net = network.trim().to_ascii_lowercase();
    let raw = decode_even_hex(pubkey_hex.trim()).ok_or(BridgeError::InvalidAddress)?;
    match net.as_str() {
        "bitcoin" | "btc" => {
            if raw.len() != 33 || (raw[0] != 0x02 && raw[0] != 0x03) {
                return Err(BridgeError::InvalidAddress);
            }
            let mut arr = [0u8; 33];
            arr.copy_from_slice(&raw);
            Ok(bitcoin_p2wpkh_address(&arr))
        }
        "ethereum" | "evm" | "eth" => {
            if raw.len() != 64 {
                return Err(BridgeError::InvalidAddress);
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&raw);
            Ok(ethereum_address(&arr))
        }
        "solana" | "sol" => {
            if raw.len() != 32 {
                return Err(BridgeError::InvalidAddress);
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            Ok(solana_address(&arr))
        }
        _ => Err(BridgeError::InvalidAddress),
    }
}

/// Strict even-length ASCII hex decoder (no new dependency for one call).
fn decode_even_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

pub use universal_device_sdk::secure_guard::{SecureGuardPolicyDto, SecureGuardStatusDto};

pub fn secure_guard_parse_status(payload: Vec<u8>) -> Result<SecureGuardStatusDto, BridgeError> {
    universal_device_sdk::secure_guard::decode_secure_guard_status_response(&payload)
        .map_err(|_| BridgeError::SecureGuardError)
}

pub fn secure_guard_encode_provision(
    pin: Vec<u8>,
    recovery_code: Vec<u8>,
    wipe_on_5_failures: bool,
    test_mode: bool,
) -> Result<Vec<u8>, BridgeError> {
    let policy = SecureGuardPolicyDto {
        wipe_on_5_failures,
        test_mode_non_destructive_wipe: test_mode,
        ..Default::default()
    };

    let rc = if recovery_code.is_empty() {
        None
    } else {
        Some(recovery_code.as_slice())
    };
    universal_device_sdk::secure_guard::encode_secure_guard_provision_request(
        &pin,
        rc,
        Some(&policy),
    )
    .map_err(|_| BridgeError::SecureGuardError)
}

pub fn secure_guard_encode_unlock(pin: Vec<u8>) -> Result<Vec<u8>, BridgeError> {
    universal_device_sdk::secure_guard::encode_secure_guard_unlock_request(&pin)
        .map_err(|_| BridgeError::SecureGuardError)
}

pub fn secure_guard_encode_change_pin(
    current_pin: Vec<u8>,
    new_pin: Vec<u8>,
) -> Result<Vec<u8>, BridgeError> {
    universal_device_sdk::secure_guard::encode_secure_guard_change_pin_request(
        &current_pin,
        &new_pin,
    )
    .map_err(|_| BridgeError::SecureGuardError)
}

pub fn secure_guard_encode_recover(
    recovery_code: Vec<u8>,
    new_pin: Vec<u8>,
) -> Result<Vec<u8>, BridgeError> {
    universal_device_sdk::secure_guard::encode_secure_guard_recover_request(
        &recovery_code,
        &new_pin,
    )
    .map_err(|_| BridgeError::SecureGuardError)
}

pub fn secure_guard_encode_lock() -> Result<Vec<u8>, BridgeError> {
    universal_device_sdk::secure_guard::encode_secure_guard_lock_request()
        .map_err(|_| BridgeError::SecureGuardError)
}

pub fn secure_guard_encode_config(policy: SecureGuardPolicyDto) -> Result<Vec<u8>, BridgeError> {
    universal_device_sdk::secure_guard::encode_secure_guard_config_request(&policy)
        .map_err(|_| BridgeError::SecureGuardError)
}

pub fn secure_guard_encode_wipe(scope: u8, confirm_token: String) -> Result<Vec<u8>, BridgeError> {
    universal_device_sdk::secure_guard::encode_secure_guard_wipe_request(scope, &confirm_token)
        .map_err(|_| BridgeError::SecureGuardError)
}

pub mod ffi;
pub use ffi::*;
pub mod pm_jni;

#[cfg(test)]
mod tests {
    use super::ffi::{policy_json, status_of};
    use super::*;
    use aegis_fido_core::crypto::cose::CoseKey;

    #[test]
    fn ble_constants_match_contract() {
        let info = ble_constants();
        assert_eq!(info.service_uuid, 0xFFFD);
        assert_eq!(info.control_uuid, 0xFFF1);
        assert_eq!(info.status_uuid, 0xFFF2);
        assert_eq!(info.len_uuid, 0xFFF3);
        assert_eq!(info.revision_uuid, 0xFFF4);
        assert_eq!(info.gatt_revision, 0x01);
        assert_eq!(
            (info.op_ping, info.op_msg, info.op_cancel),
            (0x81, 0x83, 0xBE)
        );
        assert_eq!(info.max_fragment_bytes, 244);
        assert_eq!(info.control_point_length, 512);
    }

    #[test]
    fn ble_single_fragment_roundtrip_shape() {
        let frags = ble_split_fragments(OP_MSG, b"hello-ctap".to_vec()).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(&frags[0][..3], &[OP_MSG, 0x00, 0x0A]);
        assert_eq!(&frags[0][3..], b"hello-ctap");
    }

    #[test]
    fn ble_multi_fragment_sizes_match_reassembler() {
        // 300B payload: first 3+241B, then [seq + 59B].
        let payload = vec![0xABu8; 300];
        let frags = ble_split_fragments(OP_MSG, payload.clone()).unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].len(), 244);
        assert_eq!(&frags[0][..3], &[OP_MSG, 0x01, 0x2C]);
        assert_eq!(frags[1][0], 0x00);
        assert_eq!(frags[1].len(), 60);
        let mut joined = frags[0][3..].to_vec();
        joined.extend_from_slice(&frags[1][1..]);
        assert_eq!(joined, payload);
    }

    #[test]
    fn ble_split_accepts_bind_and_ota_fragments() {
        // Bind-mgmt 0x28-0x2D (Sec.11) fragments like CTAP-BLE.
        for op in BIND_MGMT_OP_MIN..=BIND_MGMT_OP_MAX {
            let frags = ble_split_fragments(op, vec![0xABu8; 16]).unwrap();
            assert_eq!(frags.len(), 1);
            assert_eq!(&frags[0][..3], &[op, 0x00, 0x10]);
        }
        // OTA 0x30-0x34 fragments; 0x33 COMMIT framing accepted here,
        // execution stays USB-only device-side.
        for op in OTA_OP_MIN..=OTA_OP_MAX {
            let frags = ble_split_fragments(op, vec![0xCDu8; 4]).unwrap();
            assert_eq!(&frags[0][..3], &[op, 0x00, 0x04]);
        }
        // Multi-fragment shape holds for the new opcodes too.
        let payload = vec![0xABu8; 300];
        let frags = ble_split_fragments(0x28, payload.clone()).unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].len(), 244);
        assert_eq!(&frags[0][..3], &[0x28, 0x01, 0x2C]);
        let mut joined = frags[0][3..].to_vec();
        joined.extend_from_slice(&frags[1][1..]);
        assert_eq!(joined, payload);
    }

    #[test]
    fn ble_split_still_rejects_rescue_reserved_and_cancel() {
        // 0x2E rescue travels ONLY as OP_MSG payload, never as fragment.
        assert_eq!(
            ble_split_fragments(0x2E, vec![1]),
            Err(BridgeError::InvalidOpcode)
        );
        // 0x2F reserved stays rejected fail-closed.
        assert_eq!(
            ble_split_fragments(0x2F, vec![1]),
            Err(BridgeError::InvalidOpcode)
        );
    }

    #[test]
    fn ble_rejects_cancel_and_oversize() {
        assert_eq!(
            ble_split_fragments(OP_CANCEL, vec![1, 2]),
            Err(BridgeError::InvalidOpcode)
        );
        assert_eq!(
            ble_split_fragments(0x00, vec![1]),
            Err(BridgeError::InvalidOpcode)
        );
        assert_eq!(
            ble_split_fragments(OP_MSG, vec![0u8; CONTROL_POINT_LENGTH + 1]),
            Err(BridgeError::Overflow)
        );
    }

    #[test]
    fn envelope_validate_mirrors_firmware() {
        let mut env = Vec::new();
        env.extend_from_slice(&[0x41, 0x45, 0x47, 0x4E, 0x01]);
        env.extend_from_slice(&[0x11u8; 12]);
        env.extend_from_slice(&[9u8; 20]);
        env.extend_from_slice(&[0u8; 16]);
        assert!(envelope_validate(env.clone()).is_ok());
        // All-zero nonce is rejected fail-closed (device TRNG never emits
        // zero; mirrors SDK `ZeroNonce`, wire `0x04`).
        let mut zero = env.clone();
        zero[5..17].copy_from_slice(&[0u8; 12]);
        assert_eq!(envelope_validate(zero), Err(BridgeError::InvalidEnvelope));
        // Oversize envelope is rejected fail-closed (mirrors SDK `TooLarge`).
        assert_eq!(
            envelope_validate(vec![0x41u8; MAX_ENVELOPE_BYTES + 1]),
            Err(BridgeError::Overflow)
        );
        assert_eq!(
            envelope_validate(b"lixo".to_vec()),
            Err(BridgeError::InvalidEnvelope)
        );
        let mut bad = env.clone();
        bad[0] ^= 0xFF;
        assert_eq!(envelope_validate(bad), Err(BridgeError::InvalidEnvelope));
    }

    #[test]
    fn envelope_seal_open_roundtrip_with_transient_key() {
        let key = vec![0x42u8; 32];
        let nonce = vec![0x11u8; 12];
        let aad = b"Aegis-Vault-Header-v1".to_vec();
        let pt = b"oath-export-backup".to_vec();
        let env = envelope_seal(key.clone(), pt.clone(), aad.clone(), nonce).unwrap();
        assert_eq!(&env[..5], &[0x41, 0x45, 0x47, 0x4E, 0x01]);
        assert_eq!(
            envelope_validate(env.clone()).unwrap() as usize,
            env.len() - 17
        );
        let back = envelope_open(key, env.clone(), aad).unwrap();
        assert_eq!(back, pt);
        let mut tampered = env;
        tampered[20] ^= 0x01;
        assert_eq!(
            envelope_open(
                vec![0x42u8; 32],
                tampered,
                b"Aegis-Vault-Header-v1".to_vec()
            ),
            Err(BridgeError::CryptoError)
        );
    }

    #[test]
    fn envelope_seal_parity_matches_firmware_persistence_ceiling() {
        // Canonical: crates/aegis-fido-firmware/src/persistence.rs
        // MAX_PLAINTEXT_BYTES = 4096, MAX_ENVELOPE_BYTES = 4129
        // (== universal-device-sdk envelope ceilings; bridge keeps a
        // documented copy only, no firmware/SDK dependency in the cdylib).
        assert_eq!(MAX_PLAINTEXT_BYTES, 4096);
        assert_eq!(MAX_ENVELOPE_BYTES, 4129);
        assert_eq!(MIN_ENVELOPE_LEN, 33);
        let key = vec![0x42u8; 32];
        let nonce = vec![0x11u8; 12];
        let aad = b"Aegis-Vault-Header-v1".to_vec();
        let pt = vec![0x5Au8; MAX_PLAINTEXT_BYTES];
        let env = envelope_seal(key.clone(), pt.clone(), aad.clone(), nonce).unwrap();
        let back = envelope_open(key, env, aad).unwrap();
        assert_eq!(back, pt);
        let over = vec![0x5Au8; MAX_PLAINTEXT_BYTES + 1];
        assert_eq!(
            envelope_seal(
                vec![0x42u8; 32],
                over,
                b"Aegis-Vault-Header-v1".to_vec(),
                vec![0x11u8; 12]
            ),
            Err(BridgeError::Overflow)
        );
    }

    /// Cross-vector: byte-exact framing shared with the SDK and firmware
    /// (R15/R16, section 9). Mirrors SDK
    /// `aegn_cross_vector_matches_bridge_and_firmware` in
    /// `crates/universal-device-sdk/src/envelope.rs`: same fixed nonce
    /// (`01..0C`), same opaque `ct + tag` (`0xA5 x 16`, the tag floor),
    /// same expected wire bytes `MAGIC[4] | VER[1] | NONCE[12] | CT+TAG`.
    /// Any framing drift on either side breaks both tests. Also pins the
    /// fail-closed deltas vs the old bridge (oversize + zero-nonce reject).
    #[test]
    fn envelope_cross_vector_matches_sdk_framing() {
        assert_eq!(ENVELOPE_MAGIC, [0x41, 0x45, 0x47, 0x4E]);
        assert_eq!(ENVELOPE_VERSION, 0x01);
        assert_eq!(MIN_ENVELOPE_LEN, 33);
        assert_eq!(MAX_ENVELOPE_BYTES, 4129);
        let nonce: Vec<u8> = (1u8..=12).collect();
        let ct = vec![0xA5u8; 16];
        let mut expected = Vec::with_capacity(MIN_ENVELOPE_LEN);
        expected.extend_from_slice(&ENVELOPE_MAGIC);
        expected.push(ENVELOPE_VERSION);
        expected.extend_from_slice(&nonce);
        expected.extend_from_slice(&ct);
        assert_eq!(expected.len(), MIN_ENVELOPE_LEN);
        // SDK-sealed framing validates unchanged on the bridge side.
        assert_eq!(
            envelope_validate(expected.clone()).unwrap() as usize,
            ct.len()
        );
        assert_eq!(&expected[0..4], &ENVELOPE_MAGIC);
        assert_eq!(expected[4], ENVELOPE_VERSION);
        assert_eq!(&expected[5..17], nonce.as_slice());
        // Bridge seal echoes the same header layout (AEAD ct stays opaque).
        let env = envelope_seal(
            vec![0x42u8; 32],
            b"cross-vector".to_vec(),
            b"Aegis-Vault-Header-v1".to_vec(),
            nonce.clone(),
        )
        .unwrap();
        assert_eq!(&env[0..4], &ENVELOPE_MAGIC);
        assert_eq!(env[4], ENVELOPE_VERSION);
        assert_eq!(&env[5..17], nonce.as_slice());
        assert_eq!(
            envelope_validate(env.clone()).unwrap() as usize,
            env.len() - 17
        );
        // Fail-closed deltas (mirror SDK TooLarge / ZeroNonce, wire 0x04).
        assert_eq!(
            envelope_validate(vec![0x41u8; MAX_ENVELOPE_BYTES + 1]),
            Err(BridgeError::Overflow)
        );
        let mut zero_nonce_env = expected.clone();
        zero_nonce_env[5..17].copy_from_slice(&[0u8; 12]);
        assert_eq!(
            envelope_validate(zero_nonce_env),
            Err(BridgeError::InvalidEnvelope)
        );
        assert_eq!(
            envelope_seal(
                vec![0x42u8; 32],
                b"pt".to_vec(),
                b"Aegis-Vault-Header-v1".to_vec(),
                vec![0u8; 12]
            ),
            Err(BridgeError::CryptoError)
        );
    }

    #[test]
    fn cose_parse_only_never_renders_key_bytes() {
        let cbor = CoseKey::p256(vec![1u8; 32], vec![2u8; 32]).to_cbor_bytes();
        let info = cose_key_info(cbor).unwrap();
        assert_eq!(info, "kty=EC2 crv=1 alg=-7 x_len=32 y_len=32");
        assert_eq!(
            cose_key_info(b"not-cbor".to_vec()),
            Err(BridgeError::InvalidCose)
        );
    }

    #[test]
    fn oath_response_parses_code_only() {
        let json =
            r#"{"account":"GitHub:alice","code":"287082","remaining_seconds":28}"#.to_string();
        let parsed = oath_parse_response(json).unwrap();
        assert_eq!(parsed.account, "GitHub:alice");
        assert_eq!(parsed.code, "287082");
        assert_eq!(parsed.remaining_seconds, 28);
        assert!(oath_code_valid("287082".to_string()));
        assert!(!oath_code_valid("28708".to_string()));
        assert!(!oath_code_valid("287082123".to_string()));
        assert!(!oath_code_valid("28a082".to_string()));
        let bad =
            r#"{"account":"GitHub:alice","code":"28a082","remaining_seconds":28}"#.to_string();
        assert_eq!(oath_parse_response(bad), Err(BridgeError::InvalidOath));
    }

    #[test]
    fn app_lock_derive_is_deterministic_and_salted() {
        let salt = vec![0x11u8; 16];
        let a = app_lock_derive(b"correct-horse".to_vec(), salt.clone()).unwrap();
        let b = app_lock_derive(b"correct-horse".to_vec(), salt.clone()).unwrap();
        assert_eq!(a.len(), APP_LOCK_VERIFIER_LEN);
        assert_eq!(a, b);
        let c = app_lock_derive(b"correct-horse".to_vec(), vec![0x22u8; 16]).unwrap();
        assert_ne!(a, c);
        let d = app_lock_derive(b"wrong-horse".to_vec(), salt).unwrap();
        assert_ne!(a, d);
    }

    #[test]
    fn app_lock_derive_rejects_bad_inputs() {
        assert_eq!(
            app_lock_derive(vec![], vec![0x11u8; 16]),
            Err(BridgeError::CryptoError)
        );
        assert_eq!(
            app_lock_derive(vec![0x41u8; 129], vec![0x11u8; 16]),
            Err(BridgeError::CryptoError)
        );
        assert_eq!(
            app_lock_derive(b"pw".to_vec(), vec![0x11u8; 15]),
            Err(BridgeError::CryptoError)
        );
        assert_eq!(
            app_lock_derive(b"pw".to_vec(), vec![0x11u8; 65]),
            Err(BridgeError::CryptoError)
        );
    }

    #[test]
    fn oath_remaining_mirrors_firmware_window() {
        assert_eq!(oath_remaining_seconds(59), 1);
        assert_eq!(oath_remaining_seconds(60), 30);
        assert_eq!(oath_remaining_seconds(0), 30);
    }

    #[test]
    fn wifi_password_bounds_match_firmware() {
        assert!(wifi_password_valid("nova-senha-123".to_string()));
        assert!(!wifi_password_valid("curta".to_string()));
        assert!(!wifi_password_valid("x".repeat(64)));
        assert!(!wifi_password_valid("senha-com-é".to_string()));
    }

    #[test]
    fn oath_account_query_mirrors_firmware() {
        assert_eq!(
            oath_account_from_path("/oath/code?account=GitHub".to_string()),
            Some("GitHub".to_string())
        );
        assert_eq!(oath_account_from_path("/oath/code".to_string()), None);
        assert_eq!(
            oath_account_from_path("/oath/code?account=".to_string()),
            None
        );
    }

    /// secp256k1 generator G vectors (same as core known-answer tests).
    const G_COMPRESSED_HEX: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const G_UNCOMPRESSED_HEX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    const ED_ZERO_PUB_HEX: &str =
        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

    #[test]
    fn wallet_address_known_answers() {
        assert_eq!(
            wallet_address("bitcoin".to_string(), G_COMPRESSED_HEX.to_string()).unwrap(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        assert_eq!(
            wallet_address("ETHEREUM".to_string(), G_UNCOMPRESSED_HEX.to_string()).unwrap(),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
        assert_eq!(
            wallet_address(" sol ".to_string(), ED_ZERO_PUB_HEX.to_string()).unwrap(),
            "4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS"
        );
    }

    #[test]
    fn envelope_parity_with_firmware_limits() {
        // Firmware: persistence.rs MAX_PLAINTEXT_BYTES = 4096,
        // MAX_ENVELOPE_BYTES = 4 + 1 + 12 + 4096 + 16 = 4129.
        assert_eq!(MAX_PLAINTEXT_BYTES, 4096);
        assert_eq!(MAX_ENVELOPE_BYTES, 4129);
        // Bridge seal must accept firmware-valid plaintext up to 4096
        // (regression: old 512 cap rejected valid payloads).
        let key = vec![0x42u8; 32];
        let nonce = vec![0x11u8; 12];
        let aad = b"Aegis-Vault-Header-v1".to_vec();
        let max_pt = vec![0xABu8; MAX_PLAINTEXT_BYTES];
        let env = envelope_seal(key.clone(), max_pt.clone(), aad.clone(), nonce).unwrap();
        assert_eq!(env.len(), MAX_ENVELOPE_BYTES);
        let back = envelope_open(key, env, aad).unwrap();
        assert_eq!(back, max_pt);
        // One byte over the firmware ceiling is rejected (fail-closed).
        let over = vec![0xABu8; MAX_PLAINTEXT_BYTES + 1];
        assert_eq!(
            envelope_seal(vec![0x42u8; 32], over, vec![], vec![0x11u8; 12]),
            Err(BridgeError::Overflow)
        );
        // BLE transport cap stays frozen at 512 (independent of seal cap).
        assert_eq!(CONTROL_POINT_LENGTH, 512);
    }

    #[test]
    fn wallet_address_rejects_bad_inputs() {
        // Rede desconhecida.
        assert_eq!(
            wallet_address("dogecoin".to_string(), G_COMPRESSED_HEX.to_string()),
            Err(BridgeError::InvalidAddress)
        );
        // Hex ímpar, vazio e não-hex.
        assert_eq!(
            wallet_address("bitcoin".to_string(), "abc".to_string()),
            Err(BridgeError::InvalidAddress)
        );
        assert_eq!(
            wallet_address("bitcoin".to_string(), "".to_string()),
            Err(BridgeError::InvalidAddress)
        );
        assert_eq!(
            wallet_address("bitcoin".to_string(), "zz".to_string()),
            Err(BridgeError::InvalidAddress)
        );
        // Tamanhos trocados entre redes.
        assert_eq!(
            wallet_address("bitcoin".to_string(), ED_ZERO_PUB_HEX.to_string()),
            Err(BridgeError::InvalidAddress)
        );
        assert_eq!(
            wallet_address("ethereum".to_string(), G_COMPRESSED_HEX.to_string()),
            Err(BridgeError::InvalidAddress)
        );
        assert_eq!(
            wallet_address("solana".to_string(), G_COMPRESSED_HEX.to_string()),
            Err(BridgeError::InvalidAddress)
        );
        // Prefixo comprimido inválido (0x04 com 33B).
        let mut bad_prefix = String::from("04");
        bad_prefix.push_str(&G_COMPRESSED_HEX[2..]);
        assert_eq!(
            wallet_address("bitcoin".to_string(), bad_prefix),
            Err(BridgeError::InvalidAddress)
        );
    }

    #[test]
    fn totp_format_display_formats_and_preserves() {
        assert_eq!(totp_format_display("123456".to_string()), "123 456");
        assert_eq!(totp_format_display("12345678".to_string()), "1234 5678");
        assert_eq!(totp_format_display("1234567".to_string()), "123 4567");
        assert_eq!(totp_format_display("  123456  ".to_string()), "123 456");
        assert_eq!(totp_format_display("123 456".to_string()), "123 456");
        assert_eq!(totp_format_display("1234 5678".to_string()), "1234 5678");
        // Non-matching lengths and non-digits are preserved as-is.
        assert_eq!(totp_format_display("12345".to_string()), "12345");
        assert_eq!(totp_format_display("123456789".to_string()), "123456789");
        assert_eq!(totp_format_display("123a56".to_string()), "123a56");
        assert_eq!(totp_format_display("".to_string()), "");
    }

    #[test]
    fn otpauth_extract_uri_success() {
        // Standard URI with issuer prefix in label.
        let parsed = otpauth_extract_label_and_secret(
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP".to_string(),
        )
        .unwrap();
        assert_eq!(parsed.issuer, "GitHub");
        assert_eq!(parsed.account_name, "alice");
        assert_eq!(parsed.secret_base32, "JBSWY3DPEHPK3PXP");
        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period, 30);

        // URI with issuer parameter overriding or setting issuer, custom digits and period.
        let parsed2 = otpauth_extract_label_and_secret(
            "otpauth://totp/alice@example.com?secret=jbswy3dpehpk3pxp&issuer=Example&digits=8&period=60".to_string(),
        ).unwrap();
        assert_eq!(parsed2.issuer, "Example");
        assert_eq!(parsed2.account_name, "alice@example.com");
        assert_eq!(parsed2.secret_base32, "JBSWY3DPEHPK3PXP");
        assert_eq!(parsed2.digits, 8);
        assert_eq!(parsed2.period, 60);

        // URL encoded label and query param.
        let parsed3 = otpauth_extract_label_and_secret(
            "otpauth://totp/Acme%20Corp:bob%2Btest@email.com?secret=JBSW%20Y3DP&issuer=Acme%20Corp"
                .to_string(),
        )
        .unwrap();
        assert_eq!(parsed3.issuer, "Acme Corp");
        assert_eq!(parsed3.account_name, "bob+test@email.com");
        assert_eq!(parsed3.secret_base32, "JBSWY3DP");

        // Label without colon.
        let parsed4 = otpauth_extract_label_and_secret(
            "otpauth://totp/SingleLabel?secret=JBSWY3DPEHPK3PXP".to_string(),
        )
        .unwrap();
        assert_eq!(parsed4.issuer, "");
        assert_eq!(parsed4.account_name, "SingleLabel");
        assert_eq!(parsed4.secret_base32, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn otpauth_extract_raw_secret_success() {
        // Pure Base32 string.
        let p1 = otpauth_extract_label_and_secret("JBSWY3DPEHPK3PXP".to_string()).unwrap();
        assert_eq!(p1.issuer, "");
        assert_eq!(p1.account_name, "");
        assert_eq!(p1.secret_base32, "JBSWY3DPEHPK3PXP");
        assert_eq!(p1.digits, 6);
        assert_eq!(p1.period, 30);

        // Lowercase with spaces.
        let p2 = otpauth_extract_label_and_secret("  jbsw y3dp ehpk 3pxp  ".to_string()).unwrap();
        assert_eq!(p2.secret_base32, "JBSWY3DPEHPK3PXP");

        // With hyphens.
        let p3 = otpauth_extract_label_and_secret("JBSW-Y3DP-EHPK-3PXP".to_string()).unwrap();
        assert_eq!(p3.secret_base32, "JBSWY3DPEHPK3PXP");

        // With padding.
        let p4 = otpauth_extract_label_and_secret("JBSWY3DPEHPK3PXP===".to_string()).unwrap();
        assert_eq!(p4.secret_base32, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn otpauth_extract_invalid_fails() {
        assert_eq!(
            otpauth_extract_label_and_secret("".to_string()),
            Err(BridgeError::InvalidOath)
        );
        assert_eq!(
            otpauth_extract_label_and_secret("   ".to_string()),
            Err(BridgeError::InvalidOath)
        );
        // Invalid Base32 characters (8, 9, 0, 1).
        assert_eq!(
            otpauth_extract_label_and_secret("JBSWY3DP890".to_string()),
            Err(BridgeError::InvalidOath)
        );
        // URI without secret.
        assert_eq!(
            otpauth_extract_label_and_secret("otpauth://totp/TestAccount".to_string()),
            Err(BridgeError::InvalidOath)
        );
        // URI with invalid secret.
        assert_eq!(
            otpauth_extract_label_and_secret(
                "otpauth://totp/TestAccount?secret=bad890".to_string()
            ),
            Err(BridgeError::InvalidOath)
        );
        // Unsupported schemes/types.
        assert_eq!(
            otpauth_extract_label_and_secret(
                "ftp://totp/TestAccount?secret=JBSWY3DPEHPK3PXP".to_string()
            ),
            Err(BridgeError::InvalidOath)
        );
        assert_eq!(
            otpauth_extract_label_and_secret(
                "otpauth://unknown/TestAccount?secret=JBSWY3DPEHPK3PXP".to_string()
            ),
            Err(BridgeError::InvalidOath)
        );
    }

    #[test]
    fn ble_split_fragments_opcode_validation_matrix() {
        // Must accept 0x81 (PING) and 0x83 (MSG).
        assert!(ble_split_fragments(0x81, vec![1, 2, 3]).is_ok());
        assert!(ble_split_fragments(0x83, vec![1, 2, 3]).is_ok());

        // Must accept all bind-mgmt opcodes 0x28..=0x2D.
        for op in 0x28..=0x2D {
            assert!(
                ble_split_fragments(op, vec![1, 2, 3]).is_ok(),
                "opcode {:#04x} should be accepted",
                op
            );
        }

        // Must accept all OTA opcodes 0x30..=0x34.
        for op in 0x30..=0x34 {
            assert!(
                ble_split_fragments(op, vec![1, 2, 3]).is_ok(),
                "opcode {:#04x} should be accepted",
                op
            );
        }

        // Must reject 0x2E, 0x2F and 0xBE fail-closed.
        assert_eq!(
            ble_split_fragments(0x2E, vec![1]),
            Err(BridgeError::InvalidOpcode)
        );
        assert_eq!(
            ble_split_fragments(0x2F, vec![1]),
            Err(BridgeError::InvalidOpcode)
        );
        assert_eq!(
            ble_split_fragments(0xBE, vec![1]),
            Err(BridgeError::InvalidOpcode)
        );
    }

    #[test]
    fn secure_guard_bridge_roundtrip() {
        let policy = SecureGuardPolicyDto {
            wipe_on_5_failures: true,
            session_duration_ms: 60_000,
            inactivity_timeout_ms: 30_000,
            protect_keys_and_aegn: true,
            protect_oath: true,
            test_mode_non_destructive_wipe: true,
        };
        let cfg_bytes = secure_guard_encode_config(policy.clone()).expect("encode config");
        assert!(!cfg_bytes.is_empty());

        let unlock_bytes = secure_guard_encode_unlock(b"1234".to_vec()).expect("encode unlock");
        assert!(!unlock_bytes.is_empty());

        let lock_bytes = secure_guard_encode_lock().expect("encode lock");
        assert!(!lock_bytes.is_empty());

        let prov_bytes = secure_guard_encode_provision(b"1234".to_vec(), vec![], false, false)
            .expect("encode provision");
        assert!(!prov_bytes.is_empty());

        let chg_bytes = secure_guard_encode_change_pin(b"1234".to_vec(), b"5678".to_vec())
            .expect("encode change pin");
        assert!(!chg_bytes.is_empty());

        let rec_bytes = secure_guard_encode_recover(b"rec_code".to_vec(), b"5678".to_vec())
            .expect("encode recover");
        assert!(!rec_bytes.is_empty());

        let wipe_bytes =
            secure_guard_encode_wipe(1, "CONFIRM_WIPE".to_string()).expect("encode wipe");
        assert!(!wipe_bytes.is_empty());
    }

    // ---- Manual C-ABI test drivers (same-crate `extern "C"` calls are
    // safe; raw-pointer soundness lives in `input_bytes` / `emit_*`, which
    // carry the SAFETY justifications) ----

    /// Query-then-fill driver for C entries behind a single-input adapter.
    fn c_roundtrip(
        input: &[u8],
        call: impl Fn(*const u8, usize, *mut u8, usize, *mut usize) -> i32,
    ) -> Result<Vec<u8>, i32> {
        let mut need: usize = 0;
        let reported = {
            call(
                input.as_ptr(),
                input.len(),
                core::ptr::null_mut(),
                0,
                &mut need,
            )
        };
        if reported < 0 {
            return Err(reported);
        }
        assert_eq!(reported as usize, need);
        let mut buf = vec![0u8; need];
        let mut got: usize = 0;
        let code = {
            call(
                input.as_ptr(),
                input.len(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut got,
            )
        };
        if code != 0 {
            return Err(code);
        }
        assert_eq!(got, need);
        Ok(buf)
    }

    /// Adapter for two-input byte entries.
    fn c_roundtrip2(
        first: &[u8],
        second: &[u8],
        call: impl Fn(*const u8, usize, *const u8, usize, *mut u8, usize, *mut usize) -> i32,
    ) -> Result<Vec<u8>, i32> {
        let mut need: usize = 0;
        let reported = {
            call(
                first.as_ptr(),
                first.len(),
                second.as_ptr(),
                second.len(),
                core::ptr::null_mut(),
                0,
                &mut need,
            )
        };
        if reported < 0 {
            return Err(reported);
        }
        assert_eq!(reported as usize, need);
        let mut buf = vec![0u8; need];
        let mut got: usize = 0;
        let code = {
            call(
                first.as_ptr(),
                first.len(),
                second.as_ptr(),
                second.len(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut got,
            )
        };
        if code != 0 {
            return Err(code);
        }
        assert_eq!(got, need);
        Ok(buf)
    }

    #[test]
    fn ffi_version_and_status_codes() {
        // `aegis_bridge_version` returns a 'static NUL-terminated string.
        // SAFETY: read-only access through it is sound for 'static data.
        let version = unsafe { core::ffi::CStr::from_ptr(aegis_bridge_version()) };
        assert_eq!(version.to_bytes(), b"1.0.0");
        assert_eq!(AEGIS_STATUS_OK, 0);
        assert_eq!(
            status_of(BridgeError::InvalidOpcode),
            AEGIS_ERR_INVALID_OPCODE
        );
        assert_eq!(status_of(BridgeError::Overflow), AEGIS_ERR_OVERFLOW);
        assert_eq!(
            status_of(BridgeError::SecureGuardError),
            AEGIS_ERR_SECURE_GUARD
        );
    }

    #[test]
    fn ffi_ble_constants_and_fragments() {
        let raw = c_roundtrip(&[], |p, n, o, c, l| {
            let _ = (p, n);
            aegis_ble_constants(o, c, l)
        })
        .unwrap();
        let json = core::str::from_utf8(&raw).unwrap();
        assert!(json.contains("\"service_uuid\":65533"));
        assert!(json.contains("\"max_fragment_bytes\":244"));

        let payload = vec![0xABu8; 300];
        let mut need: usize = 0;
        let reported = {
            aegis_ble_split_fragments(
                OP_MSG,
                payload.as_ptr(),
                payload.len(),
                core::ptr::null_mut(),
                0,
                &mut need,
            )
        };
        assert!(reported >= 0);
        let mut buf = vec![0u8; need];
        let mut got: usize = 0;
        let code = {
            aegis_ble_split_fragments(
                OP_MSG,
                payload.as_ptr(),
                payload.len(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut got,
            )
        };
        assert_eq!(code, AEGIS_STATUS_OK);
        let json = core::str::from_utf8(&buf[..got]).unwrap();
        assert!(json.starts_with("{\"count\":2,\"fragments\":["));

        // Invalid opcode maps to the typed error code.
        let mut small = [0u8; 8];
        let mut got: usize = 0;
        let code = {
            aegis_ble_split_fragments(
                0x2E,
                payload.as_ptr(),
                payload.len(),
                small.as_mut_ptr(),
                small.len(),
                &mut got,
            )
        };
        assert_eq!(code, AEGIS_ERR_INVALID_OPCODE);
    }

    #[test]
    fn ffi_envelope_validate_seal_open() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let aad = b"Aegis-Vault-Header-v1".to_vec();
        let pt = b"oath-export-backup".to_vec();
        let env = c_roundtrip(&pt, |p, n, o, c, l| {
            {
                aegis_envelope_seal(
                    key.as_ptr(),
                    key.len(),
                    p,
                    n,
                    aad.as_ptr(),
                    aad.len(),
                    nonce.as_ptr(),
                    nonce.len(),
                    o,
                    c,
                    l,
                )
            }
        })
        .unwrap();
        assert_eq!(&env[..5], &[0x41, 0x45, 0x47, 0x4E, 0x01]);

        let mut ct_len: u32 = 0;
        let code = { aegis_envelope_validate(env.as_ptr(), env.len(), &mut ct_len) };
        assert_eq!(code, AEGIS_STATUS_OK);
        assert_eq!(ct_len as usize, env.len() - 17);

        let back = c_roundtrip(&env, |p, n, o, c, l| {
            {
                aegis_envelope_open(
                    key.as_ptr(),
                    key.len(),
                    p,
                    n,
                    aad.as_ptr(),
                    aad.len(),
                    o,
                    c,
                    l,
                )
            }
        })
        .unwrap();
        assert_eq!(back, pt);

        // Tampered envelope surfaces the crypto error code.
        let mut tampered = env.clone();
        tampered[20] ^= 0x01;
        let err = c_roundtrip(&tampered, |p, n, o, c, l| {
            {
                aegis_envelope_open(
                    key.as_ptr(),
                    key.len(),
                    p,
                    n,
                    aad.as_ptr(),
                    aad.len(),
                    o,
                    c,
                    l,
                )
            }
        });
        assert_eq!(err, Err(AEGIS_ERR_CRYPTO));

        // NULL envelope with nonzero length is rejected before parsing.
        let mut ct_len: u32 = 0;
        let code = { aegis_envelope_validate(core::ptr::null(), 33, &mut ct_len) };
        assert_eq!(code, AEGIS_ERR_NULL_POINTER);
    }

    #[test]
    fn ffi_small_buffer_reports_required_size() {
        let payload = b"hello-ctap".to_vec();
        let mut need: usize = 0;
        let reported = {
            aegis_ble_split_fragments(
                OP_MSG,
                payload.as_ptr(),
                payload.len(),
                core::ptr::null_mut(),
                0,
                &mut need,
            )
        };
        assert!(reported > 1);
        let mut tiny = vec![0u8; need - 1];
        let mut got: usize = usize::MAX;
        let code = {
            aegis_ble_split_fragments(
                OP_MSG,
                payload.as_ptr(),
                payload.len(),
                tiny.as_mut_ptr(),
                tiny.len(),
                &mut got,
            )
        };
        assert_eq!(code, AEGIS_ERR_BUFFER_TOO_SMALL);
        assert_eq!(got, need);
    }

    #[test]
    fn ffi_oath_parse_predicates_and_format() {
        let json =
            r#"{"account":"GitHub:alice","code":"287082","remaining_seconds":28}"#.as_bytes();
        let raw = c_roundtrip(json, |p, n, o, c, l| {
            aegis_oath_parse_response(p, n, o, c, l)
        })
        .unwrap();
        let out = core::str::from_utf8(&raw).unwrap();
        assert!(out.contains("\"account\":\"GitHub:alice\""));
        assert!(out.contains("\"code\":\"287082\""));
        assert!(out.contains("\"remaining_seconds\":28}"));

        let mut valid: u8 = 0;
        let code = { aegis_oath_code_valid(b"287082".as_ptr(), 6, &mut valid) };
        assert_eq!(code, AEGIS_STATUS_OK);
        assert_eq!(valid, 1);

        let mut remaining: u32 = 0;
        let code = { aegis_oath_remaining_seconds(59, &mut remaining) };
        assert_eq!(code, AEGIS_STATUS_OK);
        assert_eq!(remaining, 1);

        let raw = c_roundtrip(b"123456", |p, n, o, c, l| {
            aegis_totp_format_display(p, n, o, c, l)
        })
        .unwrap();
        assert_eq!(raw, b"123 456");
    }

    #[test]
    fn ffi_account_from_path_present_and_absent() {
        let path = b"/oath/code?account=GitHub".to_vec();
        let mut need: usize = 0;
        let reported = {
            aegis_oath_account_from_path(
                path.as_ptr(),
                path.len(),
                core::ptr::null_mut(),
                0,
                &mut need,
            )
        };
        // Query phase reports the required length (like every byte emitter);
        // presence is signalled by the fill-phase `1` below.
        assert_eq!(reported as usize, need);
        assert_eq!(need, b"GitHub".len());
        let mut buf = vec![0u8; need];
        let mut got: usize = 0;
        let present = {
            aegis_oath_account_from_path(
                path.as_ptr(),
                path.len(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut got,
            )
        };
        assert_eq!(present, 1);
        assert_eq!(&buf[..got], b"GitHub");

        let missing = b"/oath/code".to_vec();
        let mut got: usize = usize::MAX;
        let absent = {
            aegis_oath_account_from_path(
                missing.as_ptr(),
                missing.len(),
                core::ptr::null_mut(),
                0,
                &mut got,
            )
        };
        assert_eq!(absent, 0);
        assert_eq!(got, 0);
    }

    #[test]
    fn ffi_app_lock_derive_and_wifi_hint() {
        let password = b"correct-horse".to_vec();
        let salt = vec![0x11u8; 16];
        let verifier = c_roundtrip2(&password, &salt, |p, pn, s, sn, o, c, l| {
            aegis_app_lock_derive(p, pn, s, sn, o, c, l)
        })
        .unwrap();
        assert_eq!(verifier.len(), APP_LOCK_VERIFIER_LEN);

        let mut valid: u8 = 0;
        let pw = b"nova-senha-123".to_vec();
        let code = { aegis_wifi_password_valid(pw.as_ptr(), pw.len(), &mut valid) };
        assert_eq!(code, AEGIS_STATUS_OK);
        assert_eq!(valid, 1);
    }

    #[test]
    fn ffi_cose_wallet_otpauth() {
        let cbor = CoseKey::p256(vec![1u8; 32], vec![2u8; 32]).to_cbor_bytes();
        let raw = c_roundtrip(&cbor, |p, n, o, c, l| aegis_cose_key_info(p, n, o, c, l)).unwrap();
        assert_eq!(raw, b"kty=EC2 crv=1 alg=-7 x_len=32 y_len=32");

        let network = b"bitcoin".to_vec();
        let hex = b"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_vec();
        let raw = c_roundtrip2(&network, &hex, |p, pn, s, sn, o, c, l| {
            aegis_wallet_address(p, pn, s, sn, o, c, l)
        })
        .unwrap();
        assert_eq!(raw, b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");

        let uri = b"otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP".to_vec();
        let raw = c_roundtrip(&uri, |p, n, o, c, l| aegis_otpauth_extract(p, n, o, c, l)).unwrap();
        let out = core::str::from_utf8(&raw).unwrap();
        assert!(out.contains("\"issuer\":\"GitHub\""));
        assert!(out.contains("\"secret_base32\":\"JBSWY3DPEHPK3PXP\""));
    }

    #[test]
    fn ffi_secure_guard_encode_and_parse() {
        let pin = b"1234".to_vec();
        let unlock = c_roundtrip(&pin, |p, n, o, c, l| {
            aegis_secure_guard_encode_unlock(p, n, o, c, l)
        })
        .unwrap();
        assert!(!unlock.is_empty());

        let lock = c_roundtrip(&[], |p, n, o, c, l| {
            let _ = (p, n);
            aegis_secure_guard_encode_lock(o, c, l)
        });
        // `c_roundtrip` passes a possibly-dangling empty input pointer with
        // length 0, which lock ignores; the call must still succeed.
        let lock = lock.unwrap();
        assert!(!lock.is_empty());

        // Minimal CBOR status map: {"state": 4, "unlocked": true}.
        let payload: Vec<u8> = vec![
            0xA2, 0x65, b's', b't', b'a', b't', b'e', 0x04, 0x68, b'u', b'n', b'l', b'o', b'c',
            b'k', b'e', b'd', 0xF5,
        ];
        let raw = c_roundtrip(&payload, |p, n, o, c, l| {
            aegis_secure_guard_parse_status(p, n, o, c, l)
        })
        .unwrap();
        let out = core::str::from_utf8(&raw).unwrap();
        assert!(out.contains("\"state\":4"));
        assert!(out.contains("\"is_unlocked\":true"));
        assert!(out.contains("\"state_name\":\"Unlocked\""));

        // Policy JSON round-trips through config encoding (CBOR bytes out).
        let policy = SecureGuardPolicyDto {
            wipe_on_5_failures: true,
            session_duration_ms: 60_000,
            inactivity_timeout_ms: 30_000,
            protect_keys_and_aegn: true,
            protect_oath: true,
            test_mode_non_destructive_wipe: true,
        };
        let policy_json = policy_json(&policy);
        let cfg = c_roundtrip(policy_json.as_bytes(), |p, n, o, c, l| {
            aegis_secure_guard_encode_config(p, n, o, c, l)
        })
        .unwrap();
        assert!(!cfg.is_empty());

        // Malformed policy JSON is invalid input, never a defaulted policy.
        let bad = c_roundtrip(b"{\"wipe_on_5_failures\":true}", |p, n, o, c, l| {
            aegis_secure_guard_encode_config(p, n, o, c, l)
        });
        assert_eq!(bad, Err(AEGIS_ERR_INVALID_JSON));
    }

    #[test]
    fn ffi_rejects_null_out_len() {
        let payload = b"hello".to_vec();
        let code = {
            aegis_ble_split_fragments(
                OP_MSG,
                payload.as_ptr(),
                payload.len(),
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(code, AEGIS_ERR_NULL_POINTER);
    }
}
