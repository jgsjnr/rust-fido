#![allow(clippy::empty_line_after_doc_comments)] // Uniffi-generated scaffolding in OUT_DIR (third-party, cannot edit); behavior identical.
//! UniFFI bridge for the Android app (`aegis_bridge` cdylib).
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

uniffi::include_scaffolding!("aegis_bridge");

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
/// Reassemble cap (== envelope MAX-ESP).
pub const CONTROL_POINT_LENGTH: usize = 512;
/// `AEGN` envelope magic.
pub const ENVELOPE_MAGIC: [u8; 4] = [0x41, 0x45, 0x47, 0x4E];
/// `AEGN` envelope version.
pub const ENVELOPE_VERSION: u8 = 0x01;
/// `MAGIC[4] | VER[1] | NONCE[12] | TAG[16]` floor (empty ciphertext).
pub const MIN_ENVELOPE_LEN: usize = 33;
/// Max plaintext accepted by seal (firmware `MAX_PLAINTEXT_BYTES`).
pub const MAX_PLAINTEXT_BYTES: usize = 512;
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

/// Splits a CTAP2-BLE payload into FFF1 fragments.
///
/// First fragment: `[opcode, len_hi, len_lo, data..]` (up to 241B of data);
/// continuations: `[seq, data..]` with `seq = 0, 1, ...` (up to 243B each),
/// matching `BleReassembler::feed`. `CANCEL` is single-byte and rejected here.
pub fn ble_split_fragments(opcode: u8, payload: Vec<u8>) -> Result<Vec<Vec<u8>>, BridgeError> {
    if opcode != OP_PING && opcode != OP_MSG {
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

/// Validates a `POST /ctap` envelope (`AEGN` magic + version + min length).
/// Returns the ciphertext length on success (content delegates to device).
pub fn envelope_validate(envelope: Vec<u8>) -> Result<u32, BridgeError> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(BridgeError::InvalidEnvelope);
    }
    if envelope[0..4] != ENVELOPE_MAGIC || envelope[4] != ENVELOPE_VERSION {
        return Err(BridgeError::InvalidEnvelope);
    }
    Ok((envelope.len() - (4 + 1 + 12)) as u32)
}

/// Seals `plaintext` into an `AEGN` envelope with an explicit nonce.
///
/// `key` (32B) and `nonce` (12B) are transient caller buffers, zeroized
/// before return. Deterministic nonce keeps UniFFI tests reproducible;
/// the app must supply a fresh random nonce per seal (device TRNG guidance).
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

/// PBKDF2-SHA1 iterations for the app lock verifier (mirrors YKOATH set_password).
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

#[cfg(test)]
mod tests {
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
        env.extend_from_slice(&[0u8; 12]);
        env.extend_from_slice(&[9u8; 20]);
        env.extend_from_slice(&[0u8; 16]);
        assert!(envelope_validate(env.clone()).is_ok());
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
    const G_COMPRESSED_HEX: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const G_UNCOMPRESSED_HEX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    const ED_ZERO_PUB_HEX: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

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
}
