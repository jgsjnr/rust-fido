use crate::pm_jni::{pm_frame_unwrap, pm_frame_wrap, pm_status_name};
use crate::{
    app_lock_derive, ble_constants, ble_split_fragments, cose_key_info, envelope_open,
    envelope_seal, envelope_validate, oath_account_from_path, oath_code_valid, oath_parse_response,
    oath_remaining_seconds, otpauth_extract_label_and_secret, secure_guard_encode_change_pin,
    secure_guard_encode_config, secure_guard_encode_lock, secure_guard_encode_provision,
    secure_guard_encode_recover, secure_guard_encode_unlock, secure_guard_encode_wipe,
    secure_guard_parse_status, totp_format_display, wallet_address, wifi_password_valid,
    BridgeError, OathCode, OtpAuthParsed, SecureGuardPolicyDto, SecureGuardStatusDto,
};

// =========================================================================
// Manual C ABI for JNI/JNA callers (replaces the removed UniFFI runtime).
//
// Design contract (stable, versioned via `aegis_bridge_version`):
// - Every fallible entry returns an `i32` status: `0` (`AEGIS_STATUS_OK`)
//   on success, otherwise a negative `AEGIS_ERR_*` code. `BridgeError`
//   variants map 1:1 to codes `-1..=-9`, so no meaning is lost in transit.
// - Byte outputs use the two-call pattern through
//   `(out: *mut u8, out_cap: usize, out_len: *mut usize)`:
//   `out == NULL` queries the required length (written to `*out_len` and
//   returned as `i32`); otherwise `out_cap` must hold the value or
//   `AEGIS_ERR_BUFFER_TOO_SMALL` is returned with `*out_len` set to the
//   required size so the caller can retry. `out_len` itself is never NULL.
// - Inputs are `(ptr: *const u8, len: usize)` plus explicit scalars. A NULL
//   pointer with `len == 0` denotes the empty input; NULL with `len > 0`
//   is `AEGIS_ERR_NULL_POINTER`. Strings must be valid UTF-8
//   (`AEGIS_ERR_INVALID_UTF8` otherwise).
// - Structured values cross this edge as JSON objects only (typed Rust
//   structs rule the inside; JSON is restricted to FFI/JNI edges): outputs
//   for `BleInfo`, `OathCode`, `OtpAuthParsed`, `SecureGuardStatusDto`;
//   input for `SecureGuardPolicyDto`. Key order is fixed (serializer order)
//   but parsers accept any order. This JSON is a JNI-edge encoding only —
//   never a wire format.
// - Errors carry no payload (never secrets/PII); buffers handed to crypto
//   stay caller-owned and are zeroized on the Rust side where the typed
//   API already does so.
//
// The Android facade (`AegisBridge.kt`) keeps working through its
// pure-Kotlin fallbacks until it binds these symbols via JNA; no Kotlin
// change is implied by this surface.

/// Success status for every `aegis_*` C entry point.
pub const AEGIS_STATUS_OK: i32 = 0;
/// `BridgeError::InvalidOpcode` at the C edge.
pub const AEGIS_ERR_INVALID_OPCODE: i32 = -1;
/// `BridgeError::Overflow` at the C edge.
pub const AEGIS_ERR_OVERFLOW: i32 = -2;
/// `BridgeError::InvalidFragment` at the C edge.
pub const AEGIS_ERR_INVALID_FRAGMENT: i32 = -3;
/// `BridgeError::InvalidEnvelope` at the C edge.
pub const AEGIS_ERR_INVALID_ENVELOPE: i32 = -4;
/// `BridgeError::InvalidCose` at the C edge.
pub const AEGIS_ERR_INVALID_COSE: i32 = -5;
/// `BridgeError::InvalidOath` at the C edge.
pub const AEGIS_ERR_INVALID_OATH: i32 = -6;
/// `BridgeError::CryptoError` at the C edge.
pub const AEGIS_ERR_CRYPTO: i32 = -7;
/// `BridgeError::InvalidAddress` at the C edge.
pub const AEGIS_ERR_INVALID_ADDRESS: i32 = -8;
/// `BridgeError::SecureGuardError` at the C edge.
pub const AEGIS_ERR_SECURE_GUARD: i32 = -9;
/// NULL pointer where the protocol forbids it (input with `len > 0`,
/// any `*_out` slot, or a NULL `out_len`).
pub const AEGIS_ERR_NULL_POINTER: i32 = -10;
/// Caller buffer too small; `*out_len` holds the required size.
pub const AEGIS_ERR_BUFFER_TOO_SMALL: i32 = -11;
/// Input bytes are not valid UTF-8 where a string is required.
pub const AEGIS_ERR_INVALID_UTF8: i32 = -12;
/// Input JSON is malformed or misses required fields.
pub const AEGIS_ERR_INVALID_JSON: i32 = -13;

/// Maps a typed [`BridgeError`] to its stable C status code.
pub(crate) fn status_of(err: BridgeError) -> i32 {
    match err {
        BridgeError::InvalidOpcode => AEGIS_ERR_INVALID_OPCODE,
        BridgeError::Overflow => AEGIS_ERR_OVERFLOW,
        BridgeError::InvalidFragment => AEGIS_ERR_INVALID_FRAGMENT,
        BridgeError::InvalidEnvelope => AEGIS_ERR_INVALID_ENVELOPE,
        BridgeError::InvalidCose => AEGIS_ERR_INVALID_COSE,
        BridgeError::InvalidOath => AEGIS_ERR_INVALID_OATH,
        BridgeError::CryptoError => AEGIS_ERR_CRYPTO,
        BridgeError::InvalidAddress => AEGIS_ERR_INVALID_ADDRESS,
        BridgeError::SecureGuardError => AEGIS_ERR_SECURE_GUARD,
    }
}

/// Borrows caller input bytes without copying.
///
/// NULL with `len == 0` is the empty input; NULL with `len > 0` is rejected.
fn input_bytes<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(AEGIS_ERR_NULL_POINTER);
    }
    // The C caller guarantees `ptr..ptr+len` is readable for this call.
    // SAFETY: `len > 0` and non-NULL checked above; slice valid per contract.
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// Borrows caller input as UTF-8.
fn input_str<'a>(ptr: *const u8, len: usize) -> Result<&'a str, i32> {
    let bytes = input_bytes(ptr, len)?;
    core::str::from_utf8(bytes).map_err(|_| AEGIS_ERR_INVALID_UTF8)
}

/// Stores the `u32` scalar result.
fn emit_u32(slot: *mut u32, value: u32) -> i32 {
    if slot.is_null() {
        return AEGIS_ERR_NULL_POINTER;
    }
    // SAFETY: non-NULL `slot: *mut u32` is writable by the caller contract.
    unsafe {
        *slot = value;
    }
    AEGIS_STATUS_OK
}

/// Stores the boolean result as `0`/`1`.
fn emit_bool(slot: *mut u8, value: bool) -> i32 {
    if slot.is_null() {
        return AEGIS_ERR_NULL_POINTER;
    }
    // SAFETY: non-NULL `slot: *mut u8` is writable by the caller contract.
    unsafe {
        *slot = u8::from(value);
    }
    AEGIS_STATUS_OK
}

/// Stores a single status byte (PM unwrap edge).
fn emit_u8(slot: *mut u8, value: u8) -> i32 {
    if slot.is_null() {
        return AEGIS_ERR_NULL_POINTER;
    }
    // SAFETY: non-NULL `slot: *mut u8` is writable by the caller contract.
    unsafe {
        *slot = value;
    }
    AEGIS_STATUS_OK
}

/// Emits `data` through the two-call `(out, out_cap, out_len)` protocol.
fn emit_bytes(out: *mut u8, out_cap: usize, out_len: *mut usize, data: &[u8]) -> i32 {
    if out_len.is_null() {
        return AEGIS_ERR_NULL_POINTER;
    }
    // SAFETY: non-NULL `out_len: *mut usize` is writable by the caller contract.
    unsafe {
        *out_len = data.len();
    }
    if out.is_null() {
        return i32::try_from(data.len()).unwrap_or(AEGIS_ERR_OVERFLOW);
    }
    if data.is_empty() {
        return AEGIS_STATUS_OK;
    }
    if out_cap < data.len() {
        return AEGIS_ERR_BUFFER_TOO_SMALL;
    }
    // `out` is non-NULL and `out_cap >= data.len()` was just checked.
    // SAFETY: `out..out+len` is writable for this call per caller contract.
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
    }
    AEGIS_STATUS_OK
}

/// JSON string escaping for the edge serializers (`"` `\` + C0 controls).
fn json_escape_into(dst: &mut String, s: &str) {
    dst.push('"');
    for ch in s.chars() {
        match ch {
            '"' => dst.push_str("\\\""),
            '\\' => dst.push_str("\\\\"),
            '\n' => dst.push_str("\\n"),
            '\r' => dst.push_str("\\r"),
            '\t' => dst.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                dst.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => dst.push(c),
        }
    }
    dst.push('"');
}

/// Lowercase hex without a dependency (JNI-edge encoding for fragments).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

fn ble_info_json() -> String {
    let info = ble_constants();
    format!(
        "{{\"service_uuid\":{},\"control_uuid\":{},\"status_uuid\":{},\"len_uuid\":{},\"revision_uuid\":{},\"gatt_revision\":{},\"op_ping\":{},\"op_msg\":{},\"op_cancel\":{},\"max_fragment_bytes\":{},\"control_point_length\":{}}}",
        info.service_uuid,
        info.control_uuid,
        info.status_uuid,
        info.len_uuid,
        info.revision_uuid,
        info.gatt_revision,
        info.op_ping,
        info.op_msg,
        info.op_cancel,
        info.max_fragment_bytes,
        info.control_point_length
    )
}

fn oath_code_json(code: &OathCode) -> String {
    let mut fixed = String::from("{\"account\":");
    json_escape_into(&mut fixed, &code.account);
    fixed.push_str(",\"code\":");
    json_escape_into(&mut fixed, &code.code);
    fixed.push_str(&format!(
        ",\"remaining_seconds\":{}}}",
        code.remaining_seconds
    ));
    fixed
}

fn otpauth_json(parsed: &OtpAuthParsed) -> String {
    let mut s = String::from("{\"issuer\":");
    json_escape_into(&mut s, &parsed.issuer);
    s.push_str(",\"account_name\":");
    json_escape_into(&mut s, &parsed.account_name);
    s.push_str(",\"secret_base32\":");
    json_escape_into(&mut s, &parsed.secret_base32);
    s.push_str(&format!(
        ",\"digits\":{},\"period\":{}}}",
        parsed.digits, parsed.period
    ));
    s
}

pub(crate) fn policy_json(policy: &SecureGuardPolicyDto) -> String {
    format!(
        "{{\"wipe_on_5_failures\":{},\"session_duration_ms\":{},\"inactivity_timeout_ms\":{},\"protect_keys_and_aegn\":{},\"protect_oath\":{},\"test_mode_non_destructive_wipe\":{}}}",
        policy.wipe_on_5_failures,
        policy.session_duration_ms,
        policy.inactivity_timeout_ms,
        policy.protect_keys_and_aegn,
        policy.protect_oath,
        policy.test_mode_non_destructive_wipe
    )
}

fn secure_guard_status_json(status: &SecureGuardStatusDto) -> String {
    let mut s = format!("{{\"state\":{},\"state_name\":", status.state);
    json_escape_into(&mut s, &status.state_name);
    s.push_str(&format!(
        ",\"is_provisioned\":{},\"is_unlocked\":{},\"failed_attempts\":{},\"remaining_attempts\":{},\"max_attempts\":{},\"rate_limit_remaining_ms\":{},\"session_remaining_ms\":{},\"policy\":{}",
        status.is_provisioned,
        status.is_unlocked,
        status.failed_attempts,
        status.remaining_attempts,
        status.max_attempts,
        status.rate_limit_remaining_ms,
        status.session_remaining_ms,
        policy_json(&status.policy)
    ));
    s.push_str(&format!(
        ",\"last_wipe_simulated\":{},\"audit_count\":{}}}",
        status.last_wipe_simulated, status.audit_count
    ));
    s
}

fn extract_json_bool(json: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{key}\"");
    let after_key = json.find(pattern.as_str())?;
    let rest = json[after_key + pattern.len()..]
        .split_once(':')?
        .1
        .trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
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

/// Parses a JNI-edge policy JSON object into the typed policy DTO.
///
/// Every field is required (callers serialize via the same key set the
/// [`policy_json`] emitter produces); anything else is invalid input, not
/// a transport default — defaults live in `SecureGuardPolicyDto::default`
/// on the Rust side.
fn policy_from_json(json: &str) -> Result<SecureGuardPolicyDto, i32> {
    Ok(SecureGuardPolicyDto {
        wipe_on_5_failures: extract_json_bool(json, "wipe_on_5_failures")
            .ok_or(AEGIS_ERR_INVALID_JSON)?,
        session_duration_ms: extract_json_u64(json, "session_duration_ms")
            .ok_or(AEGIS_ERR_INVALID_JSON)?,
        inactivity_timeout_ms: extract_json_u64(json, "inactivity_timeout_ms")
            .ok_or(AEGIS_ERR_INVALID_JSON)?,
        protect_keys_and_aegn: extract_json_bool(json, "protect_keys_and_aegn")
            .ok_or(AEGIS_ERR_INVALID_JSON)?,
        protect_oath: extract_json_bool(json, "protect_oath").ok_or(AEGIS_ERR_INVALID_JSON)?,
        test_mode_non_destructive_wipe: extract_json_bool(json, "test_mode_non_destructive_wipe")
            .ok_or(AEGIS_ERR_INVALID_JSON)?,
    })
}

/// Crate version string (`MAJOR.MINOR.PATCH\0`) for JNA-side pinning.
///
/// The returned pointer targets a `'static` NUL-terminated byte string and
/// must not be freed.
#[no_mangle]
pub extern "C" fn aegis_bridge_version() -> *const core::ffi::c_char {
    static VERSION: &[u8] = b"1.0.0\0";
    VERSION.as_ptr() as *const core::ffi::c_char
}

/// Frozen BLE constants as JNI-edge JSON (see [`ble_info_json`]).
#[no_mangle]
pub extern "C" fn aegis_ble_constants(out: *mut u8, out_cap: usize, out_len: *mut usize) -> i32 {
    emit_bytes(out, out_cap, out_len, ble_info_json().as_bytes())
}

/// FFF1 fragments as JNI-edge JSON: `{"count":N,"fragments":["hex",...]}`.
#[no_mangle]
pub extern "C" fn aegis_ble_split_fragments(
    opcode: u8,
    payload: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let bytes = match input_bytes(payload, payload_len) {
        Ok(b) => b,
        Err(code) => return code,
    };
    let frags = match ble_split_fragments(opcode, bytes.to_vec()) {
        Ok(f) => f,
        Err(err) => return status_of(err),
    };
    let mut s = format!("{{\"count\":{},\"fragments\":[", frags.len());
    for (i, frag) in frags.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        s.push_str(&hex_encode(frag));
        s.push('"');
    }
    s.push_str("]}");
    emit_bytes(out, out_cap, out_len, s.as_bytes())
}

/// Validates an AEGN envelope; writes the ciphertext length on success.
#[no_mangle]
pub extern "C" fn aegis_envelope_validate(
    envelope: *const u8,
    envelope_len: usize,
    ct_len_out: *mut u32,
) -> i32 {
    let bytes = match input_bytes(envelope, envelope_len) {
        Ok(b) => b,
        Err(code) => return code,
    };
    match envelope_validate(bytes.to_vec()) {
        Ok(ct_len) => emit_u32(ct_len_out, ct_len),
        Err(err) => status_of(err),
    }
}

/// Seals `plaintext` into an AEGN envelope (transient key/nonce, zeroized).
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn aegis_envelope_seal(
    key: *const u8,
    key_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    aad: *const u8,
    aad_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let (key, plaintext, aad, nonce) = match (
        input_bytes(key, key_len),
        input_bytes(plaintext, plaintext_len),
        input_bytes(aad, aad_len),
        input_bytes(nonce, nonce_len),
    ) {
        (Ok(k), Ok(p), Ok(a), Ok(n)) => (k, p, a, n),
        _ => return AEGIS_ERR_NULL_POINTER,
    };
    match envelope_seal(
        key.to_vec(),
        plaintext.to_vec(),
        aad.to_vec(),
        nonce.to_vec(),
    ) {
        Ok(env) => emit_bytes(out, out_cap, out_len, &env),
        Err(err) => status_of(err),
    }
}

/// Opens an AEGN envelope with a transient key (zeroized before return).
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn aegis_envelope_open(
    key: *const u8,
    key_len: usize,
    envelope: *const u8,
    envelope_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let (key, envelope, aad) = match (
        input_bytes(key, key_len),
        input_bytes(envelope, envelope_len),
        input_bytes(aad, aad_len),
    ) {
        (Ok(k), Ok(e), Ok(a)) => (k, e, a),
        _ => return AEGIS_ERR_NULL_POINTER,
    };
    match envelope_open(key.to_vec(), envelope.to_vec(), aad.to_vec()) {
        Ok(pt) => emit_bytes(out, out_cap, out_len, &pt),
        Err(err) => status_of(err),
    }
}

/// COSE key description (parse-only, never key bytes) as a UTF-8 string.
#[no_mangle]
pub extern "C" fn aegis_cose_key_info(
    cbor: *const u8,
    cbor_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let bytes = match input_bytes(cbor, cbor_len) {
        Ok(b) => b,
        Err(code) => return code,
    };
    match cose_key_info(bytes.to_vec()) {
        Ok(info) => emit_bytes(out, out_cap, out_len, info.as_bytes()),
        Err(err) => status_of(err),
    }
}

/// Display-only TOTP check (`1` = valid `6..=8` ASCII digits).
#[no_mangle]
pub extern "C" fn aegis_oath_code_valid(
    code: *const u8,
    code_len: usize,
    valid_out: *mut u8,
) -> i32 {
    let s = match input_str(code, code_len) {
        Ok(s) => s,
        Err(code) => return code,
    };
    emit_bool(valid_out, oath_code_valid(s.to_string()))
}

/// Seconds left in the 30s TOTP window.
#[no_mangle]
pub extern "C" fn aegis_oath_remaining_seconds(unix_seconds: u64, remaining_out: *mut u32) -> i32 {
    emit_u32(remaining_out, oath_remaining_seconds(unix_seconds))
}

/// Parses a `GET /oath/code` JSON body; emits display-only fields as JSON.
#[no_mangle]
pub extern "C" fn aegis_oath_parse_response(
    json: *const u8,
    json_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let s = match input_str(json, json_len) {
        Ok(s) => s,
        Err(code) => return code,
    };
    match oath_parse_response(s.to_string()) {
        Ok(parsed) => emit_bytes(out, out_cap, out_len, oath_code_json(&parsed).as_bytes()),
        Err(err) => status_of(err),
    }
}

/// Friendly TOTP grouping (`"123456"` -> `"123 456"`); input preserved as-is
/// when non-numeric.
#[no_mangle]
pub extern "C" fn aegis_totp_format_display(
    code: *const u8,
    code_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let s = match input_str(code, code_len) {
        Ok(s) => s,
        Err(code) => return code,
    };
    emit_bytes(
        out,
        out_cap,
        out_len,
        totp_format_display(s.to_string()).as_bytes(),
    )
}

/// PBKDF2-SHA1 app-lock verifier (password zeroized before return).
#[no_mangle]
pub extern "C" fn aegis_app_lock_derive(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let (password, salt) = match (
        input_bytes(password, password_len),
        input_bytes(salt, salt_len),
    ) {
        (Ok(p), Ok(s)) => (p, s),
        _ => return AEGIS_ERR_NULL_POINTER,
    };
    match app_lock_derive(password.to_vec(), salt.to_vec()) {
        Ok(verifier) => emit_bytes(out, out_cap, out_len, &verifier),
        Err(err) => status_of(err),
    }
}

/// WPA2-usable AP password hint (`1` = ASCII, `8..=63` chars).
#[no_mangle]
pub extern "C" fn aegis_wifi_password_valid(
    password: *const u8,
    password_len: usize,
    valid_out: *mut u8,
) -> i32 {
    let s = match input_str(password, password_len) {
        Ok(s) => s,
        Err(code) => return code,
    };
    emit_bool(valid_out, wifi_password_valid(s.to_string()))
}

/// Extracts `account` from a `/oath/code?account=` path.
///
/// Query phase (`out == NULL`) reports the account length like every byte
/// emitter; fill phase returns `1` with the account bytes on success, `0`
/// with `*out_len = 0` when absent, or a negative status on bad pointers.
#[no_mangle]
pub extern "C" fn aegis_oath_account_from_path(
    path: *const u8,
    path_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let s = match input_str(path, path_len) {
        Ok(s) => s,
        Err(code) => return code,
    };
    match oath_account_from_path(s.to_string()) {
        Some(account) => {
            let code = emit_bytes(out, out_cap, out_len, account.as_bytes());
            if code == AEGIS_STATUS_OK {
                1
            } else {
                code
            }
        }
        // Absent account: zero-length emission (sets `*out_len = 0`;
        // NULL `out_len` still rejected inside `emit_bytes`).
        None => {
            let code = emit_bytes(out, out_cap, out_len, &[]);
            if code == AEGIS_STATUS_OK {
                0
            } else {
                code
            }
        }
    }
}

/// Parses an `otpauth://` URI or raw Base32 secret; emits JSON.
#[no_mangle]
pub extern "C" fn aegis_otpauth_extract(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let s = match input_str(input, input_len) {
        Ok(s) => s,
        Err(code) => return code,
    };
    match otpauth_extract_label_and_secret(s.to_string()) {
        Ok(parsed) => emit_bytes(out, out_cap, out_len, otpauth_json(&parsed).as_bytes()),
        Err(err) => status_of(err),
    }
}

/// Public-key wallet address (public computation only, no secrets).
#[no_mangle]
pub extern "C" fn aegis_wallet_address(
    network: *const u8,
    network_len: usize,
    pubkey_hex: *const u8,
    pubkey_hex_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let (network, pubkey_hex) = match (
        input_str(network, network_len),
        input_str(pubkey_hex, pubkey_hex_len),
    ) {
        (Ok(n), Ok(h)) => (n, h),
        _ => return AEGIS_ERR_NULL_POINTER,
    };
    match wallet_address(network.to_string(), pubkey_hex.to_string()) {
        Ok(address) => emit_bytes(out, out_cap, out_len, address.as_bytes()),
        Err(err) => status_of(err),
    }
}

/// SecureGuard status CBOR response decoded to JNI-edge JSON.
#[no_mangle]
pub extern "C" fn aegis_secure_guard_parse_status(
    payload: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let bytes = match input_bytes(payload, payload_len) {
        Ok(b) => b,
        Err(code) => return code,
    };
    match secure_guard_parse_status(bytes.to_vec()) {
        Ok(status) => emit_bytes(
            out,
            out_cap,
            out_len,
            secure_guard_status_json(&status).as_bytes(),
        ),
        Err(err) => status_of(err),
    }
}

/// SecureGuard provision request encoding (CBOR bytes out).
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn aegis_secure_guard_encode_provision(
    pin: *const u8,
    pin_len: usize,
    recovery_code: *const u8,
    recovery_code_len: usize,
    wipe_on_5_failures: u8,
    test_mode: u8,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let (pin, recovery_code) = match (
        input_bytes(pin, pin_len),
        input_bytes(recovery_code, recovery_code_len),
    ) {
        (Ok(p), Ok(r)) => (p, r),
        _ => return AEGIS_ERR_NULL_POINTER,
    };
    match secure_guard_encode_provision(
        pin.to_vec(),
        recovery_code.to_vec(),
        wipe_on_5_failures != 0,
        test_mode != 0,
    ) {
        Ok(bytes) => emit_bytes(out, out_cap, out_len, &bytes),
        Err(err) => status_of(err),
    }
}

/// SecureGuard unlock request encoding (CBOR bytes out).
#[no_mangle]
pub extern "C" fn aegis_secure_guard_encode_unlock(
    pin: *const u8,
    pin_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let bytes = match input_bytes(pin, pin_len) {
        Ok(b) => b,
        Err(code) => return code,
    };
    match secure_guard_encode_unlock(bytes.to_vec()) {
        Ok(encoded) => emit_bytes(out, out_cap, out_len, &encoded),
        Err(err) => status_of(err),
    }
}

/// SecureGuard change-PIN request encoding (CBOR bytes out).
#[no_mangle]
pub extern "C" fn aegis_secure_guard_encode_change_pin(
    current_pin: *const u8,
    current_pin_len: usize,
    new_pin: *const u8,
    new_pin_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let (current_pin, new_pin) = match (
        input_bytes(current_pin, current_pin_len),
        input_bytes(new_pin, new_pin_len),
    ) {
        (Ok(c), Ok(n)) => (c, n),
        _ => return AEGIS_ERR_NULL_POINTER,
    };
    match secure_guard_encode_change_pin(current_pin.to_vec(), new_pin.to_vec()) {
        Ok(encoded) => emit_bytes(out, out_cap, out_len, &encoded),
        Err(err) => status_of(err),
    }
}

/// SecureGuard recover request encoding (CBOR bytes out).
#[no_mangle]
pub extern "C" fn aegis_secure_guard_encode_recover(
    recovery_code: *const u8,
    recovery_code_len: usize,
    new_pin: *const u8,
    new_pin_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let (recovery_code, new_pin) = match (
        input_bytes(recovery_code, recovery_code_len),
        input_bytes(new_pin, new_pin_len),
    ) {
        (Ok(r), Ok(n)) => (r, n),
        _ => return AEGIS_ERR_NULL_POINTER,
    };
    match secure_guard_encode_recover(recovery_code.to_vec(), new_pin.to_vec()) {
        Ok(encoded) => emit_bytes(out, out_cap, out_len, &encoded),
        Err(err) => status_of(err),
    }
}

/// SecureGuard lock request encoding (CBOR bytes out).
#[no_mangle]
pub extern "C" fn aegis_secure_guard_encode_lock(
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    match secure_guard_encode_lock() {
        Ok(encoded) => emit_bytes(out, out_cap, out_len, &encoded),
        Err(err) => status_of(err),
    }
}

/// SecureGuard config request encoding from JNI-edge policy JSON.
#[no_mangle]
pub extern "C" fn aegis_secure_guard_encode_config(
    policy_json: *const u8,
    policy_json_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let s = match input_str(policy_json, policy_json_len) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let policy = match policy_from_json(s) {
        Ok(p) => p,
        Err(code) => return code,
    };
    match secure_guard_encode_config(policy) {
        Ok(encoded) => emit_bytes(out, out_cap, out_len, &encoded),
        Err(err) => status_of(err),
    }
}

/// SecureGuard wipe request encoding (CBOR bytes out).
#[no_mangle]
pub extern "C" fn aegis_secure_guard_encode_wipe(
    scope: u8,
    confirm_token: *const u8,
    confirm_token_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let token = match input_str(confirm_token, confirm_token_len) {
        Ok(s) => s,
        Err(code) => return code,
    };
    match secure_guard_encode_wipe(scope, token.to_string()) {
        Ok(encoded) => emit_bytes(out, out_cap, out_len, &encoded),
        Err(err) => status_of(err),
    }
}

// =========================================================================
// PM blind transport (F-PM2): thin C edge over `pm_jni` framing.
// Additive only — reuses the frozen `AEGIS_ERR_*` codes above, so the
// existing ABI is untouched. Payloads cross opaquely: this edge never
// inspects, renders, or retains CBOR bodies; only the opcode/status
// framing is validated here. No UDL entry is added (UDL stays frozen);
// any future UDL mapping mirrors these three symbols 1:1.
// =========================================================================

/// Wraps a PM CBOR body into `[opcode, len_hi, len_lo, payload..]`.
///
/// `opcode` must be `0x43..=0x47` (`InvalidOpcode` otherwise); bodies over
/// the envelope ceiling fail with `Overflow`. Standard two-call output.
#[no_mangle]
pub extern "C" fn aegis_pm_frame_wrap(
    opcode: u8,
    payload: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let bytes = match input_bytes(payload, payload_len) {
        Ok(b) => b,
        Err(code) => return code,
    };
    match pm_frame_wrap(opcode, bytes.to_vec()) {
        Ok(frame) => emit_bytes(out, out_cap, out_len, &frame),
        Err(err) => status_of(err),
    }
}

/// Unwraps a status-first PM frame into its wire status plus opaque body.
///
/// Writes the §9.5 status byte to `status_out` and the body through the
/// standard two-call output. Unknown status bytes fail with
/// `InvalidEnvelope` (never mistaken for success); the body is opaque.
#[no_mangle]
pub extern "C" fn aegis_pm_frame_unwrap(
    frame: *const u8,
    frame_len: usize,
    status_out: *mut u8,
    body_out: *mut u8,
    body_cap: usize,
    body_len: *mut usize,
) -> i32 {
    let bytes = match input_bytes(frame, frame_len) {
        Ok(b) => b,
        Err(code) => return code,
    };
    let (status, body) = match pm_frame_unwrap(bytes.to_vec()) {
        Ok(t) => t,
        Err(err) => return status_of(err),
    };
    if emit_u8(status_out, status) != AEGIS_STATUS_OK {
        return AEGIS_ERR_NULL_POINTER;
    }
    emit_bytes(body_out, body_cap, body_len, &body)
}

/// Names a PM wire status for logs only (`Ok`/`NeedBinding`/...).
///
/// Emits ASCII bytes through the standard two-call output; never attached
/// to payloads.
#[no_mangle]
pub extern "C" fn aegis_pm_status_name(
    status: u8,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    emit_bytes(out, out_cap, out_len, pm_status_name(status).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pm_jni::{OP_PM_GET, OP_PM_LIST, PM_OP_MAX, PM_OP_MIN};

    fn wrap_call(opcode: u8, payload: &[u8]) -> (i32, Vec<u8>, usize) {
        let mut out = vec![0u8; 64];
        let mut out_len = 0usize;
        let rc = aegis_pm_frame_wrap(
            opcode,
            payload.as_ptr(),
            payload.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len as *mut usize,
        );
        out.truncate(out_len.min(out.len()));
        (rc, out, out_len)
    }

    #[test]
    fn pm_wrap_c_edge_roundtrip_shape() {
        let (rc, out, out_len) = wrap_call(OP_PM_LIST, b"opaque-cbor");
        assert_eq!(rc, AEGIS_STATUS_OK);
        assert_eq!(out_len, 3 + b"opaque-cbor".len());
        assert_eq!(&out[..3], &[OP_PM_LIST, 0x00, 0x0B]);
        assert_eq!(&out[3..], b"opaque-cbor");
    }

    #[test]
    fn pm_wrap_c_edge_two_call_query_and_bounds() {
        // Query path: NULL out reports the required length.
        let mut need = 0usize;
        let rc = aegis_pm_frame_wrap(
            OP_PM_GET,
            b"ab".as_ptr(),
            2,
            core::ptr::null_mut(),
            0,
            &mut need as *mut usize,
        );
        assert_eq!(rc, 5);
        assert_eq!(need, 5);
        // Too-small buffer reports the required size without writing.
        let mut small = vec![0u8; 2];
        let mut small_len = 0usize;
        let rc = aegis_pm_frame_wrap(
            OP_PM_GET,
            b"ab".as_ptr(),
            2,
            small.as_mut_ptr(),
            small.len(),
            &mut small_len as *mut usize,
        );
        assert_eq!(rc, AEGIS_ERR_BUFFER_TOO_SMALL);
        assert_eq!(small_len, 5);
        // Non-PM opcode fails with the frozen opcode code (no new ABI).
        let (rc, _, _) = wrap_call(0x42, b"ab");
        assert_eq!(rc, AEGIS_ERR_INVALID_OPCODE);
        assert_eq!(PM_OP_MIN, 0x43);
        assert_eq!(PM_OP_MAX, 0x47);
    }

    #[test]
    fn pm_unwrap_c_edge_status_first_and_opaque_body() {
        let frame = [0x05u8, 0xAA, 0xBB];
        let mut status = 0xFFu8;
        let mut body = vec![0u8; 16];
        let mut body_len = 0usize;
        let rc = aegis_pm_frame_unwrap(
            frame.as_ptr(),
            frame.len(),
            &mut status as *mut u8,
            body.as_mut_ptr(),
            body.len(),
            &mut body_len as *mut usize,
        );
        assert_eq!(rc, AEGIS_STATUS_OK);
        assert_eq!(status, 0x05);
        assert_eq!(body_len, 2);
        assert_eq!(&body[..2], &[0xAA, 0xBB]);
        // Unknown status is InvalidEnvelope, body untouched by success path.
        let mut status = 0xFFu8;
        let mut body_len = 0usize;
        let rc = aegis_pm_frame_unwrap(
            [0x03u8, 0xAA].as_ptr(),
            2,
            &mut status as *mut u8,
            core::ptr::null_mut(),
            0,
            &mut body_len as *mut usize,
        );
        assert_eq!(rc, AEGIS_ERR_INVALID_ENVELOPE);
        // Empty frame is InvalidEnvelope.
        let rc = aegis_pm_frame_unwrap(
            core::ptr::null(),
            0,
            &mut status as *mut u8,
            core::ptr::null_mut(),
            0,
            &mut body_len as *mut usize,
        );
        assert_eq!(rc, AEGIS_ERR_INVALID_ENVELOPE);
        // NULL status slot is a contract violation even on success.
        let mut body_len = 0usize;
        let rc = aegis_pm_frame_unwrap(
            [0x00u8].as_ptr(),
            1,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
            &mut body_len as *mut usize,
        );
        assert_eq!(rc, AEGIS_ERR_NULL_POINTER);
    }

    #[test]
    fn pm_status_name_c_edge_emits_log_label_only() {
        let mut out = vec![0u8; 32];
        let mut out_len = 0usize;
        let rc = aegis_pm_status_name(
            0x05,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len as *mut usize,
        );
        assert_eq!(rc, AEGIS_STATUS_OK);
        assert_eq!(&out[..out_len], b"NeedBinding");
        let mut out_len = 0usize;
        let rc = aegis_pm_status_name(0x00, core::ptr::null_mut(), 0, &mut out_len as *mut usize);
        assert_eq!(rc, "Ok".len() as i32);
        assert_eq!(out_len, "Ok".len());
    }
}
