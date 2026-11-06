use crate::{BridgeError, SecureGuardPolicyDto};

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
pub(crate) fn input_bytes<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
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
pub(crate) fn input_str<'a>(ptr: *const u8, len: usize) -> Result<&'a str, i32> {
    let bytes = input_bytes(ptr, len)?;
    core::str::from_utf8(bytes).map_err(|_| AEGIS_ERR_INVALID_UTF8)
}

/// Stores the `u32` scalar result.
pub(crate) fn emit_u32(slot: *mut u32, value: u32) -> i32 {
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
pub(crate) fn emit_bool(slot: *mut u8, value: bool) -> i32 {
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
pub(crate) fn emit_u8(slot: *mut u8, value: u8) -> i32 {
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
pub(crate) fn emit_bytes(out: *mut u8, out_cap: usize, out_len: *mut usize, data: &[u8]) -> i32 {
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
pub(crate) fn json_escape_into(dst: &mut String, s: &str) {
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
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
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

pub(crate) fn extract_json_bool(json: &str, key: &str) -> Option<bool> {
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

pub(crate) fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
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
pub(crate) fn policy_from_json(json: &str) -> Result<SecureGuardPolicyDto, i32> {
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
