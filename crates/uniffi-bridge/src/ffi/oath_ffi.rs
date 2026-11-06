use super::common::{
    emit_bool, emit_bytes, emit_u32, input_bytes, input_str, json_escape_into, status_of,
    AEGIS_ERR_NULL_POINTER,
};
use crate::{
    app_lock_derive, oath_account_from_path, oath_code_valid, oath_parse_response,
    oath_remaining_seconds, otpauth_extract_label_and_secret, totp_format_display,
    wifi_password_valid, OathCode, OtpAuthParsed,
};

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
            if code == super::common::AEGIS_STATUS_OK {
                1
            } else {
                code
            }
        }
        // Absent account: zero-length emission (sets `*out_len = 0`;
        // NULL `out_len` still rejected inside `emit_bytes`).
        None => {
            let code = emit_bytes(out, out_cap, out_len, &[]);
            if code == super::common::AEGIS_STATUS_OK {
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
