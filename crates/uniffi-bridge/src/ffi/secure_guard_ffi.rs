use super::common::{
    emit_bytes, input_bytes, input_str, json_escape_into, policy_from_json, policy_json, status_of,
    AEGIS_ERR_NULL_POINTER,
};
use crate::{
    secure_guard_encode_change_pin, secure_guard_encode_config, secure_guard_encode_lock,
    secure_guard_encode_provision, secure_guard_encode_recover, secure_guard_encode_unlock,
    secure_guard_encode_wipe, secure_guard_parse_status, SecureGuardStatusDto,
};

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
