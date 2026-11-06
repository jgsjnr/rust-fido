use super::common::{emit_bytes, emit_u32, input_bytes, status_of, AEGIS_ERR_NULL_POINTER};
use crate::{cose_key_info, envelope_open, envelope_seal, envelope_validate};

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
