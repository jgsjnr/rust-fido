use super::common::{emit_bytes, input_bytes, input_str, status_of, AEGIS_ERR_NULL_POINTER};
use crate::{
    pending_summary_json, wallet_address, wallet_approval_receipt, wallet_pending_query_encode,
    wallet_pending_summary_decode, wallet_sign_envelope_encode, xpub_from_seed,
};

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

/// Account-level extended public key (off-device, public output only).
///
/// Same narrow contract as [`aegis_wallet_address`]: two-call
/// `(out, out_cap, out_len)` bytes out, NULL with `len > 0` rejected, UTF-8
/// required. `account` is the `< 2^31` account level (hardened by
/// derivation); out-of-range accounts, unknown networks, and bad seed hex
/// fail closed with `AEGIS_ERR_INVALID_ADDRESS` (never a new code: the frozen
/// `-1..-13` set is untouched). Errors carry no payload; the input seed is
/// zeroized inside the typed call and the output is public-only.
#[no_mangle]
pub extern "C" fn aegis_xpub_from_seed(
    seed_hex: *const u8,
    seed_hex_len: usize,
    network: *const u8,
    network_len: usize,
    account: u32,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let (seed_hex, network) = match (
        input_str(seed_hex, seed_hex_len),
        input_str(network, network_len),
    ) {
        (Ok(s), Ok(n)) => (s, n),
        _ => return AEGIS_ERR_NULL_POINTER,
    };
    match xpub_from_seed(seed_hex.to_string(), network.to_string(), account) {
        Ok(xpub) => emit_bytes(out, out_cap, out_len, xpub.as_bytes()),
        Err(err) => status_of(err),
    }
}

// =========================================================================
// Wallet companion passthrough (F7): pure 1:1 delegation to the
// `universal-device-sdk` companion codecs (`wallet_companion`). This edge
// owns no TLV framing, no opcode table and no receipt strings — it only
// forwards bytes through the standard two-call protocol on the frozen
// `AEGIS_ERR_*` codes. Structured values cross as JNI-edge JSON only.
// No UDL entry is added (UDL stays frozen); any future UDL mapping mirrors
// these four symbols 1:1.
// =========================================================================

/// Encodes a companion pending-preview query (`0x4B` payload) via the SDK.
///
/// Shape violations fail on the frozen codes (`Overflow` past the
/// transport ceiling, `InvalidEnvelope` otherwise); errors carry no payload.
#[no_mangle]
pub extern "C" fn aegis_wallet_pending_query(
    slot: u8,
    psbt: *const u8,
    psbt_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let bytes = match input_bytes(psbt, psbt_len) {
        Ok(b) => b,
        Err(code) => return code,
    };
    match wallet_pending_query_encode(slot, bytes.to_vec()) {
        Ok(query) => emit_bytes(out, out_cap, out_len, &query),
        Err(err) => status_of(err),
    }
}

/// Encodes a companion sign envelope (`0x4A` payload) via the SDK.
///
/// `receipt` must be exactly `approve`/`deny` (anything else fails as
/// `InvalidEnvelope` before any wire byte is built). Standard two-call
/// output; errors carry no payload.
#[no_mangle]
pub extern "C" fn aegis_wallet_sign_envelope(
    slot: u8,
    psbt: *const u8,
    psbt_len: usize,
    receipt: *const u8,
    receipt_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let (psbt, receipt) = match (
        input_bytes(psbt, psbt_len),
        input_bytes(receipt, receipt_len),
    ) {
        (Ok(p), Ok(r)) => (p, r),
        _ => return AEGIS_ERR_NULL_POINTER,
    };
    match wallet_sign_envelope_encode(slot, psbt.to_vec(), receipt.to_vec()) {
        Ok(envelope) => emit_bytes(out, out_cap, out_len, &envelope),
        Err(err) => status_of(err),
    }
}

/// Decodes a pending-summary body to JNI-edge JSON via the SDK.
///
/// Emits `{"slot":N,"tx_hash_hex":"…","inputs":N,"outputs":N}` (display-only
/// public metadata). Malformed bodies fail as `InvalidEnvelope`.
#[no_mangle]
pub extern "C" fn aegis_wallet_pending_summary(
    body: *const u8,
    body_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let bytes = match input_bytes(body, body_len) {
        Ok(b) => b,
        Err(code) => return code,
    };
    match wallet_pending_summary_decode(bytes.to_vec()) {
        Ok(summary) => emit_bytes(
            out,
            out_cap,
            out_len,
            pending_summary_json(&summary).as_bytes(),
        ),
        Err(err) => status_of(err),
    }
}

/// Approval receipt bytes for the sign envelope (biometric-gated).
///
/// Returns `1` with the receipt bytes on success, `0` with `*out_len = 0`
/// when there is no receipt (approve without a live biometric: the
/// companion sends nothing, never a forged approve), or a negative status
/// on bad pointers. Mirrors the `aegis_oath_account_from_path` convention.
#[no_mangle]
pub extern "C" fn aegis_wallet_approval_receipt(
    approve: u8,
    biometric_ok: u8,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    match wallet_approval_receipt(approve != 0, biometric_ok != 0) {
        Some(receipt) => {
            let code = emit_bytes(out, out_cap, out_len, &receipt);
            if code == super::common::AEGIS_STATUS_OK {
                1
            } else {
                code
            }
        }
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

#[cfg(test)]
mod tests {
    use super::super::common::{AEGIS_ERR_INVALID_ENVELOPE, AEGIS_STATUS_OK};
    use super::*;

    fn query_call(slot: u8, psbt: &[u8]) -> (i32, Vec<u8>, usize) {
        let mut out = vec![0u8; 1024];
        let mut out_len = 0usize;
        let rc = aegis_wallet_pending_query(
            slot,
            psbt.as_ptr(),
            psbt.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len as *mut usize,
        );
        out.truncate(out_len.min(out.len()));
        (rc, out, out_len)
    }

    #[test]
    fn wallet_companion_c_edge_passthrough_roundtrip() {
        let psbt = [0x70u8, 0x73, 0x62, 0x74];
        let (rc, query, _) = query_call(3, &psbt);
        assert_eq!(rc, AEGIS_STATUS_OK);
        // `[slot, psbt]` TLV framing comes from the SDK, never rebuilt here.
        assert_eq!(&query[..3], &[0x01, 0x01, 0x03]);
        // Bad slot fails on the frozen codes, never a forged query.
        let (rc, _, _) = query_call(32, &psbt);
        assert_eq!(rc, AEGIS_ERR_INVALID_ENVELOPE);
        // Sign envelope carries the receipt; a forged value never encodes.
        let mut out = vec![0u8; 1024];
        let mut out_len = 0usize;
        let rc = aegis_wallet_sign_envelope(
            3,
            psbt.as_ptr(),
            psbt.len(),
            b"approve".as_ptr(),
            b"approve".len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len as *mut usize,
        );
        assert_eq!(rc, AEGIS_STATUS_OK);
        assert!(out[..out_len].windows(7).any(|w| w == b"approve"));
        let mut out_len = 0usize;
        let rc = aegis_wallet_sign_envelope(
            3,
            psbt.as_ptr(),
            psbt.len(),
            b"maybe".as_ptr(),
            b"maybe".len(),
            core::ptr::null_mut(),
            0,
            &mut out_len as *mut usize,
        );
        assert_eq!(rc, AEGIS_ERR_INVALID_ENVELOPE);
    }

    #[test]
    fn wallet_companion_c_edge_summary_and_receipt() {
        // Summary body `[slot, tx_hash, counts]` decodes to JNI-edge JSON.
        let mut body = vec![0x01u8, 0x01, 0x03, 0x0Eu8, 0x20];
        body.extend_from_slice(&[0xABu8; 32]);
        body.extend_from_slice(&[0x0Fu8, 0x04, 0x01, 0x00, 0x02, 0x00]);
        let mut out = vec![0u8; 256];
        let mut out_len = 0usize;
        let rc = aegis_wallet_pending_summary(
            body.as_ptr(),
            body.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len as *mut usize,
        );
        assert_eq!(rc, AEGIS_STATUS_OK);
        let json = core::str::from_utf8(&out[..out_len]).unwrap();
        assert!(json.contains("\"slot\":3"));
        assert!(json.contains(&"ab".repeat(32)));
        // Receipt: approve + biometry -> 1 with bytes; approve alone -> 0
        // with no bytes (never forged); deny -> 1 with `deny`.
        let mut out = vec![0u8; 16];
        let mut out_len = 0usize;
        let rc = aegis_wallet_approval_receipt(
            1,
            1,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len as *mut usize,
        );
        assert_eq!(rc, 1);
        assert_eq!(&out[..out_len], b"approve");
        let mut out_len = 0usize;
        let rc = aegis_wallet_approval_receipt(
            1,
            0,
            core::ptr::null_mut(),
            0,
            &mut out_len as *mut usize,
        );
        assert_eq!(rc, 0);
        assert_eq!(out_len, 0);
        let mut out = vec![0u8; 16];
        let mut out_len = 0usize;
        let rc = aegis_wallet_approval_receipt(
            0,
            0,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len as *mut usize,
        );
        assert_eq!(rc, 1);
        assert_eq!(&out[..out_len], b"deny");
    }
}
