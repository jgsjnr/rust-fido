use super::common::{emit_bytes, emit_u8, input_bytes, status_of, AEGIS_ERR_NULL_POINTER};
use crate::pm_jni::{pm_frame_unwrap, pm_frame_wrap, pm_status_name};

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
    if emit_u8(status_out, status) != super::common::AEGIS_STATUS_OK {
        return AEGIS_ERR_NULL_POINTER;
    }
    emit_bytes(body_out, body_cap, body_len, &body)
}

/// Names a PM wire status for logs only (`Ok`/`NeedBinding`/…).
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
    use super::super::common::{
        AEGIS_ERR_BUFFER_TOO_SMALL, AEGIS_ERR_INVALID_ENVELOPE, AEGIS_ERR_INVALID_OPCODE,
        AEGIS_STATUS_OK,
    };
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
