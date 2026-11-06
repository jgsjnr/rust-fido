use super::common::{emit_bytes, hex_encode, input_bytes, status_of};
use crate::{ble_constants, ble_split_fragments};

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
