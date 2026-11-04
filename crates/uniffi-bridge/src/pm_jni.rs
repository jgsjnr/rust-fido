//! PM blind-transport mapping (F-PM2): opcode/status framing only.
//!
//! Pure passthrough for the password-manager viewer: validates PM opcodes,
//! wraps `[opcode, len_hi, len_lo, payload..]` request frames and unwraps
//! status-first `[status, body..]` responses. No business logic, no
//! persistence, no secret logging — payload bytes are never inspected,
//! rendered, or stored; only lengths and status names surface for logs.
//!
//! Layering: the typed CBOR DTOs live in `universal-device-sdk::pm`
//! (feature `pm`); envelope/policy decisions live in `aegis-pm-vault`
//! and firmware. This module keeps documented copies of the PM opcode
//! constants (same pattern as `ENVELOPE_MAGIC` above: parity is enforced
//! by the tests below, which pin the values against the SDK source path)
//! so this cdylib stays decoupled from SDK feature unification.
//!
//! UDL/C-ABI note: the thin C edge (`aegis_pm_frame_wrap`,
//! `aegis_pm_frame_unwrap`, `aegis_pm_status_name` in `ffi.rs`) wraps the
//! helpers below additively and reuses the frozen `AEGIS_ERR_*` codes, so
//! the existing ABI is untouched and no `BridgeError` variant was added.
//! No `aegis_bridge.udl` entry is added: the UDL stays frozen. If a UDL
//! mapping is ever needed, it mirrors those three C symbols 1:1 without
//! changing this framing.

use crate::{BridgeError, MAX_ENVELOPE_BYTES};

/// PM put: store (or replace) one login record (device seals on receipt).
pub const OP_PM_PUT: u8 = 0x43;
/// PM get: fetch one sealed record by opaque id (gated release).
pub const OP_PM_GET: u8 = 0x44;
/// PM list: page over opaque record ids (no labels cross this edge).
pub const OP_PM_LIST: u8 = 0x45;
/// PM delete: remove one record by opaque id.
pub const OP_PM_DELETE: u8 = 0x46;
/// PM status: entry-count / quota telemetry (no secrets).
pub const OP_PM_STATUS: u8 = 0x47;
/// First PM opcode (first free byte after BLE OOB `0x42`).
pub const PM_OP_MIN: u8 = OP_PM_PUT;
/// Last PM opcode.
pub const PM_OP_MAX: u8 = OP_PM_STATUS;

/// `true` for PM opcodes `0x43..=0x47`.
///
/// Neighbors are owned elsewhere (`0x42` BLE OOB, `0x3A..=0x3E` Secure
/// Guard) and rejected here fail-closed.
pub fn pm_opcode_valid(opcode: u8) -> bool {
    (PM_OP_MIN..=PM_OP_MAX).contains(&opcode)
}

/// Wraps a PM CBOR body into a status-first transport frame
/// `[opcode, len_hi, len_lo, payload..]`.
///
/// Mirrors the BLE first-fragment header shape (`ble_split_fragments`)
/// without fragmenting: fragmentation stays in the BLE dispatcher.
/// Rejects non-PM opcodes (`InvalidOpcode`) and bodies larger than
/// `MAX_ENVELOPE_BYTES` (`Overflow`) fail-closed. The body is opaque.
pub fn pm_frame_wrap(opcode: u8, payload: Vec<u8>) -> Result<Vec<u8>, BridgeError> {
    if !pm_opcode_valid(opcode) {
        return Err(BridgeError::InvalidOpcode);
    }
    if payload.len() > MAX_ENVELOPE_BYTES {
        return Err(BridgeError::Overflow);
    }
    let total = payload.len();
    let mut out = Vec::with_capacity(3 + total);
    out.push(opcode);
    out.push(((total >> 8) & 0xFF) as u8);
    out.push((total & 0xFF) as u8);
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Unwraps a status-first PM response frame into `(status, body)`.
///
/// `status` is the frozen §9.5 byte (`0x00`/`0x01`/`0x02`/`0x04`/`0x05`);
/// any other value is rejected fail-closed (`InvalidEnvelope`) so unknown
/// firmware states can never be mistaken for success. The body stays
/// opaque to this crate.
pub fn pm_frame_unwrap(frame: Vec<u8>) -> Result<(u8, Vec<u8>), BridgeError> {
    let (status, body) = frame.split_first().ok_or(BridgeError::InvalidEnvelope)?;
    match status {
        0x00 | 0x01 | 0x02 | 0x04 | 0x05 => Ok((*status, body.to_vec())),
        _ => Err(BridgeError::InvalidEnvelope),
    }
}

/// Names a PM wire status for logs only (never attached to payloads).
///
/// `0x00` Ok, `0x05` NeedBinding, `0x01` PresenceRequired, `0x02`
/// PinRequired, `0x04` InvalidEnvelope, anything else Unknown.
pub fn pm_status_name(status: u8) -> &'static str {
    match status {
        0x00 => "Ok",
        0x05 => "NeedBinding",
        0x01 => "PresenceRequired",
        0x02 => "PinRequired",
        0x04 => "InvalidEnvelope",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pm_opcode_audit_first_free_after_oob() {
        // Neighbors frozen elsewhere: 0x3E Secure Guard end, 0x3F GET_CAPS,
        // 0x40 SET_UP_POLICY, 0x41 VENDOR_SIGN, 0x42 BLE OOB (taken).
        // Parity: mirrors universal-device-sdk/src/pm.rs OP_PM_* (the SDK
        // owns the DTOs; this crate only transports frames).
        assert_eq!((OP_PM_PUT, OP_PM_GET, OP_PM_LIST, OP_PM_DELETE, OP_PM_STATUS), (0x43, 0x44, 0x45, 0x46, 0x47));
        assert_eq!((PM_OP_MIN, PM_OP_MAX), (0x43, 0x47));
        for op in PM_OP_MIN..=PM_OP_MAX {
            assert!(pm_opcode_valid(op), "opcode {op:#04x} should be PM");
        }
        for op in [0x3Eu8, 0x3F, 0x40, 0x41, 0x42, 0x48, 0x81, 0x83] {
            assert!(!pm_opcode_valid(op), "opcode {op:#04x} must not be PM");
        }
    }

    #[test]
    fn pm_frame_wrap_unwrap_roundtrip() {
        let body = b"opaque-cbor".to_vec();
        let frame = pm_frame_wrap(OP_PM_LIST, body.clone()).unwrap();
        assert_eq!(&frame[..3], &[OP_PM_LIST, 0x00, 0x0B]);
        assert_eq!(&frame[3..], body.as_slice());
        let empty = pm_frame_wrap(OP_PM_STATUS, Vec::new()).unwrap();
        assert_eq!(empty, vec![OP_PM_STATUS, 0x00, 0x00]);
    }

    #[test]
    fn pm_frame_wrap_rejects_fail_closed() {
        assert_eq!(
            pm_frame_wrap(0x42, vec![1]),
            Err(BridgeError::InvalidOpcode)
        );
        assert_eq!(
            pm_frame_wrap(0x48, vec![1]),
            Err(BridgeError::InvalidOpcode)
        );
        assert_eq!(
            pm_frame_wrap(OP_PM_PUT, vec![0xABu8; MAX_ENVELOPE_BYTES + 1]),
            Err(BridgeError::Overflow)
        );
        // Ceiling itself is accepted (parity with envelope seal cap).
        assert!(pm_frame_wrap(OP_PM_PUT, vec![0xABu8; MAX_ENVELOPE_BYTES]).is_ok());
    }

    #[test]
    fn pm_frame_unwrap_status_first() {
        let (status, body) = pm_frame_unwrap(vec![0x00, 0xAA, 0xBB]).unwrap();
        assert_eq!((status, body), (0x00, vec![0xAA, 0xBB]));
        for known in [0x00u8, 0x01, 0x02, 0x04, 0x05] {
            let (status, body) = pm_frame_unwrap(vec![known]).unwrap();
            assert_eq!((status, body), (known, Vec::new()));
        }
        assert_eq!(pm_frame_unwrap(Vec::new()), Err(BridgeError::InvalidEnvelope));
        assert_eq!(
            pm_frame_unwrap(vec![0x03, 0xAA]),
            Err(BridgeError::InvalidEnvelope)
        );
        assert_eq!(
            pm_frame_unwrap(vec![0xFF, 0xAA]),
            Err(BridgeError::InvalidEnvelope)
        );
    }

    #[test]
    fn pm_status_names_frozen_for_logs() {
        assert_eq!(pm_status_name(0x00), "Ok");
        assert_eq!(pm_status_name(0x05), "NeedBinding");
        assert_eq!(pm_status_name(0x01), "PresenceRequired");
        assert_eq!(pm_status_name(0x02), "PinRequired");
        assert_eq!(pm_status_name(0x04), "InvalidEnvelope");
        assert_eq!(pm_status_name(0x03), "Unknown");
        assert_eq!(pm_status_name(0xFF), "Unknown");
    }

    /// Source parity: the opcode copies above track the SDK contract that
    /// owns the DTOs (`universal-device-sdk/src/pm.rs`). Any drift in the
    /// canonical declarations breaks this test.
    #[test]
    fn pm_opcodes_match_sdk_source() {
        const SDK_PM: &str = include_str!("../../universal-device-sdk/src/pm.rs");
        for (name, byte) in [
            ("OP_PM_PUT", OP_PM_PUT),
            ("OP_PM_GET", OP_PM_GET),
            ("OP_PM_LIST", OP_PM_LIST),
            ("OP_PM_DELETE", OP_PM_DELETE),
            ("OP_PM_STATUS", OP_PM_STATUS),
        ] {
            let decl = format!("pub const {name}: u8 = {byte:#04X};");
            assert!(
                SDK_PM.contains(decl.as_str()),
                "drift vs SDK declaration `{decl}`"
            );
        }
    }
}
