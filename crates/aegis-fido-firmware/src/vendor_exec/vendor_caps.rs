//! Capability advertisement (`GET_CAPS`, `0x3F`) -- read-only, no auth.
//!
//! Opcode audit (first byte of `CMD_MSG` payload / BLE vendor message):
//! - `0x20-0x27` vendor keys/OATH (Fase6, all taken).
//! - `0x28-0x2D` bind-mgmt (Sec.11, all taken).
//! - `0x2E` rescue transport (travels ONLY as `OP_MSG` payload, never a
//!   fragment opcode -- must stay untouched).
//! - `0x2F` reserved (reassembler/tests assert fail-closed rejection).
//! - `0x30-0x34` OTA (`OP_OTA_BEGIN..OP_OTA_ABORT`, canonical in `ota`).
//! - `0x35-0x37` wallet (`OP_WALLET_GEN/LIST/ADDR`).
//! - `0x38` fw-log (`OP_FW_LOG`).
//! - `0x39` PIV enroll (`OP_PIV_ENROLL`).
//! - `0x3A-0x3E` Secure Guard (STATUS/UNLOCK/LOCK/CONFIG/WIPE_SELECTIVE).
//! - `0x3F` GET_CAPS (this module): first free byte after the SG range.
//!   No collision with the SG range, wallet, OATH, or CCID dispatch
//!   (CCID is APDU-framed `CLA/INS/P1/P2` -- a different namespace; the
//!   `0x3F` values in PIV APDUs / CTAP status codes live in those
//!   namespaces, not the vendor-op namespace).
//!
//! Wire contract (mirrors `scripts/capability-catalog.json#wire_contract`):
//! - Request: empty. Any non-empty payload fails closed (`0x04`).
//! - Response: `(0x00, CBOR map)` with keys `fw_version` (text, crate
//!   version), `preset` (text: `"full"` / `"fido-only"` / `"fido-totp"`
//!   via cfg), `caps` (array of text capability IDs, EXACTLY the
//!   `presets.<preset>.includes` list in the catalog), `unsupported_count`
//!   (uint: number of diet-gated vendor commands, `0` on full).
//! - No auth required: read-only, no secrets (same visibility class as
//!   `0x38` fw-log over serial). Handled BEFORE `authorize_vendor_op`
//!   (like `OP_PIV_ENROLL`), so binding/UP/PIN are never consulted.
//! - Fail-closed on malformed input; unknown ops keep prior behavior
//!   (`0x04` InvalidOpcode mapping, e.g. `0x2F`/`0x40` still deny).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use ciborium::value::Value;

/// Read-only capability advertisement opcode (`0x3F`).
pub const OP_GET_CAPS: u8 = 0x3F;

/// `true` for the `GET_CAPS` opcode (funnel-routing helper).
///
/// Transport funnels (`freertos_route::dispatch_serial_vendor_msg`,
/// legacy serial loop, `ble_dispatch_complete`, BLE reassembler) route
/// vendor ops by opcode predicate; OR this in next to
/// `is_vendor_keys_oath_op` / `is_wallet_op` / `is_piv_enroll_op` and
/// accept the single-byte message WITHOUT pairing/UP/PIN gates
/// (read-only, no secrets -- same class as `0x38` fw-log over serial).
pub fn is_get_caps_op(op: u8) -> bool {
    op == OP_GET_CAPS
}

/// Preset string for this build (`"full"` / `"fido-only"` / `"fido-totp"`).
///
/// Exhaustive under the `lib.rs` `compile_error!` guards (`cap-*` are
/// mutually exclusive alternative roots, `full` = neither set).
pub fn preset_name() -> &'static str {
    #[cfg(all(feature = "cap-fido-only", not(feature = "cap-fido-totp")))]
    {
        "fido-only"
    }
    #[cfg(all(feature = "cap-fido-totp", not(feature = "cap-fido-only")))]
    {
        "fido-totp"
    }
    #[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
    {
        "full"
    }
}

/// Capability IDs advertised by this build.
///
/// EXACT mirror of `scripts/capability-catalog.json`
/// `presets.<preset>.includes` (same IDs, same order) -- the catalog is
/// the machine-readable source of truth; this table is its compiled-in
/// projection so `fido-only` truthfully reports its diet.
pub fn capability_ids() -> &'static [&'static str] {
    #[cfg(all(feature = "cap-fido-only", not(feature = "cap-fido-totp")))]
    {
        &[
            "ctap-makecred",
            "ctap-getassert",
            "ctap-clientpin",
            "ccid",
            "piv",
            "openpgp",
            "vendor-mgmt",
        ]
    }
    #[cfg(all(feature = "cap-fido-totp", not(feature = "cap-fido-only")))]
    {
        &[
            "ctap-makecred",
            "ctap-getassert",
            "ctap-clientpin",
            "ccid",
            "piv",
            "openpgp",
            "oath-totp",
            "oath-hotp",
            "otp-challenge-response",
            "vendor-mgmt",
        ]
    }
    #[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
    {
        &[
            "ctap-makecred",
            "ctap-getassert",
            "ctap-clientpin",
            "ccid",
            "piv",
            "openpgp",
            "oath-totp",
            "oath-hotp",
            "otp-challenge-response",
            "wallet",
            "vault",
            "ble",
            "wifi-sntp",
            "display",
            "proximity",
            "vendor-mgmt",
            "debug-terminal",
            "test-hooks",
        ]
    }
}

/// Vendor opcodes that answer `UNSUPPORTED_FEATURE` (`0x06`) in this build.
///
/// - full: none (`[]`).
/// - fido-only: OATH `0x24-0x27` + wallet `0x35-0x37` (7).
/// - fido-totp: wallet `0x35-0x37` (3).
///
/// `unsupported_count()` is exactly this slice's length.
pub fn diet_gated_ops() -> &'static [u8] {
    #[cfg(all(feature = "cap-fido-only", not(feature = "cap-fido-totp")))]
    {
        &[0x24, 0x25, 0x26, 0x27, 0x35, 0x36, 0x37]
    }
    #[cfg(all(feature = "cap-fido-totp", not(feature = "cap-fido-only")))]
    {
        &[0x35, 0x36, 0x37]
    }
    #[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
    {
        &[]
    }
}

/// Number of diet-gated vendor commands (`0` on full).
pub fn unsupported_count() -> u64 {
    diet_gated_ops().len() as u64
}

/// Executes `GET_CAPS`: empty request -> `(0x00, CBOR map)`.
///
/// No auth consulted (read-only, no secrets). Non-empty payload fails
/// closed (`0x04`, empty body). CBOR encode failure also fails closed
/// (never partial bytes on the wire).
pub(crate) fn exec_get_caps(payload: &[u8]) -> (u8, Vec<u8>) {
    if !payload.is_empty() {
        return (0x04, Vec::new());
    }
    let mut caps: Vec<Value> = Vec::with_capacity(capability_ids().len());
    for id in capability_ids() {
        caps.push(Value::Text(String::from(*id)));
    }
    let map = Value::Map(alloc::vec![
        (
            Value::Text(String::from("fw_version")),
            Value::Text(String::from(env!("CARGO_PKG_VERSION"))),
        ),
        (
            Value::Text(String::from("preset")),
            Value::Text(String::from(preset_name())),
        ),
        (
            Value::Text(String::from("caps")),
            Value::Array(caps),
        ),
        (
            Value::Text(String::from("unsupported_count")),
            Value::from(unsupported_count()),
        ),
    ]);
    let mut out = Vec::new();
    if ciborium::into_writer(&map, &mut out).is_err() {
        return (0x04, Vec::new());
    }
    (0x00, out)
}

/// Looks up a field in a decoded CBOR map (host-test helper).
#[cfg(test)]
pub(crate) fn get_map_field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    for (k, v) in entries {
        if let Value::Text(s) = k {
            if s == key {
                return Some(v);
            }
        }
    }
    None
}
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn decode_map(body: &[u8]) -> Vec<(Value, Value)> {
        let v: Value = ciborium::from_reader(body).expect("GET_CAPS body is CBOR");
        match v {
            Value::Map(m) => m,
            _ => panic!("GET_CAPS body must be a CBOR map"),
        }
    }

    #[test]
    fn opcode_audit_next_free_after_sg_range() {
        // Collision audit: neighbors keep their canonical values.
        assert_eq!(OP_GET_CAPS, 0x3F);
        assert!(is_get_caps_op(0x3F));
        assert!(!is_get_caps_op(0x3E));
        assert!(!is_get_caps_op(0x40));
        assert!(!is_get_caps_op(0x2F));
        assert_eq!(crate::ble_gatt::SECURE_GUARD_OP_MAX, 0x3E);
        assert_eq!(crate::ble_gatt::OP_PIV_ENROLL, 0x39);
        assert_eq!(crate::ble_gatt::WALLET_OP_MAX, 0x37);
        assert_eq!(crate::fw_log::OP_FW_LOG, 0x38);
        assert_eq!(crate::ble_gatt::VENDOR_OP_MAX, 0x27);
        // 0x3F is outside every existing funnel range (routing must OR in
        // `is_get_caps_op`; it must NOT be swallowed by another predicate).
        assert!(!crate::ble_gatt::is_vendor_keys_oath_op(OP_GET_CAPS));
        assert!(!crate::ble_gatt::is_wallet_op(OP_GET_CAPS));
        assert!(!crate::ble_gatt::is_secure_guard_op(OP_GET_CAPS));
        assert!(!crate::ble_gatt::is_bind_mgmt_op(OP_GET_CAPS));
        assert!(!crate::fw_log::is_fw_log_op(OP_GET_CAPS));
        assert!(!crate::ble_gatt::is_piv_enroll_op(OP_GET_CAPS));
    }

    #[test]
    fn response_schema_parses_with_expected_types() {
        let (st, body) = exec_get_caps(&[]);
        assert_eq!(st, 0x00);
        assert!(!body.is_empty());
        let map = decode_map(&body);
        // fw_version: text == crate version.
        assert_eq!(
            get_map_field(&map, "fw_version"),
            Some(&Value::Text(String::from(env!("CARGO_PKG_VERSION"))))
        );
        // preset: text, one of the three known strings, matches cfg.
        let preset_val = get_map_field(&map, "preset").expect("preset field");
        assert_eq!(preset_val, &Value::Text(String::from(preset_name())));
        match preset_val {
            Value::Text(p) => assert!(p == "full" || p == "fido-only" || p == "fido-totp"),
            _ => panic!("preset must be text"),
        }
        // caps: array of text, exactly the compiled-in table.
        match get_map_field(&map, "caps") {
            Some(Value::Array(items)) => {
                assert_eq!(items.len(), capability_ids().len());
                for (item, want) in items.iter().zip(capability_ids().iter()) {
                    assert_eq!(item, &Value::Text(String::from(*want)));
                }
            }
            _ => panic!("caps must be an array of text"),
        }
        // unsupported_count: uint == diet-gated opcode count.
        assert_eq!(
            get_map_field(&map, "unsupported_count"),
            Some(&Value::from(unsupported_count()))
        );
        assert_eq!(unsupported_count(), diet_gated_ops().len() as u64);
    }

    #[test]
    fn preset_table_is_diet_truthful() {
        // Runtime match (compiles in every preset) + cfg-gated spot
        // checks per preset (full + fido-only at minimum).
        match preset_name() {
            "full" => {
                assert_eq!(capability_ids().len(), 18);
                assert_eq!(unsupported_count(), 0);
                assert!(diet_gated_ops().is_empty());
                assert!(capability_ids().contains(&"wallet"));
                assert!(capability_ids().contains(&"oath-totp"));
            }
            "fido-only" => {
                assert_eq!(capability_ids().len(), 7);
                assert_eq!(unsupported_count(), 7);
                assert_eq!(diet_gated_ops(), &[0x24, 0x25, 0x26, 0x27, 0x35, 0x36, 0x37]);
                assert!(!capability_ids().contains(&"wallet"));
                assert!(!capability_ids().contains(&"oath-totp"));
                assert!(capability_ids().contains(&"vendor-mgmt"));
            }
            "fido-totp" => {
                assert_eq!(capability_ids().len(), 10);
                assert_eq!(unsupported_count(), 3);
                assert_eq!(diet_gated_ops(), &[0x35, 0x36, 0x37]);
                assert!(!capability_ids().contains(&"wallet"));
                assert!(capability_ids().contains(&"oath-totp"));
            }
            _ => panic!("unknown preset"),
        }
        #[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
        {
            assert_eq!(preset_name(), "full");
            assert_eq!(unsupported_count(), 0);
        }
        #[cfg(all(feature = "cap-fido-only", not(feature = "cap-fido-totp")))]
        {
            assert_eq!(preset_name(), "fido-only");
            assert_eq!(capability_ids().len(), 7);
            assert_eq!(unsupported_count(), 7);
        }
        #[cfg(all(feature = "cap-fido-totp", not(feature = "cap-fido-only")))]
        {
            assert_eq!(preset_name(), "fido-totp");
            assert_eq!(capability_ids().len(), 10);
            assert_eq!(unsupported_count(), 3);
        }
    }

    #[test]
    fn nonempty_request_fails_closed() {
        let one = [0x00u8];
        let two = [0x01u8, 0x02u8];
        let big = [0xFFu8; 64];
        for payload in [&one[..], &two[..], &big[..]] {
            let (st, body) = exec_get_caps(payload);
            assert_eq!(st, 0x04);
            assert!(body.is_empty());
        }
    }
}
