use super::{
    cbor_err, extract_bytes, get_field, to_cbor_bytes, CTAP2_ERR_PIN_AUTH_INVALID,
    CTAP2_ERR_PIN_REQUIRED,
};
use aegis_fido_core::secure_guard::SecureGuardEngine;
use ciborium::value::Value;
use std::format;
use std::vec::Vec;
use crate::persistence::{FlashStorageBackend, SecureStorage};
use crate::secure_guard_storage::save_secure_guard_record;
/// 0x3D: OP_SECURE_GUARD_CONFIG
pub(crate) fn handle_config<B: FlashStorageBackend>(
    engine: &mut SecureGuardEngine,
    storage: &mut SecureStorage<B>,
    payload: &[u8],
    now_ms: u64,
) -> (u8, Vec<u8>) {
    let entries = match ciborium::from_reader(payload) {
        Ok(Value::Map(entries)) => entries,
        _ => Vec::new(),
    };

    let pin_opt = get_field(&entries, "pin").and_then(extract_bytes);

    if engine.is_provisioned() {
        if let Some(pin) = pin_opt {
            if let Err(e) = engine.verify_pin_for_critical_action(&pin, now_ms) {
                let _ = save_secure_guard_record(storage, engine);
                return (
                    CTAP2_ERR_PIN_AUTH_INVALID,
                    to_cbor_bytes(&cbor_err(&format!("{:?}", e))),
                );
            }
        } else {
            let _ = engine.check_and_touch_session(now_ms);
            if !engine.is_unlocked() {
                return (
                    CTAP2_ERR_PIN_REQUIRED,
                    to_cbor_bytes(&cbor_err("SECURE_GUARD_LOCKED")),
                );
            }
        }
    }

    if let Some(Value::Bool(b)) = get_field(&entries, "wipe_on_5_failures") {
        engine.policy_mut().wipe_on_5_failures = *b;
    }
    if let Some(Value::Bool(b)) = get_field(&entries, "protect_keys_and_aegn") {
        engine.policy_mut().protect_keys_and_aegn = *b;
    }
    if let Some(Value::Bool(b)) = get_field(&entries, "protect_oath") {
        engine.policy_mut().protect_oath = *b;
    }
    if let Some(Value::Bool(b)) = get_field(&entries, "test_mode_non_destructive_wipe") {
        engine.policy_mut().test_mode_non_destructive_wipe = *b;
    }
    if let Some(Value::Integer(i)) = get_field(&entries, "session_duration_ms") {
        if let Ok(v) = u64::try_from(*i) {
            engine.policy_mut().session_duration_ms = v;
        }
    }
    if let Some(Value::Integer(i)) = get_field(&entries, "inactivity_timeout_ms") {
        if let Ok(v) = u64::try_from(*i) {
            engine.policy_mut().inactivity_timeout_ms = v;
        }
    }
    let _ = save_secure_guard_record(storage, engine);

    let out_map = vec![
        (
            Value::Text("status".into()),
            Value::Text("config_updated".into()),
        ),
        (
            Value::Text("wipe_on_5_failures".into()),
            Value::Bool(engine.policy().wipe_on_5_failures),
        ),
        (
            Value::Text("protect_keys_and_aegn".into()),
            Value::Bool(engine.policy().protect_keys_and_aegn),
        ),
        (
            Value::Text("protect_oath".into()),
            Value::Bool(engine.policy().protect_oath),
        ),
        (
            Value::Text("test_mode_non_destructive_wipe".into()),
            Value::Bool(engine.policy().test_mode_non_destructive_wipe),
        ),
    ];

    (0x00, to_cbor_bytes(&Value::Map(out_map)))
}