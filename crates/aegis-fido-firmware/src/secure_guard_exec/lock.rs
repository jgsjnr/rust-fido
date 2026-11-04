use super::to_cbor_bytes;
use crate::persistence::{FlashStorageBackend, SecureStorage};
use crate::secure_guard_storage::save_secure_guard_record;
use aegis_fido_core::secure_guard::SecureGuardEngine;
use ciborium::value::Value;
use std::vec::Vec;
/// 0x3C: OP_SECURE_GUARD_LOCK
pub(crate) fn handle_lock<B: FlashStorageBackend>(
    engine: &mut SecureGuardEngine,
    storage: &mut SecureStorage<B>,
    now_ms: u64,
) -> (u8, Vec<u8>) {
    let _ = engine.lock_now(now_ms);
    crate::hmac_cr_compat_layer::set_secure_guard_unlocked(false);
    let _ = save_secure_guard_record(storage, engine);

    let out_map = vec![
        (
            Value::Text("state".into()),
            Value::from(engine.state().wire_code()),
        ),
        (
            Value::Text("state_name".into()),
            Value::Text("Locked".into()),
        ),
        (Value::Text("locked".into()), Value::Bool(true)),
        (Value::Text("unlocked".into()), Value::Bool(false)),
        (Value::Text("failed_attempts".into()), Value::from(0u8)),
        (
            Value::Text("rate_limit_remaining_ms".into()),
            Value::from(0u64),
        ),
    ];
    (0x00, to_cbor_bytes(&Value::Map(out_map)))
}
