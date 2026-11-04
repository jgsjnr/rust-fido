use super::to_cbor_bytes;
use aegis_fido_core::secure_guard::{SecureGuardEngine, MAX_ATTEMPTS};
use ciborium::value::Value;
use std::format;
use std::vec::Vec;
/// 0x3A: OP_SECURE_GUARD_STATUS
pub fn handle_status(engine: &mut SecureGuardEngine, now_ms: u64) -> (u8, Vec<u8>) {
    // Touch / check de sessão se Unlocked
    let _ = engine.check_and_touch_session(now_ms);

    let rate_limit_remaining_ms = if engine.rate_limit_until_ms() > now_ms {
        engine.rate_limit_until_ms().saturating_sub(now_ms)
    } else {
        0
    };

    let session_remaining_ms = if engine.is_unlocked() {
        engine.policy().session_duration_ms
    } else {
        0
    };

    let mut map = Vec::new();
    map.push((
        Value::Text("state".into()),
        Value::from(engine.state().wire_code()),
    ));
    map.push((
        Value::Text("state_name".into()),
        Value::Text(format!("{:?}", engine.state())),
    ));
    map.push((
        Value::Text("provisioned".into()),
        Value::Bool(engine.is_provisioned()),
    ));
    map.push((
        Value::Text("unlocked".into()),
        Value::Bool(engine.is_unlocked()),
    ));
    map.push((
        Value::Text("failed_attempts".into()),
        Value::from(engine.failed_attempts()),
    ));
    let rem_attempts = MAX_ATTEMPTS.saturating_sub(engine.failed_attempts());
    map.push((
        Value::Text("remaining_attempts".into()),
        Value::from(rem_attempts),
    ));
    map.push((
        Value::Text("max_attempts".into()),
        Value::from(MAX_ATTEMPTS),
    ));
    map.push((
        Value::Text("rate_limit_remaining_ms".into()),
        Value::from(rate_limit_remaining_ms),
    ));
    map.push((
        Value::Text("session_remaining_ms".into()),
        Value::from(session_remaining_ms),
    ));
    map.push((
        Value::Text("wipe_on_5_failures".into()),
        Value::Bool(engine.policy().wipe_on_5_failures),
    ));
    map.push((
        Value::Text("protect_keys_and_aegn".into()),
        Value::Bool(engine.policy().protect_keys_and_aegn),
    ));
    map.push((
        Value::Text("protect_oath".into()),
        Value::Bool(engine.policy().protect_oath),
    ));
    map.push((
        Value::Text("test_mode_non_destructive_wipe".into()),
        Value::Bool(engine.policy().test_mode_non_destructive_wipe),
    ));
    map.push((
        Value::Text("last_wipe_simulated".into()),
        Value::Bool(engine.last_wipe_simulated()),
    ));
    map.push((
        Value::Text("audit_count".into()),
        Value::from(engine.audit_log().len() as u64),
    ));
    map.push((
        Value::Text("efuse_safety_locked".into()),
        Value::Bool(crate::efuse_safety_lock::EFUSE_WRITE_HARD_LOCKED),
    ));
    map.push((
        Value::Text("ecdh_channel_supported".into()),
        Value::Bool(true),
    ));
    map.push((
        Value::Text("shamir_slip39_supported".into()),
        Value::Bool(true),
    ));
    map.push((
        Value::Text("ctap21_hmac_secret_supported".into()),
        Value::Bool(true),
    ));
    map.push((
        Value::Text("oled_clear_sign_code_ready".into()),
        Value::Bool(true),
    ));
    map.push((
        Value::Text("paired_ble_mac".into()),
        Value::Bytes(engine.paired_ble_mac().to_vec()),
    ));
    let name_str = core::str::from_utf8(engine.paired_ble_name())
        .unwrap_or("")
        .trim_matches('\0');
    map.push((
        Value::Text("paired_ble_name".into()),
        Value::Text(name_str.into()),
    ));
    map.push((
        Value::Text("ble_proximity_registered".into()),
        Value::Bool(engine.ble_proximity_registered()),
    ));
    map.push((
        Value::Text("last_ble_rssi_dbm".into()),
        Value::from(engine.last_ble_rssi_dbm() as i64),
    ));
    map.push((
        Value::Text("ble_proximity_away".into()),
        Value::Bool(engine.ble_proximity_away()),
    ));
    map.push((
        Value::Text("auto_lock_on_ble_away".into()),
        Value::Bool(engine.auto_lock_on_ble_away()),
    ));

    let device_ble_mac = {
        #[cfg(target_os = "espidf")]
        {
            let mut mac = [0u8; 6];
            let _ = unsafe {
                esp_idf_sys::esp_read_mac(mac.as_mut_ptr(), esp_idf_sys::esp_mac_type_t_ESP_MAC_BT)
            };
            mac
        }
        #[cfg(not(target_os = "espidf"))]
        {
            [0x3C, 0x84, 0x27, 0xC7, 0x17, 0x78]
        }
    };
    map.push((
        Value::Text("device_ble_mac".into()),
        Value::Bytes(device_ble_mac.to_vec()),
    ));
    map.push((
        Value::Text("device_ble_name".into()),
        Value::Text("AegisKey".into()),
    ));

    (0x00, to_cbor_bytes(&Value::Map(map)))
}
