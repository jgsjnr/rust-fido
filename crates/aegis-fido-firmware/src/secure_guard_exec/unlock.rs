use super::{
    cbor_err, extract_bytes, get_field, hex_decode, hex_encode, shamir_2_of_3_recover,
    shamir_2_of_3_split, to_cbor_bytes, CTAP2_ERR_PIN_AUTH_INVALID, CTAP2_ERR_PIN_REQUIRED,
};
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::secure_guard::{MAX_ATTEMPTS, SecureGuardEngine, SecureGuardState};
use aegis_fido_core::wallet::WalletStore;
use ciborium::value::Value;
use core::sync::atomic::{AtomicU64, Ordering};
use rand_core::CryptoRng;
use std::format;
use std::vec::Vec;
use p256::elliptic_curve::Generate;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::SecretKey;
use crate::persistence::{FlashStorageBackend, SecureStorage};
use crate::secure_guard_storage::save_secure_guard_record;
/// F-05: deadline (ms monotonicos) ate a qual `change_pin` e negado sem oraculo.
///
/// O `change_pin` do engine nao arma `rate_limit_until_ms` (so o unlock arma);
/// a janela propria aqui espelha o atraso da MESMA `compute_backoff_ms` do unlock
/// (sem segunda tabela). Limpa no sucesso; reboot zera (a janela do engine,
/// persistida em NVS, segue valendo via pre-gate).
static CHANGE_PIN_BACKOFF_UNTIL_MS: AtomicU64 = AtomicU64::new(0);

/// Le a janela propria do change_pin (0 = sem backoff armado).
pub(crate) fn change_pin_backoff_until_ms() -> u64 {
    CHANGE_PIN_BACKOFF_UNTIL_MS.load(Ordering::Relaxed)
}

/// Arma a janela propria do change_pin.
pub(crate) fn arm_change_pin_backoff(until_ms: u64) {
    CHANGE_PIN_BACKOFF_UNTIL_MS.store(until_ms, Ordering::Relaxed);
}

/// Limpa a janela propria (sucesso troca o PIN e zera o contador).
pub(crate) fn clear_change_pin_backoff() {
    CHANGE_PIN_BACKOFF_UNTIL_MS.store(0, Ordering::Relaxed);
}

/// Corpo CBOR do change_pin negado por backoff (mesmo formato do unlock em
/// `RateLimited`: sucesso falso, contadores e `rate_limit_remaining_ms`).
fn change_pin_backoff_body(engine: &SecureGuardEngine, rate_limit_remaining_ms: u64) -> Vec<u8> {
    let rem_attempts = MAX_ATTEMPTS.saturating_sub(engine.failed_attempts());
    let out_map = vec![
        (Value::Text("success".into()), Value::Bool(false)),
        (Value::Text("state".into()), Value::from(engine.state().wire_code())),
        (Value::Text("state_name".into()), Value::Text(format!("{:?}", engine.state()))),
        (Value::Text("failed_attempts".into()), Value::from(engine.failed_attempts())),
        (Value::Text("remaining_attempts".into()), Value::from(rem_attempts)),
        (Value::Text("rate_limit_remaining_ms".into()), Value::from(rate_limit_remaining_ms)),
        (Value::Text("error".into()), Value::Text("rate_limited_change_pin_backoff".into())),
    ];
    to_cbor_bytes(&Value::Map(out_map))
}

/// Pre-gate F-05: nega change_pin sem consultar o oraculo com backoff ativo
/// (janela compartilhada do engine OU janela propria). `Some` = negado.
fn deny_change_pin_if_rate_limited(
    engine: &SecureGuardEngine,
    now_ms: u64,
) -> Option<(u8, Vec<u8>)> {
    let engine_remaining = engine.rate_limit_until_ms().saturating_sub(now_ms);
    let own_remaining = change_pin_backoff_until_ms().saturating_sub(now_ms);
    let remaining_ms = engine_remaining.max(own_remaining);
    if remaining_ms == 0 {
        return None;
    }
    Some((CTAP2_ERR_PIN_REQUIRED, change_pin_backoff_body(engine, remaining_ms)))
}
/// 0x3B: OP_SECURE_GUARD_UNLOCK
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_unlock_or_mgmt<B, R>(
    engine: &mut SecureGuardEngine,
    storage: &mut SecureStorage<B>,
    wallet: &mut WalletStore,
    key_mgr: &mut KeyManager,
    oath: &mut OathApplet,
    payload: &[u8],
    now_ms: u64,
    rng: &mut R,
) -> (u8, Vec<u8>)
where
    B: FlashStorageBackend,
    R: CryptoRng,
{
    // Tenta decodificar como mapa CBOR
    let cbor_parsed: Option<Value> = if !payload.is_empty() {
        ciborium::from_reader(payload).ok()
    } else {
        None
    };

    let entries: Vec<(Value, Value)> = match cbor_parsed {
        Some(Value::Map(m)) => m,
        _ => {
            // Se não for mapa CBOR, pode ser PIN raw (UTF-8 direto)
            if !payload.is_empty() {
                vec![
                    (Value::Text("action".into()), Value::Text("unlock".into())),
                    (Value::Text("pin".into()), Value::Bytes(payload.to_vec())),
                ]
            } else {
                return (CTAP2_ERR_PIN_REQUIRED, Vec::new());
            }
        }
    };

    let action_str = get_field(&entries, "action").and_then(|v| match v {
        Value::Text(s) => Some(s.as_str()),
        _ => None,
    });
    let op_num = get_field(&entries, "op").and_then(|v| match v {
        Value::Integer(i) => i64::try_from(*i).ok(),
        _ => None,
    });

    let is_provision = action_str == Some("provision") || op_num == Some(1);
    let is_change_pin = action_str == Some("change_pin") || op_num == Some(2);
    let is_recover = action_str == Some("recover") || op_num == Some(3);

    if is_provision {
        // --- 1. PROVISION ---
        let pin = match get_field(&entries, "pin").and_then(extract_bytes) {
            Some(p) => p,
            None => return (0x04, to_cbor_bytes(&cbor_err("missing_pin"))),
        };

        let mut recovery_code_raw = Vec::new();
        if let Some(r_val) = get_field(&entries, "recovery_code") {
            if let Some(b) = extract_bytes(r_val) {
                recovery_code_raw = b;
            }
        }
        if recovery_code_raw.is_empty() {
            // Gera 16 bytes CSPRNG
            recovery_code_raw.resize(16, 0);
            rng.fill_bytes(&mut recovery_code_raw);
        }

        // Configurações de política iniciais opcionais
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

        let mut pin_salt = [0u8; 16];
        rng.fill_bytes(&mut pin_salt);
        let mut rec_salt = [0u8; 16];
        rng.fill_bytes(&mut rec_salt);

        // Se a chave já estiver provisionada:
        if engine.is_provisioned() {
            let unl_res = engine.unlock_with_pin(&pin, now_ms);
            if unl_res.is_ok() {
                crate::hmac_cr_compat_layer::set_secure_guard_unlocked(true);
                let _ = save_secure_guard_record(storage, engine);
                let out_map = vec![
                    (
                        Value::Text("status".into()),
                        Value::Text("provisioned".into()),
                    ),
                    (
                        Value::Text("recovery_code".into()),
                        Value::Text(
                            engine
                                .last_rotated_recovery_code()
                                .map(|c| hex_encode(&c))
                                .unwrap_or_default(),
                        ),
                    ),
                    (
                        Value::Text("state".into()),
                        Value::from(engine.state().wire_code()),
                    ),
                    (Value::Text("unlocked".into()), Value::Bool(true)),
                ];
                return (0x00, to_cbor_bytes(&Value::Map(out_map)));
            } else {
                return (
                    CTAP2_ERR_PIN_AUTH_INVALID,
                    to_cbor_bytes(&cbor_err("already_provisioned_invalid_pin")),
                );
            }
        }

        match engine.provision_pin(&pin, pin_salt, &recovery_code_raw, rec_salt, now_ms) {
            Ok(rec_code) => {
                let _ = engine.unlock_with_pin(&pin, now_ms);
                crate::hmac_cr_compat_layer::set_secure_guard_unlocked(true);
                let _ = save_secure_guard_record(storage, engine);
                let out_map = vec![
                    (
                        Value::Text("status".into()),
                        Value::Text("provisioned".into()),
                    ),
                    (
                        Value::Text("recovery_code".into()),
                        Value::Text(hex_encode(&rec_code)),
                    ),
                    (
                        Value::Text("state".into()),
                        Value::from(engine.state().wire_code()),
                    ),
                    (Value::Text("unlocked".into()), Value::Bool(true)),
                ];
                (0x00, to_cbor_bytes(&Value::Map(out_map)))
            }
            Err(e) => (
                CTAP2_ERR_PIN_AUTH_INVALID,
                to_cbor_bytes(&cbor_err(&format!("{:?}", e))),
            ),
        }
    } else if is_change_pin {
        // --- 2. CHANGE PIN ---
        // F-05: backoff igual ao do unlock (pre-gate sem oraculo).
        if let Some(denied) = deny_change_pin_if_rate_limited(engine, now_ms) {
            return denied;
        }
        let current_pin = match get_field(&entries, "current_pin").and_then(extract_bytes) {
            Some(p) => p,
            None => return (0x04, to_cbor_bytes(&cbor_err("missing_current_pin"))),
        };
        let new_pin = match get_field(&entries, "new_pin").and_then(extract_bytes) {
            Some(p) => p,
            None => return (0x04, to_cbor_bytes(&cbor_err("missing_new_pin"))),
        };

        let mut new_salt = [0u8; 16];
        rng.fill_bytes(&mut new_salt);

        let res = engine.change_pin(&current_pin, &new_pin, new_salt, now_ms);
        let _ = save_secure_guard_record(storage, engine);

        match res {
            Ok(()) => {
                clear_change_pin_backoff();
                crate::hmac_cr_compat_layer::set_secure_guard_unlocked(true);
                let out_map = vec![
                    (
                        Value::Text("status".into()),
                        Value::Text("pin_changed".into()),
                    ),
                    (
                        Value::Text("state".into()),
                        Value::from(engine.state().wire_code()),
                    ),
                ];
                (0x00, to_cbor_bytes(&Value::Map(out_map)))
            }
            Err(e) => {
                // F-05: reusa a MESMA politica do unlock (compute_backoff_ms),
                // sem segunda tabela. Com atraso > 0, arma a janela propria e
                // responde como o unlock em backoff (0x36 + remaining_ms).
                let delay_ms = engine.policy().compute_backoff_ms(engine.failed_attempts());
                if delay_ms > 0 {
                    arm_change_pin_backoff(now_ms.saturating_add(delay_ms));
                    (
                        CTAP2_ERR_PIN_REQUIRED,
                        change_pin_backoff_body(engine, delay_ms),
                    )
                } else {
                    (
                        CTAP2_ERR_PIN_AUTH_INVALID,
                        to_cbor_bytes(&cbor_err(&format!("{:?}", e))),
                    )
                }
            }
        }
    } else if is_recover {
        // --- 3. RECOVER WITH CODE ---
        let recovery_code = match get_field(&entries, "recovery_code").and_then(extract_bytes) {
            Some(r) => r,
            None => return (0x04, to_cbor_bytes(&cbor_err("missing_recovery_code"))),
        };
        let new_pin = match get_field(&entries, "new_pin").and_then(extract_bytes) {
            Some(p) => p,
            None => return (0x04, to_cbor_bytes(&cbor_err("missing_new_pin"))),
        };

        // Decodifica hex se tiver 32 chars
        let rec_bytes = if recovery_code.len() == 32 {
            hex_decode(&recovery_code).unwrap_or(recovery_code)
        } else {
            recovery_code
        };

        let mut new_rec_salt = [0u8; 16];
        rng.fill_bytes(&mut new_rec_salt);

        let res = engine.recover_with_code(&rec_bytes, &new_pin, new_rec_salt, now_ms);
        let _ = save_secure_guard_record(storage, engine);

        match res {
            Ok(new_state) => {
                let mut out_map = Vec::new();
                out_map.push((
                    Value::Text("status".into()),
                    Value::Text("recovered".into()),
                ));
                out_map.push((
                    Value::Text("state".into()),
                    Value::from(new_state.wire_code()),
                ));
                if let Some(rotated) = engine.last_rotated_recovery_code() {
                    out_map.push((
                        Value::Text("new_recovery_code".into()),
                        Value::Text(hex_encode(&rotated)),
                    ));
                }
                (0x00, to_cbor_bytes(&Value::Map(out_map)))
            }
            Err(e) => (
                CTAP2_ERR_PIN_AUTH_INVALID,
                to_cbor_bytes(&cbor_err(&format!("{:?}", e))),
            ),
        }
    } else if action_str == Some("ecdh_handshake") {
        // --- 4. ECDH HANDSHAKE (GAP-02) ---
        let eph_secret = SecretKey::generate_from_rng(rng);
        let eph_public = eph_secret.public_key();
        let encoded_point = eph_public.to_sec1_point(false);
        let pub_bytes = encoded_point.as_bytes().to_vec();

        let out_map = vec![
            (Value::Text("status".into()), Value::Text("ecdh_ready".into())),
            (Value::Text("curve".into()), Value::Text("P-256".into())),
            (Value::Text("kdf".into()), Value::Text("HKDF-SHA256".into())),
            (Value::Text("aead".into()), Value::Text("AES-256-GCM".into())),
            (Value::Text("device_public_key".into()), Value::Bytes(pub_bytes)),
        ];
        (0x00, to_cbor_bytes(&Value::Map(out_map)))
    } else if action_str == Some("shamir_split") {
        // --- 5. SHAMIR 2-OF-3 SPLIT (OPP-05) ---
        if !engine.is_unlocked() {
            return (
                CTAP2_ERR_PIN_REQUIRED,
                to_cbor_bytes(&cbor_err("secure_guard_locked")),
            );
        }
        let secret = match get_field(&entries, "secret").and_then(extract_bytes) {
            Some(s) if !s.is_empty() => s,
            _ => return (0x04, to_cbor_bytes(&cbor_err("missing_secret"))),
        };

        if secret.len() > 512 {
            return (0x04, to_cbor_bytes(&cbor_err("secret_too_large")));
        }

        let shares = shamir_2_of_3_split(&secret, rng);
        let shares_val: Vec<Value> = shares.into_iter().map(Value::Bytes).collect();

        let out_map = vec![
            (Value::Text("status".into()), Value::Text("split_ok".into())),
            (Value::Text("threshold".into()), Value::from(2u8)),
            (Value::Text("total_shares".into()), Value::from(3u8)),
            (Value::Text("shares".into()), Value::Array(shares_val)),
        ];
        (0x00, to_cbor_bytes(&Value::Map(out_map)))
    } else if action_str == Some("shamir_recover") {
        // --- 6. SHAMIR 2-OF-3 RECOVER (OPP-05) ---
        if !engine.is_unlocked() {
            return (
                CTAP2_ERR_PIN_REQUIRED,
                to_cbor_bytes(&cbor_err("secure_guard_locked")),
            );
        }
        let shares_entries = match get_field(&entries, "shares") {
            Some(Value::Array(arr)) => arr,
            _ => return (0x04, to_cbor_bytes(&cbor_err("missing_shares_array"))),
        };

        let mut extracted_shares = Vec::new();
        for item in shares_entries {
            if let Some(b) = extract_bytes(item) {
                extracted_shares.push(b);
            }
        }

        if extracted_shares.len() < 2 {
            return (0x04, to_cbor_bytes(&cbor_err("insufficient_shares_need_at_least_2")));
        }

        match shamir_2_of_3_recover(&extracted_shares[0], &extracted_shares[1]) {
            Ok(recovered_secret) => {
                let out_map = vec![
                    (Value::Text("status".into()), Value::Text("recovered".into())),
                    (Value::Text("secret".into()), Value::Bytes(recovered_secret)),
                ];
                (0x00, to_cbor_bytes(&Value::Map(out_map)))
            }
            Err(err_msg) => (0x04, to_cbor_bytes(&cbor_err(err_msg))),
        }
    } else if action_str == Some("clear_sign_preview") {
        // --- 7. CLEAR SIGNING PREVIEW (OPP-06) ---
        let chain = get_field(&entries, "chain")
            .and_then(|v| match v {
                Value::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .unwrap_or("ETH");
        let tx_type = get_field(&entries, "tx_type")
            .and_then(|v| match v {
                Value::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .unwrap_or("Transfer");
        let recipient = get_field(&entries, "recipient")
            .and_then(|v| match v {
                Value::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .unwrap_or("0x71C818C04F0877C0eFa2A1a8c51F6b379361a3a9");
        let amount = get_field(&entries, "amount")
            .and_then(|v| match v {
                Value::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .unwrap_or("0.00 ETH");
        let fee = get_field(&entries, "fee")
            .and_then(|v| match v {
                Value::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .unwrap_or("0.0001 ETH");

        let mut oled = crate::oled_ssd1306_code_only::Ssd1306Driver::new();
        oled.virtual_buffer.render_clear_sign(chain, tx_type, recipient, amount, fee);

        let mut out_map = Vec::new();
        out_map.push((Value::Text("status".into()), Value::Text("preview_rendered".into())));
        out_map.push((
            Value::Text("hardware_oled_attached".into()),
            Value::Bool(crate::oled_ssd1306_code_only::HARDWARE_I2C_OLED_ATTACHED),
        ));
        out_map.push((Value::Text("frame_size".into()), Value::from(1024u64)));
        out_map.push((
            Value::Text("frame_bytes".into()),
            Value::Bytes(oled.virtual_buffer.as_slice().to_vec()),
        ));
        out_map.push((
            Value::Text("summary".into()),
            Value::Text(format!("{}: {} to {} (val: {}, fee: {})", chain, tx_type, recipient, amount, fee)),
        ));
        (0x00, to_cbor_bytes(&Value::Map(out_map)))
    } else if action_str == Some("keepassxc_slot_config") {
        let slot = match get_field(&entries, "slot") {
            Some(Value::Integer(i)) => u8::try_from(*i).unwrap_or(2),
            _ => 2,
        };
        let key_bytes = match get_field(&entries, "key").and_then(extract_bytes) {
            Some(k) if k.len() == 20 => k,
            _ => return (0x04, to_cbor_bytes(&cbor_err("invalid_or_missing_20byte_key"))),
        };
        let require_touch = match get_field(&entries, "require_touch") {
            Some(Value::Bool(b)) => *b,
            _ => false,
        };

        match crate::hmac_cr_compat_layer::configure_cr_compat_slot(slot, &key_bytes, require_touch) {
            Ok(()) => {
                let out_map = vec![
                    (Value::Text("status".into()), Value::Text("slot_configured".into())),
                    (Value::Text("slot".into()), Value::from(slot)),
                    (Value::Text("require_touch".into()), Value::Bool(require_touch)),
                ];
                (0x00, to_cbor_bytes(&Value::Map(out_map)))
            }
            Err(e) => (0x04, to_cbor_bytes(&cbor_err(e))),
        }
    } else if action_str == Some("keepassxc_challenge") {
        if !engine.is_unlocked() {
            return (
                CTAP2_ERR_PIN_REQUIRED,
                to_cbor_bytes(&cbor_err("secure_guard_locked")),
            );
        }
        let slot = match get_field(&entries, "slot") {
            Some(Value::Integer(i)) => u8::try_from(*i).unwrap_or(2),
            _ => 2,
        };
        let challenge = match get_field(&entries, "challenge").and_then(extract_bytes) {
            Some(c) if !c.is_empty() && c.len() <= 64 => c,
            _ => return (0x04, to_cbor_bytes(&cbor_err("invalid_or_missing_challenge"))),
        };

        match crate::hmac_cr_compat_layer::process_cr_compat_challenge(slot, &challenge) {
            Ok(resp) => {
                let crc = u16::from_le_bytes([resp[20], resp[21]]);
                let out_map = vec![
                    (Value::Text("status".into()), Value::Text("challenge_response_ok".into())),
                    (Value::Text("slot".into()), Value::from(slot)),
                    (Value::Text("response".into()), Value::Bytes(resp[..20].to_vec())),
                    (Value::Text("crc".into()), Value::from(crc)),
                ];
                (0x00, to_cbor_bytes(&Value::Map(out_map)))
            }
            Err(e) => (0x04, to_cbor_bytes(&cbor_err(e))),
        }
    } else if action_str == Some("register_ble_proximity") {
        // --- 8. REGISTER BLE PROXIMITY DEVICE ---
        let mut mac = [0u8; 6];
        if let Some(mac_val) = get_field(&entries, "mac") {
            match mac_val {
                Value::Bytes(b) if b.len() == 6 => mac.copy_from_slice(b),
                Value::Text(s) => {
                    let clean = s.replace([':', '-'], "");
                    if clean.len() == 12 {
                        if let Some(b) = hex_decode(clean.as_bytes()) {
                            if b.len() == 6 {
                                mac.copy_from_slice(&b);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let name_bytes = get_field(&entries, "name")
            .and_then(extract_bytes)
            .unwrap_or_else(|| b"Bluetooth Device".to_vec());

        engine.register_ble_proximity_device(mac, &name_bytes);
        if let Some(Value::Bool(b)) = get_field(&entries, "auto_lock_on_ble_away") {
            engine.set_auto_lock_on_ble_away(*b);
        }
        let _ = save_secure_guard_record(storage, engine);

        let out_map = vec![
            (Value::Text("status".into()), Value::Text("ble_proximity_registered".into())),
            (Value::Text("paired_ble_mac".into()), Value::Bytes(engine.paired_ble_mac().to_vec())),
            (Value::Text("ble_proximity_registered".into()), Value::Bool(true)),
            (Value::Text("auto_lock_on_ble_away".into()), Value::Bool(engine.auto_lock_on_ble_away())),
        ];
        (0x00, to_cbor_bytes(&Value::Map(out_map)))
    } else if action_str == Some("update_ble_rssi") {
        // --- 9. UPDATE BLE PROXIMITY RSSI & LOCK BARRIER ---
        let mut mac = *engine.paired_ble_mac();
        if let Some(mac_val) = get_field(&entries, "mac") {
            if let Some(b) = extract_bytes(mac_val) {
                if b.len() == 6 {
                    mac.copy_from_slice(&b);
                }
            }
        }
        let rssi_dbm = match get_field(&entries, "rssi") {
            Some(Value::Integer(i)) => i8::try_from(*i).unwrap_or(-75),
            _ => -75,
        };
        let is_away = match get_field(&entries, "is_away") {
            Some(Value::Bool(b)) => *b,
            _ => rssi_dbm < -75,
        };

        let locked = engine.on_ble_proximity_update(&mac, rssi_dbm, is_away, now_ms).unwrap_or(false);
        if locked {
            let _ = save_secure_guard_record(storage, engine);
        }

        let out_map = vec![
            (Value::Text("status".into()), Value::Text("ble_rssi_updated".into())),
            (Value::Text("locked".into()), Value::Bool(locked)),
            (Value::Text("state".into()), Value::from(engine.state().wire_code())),
            (Value::Text("unlocked".into()), Value::Bool(engine.is_unlocked())),
            (Value::Text("ble_proximity_away".into()), Value::Bool(engine.ble_proximity_away())),
            (Value::Text("last_ble_rssi_dbm".into()), Value::from(engine.last_ble_rssi_dbm() as i64)),
        ];
        (0x00, to_cbor_bytes(&Value::Map(out_map)))
    } else {
        // --- 4. UNLOCK (Padrão) ---
        let pin = match get_field(&entries, "pin").and_then(extract_bytes) {
            Some(p) => p,
            None => {
                return (
                    CTAP2_ERR_PIN_REQUIRED,
                    to_cbor_bytes(&cbor_err("missing_pin")),
                )
            }
        };

        let res = engine.unlock_with_pin(&pin, now_ms);

        // Se falhou 5 vezes e wipe_on_5_failures for true, apaga apenas carteiras/chaves
        if engine.state() == SecureGuardState::Unprovisioned
            && engine.policy().wipe_on_5_failures
            && !engine.policy().test_mode_non_destructive_wipe
        {
            log::warn!("[SECURE_GUARD] 5 falhas consecutivas: wipe seletivo de carteiras e chaves");
            *wallet = WalletStore::new();
            *key_mgr = KeyManager::new();
            let _ = crate::vendor_exec::save_states(storage, key_mgr, oath);
        }

        // Persiste imediatamente na NVS antes de responder!
        let _ = save_secure_guard_record(storage, engine);

        match res {
            Ok(()) => {
                crate::hmac_cr_compat_layer::set_secure_guard_unlocked(true);
                let mut out_map = Vec::new();
                out_map.push((Value::Text("success".into()), Value::Bool(true)));
                out_map.push((
                    Value::Text("state".into()),
                    Value::from(engine.state().wire_code()),
                ));
                out_map.push((
                    Value::Text("state_name".into()),
                    Value::Text(format!("{:?}", engine.state())),
                ));
                out_map.push((Value::Text("failed_attempts".into()), Value::from(0u8)));
                out_map.push((
                    Value::Text("remaining_attempts".into()),
                    Value::from(MAX_ATTEMPTS),
                ));
                (0x00, to_cbor_bytes(&Value::Map(out_map)))
            }
            Err(err) => {
                let rem_attempts = MAX_ATTEMPTS.saturating_sub(engine.failed_attempts());
                let rem_ms = if engine.rate_limit_until_ms() > now_ms {
                    engine.rate_limit_until_ms().saturating_sub(now_ms)
                } else {
                    0
                };
                let mut out_map = Vec::new();
                out_map.push((Value::Text("success".into()), Value::Bool(false)));
                out_map.push((
                    Value::Text("state".into()),
                    Value::from(engine.state().wire_code()),
                ));
                out_map.push((
                    Value::Text("state_name".into()),
                    Value::Text(format!("{:?}", engine.state())),
                ));
                out_map.push((
                    Value::Text("failed_attempts".into()),
                    Value::from(engine.failed_attempts()),
                ));
                out_map.push((
                    Value::Text("remaining_attempts".into()),
                    Value::from(rem_attempts),
                ));
                out_map.push((
                    Value::Text("rate_limit_remaining_ms".into()),
                    Value::from(rem_ms),
                ));
                out_map.push((
                    Value::Text("error".into()),
                    Value::Text(format!("{:?}", err)),
                ));
                (CTAP2_ERR_PIN_REQUIRED, to_cbor_bytes(&Value::Map(out_map)))
            }
        }
    }
}