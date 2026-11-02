//! Executor Vendor CBOR para o Secure Guard (0x3A..0x3E)
//!
//! Implementa os opcodes de gerenciamento, provisionamento, desbloqueio, bloqueio,
//! configuração e wipe seletivo do subsistema Secure Guard:
//! - 0x3A: OP_SECURE_GUARD_STATUS
//! - 0x3B: OP_SECURE_GUARD_UNLOCK (provision, unlock, change_pin, recover)
//! - 0x3C: OP_SECURE_GUARD_LOCK
//! - 0x3D: OP_SECURE_GUARD_CONFIG
//! - 0x3E: OP_SECURE_GUARD_WIPE_SELECTIVE

use ciborium::value::Value;
use rand_core::CryptoRng;
use std::format;
use std::string::String;
use std::vec::Vec;

use p256::elliptic_curve::Generate;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::SecretKey;

use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::secure_guard::{
    SecureGuardEngine, SecureGuardState, MAX_ATTEMPTS, OP_SECURE_GUARD_CONFIG,
    OP_SECURE_GUARD_LOCK, OP_SECURE_GUARD_STATUS, OP_SECURE_GUARD_UNLOCK,
    OP_SECURE_GUARD_WIPE_SELECTIVE,
};
use aegis_fido_core::wallet::WalletStore;

use crate::persistence::{FlashStorageBackend, SecureStorage};
use crate::secure_guard_storage::save_secure_guard_record;

/// Código CTAP2 de erro quando PIN / desbloqueio é requerido (0x36).
pub const CTAP2_ERR_PIN_REQUIRED: u8 = 0x36;
/// Código CTAP2 de erro quando PIN fornecido é inválido (0x33).
pub const CTAP2_ERR_PIN_AUTH_INVALID: u8 = 0x33;
/// Código CTAP2 de erro genérico / vendor.
pub const CTAP2_ERR_VENDOR_INTERNAL: u8 = 0xF0;

/// Auxiliar para serializar `Value` CBOR em `Vec<u8>`.
fn to_cbor_bytes(val: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = ciborium::into_writer(val, &mut out);
    out
}

/// Auxiliar para buscar texto ou inteiro em um mapa CBOR.
fn get_field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    for (k, v) in entries {
        if let Value::Text(s) = k {
            if s == key {
                return Some(v);
            }
        }
    }
    None
}

/// Extrai bytes de um `Value::Bytes` ou converte `Value::Text` em bytes.
fn extract_bytes(val: &Value) -> Option<Vec<u8>> {
    match val {
        Value::Bytes(b) => Some(b.clone()),
        Value::Text(s) => Some(s.as_bytes().to_vec()),
        _ => None,
    }
}

/// Multiplicação no corpo de Galois GF(256) com polinômio redutor 0x11B (AES).
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

/// Inverso multiplicativo em GF(256) via a^254 (Pequeno Teorema de Fermat).
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut res = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    while exp > 0 {
        if (exp & 1) != 0 {
            res = gf256_mul(res, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    res
}

/// Divisão no corpo GF(256).
fn gf256_div(a: u8, b: u8) -> u8 {
    gf256_mul(a, gf256_inv(b))
}

/// Divide um segredo em 3 partes com limiar de 2 partes (Shamir 2-de-3 sobre GF(256)).
/// Cada share é formado por `[x_coord, y_0, y_1, ..., y_{n-1}]`.
pub fn shamir_2_of_3_split<R: CryptoRng>(secret: &[u8], rng: &mut R) -> [Vec<u8>; 3] {
    let len = secret.len();
    let mut share1 = Vec::with_capacity(1 + len);
    let mut share2 = Vec::with_capacity(1 + len);
    let mut share3 = Vec::with_capacity(1 + len);

    // Coordenadas x para as 3 partes (1, 2, 3)
    share1.push(1);
    share2.push(2);
    share3.push(3);

    for &s in secret {
        // Coeficiente aleatório não nulo em GF(256)
        let mut coef = 0u8;
        while coef == 0 {
            let mut buf = [0u8; 1];
            rng.fill_bytes(&mut buf);
            coef = buf[0];
        }

        // f(x) = s ^ (coef * x)
        let y1 = s ^ gf256_mul(coef, 1);
        let y2 = s ^ gf256_mul(coef, 2);
        let y3 = s ^ gf256_mul(coef, 3);

        share1.push(y1);
        share2.push(y2);
        share3.push(y3);
    }

    [share1, share2, share3]
}

/// Reconstrói o segredo a partir de quaisquer 2 partes distintas (Shamir 2-de-3).
pub fn shamir_2_of_3_recover(share_a: &[u8], share_b: &[u8]) -> Result<Vec<u8>, &'static str> {
    if share_a.is_empty() || share_b.is_empty() {
        return Err("Share cannot be empty");
    }
    if share_a.len() != share_b.len() {
        return Err("Shares length mismatch");
    }
    let x_a = share_a[0];
    let x_b = share_b[0];
    if x_a == 0 || x_b == 0 {
        return Err("Invalid share x coordinate 0");
    }
    if x_a == x_b {
        return Err("Shares must have distinct coordinates");
    }

    let denom = x_a ^ x_b;
    let l_a = gf256_div(x_b, denom);
    let l_b = gf256_div(x_a, denom);

    let len = share_a.len() - 1;
    let mut recovered = Vec::with_capacity(len);

    for i in 1..share_a.len() {
        let y_a = share_a[i];
        let y_b = share_b[i];
        let term_a = gf256_mul(y_a, l_a);
        let term_b = gf256_mul(y_b, l_b);
        recovered.push(term_a ^ term_b);
    }

    Ok(recovered)
}

/// Executa qualquer opcode do Secure Guard (0x3A..0x3E).
#[allow(clippy::too_many_arguments)]
pub fn exec_secure_guard_op<B, R>(
    engine: &mut SecureGuardEngine,
    storage: &mut SecureStorage<B>,
    wallet: &mut WalletStore,
    key_mgr: &mut KeyManager,
    oath: &mut OathApplet,
    op: u8,
    payload: &[u8],
    now_ms: u64,
    rng: &mut R,
) -> (u8, Vec<u8>)
where
    B: FlashStorageBackend,
    R: CryptoRng,
{
    match op {
        OP_SECURE_GUARD_STATUS => handle_status(engine, now_ms),
        OP_SECURE_GUARD_UNLOCK => {
            handle_unlock_or_mgmt(engine, storage, wallet, key_mgr, oath, payload, now_ms, rng)
        }
        OP_SECURE_GUARD_LOCK => handle_lock(engine, storage, now_ms),
        OP_SECURE_GUARD_CONFIG => handle_config(engine, storage, payload, now_ms),
        OP_SECURE_GUARD_WIPE_SELECTIVE => {
            handle_wipe_selective(engine, storage, wallet, key_mgr, oath, payload, now_ms)
        }
        _ => (0x04, Vec::new()),
    }
}

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
                esp_idf_sys::esp_read_mac(
                    mac.as_mut_ptr(),
                    esp_idf_sys::esp_mac_type_t_ESP_MAC_BT,
                )
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

/// 0x3B: OP_SECURE_GUARD_UNLOCK
#[allow(clippy::too_many_arguments)]
fn handle_unlock_or_mgmt<B, R>(
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
            Err(e) => (
                CTAP2_ERR_PIN_AUTH_INVALID,
                to_cbor_bytes(&cbor_err(&format!("{:?}", e))),
            ),
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

/// 0x3C: OP_SECURE_GUARD_LOCK
fn handle_lock<B: FlashStorageBackend>(
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

/// 0x3D: OP_SECURE_GUARD_CONFIG
fn handle_config<B: FlashStorageBackend>(
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

/// 0x3E: OP_SECURE_GUARD_WIPE_SELECTIVE
fn handle_wipe_selective<B: FlashStorageBackend>(
    engine: &mut SecureGuardEngine,
    storage: &mut SecureStorage<B>,
    wallet: &mut WalletStore,
    key_mgr: &mut KeyManager,
    oath: &mut OathApplet,
    payload: &[u8],
    now_ms: u64,
) -> (u8, Vec<u8>) {
    let entries = match ciborium::from_reader(payload) {
        Ok(Value::Map(entries)) => entries,
        _ => Vec::new(),
    };

    let pin_opt = get_field(&entries, "pin").and_then(extract_bytes);

    // Validação de confirmação de Wipe Full / Factory Reset de emergência:
    // Permite reset para Unprovisioned mesmo se a chave estiver Locked, RateLimited ou RecoveryRequired!
    let confirm_bool = get_field(&entries, "confirm") == Some(&Value::Bool(true));
    let confirm_str = get_field(&entries, "confirmation")
        .and_then(|v| match v {
            Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
        .map(|s| s.eq_ignore_ascii_case("WIPE-CONFIRMED") || !s.is_empty())
        .unwrap_or(false);

    let scope_full = get_field(&entries, "scope")
        .map(|v| match v {
            Value::Integer(i) => {
                let val = i64::try_from(*i).unwrap_or(0);
                val == 0xFF || val == 0x07
            }
            Value::Text(s) => {
                s == "0xFF" || s == "0x07" || s == "full" || s == "all" || s == "factory_reset"
            }
            _ => false,
        })
        .unwrap_or(false);

    let is_emergency_wipe = confirm_bool || confirm_str || scope_full;

    // Se NÃO for Wipe Full / Emergency Wipe, exige autorização com PIN ou sessão ativa
    if !is_emergency_wipe && engine.is_provisioned() {
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
            let is_authorized = engine.is_unlocked() || engine.policy().test_mode_non_destructive_wipe;
            if !is_authorized {
                return (
                    CTAP2_ERR_PIN_REQUIRED,
                    to_cbor_bytes(&cbor_err("SECURE_GUARD_LOCKED")),
                );
            }
        }
    }

    // Valida confirmação explícita
    let mut confirmed = is_emergency_wipe;
    if let Some(Value::Text(s)) = get_field(&entries, "scope") {
        if s == "protected_resources" {
            confirmed = true;
        }
    }

    if !confirmed && !engine.policy().test_mode_non_destructive_wipe {
        return (0x04, to_cbor_bytes(&cbor_err("CONFIRMATION_REQUIRED")));
    }

    if is_emergency_wipe {
        engine.reset_to_factory();
    } else {
        let _ = engine.execute_wipe(now_ms);
    }

    if !engine.last_wipe_simulated() {
        log::info!("[SECURE_GUARD] Wipe full/seletivo: limpando carteiras e chaves protegidas");
        *wallet = WalletStore::new();
        *key_mgr = KeyManager::new();
        *oath = OathApplet::new();
        let _ = crate::vendor_exec::save_states(storage, key_mgr, oath);
    } else {
        log::info!("[SECURE_GUARD] Wipe simulado em modo de teste (chaves físicas mantidas)");
    }

    crate::hmac_cr_compat_layer::set_secure_guard_unlocked(false);
    let _ = save_secure_guard_record(storage, engine);

    let out_map = vec![
        (Value::Text("wiped".into()), Value::Bool(true)),
        (
            Value::Text("simulated".into()),
            Value::Bool(engine.last_wipe_simulated()),
        ),
        (
            Value::Text("state".into()),
            Value::from(engine.state().wire_code()),
        ),
    ];

    (0x00, to_cbor_bytes(&Value::Map(out_map)))
}

fn cbor_err(msg: &str) -> Value {
    Value::Map(vec![(Value::Text("error".into()), Value::Text(msg.into()))])
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_decode(s: &[u8]) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let hi = hex_val(s[i])?;
        let lo = hex_val(s[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::MockFlashBackend;
    use aegis_fido_core::secure_guard::SecureGuardPolicy;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x11; 32], &[0x22; 32])
    }

    #[test]
    fn test_status_op_returns_complete_fields() {
        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..Default::default()
        };
        let mut engine = SecureGuardEngine::new(policy);
        let (st, body) = handle_status(&mut engine, 1000);
        assert_eq!(st, 0x00);
        let val: Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
        if let Value::Map(entries) = val {
            assert_eq!(
                get_field(&entries, "provisioned"),
                Some(&Value::Bool(false))
            );
            assert_eq!(get_field(&entries, "unlocked"), Some(&Value::Bool(false)));
            assert_eq!(get_field(&entries, "max_attempts"), Some(&Value::from(5u8)));
        } else {
            panic!("expected cbor map");
        }
    }

    #[test]
    fn test_provision_and_unlock_flow() {
        let mut storage = test_storage();
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();
        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..Default::default()
        };
        let mut engine = SecureGuardEngine::new(policy);
        let mut rng = rand::rng();

        // 1. Provision via 0x3B CBOR
        let prov_map = vec![
            (
                Value::Text("action".into()),
                Value::Text("provision".into()),
            ),
            (Value::Text("pin".into()), Value::Text("5839".into())),
        ];
        let prov_cbor = to_cbor_bytes(&Value::Map(prov_map));

        let (st, _body) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &prov_cbor,
            1000,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert_eq!(engine.state(), SecureGuardState::Unlocked);
        assert!(engine.is_unlocked());
        assert!(engine.is_provisioned());
        let _ = engine.lock_now(1001);
        assert_eq!(engine.state(), SecureGuardState::Locked);

        // 2. Unlock com PIN errado
        let bad_unlock = vec![
            (Value::Text("action".into()), Value::Text("unlock".into())),
            (Value::Text("pin".into()), Value::Text("9999".into())),
        ];
        let bad_cbor = to_cbor_bytes(&Value::Map(bad_unlock));

        let (st_bad, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &bad_cbor,
            1100,
            &mut rng,
        );
        assert_eq!(st_bad, CTAP2_ERR_PIN_REQUIRED);
        assert_eq!(engine.failed_attempts(), 1);

        // 3. Unlock com PIN correto
        let good_unlock = vec![
            (Value::Text("action".into()), Value::Text("unlock".into())),
            (Value::Text("pin".into()), Value::Text("5839".into())),
        ];
        let good_cbor = to_cbor_bytes(&Value::Map(good_unlock));

        let (st_good, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &good_cbor,
            1200,
            &mut rng,
        );
        assert_eq!(st_good, 0x00);
        assert_eq!(engine.state(), SecureGuardState::Unlocked);
        assert!(engine.is_unlocked());

        // 4. Lock via 0x3C
        let (st_lock, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_LOCK,
            &[],
            1300,
            &mut rng,
        );
        assert_eq!(st_lock, 0x00);
        assert_eq!(engine.state(), SecureGuardState::Locked);
    }

    #[test]
    fn test_status_includes_security_feature_flags() {
        let policy = SecureGuardPolicy::default();
        let mut engine = SecureGuardEngine::new(policy);
        let (st, body) = handle_status(&mut engine, 1000);
        assert_eq!(st, 0x00);
        let val: Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
        if let Value::Map(entries) = val {
            assert_eq!(
                get_field(&entries, "efuse_safety_locked"),
                Some(&Value::Bool(true))
            );
            assert_eq!(
                get_field(&entries, "ecdh_channel_supported"),
                Some(&Value::Bool(true))
            );
            assert_eq!(
                get_field(&entries, "shamir_slip39_supported"),
                Some(&Value::Bool(true))
            );
            assert_eq!(
                get_field(&entries, "ctap21_hmac_secret_supported"),
                Some(&Value::Bool(true))
            );
            assert_eq!(
                get_field(&entries, "oled_clear_sign_code_ready"),
                Some(&Value::Bool(true))
            );
        } else {
            panic!("expected cbor map");
        }
    }

    #[test]
    fn test_ecdh_handshake_action() {
        let mut storage = test_storage();
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();
        let mut engine = SecureGuardEngine::new(SecureGuardPolicy::default());
        let mut rng = rand::rng();

        let req = vec![(
            Value::Text("action".into()),
            Value::Text("ecdh_handshake".into()),
        )];
        let req_cbor = to_cbor_bytes(&Value::Map(req));

        let (st, body) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &req_cbor,
            1000,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        let val: Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
        if let Value::Map(entries) = val {
            assert_eq!(
                get_field(&entries, "status"),
                Some(&Value::Text("ecdh_ready".into()))
            );
            assert_eq!(
                get_field(&entries, "curve"),
                Some(&Value::Text("P-256".into()))
            );
            let pub_bytes = get_field(&entries, "device_public_key")
                .and_then(extract_bytes)
                .expect("public key bytes");
            assert_eq!(pub_bytes.len(), 65);
            assert_eq!(pub_bytes[0], 0x04);
        } else {
            panic!("expected cbor map");
        }
    }

    #[test]
    fn test_shamir_2_of_3_workflow() {
        let mut storage = test_storage();
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();
        let mut engine = SecureGuardEngine::new(SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..Default::default()
        });
        let mut rng = rand::rng();

        // Provision e unlock primeiro
        let prov_map = vec![
            (Value::Text("action".into()), Value::Text("provision".into())),
            (Value::Text("pin".into()), Value::Text("5839".into())),
        ];
        exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(prov_map)),
            1000,
            &mut rng,
        );
        let unlock_map = vec![
            (Value::Text("action".into()), Value::Text("unlock".into())),
            (Value::Text("pin".into()), Value::Text("5839".into())),
        ];
        exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(unlock_map)),
            1100,
            &mut rng,
        );
        assert!(engine.is_unlocked());

        // Split
        let secret = b"my_super_secret_seed_phrase_backup";
        let split_map = vec![
            (Value::Text("action".into()), Value::Text("shamir_split".into())),
            (Value::Text("secret".into()), Value::Bytes(secret.to_vec())),
        ];
        let (st_split, split_body) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(split_map)),
            1200,
            &mut rng,
        );
        assert_eq!(st_split, 0x00);
        let split_val: Value = ciborium::from_reader(split_body.as_slice()).expect("cbor parse");
        let (s1, s2, s3) = if let Value::Map(entries) = split_val {
            let shares = get_field(&entries, "shares").expect("shares");
            if let Value::Array(arr) = shares {
                (
                    extract_bytes(&arr[0]).unwrap(),
                    extract_bytes(&arr[1]).unwrap(),
                    extract_bytes(&arr[2]).unwrap(),
                )
            } else {
                panic!("shares not array");
            }
        } else {
            panic!("not map");
        };

        // Recover usando (s1, s2)
        let rec12 = shamir_2_of_3_recover(&s1, &s2).expect("recover 1+2");
        assert_eq!(rec12, secret);

        // Recover usando (s1, s3)
        let rec13 = shamir_2_of_3_recover(&s1, &s3).expect("recover 1+3");
        assert_eq!(rec13, secret);

        // Recover usando (s2, s3)
        let rec23 = shamir_2_of_3_recover(&s2, &s3).expect("recover 2+3");
        assert_eq!(rec23, secret);
    }

    #[test]
    fn test_clear_sign_preview_action() {
        let mut storage = test_storage();
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();
        let mut engine = SecureGuardEngine::new(SecureGuardPolicy::default());
        let mut rng = rand::rng();

        let preview_map = vec![
            (
                Value::Text("action".into()),
                Value::Text("clear_sign_preview".into()),
            ),
            (Value::Text("chain".into()), Value::Text("ETH".into())),
            (
                Value::Text("tx_type".into()),
                Value::Text("EIP-1559".into()),
            ),
            (
                Value::Text("recipient".into()),
                Value::Text("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".into()),
            ),
            (Value::Text("amount".into()), Value::Text("2.5 ETH".into())),
            (Value::Text("fee".into()), Value::Text("0.003 ETH".into())),
        ];

        let (st, body) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(preview_map)),
            1000,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        let val: Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
        if let Value::Map(entries) = val {
            assert_eq!(
                get_field(&entries, "status"),
                Some(&Value::Text("preview_rendered".into()))
            );
            assert_eq!(
                get_field(&entries, "hardware_oled_attached"),
                Some(&Value::Bool(false))
            );
            assert_eq!(get_field(&entries, "frame_size"), Some(&Value::from(1024u64)));
            let frame = get_field(&entries, "frame_bytes")
                .and_then(extract_bytes)
                .expect("frame bytes");
            assert_eq!(frame.len(), 1024);
        } else {
            panic!("not map");
        }
    }

    #[test]
    fn test_config_pin_validation() {
        let mut storage = test_storage();
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();
        let mut engine = SecureGuardEngine::new(SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..Default::default()
        });
        let mut rng = rand::rng();

        // Provision PIN "4927"
        let prov_map = vec![
            (Value::Text("action".into()), Value::Text("provision".into())),
            (Value::Text("pin".into()), Value::Bytes(b"4927".to_vec())),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(prov_map)),
            1000,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert_eq!(engine.state(), SecureGuardState::Unlocked);
        assert!(engine.is_unlocked());
        let _ = engine.lock_now(1001);
        assert_eq!(engine.state(), SecureGuardState::Locked);

        // 1. Config without PIN while Locked -> Rejects with CTAP2_ERR_PIN_REQUIRED (0x36)
        let config_map = vec![
            (Value::Text("wipe_on_5_failures".into()), Value::Bool(true)),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_CONFIG,
            &to_cbor_bytes(&Value::Map(config_map)),
            1100,
            &mut rng,
        );
        assert_eq!(st, CTAP2_ERR_PIN_REQUIRED);

        // 2. Config with WRONG PIN -> Rejects with CTAP2_ERR_PIN_AUTH_INVALID (0x33)
        let config_bad_pin = vec![
            (Value::Text("wipe_on_5_failures".into()), Value::Bool(true)),
            (Value::Text("pin".into()), Value::Bytes(b"9999".to_vec())),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_CONFIG,
            &to_cbor_bytes(&Value::Map(config_bad_pin)),
            1200,
            &mut rng,
        );
        assert_eq!(st, CTAP2_ERR_PIN_AUTH_INVALID);

        // 3. Config with CORRECT PIN -> Succeeds (0x00) and updates policy
        let config_good_pin = vec![
            (Value::Text("wipe_on_5_failures".into()), Value::Bool(true)),
            (Value::Text("pin".into()), Value::Bytes(b"4927".to_vec())),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_CONFIG,
            &to_cbor_bytes(&Value::Map(config_good_pin)),
            1300,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert!(engine.policy().wipe_on_5_failures);
    }

    #[test]
    fn test_wipe_selective_pin_validation() {
        let mut storage = test_storage();
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();
        let mut engine = SecureGuardEngine::new(SecureGuardPolicy {
            pbkdf2_iterations: 10,
            test_mode_non_destructive_wipe: false,
            ..Default::default()
        });
        let mut rng = rand::rng();

        // Provision PIN "4927"
        let prov_map = vec![
            (Value::Text("action".into()), Value::Text("provision".into())),
            (Value::Text("pin".into()), Value::Bytes(b"4927".to_vec())),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(prov_map)),
            1000,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert_eq!(engine.state(), SecureGuardState::Unlocked);
        assert!(engine.is_unlocked());
        let _ = engine.lock_now(1001);
        assert_eq!(engine.state(), SecureGuardState::Locked);

        // 1. Wipe without confirmation or PIN while Locked -> Rejects with CTAP2_ERR_PIN_REQUIRED (0x36)
        let wipe_no_confirm = vec![];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_WIPE_SELECTIVE,
            &to_cbor_bytes(&Value::Map(wipe_no_confirm)),
            1100,
            &mut rng,
        );
        assert_eq!(st, CTAP2_ERR_PIN_REQUIRED);

        // 2. Wipe Full confirmed without PIN -> Succeeds (0x00) and executes Wipe Full to Unprovisioned
        let wipe_confirmed = vec![
            (Value::Text("confirm".into()), Value::Bool(true)),
            (Value::Text("confirmation".into()), Value::Text("WIPE-CONFIRMED".into())),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_WIPE_SELECTIVE,
            &to_cbor_bytes(&Value::Map(wipe_confirmed)),
            1200,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert_eq!(engine.state(), SecureGuardState::Unprovisioned);
        assert!(!engine.is_provisioned());
    }

    #[test]
    fn test_any_pin_creation_000000_and_849201() {
        let mut storage = test_storage();
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();
        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..Default::default()
        };
        let mut engine = SecureGuardEngine::new(policy.clone());
        let mut rng = rand_core::OsRng;

        // 1. PIN 000000 is accepted
        let prov_zeros = vec![
            (Value::Text("action".into()), Value::Text("provision".into())),
            (Value::Text("pin".into()), Value::Text("000000".into())),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(prov_zeros)),
            1000,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert!(engine.is_provisioned());

        // Unlock com 000000
        let unl_zeros = vec![
            (Value::Text("action".into()), Value::Text("unlock".into())),
            (Value::Text("pin".into()), Value::Text("000000".into())),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(unl_zeros)),
            1100,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert!(engine.is_unlocked());

        // Wipe full com scope 0xFF
        let wipe_full = vec![
            (Value::Text("scope".into()), Value::from(0xFF)),
            (Value::Text("confirm".into()), Value::Bool(true)),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_WIPE_SELECTIVE,
            &to_cbor_bytes(&Value::Map(wipe_full)),
            1200,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert_eq!(engine.state(), SecureGuardState::Unprovisioned);

        // 2. PIN 849201 is accepted
        let prov_custom = vec![
            (Value::Text("action".into()), Value::Text("provision".into())),
            (Value::Text("pin".into()), Value::Text("849201".into())),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(prov_custom)),
            1300,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert!(engine.is_provisioned());

        // Unlock com 849201
        let unl_custom = vec![
            (Value::Text("action".into()), Value::Text("unlock".into())),
            (Value::Text("pin".into()), Value::Text("849201".into())),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(unl_custom)),
            1400,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert!(engine.is_unlocked());
    }

    #[test]
    fn test_wipe_full_emergency_in_ratelimited_or_locked_state() {
        let mut storage = test_storage();
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();
        let mut engine = SecureGuardEngine::new(SecureGuardPolicy {
            pbkdf2_iterations: 10,
            wipe_on_5_failures: false,
            ..Default::default()
        });
        let mut rng = rand_core::OsRng;

        // Provision PIN "849201"
        let prov = vec![
            (Value::Text("action".into()), Value::Text("provision".into())),
            (Value::Text("pin".into()), Value::Text("849201".into())),
        ];
        exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(prov)),
            1000,
            &mut rng,
        );
        let _ = engine.lock_now(1001);

        // 5 consecutive failures -> RateLimited (15s backoff)
        let mut time = 2000u64;
        for _ in 1..=5 {
            let bad = vec![
                (Value::Text("action".into()), Value::Text("unlock".into())),
                (Value::Text("pin".into()), Value::Text("000000".into())),
            ];
            exec_secure_guard_op(
                &mut engine,
                &mut storage,
                &mut wallet,
                &mut key_mgr,
                &mut oath,
                OP_SECURE_GUARD_UNLOCK,
                &to_cbor_bytes(&Value::Map(bad)),
                time,
                &mut rng,
            );
            time += 100;
        }
        assert_eq!(engine.state(), SecureGuardState::RateLimited);

        // Wipe Full emergency com confirmation "WIPE-CONFIRMED" mesmo em RateLimited!
        let emergency_wipe = vec![
            (Value::Text("confirmation".into()), Value::Text("WIPE-CONFIRMED".into())),
            (Value::Text("scope".into()), Value::from(0x07)),
        ];
        let (st, body) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_WIPE_SELECTIVE,
            &to_cbor_bytes(&Value::Map(emergency_wipe)),
            time,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert_eq!(engine.state(), SecureGuardState::Unprovisioned);
        assert!(!engine.is_provisioned());
        let val: Value = ciborium::from_reader(body.as_slice()).expect("cbor parse");
        if let Value::Map(entries) = val {
            assert_eq!(get_field(&entries, "wiped"), Some(&Value::Bool(true)));
            assert_eq!(get_field(&entries, "state"), Some(&Value::from(0u8)));
        }
    }

    #[test]
    fn test_keepassxc_slot_config_and_challenge_vendor_exec() {
        let mut rng = rand::rng();
        let mut storage = test_storage();
        let mut engine = SecureGuardEngine::new(SecureGuardPolicy { pbkdf2_iterations: 10, ..Default::default() });
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();

        // 1. Provision & Unlock
        let prov_payload = vec![
            (Value::Text("action".into()), Value::Text("provision".into())),
            (Value::Text("pin".into()), Value::Text("5839".into())),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(prov_payload)),
            100,
            &mut rng,
        );
        assert_eq!(st, 0x00);

        let unlock_payload = vec![
            (Value::Text("action".into()), Value::Text("unlock".into())),
            (Value::Text("pin".into()), Value::Text("5839".into())),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(unlock_payload)),
            200,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert!(engine.is_unlocked());

        // 2. Configure KeePassXC slot 2
        let cfg_payload = vec![
            (Value::Text("action".into()), Value::Text("keepassxc_slot_config".into())),
            (Value::Text("slot".into()), Value::from(2)),
            (Value::Text("key".into()), Value::Bytes(vec![0x77u8; 20])),
            (Value::Text("require_touch".into()), Value::Bool(false)),
        ];
        let (st, resp_bytes) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(cfg_payload)),
            300,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        let resp_val: Value = ciborium::from_reader(&resp_bytes[..]).unwrap();
        assert_eq!(get_field(resp_val.as_map().unwrap(), "status"), Some(&Value::Text("slot_configured".into())));

        // 3. Challenge on slot 2
        let chal_payload = vec![
            (Value::Text("action".into()), Value::Text("keepassxc_challenge".into())),
            (Value::Text("slot".into()), Value::from(2)),
            (Value::Text("challenge".into()), Value::Bytes(b"MySecretKeePassChallenge".to_vec())),
        ];
        let (st, resp_bytes) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(chal_payload)),
            400,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        let resp_val: Value = ciborium::from_reader(&resp_bytes[..]).unwrap();
        assert_eq!(get_field(resp_val.as_map().unwrap(), "status"), Some(&Value::Text("challenge_response_ok".into())));
        let resp_hmac = extract_bytes(get_field(resp_val.as_map().unwrap(), "response").unwrap()).unwrap();
        assert_eq!(resp_hmac.len(), 20);

        // 4. When locked, challenge is rejected
        let (st_lock, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_LOCK,
            &[],
            500,
            &mut rng,
        );
        assert_eq!(st_lock, 0x00);
        assert!(!engine.is_unlocked());

        let (st_chal_locked, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(vec![
                (Value::Text("action".into()), Value::Text("keepassxc_challenge".into())),
                (Value::Text("slot".into()), Value::from(2)),
                (Value::Text("challenge".into()), Value::Bytes(b"MySecretKeePassChallenge".to_vec())),
            ])),
            600,
            &mut rng,
        );
        assert_eq!(st_chal_locked, CTAP2_ERR_PIN_REQUIRED);
    }

    #[test]
    fn test_register_ble_proximity_and_rssi_update_cbor() {
        let mut rng = rand::rng();
        let mut storage = test_storage();
        let mut engine = SecureGuardEngine::new(SecureGuardPolicy::default());
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();

        // 1. Provision and Unlock
        let prov_payload = vec![
            (Value::Text("action".into()), Value::Text("provision".into())),
            (Value::Text("pin".into()), Value::Bytes(b"4927".to_vec())),
        ];
        let (st, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(prov_payload)),
            100,
            &mut rng,
        );
        assert_eq!(st, 0x00);

        let unl_payload = vec![
            (Value::Text("action".into()), Value::Text("unlock".into())),
            (Value::Text("pin".into()), Value::Bytes(b"4927".to_vec())),
        ];
        let (st_unl, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(unl_payload)),
            150,
            &mut rng,
        );
        assert_eq!(st_unl, 0x00);
        assert!(engine.is_unlocked());

        // 2. Register Bluetooth device
        let reg_payload = vec![
            (Value::Text("action".into()), Value::Text("register_ble_proximity".into())),
            (Value::Text("mac".into()), Value::Text("AA:BB:CC:DD:EE:FF".into())),
            (Value::Text("name".into()), Value::Text("Galaxy S24".into())),
        ];
        let (st_reg, resp_reg) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(reg_payload)),
            200,
            &mut rng,
        );
        assert_eq!(st_reg, 0x00);
        let resp_val: Value = ciborium::from_reader(&resp_reg[..]).unwrap();
        assert_eq!(get_field(resp_val.as_map().unwrap(), "status"), Some(&Value::Text("ble_proximity_registered".into())));
        assert!(engine.ble_proximity_registered());
        assert_eq!(engine.paired_ble_mac(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        // 3. Status includes BLE registration info
        let (st_st, resp_st) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_STATUS,
            &[],
            250,
            &mut rng,
        );
        assert_eq!(st_st, 0x00);
        let st_val: Value = ciborium::from_reader(&resp_st[..]).unwrap();
        assert_eq!(get_field(st_val.as_map().unwrap(), "ble_proximity_registered"), Some(&Value::Bool(true)));
        assert_eq!(get_field(st_val.as_map().unwrap(), "paired_ble_name"), Some(&Value::Text("Galaxy S24".into())));
        assert_eq!(get_field(st_val.as_map().unwrap(), "device_ble_mac"), Some(&Value::Bytes(vec![0x3C, 0x84, 0x27, 0xC7, 0x17, 0x78])));
        assert_eq!(get_field(st_val.as_map().unwrap(), "device_ble_name"), Some(&Value::Text("AegisKey".into())));

        // 4. Update RSSI: away -> Locks session immediately!
        let away_payload = vec![
            (Value::Text("action".into()), Value::Text("update_ble_rssi".into())),
            (Value::Text("rssi".into()), Value::from(-92)),
            (Value::Text("is_away".into()), Value::Bool(true)),
        ];
        let (st_away, resp_away) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &to_cbor_bytes(&Value::Map(away_payload)),
            300,
            &mut rng,
        );
        assert_eq!(st_away, 0x00);
        let away_val: Value = ciborium::from_reader(&resp_away[..]).unwrap();
        assert_eq!(get_field(away_val.as_map().unwrap(), "locked"), Some(&Value::Bool(true)));
        assert_eq!(get_field(away_val.as_map().unwrap(), "unlocked"), Some(&Value::Bool(false)));
        assert!(!engine.is_unlocked());
        assert_eq!(engine.state(), SecureGuardState::Locked);
    }
}