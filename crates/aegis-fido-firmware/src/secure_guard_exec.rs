//! Executor Vendor CBOR para o Secure Guard (0x3A..0x3E)
//!
//! Implementa os opcodes de gerenciamento, provisionamento, desbloqueio, bloqueio,
//! configuração e wipe seletivo do subsistema Secure Guard:
//! - 0x3A: OP_SECURE_GUARD_STATUS
//! - 0x3B: OP_SECURE_GUARD_UNLOCK (provision, unlock, change_pin, recover)
//! - 0x3C: OP_SECURE_GUARD_LOCK
//! - 0x3D: OP_SECURE_GUARD_CONFIG
//! - 0x3E: OP_SECURE_GUARD_WIPE_SELECTIVE

use std::format;
use std::string::String;
use std::vec::Vec;
use ciborium::value::Value;
use rand_core::{CryptoRng, RngCore};

use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::secure_guard::{
    SecureGuardEngine, SecureGuardState, MAX_ATTEMPTS,
    OP_SECURE_GUARD_CONFIG, OP_SECURE_GUARD_LOCK, OP_SECURE_GUARD_STATUS, OP_SECURE_GUARD_UNLOCK,
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
    R: RngCore + CryptoRng,
{
    match op {
        OP_SECURE_GUARD_STATUS => handle_status(engine, now_ms),
        OP_SECURE_GUARD_UNLOCK => handle_unlock_or_mgmt(
            engine, storage, wallet, key_mgr, oath, payload, now_ms, rng,
        ),
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
    R: RngCore + CryptoRng,
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
                    (
                        Value::Text("action".into()),
                        Value::Text("unlock".into()),
                    ),
                    (
                        Value::Text("pin".into()),
                        Value::Bytes(payload.to_vec()),
                    ),
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

        match engine.provision_pin(&pin, pin_salt, &recovery_code_raw, rec_salt, now_ms) {
            Ok(rec_code) => {
                let _ = save_secure_guard_record(storage, engine);
                let out_map = vec![
                    (Value::Text("status".into()), Value::Text("provisioned".into())),
                    (
                        Value::Text("recovery_code".into()),
                        Value::Text(hex_encode(&rec_code)),
                    ),
                    (
                        Value::Text("state".into()),
                        Value::from(engine.state().wire_code()),
                    ),
                    (Value::Text("unlocked".into()), Value::Bool(false)),
                ];
                (0x00, to_cbor_bytes(&Value::Map(out_map)))
            }
            Err(e) => (CTAP2_ERR_PIN_AUTH_INVALID, to_cbor_bytes(&cbor_err(&format!("{:?}", e)))),
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
                let out_map = vec![
                    (Value::Text("status".into()), Value::Text("pin_changed".into())),
                    (
                        Value::Text("state".into()),
                        Value::from(engine.state().wire_code()),
                    ),
                ];
                (0x00, to_cbor_bytes(&Value::Map(out_map)))
            }
            Err(e) => (CTAP2_ERR_PIN_AUTH_INVALID, to_cbor_bytes(&cbor_err(&format!("{:?}", e)))),
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
                out_map.push((Value::Text("status".into()), Value::Text("recovered".into())));
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
            Err(e) => (CTAP2_ERR_PIN_AUTH_INVALID, to_cbor_bytes(&cbor_err(&format!("{:?}", e)))),
        }
    } else {
        // --- 4. UNLOCK (Padrão) ---
        let pin = match get_field(&entries, "pin").and_then(extract_bytes) {
            Some(p) => p,
            None => return (CTAP2_ERR_PIN_REQUIRED, to_cbor_bytes(&cbor_err("missing_pin"))),
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
    let _ = save_secure_guard_record(storage, engine);

    let out_map = vec![
        (
            Value::Text("state".into()),
            Value::from(engine.state().wire_code()),
        ),
        (Value::Text("locked".into()), Value::Bool(true)),
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
    let _ = engine.check_and_touch_session(now_ms);

    if engine.is_provisioned() && !engine.is_unlocked() {
        return (
            CTAP2_ERR_PIN_REQUIRED,
            to_cbor_bytes(&cbor_err("SECURE_GUARD_LOCKED")),
        );
    }

    if let Ok(Value::Map(entries)) = ciborium::from_reader(payload) {
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
    }

    let out_map = vec![
        (Value::Text("status".into()), Value::Text("config_updated".into())),
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
    let _ = engine.check_and_touch_session(now_ms);

    let is_authorized = !engine.is_provisioned()
        || engine.is_unlocked()
        || engine.policy().test_mode_non_destructive_wipe;

    if !is_authorized {
        return (
            CTAP2_ERR_PIN_REQUIRED,
            to_cbor_bytes(&cbor_err("SECURE_GUARD_LOCKED")),
        );
    }

    // Valida confirmação explícita
    let mut confirmed = false;
    if let Ok(Value::Map(entries)) = ciborium::from_reader(payload) {
        if let Some(Value::Bool(b)) = get_field(&entries, "confirm") {
            confirmed = *b;
        }
        if let Some(Value::Text(s)) = get_field(&entries, "scope") {
            if s == "protected_resources" {
                confirmed = true;
            }
        }
    }

    if !confirmed && !engine.policy().test_mode_non_destructive_wipe {
        return (0x04, to_cbor_bytes(&cbor_err("CONFIRMATION_REQUIRED")));
    }

    let _ = engine.execute_wipe(now_ms);

    if !engine.last_wipe_simulated() {
        log::info!("[SECURE_GUARD] Wipe seletivo: limpando carteiras e chaves protegidas");
        *wallet = WalletStore::new();
        *key_mgr = KeyManager::new();
        let _ = crate::vendor_exec::save_states(storage, key_mgr, oath);
    } else {
        log::info!("[SECURE_GUARD] Wipe simulado em modo de teste (chaves físicas mantidas)");
    }

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
    use aegis_fido_core::secure_guard::SecureGuardPolicy;
    use crate::persistence::MockFlashBackend;

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
            assert_eq!(
                get_field(&entries, "max_attempts"),
                Some(&Value::from(5u8))
            );
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
        let mut rng = rand_core::OsRng;

        // 1. Provision via 0x3B CBOR
        let prov_map = vec![
            (Value::Text("action".into()), Value::Text("provision".into())),
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
        assert_eq!(engine.state(), SecureGuardState::Locked);
        assert!(engine.is_provisioned());

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
}
