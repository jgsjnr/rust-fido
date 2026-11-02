use super::{
    cbor_err, extract_bytes, get_field, to_cbor_bytes, CTAP2_ERR_PIN_AUTH_INVALID,
    CTAP2_ERR_PIN_REQUIRED,
};
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::secure_guard::SecureGuardEngine;
use aegis_fido_core::wallet::WalletStore;
use ciborium::value::Value;
use std::format;
use std::vec::Vec;
use crate::persistence::{FlashStorageBackend, SecureStorage};
use crate::secure_guard_storage::save_secure_guard_record;
/// 0x3E: OP_SECURE_GUARD_WIPE_SELECTIVE
pub(crate) fn handle_wipe_selective<B: FlashStorageBackend>(
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