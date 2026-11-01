//! Secure Guard typed DTOs, opcodes and serialization/deserialization helpers.
//!
//! Provides client models and CBOR wire helpers for opcodes 0x3A..0x3E:
//! - 0x3A: OP_SECURE_GUARD_STATUS
//! - 0x3B: OP_SECURE_GUARD_UNLOCK (provision, unlock, change_pin, recover)
//! - 0x3C: OP_SECURE_GUARD_LOCK
//! - 0x3D: OP_SECURE_GUARD_CONFIG
//! - 0x3E: OP_SECURE_GUARD_WIPE_SELECTIVE

use crate::error::SdkError;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use ciborium::value::Value;

/// Opcode 0x3A: consulta telemetria e estado da FSM
pub const OP_SECURE_GUARD_STATUS: u8 = 0x3A;
/// Opcode 0x3B: provisionamento, desbloqueio, troca de PIN e recuperação
pub const OP_SECURE_GUARD_UNLOCK: u8 = 0x3B;
/// Opcode 0x3C: bloqueio imediato de sessão ativa
pub const OP_SECURE_GUARD_LOCK: u8 = 0x3C;
/// Opcode 0x3D: atualização autenticada de políticas
pub const OP_SECURE_GUARD_CONFIG: u8 = 0x3D;
/// Opcode 0x3E: acionamento de wipe seletivo de recursos protegidos
pub const OP_SECURE_GUARD_WIPE_SELECTIVE: u8 = 0x3E;

/// Códigos wire dos 10 estados canônicos do Secure Guard
pub const STATE_UNPROVISIONED: u8 = 0x00;
pub const STATE_PROVISIONING: u8 = 0x01;
pub const STATE_LOCKED: u8 = 0x02;
pub const STATE_AUTHENTICATING: u8 = 0x03;
pub const STATE_UNLOCKED: u8 = 0x04;
pub const STATE_RECOVERY_REQUIRED: u8 = 0x05;
pub const STATE_RATE_LIMITED: u8 = 0x06;
pub const STATE_WIPE_PENDING: u8 = 0x07;
pub const STATE_WIPE_IN_PROGRESS: u8 = 0x08;
pub const STATE_ERROR_LOCKED: u8 = 0x09;

/// Retorna o nome textual legível correspondente ao código wire do estado
pub fn state_name_from_code(code: u8) -> &'static str {
    match code {
        STATE_UNPROVISIONED => "Unprovisioned",
        STATE_PROVISIONING => "Provisioning",
        STATE_LOCKED => "Locked",
        STATE_AUTHENTICATING => "Authenticating",
        STATE_UNLOCKED => "Unlocked",
        STATE_RECOVERY_REQUIRED => "RecoveryRequired",
        STATE_RATE_LIMITED => "RateLimited",
        STATE_WIPE_PENDING => "WipePending",
        STATE_WIPE_IN_PROGRESS => "WipeInProgress",
        STATE_ERROR_LOCKED => "ErrorLocked",
        _ => "Unknown",
    }
}

/// DTO de parâmetros de políticas ativas do Secure Guard
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecureGuardPolicyDto {
    pub wipe_on_5_failures: bool,
    pub session_duration_ms: u64,
    pub inactivity_timeout_ms: u64,
    pub protect_keys_and_aegn: bool,
    pub protect_oath: bool,
    pub test_mode_non_destructive_wipe: bool,
}

impl Default for SecureGuardPolicyDto {
    fn default() -> Self {
        Self {
            wipe_on_5_failures: false,
            session_duration_ms: 300_000,
            inactivity_timeout_ms: 120_000,
            protect_keys_and_aegn: true,
            protect_oath: false,
            test_mode_non_destructive_wipe: false,
        }
    }
}

/// DTO de estado, contadores de tentativas e telemetria do Secure Guard
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecureGuardStatusDto {
    pub state: u8,
    pub state_name: String,
    pub is_provisioned: bool,
    pub is_unlocked: bool,
    pub failed_attempts: u8,
    pub remaining_attempts: u8,
    pub max_attempts: u8,
    pub rate_limit_remaining_ms: u64,
    pub session_remaining_ms: u64,
    pub policy: SecureGuardPolicyDto,
    pub last_wipe_simulated: bool,
    pub audit_count: u64,
}

/// DTO de resultado da operação de provisionamento
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecureGuardProvisionResultDto {
    pub status: String,
    pub recovery_code: String,
    pub state: u8,
    pub unlocked: bool,
}

/// DTO de resultado da operação de desbloqueio
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecureGuardUnlockResultDto {
    pub success: bool,
    pub state: u8,
    pub state_name: String,
    pub failed_attempts: u8,
    pub remaining_attempts: u8,
    pub rate_limit_remaining_ms: u64,
    pub error: Option<String>,
}

/// DTO de resultado de alteração de PIN
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecureGuardChangePinResultDto {
    pub status: String,
    pub state: u8,
}

/// DTO de resultado de recuperação de emergência
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecureGuardRecoverResultDto {
    pub status: String,
    pub state: u8,
    pub new_recovery_code: Option<String>,
}

/// DTO de resultado de bloqueio imediato
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecureGuardLockResultDto {
    pub state: u8,
    pub locked: bool,
}

/// DTO de resultado de wipe seletivo
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecureGuardWipeResultDto {
    pub status: String,
    pub state: u8,
    pub simulated: bool,
}

// --- Helpers internos CBOR ---

fn to_cbor(val: &Value) -> Result<Vec<u8>, SdkError> {
    let mut out = Vec::new();
    ciborium::into_writer(val, &mut out).map_err(|_| SdkError::Unsupported)?;
    Ok(out)
}

fn from_cbor(bytes: &[u8]) -> Result<Value, SdkError> {
    ciborium::from_reader(bytes).map_err(|_| SdkError::Unsupported)
}

fn get_map_field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    for (k, v) in entries {
        if let Value::Text(s) = k {
            if s == key {
                return Some(v);
            }
        }
    }
    None
}

fn get_bool(entries: &[(Value, Value)], key: &str, default: bool) -> bool {
    get_map_field(entries, key)
        .and_then(|v| match v {
            Value::Bool(b) => Some(*b),
            _ => None,
        })
        .unwrap_or(default)
}

fn get_u64(entries: &[(Value, Value)], key: &str, default: u64) -> u64 {
    get_map_field(entries, key)
        .and_then(|v| match v {
            Value::Integer(i) => i128::from(*i).try_into().ok(),
            _ => None,
        })
        .unwrap_or(default)
}

fn get_u8(entries: &[(Value, Value)], key: &str, default: u8) -> u8 {
    get_u64(entries, key, default as u64) as u8
}

fn get_str(entries: &[(Value, Value)], key: &str) -> Option<String> {
    get_map_field(entries, key).and_then(|v| match v {
        Value::Text(s) => Some(s.clone()),
        Value::Bytes(b) => Some(alloc::string::String::from_utf8_lossy(b).into()),
        _ => None,
    })
}

// --- Funções de Serialização / Deserialização ---

/// Codifica a requisição de status (0x3A)
pub fn encode_secure_guard_status_request(include_audit: bool) -> Result<Vec<u8>, SdkError> {
    let map = vec![(
        Value::Text("include_audit".into()),
        Value::Bool(include_audit),
    )];
    to_cbor(&Value::Map(map))
}

/// Decodifica a resposta CBOR do status (0x3A)
pub fn decode_secure_guard_status_response(
    payload: &[u8],
) -> Result<SecureGuardStatusDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let state = get_u8(&entries, "state", STATE_UNPROVISIONED);
    let state_name = get_str(&entries, "state_name")
        .unwrap_or_else(|| String::from(state_name_from_code(state)));
    let is_provisioned = get_bool(&entries, "provisioned", false);
    let is_unlocked = get_bool(&entries, "unlocked", false);
    let failed_attempts = get_u8(&entries, "failed_attempts", 0);
    let remaining_attempts = get_u8(&entries, "remaining_attempts", 5);
    let max_attempts = get_u8(&entries, "max_attempts", 5);
    let rate_limit_remaining_ms = get_u64(&entries, "rate_limit_remaining_ms", 0);
    let session_remaining_ms = get_u64(&entries, "session_remaining_ms", 0);
    let last_wipe_simulated = get_bool(&entries, "last_wipe_simulated", false);
    let audit_count = get_u64(&entries, "audit_count", 0);

    let policy = SecureGuardPolicyDto {
        wipe_on_5_failures: get_bool(&entries, "wipe_on_5_failures", false),
        session_duration_ms: get_u64(&entries, "session_duration_ms", 300_000),
        inactivity_timeout_ms: get_u64(&entries, "inactivity_timeout_ms", 120_000),
        protect_keys_and_aegn: get_bool(&entries, "protect_keys_and_aegn", true),
        protect_oath: get_bool(&entries, "protect_oath", false),
        test_mode_non_destructive_wipe: get_bool(&entries, "test_mode_non_destructive_wipe", false),
    };

    Ok(SecureGuardStatusDto {
        state,
        state_name,
        is_provisioned,
        is_unlocked,
        failed_attempts,
        remaining_attempts,
        max_attempts,
        rate_limit_remaining_ms,
        session_remaining_ms,
        policy,
        last_wipe_simulated,
        audit_count,
    })
}

/// Codifica a requisição de provisionamento (0x3B action="provision")
pub fn encode_secure_guard_provision_request(
    pin: &[u8],
    recovery_code: Option<&[u8]>,
    policy: Option<&SecureGuardPolicyDto>,
) -> Result<Vec<u8>, SdkError> {
    let mut map = Vec::new();
    map.push((
        Value::Text("action".into()),
        Value::Text("provision".into()),
    ));
    map.push((Value::Text("pin".into()), Value::Bytes(pin.to_vec())));

    if let Some(rc) = recovery_code {
        if !rc.is_empty() {
            map.push((
                Value::Text("recovery_code".into()),
                Value::Bytes(rc.to_vec()),
            ));
        }
    }

    if let Some(p) = policy {
        map.push((
            Value::Text("wipe_on_5_failures".into()),
            Value::Bool(p.wipe_on_5_failures),
        ));
        map.push((
            Value::Text("protect_keys_and_aegn".into()),
            Value::Bool(p.protect_keys_and_aegn),
        ));
        map.push((
            Value::Text("protect_oath".into()),
            Value::Bool(p.protect_oath),
        ));
        map.push((
            Value::Text("test_mode_non_destructive_wipe".into()),
            Value::Bool(p.test_mode_non_destructive_wipe),
        ));
        map.push((
            Value::Text("session_duration_ms".into()),
            Value::from(p.session_duration_ms),
        ));
        map.push((
            Value::Text("inactivity_timeout_ms".into()),
            Value::from(p.inactivity_timeout_ms),
        ));
    }

    to_cbor(&Value::Map(map))
}

/// Decodifica a resposta de provisionamento (0x3B)
pub fn decode_secure_guard_provision_response(
    payload: &[u8],
) -> Result<SecureGuardProvisionResultDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let status = get_str(&entries, "status").unwrap_or_else(|| "provisioned".into());
    let recovery_code = get_str(&entries, "recovery_code").unwrap_or_default();
    let state = get_u8(&entries, "state", STATE_LOCKED);
    let unlocked = get_bool(&entries, "unlocked", false);

    Ok(SecureGuardProvisionResultDto {
        status,
        recovery_code,
        state,
        unlocked,
    })
}

/// Codifica a requisição de desbloqueio (0x3B action="unlock")
pub fn encode_secure_guard_unlock_request(pin: &[u8]) -> Result<Vec<u8>, SdkError> {
    let map = vec![
        (Value::Text("action".into()), Value::Text("unlock".into())),
        (Value::Text("pin".into()), Value::Bytes(pin.to_vec())),
    ];
    to_cbor(&Value::Map(map))
}

/// Decodifica a resposta de desbloqueio (0x3B)
pub fn decode_secure_guard_unlock_response(
    payload: &[u8],
) -> Result<SecureGuardUnlockResultDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let success = get_bool(&entries, "success", false);
    let state = get_u8(
        &entries,
        "state",
        if success {
            STATE_UNLOCKED
        } else {
            STATE_LOCKED
        },
    );
    let state_name = get_str(&entries, "state_name")
        .unwrap_or_else(|| String::from(state_name_from_code(state)));
    let failed_attempts = get_u8(&entries, "failed_attempts", 0);
    let remaining_attempts = get_u8(&entries, "remaining_attempts", 5);
    let rate_limit_remaining_ms = get_u64(&entries, "rate_limit_remaining_ms", 0);
    let error = get_str(&entries, "error");

    Ok(SecureGuardUnlockResultDto {
        success,
        state,
        state_name,
        failed_attempts,
        remaining_attempts,
        rate_limit_remaining_ms,
        error,
    })
}

/// Codifica a requisição de alteração de PIN (0x3B action="change_pin")
pub fn encode_secure_guard_change_pin_request(
    current_pin: &[u8],
    new_pin: &[u8],
) -> Result<Vec<u8>, SdkError> {
    let map = vec![
        (
            Value::Text("action".into()),
            Value::Text("change_pin".into()),
        ),
        (
            Value::Text("current_pin".into()),
            Value::Bytes(current_pin.to_vec()),
        ),
        (
            Value::Text("new_pin".into()),
            Value::Bytes(new_pin.to_vec()),
        ),
    ];
    to_cbor(&Value::Map(map))
}

/// Decodifica a resposta de alteração de PIN (0x3B)
pub fn decode_secure_guard_change_pin_response(
    payload: &[u8],
) -> Result<SecureGuardChangePinResultDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let status = get_str(&entries, "status").unwrap_or_else(|| "pin_changed".into());
    let state = get_u8(&entries, "state", STATE_LOCKED);

    Ok(SecureGuardChangePinResultDto { status, state })
}

/// Codifica a requisição de recuperação (0x3B action="recover")
pub fn encode_secure_guard_recover_request(
    recovery_code: &[u8],
    new_pin: &[u8],
) -> Result<Vec<u8>, SdkError> {
    let map = vec![
        (Value::Text("action".into()), Value::Text("recover".into())),
        (
            Value::Text("recovery_code".into()),
            Value::Bytes(recovery_code.to_vec()),
        ),
        (
            Value::Text("new_pin".into()),
            Value::Bytes(new_pin.to_vec()),
        ),
    ];
    to_cbor(&Value::Map(map))
}

/// Decodifica a resposta de recuperação (0x3B)
pub fn decode_secure_guard_recover_response(
    payload: &[u8],
) -> Result<SecureGuardRecoverResultDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let status = get_str(&entries, "status").unwrap_or_else(|| "recovered".into());
    let state = get_u8(&entries, "state", STATE_LOCKED);
    let new_recovery_code = get_str(&entries, "new_recovery_code");

    Ok(SecureGuardRecoverResultDto {
        status,
        state,
        new_recovery_code,
    })
}

/// Codifica a requisição de bloqueio de sessão (0x3C)
pub fn encode_secure_guard_lock_request() -> Result<Vec<u8>, SdkError> {
    let map: Vec<(Value, Value)> = Vec::new();
    to_cbor(&Value::Map(map))
}

/// Decodifica a resposta de bloqueio de sessão (0x3C)
pub fn decode_secure_guard_lock_response(
    payload: &[u8],
) -> Result<SecureGuardLockResultDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let state = get_u8(&entries, "state", STATE_LOCKED);
    let locked = get_bool(&entries, "locked", true);

    Ok(SecureGuardLockResultDto { state, locked })
}

/// Codifica a requisição de configuração de políticas (0x3D)
pub fn encode_secure_guard_config_request(
    policy: &SecureGuardPolicyDto,
) -> Result<Vec<u8>, SdkError> {
    let map = vec![
        (
            Value::Text("wipe_on_5_failures".into()),
            Value::Bool(policy.wipe_on_5_failures),
        ),
        (
            Value::Text("protect_keys_and_aegn".into()),
            Value::Bool(policy.protect_keys_and_aegn),
        ),
        (
            Value::Text("protect_oath".into()),
            Value::Bool(policy.protect_oath),
        ),
        (
            Value::Text("test_mode_non_destructive_wipe".into()),
            Value::Bool(policy.test_mode_non_destructive_wipe),
        ),
        (
            Value::Text("session_duration_ms".into()),
            Value::from(policy.session_duration_ms),
        ),
        (
            Value::Text("inactivity_timeout_ms".into()),
            Value::from(policy.inactivity_timeout_ms),
        ),
    ];
    to_cbor(&Value::Map(map))
}

/// Decodifica a resposta de configuração de políticas (0x3D)
pub fn decode_secure_guard_config_response(
    payload: &[u8],
) -> Result<SecureGuardPolicyDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    Ok(SecureGuardPolicyDto {
        wipe_on_5_failures: get_bool(&entries, "wipe_on_5_failures", false),
        session_duration_ms: get_u64(&entries, "session_duration_ms", 300_000),
        inactivity_timeout_ms: get_u64(&entries, "inactivity_timeout_ms", 120_000),
        protect_keys_and_aegn: get_bool(&entries, "protect_keys_and_aegn", true),
        protect_oath: get_bool(&entries, "protect_oath", false),
        test_mode_non_destructive_wipe: get_bool(&entries, "test_mode_non_destructive_wipe", false),
    })
}

/// Codifica a requisição de wipe seletivo (0x3E)
pub fn encode_secure_guard_wipe_request(
    scope: u8,
    confirm_token: &str,
) -> Result<Vec<u8>, SdkError> {
    let map = vec![
        (Value::Text("scope".into()), Value::from(scope)),
        (
            Value::Text("confirmation".into()),
            Value::Text(confirm_token.into()),
        ),
    ];
    to_cbor(&Value::Map(map))
}

/// Codifica a requisição de configuração de políticas com PIN opcional (0x3D)
pub fn encode_secure_guard_config_request_with_pin(
    policy: &SecureGuardPolicyDto,
    pin: Option<&[u8]>,
) -> Result<Vec<u8>, SdkError> {
    let mut map = vec![
        (
            Value::Text("wipe_on_5_failures".into()),
            Value::Bool(policy.wipe_on_5_failures),
        ),
        (
            Value::Text("protect_keys_and_aegn".into()),
            Value::Bool(policy.protect_keys_and_aegn),
        ),
        (
            Value::Text("protect_oath".into()),
            Value::Bool(policy.protect_oath),
        ),
        (
            Value::Text("test_mode_non_destructive_wipe".into()),
            Value::Bool(policy.test_mode_non_destructive_wipe),
        ),
        (
            Value::Text("session_duration_ms".into()),
            Value::from(policy.session_duration_ms),
        ),
        (
            Value::Text("inactivity_timeout_ms".into()),
            Value::from(policy.inactivity_timeout_ms),
        ),
    ];
    if let Some(p) = pin {
        map.push((Value::Text("pin".into()), Value::Bytes(p.to_vec())));
    }
    to_cbor(&Value::Map(map))
}

/// Codifica a requisição de wipe seletivo com PIN opcional (0x3E)
pub fn encode_secure_guard_wipe_request_with_pin(
    scope: u8,
    confirm_token: &str,
    pin: Option<&[u8]>,
) -> Result<Vec<u8>, SdkError> {
    let mut map = vec![
        (Value::Text("scope".into()), Value::from(scope)),
        (
            Value::Text("confirmation".into()),
            Value::Text(confirm_token.into()),
        ),
        (Value::Text("confirm".into()), Value::Bool(true)),
    ];
    if let Some(p) = pin {
        map.push((Value::Text("pin".into()), Value::Bytes(p.to_vec())));
    }
    to_cbor(&Value::Map(map))
}
/// Decodifica a resposta de wipe seletivo (0x3E)
pub fn decode_secure_guard_wipe_response(
    payload: &[u8],
) -> Result<SecureGuardWipeResultDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let status = get_str(&entries, "status").unwrap_or_else(|| "wiped".into());
    let state = get_u8(&entries, "state", STATE_UNPROVISIONED);
    let simulated = get_bool(&entries, "simulated", false);

    Ok(SecureGuardWipeResultDto {
        status,
        state,
        simulated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_defaults_and_serde() {
        let policy = SecureGuardPolicyDto::default();
        assert!(!policy.wipe_on_5_failures);
        assert_eq!(policy.session_duration_ms, 300_000);
        assert_eq!(policy.inactivity_timeout_ms, 120_000);
        assert!(policy.protect_keys_and_aegn);
        assert!(!policy.protect_oath);
        assert!(!policy.test_mode_non_destructive_wipe);
    }

    #[test]
    fn test_status_response_roundtrip() {
        let map = vec![
            (Value::Text("state".into()), Value::from(STATE_LOCKED)),
            (
                Value::Text("state_name".into()),
                Value::Text("Locked".into()),
            ),
            (Value::Text("provisioned".into()), Value::Bool(true)),
            (Value::Text("unlocked".into()), Value::Bool(false)),
            (Value::Text("failed_attempts".into()), Value::from(2u8)),
            (Value::Text("remaining_attempts".into()), Value::from(3u8)),
            (Value::Text("max_attempts".into()), Value::from(5u8)),
            (
                Value::Text("rate_limit_remaining_ms".into()),
                Value::from(2000u64),
            ),
            (
                Value::Text("session_remaining_ms".into()),
                Value::from(0u64),
            ),
            (Value::Text("wipe_on_5_failures".into()), Value::Bool(true)),
            (
                Value::Text("protect_keys_and_aegn".into()),
                Value::Bool(true),
            ),
            (Value::Text("protect_oath".into()), Value::Bool(false)),
            (
                Value::Text("test_mode_non_destructive_wipe".into()),
                Value::Bool(false),
            ),
            (
                Value::Text("last_wipe_simulated".into()),
                Value::Bool(false),
            ),
            (Value::Text("audit_count".into()), Value::from(14u64)),
        ];

        let cbor = to_cbor(&Value::Map(map)).expect("serialize");
        let decoded = decode_secure_guard_status_response(&cbor).expect("decode");

        assert_eq!(decoded.state, STATE_LOCKED);
        assert_eq!(decoded.state_name, "Locked");
        assert!(decoded.is_provisioned);
        assert!(!decoded.is_unlocked);
        assert_eq!(decoded.failed_attempts, 2);
        assert_eq!(decoded.remaining_attempts, 3);
        assert_eq!(decoded.max_attempts, 5);
        assert_eq!(decoded.rate_limit_remaining_ms, 2000);
        assert!(decoded.policy.wipe_on_5_failures);
        assert_eq!(decoded.audit_count, 14);
    }

    #[test]
    fn test_provision_request_and_response() {
        let policy = SecureGuardPolicyDto::default();
        let encoded =
            encode_secure_guard_provision_request(b"4927", Some(b"custom_rec_code"), Some(&policy))
                .expect("encode provision");
        assert!(!encoded.is_empty());

        let resp_map = vec![
            (
                Value::Text("status".into()),
                Value::Text("provisioned".into()),
            ),
            (
                Value::Text("recovery_code".into()),
                Value::Text("a1b2c3d4e5f60718".into()),
            ),
            (Value::Text("state".into()), Value::from(STATE_LOCKED)),
            (Value::Text("unlocked".into()), Value::Bool(false)),
        ];

        let resp_cbor = to_cbor(&Value::Map(resp_map)).expect("serialize");
        let prov = decode_secure_guard_provision_response(&resp_cbor).expect("decode");

        assert_eq!(prov.status, "provisioned");
        assert_eq!(prov.recovery_code, "a1b2c3d4e5f60718");
        assert_eq!(prov.state, STATE_LOCKED);
        assert!(!prov.unlocked);
    }

    #[test]
    fn test_unlock_request_and_response() {
        let encoded = encode_secure_guard_unlock_request(b"4927").expect("encode unlock");
        assert!(!encoded.is_empty());

        // Sucesso
        let ok_map = vec![
            (Value::Text("success".into()), Value::Bool(true)),
            (Value::Text("state".into()), Value::from(STATE_UNLOCKED)),
            (
                Value::Text("state_name".into()),
                Value::Text("Unlocked".into()),
            ),
            (Value::Text("failed_attempts".into()), Value::from(0u8)),
            (Value::Text("remaining_attempts".into()), Value::from(5u8)),
        ];

        let ok_cbor = to_cbor(&Value::Map(ok_map)).expect("serialize");
        let unl = decode_secure_guard_unlock_response(&ok_cbor).expect("decode");
        assert!(unl.success);
        assert_eq!(unl.state, STATE_UNLOCKED);
        assert_eq!(unl.remaining_attempts, 5);

        // Falha
        let fail_map = vec![
            (Value::Text("success".into()), Value::Bool(false)),
            (Value::Text("state".into()), Value::from(STATE_RATE_LIMITED)),
            (
                Value::Text("state_name".into()),
                Value::Text("RateLimited".into()),
            ),
            (Value::Text("failed_attempts".into()), Value::from(3u8)),
            (Value::Text("remaining_attempts".into()), Value::from(2u8)),
            (
                Value::Text("rate_limit_remaining_ms".into()),
                Value::from(5000u64),
            ),
            (
                Value::Text("error".into()),
                Value::Text("RateLimited".into()),
            ),
        ];

        let fail_cbor = to_cbor(&Value::Map(fail_map)).expect("serialize");
        let fail_unl = decode_secure_guard_unlock_response(&fail_cbor).expect("decode");
        assert!(!fail_unl.success);
        assert_eq!(fail_unl.state, STATE_RATE_LIMITED);
        assert_eq!(fail_unl.failed_attempts, 3);
        assert_eq!(fail_unl.rate_limit_remaining_ms, 5000);
        assert_eq!(fail_unl.error.as_deref(), Some("RateLimited"));
    }

    #[test]
    fn test_change_pin_recover_lock_config_wipe() {
        let ch_enc = encode_secure_guard_change_pin_request(b"4927", b"9182").expect("change pin");
        assert!(!ch_enc.is_empty());

        let rec_enc = encode_secure_guard_recover_request(b"hex_code", b"9182").expect("recover");
        assert!(!rec_enc.is_empty());

        let lock_enc = encode_secure_guard_lock_request().expect("lock");
        assert!(!lock_enc.is_empty());

        let cfg_enc =
            encode_secure_guard_config_request(&SecureGuardPolicyDto::default()).expect("config");
        assert!(!cfg_enc.is_empty());

        let wipe_enc = encode_secure_guard_wipe_request(1, "CONFIRM_WIPE").expect("wipe");
        assert!(!wipe_enc.is_empty());
        let cfg_pin = encode_secure_guard_config_request_with_pin(&SecureGuardPolicyDto::default(), Some(b"4927")).expect("config with pin");
        assert!(!cfg_pin.is_empty());

        let wipe_pin = encode_secure_guard_wipe_request_with_pin(1, "CONFIRM_WIPE", Some(b"4927")).expect("wipe with pin");
        assert!(!wipe_pin.is_empty());
    }
}
