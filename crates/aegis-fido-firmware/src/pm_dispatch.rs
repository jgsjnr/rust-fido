//! PM dispatch `0x43..=0x47` (F-PM2 firmware side).
//!
//! - SRP: this module owns the wire dispatch only (CBOR decode -> vault call
//!   -> CBOR encode). Record shapes/policy live in `aegis-pm-vault`, gates
//!   in `pm_store::authorize_pm_op`, persistence in `pm_store` (NVS opaque
//!   blob). The phone is a blind transport.
//! - Gates (binding -> UP -> PIN -> 60 s window) come from
//!   [`crate::pm_store::authorize_pm_op`]; denials reuse the frozen BLE
//!   vocabulary (`NeedBinding` `0x05` / `PresenceRequired` `0x01` /
//!   `PinRequired` `0x02`). Vault errors map fail-closed: `NotFound` ->
//!   `0x03` (NO_SLOT), anything else -> `0x04` (generic).
//! - CBOR mirrors `universal-device-sdk/src/pm.rs` DTOs byte-for-byte:
//!   put `{label, username, secret, url}`, id bodies `{id}`, list
//!   `{cursor, limit}` / `{ids, next_cursor, has_more}`, release
//!   `{id, username, secret}`, status `{entry_count, max_entries}`.
//!   Field caps mirror the SDK transport mirrors (label 128 / username 256
//!   / secret 1..=512 / url 512 / id 1..=64); policy quotas stay vault-side.
//! - `no_std`-compatible (`alloc`-only). No logging of user data, no
//!   `unwrap`/`expect` outside `#[cfg(test)]`, no eFuse/Secure Boot/OTP
//!   call sites (REGRA PRINCIPAL N1).
//!
//! Diet: this module only exists outside the capability presets
//! (`cap-fido-only` / `cap-fido-totp`); inside the diet every PM op answers
//! `UNSUPPORTED_FEATURE` (`0x06`) at the funnels, never routed here.

extern crate alloc;

use aegis_pm_vault::{PasswordEntry, PmError, PmPolicy, PmVault};
use alloc::string::String;
use alloc::vec::Vec;
use ciborium::value::Value;

use crate::persistence::{FlashStorageBackend, SecureStorage};
use crate::ble_gatt::PmBackoffGate;
use crate::pm_store::{
    authorize_pm_op, pm_blob_load_opt, pm_blob_save, PmAuditEvent, PmGateState,
    OP_PM_DELETE, OP_PM_GET, OP_PM_LIST, OP_PM_PUT, OP_PM_STATUS,
};

/// Device PM vault master key (RAM session key material; the sealed NVS blob
/// is AEAD under this key via `PmVault::seal_to_blob`). Placeholder constant
/// until a TRNG-provisioned device key lands; no eFuse/Secure Boot surface.
pub const PM_VAULT_MASTER_KEY: [u8; 32] = [0x5Au8; 32];
/// Fixed domain separation token for the PM envelope seal (no user secret;
/// the same token seals and opens on every transport).
pub const PM_SEAL_PIN_TOKEN: &[u8] = b"aegis-pm-v1";

/// Wire status for a vault-level failure (gates already passed).
fn pm_error_to_wire(e: PmError) -> u8 {
    match e {
        PmError::NeedBinding => 0x05,
        PmError::PresenceRequired | PmError::BindingWindowExpired => 0x01,
        PmError::PinRequired => 0x02,
        PmError::NotFound => 0x03,
        _ => 0x04,
    }
}

/// Converts the firmware gate snapshot to the vault gate snapshot
/// (same fields, vault-owned type; the vault decides enforcement).
fn to_vault_gate(gate: &PmGateState) -> aegis_pm_vault::PmGateState {
    aegis_pm_vault::PmGateState {
        binding_bound: gate.binding_bound,
        presence_confirmed: gate.presence_confirmed,
        pin_authenticated: gate.pin_authenticated,
        bound_within_ms: gate.bound_within_ms,
    }
}

fn to_cbor(val: &Value) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(val, &mut out).ok()?;
    Some(out)
}

fn from_cbor(bytes: &[u8]) -> Option<Vec<(Value, Value)>> {
    let val: Value = ciborium::from_reader(bytes).ok()?;
    match val {
        Value::Map(m) => Some(m),
        _ => None,
    }
}

fn field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries.iter().find_map(|(k, v)| match k {
        Value::Text(s) if s == key => Some(v),
        _ => None,
    })
}

fn get_text(entries: &[(Value, Value)], key: &str) -> Option<String> {
    match field(entries, key)? {
        Value::Text(s) => Some(s.clone()),
        _ => None,
    }
}

fn get_bytes(entries: &[(Value, Value)], key: &str) -> Option<Vec<u8>> {
    match field(entries, key)? {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

fn get_u32(entries: &[(Value, Value)], key: &str, default: u32) -> Option<u32> {
    match field(entries, key) {
        None => Some(default),
        Some(Value::Integer(i)) => u32::try_from(i128::from(*i)).ok(),
        Some(_) => None,
    }
}

fn check_id(id: &[u8]) -> bool {
    !id.is_empty() && id.len() <= 64
}

fn encode_id_body(id: &[u8]) -> Option<Vec<u8>> {
    if !check_id(id) {
        return None;
    }
    to_cbor(&Value::Map(alloc::vec![(
        Value::Text("id".into()),
        Value::Bytes(id.to_vec()),
    )]))
}

fn decode_id_body(bytes: &[u8]) -> Option<Vec<u8>> {
    let entries = from_cbor(bytes)?;
    let id = get_bytes(&entries, "id")?;
    if !check_id(&id) {
        return None;
    }
    Some(id)
}

/// Loads the sealed PM blob (if any) from NVS into `vault`.
///
/// Absent blob = fresh vault (`Ok(0)`). Corrupt/tampered blob = fail-closed
/// fresh vault (`Ok(0)`; the next mutating op overwrites the torn slot).
/// Never logs secrets, no panics.
pub fn pm_vault_load<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    vault: &mut PmVault,
    policy: &PmPolicy,
    gate: &PmGateState,
) -> usize {
    let Some(blob) = pm_blob_load_opt(storage) else {
        return 0;
    };
    let vgate = to_vault_gate(gate);
    match vault.load_from_blob(policy, &vgate, &blob, PM_SEAL_PIN_TOKEN) {
        Ok(n) => n,
        Err(_) => {
            *vault = PmVault::new(PM_VAULT_MASTER_KEY);
            0
        }
    }
}

/// Seals `vault` and persists the opaque blob to NVS (single-blob
/// `vault-pm/blob` semantics, mirroring `key_slots_v1` via `NamespacedStore`).
/// Seal/verify failure = `false` (caller keeps the RAM copy, fail-closed).
pub fn pm_vault_save<B: FlashStorageBackend, R: rand_core::CryptoRng>(
    storage: &mut SecureStorage<B>,
    vault: &PmVault,
    policy: &PmPolicy,
    gate: &PmGateState,
    rng: &mut R,
) -> bool {
    let vgate = to_vault_gate(gate);
    let blob = match vault.seal_to_blob(policy, &vgate, PM_SEAL_PIN_TOKEN, rng) {
        Ok(b) => b,
        Err(_) => return false,
    };
    pm_blob_save(storage, &blob).is_ok()
}

/// Dispatches one PM op with NVS persistence (all transports).
///
/// Loads the sealed blob before dispatch; on success (`0x00`) of a mutating
/// op (`PUT`/`DELETE`) seals and saves afterwards. Read ops (`GET`/`LIST/
/// `STATUS`) never write. Gate/vault failures map exactly like
/// [`dispatch_pm_op`].
#[allow(clippy::too_many_arguments)]
pub fn dispatch_pm_op_persist<B: FlashStorageBackend, R: rand_core::CryptoRng>(
    op: u8,
    body: &[u8],
    gate: &PmGateState,
    storage: &mut SecureStorage<B>,
    policy: &PmPolicy,
    now_secs: u64,
    rng: &mut R,
    limiter: &mut impl PmBackoffGate,
    now_ms: u64,
) -> (u8, Vec<u8>) {
    let mut vault = PmVault::new(PM_VAULT_MASTER_KEY);
    let _ = pm_vault_load(storage, &mut vault, policy, gate);
    let (st, out) = dispatch_pm_op(op, body, gate, &mut vault, policy, now_secs, rng, limiter, now_ms);
    if st == 0x00
        && (op == OP_PM_PUT || op == OP_PM_DELETE)
        && !pm_vault_save(storage, &vault, policy, gate, rng)
    {
        return (0x04, Vec::new());
    }
    (st, out)
}

/// Dispatches one PM op over a RAM vault.
///
/// Single choke point for every transport: backoff is checked first
/// (fail-closed `0x04` while armed), then the canonical gate, then the
/// vault. Exactly one secret-free [`PmAuditEvent`] line is emitted per
/// call; the budget records only authenticated outcomes (`0x00` resets,
/// `0x03`/`0x04` spend).
#[allow(clippy::too_many_arguments)]
pub fn dispatch_pm_op<R: rand_core::CryptoRng>(
    op: u8,
    body: &[u8],
    gate: &PmGateState,
    vault: &mut PmVault,
    policy: &PmPolicy,
    now_secs: u64,
    rng: &mut R,
    limiter: &mut impl PmBackoffGate,
    now_ms: u64,
) -> (u8, Vec<u8>) {
    if limiter.poll(now_ms).is_err() {
        let st = 0x04u8;
        log::info!("{}", PmAuditEvent { op, status: st });
        return (st, Vec::new());
    }
    let (st, out) = dispatch_pm_op_inner(op, body, gate, vault, policy, now_secs, rng);
    limiter.record(st, now_ms);
    log::info!("{}", PmAuditEvent { op, status: st });
    (st, out)
}

/// Gate + vault execution without backoff/audit (wrapped by
/// [`dispatch_pm_op`]; never called directly by transports).
#[allow(clippy::too_many_arguments)]
fn dispatch_pm_op_inner<R: rand_core::CryptoRng>(
    op: u8,
    body: &[u8],
    gate: &PmGateState,
    vault: &mut PmVault,
    policy: &PmPolicy,
    now_secs: u64,
    rng: &mut R,
) -> (u8, Vec<u8>) {
    if let Err(e) = authorize_pm_op(op, gate) {
        return (e.to_vendor_status(), Vec::new());
    }
    let vgate = to_vault_gate(gate);
    match op {
        OP_PM_PUT => {
            let entries = match from_cbor(body) {
                Some(e) => e,
                None => return (0x04, Vec::new()),
            };
            let (Some(label), Some(username), Some(secret)) = (
                get_text(&entries, "label"),
                get_text(&entries, "username"),
                get_bytes(&entries, "secret"),
            ) else {
                return (0x04, Vec::new());
            };
            let url = match field(&entries, "url") {
                None | Some(Value::Null) => None,
                Some(Value::Text(s)) => Some(s.clone()),
                Some(_) => return (0x04, Vec::new()),
            };
            if label.len() > 128
                || username.len() > 256
                || secret.is_empty()
                || secret.len() > 512
                || url.as_ref().is_some_and(|u| u.len() > 512)
            {
                return (0x04, Vec::new());
            }
            let mut id = [0u8; 16];
            rng.fill_bytes(&mut id);
            let entry =
                match PasswordEntry::new(id.to_vec(), label, username, secret, url, now_secs) {
                    Ok(e) => e,
                    Err(e) => return (pm_error_to_wire(e), Vec::new()),
                };
            match vault.put_password(policy, &vgate, entry) {
                Ok(()) => match encode_id_body(&id) {
                    Some(b) => (0x00, b),
                    None => (0x04, Vec::new()),
                },
                Err(e) => (pm_error_to_wire(e), Vec::new()),
            }
        }
        OP_PM_GET => {
            let id = match decode_id_body(body) {
                Some(id) => id,
                None => return (0x04, Vec::new()),
            };
            let rec = match vault.get(policy, &vgate, &id) {
                Ok(r) => r,
                Err(e) => return (pm_error_to_wire(e), Vec::new()),
            };
            let entry = match rec.as_password() {
                Some(e) => e,
                None => return (0x04, Vec::new()),
            };
            let map = alloc::vec![
                (Value::Text("id".into()), Value::Bytes(entry.id.clone())),
                (
                    Value::Text("username".into()),
                    Value::Text(entry.username.clone())
                ),
                (
                    Value::Text("secret".into()),
                    Value::Bytes(entry.secret.clone())
                ),
            ];
            match to_cbor(&Value::Map(map)) {
                Some(b) => (0x00, b),
                None => (0x04, Vec::new()),
            }
        }
        OP_PM_LIST => {
            let entries = match from_cbor(body) {
                Some(e) => e,
                None => return (0x04, Vec::new()),
            };
            let cursor = match get_u32(&entries, "cursor", 0) {
                Some(c) => c,
                None => return (0x04, Vec::new()),
            };
            let limit = match get_u32(&entries, "limit", 32) {
                Some(0) => 32u32,
                Some(l) => l,
                None => return (0x04, Vec::new()),
            };
            let ids = match vault.list_ids(policy, &vgate) {
                Ok(ids) => ids,
                Err(e) => return (pm_error_to_wire(e), Vec::new()),
            };
            let start = (cursor as usize).min(ids.len());
            let take = (limit as usize).min(ids.len().saturating_sub(start));
            let page: Vec<Value> = ids[start..start + take]
                .iter()
                .map(|id| Value::Bytes(id.clone()))
                .collect();
            let next_cursor = (start + take) as u32;
            let has_more = start + take < ids.len();
            let map = alloc::vec![
                (Value::Text("ids".into()), Value::Array(page)),
                (
                    Value::Text("next_cursor".into()),
                    Value::from(next_cursor as u64)
                ),
                (Value::Text("has_more".into()), Value::Bool(has_more)),
            ];
            match to_cbor(&Value::Map(map)) {
                Some(b) => (0x00, b),
                None => (0x04, Vec::new()),
            }
        }
        OP_PM_DELETE => {
            let id = match decode_id_body(body) {
                Some(id) => id,
                None => return (0x04, Vec::new()),
            };
            match vault.delete(policy, &vgate, &id) {
                Ok(()) => (0x00, Vec::new()),
                Err(e) => (pm_error_to_wire(e), Vec::new()),
            }
        }
        OP_PM_STATUS => {
            let map = alloc::vec![
                (
                    Value::Text("entry_count".into()),
                    Value::from(vault.len() as u64)
                ),
                (
                    Value::Text("max_entries".into()),
                    Value::from(policy.max_entries as u64)
                ),
            ];
            match to_cbor(&Value::Map(map)) {
                Some(b) => (0x00, b),
                None => (0x04, Vec::new()),
            }
        }
        _ => (
            crate::ble_gatt::BleGattError::InvalidOpcode.to_vendor_status(),
            Vec::new(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ble_gatt::BleGattError;
    use crate::pm_store::{
        PM_BACKOFF_MS, PM_BINDING_WINDOW_MS, PM_MAX_CONSEC_FAIL, PM_UP_WINDOW_MS, PmRateLimiter,
    };

    fn test_vault() -> (PmVault, PmPolicy) {
        (PmVault::new([0x5Au8; 32]), PmPolicy::default())
    }

    fn put_body(label: &str, user: &str, secret: &[u8]) -> Vec<u8> {
        let map = alloc::vec![
            (
                Value::Text("label".into()),
                Value::Text(String::from(label))
            ),
            (
                Value::Text("username".into()),
                Value::Text(String::from(user))
            ),
            (Value::Text("secret".into()), Value::Bytes(secret.to_vec())),
            (Value::Text("url".into()), Value::Null),
        ];
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
        out
    }

    fn gate() -> PmGateState {
        PmGateState::authorized()
    }

    const NOW_MS: u64 = 1_770_000_000_000;

    fn put_one(vault: &mut PmVault, policy: &PmPolicy) -> Vec<u8> {
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let (st, body) = dispatch_pm_op(
            OP_PM_PUT,
            &put_body("bank", "alice", b"s3cr3t"),
            &gate(),
            vault,
            policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x00);
        decode_id_body(&body).expect("put answers opaque id")
    }

    #[test]
    fn gates_deny_every_op_in_canonical_order() {
        let (mut vault, policy) = test_vault();
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let bodies: [(u8, Vec<u8>); 5] = [
            (OP_PM_PUT, put_body("bank", "alice", b"s3cr3t")),
            (OP_PM_GET, encode_id_body(&[0x01; 16]).expect("id body")),
            (OP_PM_LIST, {
                let map = alloc::vec![
                    (Value::Text("cursor".into()), Value::from(0u64)),
                    (Value::Text("limit".into()), Value::from(32u64)),
                ];
                let mut out = Vec::new();
                ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
                out
            }),
            (OP_PM_DELETE, encode_id_body(&[0x01; 16]).expect("id body")),
            (OP_PM_STATUS, Vec::new()),
        ];
        // STATUS with empty body is a malformed frame (0x04), still gated first.
        let denied = [
            (
                PmGateState {
                    binding_bound: false,
                    ..gate()
                },
                BleGattError::NeedBinding.to_vendor_status(),
            ),
            (
                PmGateState {
                    presence_confirmed: false,
                    ..gate()
                },
                BleGattError::PresenceRequired.to_vendor_status(),
            ),
            (
                PmGateState {
                    pin_authenticated: false,
                    ..gate()
                },
                BleGattError::PinRequired.to_vendor_status(),
            ),
            (
                PmGateState {
                    bound_within_ms: PM_BINDING_WINDOW_MS + 1,
                    ..gate()
                },
                BleGattError::PresenceRequired.to_vendor_status(),
            ),
        ];
        for (op, body) in &bodies {
            for (g, want) in denied {
                let (st, _) =
                    dispatch_pm_op(*op, body, &g, &mut vault, &policy, 1_770_000_000, &mut rng, &mut PmRateLimiter::new(), NOW_MS);
                assert_eq!(st, want, "op 0x{op:02X}");
            }
        }
        // Outside the family: InvalidOpcode, never routed to the vault.
        let (st, _) = dispatch_pm_op(
            0x22,
            &[],
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(
            st,
            BleGattError::InvalidOpcode.to_vendor_status(),
            "non-PM op"
        );
    }

    #[test]
    fn put_get_delete_roundtrip() {
        let (mut vault, policy) = test_vault();
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let id = put_one(&mut vault, &policy);
        // GET returns the punctual release (username + secret, no label).
        let (st, body) = dispatch_pm_op(
            OP_PM_GET,
            &encode_id_body(&id).unwrap(),
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x00);
        let entries = from_cbor(&body).expect("release cbor");
        assert_eq!(get_text(&entries, "username").unwrap(), "alice");
        assert_eq!(get_bytes(&entries, "secret").unwrap(), b"s3cr3t");
        // GET unknown id -> NO_SLOT (0x03).
        let (st, _) = dispatch_pm_op(
            OP_PM_GET,
            &encode_id_body(&[0xFF; 16]).unwrap(),
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x03);
        // DELETE then GET -> NO_SLOT.
        let (st, _) = dispatch_pm_op(
            OP_PM_DELETE,
            &encode_id_body(&id).unwrap(),
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x00);
        let (st, _) = dispatch_pm_op(
            OP_PM_GET,
            &encode_id_body(&id).unwrap(),
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x03);
        // DELETE unknown -> NO_SLOT (0x03), never 0x00.
        let (st, _) = dispatch_pm_op(
            OP_PM_DELETE,
            &encode_id_body(&[0xFF; 16]).unwrap(),
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x03);
    }

    #[test]
    fn list_pages_over_opaque_ids_and_status_census() {
        let (mut vault, policy) = test_vault();
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let id0 = put_one(&mut vault, &policy);
        let _id1 = put_one(&mut vault, &policy);
        let list_req = |cursor: u32, limit: u32| {
            let map = alloc::vec![
                (Value::Text("cursor".into()), Value::from(cursor as u64)),
                (Value::Text("limit".into()), Value::from(limit as u64)),
            ];
            let mut out = Vec::new();
            ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
            out
        };
        // Page 1 of 2.
        let (st, body) = dispatch_pm_op(
            OP_PM_LIST,
            &list_req(0, 1),
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x00);
        let entries = from_cbor(&body).expect("list cbor");
        let ids = match field(&entries, "ids").unwrap() {
            Value::Array(a) => a.clone(),
            _ => panic!("ids array"),
        };
        assert_eq!(ids.len(), 1);
        let has_more = match field(&entries, "has_more") {
            Some(Value::Bool(b)) => *b,
            _ => panic!("has_more bool"),
        };
        assert!(has_more);
        let next = get_u32(&entries, "next_cursor", 0).unwrap();
        assert_eq!(next, 1);
        // Page 2 carries the remaining id (opaque: no labels cross the edge).
        let (st, body2) = dispatch_pm_op(
            OP_PM_LIST,
            &list_req(next, 1),
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x00);
        let entries2 = from_cbor(&body2).expect("list cbor");
        let has_more2 = match field(&entries2, "has_more") {
            Some(Value::Bool(b)) => *b,
            _ => panic!("has_more bool"),
        };
        assert!(!has_more2);
        // First id matches the created record (opaque, device-chosen).
        match &ids[0] {
            Value::Bytes(b) => assert_eq!(b, &id0),
            _ => panic!("id bytes"),
        }
        // STATUS census, no secrets.
        let (st, body) = dispatch_pm_op(
            OP_PM_STATUS,
            &{
                let mut out = Vec::new();
                ciborium::into_writer(&Value::Map(Vec::new()), &mut out).unwrap();
                out
            },
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x00);
        let entries = from_cbor(&body).expect("status cbor");
        assert_eq!(get_u32(&entries, "entry_count", 99), Some(2));
        assert_eq!(
            get_u32(&entries, "max_entries", 0),
            Some(policy.max_entries as u32)
        );
    }

    #[test]
    fn malformed_frames_fail_closed_without_secrets() {
        let (mut vault, policy) = test_vault();
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        // Empty secret rejected (transport cap, fail-closed 0x04).
        let (st, _) = dispatch_pm_op(
            OP_PM_PUT,
            &put_body("bank", "alice", b""),
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x04);
        // Non-CBOR body rejected.
        let (st, _) = dispatch_pm_op(
            OP_PM_GET,
            b"not-cbor",
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x04);
        // Empty id rejected.
        let map = alloc::vec![(Value::Text("id".into()), Value::Bytes(Vec::new()))];
        let mut bad = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bad).unwrap();
        let (st, _) = dispatch_pm_op(
            OP_PM_DELETE,
            &bad,
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x04);
        // Debug of errors carries no blob bytes.
        let dbg = alloc::format!("{:?}", PmError::Sealed);
        assert!(!dbg.contains("s3cr3t"));
    }

    fn list_req(cursor: u32, limit: u32) -> Vec<u8> {
        let map = alloc::vec![
            (Value::Text("cursor".into()), Value::from(cursor as u64)),
            (Value::Text("limit".into()), Value::from(limit as u64)),
        ];
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
        out
    }

    #[test]
    fn persist_put_list_get_delete_survives_reboot() {
        use crate::persistence::{MockFlashBackend, SecureStorage};
        let mut storage = SecureStorage::new(MockFlashBackend::new(), &[0x11u8; 32], &[0x22u8; 32]);
        let policy = PmPolicy::default();
        let gate = gate();
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        // PUT persists.
        let (st, body) = dispatch_pm_op_persist(
            OP_PM_PUT,
            &put_body("bank", "alice", b"s3cr3t"),
            &gate,
            &mut storage,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x00);
        let id = decode_id_body(&body).expect("opaque id");
        // LIST sees it on a fresh call (blob reloaded from NVS).
        let (st, body) = dispatch_pm_op_persist(
            OP_PM_LIST,
            &list_req(0, 32),
            &gate,
            &mut storage,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x00);
        let entries = from_cbor(&body).expect("list cbor");
        let ids = match field(&entries, "ids").unwrap() {
            Value::Array(a) => a.clone(),
            _ => panic!("ids array"),
        };
        assert_eq!(ids.len(), 1);
        // GET returns the record.
        let (st, _) = dispatch_pm_op_persist(
            OP_PM_GET,
            &encode_id_body(&id).unwrap(),
            &gate,
            &mut storage,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x00);
        // Simulated reboot: new engine over the persisted backend image.
        let backend_clone = storage.backend().clone();
        let mut rebooted = SecureStorage::new(backend_clone, &[0x11u8; 32], &[0x22u8; 32]);
        let (st, body) = dispatch_pm_op_persist(
            OP_PM_LIST,
            &list_req(0, 32),
            &gate,
            &mut rebooted,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x00);
        let entries = from_cbor(&body).expect("reboot list cbor");
        let ids = match field(&entries, "ids").unwrap() {
            Value::Array(a) => a.clone(),
            _ => panic!("ids array"),
        };
        assert_eq!(ids.len(), 1);
        // DELETE persists; post-reboot LIST is empty.
        let (st, _) = dispatch_pm_op_persist(
            OP_PM_DELETE,
            &encode_id_body(&id).unwrap(),
            &gate,
            &mut rebooted,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x00);
        let backend_clone = rebooted.backend().clone();
        let mut rebooted2 = SecureStorage::new(backend_clone, &[0x11u8; 32], &[0x22u8; 32]);
        let (st, body) = dispatch_pm_op_persist(
            OP_PM_LIST,
            &list_req(0, 32),
            &gate,
            &mut rebooted2,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut PmRateLimiter::new(),
            NOW_MS,
        );
        assert_eq!(st, 0x00);
        let entries = from_cbor(&body).expect("empty list cbor");
        let ids = match field(&entries, "ids").unwrap() {
            Value::Array(a) => a.clone(),
            _ => panic!("ids array"),
        };
        assert!(ids.is_empty());
    }

    #[test]
    fn backoff_denies_authenticated_ops_until_lapse() {
        let (mut vault, policy) = test_vault();
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let mut lim = PmRateLimiter::new();
        let unknown = encode_id_body(&[0xFF; 16]).expect("id body");
        // Five authenticated misses (0x03) spend the budget; the sixth op
        // is denied 0x04 even fully authorized (fail-closed backoff).
        for _ in 0..PM_MAX_CONSEC_FAIL {
            let (st, _) = dispatch_pm_op(
                OP_PM_GET,
                &unknown,
                &gate(),
                &mut vault,
                &policy,
                1_770_000_000,
                &mut rng,
                &mut lim,
                NOW_MS,
            );
            assert_eq!(st, 0x03);
        }
        let (st, _) = dispatch_pm_op(
            OP_PM_GET,
            &unknown,
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut lim,
            NOW_MS,
        );
        assert_eq!(st, 0x04);
        // Backoff is per-limiter, not per-op: PUT also denied.
        let (st, _) = dispatch_pm_op(
            OP_PM_PUT,
            &put_body("bank", "alice", b"s3cr3t"),
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut lim,
            NOW_MS,
        );
        assert_eq!(st, 0x04);
        // After the window lapses the same op is evaluated normally again.
        let (st, _) = dispatch_pm_op(
            OP_PM_GET,
            &unknown,
            &gate(),
            &mut vault,
            &policy,
            1_770_000_000,
            &mut rng,
            &mut lim,
            NOW_MS + PM_BACKOFF_MS,
        );
        assert_eq!(st, 0x03);
    }

    #[test]
    fn stale_up_and_missing_pin_deny_at_dispatch() {
        let (mut vault, policy) = test_vault();
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let unknown = encode_id_body(&[0xFF; 16]).expect("id body");
        // Stale UP age denies even with the latch bit set.
        let stale_up = PmGateState {
            up_within_ms: PM_UP_WINDOW_MS + 1,
            ..gate()
        };
        for op in [OP_PM_PUT, OP_PM_GET, OP_PM_LIST, OP_PM_DELETE, OP_PM_STATUS] {
            let body = if op == OP_PM_PUT {
                put_body("bank", "alice", b"s3cr3t")
            } else if op == OP_PM_LIST || op == OP_PM_STATUS {
                list_req(0, 32)
            } else {
                unknown.clone()
            };
            let (st, _) = dispatch_pm_op(
                op,
                &body,
                &stale_up,
                &mut vault,
                &policy,
                1_770_000_000,
                &mut rng,
                &mut PmRateLimiter::new(),
                NOW_MS,
            );
            assert_eq!(st, 0x01, "stale UP must deny op 0x{op:02X}");
        }
        // Secret-touching ops require PIN strictly: binding + fresh UP
        // without PIN denies 0x02 on GET and DELETE.
        let no_pin = PmGateState {
            pin_authenticated: false,
            ..gate()
        };
        for op in [OP_PM_GET, OP_PM_DELETE] {
            let (st, _) = dispatch_pm_op(
                op,
                &unknown,
                &no_pin,
                &mut vault,
                &policy,
                1_770_000_000,
                &mut rng,
                &mut PmRateLimiter::new(),
                NOW_MS,
            );
            assert_eq!(st, 0x02, "GET/DELETE without PIN must deny 0x02");
        }
        // Unbound transport denies 0x05 on every PM op (fail-closed).
        let unbound = PmGateState {
            binding_bound: false,
            ..gate()
        };
        for op in [OP_PM_PUT, OP_PM_GET, OP_PM_LIST, OP_PM_DELETE, OP_PM_STATUS] {
            let body = if op == OP_PM_PUT {
                put_body("bank", "alice", b"s3cr3t")
            } else if op == OP_PM_LIST || op == OP_PM_STATUS {
                list_req(0, 32)
            } else {
                unknown.clone()
            };
            let (st, _) = dispatch_pm_op(
                op,
                &body,
                &unbound,
                &mut vault,
                &policy,
                1_770_000_000,
                &mut rng,
                &mut PmRateLimiter::new(),
                NOW_MS,
            );
            assert_eq!(st, 0x05, "unbound must deny op 0x{op:02X}");
        }
    }
}
