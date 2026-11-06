//! PM dispatch core: persistence + wire dispatch (F-PM2 firmware side).
//!
//! Split from `pm_dispatch` (dep-track god-split, no behavior change).
//! Single choke point for every transport: backoff is checked first
//! (fail-closed `0x04` while armed), then the canonical gate, then the
//! vault. Exactly one secret-free [`PmAuditEvent`](crate::pm_store::PmAuditEvent)
//! line is emitted per call; the budget records only authenticated outcomes
//! (`0x00` resets, `0x03`/`0x04` spend).
//!
//! - SRP: this module owns the wire dispatch only (CBOR decode -> vault call
//!   -> CBOR encode). Record shapes/policy live in `aegis-pm-vault`, gates
//!   in `pm_store::authorize_pm_op`, persistence in `pm_store` (NVS opaque
//!   blob). The phone is a blind transport.
//! - `no_std`-compatible (`alloc`-only). No logging of user data, no
//!   `unwrap`/`expect` outside `#[cfg(test)]`, no eFuse/Secure Boot/OTP
//!   call sites (REGRA PRINCIPAL N1).
//!
//! Diet: this module only exists outside the capability presets
//! (`cap-fido-only` / `cap-fido-totp`); inside the diet every PM op answers
//! `UNSUPPORTED_FEATURE` (`0x06`) at the funnels, never routed here.

extern crate alloc;

use aegis_pm_vault::{PasswordEntry, PmPolicy, PmVault};
use alloc::vec::Vec;
use ciborium::value::Value;

use crate::ble_gatt::PmBackoffGate;
use crate::persistence::{FlashStorageBackend, SecureStorage};
use crate::pm_store::{
    authorize_pm_op, pm_blob_load_opt, pm_blob_save, PmAuditEvent, PmGateState, OP_PM_DELETE,
    OP_PM_GET, OP_PM_LIST, OP_PM_PUT, OP_PM_STATUS,
};

use crate::pm_cbor::{
    decode_id_body, encode_id_body, field, from_cbor, get_bytes, get_text, get_u32, to_cbor,
};
use crate::pm_gate::{pm_error_to_wire, to_vault_gate, PM_SEAL_PIN_TOKEN, PM_VAULT_MASTER_KEY};

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
    let (st, out) = dispatch_pm_op(
        op, body, gate, &mut vault, policy, now_secs, rng, limiter, now_ms,
    );
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
#[path = "pm_tests.rs"]
mod pm_tests;
