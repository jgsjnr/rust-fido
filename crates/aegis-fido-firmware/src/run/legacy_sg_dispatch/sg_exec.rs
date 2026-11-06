//! Secure Guard serial dispatch core (move-only split of `legacy_sg_dispatch`).
//!
//! Same opcodes `0x3A..=0x3E`, same `(status, body)` responses, same gates
//! as [`crate::freertos_route::dispatch_serial_vendor_msg`]. No new protocol.

use crate::persistence::{FlashStorageBackend, SecureStorage};
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::secure_guard::SecureGuardEngine;
use aegis_fido_core::wallet::WalletStore;

/// `true` for Secure Guard opcodes `0x3A..=0x3E` (same predicate as freertos).
#[cfg_attr(not(target_os = "espidf"), allow(dead_code))]
pub(crate) fn is_legacy_sg_op(op: u8) -> bool {
    crate::ble_gatt::is_secure_guard_op(op)
}

/// Side effects the freertos dispatcher applies around a successful SG op.
///
/// Mirrors `dispatch_serial_vendor_msg`: unlock success opens the host
/// pairing window, arms UP and captures the verified PIN for CTAP2 sync;
/// lock success closes the window.
#[derive(Debug, Default)]
#[cfg_attr(not(target_os = "espidf"), allow(dead_code))]
pub(crate) struct LegacySgEffects {
    /// `true` when `st == 0x00` and the guard reports unlocked after the op.
    pub did_unlock: bool,
    /// `true` when `st == 0x00` and `op == 0x3C` (lock) without unlock.
    pub did_lock: bool,
    /// PIN bytes extracted from a successful unlock/provision payload.
    pub verified_pin: Option<Vec<u8>>,
}

/// Extract PIN bytes from a `0x3B` CBOR payload (`pin` / `new_pin`, bytes or
/// text) or fall back to the raw payload. Byte-identical copy of the freertos
/// helper (no new protocol, no secrets logged).
#[cfg_attr(not(target_os = "espidf"), allow(dead_code))]
pub(crate) fn extract_pin_from_payload(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.is_empty() {
        return None;
    }
    if let Ok(ciborium::value::Value::Map(entries)) =
        ciborium::from_reader::<ciborium::value::Value, _>(payload)
    {
        for (k, v) in &entries {
            if let ciborium::value::Value::Text(key_str) = k {
                if key_str == "pin" || key_str == "new_pin" {
                    match v {
                        ciborium::value::Value::Bytes(b) => return Some(b.clone()),
                        ciborium::value::Value::Text(s) => return Some(s.as_bytes().to_vec()),
                        _ => {}
                    }
                }
            }
        }
        None
    } else {
        Some(payload.to_vec())
    }
}

/// Execute one Secure Guard op with freertos-identical semantics plus progresso OTA opcional no 0x3A serial.
///
/// Calls [`crate::secure_guard_exec::exec_secure_guard_op_with_ota`] then derives the
/// same side effects the freertos path applies (unlock opens window / arms
/// UP / captures PIN; lock closes window). Returns `(status, body, effects)`.
/// Framing (`[status] + body` via `CtapHidFramer::frame_message`) stays with
/// the caller so both loops frame identically. `ota_progress = Some(p)` (0..=100, de OtaState::progress com sessao aberta) anexa ota_progress ao CBOR do 0x3A; None (sem sessao) omite o campo (compat). Demais opcodes ignoram o argumento.
#[cfg_attr(not(target_os = "espidf"), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_legacy_secure_guard_op_with_ota<B, R>(
    sg: &mut SecureGuardEngine,
    storage: &mut SecureStorage<B>,
    wallet: &mut WalletStore,
    key_mgr: &mut KeyManager,
    oath: &mut OathApplet,
    op: u8,
    payload_cbor: &[u8],
    now_ms: u64,
    rng: &mut R,
    ota_progress: Option<u8>,
) -> (u8, Vec<u8>, LegacySgEffects)
where
    B: FlashStorageBackend,
    R: rand_core::CryptoRng,
{
    let (st, body) = crate::secure_guard_exec::exec_secure_guard_op_with_ota(
        sg,
        storage,
        wallet,
        key_mgr,
        oath,
        op,
        payload_cbor,
        now_ms,
        rng,
        ota_progress,
    );
    let mut effects = LegacySgEffects::default();
    if st == 0x00 && sg.is_unlocked() {
        effects.did_unlock = true;
        effects.verified_pin = extract_pin_from_payload(payload_cbor);
    } else if st == 0x00 && op == crate::ble_gatt::OP_SECURE_GUARD_LOCK {
        effects.did_lock = true;
    }
    (st, body, effects)
}

/// Execute one Secure Guard op with freertos-identical semantics (corpo legado).
///
/// Wrapper compat: delega para dispatch_legacy_secure_guard_op_with_ota com
/// `ota_progress = None` (0x3A sem campo, byte-identico ao anterior).
#[cfg_attr(not(target_os = "espidf"), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_legacy_secure_guard_op<B, R>(
    sg: &mut SecureGuardEngine,
    storage: &mut SecureStorage<B>,
    wallet: &mut WalletStore,
    key_mgr: &mut KeyManager,
    oath: &mut OathApplet,
    op: u8,
    payload_cbor: &[u8],
    now_ms: u64,
    rng: &mut R,
) -> (u8, Vec<u8>, LegacySgEffects)
where
    B: FlashStorageBackend,
    R: rand_core::CryptoRng,
{
    dispatch_legacy_secure_guard_op_with_ota(
        sg,
        storage,
        wallet,
        key_mgr,
        oath,
        op,
        payload_cbor,
        now_ms,
        rng,
        None,
    )
}
