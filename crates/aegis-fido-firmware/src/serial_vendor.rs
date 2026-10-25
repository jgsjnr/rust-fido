//! Serial vendor dispatch (UART 115200).
//!
//! Move-only split of `serial_ctaphid` (F3): the four vendor-family
//! dispatchers live here with byte-identical bodies. Gates, predicates
//! (`serial_requires_pairing`, `serial_is_up_required`,
//! `serial_bind_mgmt_consumes_up`, `is_rescue_msg`), the router and the
//! deny framing stay in `serial_ctaphid`, which re-exports these four
//! for compat so external callers keep working unchanged.
//!
//! `no_std` compatible (`alloc` only).

extern crate alloc;

use alloc::vec::Vec;

use crate::ble::dispatch_bind::{
    authorize_backup_export_op, authorize_vendor_op, authorize_wallet_op,
};
use crate::persistence::{FlashStorageBackend, SecureStorage};
use crate::vendor_exec::{NVS_KEYS_OATH, NVS_KEYS_SLOTS};

/// Seletor do backup-export: chaves vendor on-device (`key_slots_v1`).
pub const BACKUP_SELECTOR_KEYS: u8 = 0x01;
/// Seletor do backup-export: credenciais OATH (`oath_creds_v1`).
pub const BACKUP_SELECTOR_OATH: u8 = 0x02;

/// Tamanho mínimo do envelope AEGN at-rest (`MAGIC(4) || VER(1) || NONCE(12) || CT+TAG(16)`).
const BACKUP_ENVELOPE_MIN: usize = 4 + 1 + 12 + 16;

/// Dispatches one vendor op with the exact BLE gates.
///
/// Returns `(wire_status, body)`; gate pass answers `0x04` (on-device
/// executor = follow-up, same as BLE), denial maps via `to_vendor_status`.
/// `binding_ok` comes from the caller (`BindingManager::verify` proof);
/// `pin_authenticated` = sessao pinUvAuth viva (plumbing ClientPIN, como
/// no rescue; fail-closed sem ela).
pub fn dispatch_serial_vendor(
    op: u8,
    binding_ok: bool,
    pin_authenticated: bool,
    up: bool,
) -> (u8, Vec<u8>) {
    match authorize_vendor_op(op, binding_ok, pin_authenticated, up) {
        Ok(()) => (0x04, Vec::new()),
        Err(e) => (e.to_vendor_status(), Vec::new()),
    }
}

/// Dispatches one wallet op (0x35-0x37) with the exact BLE gates.
///
/// Returns `(wire_status, body)`; gate pass answers `0x04` (on-device
/// executor `WalletStore` + NVS = follow-up, same as BLE), denial maps
/// via `to_vendor_status` (binding -> `0x05`, UP -> `0x01`).
pub fn dispatch_serial_wallet(op: u8, binding_ok: bool, up: bool) -> (u8, Vec<u8>) {
    match authorize_wallet_op(op, binding_ok, up) {
        Ok(()) => (0x04, Vec::new()),
        Err(e) => (e.to_vendor_status(), Vec::new()),
    }
}

/// Dispatches one backup-export request (`0x3A [selector:1]`).
///
/// Returns `(0x00, envelope)` with the at-rest AEGN envelope bytes of the
/// requested store (`0x01` = `key_slots_v1`, `0x02` = `oath_creds_v1`);
/// the bytes travel opaque and encrypted — plaintext/keys never leave the
/// device (restore/import is a follow-up opcode). Gates: privileged CONFIG
/// policy binding -> UP -> PIN via [`authorize_backup_export_op`]
/// (`0x05`/`0x01`/`0x02`); unknown selector, missing selector, absent
/// store or off-shape blob deny `0x04` fail-closed (never `0x00` empty).
pub fn dispatch_serial_backup_export<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    params: &[u8],
    binding_ok: bool,
    pin_authenticated: bool,
    up: bool,
) -> (u8, Vec<u8>) {
    use crate::ble::gatt_core::BleGattError;
    use crate::persistence::{ENVELOPE_MAGIC, ENVELOPE_VERSION};
    let key = match params.first() {
        Some(&BACKUP_SELECTOR_KEYS) => NVS_KEYS_SLOTS,
        Some(&BACKUP_SELECTOR_OATH) => NVS_KEYS_OATH,
        _ => return (BleGattError::InvalidOpcode.to_vendor_status(), Vec::new()),
    };
    if let Err(e) = authorize_backup_export_op(binding_ok, pin_authenticated, up) {
        return (e.to_vendor_status(), Vec::new());
    }
    let raw = match storage.backend().read_raw(key) {
        Ok(v) => v,
        Err(_) => return (BleGattError::InvalidFragment.to_vendor_status(), Vec::new()),
    };
    // Shape do envelope AEGN at-rest (magia + versão + mínimo criptográfico):
    // blob fora de forma nunca sai como backup (sem oráculo de tamanho).
    if raw.len() < BACKUP_ENVELOPE_MIN || raw[0..4] != ENVELOPE_MAGIC || raw[4] != ENVELOPE_VERSION
    {
        return (BleGattError::InvalidFragment.to_vendor_status(), Vec::new());
    }
    (0x00, raw)
}

/// Dispatches one rescue frame (`0x2E` already stripped by the caller).
///
/// Pure `RescueEngine::handle_packet` pass-through: UP/PIN latches must be
/// set by the caller beforehand (`set_user_presence` from the BOOT latch;
/// `set_pin_uv_authenticated` from `ClientPinState::has_valid_pin_uv_session`,
/// wired at all three transports). Returns `(wire_status, body)` for the
/// caller to frame status-first (`[status, body...]`), same shape
/// as the bind-mgmt branch.
pub fn dispatch_serial_rescue(
    engine: &mut aegis_fido_core::otp::rescue::RescueEngine,
    frame: &[u8],
) -> (u8, Vec<u8>) {
    engine.handle_packet(frame)
}

/// Dispatches one binding-mgmt op (`0x28-0x2D`) over serial with BLE-identical gates.
///
/// Reuses the `ble::gatt_core::dispatch_*` helpers byte-for-byte (claim / challenge /
/// verify / release / recovery); returns `(wire_status, body)` for the caller to
/// frame as `CMD_MSG` `[status, body...]` (status-first like BLE `notify_frame`,
/// no protocol change: the payload content is app-level).
/// `pairing_open`/`up` come from the caller (5s-hold window + BOOT latch).
pub fn dispatch_serial_bind_mgmt<B, R>(
    op: u8,
    params: &[u8],
    pairing_open: bool,
    up: bool,
    binding: &mut crate::binding::BindingManager,
    storage: &mut crate::persistence::SecureStorage<B>,
    rng: &mut R,
) -> (u8, Vec<u8>)
where
    B: crate::persistence::FlashStorageBackend,
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    use crate::binding::{BIND_CHALLENGE_LEN, BIND_ID_LEN, BIND_PAYLOAD_HASH_LEN, BIND_PUB_LEN};
    use crate::ble::dispatch_bind as gd;
    use crate::ble::gatt_core as g;
    if !gd::is_bind_mgmt_op(op) {
        return (
            g::BleGattError::InvalidOpcode.to_vendor_status(),
            Vec::new(),
        );
    }
    match op {
        g::OP_BIND_CLAIM => {
            if params.len() != BIND_PUB_LEN + BIND_ID_LEN {
                return (
                    g::BleGattError::InvalidFragment.to_vendor_status(),
                    Vec::new(),
                );
            }
            let mut app_pub = [0u8; BIND_PUB_LEN];
            let mut binding_id = [0u8; BIND_ID_LEN];
            app_pub.copy_from_slice(&params[..BIND_PUB_LEN]);
            binding_id.copy_from_slice(&params[BIND_PUB_LEN..]);
            match gd::dispatch_bind_claim(binding, storage, &app_pub, &binding_id, pairing_open, up)
            {
                Ok(()) => (0x00, binding_id.to_vec()),
                Err(e) => (e.to_vendor_status(), Vec::new()),
            }
        }
        g::OP_BIND_CHALLENGE => {
            if !params.is_empty() {
                return (
                    g::BleGattError::InvalidFragment.to_vendor_status(),
                    Vec::new(),
                );
            }
            match gd::dispatch_bind_challenge(binding, storage, rng) {
                Ok(ch) => (0x00, ch.to_vec()),
                Err(e) => (e.to_vendor_status(), Vec::new()),
            }
        }
        g::OP_BIND_VERIFY => {
            if params.len() < 1 + BIND_CHALLENGE_LEN + BIND_PAYLOAD_HASH_LEN {
                return (
                    g::BleGattError::InvalidFragment.to_vendor_status(),
                    Vec::new(),
                );
            }
            let vop = params[0];
            let mut ch = [0u8; BIND_CHALLENGE_LEN];
            let mut ph = [0u8; BIND_PAYLOAD_HASH_LEN];
            ch.copy_from_slice(&params[1..1 + BIND_CHALLENGE_LEN]);
            ph.copy_from_slice(
                &params[1 + BIND_CHALLENGE_LEN..1 + BIND_CHALLENGE_LEN + BIND_PAYLOAD_HASH_LEN],
            );
            match gd::dispatch_bind_verify(
                binding,
                &params[1 + BIND_CHALLENGE_LEN + BIND_PAYLOAD_HASH_LEN..],
                &ch,
                vop,
                &ph,
            ) {
                Ok(()) => (0x00, Vec::new()),
                Err(e) => (e.to_vendor_status(), Vec::new()),
            }
        }
        g::OP_BIND_RELEASE => {
            if params.len() < BIND_CHALLENGE_LEN + BIND_PAYLOAD_HASH_LEN {
                return (
                    g::BleGattError::InvalidFragment.to_vendor_status(),
                    Vec::new(),
                );
            }
            let mut ch = [0u8; BIND_CHALLENGE_LEN];
            let mut ph = [0u8; BIND_PAYLOAD_HASH_LEN];
            ch.copy_from_slice(&params[..BIND_CHALLENGE_LEN]);
            ph.copy_from_slice(
                &params[BIND_CHALLENGE_LEN..BIND_CHALLENGE_LEN + BIND_PAYLOAD_HASH_LEN],
            );
            match gd::dispatch_bind_release(
                binding,
                storage,
                &params[BIND_CHALLENGE_LEN + BIND_PAYLOAD_HASH_LEN..],
                &ch,
                &ph,
                up,
            ) {
                Ok(()) => (0x00, Vec::new()),
                Err(e) => (e.to_vendor_status(), Vec::new()),
            }
        }
        g::OP_RECOVERY_SET => match core::str::from_utf8(params) {
            Ok(pin) => match gd::dispatch_recovery_set(storage, pin, up) {
                Ok(()) => (0x00, Vec::new()),
                Err(e) => (e.to_vendor_status(), Vec::new()),
            },
            Err(_) => (
                g::BleGattError::InvalidFragment.to_vendor_status(),
                Vec::new(),
            ),
        },
        g::OP_RECOVERY_UNLOCK => match core::str::from_utf8(params) {
            Ok(pin) => match gd::dispatch_recovery_unlock(storage, binding, pin, up) {
                Ok(()) => (0x00, Vec::new()),
                Err(e) => (e.to_vendor_status(), Vec::new()),
            },
            Err(_) => (
                g::BleGattError::InvalidFragment.to_vendor_status(),
                Vec::new(),
            ),
        },
        _ => (
            g::BleGattError::InvalidOpcode.to_vendor_status(),
            Vec::new(),
        ),
    }
}
