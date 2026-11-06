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

use crate::ble_gatt::{authorize_vendor_op, authorize_wallet_op, BleGattError};

/// Dispatches one vendor op with the exact BLE gates.
///
/// Returns `(wire_status, body)`; gate pass answers `0x04` (on-device
/// executor = follow-up, same as BLE), denial maps via `to_vendor_status`.
/// `VENDOR_SIGN` (`0x41`) usa gate proprio classe GEN (binding -> UP, sem PIN),
/// fora da faixa `0x20-0x27` congelada (ver `vendor_keys::OP_VENDOR_SIGN`).
/// `binding_ok` comes from the caller (`BindingManager::verify` proof);
/// `pin_authenticated` = sessao pinUvAuth viva (plumbing ClientPIN, como
/// no rescue; fail-closed sem ela).
pub fn dispatch_serial_vendor(
    op: u8,
    binding_ok: bool,
    pin_authenticated: bool,
    up: bool,
) -> (u8, Vec<u8>) {
    // VENDOR_SIGN (0x41): SIGN dedicado, classe GEN (binding -> UP, sem PIN).
    // `authorize_vendor_op` rejeitaria como InvalidOpcode (faixa 0x20-0x27
    // congelada); gate proprio identico ao GEN, espelhando o executor.
    if crate::vendor_exec::is_vendor_sign_op(op) {
        if !crate::binding::binding_bypass_enabled() && !binding_ok {
            return (BleGattError::NeedBinding.to_vendor_status(), Vec::new());
        }
        if !up {
            return (
                BleGattError::PresenceRequired.to_vendor_status(),
                Vec::new(),
            );
        }
        return (0x04, Vec::new());
    }
    match authorize_vendor_op(op, binding_ok, pin_authenticated, up) {
        Ok(()) => (0x04, Vec::new()),
        Err(e) => (e.to_vendor_status(), Vec::new()),
    }
}

/// Dispatches one PM op (`0x43..=0x47`) over serial with the exact BLE gates.
///
/// Session RAM vault: the caller owns the [`PmVault`] (RAM only; sealed NVS
/// blob I/O is a follow-up via `pm_store`). Gate denial maps via
/// `authorize_pm_op` (binding -> `0x05`, UP -> `0x01`, PIN -> `0x02`,
/// window-expiry -> `0x01`); vault failures map fail-closed (`NotFound` ->
/// `0x03`, else `0x04`). Backoff (`limiter`, `now_ms`) denies `0x04` while
/// armed; `up_within_ms` is `0` because the serial funnel consumes the UP
/// latch for this op (fresh UP by construction). Outside the diet the caller
/// must answer `UNSUPPORTED_FEATURE` (`0x06`) and never call this.
#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
#[allow(clippy::too_many_arguments)]
pub fn dispatch_serial_pm<R: rand_core::CryptoRng>(
    op: u8,
    body: &[u8],
    binding_ok: bool,
    pin_authenticated: bool,
    up: bool,
    bound_within_ms: u64,
    vault: &mut aegis_pm_vault::PmVault,
    policy: &aegis_pm_vault::PmPolicy,
    now_secs: u64,
    rng: &mut R,
    limiter: &mut impl crate::ble_gatt::PmBackoffGate,
    now_ms: u64,
) -> (u8, Vec<u8>) {
    use crate::pm_store::PmGateState;
    let gate = PmGateState {
        binding_bound: binding_ok,
        presence_confirmed: up,
        pin_authenticated,
        bound_within_ms,
        up_within_ms: 0,
    };
    crate::pm_dispatch::dispatch_pm_op(
        op, body, &gate, vault, policy, now_secs, rng, limiter, now_ms,
    )
}

#[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
#[allow(clippy::too_many_arguments)]
pub fn dispatch_serial_pm_persist<
    B: crate::persistence::FlashStorageBackend,
    R: rand_core::CryptoRng,
>(
    op: u8,
    body: &[u8],
    binding_ok: bool,
    pin_authenticated: bool,
    up: bool,
    bound_within_ms: u64,
    storage: &mut crate::persistence::SecureStorage<B>,
    policy: &aegis_pm_vault::PmPolicy,
    now_secs: u64,
    rng: &mut R,
    limiter: &mut impl crate::ble_gatt::PmBackoffGate,
    now_ms: u64,
) -> (u8, Vec<u8>) {
    use crate::pm_store::PmGateState;
    let gate = PmGateState {
        binding_bound: binding_ok,
        presence_confirmed: up,
        pin_authenticated,
        bound_within_ms,
        up_within_ms: 0,
    };
    crate::pm_dispatch::dispatch_pm_op_persist(
        op, body, &gate, storage, policy, now_secs, rng, limiter, now_ms,
    )
}

/// Dispatches one wallet op (`0x35`-`0x37` + compat `0x48`-`0x4B`) with
/// the exact BLE gates.
///
/// Returns `(wire_status, body)`; gate pass answers `0x04` (status-only
/// helper: the executing funnels — serial legado, FreeRTOS, BLE — run
/// the real executor via `wallet_sign::wallet_dispatch`; PSBT `0x4A`
/// additionally requires the app-mediated approval receipt + PIN there,
/// and PENDING `0x4B` exposes the preview, so this helper can never
/// sign by construction). Denial maps via `to_vendor_status`
/// (binding -> `0x05`, UP -> `0x01`).
pub fn dispatch_serial_wallet(op: u8, binding_ok: bool, up: bool) -> (u8, Vec<u8>) {
    match authorize_wallet_op(op, binding_ok, up) {
        Ok(()) => (0x04, Vec::new()),
        Err(e) => (e.to_vendor_status(), Vec::new()),
    }
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

#[cfg(all(test, not(any(feature = "cap-fido-only", feature = "cap-fido-totp"))))]
mod tests {
    use super::*;
    use crate::persistence::{MockFlashBackend, SecureStorage};
    use crate::pm_store::{
        PmRateLimiter, OP_PM_DELETE, OP_PM_GET, OP_PM_LIST, OP_PM_PUT, OP_PM_STATUS,
    };

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x11u8; 32], &[0x22u8; 32])
    }

    /// Funnel-level fail-closed: unbound transport denies 0x05 on every PM
    /// op before any vault access (binding -> UP -> PIN -> window).
    #[test]
    fn unbound_serial_denies_every_pm_op() {
        let mut storage = test_storage();
        let policy = aegis_pm_vault::PmPolicy::default();
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        for op in [OP_PM_PUT, OP_PM_GET, OP_PM_LIST, OP_PM_DELETE, OP_PM_STATUS] {
            let (st, body) = dispatch_serial_pm_persist(
                op,
                &[],
                false, // binding_ok: unbound transport
                true,
                true,
                0,
                &mut storage,
                &policy,
                1_770_000_000,
                &mut rng,
                &mut PmRateLimiter::new(),
                1_770_000_000_000,
            );
            assert_eq!(st, 0x05, "unbound must deny op 0x{op:02X}");
            assert!(body.is_empty());
        }
    }

    /// Funnel-level strict PIN: GET/DELETE deny 0x02 with binding + UP but
    /// no PIN session (no test-mode bypass at this layer).
    #[test]
    fn serial_pm_get_delete_require_strict_pin() {
        let mut storage = test_storage();
        let policy = aegis_pm_vault::PmPolicy::default();
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        for op in [OP_PM_GET, OP_PM_DELETE] {
            let (st, _) = dispatch_serial_pm_persist(
                op,
                &[],
                true,
                false, // pin_authenticated: no session
                true,
                0,
                &mut storage,
                &policy,
                1_770_000_000,
                &mut rng,
                &mut PmRateLimiter::new(),
                1_770_000_000_000,
            );
            assert_eq!(st, 0x02, "GET/DELETE without PIN must deny 0x02");
        }
    }
}
///
/// Dispatches one binding-mgmt op (`0x28-0x2D`) over serial with BLE-identical gates.
///
/// Reuses the `ble_gatt::dispatch_*` helpers byte-for-byte (claim / challenge /
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
    R: rand_core::CryptoRng,
{
    use crate::binding::{BIND_CHALLENGE_LEN, BIND_ID_LEN, BIND_PAYLOAD_HASH_LEN, BIND_PUB_LEN};
    use crate::ble_gatt as g;
    if !g::is_bind_mgmt_op(op) {
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
            match g::dispatch_bind_claim(binding, storage, &app_pub, &binding_id, pairing_open, up)
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
            match g::dispatch_bind_challenge(binding, storage, rng) {
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
            match g::dispatch_bind_verify(
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
            if params.is_empty() {
                if !up {
                    return (
                        g::BleGattError::PresenceRequired.to_vendor_status(),
                        Vec::new(),
                    );
                }
                binding.wipe(storage);
                return (0x00, Vec::new());
            }
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
            match g::dispatch_bind_release(
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
            Ok(pin) => match g::dispatch_recovery_set(storage, pin, up) {
                Ok(()) => (0x00, Vec::new()),
                Err(e) => (e.to_vendor_status(), Vec::new()),
            },
            Err(_) => (
                g::BleGattError::InvalidFragment.to_vendor_status(),
                Vec::new(),
            ),
        },
        g::OP_RECOVERY_UNLOCK => match core::str::from_utf8(params) {
            Ok(pin) => match g::dispatch_recovery_unlock(storage, binding, pin, up) {
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
