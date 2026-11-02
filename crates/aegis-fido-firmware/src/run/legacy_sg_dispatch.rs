//! Legacy serial Secure Guard dispatch (parity with freertos).
//!
//! Move-only reuse of [`crate::secure_guard_exec::exec_secure_guard_op`]:
//! same opcodes `0x3A..=0x3E`, same `(status, body)` responses, same gates
//! as [`crate::freertos_route::dispatch_serial_vendor_msg`]. No new protocol.
//!
//! The legacy serial loop (`run_loop_legacy`, section D) had no `0x3A..0x3E`
//! branch; the freertos dispatcher has it. This module is the single shared
//! tail so host tests can prove byte parity without hardware.

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

/// Execute one Secure Guard op with freertos-identical semantics.
///
/// Calls [`crate::secure_guard_exec::exec_secure_guard_op`] then derives the
/// same side effects the freertos path applies (unlock opens window / arms
/// UP / captures PIN; lock closes window). Returns `(status, body, effects)`.
/// Framing (`[status] + body` via `CtapHidFramer::frame_message`) stays with
/// the caller so both loops frame identically.
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
    let (st, body) = crate::secure_guard_exec::exec_secure_guard_op(
        sg,
        storage,
        wallet,
        key_mgr,
        oath,
        op,
        payload_cbor,
        now_ms,
        rng,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ble_gatt::{OP_SECURE_GUARD_LOCK, OP_SECURE_GUARD_STATUS, OP_SECURE_GUARD_UNLOCK};
    use crate::pairing::PairingManager;
    use aegis_fido_core::secure_guard::{SecureGuardPolicy, SecureGuardState};
    use aegis_fido_usb::ctaphid::{CtapHidFramer, CtapHidMessage, CMD_MSG};

    fn test_policy() -> SecureGuardPolicy {
        SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..Default::default()
        }
    }

    fn cbor_action_pin(action: &str, pin: &[u8]) -> Vec<u8> {
        let map = vec![
            (
                ciborium::value::Value::Text("action".into()),
                ciborium::value::Value::Text(action.into()),
            ),
            (
                ciborium::value::Value::Text("pin".into()),
                ciborium::value::Value::Bytes(pin.to_vec()),
            ),
        ];
        let mut out = Vec::new();
        ciborium::into_writer(&ciborium::value::Value::Map(map), &mut out).unwrap();
        out
    }

    fn frame_msg(cid: u32, cmd: u8, op: u8, body_cbor: &[u8]) -> CtapHidMessage {
        let mut payload = Vec::with_capacity(1 + body_cbor.len());
        payload.push(op);
        payload.extend_from_slice(body_cbor);
        CtapHidMessage { cid, cmd, payload }
    }

    /// Freertos vendor ctx with owned parts leaked for the ctx lifetime
    /// (tests only). `provision_first` pre-provisions with fixed salts so
    /// no random provision response is involved. NO wipe/config ops here.
    fn freertos_ctx(
        pin: &[u8],
        provision_first: bool,
    ) -> crate::freertos_route::SerialVendorCtx<'static> {
        use crate::binding::BindingManager;
        use crate::fw_log::FwLog;
        use crate::persistence::{PlatformFlashBackend, SecureStorage};
        use aegis_fido_core::otp::rescue::RescueEngine;

        fn leak<T>(v: T) -> &'static mut T {
            Box::leak(Box::new(v))
        }

        let mut sg = SecureGuardEngine::new(test_policy());
        if provision_first {
            sg.provision_pin(pin, [0x11; 16], b"", [0x22; 16], 1000)
                .expect("provision ctx");
            let _ = sg.lock_now(1001);
        }
        crate::freertos_route::SerialVendorCtx {
            pairing_open: false,
            up_latched: false,
            now_ms: 2000,
            now_secs: 2,
            arm_up: false,
            pin_verified: false,
            binding: leak(BindingManager::new()),
            storage: leak(SecureStorage::new(
                PlatformFlashBackend::new(),
                &[0x11; 32],
                &[0x22; 32],
            )),
            wallet: leak(WalletStore::new()),
            key_mgr: leak(KeyManager::new()),
            oath: leak(OathApplet::new()),
            fwlog: leak(FwLog::new()),
            rescue: leak(RescueEngine::new()),
            pairing: leak(PairingManager::new()),
            pin_uv_session: false,
            secure_guard: Some(leak(sg)),
            verified_pin: None,
        }
    }

    /// Legacy SG setup with identical initial state (same fixed salts).
    fn legacy_setup(
        pin: &[u8],
        provision_first: bool,
    ) -> (
        SecureGuardEngine,
        SecureStorage<crate::persistence::PlatformFlashBackend>,
        WalletStore,
        KeyManager,
        OathApplet,
        PairingManager,
    ) {
        use crate::persistence::{PlatformFlashBackend, SecureStorage};
        let mut sg = SecureGuardEngine::new(test_policy());
        if provision_first {
            sg.provision_pin(pin, [0x11; 16], b"", [0x22; 16], 1000)
                .expect("provision legacy");
            let _ = sg.lock_now(1001);
        }
        (
            sg,
            SecureStorage::new(PlatformFlashBackend::new(), &[0x11; 32], &[0x22; 32]),
            WalletStore::new(),
            KeyManager::new(),
            OathApplet::new(),
            PairingManager::new(),
        )
    }

    #[test]
    fn legacy_status_matches_freertos_bytes() {
        let pin = b"4829";
        let mut ctx = freertos_ctx(pin, false);
        let (mut sg, mut storage, mut wallet, mut key_mgr, mut oath, _pairing) =
            legacy_setup(pin, false);
        let now_ms = 2000u64;

        let msg = frame_msg(0x0102_0304, CMD_MSG, OP_SECURE_GUARD_STATUS, &[]);
        let out = crate::freertos_route::dispatch_serial_vendor_msg(&mut ctx, &msg)
            .expect("freertos handles 0x3A");
        assert!(!out.1, "SG never consumes UP");

        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let (st, body, effects) = dispatch_legacy_secure_guard_op(
            &mut sg,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_STATUS,
            &[],
            now_ms,
            &mut rng,
        );
        assert!(!effects.did_unlock && !effects.did_lock);
        assert!(effects.verified_pin.is_none());

        let mut resp = Vec::with_capacity(1 + body.len());
        resp.push(st);
        resp.extend_from_slice(&body);
        let expected = CtapHidFramer::frame_message(0x0102_0304, CMD_MSG, &resp);
        assert_eq!(out.0, expected, "status bytes must match freertos");
        assert_eq!(resp[0], 0x00);
        assert_eq!(sg.state(), SecureGuardState::Unprovisioned);
    }

    #[test]
    fn legacy_unlock_matches_freertos_bytes() {
        let pin = b"4829";
        let mut ctx = freertos_ctx(pin, true);
        let (mut sg, mut storage, mut wallet, mut key_mgr, mut oath, mut pairing) =
            legacy_setup(pin, true);
        let now_ms = 3000u64;
        let cbor = cbor_action_pin("unlock", pin);

        let msg = frame_msg(0x1122_3344, CMD_MSG, OP_SECURE_GUARD_UNLOCK, &cbor);
        let out = crate::freertos_route::dispatch_serial_vendor_msg(&mut ctx, &msg)
            .expect("freertos handles 0x3B");
        assert!(!out.1, "SG never consumes UP");

        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let (st, body, effects) = dispatch_legacy_secure_guard_op(
            &mut sg,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &cbor,
            now_ms,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert!(effects.did_unlock);
        assert_eq!(effects.verified_pin.as_deref(), Some(pin.as_slice()));
        assert!(sg.is_unlocked());

        let mut resp = Vec::with_capacity(1 + body.len());
        resp.push(st);
        resp.extend_from_slice(&body);
        let expected = CtapHidFramer::frame_message(0x1122_3344, CMD_MSG, &resp);
        assert_eq!(out.0, expected, "unlock bytes must match freertos");
        // Freertos side effects parity: unlock opens window + arms UP + PIN.
        assert!(ctx.pin_verified);
        assert!(ctx.arm_up);
        assert!(ctx.pairing_open);
        assert!(ctx.verified_pin.is_some());
        // Legacy caller applies the same window effect.
        pairing.open_host_window(now_ms);
        assert!(pairing.is_pairing_window_open(now_ms));
    }

    #[test]
    fn legacy_lock_matches_freertos_bytes() {
        let pin = b"4829";
        let mut ctx = freertos_ctx(pin, true);
        let (mut sg, mut storage, mut wallet, mut key_mgr, mut oath, _pairing) =
            legacy_setup(pin, true);
        let now_ms = 4000u64;
        // Unlock both sides first (deterministic: pre-provisioned above).
        let cbor = cbor_action_pin("unlock", pin);
        let msg_un = frame_msg(0x1122_3344, CMD_MSG, OP_SECURE_GUARD_UNLOCK, &cbor);
        let _ = crate::freertos_route::dispatch_serial_vendor_msg(&mut ctx, &msg_un);
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let (st_un, _, _) = dispatch_legacy_secure_guard_op(
            &mut sg,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &cbor,
            now_ms,
            &mut rng,
        );
        assert_eq!(st_un, 0x00);
        assert!(sg.is_unlocked());
        assert!(ctx.secure_guard.as_ref().unwrap().is_unlocked());

        // Now lock via both paths with identical input bytes.
        let msg = frame_msg(0x1122_3344, CMD_MSG, OP_SECURE_GUARD_LOCK, &[]);
        let out = crate::freertos_route::dispatch_serial_vendor_msg(&mut ctx, &msg)
            .expect("freertos handles 0x3C");
        let (st, body, effects) = dispatch_legacy_secure_guard_op(
            &mut sg,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            OP_SECURE_GUARD_LOCK,
            &[],
            now_ms + 10,
            &mut rng,
        );
        assert_eq!(st, 0x00);
        assert!(effects.did_lock && !effects.did_unlock);
        assert_eq!(sg.state(), SecureGuardState::Locked);

        let mut resp = Vec::with_capacity(1 + body.len());
        resp.push(st);
        resp.extend_from_slice(&body);
        let expected = CtapHidFramer::frame_message(0x1122_3344, CMD_MSG, &resp);
        assert_eq!(out.0, expected, "lock bytes must match freertos");
    }
}
