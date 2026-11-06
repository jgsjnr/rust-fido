//! Shared test context for Secure Guard serial parity tests (move-only).
//!
//! Helpers moved verbatim from `legacy_sg_dispatch::tests`: identical
//! initial state (same fixed salts) on both freertos and legacy sides.

use crate::binding::BindingManager;
use crate::fw_log::FwLog;
use crate::pairing::PairingManager;
use crate::persistence::{PlatformFlashBackend, SecureStorage};
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::otp::rescue::RescueEngine;
use aegis_fido_core::secure_guard::{SecureGuardEngine, SecureGuardPolicy};
use aegis_fido_core::wallet::WalletStore;
use aegis_fido_usb::ctaphid::CtapHidMessage;

pub(crate) fn test_policy() -> SecureGuardPolicy {
    SecureGuardPolicy {
        pbkdf2_iterations: 10,
        ..Default::default()
    }
}

pub(crate) fn cbor_action_pin(action: &str, pin: &[u8]) -> Vec<u8> {
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

pub(crate) fn frame_msg(cid: u32, cmd: u8, op: u8, body_cbor: &[u8]) -> CtapHidMessage {
    let mut payload = Vec::with_capacity(1 + body_cbor.len());
    payload.push(op);
    payload.extend_from_slice(body_cbor);
    CtapHidMessage { cid, cmd, payload }
}

/// Freertos vendor ctx with owned parts leaked for the ctx lifetime
/// (tests only). `provision_first` pre-provisions with fixed salts so
/// no random provision response is involved. NO wipe/config ops here.
pub(crate) fn freertos_ctx(
    pin: &[u8],
    provision_first: bool,
) -> crate::freertos_route::SerialVendorCtx<'static> {
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
        pending: crate::wallet_approval::WalletPendingApproval::new(),
        key_mgr: leak(KeyManager::new()),
        oath: leak(OathApplet::new()),
        fwlog: leak(FwLog::new()),
        rescue: leak(RescueEngine::new()),
        pairing: leak(PairingManager::new()),
        pin_uv_session: false,
        secure_guard: Some(leak(sg)),
        verified_pin: None,
        ota_state: None,
        ota_provisioned: false,
        ota_pubkey: [0u8; 32],
        ota_current_version: 0,
        up_hook: false,
        #[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
        pm_limiter: crate::pm_store::PmRateLimiter::new(),
    }
}

/// Legacy SG setup with identical initial state (same fixed salts).
pub(crate) fn legacy_setup(
    pin: &[u8],
    provision_first: bool,
) -> (
    SecureGuardEngine,
    SecureStorage<PlatformFlashBackend>,
    WalletStore,
    KeyManager,
    OathApplet,
    PairingManager,
) {
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
