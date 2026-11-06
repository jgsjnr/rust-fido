//! F1 wallet-compat integration test (consumer perspective).
//!
//! Exercises the facade surface only (`universal-device-sdk` types): opcode
//! reservation, family predicates, app-approval predicate, capability bits,
//! and the `hardwallet` feature gate. No firmware, no transport, no secrets.

use universal_device_sdk::{
    capabilities, is_wallet_compat_opcode, is_wallet_family_opcode, is_wallet_opcode,
    wallet_op_requires_app_approval, CapabilitySet, SdkError, SdkRequest, WalletRequest,
    WalletSignRequest, WALLET_OP_ADDR, WALLET_OP_DERIVE, WALLET_OP_GEN, WALLET_OP_LIST,
    WALLET_OP_PSBT, WALLET_OP_XPUB,
};

#[test]
fn frozen_wallet_range_untouched() {
    assert_eq!(
        (WALLET_OP_GEN, WALLET_OP_LIST, WALLET_OP_ADDR),
        (0x35, 0x36, 0x37)
    );
    for op in [WALLET_OP_GEN, WALLET_OP_LIST, WALLET_OP_ADDR] {
        assert!(is_wallet_opcode(op));
        assert!(is_wallet_family_opcode(op));
        assert!(!is_wallet_compat_opcode(op));
        assert!(!wallet_op_requires_app_approval(op));
    }
}

#[test]
fn compat_reservation_first_free_after_pm() {
    assert_eq!(
        (WALLET_OP_DERIVE, WALLET_OP_XPUB, WALLET_OP_PSBT),
        (0x48, 0x49, 0x4A)
    );
    for op in [WALLET_OP_DERIVE, WALLET_OP_XPUB, WALLET_OP_PSBT] {
        assert!(is_wallet_compat_opcode(op));
        assert!(is_wallet_family_opcode(op));
        assert!(!is_wallet_opcode(op));
    }
    // Occupied neighbors stay outside the wallet family.
    for op in [
        0x20u8, 0x27, 0x28, 0x2D, 0x2E, 0x2F, 0x30, 0x34, 0x38, 0x39, 0x3A, 0x3E, 0x3F, 0x40, 0x41,
        0x42, 0x43, 0x47,
    ] {
        assert!(!is_wallet_family_opcode(op), "op 0x{op:02X}");
    }
}

#[test]
fn only_psbt_needs_app_mediated_approval() {
    assert!(wallet_op_requires_app_approval(WALLET_OP_PSBT));
    assert!(!wallet_op_requires_app_approval(WALLET_OP_DERIVE));
    assert!(!wallet_op_requires_app_approval(WALLET_OP_XPUB));
}

#[test]
fn compat_capability_bits_are_additive_and_follow_hardwallet() {
    assert_eq!(CapabilitySet::WALLET_DERIVE.bits(), 1 << 15);
    assert_eq!(CapabilitySet::WALLET_XPUB.bits(), 1 << 16);
    assert_eq!(CapabilitySet::WALLET_PSBT.bits(), 1 << 17);
    let caps = capabilities();
    let on = cfg!(feature = "hardwallet");
    assert_eq!(caps.contains(CapabilitySet::WALLET_DERIVE), on);
    assert_eq!(caps.contains(CapabilitySet::WALLET_XPUB), on);
    assert_eq!(caps.contains(CapabilitySet::WALLET_PSBT), on);
    // Additive: enabling compat never clears the frozen wallet bit.
    let both = CapabilitySet::HARDWALLET.union(CapabilitySet::WALLET_PSBT);
    assert!(both.contains(CapabilitySet::HARDWALLET));
}

#[test]
fn compat_requests_follow_the_hardwallet_family_gate() {
    let derive = SdkRequest::Wallet(WalletRequest {
        opcode: WALLET_OP_DERIVE,
        payload: Vec::new(),
    });
    let psbt_sign = SdkRequest::WalletSign(WalletSignRequest {
        opcode: WALLET_OP_PSBT,
        payload: Vec::new(),
    });
    if cfg!(feature = "hardwallet") {
        assert_eq!(derive.check_compiled(), Ok(()));
        assert_eq!(psbt_sign.check_compiled(), Ok(()));
    } else {
        // `NotCompiled` is the ONLY legitimate source here: never a runtime
        // failure, never a faked success.
        assert_eq!(derive.check_compiled(), Err(SdkError::NotCompiled));
        assert_eq!(psbt_sign.check_compiled(), Err(SdkError::NotCompiled));
    }
}
