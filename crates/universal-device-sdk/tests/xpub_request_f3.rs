//! F3 xpub-request integration test (consumer perspective).
//!
//! Exercises the facade surface only (`universal-device-sdk` types): the
//! typed [`XpubRequest`] (account-level public export request, no crypto
//! here), the reserved `WALLET_OP_XPUB` opcode riding the `hardwallet` family
//! gate, the app-mediated approval predicate (never required for xpub), and
//! the additive `WALLET_XPUB` capability bit. No firmware, no transport, no
//! secrets; derivation itself runs on-device or through the bridge FFI.

use universal_device_sdk::{
    capabilities, is_wallet_compat_opcode, is_wallet_family_opcode,
    wallet_op_requires_app_approval, CapabilitySet, CoinKind, SdkError, SdkRequest, WalletRequest,
    XpubRequest, WALLET_OP_GEN, WALLET_OP_XPUB,
};

#[test]
fn xpub_request_is_a_plain_typed_handle() {
    const REQ: XpubRequest = XpubRequest::new(CoinKind::Bitcoin, 0);
    assert_eq!(REQ.coin, CoinKind::Bitcoin);
    assert_eq!(REQ.account, 0);
    assert_eq!(
        XpubRequest::new(CoinKind::Ethereum, 2),
        XpubRequest {
            coin: CoinKind::Ethereum,
            account: 2,
        }
    );
    // Only the opcode range reserves wire meaning; the request itself carries
    // no encoding and no key material.
    assert_ne!(WALLET_OP_XPUB, WALLET_OP_GEN);
    assert_eq!(WALLET_OP_XPUB, 0x49);
}

#[test]
fn xpub_opcode_rides_the_hardwallet_family_gate() {
    assert!(is_wallet_compat_opcode(WALLET_OP_XPUB));
    assert!(is_wallet_family_opcode(WALLET_OP_XPUB));
    let req = SdkRequest::Wallet(WalletRequest {
        opcode: WALLET_OP_XPUB,
        payload: Vec::new(),
    });
    if cfg!(feature = "hardwallet") {
        assert_eq!(req.check_compiled(), Ok(()));
    } else {
        // `NotCompiled` is the ONLY legitimate source here: never a runtime
        // failure, never a faked success.
        assert_eq!(req.check_compiled(), Err(SdkError::NotCompiled));
    }
}

#[test]
fn xpub_never_requires_app_mediated_approval() {
    // Export is public-only; the approval bit belongs to signing alone.
    assert!(!wallet_op_requires_app_approval(WALLET_OP_XPUB));
}

#[test]
fn xpub_capability_bit_is_additive_and_follows_hardwallet() {
    assert_eq!(CapabilitySet::WALLET_XPUB.bits(), 1 << 16);
    let caps = capabilities();
    let on = cfg!(feature = "hardwallet");
    assert_eq!(caps.contains(CapabilitySet::WALLET_XPUB), on);
    // Enabling xpub never clears the frozen wallet bit.
    let both = CapabilitySet::HARDWALLET.union(CapabilitySet::WALLET_XPUB);
    assert!(both.contains(CapabilitySet::HARDWALLET));
}
