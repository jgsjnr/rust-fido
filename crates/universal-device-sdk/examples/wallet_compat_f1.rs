//! F1 wallet-compat reservation (facade-only demo).
//!
//! Shows the consumer-visible surface of the F1 opcode reservation through
//! `universal-device-sdk` types: frozen wallet range, reserved compat
//! opcodes, family predicates, the app-mediated approval bit for PSBT, the
//! additive capability bits, and the `hardwallet` feature gate. No firmware,
//! no transport, no secrets; compat opcodes carry no execution until F2-F4.

use universal_device_sdk::{
    capabilities, is_wallet_family_opcode, wallet_op_requires_app_approval, CapabilitySet,
    SdkRequest, WalletRequest, WALLET_OP_DERIVE, WALLET_OP_PSBT, WALLET_OP_XPUB,
};

fn main() {
    // Frozen range stays reserved; compat lives on the first free bytes.
    assert!(is_wallet_family_opcode(0x35));
    for (name, op) in [
        ("DERIVE", WALLET_OP_DERIVE),
        ("XPUB", WALLET_OP_XPUB),
        ("PSBT", WALLET_OP_PSBT),
    ] {
        assert!(is_wallet_family_opcode(op), "{name} must be wallet-family");
        let req = SdkRequest::Wallet(WalletRequest {
            opcode: op,
            payload: Vec::new(),
        });
        match req.check_compiled() {
            Ok(()) => println!("{name} 0x{op:02X}: compiled in (reserved, no execution yet)"),
            Err(e) => println!("{name} 0x{op:02X}: {e}"),
        }
    }
    // Only PSBT signing needs explicit app-mediated approval: the companion
    // app shows the details and returns approve/deny; the firmware signs only
    // after approval plus binding -> UP. No on-device display dependency.
    assert!(wallet_op_requires_app_approval(WALLET_OP_PSBT));
    assert!(!wallet_op_requires_app_approval(WALLET_OP_DERIVE));
    assert!(!wallet_op_requires_app_approval(WALLET_OP_XPUB));
    // Additive capability bits ride the `hardwallet` family gate.
    let caps = capabilities();
    println!(
        "hardwallet={} derive={} xpub={} psbt={}",
        caps.contains(CapabilitySet::HARDWALLET),
        caps.contains(CapabilitySet::WALLET_DERIVE),
        caps.contains(CapabilitySet::WALLET_XPUB),
        caps.contains(CapabilitySet::WALLET_PSBT),
    );
}
