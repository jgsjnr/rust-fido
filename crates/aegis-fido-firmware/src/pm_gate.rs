//! PM gate snapshot bridge (F-PM2 firmware side).
//!
//! Split from `pm_dispatch` (dep-track god-split, no behavior change):
//! device key/token constants plus the firmware-gate -> vault-gate mapping
//! and the vault-error -> wire-status mapping. Gates themselves are enforced
//! in `pm_store::authorize_pm_op`; denials reuse the frozen BLE vocabulary
//! (`NeedBinding` `0x05` / `PresenceRequired` `0x01` / `PinRequired` `0x02`).
//! No eFuse/Secure Boot/OTP call sites (REGRA PRINCIPAL N1).

use aegis_pm_vault::PmError;

/// Device PM vault master key (RAM session key material; the sealed NVS blob
/// is AEAD under this key via `PmVault::seal_to_blob`). Placeholder constant
/// until a TRNG-provisioned device key lands; no eFuse/Secure Boot surface.
pub const PM_VAULT_MASTER_KEY: [u8; 32] = [0x5Au8; 32];
/// Fixed domain separation token for the PM envelope seal (no user secret;
/// the same token seals and opens on every transport).
pub const PM_SEAL_PIN_TOKEN: &[u8] = b"aegis-pm-v1";

/// Wire status for a vault-level failure (gates already passed).
pub(crate) fn pm_error_to_wire(e: PmError) -> u8 {
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
pub(crate) fn to_vault_gate(gate: &crate::pm_store::PmGateState) -> aegis_pm_vault::PmGateState {
    aegis_pm_vault::PmGateState {
        binding_bound: gate.binding_bound,
        presence_confirmed: gate.presence_confirmed,
        pin_authenticated: gate.pin_authenticated,
        bound_within_ms: gate.bound_within_ms,
    }
}
