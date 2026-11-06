//! Resource Classification and Authorization Gate
//!
//! Categorizes operations and provides enforcement barriers for sensitive cryptographic
//! assets (Wallets, On-Device Keys, OATH) while guaranteeing unrestricted passkey access.

use super::policy::SecureGuardPolicy;

// Vendor Opcode Constants (0x20..0x4B, groups as allocated on the wire)
pub const OP_KEY_GEN_ONDEVICE: u8 = 0x20;
pub const OP_KEY_IMPORT_ENVELOPE: u8 = 0x21;
pub const OP_KEY_LIST: u8 = 0x22;
pub const OP_KEY_DELETE: u8 = 0x23;

pub const OP_OATH_PUT: u8 = 0x24;
pub const OP_OATH_LIST: u8 = 0x25;
pub const OP_OATH_CODE: u8 = 0x26;
pub const OP_OATH_DELETE: u8 = 0x27;

pub const OP_WALLET_GEN: u8 = 0x35;
pub const OP_WALLET_LIST: u8 = 0x36;
pub const OP_WALLET_ADDR: u8 = 0x37;
pub const OP_PIV_ENROLL: u8 = 0x39;

/// Dedicated SIGN opcode (0x41, GEN-class: binding -> UP, no PIN).
/// Same protection class as GEN 0x20: gated by `protect_keys_and_aegn`.
pub const OP_VENDOR_SIGN: u8 = 0x41;

/// Password-manager / local vault opcodes (0x43..0x47, device-only:
/// binding -> UP -> PIN -> 60 s window). Hold secrets, so they share the
/// `protect_keys_and_aegn` gate with on-device keys.
pub const OP_PM_PUT: u8 = 0x43;
pub const OP_PM_GET: u8 = 0x44;
pub const OP_PM_LIST: u8 = 0x45;
pub const OP_PM_DELETE: u8 = 0x46;
pub const OP_PM_STATUS: u8 = 0x47;

/// Wallet-compat reservation (F1/F6: DERIVE/XPUB/PSBT + PENDING preview).
/// Custody ops: always require an Unlocked session, like 0x35..0x37.
pub const OP_WALLET_DERIVE: u8 = 0x48;
pub const OP_WALLET_XPUB: u8 = 0x49;
pub const OP_WALLET_PSBT: u8 = 0x4A;
pub const OP_WALLET_PENDING: u8 = 0x4B;

pub const OP_SECURE_GUARD_STATUS: u8 = 0x3A;
pub const OP_SECURE_GUARD_UNLOCK: u8 = 0x3B;
pub const OP_SECURE_GUARD_LOCK: u8 = 0x3C;
pub const OP_SECURE_GUARD_CONFIG: u8 = 0x3D;
pub const OP_SECURE_GUARD_WIPE_SELECTIVE: u8 = 0x3E;

/// Scope of data erasure when wiping after failure or administrative command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureGuardWipeScope {
    /// Wipes only protected resources (Wallets and protected Vault/Key slots).
    /// NEVER touches or invalidates FIDO2/WebAuthn credentials!
    ProtectedResourcesOnly,
    /// Erases all stored credentials including FIDO2 passkeys (only if explicitly configured).
    AllCredentials,
}

/// Administrative sub-operations within the Secure Guard opcode range (0x3A..0x3E).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureGuardAdminOp {
    /// Query Secure Guard status, retry counts, and lock state (0x3A).
    Status,
    /// Submit PIN to unlock session (0x3B).
    Unlock,
    /// Explicitly terminate active session and lock (0x3C).
    Lock,
    /// Read or write policy configuration (0x3D).
    Config,
    /// Selective or scoped wipe command (0x3E).
    Wipe,
    /// Other vendor administrative opcode.
    Other(u8),
}

/// Classification of system operations for access control gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedResourceClass {
    /// FIDO2 / CTAP standard operations:
    /// MakeCredential, GetAssertion, GetInfo, ClientPin, Reset, Selection.
    ///
    /// ALWAYS ALLOWED by Secure Guard: will NEVER be blocked by PIN lock, rate-limit,
    /// or recovery state.
    FidoStandardFlow,
    /// Cryptographic wallet operations (0x35 OP_WALLET_GEN, 0x36 OP_WALLET_LIST, 0x37 OP_WALLET_ADDR).
    /// Always requires SecureGuardState::Unlocked by default.
    CryptoWalletOperation,
    /// On-device key management & AEGN envelope export/import (0x20..0x23).
    /// Gated based on `policy.protect_keys_and_aegn` (default true).
    ProtectedKeyOperation,
    /// OATH/TOTP operations (0x24..0x27).
    /// Gated based on `policy.protect_oath` (default false).
    OathTotpOperation,
    /// Internal Secure Guard admin operations (0x3A..0x3E).
    SecureGuardAdmin(SecureGuardAdminOp),
    /// Unclassified vendor opcode.
    Unknown(u8),
}

impl ProtectedResourceClass {
    /// Maps a wire vendor opcode byte to its `ProtectedResourceClass`.
    ///
    /// Canonical gate parity with the transport funnels (serial
    /// `dispatch_serial_vendor_msg`, BLE `ble_dispatch_complete`): every op
    /// the funnels barrier-check shares the class below, so Locked denies
    /// fail-closed on both transports. `Unknown` opcodes never require
    /// unlock: read-only advertisement (`0x38` fw-log, `0x3F` GET_CAPS),
    /// management with a dedicated funnel gate (PIN-session-OR-SG:
    /// `0x40` SET_UP_POLICY, `0x42` BLE OOB), OTA `0x30..0x34`, and
    /// reserved/rescue bytes (`0x2E`/`0x2F`) keep their own rules.
    pub fn from_vendor_opcode(opcode: u8) -> Self {
        match opcode {
            OP_WALLET_GEN | OP_WALLET_LIST | OP_WALLET_ADDR | OP_WALLET_DERIVE | OP_WALLET_XPUB
            | OP_WALLET_PSBT | OP_WALLET_PENDING => Self::CryptoWalletOperation,
            OP_KEY_GEN_ONDEVICE
            | OP_KEY_IMPORT_ENVELOPE
            | OP_KEY_LIST
            | OP_KEY_DELETE
            | OP_PIV_ENROLL
            | OP_VENDOR_SIGN
            | OP_PM_PUT
            | OP_PM_GET
            | OP_PM_LIST
            | OP_PM_DELETE
            | OP_PM_STATUS => Self::ProtectedKeyOperation,
            OP_OATH_PUT | OP_OATH_LIST | OP_OATH_CODE | OP_OATH_DELETE => Self::OathTotpOperation,
            OP_SECURE_GUARD_STATUS => Self::SecureGuardAdmin(SecureGuardAdminOp::Status),
            OP_SECURE_GUARD_UNLOCK => Self::SecureGuardAdmin(SecureGuardAdminOp::Unlock),
            OP_SECURE_GUARD_LOCK => Self::SecureGuardAdmin(SecureGuardAdminOp::Lock),
            OP_SECURE_GUARD_CONFIG => Self::SecureGuardAdmin(SecureGuardAdminOp::Config),
            OP_SECURE_GUARD_WIPE_SELECTIVE => Self::SecureGuardAdmin(SecureGuardAdminOp::Wipe),
            other => Self::Unknown(other),
        }
    }

    /// Evaluates whether this resource requires Secure Guard to be in `Unlocked` state.
    pub fn requires_unlock(&self, policy: &SecureGuardPolicy) -> bool {
        match self {
            Self::FidoStandardFlow => false,
            Self::CryptoWalletOperation => true,
            Self::ProtectedKeyOperation => policy.protect_keys_and_aegn,
            Self::OathTotpOperation => policy.protect_oath,
            Self::SecureGuardAdmin(admin_op) => match admin_op {
                SecureGuardAdminOp::Status => false,
                SecureGuardAdminOp::Unlock => false,
                SecureGuardAdminOp::Lock => false,
                SecureGuardAdminOp::Config => true,
                SecureGuardAdminOp::Wipe => true,
                SecureGuardAdminOp::Other(_) => true,
            },
            Self::Unknown(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fido_standard_never_requires_unlock() {
        let policy = SecureGuardPolicy::default();
        assert!(!ProtectedResourceClass::FidoStandardFlow.requires_unlock(&policy));
    }

    #[test]
    fn test_wallet_always_requires_unlock() {
        let policy = SecureGuardPolicy::default();
        assert!(ProtectedResourceClass::CryptoWalletOperation.requires_unlock(&policy));

        for op in [
            OP_WALLET_GEN,
            OP_WALLET_LIST,
            OP_WALLET_ADDR,
            OP_WALLET_DERIVE,
            OP_WALLET_XPUB,
            OP_WALLET_PSBT,
            OP_WALLET_PENDING,
        ] {
            let res = ProtectedResourceClass::from_vendor_opcode(op);
            assert_eq!(res, ProtectedResourceClass::CryptoWalletOperation);
            assert!(res.requires_unlock(&policy));
        }
    }

    #[test]
    fn test_protected_keys_policy_gating() {
        let mut policy = SecureGuardPolicy {
            protect_keys_and_aegn: true,
            ..Default::default()
        };
        let res = ProtectedResourceClass::from_vendor_opcode(OP_KEY_GEN_ONDEVICE);
        assert!(ProtectedResourceClass::from_vendor_opcode(OP_PIV_ENROLL).requires_unlock(&policy));
        assert!(res.requires_unlock(&policy));
        // VENDOR_SIGN (0x41) is GEN-class: same gate as 0x20, never weaker.
        assert_eq!(
            ProtectedResourceClass::from_vendor_opcode(OP_VENDOR_SIGN),
            ProtectedResourceClass::ProtectedKeyOperation
        );
        assert!(ProtectedResourceClass::from_vendor_opcode(OP_VENDOR_SIGN).requires_unlock(&policy));
        // PM vault ops (0x43..0x47) hold secrets: same key-protection gate.
        for op in [OP_PM_PUT, OP_PM_GET, OP_PM_LIST, OP_PM_DELETE, OP_PM_STATUS] {
            let res = ProtectedResourceClass::from_vendor_opcode(op);
            assert_eq!(res, ProtectedResourceClass::ProtectedKeyOperation);
            assert!(res.requires_unlock(&policy));
        }

        policy.protect_keys_and_aegn = false;
        assert!(!res.requires_unlock(&policy));
        assert!(
            !ProtectedResourceClass::from_vendor_opcode(OP_VENDOR_SIGN).requires_unlock(&policy)
        );
    }

    #[test]
    fn test_oath_policy_gating() {
        let mut policy = SecureGuardPolicy {
            protect_oath: false,
            ..Default::default()
        };
        let res = ProtectedResourceClass::from_vendor_opcode(OP_OATH_CODE);
        assert!(!res.requires_unlock(&policy));

        policy.protect_oath = true;
        assert!(res.requires_unlock(&policy));
    }

    #[test]
    fn test_admin_unlock_and_status_allowed_locked() {
        let policy = SecureGuardPolicy::default();
        let status = ProtectedResourceClass::from_vendor_opcode(OP_SECURE_GUARD_STATUS);
        assert!(!status.requires_unlock(&policy));

        let unlock = ProtectedResourceClass::from_vendor_opcode(OP_SECURE_GUARD_UNLOCK);
        assert!(!unlock.requires_unlock(&policy));

        let config = ProtectedResourceClass::from_vendor_opcode(OP_SECURE_GUARD_CONFIG);
        assert!(config.requires_unlock(&policy));
    }

    #[test]
    fn test_readonly_and_dedicated_gates_never_require_unlock() {
        let policy = SecureGuardPolicy::default();
        // Read-only, no secrets: fw-log + capability advertisement.
        assert!(!ProtectedResourceClass::from_vendor_opcode(0x38).requires_unlock(&policy));
        assert!(!ProtectedResourceClass::from_vendor_opcode(0x3F).requires_unlock(&policy));
        // Dedicated funnel gates (PIN-session-OR-SG, enforced in the funnel,
        // not the barrier): SET_UP_POLICY + BLE OOB stay Unknown.
        assert_eq!(
            ProtectedResourceClass::from_vendor_opcode(0x40),
            ProtectedResourceClass::Unknown(0x40)
        );
        assert_eq!(
            ProtectedResourceClass::from_vendor_opcode(0x42),
            ProtectedResourceClass::Unknown(0x42)
        );
        // Reserved / transient bytes keep their own rules, never the barrier.
        for op in [0x2Eu8, 0x2F, 0x30, 0x34] {
            assert!(!ProtectedResourceClass::from_vendor_opcode(op).requires_unlock(&policy));
        }
    }
}
