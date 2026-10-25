//! Resource Classification and Authorization Gate
//!
//! Categorizes operations and provides enforcement barriers for sensitive cryptographic
//! assets (Wallets, On-Device Keys, OATH) while guaranteeing unrestricted passkey access.

use super::policy::SecureGuardPolicy;

// Vendor Opcode Constants (0x20..0x3E)
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
    pub fn from_vendor_opcode(opcode: u8) -> Self {
        match opcode {
            OP_WALLET_GEN | OP_WALLET_LIST | OP_WALLET_ADDR => Self::CryptoWalletOperation,
            OP_KEY_GEN_ONDEVICE | OP_KEY_IMPORT_ENVELOPE | OP_KEY_LIST | OP_KEY_DELETE => {
                Self::ProtectedKeyOperation
            }
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

        for op in [OP_WALLET_GEN, OP_WALLET_LIST, OP_WALLET_ADDR] {
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
        assert!(res.requires_unlock(&policy));

        policy.protect_keys_and_aegn = false;
        assert!(!res.requires_unlock(&policy));
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
}
