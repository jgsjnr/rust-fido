//! AegisKey FIDO2 / CTAP 2.3 Core Protocol Engine
//! 100% Native Rust Implementation for ESP32-S3

extern crate alloc;

pub mod credential;
pub mod crypto;
pub mod ctap;
pub mod extensions;
pub mod lifetime;
pub mod oath;
pub mod otp;
pub mod policy;
pub mod secure_guard;
pub mod vault;
pub mod wallet;

pub use ctap::CtapEngine;
pub use lifetime::{
    record, snapshot, write_dump, LifetimeCategory, LifetimeEvent, LifetimeSnapshot,
};
pub use oath::tlv::{
    append_slot_label, find_tlv, is_vendor_op, is_wallet_tag, label_bytes, parse_tlv_records,
    single_byte, slot_id, write_tlv, TlvRecord, FW_LOG_OP, MAX_LABEL_BYTES, RESCUE_TRANSPORT_OP,
    TAG_ALG_HINT, TAG_LABEL, TAG_OATH_NAME, TAG_OATH_RESPONSE, TAG_SLOT, TAG_USAGE_HINT,
    TAG_WALLET_ADDRESS, TAG_WALLET_LABEL, TAG_WALLET_NETWORK, TAG_WALLET_SLOT, VENDOR_OP_MAX,
    VENDOR_OP_MIN,
};
pub use policy::{PolicyError, UpAndPin, UpOnly, UpPolicy};
pub use secure_guard::{
    ProtectedResourceClass, SecureGuardAdminOp, SecureGuardAuditEvent, SecureGuardAuditEventType,
    SecureGuardEngine, SecureGuardError, SecureGuardPersistentRecord, SecureGuardPolicy,
    SecureGuardState, SecureGuardWipeScope, MAX_ATTEMPTS,
};
pub use vault::AegisVault;
