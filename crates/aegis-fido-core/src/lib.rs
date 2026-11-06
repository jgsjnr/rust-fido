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
pub use aegis_secure_guard as secure_guard;
pub use aegis_secure_guard::*;
pub mod vault;
pub mod wallet;

pub use ctap::{
    CredRandomMaterial, Ctap21ExtensionError, CtapEngine, HmacSecretExtension, HmacSecretOutput,
    LargeBlobEntry, LargeBlobStore, DEFAULT_LARGE_BLOB_CAPACITY, LARGE_BLOB_TAG_LEN,
};
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
pub use vault::AegisVault;
pub use wallet::{
    base58check_encode, decode_extended_key, parse_bitcoin_tx, parse_ethereum_tx, parse_solana_tx,
    recover_secret_from_2_shares, split_secret_2_of_3, wallet_account_path, wallet_address_path,
    xpub_at_account, xpub_at_path, ChildNumber, ClearSignError, ClearSignTransactionSummary,
    DecodedExtendedKey, DerivationPath, DsHmacSeedEnvelope, ExtendedPrivateKey, ExtendedPublicKey,
    HdError, OledFrame128x64, ShamirError, ShamirShare, WalletStore, COIN_TYPE_BITCOIN,
    COIN_TYPE_EVM, EXTENDED_KEY_LEN, EXTENDED_KEY_STRLEN, HARDENED_OFFSET, MAX_PATH_DEPTH,
    MAX_SEED_LEN, MIN_SEED_LEN, PURPOSE_BIP44, PURPOSE_BIP84, XPRV_VERSION, XPUB_VERSION,
};
