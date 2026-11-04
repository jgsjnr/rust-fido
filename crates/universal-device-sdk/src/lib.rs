//! Universal Device SDK — facade-first typed surface (REGRAS R3/R4/R5/R12).
//!
//! - Consumers talk to the device only through these types; the transport
//!   (`uniffi-bridge`) stays a pure passthrough (R3).
//! - Wire statuses preserve §9.5 (`0x00`/`0x01`/`0x02`/`0x05`, see `status`).
//! - Fail-closed order (`binding -> UP -> PIN`) is *data* here
//!   (`AuthContext`); enforcement lives in firmware gates, never in this
//!   crate (R5).
//! - Every capability sits behind a Cargo feature with a stable stub API
//!   when off: off yields `SdkError::NotCompiled`, never `todo!()`,
//!   never a broken build (R12).
//! - Continuous security monitor (`secmon` feature): types/gates only
//!   (`SecurityStatus`, `TamperEvent`, `LockdownPolicy`, heartbeat,
//!   `policy_check(op, ctx)` contract via `PolicyGate`); enforcement and
//!   isolated task wiring (dedicated core, TWDT, HIL) land in T8/T12/T13.
//! - Zero business logic: only types plus `NotCompiled` mapping via `cfg`.
//! - Lab test hooks (`test-mode` feature, never in `default`, never in
//!   release): `TestHookId` mirrors firmware `TEST_COMMANDS` 1:1;
//!   no firmware behavior lives here.
//!
//! `no_std` + `alloc` only; no `std`, no `esp-idf`. Hash crates used for
//! address derivation are optional (feature `hardwallet`) and re-exported
//! here — this crate never depends on `aegis-fido-core`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod auth;
mod capabilities;
pub mod clear_signing;
pub mod ctap21;
mod envelope;
mod error;
#[cfg(feature = "hardwallet")]
pub mod hardwallet;
#[cfg(feature = "pm")]
pub mod pm;
mod providers;
mod request;
mod response;
#[cfg(feature = "secmon")]
pub mod secmon;
pub mod secure_channel;
pub mod secure_guard;
pub mod shamir;
mod status;
#[cfg(feature = "test-mode")]
pub mod test_hooks;

pub use auth::AuthContext;
pub use capabilities::{capabilities, CapabilitySet};
pub use clear_signing::{
    decode_clear_sign_summary, decode_oled_preview, encode_clear_sign_summary, encode_oled_preview,
    ClearSignSummaryDto, OledPreviewDto,
};
pub use ctap21::{
    decode_hmac_secret_request, decode_hmac_secret_response, encode_hmac_secret_request,
    encode_hmac_secret_response, HmacSecretRequestDto, HmacSecretResponseDto, LargeBlobEntryDto,
    LargeBlobStoreStatusDto,
};
pub use envelope::{
    check_envelope_auth, open_envelope, seal_envelope, EnvelopeError, OpenedEnvelope, ReplayWindow,
    SealParams, ENVELOPE_MAGIC, ENVELOPE_VERSION, HEADER_LEN, MAX_CIPHERTEXT_BYTES,
    MAX_ENVELOPE_BYTES, MAX_PLAINTEXT_BYTES, MIN_ENVELOPE_LEN, NONCE_LEN, REPLAY_WINDOW_CAP,
    TAG_LEN,
};
pub use error::{require_fido, require_hardwallet, require_pm, require_secmon, require_test_mode, SdkError};
#[cfg(feature = "hardwallet")]
pub use hardwallet::{AddressRequest, CoinKind};
#[cfg(feature = "pm")]
pub use pm::{
    decode_pm_delete_request, decode_pm_get_request, decode_pm_list_request, decode_pm_list_response,
    decode_pm_put_request, decode_pm_release_response, decode_pm_status_response,
    encode_pm_delete_request, encode_pm_get_request, encode_pm_list_request, encode_pm_list_response,
    encode_pm_put_request, encode_pm_release_response, encode_pm_status_response, PmDeleteRequestDto,
    PmGetRequestDto, PmListRequestDto, PmListResponseDto, PmOp, PmPutRequestDto, PmReleaseResponseDto,
    PmRequest, PmStatus, PmStatusDto, OP_PM_DELETE, OP_PM_GET, OP_PM_LIST, OP_PM_PUT, OP_PM_STATUS,
    PM_ID_MAX_BYTES, PM_LABEL_MAX_BYTES, PM_LIST_DEFAULT_LIMIT, PM_OP_MAX, PM_OP_MIN,
    PM_SECRET_MAX_BYTES, PM_URL_MAX_BYTES, PM_USERNAME_MAX_BYTES,
};
pub use providers::{
    AuditProvider, BackupProvider, OathProvider, OtaProvider, OtpProvider, PivProvider,
    PolicyProvider, ProximityProvider, RescueProvider, WalletProvider,
};
pub use request::{
    AuditRequest, BackupRequest, BindingOp, BindingRequest, FidoRequest, OathRequest, OtaRequest,
    OtpRequest, PivRequest, PolicyRequest, ProximityRequest, RescueRequest, SdkRequest, SystemOp,
    SystemRequest, VendorRequest, WalletRequest, WalletSignRequest, WALLET_OP_ADDR, WALLET_OP_GEN,
    WALLET_OP_LIST,
};
pub use response::SdkResponse;
#[cfg(feature = "secmon")]
pub use secmon::{
    ClockState, CoexState, CounterState, DenyReason, LockdownPolicy, PairingWindow, PinSession,
    PolicyContext, PolicyDecision, PolicyGate, PolicyOpClass, PolicyOutcome, SecurityHeartbeat,
    SecurityStatus, StoreIntegrity, TamperEvent, Transport,
};
pub use secure_channel::{
    decode_encrypted_pin_payload, decode_secure_channel_key_exchange, encode_encrypted_pin_payload,
    encode_secure_channel_key_exchange, EncryptedPinPayloadDto, SecureChannelKeyExchangeDto,
};
pub use secure_guard::{
    decode_secure_guard_change_pin_response, decode_secure_guard_config_response,
    decode_secure_guard_lock_response, decode_secure_guard_provision_response,
    decode_secure_guard_recover_response, decode_secure_guard_status_response,
    decode_secure_guard_unlock_response, decode_secure_guard_wipe_response,
    encode_secure_guard_change_pin_request, encode_secure_guard_config_request,
    encode_secure_guard_config_request_with_pin, encode_secure_guard_lock_request,
    encode_secure_guard_provision_request, encode_secure_guard_recover_request,
    encode_secure_guard_status_request, encode_secure_guard_unlock_request,
    encode_secure_guard_wipe_request, encode_secure_guard_wipe_request_with_pin,
    state_name_from_code, SecureGuardChangePinResultDto, SecureGuardLockResultDto,
    SecureGuardPolicyDto, SecureGuardProvisionResultDto, SecureGuardRecoverResultDto,
    SecureGuardStatusDto, SecureGuardUnlockResultDto, SecureGuardWipeResultDto,
    OP_SECURE_GUARD_CONFIG, OP_SECURE_GUARD_LOCK, OP_SECURE_GUARD_STATUS, OP_SECURE_GUARD_UNLOCK,
    OP_SECURE_GUARD_WIPE_SELECTIVE, STATE_AUTHENTICATING, STATE_ERROR_LOCKED, STATE_LOCKED,
    STATE_PROVISIONING, STATE_RATE_LIMITED, STATE_RECOVERY_REQUIRED, STATE_UNLOCKED,
    STATE_UNPROVISIONED, STATE_WIPE_IN_PROGRESS, STATE_WIPE_PENDING,
};
pub use shamir::{
    decode_shamir_recover_request, decode_shamir_split_response, encode_shamir_recover_request,
    encode_shamir_split_response, DsHmacSeedEnvelopeDto, ShamirRecoverRequestDto,
    ShamirRecoverResponseDto, ShamirShareDto, ShamirSplitRequestDto, ShamirSplitResponseDto,
};
pub use status::{
    STATUS_BAD_ENVELOPE, STATUS_NEED_BINDING, STATUS_NEED_PIN, STATUS_NEED_UP, STATUS_NO_SLOT,
    STATUS_OK,
};
#[cfg(feature = "test-mode")]
pub use test_hooks::TestHookId;
