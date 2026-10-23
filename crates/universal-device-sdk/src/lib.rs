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
mod error;
#[cfg(feature = "hardwallet")]
pub mod hardwallet;
mod request;
mod response;
#[cfg(feature = "secmon")]
pub mod secmon;
mod status;
#[cfg(feature = "test-mode")]
pub mod test_hooks;

pub use auth::AuthContext;
pub use capabilities::{capabilities, CapabilitySet};
pub use error::{require_fido, require_hardwallet, require_secmon, require_test_mode, SdkError};
#[cfg(feature = "hardwallet")]
pub use hardwallet::{AddressRequest, CoinKind};
pub use request::{
    BindingOp, BindingRequest, FidoRequest, SdkRequest, SystemOp, SystemRequest, VendorRequest,
    WalletRequest, WALLET_OP_ADDR, WALLET_OP_GEN, WALLET_OP_LIST,
};
pub use response::SdkResponse;
#[cfg(feature = "secmon")]
pub use secmon::{
    ClockState, CoexState, CounterState, DenyReason, LockdownPolicy, PairingWindow, PinSession,
    PolicyContext, PolicyDecision, PolicyGate, PolicyOpClass, PolicyOutcome, SecurityHeartbeat,
    SecurityStatus, StoreIntegrity, TamperEvent, Transport,
};
pub use status::{
    STATUS_BAD_ENVELOPE, STATUS_NEED_BINDING, STATUS_NEED_PIN, STATUS_NEED_UP, STATUS_NO_SLOT,
    STATUS_OK,
};
#[cfg(feature = "test-mode")]
pub use test_hooks::TestHookId;
