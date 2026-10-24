//! Provider contracts for the Phase 0 families (R12 facade, no firmware).
//!
//! One trait per family, one file per trait: changing a family's contract
//! touches only its own file (ATOMIC). Each trait names the firmware object
//! that executes one typed request family and returns a typed `SdkResponse`.
//! Traits only: no default body, no business logic, no success synthesis.
//! Firmware (or a later phase) implements them; when a family is compiled
//! off, the honest outcome is `SdkError::NotCompiled` via the matching
//! `require_*` gate (see `error` and `SdkRequest::check_compiled`), never
//! a faked `Ok`.
//!
//! Mapping (`request` -> trait -> gate): `OtaRequest` -> `OtaProvider`
//! (`ota`), `PivRequest` -> `PivProvider` (`piv`), `OtpRequest` ->
//! `OtpProvider` (`otp`), `ProximityRequest` -> `ProximityProvider`
//! (`proximity`), `RescueRequest` -> `RescueProvider` (`otp`, transport
//! `0x2E`), `WalletRequest`/`WalletSignRequest` -> `WalletProvider`
//! (`hardwallet`), `OathRequest` -> `OathProvider` (`oath`),
//! `BackupRequest` -> `BackupProvider` (`backup`), `AuditRequest` ->
//! `AuditProvider` (`audit`), `PolicyRequest` -> `PolicyProvider`
//! (`policy`).
//!
//! `no_std` + `alloc` only; no `std`, no `esp-idf`, no `unsafe`, no JSON.

mod audit;
mod backup;
mod oath;
mod ota;
mod otp;
mod piv;
mod policy;
mod proximity;
mod rescue;
mod wallet;

pub use audit::AuditProvider;
pub use backup::BackupProvider;
pub use oath::OathProvider;
pub use ota::OtaProvider;
pub use otp::OtpProvider;
pub use piv::PivProvider;
pub use policy::PolicyProvider;
pub use proximity::ProximityProvider;
pub use rescue::RescueProvider;
pub use wallet::WalletProvider;
