//! `aegis-pm-vault` — device-only password-manager vault (F-PM1).
//!
//! Lane ownership: this crate is the SOLE writer for password-manager record
//! types, PM policy/gates, the [`PmStore`] persistence abstraction, and the
//! PM-domain Shamir backup helpers. It never touches eFuse, Secure Boot, or
//! flash encryption (see REGRA PRINCIPAL Nº1 below).
//!
//! # Contract (F-PM1)
//!
//! - **Zero persistence on the phone by construction.** The API only exposes
//!   opaque AEAD blobs ([`PmVault::seal_to_blob`] / [`PmVault::load_from_blob`])
//!   plus punctual, gate-checked field release ([`PmVault::release_password`]).
//!   No plaintext record, share, or master key ever crosses the FFI/JNI edge.
//! - **AEGN v1 envelope is never modified.** Sealing reuses
//!   `aegis_fido_core::vault::AegisVault::seal_envelope` / `open_envelope`
//!   (magic `AEGN`, version `0x01`, 12-byte nonce). New record kinds enter as
//!   CBOR payload variants ([`PmRecord`]), never as envelope changes.
//! - **Fail-closed gates.** Every read/release/seal path takes a
//!   [`PmGateState`] and a [`PmPolicy`]: no binding → [`PmError::NeedBinding`],
//!   no presence → [`PmError::PresenceRequired`], no PIN → [`PmError::PinRequired`],
//!   binding window (60 s) elapsed → [`PmError::BindingWindowExpired`].
//! - **No secret logging.** [`PasswordEntry`] and [`PmShare`] have redacted
//!   `Debug` impls; labels/usernames/passwords/shares never appear in logs.
//!
//! > REGRA PRINCIPAL Nº1 — INVIOLÁVEL: nenhum código aqui queima eFuse
//! > (BLOCK7/BLOCK8, SECURE_VERSION, anti-rollback), ativa Secure Boot /
//! > flash encryption, ou expõe bypass em build release. `TEST_*` só existe sob
//! > a feature `test-mode` (que nesta crate não expõe nenhum helper de bypass).
//!
//! # SOLID mapping
//!
//! - SRP: `entry` owns record shapes, `policy` owns quota/gates, `store` owns
//!   the vault engine + persistence abstraction, `backup` owns Shamir domain
//!   separation.
//! - OCP: new record kinds arrive as new [`PmRecord`] variants; the envelope
//!   and the [`PmStore`] trait are untouched.
//! - DIP: firmware persistence is behind the [`PmStore`] trait (opaque blobs
//!   only); the phone is treated as a blind transport of those blobs.

#![no_std]
extern crate alloc;

pub mod backup;
pub mod entry;
pub mod policy;
pub mod store;

pub use backup::{recover_pm_master, split_pm_master, PmShare, PM_SHARE_DOMAIN};
pub use entry::{PasswordEntry, PmRecord, PM_PAYLOAD_VERSION};
pub use policy::{PmError, PmGateState, PmPolicy};
pub use store::{PmStore, PmVault};
