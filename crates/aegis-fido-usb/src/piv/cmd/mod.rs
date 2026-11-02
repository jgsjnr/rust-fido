//! PIV command groups (move-only split of `piv_cmd`; no behavior change).
//!
//! - `parse`: INS/P2 vocabulary, limits/slots/NVS keys, `PivSlot`, lab fixtures.
//! - `auth`: PIN/PUK validation, provisioning, salted hashes (SHA-256, ct-eq).
//! - `admin`: `PivRecordStore` / `PivKeyBackend` contracts, `NoBackend`, errors.
//!
//! `super::piv_cmd` re-exports everything below; `crate::piv::*` paths unchanged.

pub mod admin;
pub mod auth;
pub mod parse;

pub use admin::*;
pub use auth::*;
pub use parse::*;
