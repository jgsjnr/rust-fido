//! PM dispatch `0x43..=0x47` (F-PM2 firmware side) — facade.
//!
//! Split for dep-track (god-file 26.49, ~999 lines -> cohesion modules,
//! no behavior change):
//! - [`crate::pm_cbor`]: CBOR wire mirrors (decode/encode + field caps).
//! - [`crate::pm_gate`]: key/token constants + gate bridge + wire mapping.
//! - [`crate::pm_exec`]: persistence + dispatch core (single choke point).
//! - `pm_tests.rs` (`#[cfg(test)]`, via `pm_exec`): dispatch tests.
//!
//! This facade re-exports the pre-split public surface so every transport
//! (`ble_dispatch`, `serial_vendor`, integration tests) keeps compiling
//! unchanged: [`dispatch_pm_op`], [`dispatch_pm_op_persist`],
//! [`pm_vault_load`], [`pm_vault_save`], [`PM_VAULT_MASTER_KEY`],
//! [`PM_SEAL_PIN_TOKEN`].
//!
//! Diet: this module only exists outside the capability presets
//! (`cap-fido-only` / `cap-fido-totp`); inside the diet every PM op answers
//! `UNSUPPORTED_FEATURE` (`0x06`) at the funnels, never routed here.

pub use crate::pm_exec::{dispatch_pm_op, dispatch_pm_op_persist, pm_vault_load, pm_vault_save};
pub use crate::pm_gate::{PM_SEAL_PIN_TOKEN, PM_VAULT_MASTER_KEY};
