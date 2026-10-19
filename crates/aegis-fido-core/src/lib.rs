//! AegisKey FIDO2 / CTAP 2.3 Core Protocol Engine
//! 100% Native Rust Implementation for ESP32-S3

extern crate alloc;

pub mod lifetime;
pub mod ctap;
pub mod crypto;
pub mod oath;
pub mod otp;
pub mod vault;
pub mod credential;
pub mod extensions;
pub mod policy;

pub use ctap::CtapEngine;
pub use vault::AegisVault;
pub use policy::{PolicyError, UpAndPin, UpOnly, UpPolicy};
pub use lifetime::{LifetimeCategory, LifetimeEvent, LifetimeSnapshot, record, snapshot, write_dump};
