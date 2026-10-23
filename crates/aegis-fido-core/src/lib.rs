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
pub mod vault;
pub mod wallet;

pub use ctap::CtapEngine;
pub use lifetime::{
    record, snapshot, write_dump, LifetimeCategory, LifetimeEvent, LifetimeSnapshot,
};
pub use policy::{PolicyError, UpAndPin, UpOnly, UpPolicy};
pub use vault::AegisVault;
