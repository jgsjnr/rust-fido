//! Wave4 -- GATT 0xFFFD (casca fina de compat; ver `ble`).
//!
//! Conteudo movido para `ble::gatt_core` + `ble::dispatch_bind`
//! sem mudanca de comportamento. Testes `gatt_tests` ficam em
//! `ble_gatt/gatt_tests.rs`.
pub use crate::ble::dispatch_bind::*;
pub use crate::ble::gatt_core::*;

#[cfg(test)]
mod gatt_tests;
