//! Legacy serial Secure Guard dispatch (parity with freertos).
//!
//! Move-only reuse of [`crate::secure_guard_exec::exec_secure_guard_op`]:
//! same opcodes `0x3A..=0x3E`, same `(status, body)` responses, same gates
//! as [`crate::freertos_route::dispatch_serial_vendor_msg`]. No new protocol.
//!
//! The legacy serial loop (`run_loop_legacy`, section D) had no `0x3A..0x3E`
//! branch; the freertos dispatcher has it. This module is the single shared
//! tail so host tests can prove byte parity without hardware.
//!
//! Thin shim: logic lives in `sg_exec`, shared test context in
//! `sg_test_ctx`, parity tests in `sg_parity_tests`. All public paths are
//! re-exported below.

pub(crate) mod sg_exec;
#[cfg(test)]
mod sg_parity_tests;
#[cfg(test)]
mod sg_test_ctx;

#[cfg_attr(not(target_os = "espidf"), allow(unused_imports))]
pub(crate) use self::sg_exec::*;
