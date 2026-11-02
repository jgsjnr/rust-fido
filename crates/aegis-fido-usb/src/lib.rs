//! AegisKey USB Protocol & Frame Handling
//! 100% Native Rust Implementation for CTAPHID, CCID, Keyboard, WinUSB
//!
//! `no_std`-friendly: with default features (`std`) this crate links `std`
//! like before (zero breakage). With `--no-default-features` it builds as
//! `no_std` + `alloc` (heap types only: `Vec`, no OS, no I/O). The only
//! OS-backed item is the PIV salt RNG (`getrandom::SysRng`, feature
//! `getrandom`, on by default via `std`); bare-metal/ESP32 targets without
//! an OS RNG must seed explicitly via `provision_pin_with_rng` (see the
//! `getrandom` feature docs in `Cargo.toml`).

#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

pub mod ccid;
pub mod ccid_parse;
pub mod ctaphid;
pub mod kbd_gate;
pub mod keyboard;
pub mod piv;
pub mod transport;
pub mod winusb;

pub use ccid::{CcidApduHandler, CcidTransport, CommandApdu, ResponseApdu};
pub use ctaphid::{CtapHidError, CtapHidFramer, CtapHidManager, CtapHidMessage};
pub use keyboard::{KeyboardReport, OtpTyper};
pub use piv::PivApplet;
pub use transport::Transport;
pub use winusb::{WinUsbDeframer, WinUsbMessage};
