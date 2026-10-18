//! AegisKey USB Protocol & Frame Handling
//! 100% Native Rust Implementation for CTAPHID, CCID, Keyboard, WinUSB

pub mod ctaphid;
pub mod ccid;
pub mod keyboard;
pub mod winusb;

pub use ctaphid::{CtapHidError, CtapHidFramer, CtapHidManager, CtapHidMessage};
pub use ccid::{CcidApduHandler, CcidTransport, CommandApdu, ResponseApdu};
pub use keyboard::{KeyboardReport, OtpTyper};
pub use winusb::{WinUsbDeframer, WinUsbMessage};
