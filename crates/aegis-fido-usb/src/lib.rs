//! AegisKey USB Protocol & Frame Handling
//! 100% Native Rust Implementation for CTAPHID, CCID, Keyboard, WinUSB

pub mod ccid;
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
