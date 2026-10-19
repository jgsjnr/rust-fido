//! AegisKey USB Protocol & Frame Handling
//! 100% Native Rust Implementation for CTAPHID, CCID, Keyboard, WinUSB

pub mod ctaphid;
pub mod transport;
pub mod ccid;
pub mod piv;
pub mod keyboard;
pub mod winusb;

pub use ctaphid::{CtapHidError, CtapHidFramer, CtapHidManager, CtapHidMessage};
pub use transport::Transport;
pub use ccid::{CcidApduHandler, CcidTransport, CommandApdu, ResponseApdu};
pub use piv::PivApplet;
pub use keyboard::{KeyboardReport, OtpTyper};
pub use winusb::{WinUsbDeframer, WinUsbMessage};

