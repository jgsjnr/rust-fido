//! Serial CTAPHID byte source/sink (D2 split from `run`, single owner).
//!
//! UART 115200 shims over the FFI declared in `super` (run): Classic
//! reuses the UART-backed `aegis_usb_*` transport; S3/S2 use
//! `aegis_serial_*` on UART0 alongside native USB-OTG.
//!
//! Contract (R15/R16): move-only; cfgs preserved byte-for-byte
//! (espidf / board-ttgo-classic / test-mode); fail-closed bool/u16.
#[cfg(target_os = "espidf")]
use aegis_fido_usb::ctaphid::PACKET_SIZE;

/// Serial CTAPHID byte source/sink (UART 115200).
///
/// Classic (single serial port): the UART-backed `aegis_usb_*` transport IS
/// the serial link. S3/S2: `aegis_serial_*` on the UART0 diagnostic channel,
/// alongside native USB-OTG (whose section below stays untouched).
#[cfg(target_os = "espidf")]
pub(crate) fn serial_pop_packet(out: &mut [u8; PACKET_SIZE]) -> u16 {
    #[cfg(feature = "board-ttgo-classic")]
    unsafe {
        super::aegis_usb_pop_packet(out.as_mut_ptr(), PACKET_SIZE as u16)
    }
    #[cfg(not(feature = "board-ttgo-classic"))]
    unsafe {
        super::aegis_serial_pop_packet(out.as_mut_ptr(), PACKET_SIZE as u16)
    }
}

/// Sends raw bytes over the serial link (64B CTAPHID packets or dump text).
#[cfg(target_os = "espidf")]
pub(crate) fn serial_send_bytes(packet: *const u8, len: u16) -> bool {
    #[cfg(feature = "board-ttgo-classic")]
    unsafe {
        super::aegis_usb_send_report(packet, len)
    }
    #[cfg(not(feature = "board-ttgo-classic"))]
    unsafe {
        super::aegis_serial_send_report(packet, len)
    }
}

/// Non-blocking diagnostic text read.
///
/// Yields bytes ONLY while fewer than 64 are buffered, so a 64-byte CTAPHID
/// packet is never split by the dump path: binary bursts always win the wire.
/// Diagnostic-idle use (TEST_LIFETIME_DUMP with test-mode).
#[cfg(all(target_os = "espidf", feature = "test-mode"))]
pub(crate) fn serial_read_chunk(out: &mut [u8], max_len: u16) -> u16 {
    #[cfg(feature = "board-ttgo-classic")]
    unsafe {
        super::aegis_usb_read_chunk(out.as_mut_ptr(), max_len)
    }
    #[cfg(not(feature = "board-ttgo-classic"))]
    unsafe {
        super::aegis_serial_read_chunk(out.as_mut_ptr(), max_len)
    }
}
