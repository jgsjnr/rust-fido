//! Serial CTAPHID dispatch (UART 115200).
//!
//! Routes 64-byte serial bytes into [`CtapHidManager`] / vendor dispatch with
//! the same gates the app simulator enforces host-side (pairing-mode + UP).
//!
//! - Framing is byte-identical to USB: INIT/CONT, CID, keepalive all reuse
//!   `CtapHidFramer` / `CtapHidManager::process_packet` (no protocol change).
//! - Heartbeat text stays outside the framing: [`is_text_line`] lets a
//!   shared-UART poll ignore log text without emitting CTAPHID errors and
//!   without breaking an active reassembly (the `unexpected continuation`
//!   seen on COM7/COM8 came from feeding heartbeat bytes to the deframer).
//! - Privileged ops (MakeCredential, ClientPIN set/change, vendor CONFIG
//!   `0x20/0x21/0x23/0x24/0x27`) require pairing-mode (hold 5s BOOT, 60s
//!   window). Denial answers CTAP2 `NOT_ALLOWED` (`0x30`) for CTAP commands
//!   and the `NEED_BINDING` (`0x05`) vendor status for vendor ops — wire
//!   statuses only, framing untouched.
//! - Vendor dispatch mirrors the BLE gates byte-for-byte
//!   ([`authorize_vendor_op`]); the on-device executor stays follow-up
//!   (status `0x04` on gate pass, exactly like BLE).
//! - `no_std` compatible (`alloc` only).

extern crate alloc;

use aegis_fido_core::ctap::cbor::{decode_cbor_map, get_int_field};
use aegis_fido_core::ctap::client_pin::{SUBCMD_CHANGE_PIN, SUBCMD_SET_PIN};
use aegis_fido_core::ctap::{
    CTAP_CMD_CLIENT_PIN, CTAP_CMD_GET_ASSERTION, CTAP_CMD_MAKE_CREDENTIAL, CTAP_CMD_RESET,
};
use aegis_fido_usb::ctaphid::{
    CtapHidError, CtapHidFramer, CtapHidManager, CtapHidMessage, CMD_CBOR, CMD_MSG, PACKET_SIZE,
};
use alloc::string::String;
use alloc::vec::Vec;

use crate::ble_gatt::{
    authorize_vendor_op, is_bind_mgmt_op, is_vendor_keys_oath_op, BleGattError, OP_KEY_DELETE,
    OP_KEY_GEN_ONDEVICE, OP_KEY_IMPORT_ENVELOPE, OP_OATH_DELETE, OP_OATH_PUT,
    VENDOR_STATUS_NEED_BINDING,
};

/// UART line rate for the serial CTAPHID link (8N1, same as the monitor).
pub const SERIAL_BAUD: u32 = 115_200;

/// Serial packet size: identical to USB CTAPHID (no protocol change).
pub const SERIAL_PACKET_SIZE: usize = PACKET_SIZE;

/// CTAP2 status answered when pairing-mode denies a serial CTAP command.
///
/// In-spec wire status only (`NOT_ALLOWED`); framing is untouched.
pub const SERIAL_DENY_CTAP_STATUS: u8 = 0x30;

/// `true` when a 64-byte UART chunk looks like log/heartbeat text.
///
/// A chunk is text when it holds at least one non-NUL byte and every non-NUL
/// byte is printable ASCII or tab/CR/LF. Binary CTAPHID packets carry CIDs,
/// lengths and CBOR/TLV bytes outside that range, so real packets never match;
/// a pathological all-printable packet would be ignored once (host retries).
pub fn is_text_line(raw: &[u8; PACKET_SIZE]) -> bool {
    let mut seen = false;
    for b in raw.iter() {
        if *b == 0x00 {
            continue;
        }
        seen = true;
        let text = matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E);
        if !text {
            return false;
        }
    }
    seen
}

/// `true` when a serial message is privileged and requires pairing-mode.
///
/// Mirrors the simulator `PRIVILEGED` set: MakeCredential, ClientPIN
/// set/change, vendor CONFIG ops. Everything else (GetInfo, GetAssertion,
/// ClientPIN reads, vendor USAGE, binding mgmt with its own gates) is false.
pub fn serial_requires_pairing(cmd: u8, payload: &[u8]) -> bool {
    if cmd == CMD_CBOR && !payload.is_empty() {
        match payload[0] {
            CTAP_CMD_MAKE_CREDENTIAL => return true,
            CTAP_CMD_CLIENT_PIN => return client_pin_write(payload),
            _ => return false,
        }
    }
    if cmd == CMD_MSG && !payload.is_empty() {
        return matches!(
            payload[0],
            OP_KEY_GEN_ONDEVICE
                | OP_KEY_IMPORT_ENVELOPE
                | OP_KEY_DELETE
                | OP_OATH_PUT
                | OP_OATH_DELETE
        );
    }
    false
}

/// `true` for ClientPIN set/change (fail-closed on undecodable CBOR).
fn client_pin_write(payload: &[u8]) -> bool {
    let cbor = &payload[1..];
    let sub = decode_cbor_map(cbor)
        .ok()
        .and_then(|map| get_int_field(&map, 2).ok());
    match sub {
        Some(s) => s == SUBCMD_SET_PIN || s == SUBCMD_CHANGE_PIN,
        None => true,
    }
}

/// `true` when a serial message requires User Presence (mirrors USB logic).
///
/// CTAP MakeCredential/GetAssertion/Reset, U2F register/authenticate APDUs
/// and every vendor keys/OATH op need UP; binding mgmt defers to its own
/// dispatch (claim/release/set/unlock check presence internally).
pub fn serial_is_up_required(cmd: u8, payload: &[u8]) -> bool {
    if cmd == CMD_CBOR && !payload.is_empty() {
        return matches!(
            payload[0],
            CTAP_CMD_MAKE_CREDENTIAL | CTAP_CMD_GET_ASSERTION | CTAP_CMD_RESET
        );
    }
    if cmd == CMD_MSG && !payload.is_empty() {
        let op = payload[0];
        if is_vendor_keys_oath_op(op) {
            return true;
        }
        if is_bind_mgmt_op(op) {
            return false;
        }
        if payload.len() >= 4 {
            let ins = payload[1];
            let p1 = payload[2];
            return ins == 0x01 || (ins == 0x02 && p1 == 0x03);
        }
    }
    false
}

/// Serial gate outcome (canonical order: pairing -> UP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialGate {
    /// All gates pass.
    Ok,
    /// Pairing window closed for a privileged op.
    NeedPairing,
    /// UP latch missing for an UP-gated op.
    NeedUp,
}

/// Checks pairing-mode then UP for one reassembled serial message.
pub fn authorize_serial(cmd: u8, payload: &[u8], pairing_open: bool, up: bool) -> SerialGate {
    if serial_requires_pairing(cmd, payload) && !pairing_open {
        return SerialGate::NeedPairing;
    }
    if serial_is_up_required(cmd, payload) && !up {
        return SerialGate::NeedUp;
    }
    SerialGate::Ok
}

/// One 64-byte feed outcome (text never corrupts reassembly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialFeed {
    /// Log/heartbeat text: ignored, reassembly preserved.
    IgnoredText,
    /// INIT/CONT accepted, more packets expected.
    NeedMore,
    /// Message complete, ready for gate + dispatch.
    Message(CtapHidMessage),
    /// Protocol violation (framed back with [`CtapHidError::to_packet`]).
    Error(CtapHidError),
}

/// Serial-to-CTAPHID router: text-tolerant front-end over [`CtapHidManager`].
///
/// No `Debug`: the wrapped manager is intentionally opaque on the hot path.
pub struct SerialRouter {
    mgr: CtapHidManager,
}

impl SerialRouter {
    /// Creates an idle router (no assembly, fresh CID allocator).
    pub fn new() -> Self {
        Self {
            mgr: CtapHidManager::new(),
        }
    }

    /// `true` while a multi-packet message is being reassembled.
    pub fn has_pending(&self) -> bool {
        self.mgr.has_pending_assembly()
    }

    /// Feeds one 64-byte UART chunk (byte-identical framing to USB).
    pub fn feed(&mut self, raw: &[u8; PACKET_SIZE], now_ms: u64) -> SerialFeed {
        if is_text_line(raw) {
            return SerialFeed::IgnoredText;
        }
        match self.mgr.process_packet(raw, now_ms) {
            Ok(None) => SerialFeed::NeedMore,
            Ok(Some(msg)) => SerialFeed::Message(msg),
            Err(e) => SerialFeed::Error(e),
        }
    }

    /// Allocates a fresh channel id (delegates to the manager).
    pub fn allocate_cid(&mut self) -> u32 {
        self.mgr.allocate_cid()
    }
}

impl Default for SerialRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Frames the pairing-denied answer (wire statuses only, no framing change).
///
/// Vendor ops get `NEED_BINDING` (`0x05`, prompts the pairing ceremony);
/// CTAP commands get single-byte `NOT_ALLOWED` (`0x30`).
pub fn deny_response(msg: &CtapHidMessage) -> Vec<[u8; PACKET_SIZE]> {
    if msg.cmd == CMD_MSG && !msg.payload.is_empty() && is_vendor_keys_oath_op(msg.payload[0]) {
        return CtapHidFramer::frame_message(msg.cid, msg.cmd, &[VENDOR_STATUS_NEED_BINDING]);
    }
    CtapHidFramer::frame_message(msg.cid, msg.cmd, &[SERIAL_DENY_CTAP_STATUS])
}

/// Dispatches one vendor op with the exact BLE gates.
///
/// Returns `(wire_status, body)`; gate pass answers `0x04` (on-device
/// executor = follow-up, same as BLE), denial maps via `to_vendor_status`.
/// `binding_ok` comes from the caller (`BindingManager::verify` proof).
pub fn dispatch_serial_vendor(op: u8, binding_ok: bool, up: bool) -> (u8, Vec<u8>) {
    match authorize_vendor_op(op, binding_ok, false, up) {
        Ok(()) => (0x04, Vec::new()),
        Err(e) => (e.to_vendor_status(), Vec::new()),
    }
}

/// Maps a BLE gate denial to its wire status (shared with serial vendor).
pub fn vendor_status(e: BleGattError) -> u8 {
    e.to_vendor_status()
}

/// Dispatches one serial diagnostic text line (dump only, metadata only).
///
/// Returns `Some(dump)` solely for the exact `TEST_LIFETIME_DUMP` line when
/// built with `test-mode`; otherwise (or without the feature) `None`.
pub fn dispatch_serial_text_line(line: &str, extra_states: &str) -> Option<String> {
    #[cfg(feature = "test-mode")]
    {
        crate::lifetime_trace::dispatch_test_command(line, extra_states)
    }
    #[cfg(not(feature = "test-mode"))]
    {
        let _ = (line, extra_states);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_fido_usb::ctaphid::{
        BROADCAST_CID, CMD_INIT, CMD_KEEPALIVE, CMD_PING, ERR_INVALID_CHANNEL, STATUS_UPNEEDED,
    };

    fn text_chunk(line: &[u8]) -> [u8; PACKET_SIZE] {
        let mut raw = [0u8; PACKET_SIZE];
        let n = line.len().min(PACKET_SIZE);
        raw[..n].copy_from_slice(&line[..n]);
        raw
    }

    #[test]
    fn framing_single_packet_byte_identical() {
        let cid = 0x11223344;
        let payload = b"serial-ctaphid".to_vec();
        let pkts = CtapHidFramer::frame_message(cid, CMD_CBOR, &payload);
        assert_eq!(pkts.len(), 1);

        let mut router = SerialRouter::new();
        let out = router.feed(&pkts[0], 1000);
        assert!(matches!(out, SerialFeed::Message(_)));
        if let SerialFeed::Message(msg) = out {
            assert_eq!(msg.cid, cid);
            assert_eq!(msg.cmd, CMD_CBOR);
            assert_eq!(msg.payload, payload);
        }
        assert!(!router.has_pending());
    }

    #[test]
    fn framing_multi_packet_reassembly() {
        let cid = 0xAABBCCDD;
        let payload: Vec<u8> = (0..150).map(|i| (i % 256) as u8).collect();
        let pkts = CtapHidFramer::frame_message(cid, CMD_MSG, &payload);
        assert!(pkts.len() > 1);

        let mut router = SerialRouter::new();
        for p in &pkts[..pkts.len() - 1] {
            assert_eq!(router.feed(p, 1000), SerialFeed::NeedMore);
        }
        assert!(router.has_pending());
        let last = router.feed(&pkts[pkts.len() - 1], 1010);
        if let SerialFeed::Message(msg) = last {
            assert_eq!((msg.cid, msg.cmd), (cid, CMD_MSG));
            assert_eq!(msg.payload, payload);
        } else {
            panic!("expected complete message");
        }
        assert!(!router.has_pending());
    }

    #[test]
    fn keepalive_bytes_identical_to_usb() {
        let cid = 0x55667788;
        let pkt = CtapHidFramer::frame_keepalive(cid, STATUS_UPNEEDED);
        assert_eq!(&pkt[0..4], &cid.to_be_bytes());
        assert_eq!(pkt[4], CMD_KEEPALIVE);
        assert_eq!(&pkt[5..7], &[0x00, 0x01]);
        assert_eq!(pkt[7], STATUS_UPNEEDED);
    }

    #[test]
    fn heartbeat_text_ignored_without_error() {
        let mut router = SerialRouter::new();
        let hb = text_chunk(b"[HEARTBEAT] AegisKey S3 alive | uptime: 234s | USB Mounted: false");
        assert!(is_text_line(&hb));
        assert_eq!(router.feed(&hb, 1000), SerialFeed::IgnoredText);
        assert!(!router.has_pending());

        // A real INIT right after text still reassembles.
        let pkts = CtapHidFramer::frame_message(0x01020304, CMD_PING, b"ping");
        let out = router.feed(&pkts[0], 1010);
        assert!(matches!(out, SerialFeed::Message(_)));
    }

    #[test]
    fn text_does_not_break_active_reassembly() {
        let payload = vec![0xABu8; 100];
        let pkts = CtapHidFramer::frame_message(0x0A0B0C0D, CMD_CBOR, &payload);
        let mut router = SerialRouter::new();
        assert_eq!(router.feed(&pkts[0], 1000), SerialFeed::NeedMore);
        let hb = text_chunk(b"[HEARTBEAT] AegisKey S3 alive | uptime: 235s");
        assert_eq!(router.feed(&hb, 1005), SerialFeed::IgnoredText);
        assert!(router.has_pending());
        let out = router.feed(&pkts[1], 1010);
        if let SerialFeed::Message(msg) = out {
            assert_eq!(msg.payload, payload);
        } else {
            panic!("reassembly must survive heartbeat text, got {:?}", out);
        }
    }

    #[test]
    fn all_zero_packet_is_not_text() {
        let raw = [0u8; PACKET_SIZE];
        assert!(!is_text_line(&raw));
        let mut router = SerialRouter::new();
        let out = router.feed(&raw, 1000);
        assert_eq!(
            out,
            SerialFeed::Error(CtapHidError::new(0, ERR_INVALID_CHANNEL))
        );
    }

    #[test]
    fn binary_packet_is_not_text() {
        let pkts = CtapHidFramer::frame_message(BROADCAST_CID, CMD_INIT, &[1, 2, 3]);
        assert!(!is_text_line(&pkts[0]));
    }

    #[test]
    fn pairing_gate_privileged_ctap() {
        // MakeCredential always privileged.
        assert!(serial_requires_pairing(
            CMD_CBOR,
            &[CTAP_CMD_MAKE_CREDENTIAL]
        ));
        // GetInfo / GetAssertion never privileged (simulator parity).
        assert!(!serial_requires_pairing(CMD_CBOR, &[0x04]));
        assert!(!serial_requires_pairing(
            CMD_CBOR,
            &[CTAP_CMD_GET_ASSERTION]
        ));
        // PING / INIT never privileged.
        assert!(!serial_requires_pairing(CMD_PING, b"hi"));
        assert!(!serial_requires_pairing(CMD_INIT, &[0; 8]));
    }

    #[test]
    fn pairing_gate_client_pin_set_change_only() {
        // {1: pinUvAuthProtocol, 2: subCommand} minimal CBOR maps.
        let set_pin = [CTAP_CMD_CLIENT_PIN, 0xA2, 0x01, 0x01, 0x02, 0x03];
        let change_pin = [CTAP_CMD_CLIENT_PIN, 0xA2, 0x01, 0x01, 0x02, 0x04];
        let retries = [CTAP_CMD_CLIENT_PIN, 0xA2, 0x01, 0x01, 0x02, 0x01];
        let key_agreement = [CTAP_CMD_CLIENT_PIN, 0xA2, 0x01, 0x01, 0x02, 0x02];
        assert!(serial_requires_pairing(CMD_CBOR, &set_pin));
        assert!(serial_requires_pairing(CMD_CBOR, &change_pin));
        assert!(!serial_requires_pairing(CMD_CBOR, &retries));
        assert!(!serial_requires_pairing(CMD_CBOR, &key_agreement));
    }

    #[test]
    fn pairing_gate_vendor_config_only() {
        for op in [0x20, 0x21, 0x23, 0x24, 0x27] {
            assert!(serial_requires_pairing(CMD_MSG, &[op]), "op {:02X}", op);
        }
        for op in [0x22, 0x25, 0x26, 0x28, 0x2B] {
            assert!(!serial_requires_pairing(CMD_MSG, &[op]), "op {:02X}", op);
        }
    }

    #[test]
    fn up_gate_mirrors_usb() {
        assert!(serial_is_up_required(CMD_CBOR, &[CTAP_CMD_MAKE_CREDENTIAL]));
        assert!(serial_is_up_required(CMD_CBOR, &[CTAP_CMD_GET_ASSERTION]));
        assert!(serial_is_up_required(CMD_CBOR, &[CTAP_CMD_RESET]));
        assert!(!serial_is_up_required(CMD_CBOR, &[0x04]));
        assert!(!serial_is_up_required(
            CMD_CBOR,
            &[CTAP_CMD_CLIENT_PIN, 0xA2]
        ));
        assert!(serial_is_up_required(CMD_MSG, &[0x20]));
        assert!(serial_is_up_required(CMD_MSG, &[0x26]));
    }

    #[test]
    fn authorize_order_pairing_then_up() {
        let mc = [CTAP_CMD_MAKE_CREDENTIAL];
        assert_eq!(
            authorize_serial(CMD_CBOR, &mc, false, false),
            SerialGate::NeedPairing
        );
        assert_eq!(
            authorize_serial(CMD_CBOR, &mc, true, false),
            SerialGate::NeedUp
        );
        assert_eq!(authorize_serial(CMD_CBOR, &mc, true, true), SerialGate::Ok);
        assert_eq!(
            authorize_serial(CMD_CBOR, &[0x04], false, false),
            SerialGate::Ok
        );
    }

    #[test]
    fn deny_response_uses_wire_statuses() {
        let ctap = CtapHidMessage::new(0x01020304, CMD_CBOR, vec![CTAP_CMD_MAKE_CREDENTIAL]);
        let pkts = deny_response(&ctap);
        assert_eq!(pkts.len(), 1);
        let mut router = SerialRouter::new();
        if let SerialFeed::Message(back) = router.feed(&pkts[0], 1000) {
            assert_eq!(back.payload, vec![SERIAL_DENY_CTAP_STATUS]);
        } else {
            panic!("deny must re-parse as a message");
        }

        let vendor = CtapHidMessage::new(0x01020304, CMD_MSG, vec![0x23]);
        let pkts = deny_response(&vendor);
        let mut router = SerialRouter::new();
        if let SerialFeed::Message(back) = router.feed(&pkts[0], 1000) {
            assert_eq!(back.payload, vec![VENDOR_STATUS_NEED_BINDING]);
        } else {
            panic!("vendor deny must re-parse as a message");
        }
    }

    #[test]
    fn vendor_dispatch_mirrors_ble_gates() {
        // USAGE without UP -> NEED_UP (0x01) in every mode.
        assert_eq!(dispatch_serial_vendor(0x26, false, false).0, 0x01);
        assert_eq!(dispatch_serial_vendor(0x26, false, true).0, 0x04);
        // CONFIG without binding: release denies NEED_BINDING; test-mode
        // bypasses binding but keeps UP/PIN (BLE parity: PIN-less GEN passes,
        // PIN-gated DELETE answers NEED_PIN since serial carries no pin auth).
        let (st, _) = dispatch_serial_vendor(0x20, false, true);
        if crate::binding::binding_bypass_enabled() {
            assert_eq!(st, 0x04);
        } else {
            assert_eq!(st, VENDOR_STATUS_NEED_BINDING);
        }
        let (st_pin, _) = dispatch_serial_vendor(0x23, false, true);
        if crate::binding::binding_bypass_enabled() {
            assert_eq!(st_pin, 0x02);
        } else {
            assert_eq!(st_pin, VENDOR_STATUS_NEED_BINDING);
        }
    }

    #[test]
    fn router_cid_allocation_works() {
        let mut router = SerialRouter::new();
        assert_eq!(router.allocate_cid(), 1);
        assert_eq!(router.allocate_cid(), 2);
    }

    #[cfg(feature = "test-mode")]
    #[test]
    fn dump_answers_with_metadata_no_secrets() {
        let dump = dispatch_serial_text_line("TEST_LIFETIME_DUMP", "uptime_s=42").expect("dump");
        assert!(dump.starts_with("lt_dump v=1\n"));
        assert!(dump.contains("lt.state uptime_s=42"));
        assert!(dump.ends_with("lt_end\n"));
        assert!(!dump.contains("SECRET"));
        assert!(dispatch_serial_text_line("NOPE", "").is_none());
        assert!(dispatch_serial_text_line("TEST_LIFETIME_DUMP_EXTRA", "").is_none());
    }

    #[cfg(not(feature = "test-mode"))]
    #[test]
    fn dump_absent_without_test_mode() {
        assert!(dispatch_serial_text_line("TEST_LIFETIME_DUMP", "").is_none());
    }
}
