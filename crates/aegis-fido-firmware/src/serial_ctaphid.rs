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
    authorize_vendor_op, authorize_wallet_op, is_bind_mgmt_op, is_vendor_keys_oath_op,
    is_wallet_op, BleGattError, OP_KEY_DELETE,
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
        ) || crate::ble_gatt::is_wallet_op(payload[0]);
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
        if is_vendor_keys_oath_op(op) || is_wallet_op(op) {
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
    if msg.cmd == CMD_MSG
        && !msg.payload.is_empty()
        && (is_vendor_keys_oath_op(msg.payload[0]) || is_wallet_op(msg.payload[0]))
    {
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

/// Dispatches one wallet op (0x35-0x37) with the exact BLE gates.
///
/// Returns `(wire_status, body)`; gate pass answers `0x04` (on-device
/// executor `WalletStore` + NVS = follow-up, same as BLE), denial maps
/// via `to_vendor_status` (binding → `0x05`, UP → `0x01`).
pub fn dispatch_serial_wallet(op: u8, binding_ok: bool, up: bool) -> (u8, Vec<u8>) {
    match authorize_wallet_op(op, binding_ok, up) {
        Ok(()) => (0x04, Vec::new()),
        Err(e) => (e.to_vendor_status(), Vec::new()),
    }
}

/// `true` when a reassembled `CMD_MSG` carries a rescue frame.
///
/// Wire convention (Wave2 Step3): first payload byte is
/// `RESCUE_TRANSPORT_OP` (`0x2E`, first free opcode after bind-mgmt
/// `0x28-0x2D`, outside vendor `0x20-0x27`), followed by the rescue frame
/// `[MAGIC|VER|CMD|LEN_BE|PAYLOAD]`. Framing byte-identical; the predicate
/// never touches reassembly.
pub fn is_rescue_msg(cmd: u8, payload: &[u8]) -> bool {
    use aegis_fido_core::otp::rescue::is_rescue_transport_op;
    cmd == CMD_MSG
        && payload.first().is_some_and(|op| is_rescue_transport_op(*op))
}

/// Dispatches one rescue frame (`0x2E` already stripped by the caller).
///
/// Pure `RescueEngine::handle_packet` pass-through: UP/PIN latches must be
/// set by the caller beforehand (`set_user_presence` from the BOOT latch;
/// `set_pin_uv_authenticated` from `ClientPinState::has_valid_pin_uv_session`,
/// wired at all three transports). Returns `(wire_status, body)` for the
/// caller to frame status-first (`[status, body...]`), same shape
/// as the bind-mgmt branch.
pub fn dispatch_serial_rescue(
    engine: &mut aegis_fido_core::otp::rescue::RescueEngine,
    frame: &[u8],
) -> (u8, Vec<u8>) {
    engine.handle_packet(frame)
}

/// `true` when a serial bind-mgmt op consumes the UP latch on success.
///
/// CLAIM/RELEASE/RECOVERY_SET/RECOVERY_UNLOCK require UP (same gates as BLE);
/// CHALLENGE/VERIFY never touch the latch.
pub fn serial_bind_mgmt_consumes_up(op: u8) -> bool {
    use crate::ble_gatt as g;
    matches!(
        op,
        g::OP_BIND_CLAIM | g::OP_BIND_RELEASE | g::OP_RECOVERY_SET | g::OP_RECOVERY_UNLOCK
    )
}

/// Dispatches one binding-mgmt op (`0x28-0x2D`) over serial with BLE-identical gates.
///
/// Reuses the `ble_gatt::dispatch_*` helpers byte-for-byte (claim / challenge /
/// verify / release / recovery); returns `(wire_status, body)` for the caller to
/// frame as `CMD_MSG` `[status, body...]` (status-first like BLE `notify_frame`,
/// no protocol change: the payload content is app-level).
/// `pairing_open`/`up` come from the caller (5s-hold window + BOOT latch).
pub fn dispatch_serial_bind_mgmt<B, R>(
    op: u8,
    params: &[u8],
    pairing_open: bool,
    up: bool,
    binding: &mut crate::binding::BindingManager,
    storage: &mut crate::persistence::SecureStorage<B>,
    rng: &mut R,
) -> (u8, Vec<u8>)
where
    B: crate::persistence::FlashStorageBackend,
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    use crate::binding::{BIND_CHALLENGE_LEN, BIND_ID_LEN, BIND_PAYLOAD_HASH_LEN, BIND_PUB_LEN};
    use crate::ble_gatt as g;
    if !g::is_bind_mgmt_op(op) {
        return (g::BleGattError::InvalidOpcode.to_vendor_status(), Vec::new());
    }
    match op {
        g::OP_BIND_CLAIM => {
            if params.len() != BIND_PUB_LEN + BIND_ID_LEN {
                return (g::BleGattError::InvalidFragment.to_vendor_status(), Vec::new());
            }
            let mut app_pub = [0u8; BIND_PUB_LEN];
            let mut binding_id = [0u8; BIND_ID_LEN];
            app_pub.copy_from_slice(&params[..BIND_PUB_LEN]);
            binding_id.copy_from_slice(&params[BIND_PUB_LEN..]);
            match g::dispatch_bind_claim(
                binding,
                storage,
                &app_pub,
                &binding_id,
                pairing_open,
                up,
            ) {
                Ok(()) => (0x00, binding_id.to_vec()),
                Err(e) => (e.to_vendor_status(), Vec::new()),
            }
        }
        g::OP_BIND_CHALLENGE => {
            if !params.is_empty() {
                return (g::BleGattError::InvalidFragment.to_vendor_status(), Vec::new());
            }
            match g::dispatch_bind_challenge(binding, storage, rng) {
                Ok(ch) => (0x00, ch.to_vec()),
                Err(e) => (e.to_vendor_status(), Vec::new()),
            }
        }
        g::OP_BIND_VERIFY => {
            if params.len() < 1 + BIND_CHALLENGE_LEN + BIND_PAYLOAD_HASH_LEN {
                return (g::BleGattError::InvalidFragment.to_vendor_status(), Vec::new());
            }
            let vop = params[0];
            let mut ch = [0u8; BIND_CHALLENGE_LEN];
            let mut ph = [0u8; BIND_PAYLOAD_HASH_LEN];
            ch.copy_from_slice(&params[1..1 + BIND_CHALLENGE_LEN]);
            ph.copy_from_slice(
                &params[1 + BIND_CHALLENGE_LEN..1 + BIND_CHALLENGE_LEN + BIND_PAYLOAD_HASH_LEN],
            );
            match g::dispatch_bind_verify(
                binding,
                &params[1 + BIND_CHALLENGE_LEN + BIND_PAYLOAD_HASH_LEN..],
                &ch,
                vop,
                &ph,
            ) {
                Ok(()) => (0x00, Vec::new()),
                Err(e) => (e.to_vendor_status(), Vec::new()),
            }
        }
        g::OP_BIND_RELEASE => {
            if params.len() < BIND_CHALLENGE_LEN + BIND_PAYLOAD_HASH_LEN {
                return (g::BleGattError::InvalidFragment.to_vendor_status(), Vec::new());
            }
            let mut ch = [0u8; BIND_CHALLENGE_LEN];
            let mut ph = [0u8; BIND_PAYLOAD_HASH_LEN];
            ch.copy_from_slice(&params[..BIND_CHALLENGE_LEN]);
            ph.copy_from_slice(&params[BIND_CHALLENGE_LEN..BIND_CHALLENGE_LEN + BIND_PAYLOAD_HASH_LEN]);
            match g::dispatch_bind_release(
                binding,
                storage,
                &params[BIND_CHALLENGE_LEN + BIND_PAYLOAD_HASH_LEN..],
                &ch,
                &ph,
                up,
            ) {
                Ok(()) => (0x00, Vec::new()),
                Err(e) => (e.to_vendor_status(), Vec::new()),
            }
        }
        g::OP_RECOVERY_SET => match core::str::from_utf8(params) {
            Ok(pin) => match g::dispatch_recovery_set(storage, pin, up) {
                Ok(()) => (0x00, Vec::new()),
                Err(e) => (e.to_vendor_status(), Vec::new()),
            },
            Err(_) => (g::BleGattError::InvalidFragment.to_vendor_status(), Vec::new()),
        },
        g::OP_RECOVERY_UNLOCK => match core::str::from_utf8(params) {
            Ok(pin) => match g::dispatch_recovery_unlock(storage, binding, pin, up) {
                Ok(()) => (0x00, Vec::new()),
                Err(e) => (e.to_vendor_status(), Vec::new()),
            },
            Err(_) => (g::BleGattError::InvalidFragment.to_vendor_status(), Vec::new()),
        },
        _ => (g::BleGattError::InvalidOpcode.to_vendor_status(), Vec::new()),
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

/// Dispatches `TEST_PAIRING_OPEN` (test-mode only).
///
/// Abre a MESMA janela de 60s do hold 5s via
/// [`crate::pairing::PairingManager::open_test_window`]: software abre a
/// janela, NAO confirma presenca (gates UP/bonding seguem exigidos).
/// Retorna o ack na batida exata, `None` caso contrario; sem `test-mode`
/// o comando nao existe (sempre `None`, comando desconhecido).
#[cfg(feature = "test-mode")]
pub fn dispatch_serial_pairing_line(
    line: &str,
    pairing: &mut crate::pairing::PairingManager,
    now_ms: u64,
) -> Option<String> {
    if line.trim() == crate::pairing::TEST_PAIRING_OPEN_CMD {
        pairing.open_test_window(now_ms);
        Some(String::from("pairing_open window_s=60 source=software\n"))
    } else {
        None
    }
}

/// Release: `TEST_PAIRING_OPEN` nao existe (comando desconhecido, sem janela).
#[cfg(not(feature = "test-mode"))]
pub fn dispatch_serial_pairing_line(
    _line: &str,
    _pairing: &mut crate::pairing::PairingManager,
    _now_ms: u64,
) -> Option<String> {
    None
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
    fn wallet_dispatch_mirrors_ble_gates() {
        // Sem UP (com binding) -> NEED_UP (0x01) em qualquer modo.
        assert_eq!(dispatch_serial_wallet(0x35, true, false).0, 0x01);
        assert_eq!(dispatch_serial_wallet(0x36, true, false).0, 0x01);
        // Sem binding: release nega NEED_BINDING; test-mode faz bypass.
        let (st, _) = dispatch_serial_wallet(0x37, false, true);
        if crate::binding::binding_bypass_enabled() {
            assert_eq!(st, 0x04);
        } else {
            assert_eq!(st, VENDOR_STATUS_NEED_BINDING);
        }
        // Gate ok -> 0x04 (executor on-device = follow-up).
        assert_eq!(dispatch_serial_wallet(0x35, true, true).0, 0x04);
        // Fora da faixa -> opcode invalido.
        assert_eq!(
            dispatch_serial_wallet(0x20, true, true).0,
            BleGattError::InvalidOpcode.to_vendor_status()
        );
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

    #[cfg(feature = "test-mode")]
    #[test]
    fn pairing_open_reuses_hold_window_and_expires() {
        use crate::config::PAIRING_WINDOW_MS;
        use crate::pairing::PairingManager;
        let mut m = PairingManager::new();
        let ack =
            dispatch_serial_pairing_line("TEST_PAIRING_OPEN", &mut m, 5000).expect("ack");
        assert!(ack.contains("pairing_open"));
        assert!(ack.contains("source=software"));
        assert!(m.is_pairing_window_open(5000));
        assert!(!m.is_bonded());
        // Expira em 60s igual ao hold fisico.
        m.tick(5000 + PAIRING_WINDOW_MS);
        assert!(!m.is_pairing_window_open(5000 + PAIRING_WINDOW_MS));
        // Qualquer outra linha: comando desconhecido, janela intacta.
        let mut m2 = PairingManager::new();
        assert!(dispatch_serial_pairing_line("TEST_PAIRING_OPEN_EXTRA", &mut m2, 0).is_none());
        assert!(dispatch_serial_pairing_line("NOPE", &mut m2, 0).is_none());
        assert!(!m2.is_pairing_window_open(0));
    }

    #[cfg(not(feature = "test-mode"))]
    #[test]
    fn pairing_open_unknown_without_test_mode() {
        use crate::pairing::PairingManager;
        let mut m = PairingManager::new();
        assert!(dispatch_serial_pairing_line("TEST_PAIRING_OPEN", &mut m, 0).is_none());
        assert!(!m.is_pairing_window_open(0));
    }

    #[test]
    fn serial_vendor_parity_matrix_all_ops() {
        use crate::ble_gatt::{authorize_vendor_op, OP_OATH_CODE};
        // Full 0x20-0x27 x (vinculo x UP): serial responde o mesmo status do BLE.
        for op in 0x20u8..=0x27u8 {
            for binding_ok in [false, true] {
                for up in [false, true] {
                    let (st_s, _) = dispatch_serial_vendor(op, binding_ok, up);
                    let st_b = match authorize_vendor_op(op, binding_ok, false, up) {
                        Ok(()) => 0x04,
                        Err(e) => e.to_vendor_status(),
                    };
                    assert_eq!(st_s, st_b, "op {:02X} bind={} up={}", op, binding_ok, up);
                }
            }
        }
        assert_eq!(dispatch_serial_vendor(OP_OATH_CODE, false, true).0, 0x04);
        assert_eq!(dispatch_serial_vendor(OP_OATH_CODE, false, false).0, 0x01);
    }

    #[test]
    fn serial_bind_consumes_up_only_where_ble_needs_up() {
        use crate::ble_gatt as g;
        for op in [
            g::OP_BIND_CLAIM,
            g::OP_BIND_RELEASE,
            g::OP_RECOVERY_SET,
            g::OP_RECOVERY_UNLOCK,
        ] {
            assert!(serial_bind_mgmt_consumes_up(op), "op {:02X}", op);
        }
        for op in [g::OP_BIND_CHALLENGE, g::OP_BIND_VERIFY, 0x20, 0x2E] {
            assert!(!serial_bind_mgmt_consumes_up(op), "op {:02X}", op);
        }
    }

    #[test]
    fn serial_bind_rejects_malformed_framing() {
        use crate::binding::BindingManager;
        use crate::ble_gatt as g;
        use crate::persistence::{MockFlashBackend, SecureStorage};
        let mut b = BindingManager::new();
        let mut s = SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32]);
        let mut rng = rand_core::OsRng;
        // Fora da faixa, comprimentos errados e PIN nao-UTF8: 0x04, sem panics.
        assert_eq!(
            dispatch_serial_bind_mgmt(0x20, &[], true, true, &mut b, &mut s, &mut rng).0,
            0x04
        );
        assert_eq!(
            dispatch_serial_bind_mgmt(0x2E, &[], true, true, &mut b, &mut s, &mut rng).0,
            0x04
        );
        assert_eq!(
            dispatch_serial_bind_mgmt(g::OP_BIND_CLAIM, &[0x01, 0x02], true, true, &mut b, &mut s, &mut rng).0,
            0x04
        );
        assert_eq!(
            dispatch_serial_bind_mgmt(g::OP_BIND_CHALLENGE, &[0x01], true, true, &mut b, &mut s, &mut rng).0,
            0x04
        );
        assert_eq!(
            dispatch_serial_bind_mgmt(g::OP_BIND_VERIFY, &[0x22], true, true, &mut b, &mut s, &mut rng).0,
            0x04
        );
        assert_eq!(
            dispatch_serial_bind_mgmt(g::OP_BIND_RELEASE, &[0x00; 10], true, true, &mut b, &mut s, &mut rng).0,
            0x04
        );
        assert_eq!(
            dispatch_serial_bind_mgmt(g::OP_RECOVERY_SET, &[0xFF], true, true, &mut b, &mut s, &mut rng).0,
            0x04
        );
    }

    #[test]
    fn rescue_msg_detects_transport_op_only() {
        use aegis_fido_core::otp::rescue::RESCUE_TRANSPORT_OP;
        // CMD_MSG + 0x2E com frame: rescue; resto nao.
        let frame = [0x52u8, 0x45, 0x53, 0x43, 0x01, 0x01, 0x00, 0x00];
        let mut payload = alloc::vec::Vec::new();
        payload.push(RESCUE_TRANSPORT_OP);
        payload.extend_from_slice(&frame);
        assert!(is_rescue_msg(CMD_MSG, &payload));
        assert!(!is_rescue_msg(CMD_CBOR, &payload));
        assert!(!is_rescue_msg(CMD_MSG, &[]));
        assert!(!is_rescue_msg(CMD_MSG, &[0x20]));
        assert!(!is_rescue_msg(CMD_MSG, &[0x28]));
        // 0x2E nao e bind-mgmt: segue para rescue, nunca para bind.
        assert!(!crate::ble_gatt::is_bind_mgmt_op(RESCUE_TRANSPORT_OP));
    }

    #[test]
    fn rescue_dispatch_ping_needs_up_and_answers() {
        use aegis_fido_core::otp::rescue::{
            build_packet, RescueEngine, RESCUE_CMD_PING, RESCUE_STATUS_CONFIRMATION_FAILED,
            RESCUE_STATUS_OK, RESCUE_VERSION,
        };
        // Sem UP: nega fail-closed com erro existente.
        let mut engine = RescueEngine::new();
        let ping = build_packet(RESCUE_CMD_PING, &[]);
        let (st, _) = dispatch_serial_rescue(&mut engine, &ping);
        assert_eq!(st, RESCUE_STATUS_CONFIRMATION_FAILED);
        // Com UP do latch: PING responde [VER|panic|wipe|recovery].
        engine.set_user_presence(true);
        let (st2, body) = dispatch_serial_rescue(&mut engine, &ping);
        assert_eq!(st2, RESCUE_STATUS_OK);
        assert_eq!(body[0], RESCUE_VERSION);
        // Killswitch remoto sem PIN: nega (PIN=false ate o plumbing ClientPIN).
        let kill = build_packet(
            aegis_fido_core::otp::rescue::RESCUE_CMD_KILLSWITCH,
            aegis_fido_core::otp::rescue::KILLSWITCH_CONFIRM_TOKEN,
        );
        engine.set_user_presence(true);
        let (st3, _) = dispatch_serial_rescue(&mut engine, &kill);
        assert_eq!(st3, RESCUE_STATUS_CONFIRMATION_FAILED);
    }

    #[test]
    fn serial_bind_mgmt_parity_with_ble() {
        use crate::binding::{BIND_ID_LEN, BIND_PUB_LEN, BindingManager};
        use crate::ble_gatt as g;
        use crate::persistence::{MockFlashBackend, SecureStorage};

        fn fixtures() -> (BindingManager, SecureStorage<MockFlashBackend>) {
            let st = SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32]);
            (BindingManager::new(), st)
        }
        let sk = p256::ecdsa::SigningKey::from_slice(&[0x11u8; 32]).expect("scalar valido");
        let pt = sk.verifying_key().to_encoded_point(false);
        let mut sec1 = [0u8; BIND_PUB_LEN];
        sec1.copy_from_slice(pt.as_bytes());
        let id = [0xABu8; BIND_ID_LEN];
        let mut claim_p = Vec::with_capacity(BIND_PUB_LEN + BIND_ID_LEN);
        claim_p.extend_from_slice(&sec1);
        claim_p.extend_from_slice(&id);
        let mut rng = rand_core::OsRng;

        // CLAIM sem janela: PairingRequired vira PresenceRequired (0x01) nos dois.
        {
            let (mut b1, mut s1) = fixtures();
            let (mut b2, mut s2) = fixtures();
            let (st_s, _) = dispatch_serial_bind_mgmt(
                g::OP_BIND_CLAIM,
                &claim_p,
                false,
                false,
                &mut b1,
                &mut s1,
                &mut rng,
            );
            let st_b = g::dispatch_bind_claim(&mut b2, &mut s2, &sec1, &id, false, false)
                .map(|_| 0x00)
                .unwrap_or_else(|e| e.to_vendor_status());
            assert_eq!((st_s, st_b), (0x01, 0x01));
        }
        // CLAIM ok ecoa o binding_id nos dois; re-claim nega 0x04 nos dois.
        {
            let (mut b1, mut s1) = fixtures();
            let (mut b2, mut s2) = fixtures();
            let (st_s, body_s) = dispatch_serial_bind_mgmt(
                g::OP_BIND_CLAIM,
                &claim_p,
                true,
                true,
                &mut b1,
                &mut s1,
                &mut rng,
            );
            let (st_b, body_b) = match g::dispatch_bind_claim(&mut b2, &mut s2, &sec1, &id, true, true)
            {
                Ok(()) => (0x00, id.to_vec()),
                Err(e) => (e.to_vendor_status(), Vec::new()),
            };
            assert_eq!((st_s, body_s.clone()), (st_b, body_b));
            assert_eq!((st_s, body_s), (0x00, id.to_vec()));
            let (st_s2, _) = dispatch_serial_bind_mgmt(
                g::OP_BIND_CLAIM,
                &claim_p,
                true,
                true,
                &mut b1,
                &mut s1,
                &mut rng,
            );
            let st_b2 = g::dispatch_bind_claim(&mut b2, &mut s2, &sec1, &id, true, true)
                .map(|_| 0x00)
                .unwrap_or_else(|e| e.to_vendor_status());
            assert_eq!((st_s2, st_b2), (0x04, 0x04));
        }
        // CHALLENGE sem dono: NEED_BINDING (0x05); com dono: 0x00 + 32B.
        {
            let (mut b1, mut s1) = fixtures();
            let (mut b2, mut s2) = fixtures();
            let (st_s, _) = dispatch_serial_bind_mgmt(
                g::OP_BIND_CHALLENGE,
                &[],
                true,
                true,
                &mut b1,
                &mut s1,
                &mut rng,
            );
            let st_b = g::dispatch_bind_challenge(&mut b2, &s2, &mut rng)
                .map(|_| 0x00)
                .unwrap_or_else(|e| e.to_vendor_status());
            assert_eq!((st_s, st_b), (0x05, 0x05));
            b1.claim(&sec1, &id, true, true).expect("claim serial");
            b1.persist(&mut s1).expect("persist serial");
            b2.claim(&sec1, &id, true, true).expect("claim ble");
            b2.persist(&mut s2).expect("persist ble");
            let (st_s, body_s) = dispatch_serial_bind_mgmt(
                g::OP_BIND_CHALLENGE,
                &[],
                true,
                true,
                &mut b1,
                &mut s1,
                &mut rng,
            );
            let ble_ch = g::dispatch_bind_challenge(&mut b2, &s2, &mut rng).expect("ch ble");
            assert_eq!(st_s, 0x00);
            assert_eq!(body_s.len(), ble_ch.len());
            assert_eq!(body_s.len(), 32);
        }
        // VERIFY sem challenge ativo: Replay -> NEED_BINDING (0x05) nos dois.
        {
            let (mut b1, mut s1) = fixtures();
            let (mut b2, _) = fixtures();
            b1.claim(&sec1, &id, true, true).expect("claim");
            b2.claim(&sec1, &id, true, true).expect("claim");
            let mut p = Vec::with_capacity(66);
            p.push(g::OP_KEY_LIST);
            p.extend_from_slice(&[0x00u8; 32]);
            p.extend_from_slice(&[0x11u8; 32]);
            p.push(0x30);
            let ch = [0u8; 32];
            let ph = [0x11u8; 32];
            let (st_s, _) = dispatch_serial_bind_mgmt(
                g::OP_BIND_VERIFY,
                &p,
                true,
                true,
                &mut b1,
                &mut s1,
                &mut rng,
            );
            let st_b = g::dispatch_bind_verify(&mut b2, &p[65..], &ch, g::OP_KEY_LIST, &ph)
                .map(|_| 0x00)
                .unwrap_or_else(|e| e.to_vendor_status());
            assert_eq!((st_s, st_b), (0x05, 0x05));
        }
        // VERIFY com prova valida: 0x00 nos dois (uso unico preservado).
        {
            use signature::Signer;
            let (mut b1, mut s1) = fixtures();
            let (mut b2, s2) = fixtures();
            b1.claim(&sec1, &id, true, true).expect("claim");
            b2.claim(&sec1, &id, true, true).expect("claim");
            let ph = [0x11u8; 32];
            let ch1 = g::dispatch_bind_challenge(&mut b1, &s1, &mut rng).expect("ch1");
            let ch2 = g::dispatch_bind_challenge(&mut b2, &s2, &mut rng).expect("ch2");
            let mut p1 = Vec::with_capacity(80);
            p1.push(g::OP_KEY_LIST);
            p1.extend_from_slice(&ch1);
            p1.extend_from_slice(&ph);
            let msg1 = BindingManager::signed_message(&ch1, g::OP_KEY_LIST, &ph);
            let sig1: p256::ecdsa::Signature = sk.sign(&msg1);
            p1.extend_from_slice(sig1.to_der().as_bytes());
            let (st_s, body_s) = dispatch_serial_bind_mgmt(
                g::OP_BIND_VERIFY,
                &p1,
                true,
                true,
                &mut b1,
                &mut s1,
                &mut rng,
            );
            assert_eq!((st_s, body_s), (0x00, Vec::new()));
            let msg2 = BindingManager::signed_message(&ch2, g::OP_KEY_LIST, &ph);
            let sig2: p256::ecdsa::Signature = sk.sign(&msg2);
            let der2 = sig2.to_der().as_bytes().to_vec();
            g::dispatch_bind_verify(&mut b2, &der2, &ch2, g::OP_KEY_LIST, &ph).expect("verify ble");
        }
        // RELEASE sem UP: 0x01; com UP + sig lixo: bypass?0x00:0x05 (igual BLE).
        {
            let (mut b1, mut s1) = fixtures();
            let (mut b2, mut s2) = fixtures();
            b1.claim(&sec1, &id, true, true).expect("claim");
            b2.claim(&sec1, &id, true, true).expect("claim");
            let mut p = Vec::with_capacity(65);
            p.extend_from_slice(&[0x00u8; 32]);
            p.extend_from_slice(&[0xBBu8; 32]);
            p.push(0x30);
            let (st_s, _) = dispatch_serial_bind_mgmt(
                g::OP_BIND_RELEASE,
                &p,
                true,
                false,
                &mut b1,
                &mut s1,
                &mut rng,
            );
            assert_eq!(st_s, 0x01);
            let ch = [0u8; 32];
            let ph = [0xBBu8; 32];
            let st_b = g::dispatch_bind_release(&mut b2, &mut s2, &p[64..], &ch, &ph, false)
                .map(|_| 0x00)
                .unwrap_or_else(|e| e.to_vendor_status());
            assert_eq!(st_b, 0x01);
            let (st_s, _) = dispatch_serial_bind_mgmt(
                g::OP_BIND_RELEASE,
                &p,
                true,
                true,
                &mut b1,
                &mut s1,
                &mut rng,
            );
            let st_b = g::dispatch_bind_release(&mut b2, &mut s2, &p[64..], &ch, &ph, true)
                .map(|_| 0x00)
                .unwrap_or_else(|e| e.to_vendor_status());
            if crate::binding::binding_bypass_enabled() {
                assert_eq!((st_s, st_b), (0x00, 0x00));
            } else {
                assert_eq!((st_s, st_b), (0x05, 0x05));
            }
        }
        // RECOVERY_SET: PIN curto 0x02, sem UP 0x01, valido 0x00 (igual BLE).
        {
            let (mut b1, mut s1) = fixtures();
            let (_b2, mut s2) = fixtures();
            for (pin, up, want) in [("123", true, 0x02), ("4242", false, 0x01), ("4242", true, 0x00)]
            {
                let (st_s, _) = dispatch_serial_bind_mgmt(
                    g::OP_RECOVERY_SET,
                    pin.as_bytes(),
                    true,
                    up,
                    &mut b1,
                    &mut s1,
                    &mut rng,
                );
                let st_b = g::dispatch_recovery_set(&mut s2, pin, up)
                    .map(|_| 0x00)
                    .unwrap_or_else(|e| e.to_vendor_status());
                assert_eq!((st_s, st_b), (want, want), "set pin={} up={}", pin, up);
            }
        }
        // RECOVERY_UNLOCK: PIN errado 0x02, certo 0x00 + libera re-claim (igual BLE).
        {
            let (mut b1, mut s1) = fixtures();
            let (mut b2, mut s2) = fixtures();
            b1.claim(&sec1, &id, true, true).expect("claim");
            b1.persist(&mut s1).expect("persist");
            g::dispatch_recovery_set(&mut s1, "4242", true).expect("set");
            b2.claim(&sec1, &id, true, true).expect("claim");
            b2.persist(&mut s2).expect("persist");
            g::dispatch_recovery_set(&mut s2, "4242", true).expect("set");
            let (st_s, _) = dispatch_serial_bind_mgmt(
                g::OP_RECOVERY_UNLOCK,
                b"0000",
                true,
                true,
                &mut b1,
                &mut s1,
                &mut rng,
            );
            let st_b = g::dispatch_recovery_unlock(&mut s2, &mut b2, "0000", true)
                .map(|_| 0x00)
                .unwrap_or_else(|e| e.to_vendor_status());
            assert_eq!((st_s, st_b), (0x02, 0x02));
            assert!(b1.is_claimed() && b2.is_claimed());
            let (st_s, _) = dispatch_serial_bind_mgmt(
                g::OP_RECOVERY_UNLOCK,
                b"4242",
                true,
                true,
                &mut b1,
                &mut s1,
                &mut rng,
            );
            let st_b = g::dispatch_recovery_unlock(&mut s2, &mut b2, "4242", true)
                .map(|_| 0x00)
                .unwrap_or_else(|e| e.to_vendor_status());
            assert_eq!((st_s, st_b), (0x00, 0x00));
            assert!(!b1.is_claimed() && !b2.is_claimed());
        }
    }
}
