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
//!   `0x20/0x21/0x23/0x24/0x27`, backup-export `0x3A`) require pairing-mode (hold 5s BOOT, 60s
//!   window). Denial answers CTAP2 `NOT_ALLOWED` (`0x30`) for CTAP commands
//!   and the `NEED_BINDING` (`0x05`) vendor status for vendor ops — wire
//!   statuses only, framing untouched.
//! - Vendor dispatch mirrors the BLE gates byte-for-byte
//!   ([`authorize_vendor_op`]); the on-device executor stays follow-up
//!   (status `0x04` on gate pass, exactly like BLE).
//! - `no_std` compatible (`alloc` only).
//!
//! # Security contract (§3C hardening, serial side)
//!
//! - UART link is **plaintext by design**, same as USB: no AAD at framing;
//!   possession of the serial cable is the physical binding. `NEED_BINDING`
//!   is a **vendor-dispatch** status only (never a framing error) and is
//!   never emitted on the pure USB CTAPHID path.
//! - Secrets stay above framing: ClientPIN P-256 ECDH (`pin_token`, retry
//!   counters, `pinUvAuth` sessions via `ClientPinState`) and vault
//!   `seal`/`open` whose AAD is preserved byte-for-byte through
//!   reassembly/framing (this router never pads, strips, or re-keys).
//! - Framing cap is USB-identical: 64 B packets, `MAX_MSG_LEN` 7609 B, no
//!   AAD. Overruns are fail-closed (`ERR_INVALID_LEN` on INIT `BCNT`
//!   overrun, `try_frame_message → None` / `frame_message` panic on encode
//!   overrun — never a silent truncate).
//! - Out of app contract (documented, not dispatched here): keyboard OTP
//!   output, CCID/PIV APDU transport, OTA opcodes `0x30-0x34` (`UNMAPPED`).
//!
//! # Portability / quality (R13/R14/R6/R7)
//!
//! - R13 stub-only: router + gate predicates only; real UART driver lives
//!   behind a serial trait in board code (`main.rs`/HAL), not here.
//! - R14 HW-first: framing core is the portable `aegis-fido-usb` crate
//!   (see `Transport` trait); this module only adapts bytes ↔ manager.
//! - R6 zero warnings: `no_std` + `alloc` only, no `std` imports.
//! - R7 test-mode gated: `TEST_*` text/pairing hooks exist only under
//!   `feature = "test-mode"` (`dispatch_serial_text_line`,
//!   `dispatch_serial_pairing_line`); release builds answer `None`.

extern crate alloc;

use aegis_fido_core::ctap::cbor::{decode_cbor_map, get_int_field};
use aegis_fido_core::ctap::client_pin::{SUBCMD_CHANGE_PIN, SUBCMD_SET_PIN};
use aegis_fido_core::ctap::{
    CTAP_CMD_CLIENT_PIN, CTAP_CMD_GET_ASSERTION, CTAP_CMD_MAKE_CREDENTIAL, CTAP_CMD_RESET,
};
use aegis_fido_usb::ctaphid::{
    CtapHidError, CtapHidFramer, CtapHidManager, CtapHidMessage, CMD_CBOR, CMD_MSG, PACKET_SIZE,
};
use alloc::vec::Vec;

use crate::ble::dispatch_bind::{
    is_backup_export_op, is_bind_mgmt_op, is_piv_enroll_op, is_vendor_keys_oath_op, is_wallet_op,
};
use crate::ble::gatt_core::{
    BleGattError, OP_BACKUP_EXPORT, OP_KEY_DELETE, OP_KEY_GEN_ONDEVICE, OP_KEY_IMPORT_ENVELOPE,
    OP_OATH_DELETE, OP_OATH_PUT, OP_PIV_ENROLL, VENDOR_STATUS_NEED_BINDING,
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
                | OP_PIV_ENROLL
                | OP_BACKUP_EXPORT
        ) || crate::ble::dispatch_bind::is_wallet_op(payload[0]);
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
        if is_vendor_keys_oath_op(op)
            || is_wallet_op(op)
            || is_piv_enroll_op(op)
            || is_backup_export_op(op)
        {
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

/// `true` quando a janela começa com cabeçalho INIT plausível (`>IBH`).
///
/// Checagem de realinhamento do fio compartilhado UART: `cmd & 0x80`,
/// `1 <= total <= MAX_MSG_LEN` (teto CTAPHID 7609 B, sem AAD) e
/// `cid != 0` (canal reservado nunca abre sessão; `0x00000000` ancora o
/// ponto fixo do wedge L2 quando o tail de zeros de um pacote anterior
/// é lido como CID). Broadcast `0xFFFFFFFF` é plausível só p/ `CMD_INIT.
pub fn starts_with_init_header(window: &[u8]) -> bool {
    use aegis_fido_usb::ctaphid::{BROADCAST_CID, CMD_INIT, MAX_MSG_LEN};
    if window.len() < 7 {
        return false;
    }
    let cid = u32::from_be_bytes([window[0], window[1], window[2], window[3]]);
    if cid == 0 {
        return false;
    }
    let raw = window[4];
    if raw & 0x80 == 0 {
        return false;
    }
    let total = u16::from_be_bytes([window[5], window[6]]) as usize;
    if total == 0 || total > MAX_MSG_LEN {
        return false;
    }
    if cid == BROADCAST_CID {
        return raw == CMD_INIT;
    }
    true
}

/// `true` quando o prefixo até `\n` é linha de texto (descartável).
///
/// Linha é texto quando não-vazia após strip de `\x00` e todo byte é
/// imprimível ASCII ou `TAB/CR/LF`. Binário CTAPHID carrega CIDs,
/// comprimentos e CBOR/TLV fora dessa faixa, então um pacote real nunca
/// casa aqui; `0x0A` solto dentro do payload binário não forma linha
/// (`\r\n` exigido pelo dreno do harness).
pub fn is_stream_text_line(line: &[u8]) -> bool {
    let body: &[u8] = line;
    let mut seen = false;
    for b in body.iter() {
        if *b == 0x00 {
            continue;
        }
        seen = true;
        if !matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E) {
            return false;
        }
    }
    seen
}

/// Decodificador byte-stream do fio UART compartilhado (texto + CTAPHID).
///
/// O driver C (`aegis_serial_pop_packet` 64 B fixos + `read_chunk` 32 B)
/// tem dois consumidores no mesmo FIFO; quando uma linha curta `TEST_*`
/// (22 B, não-múltipla de 64) divide o FIFO com o INIT seguinte, o pop
/// de 64 B lê a janela mista e o CID ancora em `0x00000000`
/// (`ERR_INVALID_CHANNEL` persistente, L2 7/7). Este decodificador é o
/// contrato de resync testável no host: acumula bytes crus, descarta o
/// prefixo texto até `\n`, realinha em `>IBH` e delega ao
/// `CtapHidManager` (que já limpa assembly órfã no INIT broadcast).
/// `purge()` esvazia o RX (espelho do `purge-RX no open` do harness/C).
pub struct SerialStreamDecoder {
    buf: Vec<u8>,
    mgr: CtapHidManager,
}

impl SerialStreamDecoder {
    /// Cria decodificador vazio (sem assembly, sem bytes).
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            mgr: CtapHidManager::new(),
        }
    }

    /// Purge-RX: descarta bytes pendentes (abrir nunca reseta o device;
    /// só limpa o fio local). Assembly órfã cai no próximo INIT broadcast.
    pub fn purge(&mut self) {
        self.buf.clear();
    }

    /// `true` enquanto há assembly multi-pacote pendente.
    pub fn has_pending(&self) -> bool {
        self.mgr.has_pending_assembly()
    }

    /// Empurra bytes crus do fio; retorna os feeds resolvidos em ordem.
    pub fn push_bytes(&mut self, chunk: &[u8], now_ms: u64) -> Vec<SerialFeed> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            // 1) Linha texto até `\n`: descarta (fora do framing).
            if let Some(nl) = self.buf.iter().position(|b| *b == b'\n') {
                let line_len = nl + 1;
                // Só trata como texto se a linha for curta (<128 B) e
                // imprimível; binário com 0x0A no meio tem bytes fora da
                // faixa e cai no path CTAPHID abaixo (sem split).
                if line_len <= 128 && is_stream_text_line(&self.buf[..line_len]) {
                    // Linha texto genuína só vence se não houver um header
                    // CTAPHID plausível antes dela (evita comer INIT que
                    // contenha 0x0A no nonce/payload).
                    let header_first = (0..line_len.saturating_sub(7)).any(|i| {
                        self.buf.len() >= i + 7 && starts_with_init_header(&self.buf[i..])
                    });
                    if !header_first {
                        self.buf.drain(..line_len);
                        out.push(SerialFeed::IgnoredText);
                        continue;
                    }
                }
            }
            // 2) Precisa de 64 B p/ uma janela CTAPHID.
            if self.buf.len() < PACKET_SIZE {
                break;
            }
            let mut window = [0u8; PACKET_SIZE];
            window.copy_from_slice(&self.buf[..PACKET_SIZE]);
            // 2a) Janela só-texto: drena (log `[FREERTOS]`/ticks).
            if is_text_line(&window) {
                self.buf.drain(..PACKET_SIZE);
                out.push(SerialFeed::IgnoredText);
                continue;
            }
            // 2b) Janela sem header plausível e sem assembly: avança 1 B
            // (realign em `>IBH`; descarta prefixo texto byte a byte).
            if !self.mgr.has_pending_assembly() && !starts_with_init_header(&window) {
                // Linha texto parcial no início da janela? Descarta até `\n`.
                if let Some(nl) = window.iter().position(|b| *b == b'\n') {
                    let prefix = &window[..nl + 1];
                    if is_stream_text_line(prefix) {
                        self.buf.drain(..nl + 1);
                        out.push(SerialFeed::IgnoredText);
                        continue;
                    }
                }
                self.buf.drain(..1);
                continue;
            }
            // 2c) Delega ao manager (INIT broadcast limpa órfã lá dentro).
            match self.mgr.process_packet(&window, now_ms) {
                Ok(None) => {
                    self.buf.drain(..PACKET_SIZE);
                    out.push(SerialFeed::NeedMore);
                }
                Ok(Some(msg)) => {
                    self.buf.drain(..PACKET_SIZE);
                    out.push(SerialFeed::Message(msg));
                }
                Err(e) => {
                    self.buf.drain(..PACKET_SIZE);
                    out.push(SerialFeed::Error(e));
                    // Pós-erro sem header na próxima janela: o loop 2b
                    // realinha (não prende em ponto fixo de zeros).
                }
            }
            if out.len() >= 8 {
                break;
            }
        }
        out
    }
}

impl Default for SerialStreamDecoder {
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
        && (is_vendor_keys_oath_op(msg.payload[0])
            || is_wallet_op(msg.payload[0])
            || is_piv_enroll_op(msg.payload[0])
            || is_backup_export_op(msg.payload[0]))
    {
        return CtapHidFramer::frame_message(msg.cid, msg.cmd, &[VENDOR_STATUS_NEED_BINDING]);
    }
    CtapHidFramer::frame_message(msg.cid, msg.cmd, &[SERIAL_DENY_CTAP_STATUS])
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
        && payload
            .first()
            .is_some_and(|op| is_rescue_transport_op(*op))
}

/// `true` when a serial bind-mgmt op consumes the UP latch on success.
///
/// CLAIM/RELEASE/RECOVERY_SET/RECOVERY_UNLOCK require UP (same gates as BLE);
/// CHALLENGE/VERIFY never touch the latch.
pub fn serial_bind_mgmt_consumes_up(op: u8) -> bool {
    use crate::ble::gatt_core as g;
    matches!(
        op,
        g::OP_BIND_CLAIM | g::OP_BIND_RELEASE | g::OP_RECOVERY_SET | g::OP_RECOVERY_UNLOCK
    )
}

/// Maps a BLE gate denial to its wire status (shared with serial vendor).
pub fn vendor_status(e: BleGattError) -> u8 {
    e.to_vendor_status()
}

#[cfg(feature = "test-mode")]
pub use crate::serial_text::dispatch_serial_pairing_line;
#[cfg(not(feature = "test-mode"))]
pub use crate::serial_text::dispatch_serial_pairing_line;
pub use crate::serial_text::dispatch_serial_text_line;

pub use crate::serial_vendor::{
    dispatch_serial_bind_mgmt, dispatch_serial_rescue, dispatch_serial_vendor,
    dispatch_serial_wallet,
};

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
    fn serial_overrun_fail_closed() {
        use aegis_fido_usb::ctaphid::{CtapHidManager, ERR_INVALID_LEN, MAX_MSG_LEN};
        // Encode side refuses overrun (no silent truncate).
        let big = alloc::vec![0xAAu8; MAX_MSG_LEN + 1];
        assert!(CtapHidFramer::try_frame_message(0x01020304, CMD_CBOR, &big).is_none());
        // Wire side rejects overrun BCNT fail-closed through the router.
        let mut raw = [0u8; PACKET_SIZE];
        raw[0..4].copy_from_slice(&0x01020304u32.to_be_bytes());
        raw[4] = CMD_CBOR;
        raw[5..7].copy_from_slice(&((MAX_MSG_LEN as u16).wrapping_add(1)).to_be_bytes());
        let mut router = SerialRouter::new();
        assert_eq!(
            router.feed(&raw, 1000),
            SerialFeed::Error(CtapHidError::new(0x01020304, ERR_INVALID_LEN))
        );
        assert!(!router.has_pending());
        // Direct manager parity: same INIT is ERR_INVALID_LEN.
        assert_eq!(
            CtapHidManager::parse_raw_packet(&raw).unwrap_err().code,
            ERR_INVALID_LEN
        );
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
    fn stream_resync_descarta_prefixo_texto_e_realinha_em_init() {
        // Regressão L2: linha curta TEST_* (22 B, não-múltipla de 64) + INIT
        // 64 B no mesmo FIFO desalinhava o pop fixo (CID 0x00000000 ->
        // ERR 0x0B persistente). O stream descarta o prefixo e realinha.
        let mut dec = SerialStreamDecoder::new();
        let nonce = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let init = CtapHidFramer::frame_message(BROADCAST_CID, CMD_INIT, &nonce);
        let mut mixed = Vec::new();
        mixed.extend_from_slice(b"TEST_PAIRING_OPEN_300\n");
        mixed.extend_from_slice(&init[0]);
        let feeds = dec.push_bytes(&mixed, 1000);
        assert!(feeds.contains(&SerialFeed::IgnoredText));
        let msg = feeds.iter().find_map(|f| match f {
            SerialFeed::Message(m) => Some(m),
            _ => None,
        });
        assert!(
            msg.is_some(),
            "INIT deve realinhar após prefixo texto: {:?}",
            feeds
        );
        assert!(!dec.has_pending());
    }

    #[test]
    fn stream_broadcast_init_limpa_orfa_e_purge_esvazia_rx() {
        // Assembly órfã multi-pacote + INIT broadcast: recupera sem BUSY.
        let mut dec = SerialStreamDecoder::new();
        let orphan = CtapHidFramer::frame_message(0x01020304, CMD_CBOR, &[0xABu8; 100]);
        let f1 = dec.push_bytes(&orphan[0], 1000);
        assert!(f1.contains(&SerialFeed::NeedMore));
        assert!(dec.has_pending());
        dec.purge();
        // Purge esvazia o RX; a órfã do manager cai no INIT broadcast.
        let nonce = [0xAAu8; 8];
        let init = CtapHidFramer::frame_message(BROADCAST_CID, CMD_INIT, &nonce);
        let f2 = dec.push_bytes(&init[0], 1100);
        assert!(f2.iter().any(|f| matches!(f, SerialFeed::Message(_))));
        assert!(!dec.has_pending());
    }

    #[test]
    fn starts_with_init_header_rejeita_zero_e_teto() {
        use aegis_fido_usb::ctaphid::MAX_MSG_LEN;
        // CID zero nunca abre sessão (âncora do wedge).
        let mut zero = [0u8; 64];
        zero[4] = CMD_INIT;
        zero[5..7].copy_from_slice(&8u16.to_be_bytes());
        assert!(!starts_with_init_header(&zero));
        // Teto 7609: BCNT maior é inválido.
        let mut over = [0u8; 64];
        over[0..4].copy_from_slice(&0x01020304u32.to_be_bytes());
        over[4] = CMD_INIT;
        over[5..7].copy_from_slice(&((MAX_MSG_LEN as u16).wrapping_add(1)).to_be_bytes());
        assert!(!starts_with_init_header(&over));
        // Broadcast só vale p/ INIT.
        let mut bc = [0u8; 64];
        bc[0..4].copy_from_slice(&BROADCAST_CID.to_be_bytes());
        bc[4] = CMD_PING;
        bc[5..7].copy_from_slice(&4u16.to_be_bytes());
        assert!(!starts_with_init_header(&bc));
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
        for op in [0x20, 0x21, 0x23, 0x24, 0x27, OP_BACKUP_EXPORT] {
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
        assert!(serial_is_up_required(CMD_MSG, &[OP_BACKUP_EXPORT]));
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

        // Backup-export nega pairing com 0x05 como as CONFIG (posse do cabo
        // pede a cerimônia; o gate binding->UP->PIN vem no dispatch).
        let backup = CtapHidMessage::new(0x01020304, CMD_MSG, vec![OP_BACKUP_EXPORT, 0x01]);
        let pkts = deny_response(&backup);
        let mut router = SerialRouter::new();
        if let SerialFeed::Message(back) = router.feed(&pkts[0], 1000) {
            assert_eq!(back.payload, vec![VENDOR_STATUS_NEED_BINDING]);
        } else {
            panic!("backup deny must re-parse as a message");
        }
    }

    #[test]
    fn vendor_dispatch_mirrors_ble_gates() {
        // USAGE without UP -> NEED_UP (0x01) in every mode.
        assert_eq!(dispatch_serial_vendor(0x26, false, false, false).0, 0x01);
        assert_eq!(dispatch_serial_vendor(0x26, false, false, true).0, 0x04);
        // CONFIG without binding: release denies NEED_BINDING; test-mode
        // bypasses binding but keeps UP/PIN (BLE parity: PIN-less GEN passes,
        // PIN-gated DELETE answers NEED_PIN sem sessão, 0x04 com sessão).
        let (st, _) = dispatch_serial_vendor(0x20, false, false, true);
        if crate::binding::binding_bypass_enabled() {
            assert_eq!(st, 0x04);
        } else {
            assert_eq!(st, VENDOR_STATUS_NEED_BINDING);
        }
        let (st_pin, _) = dispatch_serial_vendor(0x23, false, false, true);
        if crate::binding::binding_bypass_enabled() {
            assert_eq!(st_pin, 0x02);
        } else {
            assert_eq!(st_pin, VENDOR_STATUS_NEED_BINDING);
        }
        // F1: com sessão PIN viva, privilegiada passa (gate ok -> 0x04).
        let (st_ok, _) = dispatch_serial_vendor(0x23, false, true, true);
        if crate::binding::binding_bypass_enabled() {
            assert_eq!(st_ok, 0x04);
        } else {
            assert_eq!(st_ok, VENDOR_STATUS_NEED_BINDING);
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
        let ack = dispatch_serial_pairing_line("TEST_PAIRING_OPEN", &mut m, 5000).expect("ack");
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

    #[cfg(feature = "test-mode")]
    #[test]
    fn pairing_open_300_wide_window_same_gates() {
        use crate::pairing::{PairingManager, TEST_PAIRING_OPEN_300_SECS};
        let mut m = PairingManager::new();
        let ack = dispatch_serial_pairing_line("TEST_PAIRING_OPEN_300", &mut m, 5000).expect("ack");
        assert!(ack.contains("window_s=300"));
        assert!(m.is_pairing_window_open(5000));
        assert!(m.is_pairing_window_open(5000 + TEST_PAIRING_OPEN_300_SECS * 1000 - 1));
        assert!(!m.is_bonded());
        // Sem presenca nao completa, igual a janela de 60s.
        assert!(!m.complete_pairing(false, 5100));
        m.tick(5000 + TEST_PAIRING_OPEN_300_SECS * 1000);
        assert!(!m.is_pairing_window_open(5000 + TEST_PAIRING_OPEN_300_SECS * 1000));
    }

    #[cfg(feature = "test-mode")]
    #[test]
    fn pairing_close_ends_60s_window_and_reopen_works() {
        use crate::config::PAIRING_WINDOW_MS;
        use crate::pairing::{PairingManager, PairingState};
        let mut m = PairingManager::new();
        dispatch_serial_pairing_line("TEST_PAIRING_OPEN", &mut m, 5000).expect("ack");
        assert!(m.is_pairing_window_open(5000));
        let ack = dispatch_serial_pairing_line("TEST_PAIRING_CLOSE", &mut m, 5100).expect("ack");
        assert!(ack.contains("pairing_closed"));
        assert!(ack.contains("source=software"));
        assert_eq!(m.state(), PairingState::Locked);
        assert!(!m.is_pairing_window_open(5100));
        assert!(!m.is_bonded());
        // Reabrir volta a funcionar (determinismo entre sessões sem reset).
        let reopen = dispatch_serial_pairing_line("TEST_PAIRING_OPEN", &mut m, 6000).expect("ack");
        assert!(reopen.contains("pairing_open"));
        assert!(m.is_pairing_window_open(6000));
        assert!(!m.is_bonded());
        m.tick(6000 + PAIRING_WINDOW_MS);
        assert!(!m.is_pairing_window_open(6000 + PAIRING_WINDOW_MS));
    }

    #[cfg(feature = "test-mode")]
    #[test]
    fn pairing_close_ends_300s_window_and_reopen_works() {
        use crate::pairing::{PairingManager, PairingState, TEST_PAIRING_OPEN_300_SECS};
        let mut m = PairingManager::new();
        dispatch_serial_pairing_line("TEST_PAIRING_OPEN_300", &mut m, 5000).expect("ack");
        assert!(m.is_pairing_window_open(5000 + TEST_PAIRING_OPEN_300_SECS * 1000 - 1));
        let ack = dispatch_serial_pairing_line("TEST_PAIRING_CLOSE", &mut m, 5100).expect("ack");
        assert!(ack.contains("pairing_closed"));
        assert!(ack.contains("source=software"));
        assert_eq!(m.state(), PairingState::Locked);
        assert!(!m.is_pairing_window_open(5100));
        assert!(!m.is_bonded());
        // Reabrir (300s) volta a funcionar.
        dispatch_serial_pairing_line("TEST_PAIRING_OPEN_300", &mut m, 6000).expect("ack");
        assert!(m.is_pairing_window_open(6000 + TEST_PAIRING_OPEN_300_SECS * 1000 - 1));
        assert!(!m.is_bonded());
    }

    #[cfg(not(feature = "test-mode"))]
    #[test]
    fn pairing_open_unknown_without_test_mode() {
        use crate::pairing::PairingManager;
        let mut m = PairingManager::new();
        assert!(dispatch_serial_pairing_line("TEST_PAIRING_OPEN", &mut m, 0).is_none());
        assert!(!m.is_pairing_window_open(0));
    }

    #[cfg(not(feature = "test-mode"))]
    #[test]
    fn pairing_close_unknown_without_test_mode() {
        use crate::pairing::PairingManager;
        let mut m = PairingManager::new();
        assert!(dispatch_serial_pairing_line("TEST_PAIRING_CLOSE", &mut m, 0).is_none());
        assert!(!m.is_pairing_window_open(0));
    }

    #[test]
    fn serial_vendor_parity_matrix_all_ops() {
        use crate::ble::dispatch_bind::authorize_vendor_op;
        use crate::ble::gatt_core::OP_OATH_CODE;
        // Full 0x20-0x27 x (vinculo x PIN x UP): serial responde o mesmo
        // status do BLE (paridade exata, F1).
        for op in 0x20u8..=0x27u8 {
            for binding_ok in [false, true] {
                for pin in [false, true] {
                    for up in [false, true] {
                        let (st_s, _) = dispatch_serial_vendor(op, binding_ok, pin, up);
                        let st_b = match authorize_vendor_op(op, binding_ok, pin, up) {
                            Ok(()) => 0x04,
                            Err(e) => e.to_vendor_status(),
                        };
                        assert_eq!(
                            st_s, st_b,
                            "op {:02X} bind={} pin={} up={}",
                            op, binding_ok, pin, up
                        );
                    }
                }
            }
        }
        assert_eq!(
            dispatch_serial_vendor(OP_OATH_CODE, false, false, true).0,
            0x04
        );
        assert_eq!(
            dispatch_serial_vendor(OP_OATH_CODE, false, false, false).0,
            0x01
        );
    }

    #[test]
    fn serial_bind_consumes_up_only_where_ble_needs_up() {
        use crate::ble::gatt_core as g;
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
        use crate::ble::gatt_core as g;
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
            dispatch_serial_bind_mgmt(
                g::OP_BIND_CLAIM,
                &[0x01, 0x02],
                true,
                true,
                &mut b,
                &mut s,
                &mut rng
            )
            .0,
            0x04
        );
        assert_eq!(
            dispatch_serial_bind_mgmt(
                g::OP_BIND_CHALLENGE,
                &[0x01],
                true,
                true,
                &mut b,
                &mut s,
                &mut rng
            )
            .0,
            0x04
        );
        assert_eq!(
            dispatch_serial_bind_mgmt(
                g::OP_BIND_VERIFY,
                &[0x22],
                true,
                true,
                &mut b,
                &mut s,
                &mut rng
            )
            .0,
            0x04
        );
        assert_eq!(
            dispatch_serial_bind_mgmt(
                g::OP_BIND_RELEASE,
                &[0x00; 10],
                true,
                true,
                &mut b,
                &mut s,
                &mut rng
            )
            .0,
            0x04
        );
        assert_eq!(
            dispatch_serial_bind_mgmt(
                g::OP_RECOVERY_SET,
                &[0xFF],
                true,
                true,
                &mut b,
                &mut s,
                &mut rng
            )
            .0,
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
        assert!(!crate::ble::dispatch_bind::is_bind_mgmt_op(
            RESCUE_TRANSPORT_OP
        ));
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
        use crate::binding::{BindingManager, BIND_ID_LEN, BIND_PUB_LEN};
        use crate::ble::dispatch_bind as gd;
        use crate::ble::gatt_core as g;
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
            let st_b = gd::dispatch_bind_claim(&mut b2, &mut s2, &sec1, &id, false, false)
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
            let (st_b, body_b) =
                match gd::dispatch_bind_claim(&mut b2, &mut s2, &sec1, &id, true, true) {
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
            let st_b2 = gd::dispatch_bind_claim(&mut b2, &mut s2, &sec1, &id, true, true)
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
            let st_b = gd::dispatch_bind_challenge(&mut b2, &s2, &mut rng)
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
            let ble_ch = gd::dispatch_bind_challenge(&mut b2, &s2, &mut rng).expect("ch ble");
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
            let st_b = gd::dispatch_bind_verify(&mut b2, &p[65..], &ch, g::OP_KEY_LIST, &ph)
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
            let ch1 = gd::dispatch_bind_challenge(&mut b1, &s1, &mut rng).expect("ch1");
            let ch2 = gd::dispatch_bind_challenge(&mut b2, &s2, &mut rng).expect("ch2");
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
            gd::dispatch_bind_verify(&mut b2, &der2, &ch2, g::OP_KEY_LIST, &ph)
                .expect("verify ble");
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
            let st_b = gd::dispatch_bind_release(&mut b2, &mut s2, &p[64..], &ch, &ph, false)
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
            let st_b = gd::dispatch_bind_release(&mut b2, &mut s2, &p[64..], &ch, &ph, true)
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
            for (pin, up, want) in [
                ("123", true, 0x02),
                ("4242", false, 0x01),
                ("4242", true, 0x00),
            ] {
                let (st_s, _) = dispatch_serial_bind_mgmt(
                    g::OP_RECOVERY_SET,
                    pin.as_bytes(),
                    true,
                    up,
                    &mut b1,
                    &mut s1,
                    &mut rng,
                );
                let st_b = gd::dispatch_recovery_set(&mut s2, pin, up)
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
            gd::dispatch_recovery_set(&mut s1, "4242", true).expect("set");
            b2.claim(&sec1, &id, true, true).expect("claim");
            b2.persist(&mut s2).expect("persist");
            gd::dispatch_recovery_set(&mut s2, "4242", true).expect("set");
            let (st_s, _) = dispatch_serial_bind_mgmt(
                g::OP_RECOVERY_UNLOCK,
                b"0000",
                true,
                true,
                &mut b1,
                &mut s1,
                &mut rng,
            );
            let st_b = gd::dispatch_recovery_unlock(&mut s2, &mut b2, "0000", true)
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
            let st_b = gd::dispatch_recovery_unlock(&mut s2, &mut b2, "4242", true)
                .map(|_| 0x00)
                .unwrap_or_else(|e| e.to_vendor_status());
            assert_eq!((st_s, st_b), (0x00, 0x00));
            assert!(!b1.is_claimed() && !b2.is_claimed());
        }
    }
}
