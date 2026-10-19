//! CTAPHID protocol framer, deframer, channel manager and packet processing.
//!
//! Compliant with FIDO2 / CTAP 2.1, 2.2 and 2.3 specifications.
//! 100% Native Rust implementation.

use core::fmt;

/// Standard CTAPHID packet size (64 bytes for USB Full/High Speed interrupt transfer).
pub const PACKET_SIZE: usize = 64;

/// Size of the header in an INIT packet:
/// CID (4) + CMD (1) + BCNT (2) = 7 bytes.
pub const INIT_HEADER_SIZE: usize = 7;

/// Maximum payload in an INIT packet: 64 - 7 = 57 bytes.
pub const INIT_PAYLOAD_SIZE: usize = PACKET_SIZE - INIT_HEADER_SIZE;

/// Size of the header in a CONT packet:
/// CID (4) + SEQ (1) = 5 bytes.
pub const CONT_HEADER_SIZE: usize = 5;

/// Maximum payload in a CONT packet: 64 - 5 = 59 bytes.
pub const CONT_PAYLOAD_SIZE: usize = PACKET_SIZE - CONT_HEADER_SIZE;

/// Maximum possible message length in CTAPHID protocol:
/// 57 + (128 * 59) = 7609 bytes.
pub const MAX_MSG_LEN: usize = INIT_PAYLOAD_SIZE + (128 * CONT_PAYLOAD_SIZE);

/// CTAPHID Broadcast Channel ID.
pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;

/// Reserved Channel ID (Unassigned).
pub const RESERVED_CID: u32 = 0x0000_0000;

/// Default message assembly timeout in milliseconds (3.0 seconds as per FIDO spec).
pub const MSG_TIMEOUT_MS: u64 = 3000;

// ============================================================================
// CTAPHID Commands (Bit 7 MUST always be set: 0x80 | cmd)
// ============================================================================
pub const CMD_PING: u8 = 0x81;
pub const CMD_MSG: u8 = 0x83;
pub const CMD_LOCK: u8 = 0x84;
pub const CMD_INIT: u8 = 0x86;
pub const CMD_WINK: u8 = 0x88;
pub const CMD_CBOR: u8 = 0x90;
pub const CMD_CANCEL: u8 = 0x91;
pub const CMD_KEEPALIVE: u8 = 0xBB;
pub const CMD_ERROR: u8 = 0xBF;
pub const CMD_VENDOR_FIRST: u8 = 0xC0;
pub const CMD_VENDOR_LAST: u8 = 0xFF;

// ============================================================================
// CTAPHID Error Codes
// ============================================================================
pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_PAR: u8 = 0x02;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_SEQ: u8 = 0x04;
pub const ERR_MSG_TIMEOUT: u8 = 0x05;
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
pub const ERR_LOCK_REQUIRED: u8 = 0x0A;
pub const ERR_INVALID_CHANNEL: u8 = 0x0B;
pub const ERR_OTHER: u8 = 0x7F;

// ============================================================================
// CTAPHID Keepalive Status
// ============================================================================
pub const STATUS_PROCESSING: u8 = 0x01;
pub const STATUS_UPNEEDED: u8 = 0x02;

// ============================================================================
// CTAPHID Capabilities Flags
// ============================================================================
pub const CAPABILITY_WINK: u8 = 0x01;
pub const CAPABILITY_LOCK: u8 = 0x02;
pub const CAPABILITY_CBOR: u8 = 0x04;
pub const CAPABILITY_NMSG: u8 = 0x08;

/// Represents a fully assembled CTAPHID message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtapHidMessage {
    pub cid: u32,
    pub cmd: u8,
    pub payload: Vec<u8>,
}

impl CtapHidMessage {
    pub fn new(cid: u32, cmd: u8, payload: Vec<u8>) -> Self {
        Self { cid, cmd, payload }
    }
}

/// A parsed CTAPHID raw USB packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawPacket<'a> {
    Init {
        cid: u32,
        cmd: u8,
        total_len: u16,
        payload: &'a [u8],
    },
    Cont {
        cid: u32,
        seq: u8,
        payload: &'a [u8],
    },
}

/// Errors returned by the CTAPHID packet parser / deframer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtapHidError {
    pub cid: u32,
    pub code: u8,
}

impl CtapHidError {
    pub fn new(cid: u32, code: u8) -> Self {
        Self { cid, code }
    }

    /// Creates a 64-byte CTAPHID_ERROR response packet.
    pub fn to_packet(&self) -> [u8; PACKET_SIZE] {
        let mut packet = [0u8; PACKET_SIZE];
        packet[0..4].copy_from_slice(&self.cid.to_be_bytes());
        packet[4] = CMD_ERROR;
        packet[5..7].copy_from_slice(&1u16.to_be_bytes());
        packet[7] = self.code;
        packet
    }
}

impl fmt::Display for CtapHidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CTAPHID Error(CID: 0x{:08X}, Code: 0x{:02X})", self.cid, self.code)
    }
}

/// State of an active message reassembly.
#[derive(Debug, Clone)]
struct AssemblyState {
    cid: u32,
    cmd: u8,
    expected_len: usize,
    payload: Vec<u8>,
    expected_seq: u8,
    last_packet_time_ms: u64,
}

/// Channel Manager and Protocol Deframer.
pub struct CtapHidManager {
    next_cid: u32,
    active_assembly: Option<AssemblyState>,
    locked_channel: Option<(u32, u64)>, // (cid, lock_expiry_ms)
}

impl Default for CtapHidManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CtapHidManager {
    /// Creates a new CTAPHID channel manager.
    pub fn new() -> Self {
        Self {
            next_cid: 1,
            active_assembly: None,
            locked_channel: None,
        }
    }

    /// Allocates a new unique non-zero, non-broadcast Channel ID (CID).
    pub fn allocate_cid(&mut self) -> u32 {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        if self.next_cid == RESERVED_CID || self.next_cid == BROADCAST_CID {
            self.next_cid = 1;
        }
        cid
    }

    /// Validates if a CID is currently valid for requests.
    pub fn is_valid_cid(&self, cid: u32) -> bool {
        cid != RESERVED_CID
    }

    /// Checks if a channel lock is active.
    pub fn is_locked(&self, now_ms: u64) -> bool {
        if let Some((_, expiry)) = self.locked_channel {
            now_ms < expiry
        } else {
            false
        }
    }

    /// True while a multi-packet message is being reassembled.
    ///
    /// Lets a shared-wire transport (serial logs + CTAPHID on one UART)
    /// suppress log text mid-transaction so binary framing never interleaves.
    pub fn has_pending_assembly(&self) -> bool {
        self.active_assembly.is_some()
    }

    /// Locks the channel for the specified duration (in seconds, up to 10s).
    pub fn set_lock(&mut self, cid: u32, lock_secs: u8, now_ms: u64) -> Result<(), CtapHidError> {
        if lock_secs == 0 {
            if let Some((locked_cid, _)) = self.locked_channel {
                if locked_cid == cid {
                    self.locked_channel = None;
                    return Ok(());
                } else {
                    return Err(CtapHidError::new(cid, ERR_CHANNEL_BUSY));
                }
            }
            return Ok(());
        }

        let duration_ms = (lock_secs.min(10) as u64) * 1000;
        if let Some((locked_cid, expiry)) = self.locked_channel {
            if now_ms < expiry && locked_cid != cid {
                return Err(CtapHidError::new(cid, ERR_CHANNEL_BUSY));
            }
        }
        self.locked_channel = Some((cid, now_ms + duration_ms));
        Ok(())
    }

    /// Parses an incoming 64-byte raw USB packet into an INIT or CONT descriptor.
    pub fn parse_raw_packet(raw: &[u8; PACKET_SIZE]) -> Result<RawPacket<'_>, CtapHidError> {
        let cid = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        if cid == RESERVED_CID {
            return Err(CtapHidError::new(cid, ERR_INVALID_CHANNEL));
        }

        let cmd_or_seq = raw[4];
        if (cmd_or_seq & 0x80) != 0 {
            // INIT Packet (Bit 7 is set)
            let total_len = u16::from_be_bytes([raw[5], raw[6]]);
            if (total_len as usize) > MAX_MSG_LEN {
                return Err(CtapHidError::new(cid, ERR_INVALID_LEN));
            }
            let payload_len = (total_len as usize).min(INIT_PAYLOAD_SIZE);
            Ok(RawPacket::Init {
                cid,
                cmd: cmd_or_seq,
                total_len,
                payload: &raw[7..7 + payload_len],
            })
        } else {
            // CONT Packet (Bit 7 is cleared)
            let seq = cmd_or_seq & 0x7F;
            Ok(RawPacket::Cont {
                cid,
                seq,
                payload: &raw[5..PACKET_SIZE],
            })
        }
    }

    /// Processes an incoming raw 64-byte packet.
    ///
    /// If the packet completes a message, returns `Ok(Some(CtapHidMessage))`.
    /// If more packets are expected, returns `Ok(None)`.
    /// If a protocol violation occurs, returns `Err(CtapHidError)` with the error code.
    pub fn process_packet(
        &mut self,
        raw: &[u8; PACKET_SIZE],
        now_ms: u64,
    ) -> Result<Option<CtapHidMessage>, CtapHidError> {
        // Check timeout on active assembly
        if let Some(ref state) = self.active_assembly {
            if now_ms.saturating_sub(state.last_packet_time_ms) > MSG_TIMEOUT_MS {
                let timed_out_cid = state.cid;
                self.active_assembly = None;
                return Err(CtapHidError::new(timed_out_cid, ERR_MSG_TIMEOUT));
            }
        }

        let packet = Self::parse_raw_packet(raw)?;

        match packet {
            RawPacket::Init {
                cid,
                cmd,
                total_len,
                payload,
            } => {
                // If channel is locked to someone else, reject
                if let Some((locked_cid, expiry)) = self.locked_channel {
                    if now_ms < expiry && locked_cid != cid {
                        return Err(CtapHidError::new(cid, ERR_CHANNEL_BUSY));
                    }
                }

                // If Broadcast CID, only CMD_INIT is allowed
                if cid == BROADCAST_CID && cmd != CMD_INIT {
                    return Err(CtapHidError::new(cid, ERR_INVALID_CMD));
                }

                // If CMD_CANCEL is received, cancel any pending assembly on this channel
                if cmd == CMD_CANCEL {
                    if let Some(ref state) = self.active_assembly {
                        if state.cid == cid {
                            self.active_assembly = None;
                        }
                    }
                    return Ok(Some(CtapHidMessage::new(cid, cmd, Vec::new())));
                }

                // If another channel is currently in mid-assembly, return BUSY
                if let Some(ref state) = self.active_assembly {
                    if state.cid != cid {
                        return Err(CtapHidError::new(cid, ERR_CHANNEL_BUSY));
                    }
                }

                let total_len = total_len as usize;
                if total_len <= INIT_PAYLOAD_SIZE {
                    // Single-packet message complete!
                    self.active_assembly = None;
                    Ok(Some(CtapHidMessage::new(cid, cmd, payload.to_vec())))
                } else {
                    // Multi-packet message started
                    let mut full_payload = Vec::with_capacity(total_len);
                    full_payload.extend_from_slice(payload);
                    self.active_assembly = Some(AssemblyState {
                        cid,
                        cmd,
                        expected_len: total_len,
                        payload: full_payload,
                        expected_seq: 0,
                        last_packet_time_ms: now_ms,
                    });
                    Ok(None)
                }
            }

            RawPacket::Cont { cid, seq, payload } => {
                let state = match self.active_assembly.as_mut() {
                    Some(s) if s.cid == cid => s,
                    Some(_) => {
                        // Packet received for different CID while busy
                        return Err(CtapHidError::new(cid, ERR_CHANNEL_BUSY));
                    }
                    None => {
                        // Unexpected continuation packet without prior INIT
                        return Err(CtapHidError::new(cid, ERR_INVALID_SEQ));
                    }
                };

                // Validate sequence number
                if seq != state.expected_seq {
                    let err_cid = state.cid;
                    self.active_assembly = None;
                    return Err(CtapHidError::new(err_cid, ERR_INVALID_SEQ));
                }

                state.last_packet_time_ms = now_ms;
                state.expected_seq = state.expected_seq.wrapping_add(1);

                let remaining = state.expected_len - state.payload.len();
                let to_take = remaining.min(CONT_PAYLOAD_SIZE);
                state.payload.extend_from_slice(&payload[..to_take]);

                if state.payload.len() >= state.expected_len {
                    // Message complete!
                    let finished = self.active_assembly.take().unwrap();
                    Ok(Some(CtapHidMessage::new(
                        finished.cid,
                        finished.cmd,
                        finished.payload,
                    )))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

// ============================================================================
// Frame Generators (Serialization to 64-byte USB packets)
// ============================================================================

/// Packet framer that splits a complete message into 64-byte USB packets.
pub struct CtapHidFramer;

impl CtapHidFramer {
    /// Encodes a full CTAPHID response message into a sequence of 64-byte USB packets.
    pub fn frame_message(cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; PACKET_SIZE]> {
        let total_len = payload.len();
        let mut packets = Vec::new();

        // 1. INIT Packet
        let mut init_pkt = [0u8; PACKET_SIZE];
        init_pkt[0..4].copy_from_slice(&cid.to_be_bytes());
        init_pkt[4] = cmd | 0x80; // Ensure command bit 7 is set
        init_pkt[5..7].copy_from_slice(&(total_len as u16).to_be_bytes());

        let init_chunk_len = total_len.min(INIT_PAYLOAD_SIZE);
        init_pkt[7..7 + init_chunk_len].copy_from_slice(&payload[..init_chunk_len]);
        packets.push(init_pkt);

        let mut offset = init_chunk_len;
        let mut seq: u8 = 0;

        // 2. CONT Packets
        while offset < total_len {
            let mut cont_pkt = [0u8; PACKET_SIZE];
            cont_pkt[0..4].copy_from_slice(&cid.to_be_bytes());
            cont_pkt[4] = seq & 0x7F; // Sequence number (bit 7 = 0)

            let chunk_len = (total_len - offset).min(CONT_PAYLOAD_SIZE);
            cont_pkt[5..5 + chunk_len].copy_from_slice(&payload[offset..offset + chunk_len]);
            packets.push(cont_pkt);

            offset += chunk_len;
            seq = seq.wrapping_add(1);
        }

        packets
    }

    /// Generates a 64-byte INIT response packet.
    ///
    /// Response format:
    /// - Nonce (8 bytes, matching host nonce)
    /// - New CID (4 bytes, big endian)
    /// - CTAPHID Protocol version (1 byte, 2)
    /// - Major version (1 byte)
    /// - Minor version (1 byte)
    /// - Build version (1 byte)
    /// - Capabilities (1 byte: WINK=1, CBOR=4, NMSG=8)
    pub fn frame_init_response(
        req_cid: u32,
        nonce: &[u8; 8],
        new_cid: u32,
        major: u8,
        minor: u8,
        build: u8,
        capabilities: u8,
    ) -> [u8; PACKET_SIZE] {
        let mut resp_payload = [0u8; 17];
        resp_payload[0..8].copy_from_slice(nonce);
        resp_payload[8..12].copy_from_slice(&new_cid.to_be_bytes());
        resp_payload[12] = 2; // CTAPHID version 2
        resp_payload[13] = major;
        resp_payload[14] = minor;
        resp_payload[15] = build;
        resp_payload[16] = capabilities;

        let packets = Self::frame_message(req_cid, CMD_INIT, &resp_payload);
        packets[0]
    }

    /// Generates a 64-byte KEEPALIVE status packet.
    pub fn frame_keepalive(cid: u32, status: u8) -> [u8; PACKET_SIZE] {
        let mut pkt = [0u8; PACKET_SIZE];
        pkt[0..4].copy_from_slice(&cid.to_be_bytes());
        pkt[4] = CMD_KEEPALIVE;
        pkt[5..7].copy_from_slice(&1u16.to_be_bytes());
        pkt[7] = status;
        pkt
    }

    /// Generates a 64-byte ERROR packet.
    pub fn frame_error(cid: u32, err_code: u8) -> [u8; PACKET_SIZE] {
        CtapHidError::new(cid, err_code).to_packet()
    }

    /// Generates an echo response for PING.
    pub fn frame_ping(cid: u32, data: &[u8]) -> Vec<[u8; PACKET_SIZE]> {
        Self::frame_message(cid, CMD_PING, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_packet_roundtrip() {
        let cid = 0x11223344;
        let payload = b"Hello AegisKey!".to_vec();
        let packets = CtapHidFramer::frame_message(cid, CMD_CBOR, &payload);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].len(), 64);

        let mut mgr = CtapHidManager::new();
        let res = mgr.process_packet(&packets[0], 1000).unwrap();
        assert!(res.is_some());
        let msg = res.unwrap();
        assert_eq!(msg.cid, cid);
        assert_eq!(msg.cmd, CMD_CBOR);
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn test_multi_packet_roundtrip() {
        let cid = 0xAABBCCDD;
        // 200 bytes payload requires 1 INIT (57 bytes) + 3 CONT (59 + 59 + 25 bytes) = 4 packets
        let mut payload = Vec::with_capacity(200);
        for i in 0..200 {
            payload.push((i % 256) as u8);
        }

        let packets = CtapHidFramer::frame_message(cid, CMD_MSG, &payload);
        assert_eq!(packets.len(), 4);

        let mut mgr = CtapHidManager::new();
        assert_eq!(mgr.process_packet(&packets[0], 1000).unwrap(), None);
        assert_eq!(mgr.process_packet(&packets[1], 1010).unwrap(), None);
        assert_eq!(mgr.process_packet(&packets[2], 1020).unwrap(), None);

        let final_res = mgr.process_packet(&packets[3], 1030).unwrap();
        assert!(final_res.is_some());
        let msg = final_res.unwrap();
        assert_eq!(msg.cid, cid);
        assert_eq!(msg.cmd, CMD_MSG);
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn test_init_allocation_and_handshake() {
        let mut mgr = CtapHidManager::new();
        let cid1 = mgr.allocate_cid();
        let cid2 = mgr.allocate_cid();
        assert_eq!(cid1, 1);
        assert_eq!(cid2, 2);

        let nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let init_resp = CtapHidFramer::frame_init_response(
            BROADCAST_CID,
            &nonce,
            cid1,
            1,
            0,
            0,
            CAPABILITY_CBOR | CAPABILITY_WINK,
        );

        let parsed = CtapHidManager::parse_raw_packet(&init_resp).unwrap();
        match parsed {
            RawPacket::Init { cid, cmd, total_len, payload } => {
                assert_eq!(cid, BROADCAST_CID);
                assert_eq!(cmd, CMD_INIT);
                assert_eq!(total_len, 17);
                assert_eq!(&payload[0..8], &nonce);
                assert_eq!(&payload[8..12], &cid1.to_be_bytes());
                assert_eq!(payload[12], 2); // CTAPHID ver
                assert_eq!(payload[16], CAPABILITY_CBOR | CAPABILITY_WINK);
            }
            _ => panic!("Expected INIT packet"),
        }
    }

    #[test]
    fn test_keepalive_packet() {
        let cid = 0x12345678;
        let pkt = CtapHidFramer::frame_keepalive(cid, STATUS_UPNEEDED);
        assert_eq!(&pkt[0..4], &cid.to_be_bytes());
        assert_eq!(pkt[4], CMD_KEEPALIVE);
        assert_eq!(&pkt[5..7], &[0x00, 0x01]);
        assert_eq!(pkt[7], STATUS_UPNEEDED);
    }

    #[test]
    fn test_error_handling_invalid_seq() {
        let cid = 0x44332211;
        let payload = vec![0u8; 100];
        let packets = CtapHidFramer::frame_message(cid, CMD_CBOR, &payload);

        let mut mgr = CtapHidManager::new();
        assert_eq!(mgr.process_packet(&packets[0], 1000).unwrap(), None);

        // Send packet with seq 2 instead of seq 0
        let mut bad_packet = packets[1];
        bad_packet[4] = 2; // bad seq
        let err = mgr.process_packet(&bad_packet, 1010).unwrap_err();
        assert_eq!(err.code, ERR_INVALID_SEQ);
    }

    #[test]
    fn test_reassembly_timeout() {
        let cid = 0x44332211;
        let payload = vec![0u8; 100];
        let packets = CtapHidFramer::frame_message(cid, CMD_CBOR, &payload);

        let mut mgr = CtapHidManager::new();
        assert_eq!(mgr.process_packet(&packets[0], 1000).unwrap(), None);

        // Send next packet after 3500ms (> 3000ms timeout)
        let err = mgr.process_packet(&packets[1], 4501).unwrap_err();
        assert_eq!(err.code, ERR_MSG_TIMEOUT);
    }
}
