//! Transport abstraction for CTAPHID USB without logic change.
//!
//! Moves the current USB framing/deframing behind a `Transport`
//! trait (`send`/`recv`/`poll`) so firmware and tests depend on the
//! trait. The `CtapHidManager` impl delegates to existing
//! `CtapHidFramer`/`process_packet` with identical frames/timing.

use super::ctaphid::{CtapHidError, CtapHidFramer, CtapHidManager, CtapHidMessage, PACKET_SIZE};

/// Minimal USB transport: send frames, receive packets, poll readiness.
pub trait Transport {
    /// Frames `payload` for `cid`/`cmd` into 64-byte USB packets.
    fn send(&mut self, cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; PACKET_SIZE]>;
    /// Feeds one 64-byte raw packet; returns completed message if any.
    fn recv(
        &mut self,
        raw: &[u8; PACKET_SIZE],
        now_ms: u64,
    ) -> Result<Option<CtapHidMessage>, CtapHidError>;
    /// Returns true when the channel can accept new messages.
    fn poll(&self, now_ms: u64) -> bool;
}

impl Transport for CtapHidManager {
    fn send(&mut self, cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; PACKET_SIZE]> {
        CtapHidFramer::frame_message(cid, cmd, payload)
    }

    fn recv(
        &mut self,
        raw: &[u8; PACKET_SIZE],
        now_ms: u64,
    ) -> Result<Option<CtapHidMessage>, CtapHidError> {
        self.process_packet(raw, now_ms)
    }

    fn poll(&self, now_ms: u64) -> bool {
        !self.is_locked(now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ctaphid::{CMD_CBOR, CMD_MSG};

    #[test]
    fn transport_send_recv_roundtrip() {
        let mut mgr = CtapHidManager::new();
        let payload = b"transport-test".to_vec();
        let pkts = mgr.send(0x11223344, CMD_CBOR, &payload);
        assert_eq!(pkts.len(), 1);
        let msg = mgr.recv(&pkts[0], 1000).unwrap().unwrap();
        assert_eq!(msg.cmd, CMD_CBOR);
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn transport_poll_respects_lock() {
        let mut mgr = CtapHidManager::new();
        assert!(mgr.poll(0));
        mgr.set_lock(1, 5, 0).unwrap();
        assert!(!mgr.poll(1000));
        assert!(mgr.poll(6000));
        // CMD_MSG path also covered via send
        let pkts = mgr.send(1, CMD_MSG, b"hi");
        assert_eq!(pkts.len(), 1);
    }
}
