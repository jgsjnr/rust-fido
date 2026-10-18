//! USB CCID (Smart Card / PC/SC) Protocol Transport & APDU Parser.
//!
//! Compliant with ISO 7816-4 and USB CCID Specification Rev 1.1.
//! Supports Yubico OATH applet (YKOATH) and FIDO U2F/CTAP applet routing.
//! 100% Native Rust implementation.

/// Standard ATR (Answer To Reset) for AegisKey SmartCard emulation.
pub const AEGIS_ATR: &[u8] = &[
    0x3B, 0x8D, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10,
    0x00, 0x01, 0x00,
];

// ============================================================================
// CCID Command Message Types (PC -> Reader)
// ============================================================================
pub const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
pub const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
pub const PC_TO_RDR_GET_SLOT_STATUS: u8 = 0x65;
pub const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;
pub const PC_TO_RDR_GET_PARAMETERS: u8 = 0x6C;
pub const PC_TO_RDR_RESET_PARAMETERS: u8 = 0x6D;
pub const PC_TO_RDR_SET_PARAMETERS: u8 = 0x61;
pub const PC_TO_RDR_ESCAPE: u8 = 0x6B;

// ============================================================================
// CCID Response Message Types (Reader -> PC)
// ============================================================================
pub const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
pub const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;
pub const RDR_TO_PC_PARAMETERS: u8 = 0x82;
pub const RDR_TO_PC_ESCAPE: u8 = 0x83;

// ============================================================================
// ISO 7816-4 Status Words (SW1 SW2)
// ============================================================================
pub const SW_OK: (u8, u8) = (0x90, 0x00);
pub const SW_NOT_FOUND: (u8, u8) = (0x6A, 0x82);
pub const SW_WRONG_LENGTH: (u8, u8) = (0x67, 0x00);
pub const SW_CONDITIONS_NOT_SATISFIED: (u8, u8) = (0x69, 0x85);
pub const SW_SECURITY_STATUS_NOT_SATISFIED: (u8, u8) = (0x69, 0x82);
pub const SW_WRONG_P1P2: (u8, u8) = (0x6B, 0x00);
pub const SW_INS_NOT_SUPPORTED: (u8, u8) = (0x6D, 0x00);
pub const SW_CLA_NOT_SUPPORTED: u8 = 0x6E;
pub const SW_UNKNOWN_ERROR: (u8, u8) = (0x6F, 0x00);

// ============================================================================
// Well-known Application IDs (AID)
// ============================================================================
/// Yubico OATH Application ID: A0 00 00 05 27 21 01
pub const AID_YKOATH: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

/// FIDO U2F Application ID: A0 00 00 06 47 2F 00 01
pub const AID_FIDO_U2F: &[u8] = &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

/// PIV (Personal Identity Verification) Application ID: A0 00 00 03 08
pub const AID_PIV: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08];

/// Active Applet selected on the SmartCard interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedApplet {
    None,
    Oath,
    FidoU2f,
    Piv,
    Other,
}

/// Parsed ISO 7816-4 Command APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandApdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<usize>,
}

impl CommandApdu {
    /// Parses a raw byte buffer into an ISO 7816-4 Command APDU.
    /// Supports short APDUs and extended APDUs.
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 4 {
            return Err("APDU too short, minimum 4 bytes (CLA, INS, P1, P2)");
        }

        let cla = raw[0];
        let ins = raw[1];
        let p1 = raw[2];
        let p2 = raw[3];

        if raw.len() == 4 {
            // Case 1: Header only (No data, no Le)
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: None,
            });
        }

        let b4 = raw[4] as usize;

        if raw.len() == 5 {
            // Case 2S: Header + Le (1 byte, 0 = 256)
            let le = if b4 == 0 { 256 } else { b4 };
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: Some(le),
            });
        }

        if b4 != 0 {
            // Short APDU: Lc = b4
            let lc = b4;
            let data_end = 5 + lc;
            if raw.len() < data_end {
                return Err("Short APDU payload shorter than Lc");
            }
            let data = raw[5..data_end].to_vec();

            let le = if raw.len() > data_end {
                let le_byte = raw[data_end] as usize;
                Some(if le_byte == 0 { 256 } else { le_byte })
            } else {
                None
            };

            Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data,
                le,
            })
        } else {
            // Extended APDU: b4 == 0, followed by 2 bytes Lc or 2 bytes Le
            if raw.len() < 7 {
                return Err("Malformed extended APDU length field");
            }
            let lc = u16::from_be_bytes([raw[5], raw[6]]) as usize;
            if lc == 0 {
                // Extended Le only
                let le = if raw.len() >= 7 {
                    let val = u16::from_be_bytes([raw[5], raw[6]]) as usize;
                    Some(if val == 0 { 65536 } else { val })
                } else {
                    None
                };
                return Ok(Self {
                    cla,
                    ins,
                    p1,
                    p2,
                    data: Vec::new(),
                    le,
                });
            }

            let data_end = 7 + lc;
            if raw.len() < data_end {
                return Err("Extended APDU payload shorter than Lc");
            }
            let data = raw[7..data_end].to_vec();

            let le = if raw.len() >= data_end + 2 {
                let val = u16::from_be_bytes([raw[data_end], raw[data_end + 1]]) as usize;
                Some(if val == 0 { 65536 } else { val })
            } else {
                None
            };

            Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data,
                le,
            })
        }
    }
}

/// Represents an ISO 7816-4 Response APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseApdu {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl ResponseApdu {
    pub fn ok(data: Vec<u8>) -> Self {
        Self {
            data,
            sw1: SW_OK.0,
            sw2: SW_OK.1,
        }
    }

    pub fn status(sw: (u8, u8)) -> Self {
        Self {
            data: Vec::new(),
            sw1: sw.0,
            sw2: sw.1,
        }
    }

    /// Serializes to data + SW1 + SW2.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data.len() + 2);
        out.extend_from_slice(&self.data);
        out.push(self.sw1);
        out.push(self.sw2);
        out
    }
}

/// Trait for dispatching APDU commands to external engines (such as OATH or FIDO).
pub trait CcidApduHandler {
    fn handle_oath_apdu(&mut self, apdu: &CommandApdu) -> ResponseApdu;
    fn handle_fido_apdu(&mut self, apdu: &CommandApdu) -> ResponseApdu;
}

/// Default dummy handler for standalone testing.
pub struct DefaultCcidHandler;

impl CcidApduHandler for DefaultCcidHandler {
    fn handle_oath_apdu(&mut self, apdu: &CommandApdu) -> ResponseApdu {
        match apdu.ins {
            0xA1 => {
                // LIST OATH credentials (empty example list)
                ResponseApdu::ok(vec![])
            }
            0xA2 => {
                // CALCULATE
                ResponseApdu::status(SW_NOT_FOUND)
            }
            _ => ResponseApdu::status(SW_INS_NOT_SUPPORTED),
        }
    }

    fn handle_fido_apdu(&mut self, _apdu: &CommandApdu) -> ResponseApdu {
        ResponseApdu::status(SW_INS_NOT_SUPPORTED)
    }
}

/// USB CCID Transport Manager.
pub struct CcidTransport {
    pub selected_applet: SelectedApplet,
    pub card_powered: bool,
}

impl Default for CcidTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl CcidTransport {
    pub fn new() -> Self {
        Self {
            selected_applet: SelectedApplet::None,
            card_powered: false,
        }
    }

    /// Processes an incoming USB CCID message (minimum 10-byte header).
    ///
    /// Returns the raw USB response buffer to be sent back on Bulk-IN endpoint.
    pub fn process_ccid_message<H: CcidApduHandler>(
        &mut self,
        packet: &[u8],
        handler: &mut H,
    ) -> Result<Vec<u8>, &'static str> {
        if packet.len() < 10 {
            return Err("CCID packet too short (< 10 bytes)");
        }

        let msg_type = packet[0];
        let length = u32::from_le_bytes([packet[1], packet[2], packet[3], packet[4]]) as usize;
        let slot = packet[5];
        let seq = packet[6];

        if packet.len() < 10 + length {
            return Err("CCID payload length mismatch");
        }

        let payload = &packet[10..10 + length];

        match msg_type {
            PC_TO_RDR_ICC_POWER_ON => {
                self.card_powered = true;
                // Return RDR_to_PC_DataBlock containing ATR
                Ok(Self::build_data_block_response(slot, seq, AEGIS_ATR))
            }

            PC_TO_RDR_ICC_POWER_OFF => {
                self.card_powered = false;
                self.selected_applet = SelectedApplet::None;
                Ok(Self::build_slot_status_response(slot, seq, 0x02)) // 0x02: Card absent/powered off
            }

            PC_TO_RDR_GET_SLOT_STATUS => {
                let status = if self.card_powered { 0x00 } else { 0x01 };
                Ok(Self::build_slot_status_response(slot, seq, status))
            }

            PC_TO_RDR_GET_PARAMETERS => {
                // Return default T=1 protocol parameters
                let mut resp = vec![0u8; 17];
                resp[0] = RDR_TO_PC_PARAMETERS;
                resp[1..5].copy_from_slice(&7u32.to_le_bytes()); // Length 7
                resp[5] = slot;
                resp[6] = seq;
                resp[7] = 0; // bStatus
                resp[8] = 0; // bError
                resp[9] = 1; // Protocol: T=1
                resp[10] = 0x11; // Fi/Di
                resp[11] = 0x10; // TCCKS
                resp[12] = 0x00; // GuardTime
                resp[13] = 0x4D; // BWI / CWI
                resp[14] = 0x00; // ClockStop
                resp[15] = 0x20; // IFSC (32 bytes)
                resp[16] = 0x00; // NAD
                Ok(resp)
            }

            PC_TO_RDR_XFR_BLOCK => {
                if !self.card_powered {
                    let mut resp = Self::build_data_block_response(slot, seq, &[]);
                    resp[7] = 0x01; // bStatus: error / slot not powered
                    return Ok(resp);
                }

                let apdu = CommandApdu::parse(payload)?;
                let resp_apdu = self.handle_apdu(&apdu, handler);
                Ok(Self::build_data_block_response(slot, seq, &resp_apdu.to_bytes()))
            }

            _ => {
                // Unsupported CCID command
                let mut resp = Self::build_slot_status_response(slot, seq, 0x01);
                resp[8] = 0x01; // bError: Command not supported
                Ok(resp)
            }
        }
    }

    /// Internal APDU router.
    fn handle_apdu<H: CcidApduHandler>(
        &mut self,
        apdu: &CommandApdu,
        handler: &mut H,
    ) -> ResponseApdu {
        // Check for SELECT APDU (INS = 0xA4)
        if apdu.ins == 0xA4 && apdu.p1 == 0x04 {
            if apdu.data == AID_YKOATH {
                self.selected_applet = SelectedApplet::Oath;
                // Return YKOATH applet version / name: "AegisKey OATH"
                let mut name_resp = Vec::new();
                name_resp.push(0x79); // Name tag
                name_resp.push(13); // Length
                name_resp.extend_from_slice(b"AegisKey OATH");
                return ResponseApdu::ok(name_resp);
            } else if apdu.data == AID_FIDO_U2F {
                self.selected_applet = SelectedApplet::FidoU2f;
                // Return FIDO U2F V2 version string: "U2F_V2"
                return ResponseApdu::ok(b"U2F_V2".to_vec());
            } else if apdu.data == AID_PIV {
                self.selected_applet = SelectedApplet::Piv;
                return ResponseApdu::ok(vec![0x61, 0x05, 0x4F, 0x03, 0xA0, 0x00, 0x00]);
            } else {
                self.selected_applet = SelectedApplet::None;
                return ResponseApdu::status(SW_NOT_FOUND);
            }
        }

        // Route to the currently selected applet
        match self.selected_applet {
            SelectedApplet::Oath => handler.handle_oath_apdu(apdu),
            SelectedApplet::FidoU2f => handler.handle_fido_apdu(apdu),
            _ => ResponseApdu::status(SW_CONDITIONS_NOT_SATISFIED),
        }
    }

    fn build_data_block_response(slot: u8, seq: u8, data: &[u8]) -> Vec<u8> {
        let mut resp = Vec::with_capacity(10 + data.len());
        resp.push(RDR_TO_PC_DATA_BLOCK);
        resp.extend_from_slice(&(data.len() as u32).to_le_bytes());
        resp.push(slot);
        resp.push(seq);
        resp.push(0x00); // bStatus: Success
        resp.push(0x00); // bError
        resp.push(0x00); // bChainParameter
        resp.extend_from_slice(data);
        resp
    }

    fn build_slot_status_response(slot: u8, seq: u8, status: u8) -> Vec<u8> {
        let mut resp = vec![0u8; 10];
        resp[0] = RDR_TO_PC_SLOT_STATUS;
        resp[1..5].copy_from_slice(&0u32.to_le_bytes());
        resp[5] = slot;
        resp[6] = seq;
        resp[7] = status;
        resp[8] = 0x00;
        resp[9] = 0x00;
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power_on_atr() {
        let mut transport = CcidTransport::new();
        let mut handler = DefaultCcidHandler;

        let power_on_cmd = [
            PC_TO_RDR_ICC_POWER_ON,
            0, 0, 0, 0, // dwLength: 0
            0,          // bSlot
            1,          // bSeq
            0, 0, 0,    // PowerSelect / RFU
        ];

        let resp = transport.process_ccid_message(&power_on_cmd, &mut handler).unwrap();
        assert_eq!(resp[0], RDR_TO_PC_DATA_BLOCK);
        assert_eq!(resp[5], 0); // Slot
        assert_eq!(resp[6], 1); // Seq
        assert_eq!(&resp[10..], AEGIS_ATR);
        assert!(transport.card_powered);
    }

    #[test]
    fn test_select_ykoath_applet() {
        let mut transport = CcidTransport::new();
        let mut handler = DefaultCcidHandler;
        transport.card_powered = true;

        // Command: SELECT AID A0 00 00 05 27 21 01
        let mut apdu_bytes = vec![0x00, 0xA4, 0x04, 0x00, 0x07];
        apdu_bytes.extend_from_slice(AID_YKOATH);

        let mut ccid_msg = vec![PC_TO_RDR_XFR_BLOCK];
        ccid_msg.extend_from_slice(&(apdu_bytes.len() as u32).to_le_bytes());
        ccid_msg.push(0); // Slot
        ccid_msg.push(42); // Seq
        ccid_msg.extend_from_slice(&[0, 0, 0]); // RFU
        ccid_msg.extend_from_slice(&apdu_bytes);

        let resp = transport.process_ccid_message(&ccid_msg, &mut handler).unwrap();
        assert_eq!(resp[0], RDR_TO_PC_DATA_BLOCK);
        assert_eq!(resp[6], 42); // Seq
        let apdu_resp = &resp[10..];
        let len = apdu_resp.len();
        assert!(len >= 2);
        assert_eq!(apdu_resp[len - 2], 0x90);
        assert_eq!(apdu_resp[len - 1], 0x00);
        assert_eq!(transport.selected_applet, SelectedApplet::Oath);
    }

    #[test]
    fn test_select_u2f_applet() {
        let mut transport = CcidTransport::new();
        let mut handler = DefaultCcidHandler;
        transport.card_powered = true;

        // Command: SELECT AID A0 00 00 06 47 2F 00 01
        let mut apdu_bytes = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
        apdu_bytes.extend_from_slice(AID_FIDO_U2F);

        let mut ccid_msg = vec![PC_TO_RDR_XFR_BLOCK];
        ccid_msg.extend_from_slice(&(apdu_bytes.len() as u32).to_le_bytes());
        ccid_msg.push(0);
        ccid_msg.push(99);
        ccid_msg.extend_from_slice(&[0, 0, 0]);
        ccid_msg.extend_from_slice(&apdu_bytes);

        let resp = transport.process_ccid_message(&ccid_msg, &mut handler).unwrap();
        let apdu_resp = &resp[10..];
        assert_eq!(&apdu_resp[..6], b"U2F_V2");
        assert_eq!(apdu_resp[6], 0x90);
        assert_eq!(apdu_resp[7], 0x00);
        assert_eq!(transport.selected_applet, SelectedApplet::FidoU2f);
    }
}
