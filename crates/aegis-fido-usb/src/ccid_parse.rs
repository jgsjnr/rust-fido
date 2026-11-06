//! CCID transport wire parser: raw APDU bytes <-> CommandApdu/ResponseApdu.
//!
//! Owner of the TRANSPORT-level parser (ISO 7816-4 short + extended APDU
//! framing, status words, response serialization). Field-level PIV parsing
//! (BER-TLV, GET/PUT/GEN/AUTH objects) lives in `crate::piv::apdu` and is
//! never duplicated here: the transport hands a parsed `CommandApdu` to the
//! applet, the applet parses its own fields. Do not merge the two parsers.
//!
//! Compat: `crate::ccid` re-exports every public symbol defined here, so
//! existing `crate::ccid::{CommandApdu, ...}` paths keep working.

use alloc::vec::Vec;
use zeroize::Zeroize;

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
/// PIV VERIFY failed, retries remain: SW1 `0x63`, SW2 `0xC0 | remaining`.
/// Use [`sw_retries_left`] to build it (no magic `0xC0` at call sites).
pub const SW_RETRY_BASE: u8 = 0x63;
/// Referenced data not found (e.g. PIV PIN never provisioned): `6A 88`.
pub const SW_REFERENCED_DATA_NOT_FOUND: (u8, u8) = (0x6A, 0x88);
/// Wrong data field content (malformed PIV TLV): `6A 80`.
pub const SW_WRONG_DATA: (u8, u8) = (0x6A, 0x80);
/// Authentication method blocked (PIN blocked → use PUK; PUK exhausted → wiped): `69 83`.
pub const SW_AUTH_BLOCKED: (u8, u8) = (0x69, 0x83);

/// Builds a VERIFY-failed status word: `63 CX` with `X = remaining` (0..=15).
pub fn sw_retries_left(remaining: u8) -> (u8, u8) {
    (SW_RETRY_BASE, 0xC0 | (remaining & 0x0F))
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
    /// Zeroizes the sensitive `data` buffer in place (length preserved).
    pub fn clear_sensitive(&mut self) {
        self.data.zeroize();
    }
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
    /// Zeroizes the sensitive `data` buffer in place (length preserved).
    pub fn clear_sensitive(&mut self) {
        self.data.zeroize();
    }

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

impl Drop for CommandApdu {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for ResponseApdu {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(test)]
mod zeroize_tests {
    use super::*;

    #[test]
    fn command_apdu_clear_sensitive_zeroizes_data() {
        let mut apdu = CommandApdu {
            cla: 0x00,
            ins: 0x20,
            p1: 0x00,
            p2: 0x80,
            data: alloc::vec![0x31, 0x32, 0x33, 0x34],
            le: None,
        };
        apdu.clear_sensitive();
        // `zeroize` on Vec scrubs the buffer (empties it): no PIN bytes remain.
        assert!(apdu.data.is_empty());
    }

    #[test]
    fn response_apdu_clear_sensitive_zeroizes_data() {
        let mut resp = ResponseApdu::ok(alloc::vec![0xAA, 0xBB, 0xCC]);
        resp.clear_sensitive();
        assert!(resp.data.is_empty());
    }
}
