//! PIV (NIST SP 800-73-4) applet skeleton — MVP 9A/9E, lock-only.
//!
//! `PivApplet` receives a parsed [`CommandApdu`] and returns a
//! [`ResponseApdu`]. SELECT with AID `A0 00 00 03 08` selects the applet
//! and returns a lab-mock FCI; GET DATA serves mock CHUID (`5F C1 02`)
//! and CCC (`5F C1 07`) containers. Unknown AID yields `6A 82`;
//! any command while deselected yields `69 85`.

use super::ccid::{
    AID_PIV, CommandApdu, ResponseApdu, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_NOT_FOUND,
};

/// GET DATA instruction (ISO 7816-4 / NIST SP 800-73).
const INS_GET_DATA: u8 = 0xCB;
/// SELECT instruction.
const INS_SELECT: u8 = 0xA4;

/// LAB-ONLY mock FCI returned on PIV SELECT (matches legacy `ccid.rs` bytes).
///
/// Only compiled with `#[cfg(any(test, feature = "lab-mocks"))]`; production
/// builds without `lab-mocks` return an empty `90 00` on SELECT.
#[cfg(any(test, feature = "lab-mocks"))]
pub(crate) const PIV_FCI: &[u8] = &[0x61, 0x05, 0x4F, 0x03, 0xA0, 0x00, 0x00];
/// LAB-ONLY mock CHUID container bytes (no full cert allocated).
#[cfg(any(test, feature = "lab-mocks"))]
const CHUID_MOCK: &[u8] = &[0x5F, 0xC1, 0x02, 0x00];
/// LAB-ONLY mock CCC container bytes (no full cert allocated).
#[cfg(any(test, feature = "lab-mocks"))]
const CCC_MOCK: &[u8] = &[0x5F, 0xC1, 0x07, 0x00];

/// Minimal PIV applet state: selected or not (MVP lock-only, no PIN yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PivApplet {
    selected: bool,
}

impl PivApplet {
    /// Creates a deselected applet.
    pub fn new() -> Self {
        Self { selected: false }
    }

    /// Returns true when the applet was selected via SELECT AID.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Dispatches one command APDU to the PIV applet.
    pub fn handle(&mut self, apdu: &CommandApdu) -> ResponseApdu {
        if apdu.ins == INS_SELECT && apdu.p1 == 0x04 {
            return self.handle_select(apdu);
        }
        if apdu.ins == INS_GET_DATA {
            return self.handle_get_data(apdu);
        }
        ResponseApdu::status(SW_INS_NOT_SUPPORTED)
    }

    /// Handles SELECT by AID; only `AID_PIV` selects the applet.
    fn handle_select(&mut self, apdu: &CommandApdu) -> ResponseApdu {
        if apdu.data == AID_PIV {
            self.selected = true;
            #[cfg(any(test, feature = "lab-mocks"))]
            {
                ResponseApdu::ok(PIV_FCI.to_vec())
            }
            #[cfg(not(any(test, feature = "lab-mocks")))]
            {
                ResponseApdu::ok(Vec::new())
            }
        } else {
            self.selected = false;
            ResponseApdu::status(SW_NOT_FOUND)
        }
    }

    /// Handles GET DATA; requires prior SELECT.
    ///
    /// LAB-ONLY: container mocks are served only with `lab-mocks` (or tests);
    /// without the gate every request returns `6A 82`.
    fn handle_get_data(&self, apdu: &CommandApdu) -> ResponseApdu {
        if !self.selected {
            return ResponseApdu::status(SW_CONDITIONS_NOT_SATISFIED);
        }
        #[cfg(any(test, feature = "lab-mocks"))]
        {
            match request_tag(&apdu.data) {
                Some(t) if t == [0x5F, 0xC1, 0x02] => ResponseApdu::ok(CHUID_MOCK.to_vec()),
                Some(t) if t == [0x5F, 0xC1, 0x07] => ResponseApdu::ok(CCC_MOCK.to_vec()),
                _ => ResponseApdu::status(SW_NOT_FOUND),
            }
        }
        #[cfg(not(any(test, feature = "lab-mocks")))]
        {
            let _ = apdu;
            ResponseApdu::status(SW_NOT_FOUND)
        }
    }
}

/// Extracts the requested data-object tag from a GET DATA field.
///
/// Expects `5C <len> <tag bytes>`; returns `None` on malformed input.
/// LAB-ONLY helper: only compiled with mocks/tests (sole caller is gated).
#[cfg(any(test, feature = "lab-mocks"))]
fn request_tag(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 2 || data[0] != 0x5C {
        return None;
    }
    let len = data[1] as usize;
    if data.len() < 2 + len {
        return None;
    }
    Some(&data[2..2 + len])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select_apdu(data: &[u8]) -> CommandApdu {
        CommandApdu {
            cla: 0x00,
            ins: INS_SELECT,
            p1: 0x04,
            p2: 0x00,
            data: data.to_vec(),
            le: None,
        }
    }

    fn get_data_apdu(tag: &[u8]) -> CommandApdu {
        // Arrange data field: 5C <len> <tag bytes>
        let mut data = vec![0x5C, tag.len() as u8];
        data.extend_from_slice(tag);
        CommandApdu {
            cla: 0x00,
            ins: INS_GET_DATA,
            p1: 0x3F,
            p2: 0xFF,
            data,
            le: None,
        }
    }

    #[test]
    fn should_select_piv_aid_and_return_fci() {
        // Arrange
        let mut applet = PivApplet::new();
        let apdu = select_apdu(AID_PIV);

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert!(applet.is_selected());
        assert_eq!(resp.sw1, 0x90);
        assert_eq!(resp.sw2, 0x00);
        assert_eq!(resp.data, PIV_FCI);
    }

    #[test]
    fn should_return_chuid_mock_when_selected() {
        // Arrange
        let mut applet = PivApplet::new();
        applet.handle(&select_apdu(AID_PIV));

        // Act
        let resp = applet.handle(&get_data_apdu(&[0x5F, 0xC1, 0x02]));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert_eq!(resp.data, CHUID_MOCK);
    }

    #[test]
    fn should_return_ccc_mock_when_selected() {
        // Arrange
        let mut applet = PivApplet::new();
        applet.handle(&select_apdu(AID_PIV));

        // Act
        let resp = applet.handle(&get_data_apdu(&[0x5F, 0xC1, 0x07]));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), (0x90, 0x00));
        assert_eq!(resp.data, CCC_MOCK);
    }

    #[test]
    fn should_reject_unknown_aid_with_6a82() {
        // Arrange
        let mut applet = PivApplet::new();
        let apdu = select_apdu(&[0xDE, 0xAD, 0xBE, 0xEF]);

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert!(!applet.is_selected());
        assert_eq!((resp.sw1, resp.sw2), SW_NOT_FOUND);
    }

    #[test]
    fn should_reject_get_data_when_not_selected_with_6985() {
        // Arrange
        let mut applet = PivApplet::new();

        // Act
        let resp = applet.handle(&get_data_apdu(&[0x5F, 0xC1, 0x02]));

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn should_return_6a82_for_malformed_get_data() {
        // Arrange
        let mut applet = PivApplet::new();
        applet.handle(&select_apdu(AID_PIV));
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_GET_DATA,
            p1: 0x3F,
            p2: 0xFF,
            data: vec![0x00, 0xFF],
            le: None,
        };

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_NOT_FOUND);
    }

    #[test]
    fn should_return_6d00_for_unknown_ins() {
        // Arrange
        let mut applet = PivApplet::new();
        applet.handle(&select_apdu(AID_PIV));
        let apdu = CommandApdu {
            cla: 0x00,
            ins: 0xFF,
            p1: 0x00,
            p2: 0x00,
            data: Vec::new(),
            le: None,
        };

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert_eq!((resp.sw1, resp.sw2), SW_INS_NOT_SUPPORTED);
    }

    #[test]
    fn should_reject_select_with_wrong_p1() {
        // Arrange
        let mut applet = PivApplet::new();
        let apdu = CommandApdu {
            cla: 0x00,
            ins: INS_SELECT,
            p1: 0x00,
            p2: 0x00,
            data: AID_PIV.to_vec(),
            le: None,
        };

        // Act
        let resp = applet.handle(&apdu);

        // Assert
        assert!(!applet.is_selected());
        assert_eq!((resp.sw1, resp.sw2), SW_INS_NOT_SUPPORTED);
    }
}
