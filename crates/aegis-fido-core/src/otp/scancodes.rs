extern crate alloc;

use alloc::vec::Vec;
use super::yubikey_otp::YubiOtpGenerator;

/// USB HID Keyboard Scancodes (Usage Page 0x07)
pub const HID_KEY_NONE: u8 = 0x00;
pub const HID_KEY_ENTER: u8 = 0x28;
pub const HID_KEY_TAB: u8 = 0x2B;

/// Standard 8-byte USB HID Keyboard report
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct HidKeyboardReport {
    pub modifier: u8,
    pub reserved: u8,
    pub keycodes: [u8; 6],
}

impl Default for HidKeyboardReport {
    fn default() -> Self {
        Self {
            modifier: 0,
            reserved: 0,
            keycodes: [0; 6],
        }
    }
}

impl HidKeyboardReport {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn key_down(scancode: u8, modifier: u8) -> Self {
        let mut report = Self::default();
        report.modifier = modifier;
        report.keycodes[0] = scancode;
        report
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        [
            self.modifier,
            self.reserved,
            self.keycodes[0],
            self.keycodes[1],
            self.keycodes[2],
            self.keycodes[3],
            self.keycodes[4],
            self.keycodes[5],
        ]
    }
}

/// Convert a single character (Modhex or digit) to USB HID keyboard scancode
pub fn char_to_hid_scancode(c: char) -> Option<u8> {
    match c {
        'a' | 'A' => Some(0x04),
        'b' | 'B' => Some(0x05),
        'c' | 'C' => Some(0x06),
        'd' | 'D' => Some(0x07),
        'e' | 'E' => Some(0x08),
        'f' | 'F' => Some(0x09),
        'g' | 'G' => Some(0x0A),
        'h' | 'H' => Some(0x0B),
        'i' | 'I' => Some(0x0C),
        'j' | 'J' => Some(0x0D),
        'k' | 'K' => Some(0x0E),
        'l' | 'L' => Some(0x0F),
        'm' | 'M' => Some(0x10),
        'n' | 'N' => Some(0x11),
        'o' | 'O' => Some(0x12),
        'p' | 'P' => Some(0x13),
        'q' | 'Q' => Some(0x14),
        'r' | 'R' => Some(0x15),
        's' | 'S' => Some(0x16),
        't' | 'T' => Some(0x17),
        'u' | 'U' => Some(0x18),
        'v' | 'V' => Some(0x19),
        'w' | 'W' => Some(0x1A),
        'x' | 'X' => Some(0x1B),
        'y' | 'Y' => Some(0x1C),
        'z' | 'Z' => Some(0x1D),
        '1' => Some(0x1E),
        '2' => Some(0x1F),
        '3' => Some(0x20),
        '4' => Some(0x21),
        '5' => Some(0x22),
        '6' => Some(0x23),
        '7' => Some(0x24),
        '8' => Some(0x25),
        '9' => Some(0x26),
        '0' => Some(0x27),
        '\n' | '\r' => Some(HID_KEY_ENTER),
        '\t' => Some(HID_KEY_TAB),
        _ => None,
    }
}

/// Convert a string into a sequence of USB HID keyboard reports (key press + key release pairs)
pub fn string_to_hid_reports(text: &str, append_enter: bool) -> Vec<[u8; 8]> {
    let mut reports = Vec::with_capacity((text.len() + 1) * 2);

    for c in text.chars() {
        if let Some(scancode) = char_to_hid_scancode(c) {
            let press = HidKeyboardReport::key_down(scancode, 0);
            reports.push(press.to_bytes());
            reports.push(HidKeyboardReport::empty().to_bytes());
        }
    }

    if append_enter {
        let enter_press = HidKeyboardReport::key_down(HID_KEY_ENTER, 0);
        reports.push(enter_press.to_bytes());
        reports.push(HidKeyboardReport::empty().to_bytes());
    }

    reports
}

/// USB HID Keyboard Auto-Typer engine for GPIO 0 button trigger
pub struct OtpAutoTyper {
    pub append_enter: bool,
}

impl Default for OtpAutoTyper {
    fn default() -> Self {
        Self { append_enter: true }
    }
}

impl OtpAutoTyper {
    pub fn new(append_enter: bool) -> Self {
        Self { append_enter }
    }

    /// On button press trigger (e.g. GPIO 0 press), generate OTP and return HID keyboard report stream
    pub fn on_button_press(
        &self,
        generator: &mut YubiOtpGenerator,
        nonce: u16,
    ) -> Vec<[u8; 8]> {
        let token = generator.generate_token(nonce);
        string_to_hid_reports(&token, self.append_enter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modhex_scancodes() {
        // Modhex characters: c, b, d, e, f, g, h, i, j, k, l, n, r, t, u, v
        assert_eq!(char_to_hid_scancode('c'), Some(0x06));
        assert_eq!(char_to_hid_scancode('b'), Some(0x05));
        assert_eq!(char_to_hid_scancode('d'), Some(0x07));
        assert_eq!(char_to_hid_scancode('v'), Some(0x19));
        assert_eq!(char_to_hid_scancode('\n'), Some(0x28));
    }

    #[test]
    fn test_auto_typer_generates_reports() {
        let public_id = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let private_id = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let aes_key = [0x77u8; 16];

        let mut generator = YubiOtpGenerator::new(&public_id, private_id, aes_key);
        let auto_typer = OtpAutoTyper::new(true);

        let reports = auto_typer.on_button_press(&mut generator, 0x55AA);
        // 44 characters + 1 Enter = 45 characters. Each has press + release = 90 reports.
        assert_eq!(reports.len(), 90);

        // Verify the last press report is HID_KEY_ENTER
        let last_press = reports[reports.len() - 2];
        assert_eq!(last_press[2], HID_KEY_ENTER);

        // Verify release reports are empty
        for i in (1..reports.len()).step_by(2) {
            assert_eq!(reports[i], [0u8; 8]);
        }
    }
}
