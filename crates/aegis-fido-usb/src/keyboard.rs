//! USB HID Keyboard Transport for Automatic OTP Typing.
//!
//! Converts OTP strings (TOTP, HOTP, YubiKey Modhex OTP) into standard 8-byte
//! USB HID Keyboard reports for automated keystroke injection into host systems.
//! 100% Native Rust implementation.

/// Standard 8-byte USB HID Boot Keyboard Report.
pub type KeyboardReport = [u8; 8];

// Modifier bitmasks (Byte 0)
pub const MOD_NONE: u8 = 0x00;
pub const MOD_LCTRL: u8 = 0x01;
pub const MOD_LSHIFT: u8 = 0x02;
pub const MOD_LALT: u8 = 0x04;
pub const MOD_LGUI: u8 = 0x08;
pub const MOD_RCTRL: u8 = 0x10;
pub const MOD_RSHIFT: u8 = 0x20;
pub const MOD_RALT: u8 = 0x40;
pub const MOD_RGUI: u8 = 0x80;

// USB HID Usage IDs for Keyboard / Keypad (Page 0x07)
pub const KEY_NONE: u8 = 0x00;
pub const KEY_A: u8 = 0x04;
pub const KEY_Z: u8 = 0x1D;
pub const KEY_1: u8 = 0x1E;
pub const KEY_2: u8 = 0x1F;
pub const KEY_3: u8 = 0x20;
pub const KEY_4: u8 = 0x21;
pub const KEY_5: u8 = 0x22;
pub const KEY_6: u8 = 0x23;
pub const KEY_7: u8 = 0x24;
pub const KEY_8: u8 = 0x25;
pub const KEY_9: u8 = 0x26;
pub const KEY_0: u8 = 0x27;
pub const KEY_ENTER: u8 = 0x28;
pub const KEY_ESCAPE: u8 = 0x29;
pub const KEY_BACKSPACE: u8 = 0x2A;
pub const KEY_TAB: u8 = 0x2B;
pub const KEY_SPACE: u8 = 0x2C;
pub const KEY_MINUS: u8 = 0x2D;
pub const KEY_EQUAL: u8 = 0x2E;

/// Converts an ASCII character into a (modifier, keycode) pair.
pub fn ascii_to_keycode(ch: char) -> Option<(u8, u8)> {
    match ch {
        'a'..='z' => {
            let offset = (ch as u8) - b'a';
            Some((MOD_NONE, KEY_A + offset))
        }
        'A'..='Z' => {
            let offset = (ch as u8) - b'A';
            Some((MOD_LSHIFT, KEY_A + offset))
        }
        '1'..='9' => {
            let offset = (ch as u8) - b'1';
            Some((MOD_NONE, KEY_1 + offset))
        }
        '0' => Some((MOD_NONE, KEY_0)),
        '\n' | '\r' => Some((MOD_NONE, KEY_ENTER)),
        '\t' => Some((MOD_NONE, KEY_TAB)),
        ' ' => Some((MOD_NONE, KEY_SPACE)),
        '-' => Some((MOD_NONE, KEY_MINUS)),
        '_' => Some((MOD_LSHIFT, KEY_MINUS)),
        '=' => Some((MOD_NONE, KEY_EQUAL)),
        '+' => Some((MOD_LSHIFT, KEY_EQUAL)),
        _ => None,
    }
}

/// Modhex characters used in YubiKey OTPs: 'c', 'b', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'n', 'r', 't', 'u', 'v'.
pub const MODHEX_ALPHABET: &[char] = &[
    'c', 'b', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'n', 'r', 't', 'u', 'v',
];

/// Verifies whether an OTP string conforms to standard Modhex alphabet.
pub fn is_valid_modhex(s: &str) -> bool {
    s.chars().all(|c| MODHEX_ALPHABET.contains(&c))
}

/// State machine for streaming keyboard reports to the USB host.
pub struct OtpTyper {
    queue: Vec<(u8, u8)>, // (modifier, keycode)
    current_index: usize,
    in_release_phase: bool,
    repeat_delay_ticks: usize,
    current_delay_ticks: usize,
}

impl Default for OtpTyper {
    fn default() -> Self {
        Self::new()
    }
}

impl OtpTyper {
    /// Creates a new OTP Typer with a default inter-key delay.
    pub fn new() -> Self {
        Self {
            queue: Vec::new(),
            current_index: 0,
            in_release_phase: false,
            repeat_delay_ticks: 2, // 2 USB poll frames between key changes
            current_delay_ticks: 0,
        }
    }

    /// Sets the inter-key delay in ticks.
    pub fn set_delay_ticks(&mut self, ticks: usize) {
        self.repeat_delay_ticks = ticks;
    }

    /// Queues an OTP string to be typed, optionally appending an Enter keystroke.
    pub fn queue_otp(&mut self, otp: &str, append_enter: bool) {
        self.queue.clear();
        self.current_index = 0;
        self.in_release_phase = false;
        self.current_delay_ticks = 0;

        for ch in otp.chars() {
            if let Some((mod_key, keycode)) = ascii_to_keycode(ch) {
                self.queue.push((mod_key, keycode));
            }
        }

        if append_enter {
            self.queue.push((MOD_NONE, KEY_ENTER));
        }
    }

    /// Returns `true` if there are still keystrokes to type.
    pub fn is_active(&self) -> bool {
        self.current_index < self.queue.len()
    }

    /// Cancels any active typing.
    pub fn cancel(&mut self) {
        self.queue.clear();
        self.current_index = 0;
        self.in_release_phase = false;
    }

    /// Generates the next 8-byte USB HID Keyboard report.
    /// Returns `Some(report)` if a report should be transmitted, or `None` if idle.
    pub fn next_report(&mut self) -> Option<KeyboardReport> {
        if !self.is_active() {
            return None;
        }

        if self.current_delay_ticks > 0 {
            self.current_delay_ticks -= 1;
            return None;
        }

        self.current_delay_ticks = self.repeat_delay_ticks;

        if self.in_release_phase {
            // Send empty (key release) report
            self.in_release_phase = false;
            self.current_index += 1;
            Some([0u8; 8])
        } else {
            // Send key press report
            let (mod_key, keycode) = self.queue[self.current_index];
            self.in_release_phase = true;
            let mut report = [0u8; 8];
            report[0] = mod_key;
            report[1] = 0; // Reserved
            report[2] = keycode;
            Some(report)
        }
    }

    /// Helper that renders the entire sequence into a list of reports (for testing or batch queuing).
    pub fn drain_all_reports(&mut self) -> Vec<KeyboardReport> {
        let mut reports = Vec::new();
        while self.is_active() {
            self.current_delay_ticks = 0;
            if let Some(rpt) = self.next_report() {
                reports.push(rpt);
            }
        }
        reports
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digit_keycodes() {
        assert_eq!(ascii_to_keycode('0'), Some((MOD_NONE, KEY_0)));
        assert_eq!(ascii_to_keycode('1'), Some((MOD_NONE, KEY_1)));
        assert_eq!(ascii_to_keycode('9'), Some((MOD_NONE, KEY_9)));
    }

    #[test]
    fn test_letter_keycodes() {
        assert_eq!(ascii_to_keycode('a'), Some((MOD_NONE, KEY_A)));
        assert_eq!(ascii_to_keycode('z'), Some((MOD_NONE, KEY_Z)));
        assert_eq!(ascii_to_keycode('A'), Some((MOD_LSHIFT, KEY_A)));
    }

    #[test]
    fn test_otp_typer_totp() {
        let mut typer = OtpTyper::new();
        typer.queue_otp("123456", true);
        assert!(typer.is_active());

        let reports = typer.drain_all_reports();
        // 6 digits + 1 enter = 7 keys. Each key has 1 press + 1 release = 14 reports
        assert_eq!(reports.len(), 14);

        // Check first key ('1')
        assert_eq!(reports[0][0], MOD_NONE);
        assert_eq!(reports[0][2], KEY_1);
        // Check first release
        assert_eq!(reports[1], [0u8; 8]);

        // Check last key (Enter)
        assert_eq!(reports[12][0], MOD_NONE);
        assert_eq!(reports[12][2], KEY_ENTER);
        // Check last release
        assert_eq!(reports[13], [0u8; 8]);

        assert!(!typer.is_active());
    }

    #[test]
    fn test_modhex_validation() {
        assert!(is_valid_modhex("cbdefghijklnrtuv"));
        assert!(!is_valid_modhex("cbdefghijklnrtuvw")); // 'w' is not modhex
        assert!(!is_valid_modhex("123456"));
    }
}
