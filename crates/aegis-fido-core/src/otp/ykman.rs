extern crate alloc;

use alloc::vec::Vec;

/// Yubico Management Applet AID
pub const YK_MGMT_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

/// Management Instructions
pub const INS_DEVICE_CONFIG: u8 = 0x01;
pub const INS_DEVICE_RESET: u8 = 0x1C;
pub const INS_READ_DEVICE_INFO: u8 = 0x1D;

/// Device Info TLV Tags
pub const TAG_USB_PRE_PID: u8 = 0x01;
pub const TAG_SERIAL_NUMBER: u8 = 0x02;
pub const TAG_USB_ENABLED_CAPS: u8 = 0x03;
pub const TAG_USB_SUPPORTED_CAPS: u8 = 0x04;
pub const TAG_FORM_FACTOR: u8 = 0x05;
pub const TAG_FIRMWARE_VERSION: u8 = 0x06;
pub const TAG_AUTO_EJECT_TIMEOUT: u8 = 0x07;
pub const TAG_CHALRESP_TIMEOUT: u8 = 0x08;
pub const TAG_DEVICE_FLAGS: u8 = 0x09;
pub const TAG_CONFIG_LOCKED: u8 = 0x0A;

/// Capabilities bitmask
pub const CAP_OTP: u16 = 0x0001;
pub const CAP_U2F: u16 = 0x0002;
pub const CAP_OPGP: u16 = 0x0008;
pub const CAP_PIV: u16 = 0x0010;
pub const CAP_OATH: u16 = 0x0020;
pub const CAP_FIDO2: u16 = 0x0200;

/// Default AegisKey supported capabilities: OTP, U2F, OATH, FIDO2
pub const ALL_SUPPORTED_CAPS: u16 = CAP_OTP | CAP_U2F | CAP_OATH | CAP_FIDO2;

/// YKMAN Device Info State
#[derive(Debug, Clone)]
pub struct YkmanDeviceInfo {
    pub serial: u32,
    pub version: [u8; 3], // [5, 4, 3]
    pub form_factor: u8,  // 0x01 = USB-A Keychain, 0x03 = USB-C
    pub enabled_caps: u16,
    pub supported_caps: u16,
    pub is_locked: bool,
    pub chalresp_timeout: u8,
}

impl Default for YkmanDeviceInfo {
    fn default() -> Self {
        Self {
            serial: 13374200,
            version: [5, 4, 3],
            form_factor: 0x03, // USB-C (ESP32-S3 default)
            enabled_caps: ALL_SUPPORTED_CAPS,
            supported_caps: ALL_SUPPORTED_CAPS,
            is_locked: false,
            chalresp_timeout: 15,
        }
    }
}

impl YkmanDeviceInfo {
    pub fn new(serial: u32) -> Self {
        Self {
            serial,
            ..Default::default()
        }
    }

    /// Encode device info in YKMAN TLV format
    pub fn encode_tlv(&self) -> Vec<u8> {
        let mut tlv = Vec::new();

        // Tag 0x02: Serial Number (4 bytes big endian)
        tlv.push(TAG_SERIAL_NUMBER);
        tlv.push(4);
        tlv.extend_from_slice(&self.serial.to_be_bytes());

        // Tag 0x04: Supported USB Capabilities
        tlv.push(TAG_USB_SUPPORTED_CAPS);
        tlv.push(2);
        tlv.extend_from_slice(&self.supported_caps.to_be_bytes());

        // Tag 0x03: Enabled USB Capabilities
        tlv.push(TAG_USB_ENABLED_CAPS);
        tlv.push(2);
        tlv.extend_from_slice(&self.enabled_caps.to_be_bytes());

        // Tag 0x05: Form Factor
        tlv.push(TAG_FORM_FACTOR);
        tlv.push(1);
        tlv.push(self.form_factor);

        // Tag 0x06: Firmware Version
        tlv.push(TAG_FIRMWARE_VERSION);
        tlv.push(3);
        tlv.extend_from_slice(&self.version);

        // Tag 0x08: Challenge-Response Timeout
        tlv.push(TAG_CHALRESP_TIMEOUT);
        tlv.push(1);
        tlv.push(self.chalresp_timeout);

        // Tag 0x0A: Configuration locked flag
        tlv.push(TAG_CONFIG_LOCKED);
        tlv.push(1);
        tlv.push(if self.is_locked { 1 } else { 0 });

        // Wrap with total length prefix as required by YKMAN
        let mut out = Vec::with_capacity(tlv.len() + 1);
        out.push(tlv.len() as u8);
        out.extend_from_slice(&tlv);
        out
    }

    /// Handle YKMAN Management APDU
    pub fn handle_apdu(&mut self, apdu: &[u8]) -> (Vec<u8>, u16) {
        if apdu.len() < 4 {
            return (Vec::new(), 0x6A80);
        }

        let ins = apdu[1];
        let p1 = apdu[2];

        match ins {
            // SELECT Management AID
            0xA4 if p1 == 0x04 => {
                // Return version / success
                (self.encode_tlv(), 0x9000)
            }
            // Read Device Info
            INS_READ_DEVICE_INFO => {
                (self.encode_tlv(), 0x9000)
            }
            // Write Device Config
            INS_DEVICE_CONFIG => {
                if apdu.len() > 5 {
                    // Update enabled caps if requested
                    (Vec::new(), 0x9000)
                } else {
                    (Vec::new(), 0x6A80)
                }
            }
            _ => (Vec::new(), 0x6D00),
        }
    }
}

/// YubiKey OTP Status Structure (6 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YubiOtpStatus {
    pub version_major: u8,
    pub version_minor: u8,
    pub version_build: u8,
    pub pgm_seq: u8,
    pub touch_level: u8,
    pub flags: u8,
}

impl Default for YubiOtpStatus {
    fn default() -> Self {
        Self {
            version_major: 5,
            version_minor: 4,
            version_build: 3,
            pgm_seq: 1,
            touch_level: 0,
            flags: 0x01 | 0x02, // Slot 1 configured (bit 0), Slot 2 configured (bit 1)
        }
    }
}

impl YubiOtpStatus {
    pub fn to_bytes(&self) -> [u8; 6] {
        [
            self.version_major,
            self.version_minor,
            self.version_build,
            self.pgm_seq,
            self.touch_level,
            self.flags,
        ]
    }
}
