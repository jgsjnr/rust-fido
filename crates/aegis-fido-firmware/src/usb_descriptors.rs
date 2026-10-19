//! USB Descriptors for AegisKey S3 Authenticator (Composite USB Device).
//!
//! Configures:
//!   - VID: 0x303A (Espressif Systems)
//!   - PID: 0xAE61 (AegisKey S3 Authenticator)
//!   - Manufacturer: "Aegis Security"
//!   - Product: "AegisKey S3 Authenticator"
//!   - Serial: "AEGIS-S3-XXXX"
//!   - Interface 0: FIDO2 CTAPHID (Interrupt IN/OUT 64 bytes)
//!   - Interface 1: CCID SmartCard (Bulk IN 0x83, Bulk OUT 0x03, Interrupt IN 0x84)
//!   - Interface 2: HID Keyboard (Interrupt IN 0x85 8 bytes)
//!   - Interface 3: WinUSB High-Speed Direct Management (Bulk OUT 0x02, Bulk IN 0x82)
//!   - Microsoft OS 2.0 Descriptors for automatic WinUSB.sys driver binding.
//!
//! 100% Native Rust implementation.

pub const USB_VID: u16 = 0x303A;
pub const USB_PID: u16 = 0xAE61;
pub const USB_BCD_DEVICE: u16 = 0x0100; // v1.0.0
pub const USB_BCD_USB: u16 = 0x0210; // USB 2.10 (BOS Descriptor support)

pub const MANUFACTURER_STRING: &str = "Aegis Security";
pub const PRODUCT_STRING: &str = "AegisKey S3 Authenticator";
pub const SERIAL_NUMBER_STRING: &str = "AEGIS-S3-0001";
pub const CTAPHID_INTERFACE_STRING: &str = "AegisKey FIDO2 / CTAPHID";
pub const CCID_INTERFACE_STRING: &str = "AegisKey CCID SmartCard";
pub const KEYBOARD_INTERFACE_STRING: &str = "AegisKey OTP Keyboard";
pub const WINUSB_INTERFACE_STRING: &str = "AegisKey WinUSB Direct Management";

/// Standard FIDO U2F / FIDO2 CTAPHID HID Report Descriptor (34 bytes).
/// Usage Page (0xF1D0), Usage (0x01)
pub const CTAPHID_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance 0xF1D0)
    0x09, 0x01, // Usage (U2F / FIDO Authenticator)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Data In)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8 bits)
    0x95, 0x40, //   Report Count (64 bytes)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    0x09, 0x21, //   Usage (Data Out)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8 bits)
    0x95, 0x40, //   Report Count (64 bytes)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0xC0, // End Collection
];

/// Standard USB HID Keyboard Report Descriptor (63 bytes).
pub const KEYBOARD_REPORT_DESCRIPTOR: &[u8] = &[
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x06, // Usage (Keyboard)
    0xA1, 0x01, // Collection (Application)
    0x05, 0x07, //   Usage Page (Key Codes)
    0x19, 0xE0, //   Usage Minimum (224) - Modifier Left Ctrl
    0x29, 0xE7, //   Usage Maximum (231) - Modifier Right GUI
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1 bit)
    0x95, 0x08, //   Report Count (8 bits)
    0x81, 0x02, //   Input (Data, Variable, Absolute) - Modifier byte
    0x95, 0x01, //   Report Count (1)
    0x75, 0x08, //   Report Size (8 bits)
    0x81, 0x01, //   Input (Constant) - Reserved byte
    0x95, 0x05, //   Report Count (5)
    0x75, 0x01, //   Report Size (1 bit)
    0x05, 0x08, //   Usage Page (LEDs)
    0x19, 0x01, //   Usage Minimum (1)
    0x29, 0x05, //   Usage Maximum (5)
    0x91, 0x02, //   Output (Data, Variable, Absolute) - LED report
    0x95, 0x01, //   Report Count (1)
    0x75, 0x03, //   Report Size (3 bits)
    0x91, 0x01, //   Output (Constant) - LED padding
    0x95, 0x06, //   Report Count (6)
    0x75, 0x08, //   Report Size (8 bits)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x65, //   Logical Maximum (101)
    0x05, 0x07, //   Usage Page (Key Codes)
    0x19, 0x00, //   Usage Minimum (0)
    0x29, 0x65, //   Usage Maximum (101)
    0x81, 0x00, //   Input (Data, Array) - Key arrays (6 bytes)
    0xC0, // End Collection
];

/// Builds the 18-byte standard USB Device Descriptor.
pub fn build_device_descriptor() -> [u8; 18] {
    let mut desc = [0u8; 18];
    desc[0] = 18; // bLength
    desc[1] = 0x01; // bDescriptorType: DEVICE
    desc[2..4].copy_from_slice(&USB_BCD_USB.to_le_bytes()); // bcdUSB (2.10)
    desc[4] = 0x00; // bDeviceClass (Composite / defined per interface)
    desc[5] = 0x00; // bDeviceSubClass
    desc[6] = 0x00; // bDeviceProtocol
    desc[7] = 64; // bMaxPacketSize0 (64 bytes)
    desc[8..10].copy_from_slice(&USB_VID.to_le_bytes()); // idVendor
    desc[10..12].copy_from_slice(&USB_PID.to_le_bytes()); // idProduct
    desc[12..14].copy_from_slice(&USB_BCD_DEVICE.to_le_bytes()); // bcdDevice
    desc[14] = 1; // iManufacturer (String 1)
    desc[15] = 2; // iProduct (String 2)
    desc[16] = 3; // iSerialNumber (String 3)
    desc[17] = 1; // bNumConfigurations (1)
    desc
}

/// Builds the complete USB Configuration Descriptor containing all 4 interfaces:
/// - Interface 0: CTAPHID
/// - Interface 1: CCID SmartCard
/// - Interface 2: HID Keyboard
/// - Interface 3: WinUSB Vendor Bulk
pub fn build_configuration_descriptor() -> Vec<u8> {
    let mut desc = Vec::new();

    // Configuration Descriptor Header (9 bytes)
    // Placeholder for total length at offset 2..4
    desc.extend_from_slice(&[
        9,    // bLength
        0x02, // bDescriptorType: CONFIGURATION
        0, 0,    // wTotalLength (filled at the end)
        4,    // bNumInterfaces: 4 interfaces
        1,    // bConfigurationValue: 1
        0,    // iConfiguration: 0
        0x80, // bmAttributes: Bus powered
        250,  // bMaxPower: 500mA (250 * 2mA)
    ]);

    // ========================================================================
    // Interface 0: FIDO2 CTAPHID
    // ========================================================================
    desc.extend_from_slice(&[
        9,    // bLength
        0x04, // bDescriptorType: INTERFACE
        0,    // bInterfaceNumber: 0
        0,    // bAlternateSetting: 0
        2,    // bNumEndpoints: 2 (IN + OUT)
        0x03, // bInterfaceClass: HID (0x03)
        0x00, // bInterfaceSubClass: None
        0x00, // bInterfaceProtocol: None
        4,    // iInterface: String 4
    ]);

    // HID Functional Descriptor (9 bytes)
    let hid_rep_len = CTAPHID_REPORT_DESCRIPTOR.len() as u16;
    desc.extend_from_slice(&[
        9,    // bLength
        0x21, // bDescriptorType: HID
        0x10, 0x01, // bcdHID: 1.10
        0x00, // bCountryCode
        1,    // bNumDescriptors: 1
        0x22, // bDescriptorType: REPORT
    ]);
    desc.extend_from_slice(&hid_rep_len.to_le_bytes());

    // Endpoint 1 IN (Interrupt, 64 bytes, 5ms interval)
    desc.extend_from_slice(&[7, 0x05, 0x81, 0x03, 64, 0x00, 5]);

    // Endpoint 1 OUT (Interrupt, 64 bytes, 5ms interval)
    desc.extend_from_slice(&[7, 0x05, 0x01, 0x03, 64, 0x00, 5]);

    // ========================================================================
    // Interface 1: CCID SmartCard
    // ========================================================================
    desc.extend_from_slice(&[
        9,    // bLength
        0x04, // bDescriptorType: INTERFACE
        1,    // bInterfaceNumber: 1
        0,    // bAlternateSetting: 0
        3,    // bNumEndpoints: 3 (Bulk IN, Bulk OUT, Interrupt IN)
        0x0B, // bInterfaceClass: CCID (0x0B)
        0x00, // bInterfaceSubClass: 0
        0x00, // bInterfaceProtocol: 0
        5,    // iInterface: String 5
    ]);

    // CCID Class Functional Descriptor (54 bytes)
    desc.extend_from_slice(&[
        54,   // bLength
        0x21, // bDescriptorType: CCID Functional
        0x10, 0x01, // bcdCCID: 1.10
        0,    // bMaxSlotIndex: 0 (1 slot)
        0x07, // bVoltageSupport: 5.0V, 3.0V, 1.8V
        0x02, 0x00, 0x00, 0x00, // dwProtocols: T=1
        0xA0, 0x0F, 0x00, 0x00, // dwDefaultClock: 4000 kHz
        0xA0, 0x0F, 0x00, 0x00, // dwMaximumClock: 4000 kHz
        0,    // bNumClockSupported: 0
        0x80, 0x25, 0x00, 0x00, // dwDataRate: 9600 bps
        0x00, 0xC2, 0x01, 0x00, // dwMaxDataRate: 115200 bps
        0,    // bNumDataRatesSupported: 0
        0x00, 0x01, 0x00, 0x00, // dwMaxIFSD: 256 bytes
        0x00, 0x00, 0x00, 0x00, // dwSynchProtocols: None
        0x00, 0x00, 0x00, 0x00, // dwMechanical: None
        0xFE, 0x00, 0x02, 0x00, // dwFeatures: Short APDU, Automatic parameter negotiation
        0x00, 0x04, 0x00, 0x00, // dwMaxCCIDMessageLength: 1024 bytes
        0x00, // bClassGetResponse: echo
        0x00, // bClassEnvelope: echo
        0x00, 0x00, // wLcdLayout: None
        0x00, // bPINSupport: None
        1,    // bMaxCCIDBusySlots: 1
    ]);

    // CCID Bulk IN (0x83, 64 bytes)
    desc.extend_from_slice(&[7, 0x05, 0x83, 0x02, 64, 0x00, 0]);
    // CCID Bulk OUT (0x03, 64 bytes)
    desc.extend_from_slice(&[7, 0x05, 0x03, 0x02, 64, 0x00, 0]);
    // CCID Interrupt IN (0x84, 8 bytes, 32ms)
    desc.extend_from_slice(&[7, 0x05, 0x84, 0x03, 8, 0x00, 32]);

    // ========================================================================
    // Interface 2: HID Keyboard (OTP Typer)
    // ========================================================================
    desc.extend_from_slice(&[
        9,    // bLength
        0x04, // bDescriptorType: INTERFACE
        2,    // bInterfaceNumber: 2
        0,    // bAlternateSetting: 0
        1,    // bNumEndpoints: 1 (Interrupt IN)
        0x03, // bInterfaceClass: HID (0x03)
        0x01, // bInterfaceSubClass: Boot Interface (0x01)
        0x01, // bInterfaceProtocol: Keyboard (0x01)
        6,    // iInterface: String 6
    ]);

    // Keyboard HID Descriptor
    let kbd_rep_len = KEYBOARD_REPORT_DESCRIPTOR.len() as u16;
    desc.extend_from_slice(&[9, 0x21, 0x11, 0x01, 0x00, 1, 0x22]);
    desc.extend_from_slice(&kbd_rep_len.to_le_bytes());

    // Keyboard Interrupt IN (0x85, 8 bytes, 10ms interval)
    desc.extend_from_slice(&[7, 0x05, 0x85, 0x03, 8, 0x00, 10]);

    // ========================================================================
    // Interface 3: WinUSB Vendor Bulk Direct Management
    // ========================================================================
    desc.extend_from_slice(&[
        9,    // bLength
        0x04, // bDescriptorType: INTERFACE
        3,    // bInterfaceNumber: 3
        0,    // bAlternateSetting: 0
        2,    // bNumEndpoints: 2 (Bulk OUT 0x02, Bulk IN 0x82)
        0xFF, // bInterfaceClass: Vendor Specific (0xFF)
        0x00, // bInterfaceSubClass: 0
        0x00, // bInterfaceProtocol: 0
        7,    // iInterface: String 7
    ]);

    // Bulk OUT Endpoint 0x02 (64 bytes)
    desc.extend_from_slice(&[7, 0x05, 0x02, 0x02, 64, 0x00, 0]);
    // Bulk IN Endpoint 0x82 (64 bytes)
    desc.extend_from_slice(&[7, 0x05, 0x82, 0x02, 64, 0x00, 0]);

    // Update total length in header
    let total_len = desc.len() as u16;
    desc[2..4].copy_from_slice(&total_len.to_le_bytes());

    desc
}

/// Builds the Binary Device Object Store (BOS) Descriptor.
/// Includes Microsoft OS 2.0 Platform Capability descriptor.
pub fn build_bos_descriptor(vendor_code: u8, ms_os_20_len: u16) -> Vec<u8> {
    let mut desc = Vec::new();

    // BOS Header (5 bytes)
    desc.extend_from_slice(&[
        5,    // bLength
        0x0F, // bDescriptorType: BOS
        0, 0, // wTotalLength (filled at the end)
        1, // bNumDeviceCaps: 1
    ]);

    // Microsoft OS 2.0 Platform Capability Descriptor (28 bytes)
    let ms_cap = aegis_fido_usb::winusb::build_ms_os_20_platform_capability_descriptor(
        vendor_code,
        ms_os_20_len,
    );
    desc.extend_from_slice(&ms_cap);

    let total_len = desc.len() as u16;
    desc[2..4].copy_from_slice(&total_len.to_le_bytes());

    desc
}

/// Encodes an ASCII/UTF-8 string into a standard USB String Descriptor (UTF-16LE).
pub fn encode_string_descriptor(s: &str) -> Vec<u8> {
    let mut utf16_bytes = Vec::new();
    for c in s.encode_utf16() {
        utf16_bytes.extend_from_slice(&c.to_le_bytes());
    }

    let length = 2 + utf16_bytes.len();
    let mut desc = Vec::with_capacity(length);
    desc.push(length as u8);
    desc.push(0x03); // bDescriptorType: STRING
    desc.extend_from_slice(&utf16_bytes);
    desc
}

/// Returns the string descriptor corresponding to index `idx`.
pub fn get_string_descriptor(idx: u8) -> Option<Vec<u8>> {
    match idx {
        0 => {
            // LangID Descriptor: 0x0409 (English US)
            Some(vec![4, 0x03, 0x09, 0x04])
        }
        1 => Some(encode_string_descriptor(MANUFACTURER_STRING)),
        2 => Some(encode_string_descriptor(PRODUCT_STRING)),
        3 => Some(encode_string_descriptor(SERIAL_NUMBER_STRING)),
        4 => Some(encode_string_descriptor(CTAPHID_INTERFACE_STRING)),
        5 => Some(encode_string_descriptor(CCID_INTERFACE_STRING)),
        6 => Some(encode_string_descriptor(KEYBOARD_INTERFACE_STRING)),
        7 => Some(encode_string_descriptor(WINUSB_INTERFACE_STRING)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_descriptor_fields() {
        let dev = build_device_descriptor();
        assert_eq!(dev[0], 18);
        assert_eq!(dev[1], 0x01);
        assert_eq!(u16::from_le_bytes([dev[8], dev[9]]), USB_VID);
        assert_eq!(u16::from_le_bytes([dev[10], dev[11]]), USB_PID);
    }

    #[test]
    fn test_config_descriptor_length_and_interfaces() {
        let cfg = build_configuration_descriptor();
        assert_eq!(cfg[1], 0x02);
        assert_eq!(cfg[4], 4); // 4 interfaces
        let total_len = u16::from_le_bytes([cfg[2], cfg[3]]) as usize;
        assert_eq!(cfg.len(), total_len);
    }

    #[test]
    fn test_string_descriptors() {
        let mfg = get_string_descriptor(1).unwrap();
        assert_eq!(mfg[1], 0x03);
        let prod = get_string_descriptor(2).unwrap();
        assert_eq!(prod[1], 0x03);
    }

    #[test]
    fn test_bos_descriptor() {
        let bos = build_bos_descriptor(0x02, 178);
        assert_eq!(bos[1], 0x0F);
        assert_eq!(bos[4], 1); // 1 dev cap
        let total_len = u16::from_le_bytes([bos[2], bos[3]]) as usize;
        assert_eq!(bos.len(), total_len);
    }
}
