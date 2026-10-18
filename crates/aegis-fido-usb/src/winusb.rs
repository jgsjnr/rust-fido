//! WinUSB High-Speed Bulk Transport and Microsoft OS 2.0 Descriptors.
//!
//! Provides direct, high-throughput bulk transport (Bulk OUT 0x02, Bulk IN 0x82)
//! bypassing Windows CTAPHID user-mode filtering, with full support for Microsoft OS 2.0
//! Descriptors for driverless WinUSB.sys auto-binding on Windows 8.1, 10, and 11.
//! 100% Native Rust implementation.

/// Endpoint addresses
pub const WINUSB_BULK_OUT_EP: u8 = 0x02;
pub const WINUSB_BULK_IN_EP: u8 = 0x82;

/// Standard bulk packet transfer size (64 bytes for Full-Speed, up to 512 for High-Speed).
pub const BULK_CHUNK_SIZE: usize = 64;

/// Magic header: ASCII "AEGS" (0x41454753 in big-endian, or 0x53474541 in little-endian).
pub const WINUSB_MAGIC: [u8; 4] = [0x41, 0x45, 0x47, 0x53];

/// Vendor Control Request Code for Microsoft OS 2.0 Descriptors query.
pub const MS_OS_20_VENDOR_CODE: u8 = 0x02;
pub const MS_OS_20_DESCRIPTOR_INDEX: u16 = 0x0007;

/// Device Interface GUID for AegisKey WinUSB interface:
/// {7F3A5930-B14C-4D78-9B2F-9E07A2E50123}
pub const AEGISKEY_INTERFACE_GUID: &str = "{7F3A5930-B14C-4D78-9B2F-9E07A2E50123}";

// ============================================================================
// WinUSB Bulk Commands
// ============================================================================
pub const CMD_PING: u8 = 0x01;
pub const CMD_CTAP2_CBOR: u8 = 0x02;
pub const CMD_VAULT_EXPORT: u8 = 0x03;
pub const CMD_VAULT_IMPORT: u8 = 0x04;
pub const CMD_DEVICE_INFO: u8 = 0x05;
pub const CMD_CONFIG_UPDATE: u8 = 0x06;
pub const CMD_OATH_COMMAND: u8 = 0x07;

// ============================================================================
// WinUSB Bulk Status Codes
// ============================================================================
pub const STATUS_OK: u16 = 0x0000;
pub const STATUS_INVALID_CMD: u16 = 0x0001;
pub const STATUS_AUTH_REQUIRED: u16 = 0x0002;
pub const STATUS_IO_ERROR: u16 = 0x0003;
pub const STATUS_CORRUPTED: u16 = 0x0004;

/// Represents a WinUSB bulk protocol frame.
///
/// Header (12 bytes):
/// - Bytes 0..4: Magic [0x41, 0x45, 0x47, 0x53] ("AEGS")
/// - Byte 4: Command (u8)
/// - Byte 5: Flags (u8)
/// - Bytes 6..8: Status (u16 little-endian)
/// - Bytes 8..12: Payload Length (u32 little-endian)
/// Followed by `length` bytes of payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinUsbMessage {
    pub cmd: u8,
    pub flags: u8,
    pub status: u16,
    pub payload: Vec<u8>,
}

impl WinUsbMessage {
    pub fn new(cmd: u8, flags: u8, status: u16, payload: Vec<u8>) -> Self {
        Self {
            cmd,
            flags,
            status,
            payload,
        }
    }

    pub fn ok(cmd: u8, payload: Vec<u8>) -> Self {
        Self::new(cmd, 0, STATUS_OK, payload)
    }

    pub fn error(cmd: u8, status: u16) -> Self {
        Self::new(cmd, 0, status, Vec::new())
    }

    /// Serializes the message into the complete byte buffer including the 12-byte header.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.payload.len());
        out.extend_from_slice(&WINUSB_MAGIC);
        out.push(self.cmd);
        out.push(self.flags);
        out.extend_from_slice(&self.status.to_le_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Splits the serialized message into 64-byte USB bulk packets.
    pub fn to_bulk_packets(&self) -> Vec<Vec<u8>> {
        let bytes = self.to_bytes();
        let mut packets = Vec::new();
        for chunk in bytes.chunks(BULK_CHUNK_SIZE) {
            packets.push(chunk.to_vec());
        }
        packets
    }
}

/// WinUSB streaming deframer for receiving bulk transfers.
pub struct WinUsbDeframer {
    buffer: Vec<u8>,
}

impl Default for WinUsbDeframer {
    fn default() -> Self {
        Self::new()
    }
}

impl WinUsbDeframer {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Clears the deframer buffer.
    pub fn reset(&mut self) {
        self.buffer.clear();
    }

    /// Feeds incoming bulk OUT packet data.
    ///
    /// If a complete message has been assembled, extracts it and returns `Ok(Some(WinUsbMessage))`.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Option<WinUsbMessage>, &'static str> {
        self.buffer.extend_from_slice(chunk);

        if self.buffer.len() < 12 {
            // Need more data for header
            return Ok(None);
        }

        // Verify magic
        if &self.buffer[0..4] != &WINUSB_MAGIC {
            self.buffer.clear();
            return Err("Invalid WinUSB bulk magic header");
        }

        let cmd = self.buffer[4];
        let flags = self.buffer[5];
        let status = u16::from_le_bytes([self.buffer[6], self.buffer[7]]);
        let payload_len = u32::from_le_bytes([
            self.buffer[8],
            self.buffer[9],
            self.buffer[10],
            self.buffer[11],
        ]) as usize;

        let total_expected = 12 + payload_len;
        if self.buffer.len() >= total_expected {
            let payload = self.buffer[12..total_expected].to_vec();
            self.buffer.drain(..total_expected);
            Ok(Some(WinUsbMessage::new(cmd, flags, status, payload)))
        } else {
            Ok(None)
        }
    }
}

// ============================================================================
// Microsoft OS 2.0 Descriptors Builder
// ============================================================================

/// Generates the Microsoft OS 2.0 Platform Capability Descriptor
/// to be embedded into the USB BOS (Binary Device Object Store) descriptor.
pub fn build_ms_os_20_platform_capability_descriptor(
    vendor_code: u8,
    descriptor_set_len: u16,
) -> [u8; 28] {
    let mut desc = [0u8; 28];
    desc[0] = 28; // bLength
    desc[1] = 0x10; // bDescriptorType: DEVICE CAPABILITY
    desc[2] = 0x05; // bDevCapabilityType: PLATFORM
    desc[3] = 0x00; // bReserved

    // MS OS 2.0 Platform Capability UUID: D8DD60DF-4589-4CC7-9CD2-659D9E648A9F
    desc[4..20].copy_from_slice(&[
        0xDF, 0x60, 0xDD, 0xD8, 0x89, 0x45, 0xC7, 0x4C, 0x9C, 0xD2, 0x65, 0x9D, 0x9E, 0x64,
        0x8A, 0x9F,
    ]);

    // dwWindowsVersion: 0x06030000 (Windows 8.1+)
    desc[20..24].copy_from_slice(&0x06030000u32.to_le_bytes());

    // wMSOSDescriptorSetTotalLength
    desc[24..26].copy_from_slice(&descriptor_set_len.to_le_bytes());

    // bMS_VendorCode
    desc[26] = vendor_code;

    // bAltEnumCode (0 = do not support alternate enumeration)
    desc[27] = 0x00;

    desc
}

/// Generates the Microsoft OS 2.0 Descriptor Set returned during Vendor Request.
/// Configures interface 3 as Compatible ID "WINUSB" with DeviceInterfaceGUIDs registry key.
pub fn build_ms_os_20_descriptor_set(winusb_interface_idx: u8) -> Vec<u8> {
    let mut out = Vec::new();

    // 1. MS OS 2.0 Descriptor Set Header (10 bytes)
    // 2. MS OS 2.0 Configuration Subset Header (8 bytes)
    // 3. MS OS 2.0 Function Subset Header (8 bytes)
    // 4. MS OS 2.0 Compatible ID Descriptor (20 bytes)
    // 5. MS OS 2.0 Registry Property Descriptor for DeviceInterfaceGUIDs
    //    Header (10 bytes) + Name ("DeviceInterfaceGUIDs\0" = 42 bytes) + Value ("{GUID}\0\0" = 80 bytes) = 132 bytes

    // Total length calculation:
    // Header (10) + Config Subset (8) + Function Subset (8) + Compatible ID (20) + Registry Prop (10 + 42 + 80) = 178 bytes.
    let total_len: u16 = 10 + 8 + 8 + 20 + (10 + 42 + 80);
    let config_subset_len: u16 = 8 + 8 + 20 + (10 + 42 + 80);
    let function_subset_len: u16 = 8 + 20 + (10 + 42 + 80);

    // --- 1. Set Header ---
    out.extend_from_slice(&10u16.to_le_bytes()); // wLength: 10
    out.extend_from_slice(&0x0000u16.to_le_bytes()); // wDescriptorType: SET_HEADER
    out.extend_from_slice(&0x06030000u32.to_le_bytes()); // dwWindowsVersion: Win 8.1+
    out.extend_from_slice(&total_len.to_le_bytes()); // wTotalLength

    // --- 2. Configuration Subset Header ---
    out.extend_from_slice(&8u16.to_le_bytes()); // wLength: 8
    out.extend_from_slice(&0x0001u16.to_le_bytes()); // wDescriptorType: SUBSET_HEADER_CONFIGURATION
    out.push(0); // bConfigurationValue
    out.push(0); // bReserved
    out.extend_from_slice(&config_subset_len.to_le_bytes()); // wTotalLength

    // --- 3. Function Subset Header ---
    out.extend_from_slice(&8u16.to_le_bytes()); // wLength: 8
    out.extend_from_slice(&0x0002u16.to_le_bytes()); // wDescriptorType: SUBSET_HEADER_FUNCTION
    out.push(winusb_interface_idx); // bFirstInterface
    out.push(0); // bReserved
    out.extend_from_slice(&function_subset_len.to_le_bytes()); // wSubsetLength

    // --- 4. Compatible ID Descriptor ---
    out.extend_from_slice(&20u16.to_le_bytes()); // wLength: 20
    out.extend_from_slice(&0x0003u16.to_le_bytes()); // wDescriptorType: FEATURE_COMPATIBLE_ID
    out.extend_from_slice(b"WINUSB\0\0"); // Compatible ID: "WINUSB" (8 bytes)
    out.extend_from_slice(&[0u8; 8]); // SubCompatible ID: none (8 bytes)

    // --- 5. Registry Property Descriptor (DeviceInterfaceGUIDs) ---
    let prop_name = "DeviceInterfaceGUIDs\0";
    let mut prop_name_utf16 = Vec::new();
    for c in prop_name.encode_utf16() {
        prop_name_utf16.extend_from_slice(&c.to_le_bytes());
    }

    let mut prop_val_utf16 = Vec::new();
    for c in AEGISKEY_INTERFACE_GUID.encode_utf16() {
        prop_val_utf16.extend_from_slice(&c.to_le_bytes());
    }
    // Double null terminator for REG_MULTI_SZ
    prop_val_utf16.extend_from_slice(&0u16.to_le_bytes());
    prop_val_utf16.extend_from_slice(&0u16.to_le_bytes());

    let reg_prop_len = 10 + (prop_name_utf16.len() as u16) + (prop_val_utf16.len() as u16);
    out.extend_from_slice(&reg_prop_len.to_le_bytes());
    out.extend_from_slice(&0x0004u16.to_le_bytes()); // wDescriptorType: FEATURE_REG_PROPERTY
    out.extend_from_slice(&0x0007u16.to_le_bytes()); // wPropertyDataType: REG_MULTI_SZ (7)
    out.extend_from_slice(&(prop_name_utf16.len() as u16).to_le_bytes());
    out.extend_from_slice(&prop_name_utf16);
    out.extend_from_slice(&(prop_val_utf16.len() as u16).to_le_bytes());
    out.extend_from_slice(&prop_val_utf16);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_winusb_message_roundtrip() {
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let msg = WinUsbMessage::ok(CMD_CTAP2_CBOR, payload.clone());
        let packets = msg.to_bulk_packets();

        let mut deframer = WinUsbDeframer::new();
        let mut assembled = None;
        for pkt in &packets {
            if let Some(m) = deframer.feed(pkt).unwrap() {
                assembled = Some(m);
            }
        }

        assert!(assembled.is_some());
        let m = assembled.unwrap();
        assert_eq!(m.cmd, CMD_CTAP2_CBOR);
        assert_eq!(m.status, STATUS_OK);
        assert_eq!(m.payload, payload);
    }

    #[test]
    fn test_ms_os_20_platform_capability() {
        let cap = build_ms_os_20_platform_capability_descriptor(MS_OS_20_VENDOR_CODE, 178);
        assert_eq!(cap[0], 28); // Length
        assert_eq!(cap[1], 0x10); // Device capability
        assert_eq!(cap[2], 0x05); // Platform
        assert_eq!(cap[26], MS_OS_20_VENDOR_CODE);
        assert_eq!(u16::from_le_bytes([cap[24], cap[25]]), 178);
    }

    #[test]
    fn test_ms_os_20_descriptor_set() {
        let set = build_ms_os_20_descriptor_set(3);
        assert_eq!(set.len(), 178);
        assert_eq!(&set[2..4], &0x0000u16.to_le_bytes()); // SET_HEADER
        assert_eq!(u16::from_le_bytes([set[8], set[9]]), 178); // wTotalLength
        // Verify "WINUSB" string exists in the descriptor set
        let winusb_bytes = b"WINUSB";
        assert!(set.windows(6).any(|w| w == winusb_bytes));
    }
}
