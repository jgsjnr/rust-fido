//! Wave3 P1 — device identity with defaults = current bytes (v1 preservation).
//!
//! Defaults equal observed v1 bytes (G0: sem mudar bytes v1):
//! - VID `0x303A`, PID `0xAE61` (`usb_descriptors`)
//! - Serial `"AEGIS-S3-0001"`, manufacturer, product
//! - AAGUID `00..0F` (`attestation::AEGISKEY_AAGUID`, `info::DEFAULT_AAGUID`)
//!
//! Per-unit provisioning (auditoria):
//! - AAGUID/serial por unidade (nunca reutilizar entre unidades)
//! - eFuse OTP irreversivel (BLOCK7/8 write-once, verify-after-write)
//! - Segredos nunca no repo (gerar via `factory_provision.py`, nunca commitar)
// AUDIT-PREP: wiring na Wave4

extern crate alloc;
use alloc::string::String;

/// Default USB Vendor ID (Espressif, current byte).
pub const DEFAULT_USB_VID: u16 = 0x303A;
/// Default USB Product ID (AegisKey S3, current byte).
pub const DEFAULT_USB_PID: u16 = 0xAE61;
/// Default serial string (current byte).
pub const DEFAULT_SERIAL: &str = "AEGIS-S3-0001";
/// Default manufacturer string (current byte).
pub const DEFAULT_MANUFACTURER: &str = "Aegis Security";
/// Default product string (current byte).
pub const DEFAULT_PRODUCT: &str = "AegisKey S3 Authenticator";
/// Default AAGUID bytes (current bytes `00..0F`).
pub const DEFAULT_AAGUID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
/// Serial prefix enforced per-unit.
pub const SERIAL_PREFIX: &str = "AEGIS-S3-";
/// Maximum serial length (USB string descriptor budget, MAX-ESP).
pub const MAX_SERIAL_LEN: usize = 32;

/// Typed identity validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// VID or PID is zero (reserved).
    InvalidVidPid,
    /// Serial missing prefix, empty, or over budget.
    InvalidSerial,
    /// AAGUID is all-zero (unprovisioned).
    InvalidAaguid,
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidVidPid => write!(f, "vid/pid must be non-zero"),
            Self::InvalidSerial => write!(f, "serial must start with AEGIS-S3-"),
            Self::InvalidAaguid => write!(f, "aaguid must not be all-zero"),
        }
    }
}

/// Device identity (per-unit provisionable, defaults = v1 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    /// USB Vendor ID.
    pub vid: u16,
    /// USB Product ID.
    pub pid: u16,
    /// Serial string (per-unit, e.g. `AEGIS-S3-0001`).
    pub serial: String,
    /// Manufacturer string.
    pub manufacturer: String,
    /// Product string.
    pub product: String,
    /// Authenticator AAGUID (per-unit).
    pub aaguid: [u8; 16],
}

impl DeviceIdentity {
    /// Validates and constructs identity (`new() -> Result` pattern).
    pub fn new(
        vid: u16,
        pid: u16,
        serial: String,
        manufacturer: String,
        product: String,
        aaguid: [u8; 16],
    ) -> Result<Self, IdentityError> {
        if vid == 0 || pid == 0 {
            return Err(IdentityError::InvalidVidPid);
        }
        if !is_valid_serial(&serial) {
            return Err(IdentityError::InvalidSerial);
        }
        if aaguid.iter().all(|&b| b == 0) {
            return Err(IdentityError::InvalidAaguid);
        }
        Ok(Self {
            vid,
            pid,
            serial,
            manufacturer,
            product,
            aaguid,
        })
    }

    /// Current v1 bytes (no semantic change).
    pub fn default_identity() -> Self {
        Self {
            vid: DEFAULT_USB_VID,
            pid: DEFAULT_USB_PID,
            serial: String::from(DEFAULT_SERIAL),
            manufacturer: String::from(DEFAULT_MANUFACTURER),
            product: String::from(DEFAULT_PRODUCT),
            aaguid: DEFAULT_AAGUID,
        }
    }
}

impl Default for DeviceIdentity {
    fn default() -> Self {
        Self::default_identity()
    }
}

/// Checks serial prefix, non-empty suffix, and length budget.
fn is_valid_serial(serial: &str) -> bool {
    if serial.len() > MAX_SERIAL_LEN || serial.is_empty() {
        return false;
    }
    if !serial.starts_with(SERIAL_PREFIX) {
        return false;
    }
    serial.len() > SERIAL_PREFIX.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb_descriptors;

    #[test]
    fn defaults_equal_current_bytes() {
        let id = DeviceIdentity::default();
        assert_eq!(id.vid, usb_descriptors::USB_VID);
        assert_eq!(id.pid, usb_descriptors::USB_PID);
        assert_eq!(id.serial, usb_descriptors::SERIAL_NUMBER_STRING);
        assert_eq!(id.manufacturer, usb_descriptors::MANUFACTURER_STRING);
        assert_eq!(id.product, usb_descriptors::PRODUCT_STRING);
        assert_eq!(id.aaguid, DEFAULT_AAGUID);
        assert_eq!(id.vid, DEFAULT_USB_VID);
        assert_eq!(id.pid, DEFAULT_USB_PID);
    }

    #[test]
    fn defaults_match_attestation_aaguid() {
        let id = DeviceIdentity::default();
        assert_eq!(
            id.aaguid,
            aegis_fido_core::ctap::attestation::AEGISKEY_AAGUID
        );
    }

    #[test]
    fn rejects_zero_vid_pid() {
        let base = DeviceIdentity::default();
        assert_eq!(
            DeviceIdentity::new(0, base.pid, base.serial.clone(), base.manufacturer.clone(), base.product.clone(), base.aaguid),
            Err(IdentityError::InvalidVidPid)
        );
        assert_eq!(
            DeviceIdentity::new(base.vid, 0, base.serial.clone(), base.manufacturer.clone(), base.product.clone(), base.aaguid),
            Err(IdentityError::InvalidVidPid)
        );
    }

    #[test]
    fn rejects_bad_serial() {
        let base = DeviceIdentity::default();
        assert_eq!(
            DeviceIdentity::new(base.vid, base.pid, String::from("WRONG-0001"), base.manufacturer.clone(), base.product.clone(), base.aaguid),
            Err(IdentityError::InvalidSerial)
        );
        assert_eq!(
            DeviceIdentity::new(base.vid, base.pid, String::from("AEGIS-S3-"), base.manufacturer.clone(), base.product.clone(), base.aaguid),
            Err(IdentityError::InvalidSerial)
        );
    }

    #[test]
    fn rejects_zero_aaguid() {
        let base = DeviceIdentity::default();
        assert_eq!(
            DeviceIdentity::new(base.vid, base.pid, base.serial.clone(), base.manufacturer.clone(), base.product.clone(), [0u8; 16]),
            Err(IdentityError::InvalidAaguid)
        );
    }

    #[test]
    fn accepts_per_unit_identity() {
        let id = DeviceIdentity::new(
            0x303A,
            0xAE61,
            String::from("AEGIS-S3-00AF"),
            String::from("Aegis Security"),
            String::from("AegisKey S3 Authenticator"),
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f],
        )
        .expect("per-unit valid");
        assert_eq!(id.serial, "AEGIS-S3-00AF");
    }
}
