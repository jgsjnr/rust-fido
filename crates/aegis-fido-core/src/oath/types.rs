extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// YKOATH Application Identifier (AID)
pub const YKOATH_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

/// YKOATH Instructions (INS)
pub const INS_PUT: u8 = 0x01;
pub const INS_DELETE: u8 = 0x02;
pub const INS_SET_CODE: u8 = 0x03;
pub const INS_RESET: u8 = 0x04;
pub const INS_LIST: u8 = 0xA1;
pub const INS_CALCULATE: u8 = 0xA2;
pub const INS_VALIDATE: u8 = 0xA3;
pub const INS_CALCULATE_ALL: u8 = 0xA4;
pub const INS_SELECT: u8 = 0xA4; // CLA=0x00, INS=0xA4, P1=0x04

/// YKOATH TLV Tags
pub const TAG_NAME: u8 = 0x71;
pub const TAG_NAME_LIST: u8 = 0x72;
pub const TAG_KEY: u8 = 0x73;
pub const TAG_CHALLENGE: u8 = 0x74;
pub const TAG_RESPONSE: u8 = 0x75;
pub const TAG_TRUNCATED_RESPONSE: u8 = 0x76;
pub const TAG_HOTP: u8 = 0x77;
pub const TAG_PROPERTY: u8 = 0x78;
pub const TAG_VERSION: u8 = 0x79;
pub const TAG_IMF: u8 = 0x7A;
pub const TAG_ALGORITHM: u8 = 0x7B;
pub const TAG_TOUCH: u8 = 0x7C;

/// YKOATH Status Words
pub const SW_SUCCESS: u16 = 0x9000;
pub const SW_SECURITY_STATUS_NOT_SATISFIED: u16 = 0x6982;
pub const SW_AUTH_METHOD_BLOCKED: u16 = 0x6983;
pub const SW_DATA_INVALID: u16 = 0x6984;
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
pub const SW_WRONG_DATA: u16 = 0x6A80;
pub const SW_FILE_FULL: u16 = 0x6A84;
pub const SW_DATA_NOT_FOUND: u16 = 0x6A88;
pub const SW_WRONG_P1P2: u16 = 0x6B00;
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
pub const SW_CLA_NOT_SUPPORTED: u16 = 0x6E00;

/// Supported HMAC Algorithms in YKOATH
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, zeroize::Zeroize)]
#[repr(u8)]
pub enum OathAlgorithm {
    Sha1 = 0x01,
    Sha256 = 0x02,
    Sha512 = 0x03,
}

impl OathAlgorithm {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(OathAlgorithm::Sha1),
            0x02 => Some(OathAlgorithm::Sha256),
            0x03 => Some(OathAlgorithm::Sha512),
            _ => None,
        }
    }
}

/// OATH Type: HOTP (event-based) or TOTP (time-based)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, zeroize::Zeroize)]
#[repr(u8)]
pub enum OathType {
    Hotp = 0x10,
    Totp = 0x20,
}

impl OathType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x10 => Some(OathType::Hotp),
            0x20 => Some(OathType::Totp),
            _ => None,
        }
    }
}

/// Stored OATH Credential
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OathCredential {
    pub name: String,
    pub secret: Vec<u8>,
    pub algorithm: OathAlgorithm,
    pub digits: u8,
    pub oath_type: OathType,
    pub counter: u64,
    pub touch_required: bool,
}

impl OathCredential {
    pub fn new(
        name: String,
        secret: Vec<u8>,
        algorithm: OathAlgorithm,
        digits: u8,
        oath_type: OathType,
        counter: u64,
        touch_required: bool,
    ) -> Self {
        Self {
            name,
            secret,
            algorithm,
            digits: if digits == 0 { 6 } else { digits },
            oath_type,
            counter,
            touch_required,
        }
    }

    /// Returns the property type/algo byte: (type | algorithm)
    pub fn type_algo_byte(&self) -> u8 {
        (self.oath_type as u8) | (self.algorithm as u8)
    }
}

/// Errors occurring during OATH processing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OathError {
    SecurityNotSatisfied,
    ConditionsNotSatisfied, // Touch required or timeout
    WrongData,
    DataNotFound,
    FileFull,
    InvalidLength,
    InstructionNotSupported,
    ClassNotSupported,
    CryptoError,
}

impl OathError {
    pub fn to_sw(self) -> u16 {
        match self {
            OathError::SecurityNotSatisfied => SW_SECURITY_STATUS_NOT_SATISFIED,
            OathError::ConditionsNotSatisfied => SW_CONDITIONS_NOT_SATISFIED,
            OathError::WrongData => SW_WRONG_DATA,
            OathError::DataNotFound => SW_DATA_NOT_FOUND,
            OathError::FileFull => SW_FILE_FULL,
            OathError::InvalidLength => SW_WRONG_DATA,
            OathError::InstructionNotSupported => SW_INS_NOT_SUPPORTED,
            OathError::ClassNotSupported => SW_CLA_NOT_SUPPORTED,
            OathError::CryptoError => SW_DATA_INVALID,
        }
    }
}
