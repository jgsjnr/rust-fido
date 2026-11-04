//! Shamir Secret Sharing & DS/HMAC Seed Envelope DTOs and codecs (`OPP-03`, `OPP-05`).
//!
//! Provides typed structures and CBOR encoding for Shamir 2-of-3 splits and recoveries.

use crate::error::SdkError;
use alloc::vec;
use alloc::vec::Vec;
use ciborium::value::Value;

/// DTO representing a single Shamir share in a 2-of-3 threshold scheme.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShamirShareDto {
    /// Share index in 1..=3.
    pub index: u8,
    /// 32-byte share point evaluation.
    pub data: [u8; 32],
    /// IEEE 802.3 CRC32 checksum of original secret.
    pub crc32: u32,
}

/// DTO for a 2-of-3 split request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShamirSplitRequestDto {
    /// 32-byte secret to be split.
    pub secret: [u8; 32],
}

/// DTO containing the resulting 3 shares from a 2-of-3 split.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShamirSplitResponseDto {
    /// Vector of 3 Shamir shares (Primary, Backup, Paper).
    pub shares: Vec<ShamirShareDto>,
}

/// DTO for reconstructing a secret from 2 shares.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShamirRecoverRequestDto {
    pub share_a: ShamirShareDto,
    pub share_b: ShamirShareDto,
}

/// DTO containing the recovered secret.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShamirRecoverResponseDto {
    pub recovered_secret: [u8; 32],
}

/// DTO for a hardware DS/HMAC BIP-39 sealed seed envelope.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DsHmacSeedEnvelopeDto {
    pub nonce: [u8; 12],
    pub ciphertext_and_tag: Vec<u8>,
}

// --- Internal CBOR Helpers ---

fn to_cbor(val: &Value) -> Result<Vec<u8>, SdkError> {
    let mut out = Vec::new();
    ciborium::into_writer(val, &mut out).map_err(|_| SdkError::Unsupported)?;
    Ok(out)
}

fn from_cbor(bytes: &[u8]) -> Result<Value, SdkError> {
    ciborium::from_reader(bytes).map_err(|_| SdkError::Unsupported)
}

fn get_field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    for (k, v) in entries {
        if let Value::Text(s) = k {
            if s == key {
                return Some(v);
            }
        }
    }
    None
}

fn share_to_cbor_value(share: &ShamirShareDto) -> Value {
    let map = vec![
        (Value::Text("index".into()), Value::from(share.index)),
        (
            Value::Text("data".into()),
            Value::Bytes(share.data.to_vec()),
        ),
        (Value::Text("crc32".into()), Value::from(share.crc32 as u64)),
    ];
    Value::Map(map)
}

fn share_from_cbor_value(val: &Value) -> Result<ShamirShareDto, SdkError> {
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let index = match get_field(entries, "index") {
        Some(Value::Integer(i)) => i128::from(*i) as u8,
        _ => return Err(SdkError::Unsupported),
    };

    let data_bytes = match get_field(entries, "data") {
        Some(Value::Bytes(b)) if b.len() == 32 => b.as_slice(),
        _ => return Err(SdkError::Unsupported),
    };
    let mut data = [0u8; 32];
    data.copy_from_slice(data_bytes);

    let crc32 = match get_field(entries, "crc32") {
        Some(Value::Integer(i)) => i128::from(*i) as u32,
        _ => return Err(SdkError::Unsupported),
    };

    Ok(ShamirShareDto { index, data, crc32 })
}

/// Encodes a Shamir split response to CBOR.
pub fn encode_shamir_split_response(dto: &ShamirSplitResponseDto) -> Result<Vec<u8>, SdkError> {
    let shares_val: Vec<Value> = dto.shares.iter().map(share_to_cbor_value).collect();
    let map = vec![(Value::Text("shares".into()), Value::Array(shares_val))];
    to_cbor(&Value::Map(map))
}

/// Decodes a Shamir split response from CBOR.
pub fn decode_shamir_split_response(payload: &[u8]) -> Result<ShamirSplitResponseDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let shares_arr = match get_field(&entries, "shares") {
        Some(Value::Array(a)) => a,
        _ => return Err(SdkError::Unsupported),
    };

    let mut shares = Vec::with_capacity(shares_arr.len());
    for s_val in shares_arr {
        shares.push(share_from_cbor_value(s_val)?);
    }

    Ok(ShamirSplitResponseDto { shares })
}

/// Encodes a Shamir recover request to CBOR.
pub fn encode_shamir_recover_request(dto: &ShamirRecoverRequestDto) -> Result<Vec<u8>, SdkError> {
    let map = vec![
        (
            Value::Text("share_a".into()),
            share_to_cbor_value(&dto.share_a),
        ),
        (
            Value::Text("share_b".into()),
            share_to_cbor_value(&dto.share_b),
        ),
    ];
    to_cbor(&Value::Map(map))
}

/// Decodes a Shamir recover request from CBOR.
pub fn decode_shamir_recover_request(payload: &[u8]) -> Result<ShamirRecoverRequestDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let share_a_val = match get_field(&entries, "share_a") {
        Some(v) => v,
        _ => return Err(SdkError::Unsupported),
    };
    let share_b_val = match get_field(&entries, "share_b") {
        Some(v) => v,
        _ => return Err(SdkError::Unsupported),
    };

    let share_a = share_from_cbor_value(share_a_val)?;
    let share_b = share_from_cbor_value(share_b_val)?;

    Ok(ShamirRecoverRequestDto { share_a, share_b })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_split_response_codec() {
        let dto = ShamirSplitResponseDto {
            shares: vec![
                ShamirShareDto {
                    index: 1,
                    data: [0x11; 32],
                    crc32: 0x12345678,
                },
                ShamirShareDto {
                    index: 2,
                    data: [0x22; 32],
                    crc32: 0x12345678,
                },
                ShamirShareDto {
                    index: 3,
                    data: [0x33; 32],
                    crc32: 0x12345678,
                },
            ],
        };

        let encoded = encode_shamir_split_response(&dto).expect("encode");
        let decoded = decode_shamir_split_response(&encoded).expect("decode");

        assert_eq!(decoded, dto);
    }

    #[test]
    fn test_shamir_recover_request_codec() {
        let req = ShamirRecoverRequestDto {
            share_a: ShamirShareDto {
                index: 1,
                data: [0xAA; 32],
                crc32: 0xCAFEBABE,
            },
            share_b: ShamirShareDto {
                index: 2,
                data: [0xBB; 32],
                crc32: 0xCAFEBABE,
            },
        };

        let encoded = encode_shamir_recover_request(&req).expect("encode");
        let decoded = decode_shamir_recover_request(&encoded).expect("decode");

        assert_eq!(decoded, req);
    }
}
