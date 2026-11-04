//! CTAP 2.1 Extension DTOs and CBOR codecs (`OPP-02`).
//!
//! Provides typed structures and wire serialization for `hmac-secret` and `largeBlobs`.

use crate::error::SdkError;
use alloc::vec;
use alloc::vec::Vec;
use ciborium::value::Value;

/// DTO for a CTAP 2.1 `hmac-secret` evaluation request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HmacSecretRequestDto {
    /// 32-byte primary salt.
    pub salt1: [u8; 32],
    /// Optional 32-byte secondary salt.
    pub salt2: Option<[u8; 32]>,
    /// Whether User Verification was required/performed.
    pub uv_required: bool,
}

/// DTO for a CTAP 2.1 `hmac-secret` evaluation response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HmacSecretResponseDto {
    /// 32-byte primary HMAC output.
    pub output1: [u8; 32],
    /// Optional 32-byte secondary HMAC output.
    pub output2: Option<[u8; 32]>,
}

/// DTO representing an authenticated large blob entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LargeBlobEntryDto {
    /// 32-byte `largeBlobKey` digest.
    pub key: [u8; 32],
    /// Stored data payload.
    pub data: Vec<u8>,
}

/// DTO representing status and telemetry of the Large Blob Store.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LargeBlobStoreStatusDto {
    pub total_size: usize,
    pub capacity: usize,
    pub is_integrity_valid: bool,
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

/// Encodes an `hmac-secret` request to CBOR.
pub fn encode_hmac_secret_request(dto: &HmacSecretRequestDto) -> Result<Vec<u8>, SdkError> {
    let mut map = vec![
        (
            Value::Text("salt1".into()),
            Value::Bytes(dto.salt1.to_vec()),
        ),
        (
            Value::Text("uv_required".into()),
            Value::Bool(dto.uv_required),
        ),
    ];
    if let Some(s2) = dto.salt2 {
        map.push((Value::Text("salt2".into()), Value::Bytes(s2.to_vec())));
    }
    to_cbor(&Value::Map(map))
}

/// Decodes an `hmac-secret` request from CBOR.
pub fn decode_hmac_secret_request(payload: &[u8]) -> Result<HmacSecretRequestDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let salt1_bytes = match get_field(&entries, "salt1") {
        Some(Value::Bytes(b)) if b.len() == 32 => b.as_slice(),
        _ => return Err(SdkError::Unsupported),
    };
    let mut salt1 = [0u8; 32];
    salt1.copy_from_slice(salt1_bytes);

    let salt2 = match get_field(&entries, "salt2") {
        Some(Value::Bytes(b)) if b.len() == 32 => {
            let mut s2 = [0u8; 32];
            s2.copy_from_slice(b.as_slice());
            Some(s2)
        }
        _ => None,
    };

    let uv_required = match get_field(&entries, "uv_required") {
        Some(Value::Bool(b)) => *b,
        _ => false,
    };

    Ok(HmacSecretRequestDto {
        salt1,
        salt2,
        uv_required,
    })
}

/// Encodes an `hmac-secret` response to CBOR.
pub fn encode_hmac_secret_response(dto: &HmacSecretResponseDto) -> Result<Vec<u8>, SdkError> {
    let mut map = vec![(
        Value::Text("output1".into()),
        Value::Bytes(dto.output1.to_vec()),
    )];
    if let Some(o2) = dto.output2 {
        map.push((Value::Text("output2".into()), Value::Bytes(o2.to_vec())));
    }
    to_cbor(&Value::Map(map))
}

/// Decodes an `hmac-secret` response from CBOR.
pub fn decode_hmac_secret_response(payload: &[u8]) -> Result<HmacSecretResponseDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let out1_bytes = match get_field(&entries, "output1") {
        Some(Value::Bytes(b)) if b.len() == 32 => b.as_slice(),
        _ => return Err(SdkError::Unsupported),
    };
    let mut output1 = [0u8; 32];
    output1.copy_from_slice(out1_bytes);

    let output2 = match get_field(&entries, "output2") {
        Some(Value::Bytes(b)) if b.len() == 32 => {
            let mut o2 = [0u8; 32];
            o2.copy_from_slice(b.as_slice());
            Some(o2)
        }
        _ => None,
    };

    Ok(HmacSecretResponseDto { output1, output2 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_secret_request_codec() {
        let req = HmacSecretRequestDto {
            salt1: [0x11; 32],
            salt2: Some([0x22; 32]),
            uv_required: true,
        };
        let encoded = encode_hmac_secret_request(&req).expect("encode");
        let decoded = decode_hmac_secret_request(&encoded).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    fn test_hmac_secret_response_codec() {
        let resp = HmacSecretResponseDto {
            output1: [0xAA; 32],
            output2: Some([0xBB; 32]),
        };
        let encoded = encode_hmac_secret_response(&resp).expect("encode");
        let decoded = decode_hmac_secret_response(&encoded).expect("decode");
        assert_eq!(decoded, resp);
    }
}
