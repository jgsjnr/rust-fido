//! Secure Channel DTOs and CBOR codecs (`GAP-02`).
//!
//! Provides data transfer objects and wire encoding for ephemeral ECDH P-256 key exchange
//! and encrypted PIN payloads across the transport bus.

use crate::error::SdkError;
use alloc::vec;
use alloc::vec::Vec;
use ciborium::value::Value;

/// DTO representing an ephemeral ECDH key agreement exchange.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecureChannelKeyExchangeDto {
    /// 65-byte uncompressed SEC1 public key of the device (`0x04 || X || Y`).
    pub device_public_key_sec1: Vec<u8>,
    /// 65-byte uncompressed SEC1 public key of the host (`0x04 || X || Y`).
    pub host_public_key_sec1: Vec<u8>,
}

/// DTO representing an encrypted, authenticated PIN payload.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EncryptedPinPayloadDto {
    /// Encrypted PIN ciphertext.
    pub ciphertext: Vec<u8>,
    /// 32-byte HMAC-SHA256 authentication tag.
    pub tag: [u8; 32],
    /// 12-byte initialization nonce.
    pub nonce: [u8; 12],
    /// Monotonic sequence counter.
    pub counter: u32,
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

/// Encodes an ephemeral key exchange message to CBOR.
pub fn encode_secure_channel_key_exchange(
    device_pub: &[u8],
    host_pub: &[u8],
) -> Result<Vec<u8>, SdkError> {
    let map = vec![
        (
            Value::Text("device_pub".into()),
            Value::Bytes(device_pub.to_vec()),
        ),
        (
            Value::Text("host_pub".into()),
            Value::Bytes(host_pub.to_vec()),
        ),
    ];
    to_cbor(&Value::Map(map))
}

/// Decodes an ephemeral key exchange message from CBOR.
pub fn decode_secure_channel_key_exchange(
    payload: &[u8],
) -> Result<SecureChannelKeyExchangeDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let device_pub = match get_field(&entries, "device_pub") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => Vec::new(),
    };
    let host_pub = match get_field(&entries, "host_pub") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => Vec::new(),
    };

    Ok(SecureChannelKeyExchangeDto {
        device_public_key_sec1: device_pub,
        host_public_key_sec1: host_pub,
    })
}

/// Encodes an encrypted PIN payload to CBOR.
pub fn encode_encrypted_pin_payload(dto: &EncryptedPinPayloadDto) -> Result<Vec<u8>, SdkError> {
    let map = vec![
        (
            Value::Text("ciphertext".into()),
            Value::Bytes(dto.ciphertext.clone()),
        ),
        (
            Value::Text("tag".into()),
            Value::Bytes(dto.tag.to_vec()),
        ),
        (
            Value::Text("nonce".into()),
            Value::Bytes(dto.nonce.to_vec()),
        ),
        (
            Value::Text("counter".into()),
            Value::from(dto.counter as u64),
        ),
    ];
    to_cbor(&Value::Map(map))
}

/// Decodes an encrypted PIN payload from CBOR.
pub fn decode_encrypted_pin_payload(payload: &[u8]) -> Result<EncryptedPinPayloadDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let ciphertext = match get_field(&entries, "ciphertext") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err(SdkError::Unsupported),
    };

    let tag_bytes = match get_field(&entries, "tag") {
        Some(Value::Bytes(b)) if b.len() == 32 => b.as_slice(),
        _ => return Err(SdkError::Unsupported),
    };
    let mut tag = [0u8; 32];
    tag.copy_from_slice(tag_bytes);

    let nonce_bytes = match get_field(&entries, "nonce") {
        Some(Value::Bytes(b)) if b.len() == 12 => b.as_slice(),
        _ => return Err(SdkError::Unsupported),
    };
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_bytes);

    let counter = match get_field(&entries, "counter") {
        Some(Value::Integer(i)) => i128::from(*i) as u32,
        _ => return Err(SdkError::Unsupported),
    };

    Ok(EncryptedPinPayloadDto {
        ciphertext,
        tag,
        nonce,
        counter,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_channel_key_exchange_codec() {
        let dev_pub = vec![0x04; 65];
        let host_pub = vec![0x04; 65];

        let encoded = encode_secure_channel_key_exchange(&dev_pub, &host_pub).expect("encode");
        let decoded = decode_secure_channel_key_exchange(&encoded).expect("decode");

        assert_eq!(decoded.device_public_key_sec1, dev_pub);
        assert_eq!(decoded.host_public_key_sec1, host_pub);
    }

    #[test]
    fn test_encrypted_pin_payload_codec() {
        let dto = EncryptedPinPayloadDto {
            ciphertext: vec![0x11, 0x22, 0x33, 0x44],
            tag: [0xAA; 32],
            nonce: [0x55; 12],
            counter: 42,
        };

        let encoded = encode_encrypted_pin_payload(&dto).expect("encode");
        let decoded = decode_encrypted_pin_payload(&encoded).expect("decode");

        assert_eq!(decoded, dto);
    }
}
