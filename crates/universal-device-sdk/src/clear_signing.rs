//! Clear Signing & OLED Preview DTOs and codecs (`OPP-06`).
//!
//! Provides typed data transfer objects for Web3 transaction verification and 128x64 display frames.

use crate::error::SdkError;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use ciborium::value::Value;

/// DTO representing a human-readable Web3 transaction summary for clear signing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClearSignSummaryDto {
    pub network: String,
    pub action: String,
    pub to_address: String,
    pub amount: String,
    pub tx_hash_hex: String,
}

/// DTO representing the 4-line clear signing visual preview and optional 1024-byte framebuffer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OledPreviewDto {
    pub line1_network: String,
    pub line2_to: String,
    pub line3_amount: String,
    pub line4_prompt: String,
    pub framebuffer_1024_bytes: Option<Vec<u8>>,
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

fn get_str(entries: &[(Value, Value)], key: &str) -> String {
    get_field(entries, key)
        .and_then(|v| match v {
            Value::Text(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Encodes a clear-signing summary to CBOR.
pub fn encode_clear_sign_summary(dto: &ClearSignSummaryDto) -> Result<Vec<u8>, SdkError> {
    let map = vec![
        (
            Value::Text("network".into()),
            Value::Text(dto.network.clone()),
        ),
        (
            Value::Text("action".into()),
            Value::Text(dto.action.clone()),
        ),
        (
            Value::Text("to_address".into()),
            Value::Text(dto.to_address.clone()),
        ),
        (
            Value::Text("amount".into()),
            Value::Text(dto.amount.clone()),
        ),
        (
            Value::Text("tx_hash_hex".into()),
            Value::Text(dto.tx_hash_hex.clone()),
        ),
    ];
    to_cbor(&Value::Map(map))
}

/// Decodes a clear-signing summary from CBOR.
pub fn decode_clear_sign_summary(payload: &[u8]) -> Result<ClearSignSummaryDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    Ok(ClearSignSummaryDto {
        network: get_str(&entries, "network"),
        action: get_str(&entries, "action"),
        to_address: get_str(&entries, "to_address"),
        amount: get_str(&entries, "amount"),
        tx_hash_hex: get_str(&entries, "tx_hash_hex"),
    })
}

/// Encodes an OLED preview DTO to CBOR.
pub fn encode_oled_preview(dto: &OledPreviewDto) -> Result<Vec<u8>, SdkError> {
    let mut map = vec![
        (
            Value::Text("line1_network".into()),
            Value::Text(dto.line1_network.clone()),
        ),
        (
            Value::Text("line2_to".into()),
            Value::Text(dto.line2_to.clone()),
        ),
        (
            Value::Text("line3_amount".into()),
            Value::Text(dto.line3_amount.clone()),
        ),
        (
            Value::Text("line4_prompt".into()),
            Value::Text(dto.line4_prompt.clone()),
        ),
    ];
    if let Some(fb) = &dto.framebuffer_1024_bytes {
        map.push((Value::Text("framebuffer".into()), Value::Bytes(fb.clone())));
    }
    to_cbor(&Value::Map(map))
}

/// Decodes an OLED preview DTO from CBOR.
pub fn decode_oled_preview(payload: &[u8]) -> Result<OledPreviewDto, SdkError> {
    let val = from_cbor(payload)?;
    let entries = match val {
        Value::Map(m) => m,
        _ => return Err(SdkError::Unsupported),
    };

    let fb = match get_field(&entries, "framebuffer") {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    };

    Ok(OledPreviewDto {
        line1_network: get_str(&entries, "line1_network"),
        line2_to: get_str(&entries, "line2_to"),
        line3_amount: get_str(&entries, "line3_amount"),
        line4_prompt: get_str(&entries, "line4_prompt"),
        framebuffer_1024_bytes: fb,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clear_sign_summary_codec() {
        let dto = ClearSignSummaryDto {
            network: "ETH (Mainnet)".into(),
            action: "ERC-20 transfer".into(),
            to_address: "0x71C95911E9a5D330f4d621432f74136C9543Ea91".into(),
            amount: "500.000000 USDC".into(),
            tx_hash_hex: "0x1234abcd".into(),
        };

        let encoded = encode_clear_sign_summary(&dto).expect("encode");
        let decoded = decode_clear_sign_summary(&encoded).expect("decode");

        assert_eq!(decoded, dto);
    }

    #[test]
    fn test_oled_preview_codec() {
        let dto = OledPreviewDto {
            line1_network: "ETH: Send ETH".into(),
            line2_to: "TO: 0x71C...Ea91".into(),
            line3_amount: "AMT: 1.500000 ETH".into(),
            line4_prompt: "PRESS GPIO0 TO SIGN".into(),
            framebuffer_1024_bytes: Some(vec![0xAA; 1024]),
        };

        let encoded = encode_oled_preview(&dto).expect("encode");
        let decoded = decode_oled_preview(&encoded).expect("decode");

        assert_eq!(decoded, dto);
    }
}
