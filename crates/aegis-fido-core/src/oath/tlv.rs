//! Canonical TLV (BER short/long form) shared by wallet, vendor, rescue and fw-log.
//!
//! Wire frozen (no change): TLV data tags `0x01` slot, `0x02` label,
//! `0x07` address (response), `0x08` network (GEN request); vendor op range
//! `0x20-0x27` (transport opcodes, see firmware `ble_gatt`); rescue transport
//! op `0x2E`; fw-log op `0x38`. This module only names the wire values and
//! hosts the helpers duplicated by on-device executors; it never alters the
//! encoding (`write_tlv` / `parse_tlv_records` byte-identical).
//!
//! Always compiled (shared primitive, no feature gate per R12); `no_std` +
//! `alloc` only, no hardware access (pure codec, nothing to prefer per R14).

extern crate alloc;

use crate::oath::types::OathError;
use alloc::vec::Vec;

/// TLV wallet: slot id (1 byte).
pub const TAG_WALLET_SLOT: u8 = 0x01;
/// TLV wallet: UTF-8 label (1..=32 bytes).
pub const TAG_WALLET_LABEL: u8 = 0x02;
/// TLV wallet: derived address (response; old decoders ignore per §9.6).
pub const TAG_WALLET_ADDRESS: u8 = 0x07;
/// TLV wallet: network discriminant (1 byte) in the GEN request.
pub const TAG_WALLET_NETWORK: u8 = 0x08;

/// TLV vendor keys: slot id (same wire value as wallet slot).
pub const TAG_SLOT: u8 = 0x01;
/// TLV vendor keys: UTF-8 label (same wire value as wallet label).
pub const TAG_LABEL: u8 = 0x02;
/// TLV vendor keys: algorithm hint (big-endian `i32`, 4 bytes).
pub const TAG_ALG_HINT: u8 = 0x05;
/// TLV vendor keys: usage hint bitmask (1 byte, non-zero).
pub const TAG_USAGE_HINT: u8 = 0x06;
/// TLV OATH name field in vendor LIST responses.
pub const TAG_OATH_NAME: u8 = 0x71;
/// TLV OATH code field in vendor CODE responses.
pub const TAG_OATH_RESPONSE: u8 = 0x75;

/// First vendor keys/OATH transport opcode (mirror of firmware `ble_gatt`).
pub const VENDOR_OP_MIN: u8 = 0x20;
/// Last vendor keys/OATH transport opcode (mirror of firmware `ble_gatt`).
pub const VENDOR_OP_MAX: u8 = 0x27;
/// Rescue transport opcode (equals `crate::otp::rescue::RESCUE_TRANSPORT_OP`).
pub const RESCUE_TRANSPORT_OP: u8 = 0x2E;
/// Firmware log opcode (mirror of firmware `fw_log::OP_FW_LOG`).
pub const FW_LOG_OP: u8 = 0x38;

/// Maximum label length accepted by the shared helpers (wallet + vendor).
pub const MAX_LABEL_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlvRecord<'a> {
    pub tag: u8,
    pub value: &'a [u8],
}

impl<'a> TlvRecord<'a> {
    pub fn new(tag: u8, value: &'a [u8]) -> Self {
        Self { tag, value }
    }
}

/// Parse all TLV records from a buffer
pub fn parse_tlv_records(data: &[u8]) -> Result<Vec<TlvRecord<'_>>, OathError> {
    let mut records = Vec::new();
    let mut idx = 0;

    while idx < data.len() {
        let tag = data[idx];
        idx += 1;
        if idx >= data.len() {
            return Err(OathError::WrongData);
        }

        let len_byte = data[idx];
        idx += 1;

        let len = if len_byte < 0x80 {
            len_byte as usize
        } else if len_byte == 0x81 {
            if idx >= data.len() {
                return Err(OathError::WrongData);
            }
            let l = data[idx] as usize;
            idx += 1;
            l
        } else if len_byte == 0x82 {
            if idx + 1 >= data.len() {
                return Err(OathError::WrongData);
            }
            let l = ((data[idx] as usize) << 8) | (data[idx + 1] as usize);
            idx += 2;
            l
        } else {
            return Err(OathError::WrongData);
        };

        if idx + len > data.len() {
            return Err(OathError::WrongData);
        }

        let value = &data[idx..idx + len];
        idx += len;

        records.push(TlvRecord { tag, value });
    }

    Ok(records)
}

/// Find the first record with the given tag
pub fn find_tlv<'a>(records: &'a [TlvRecord<'a>], tag: u8) -> Option<&'a [u8]> {
    for r in records {
        if r.tag == tag {
            return Some(r.value);
        }
    }
    None
}

/// Serialize a TLV record into a destination vector
pub fn write_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
    out.extend_from_slice(value);
}

/// `true` for wallet TLV data tags (`0x01/0x02/0x07/0x08`).
pub fn is_wallet_tag(tag: u8) -> bool {
    matches!(
        tag,
        TAG_WALLET_SLOT | TAG_WALLET_LABEL | TAG_WALLET_ADDRESS | TAG_WALLET_NETWORK
    )
}

/// `true` for vendor keys/OATH transport opcodes (`0x20-0x27`).
pub fn is_vendor_op(op: u8) -> bool {
    (VENDOR_OP_MIN..=VENDOR_OP_MAX).contains(&op)
}

/// Shared helper (wallet + vendor): single-byte TLV value, e.g. slot `0x01`.
pub fn single_byte(records: &[TlvRecord<'_>], tag: u8) -> Option<u8> {
    match find_tlv(records, tag) {
        Some(v) if v.len() == 1 => Some(v[0]),
        _ => None,
    }
}

/// Shared helper (wallet + vendor): slot id from tag `0x01` (1 byte).
pub fn slot_id(records: &[TlvRecord<'_>]) -> Option<u8> {
    single_byte(records, TAG_SLOT)
}

/// Shared helper (wallet + vendor): label bytes from tag `0x02` (1..=32 bytes).
pub fn label_bytes<'a>(records: &'a [TlvRecord<'a>]) -> Option<&'a [u8]> {
    match find_tlv(records, TAG_LABEL) {
        Some(v) if !v.is_empty() && v.len() <= MAX_LABEL_BYTES => Some(v),
        _ => None,
    }
}

/// Shared helper (wallet + vendor): append `[slot 0x01, label 0x02]` to `out`.
pub fn append_slot_label(out: &mut Vec<u8>, slot: u8, label: &[u8]) {
    write_tlv(out, TAG_SLOT, &[slot]);
    write_tlv(out, TAG_LABEL, label);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::rescue;
    use alloc::vec;

    #[test]
    fn test_tlv_roundtrip() {
        let mut buf = Vec::new();
        write_tlv(&mut buf, 0x71, b"Google:alice@gmail.com");
        write_tlv(&mut buf, 0x74, &[1, 2, 3, 4, 5, 6, 7, 8]);

        let records = parse_tlv_records(&buf).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(find_tlv(&records, 0x71).unwrap(), b"Google:alice@gmail.com");
        assert_eq!(find_tlv(&records, 0x74).unwrap(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn wire_tags_frozen() {
        assert_eq!(TAG_WALLET_SLOT, 0x01);
        assert_eq!(TAG_WALLET_LABEL, 0x02);
        assert_eq!(TAG_WALLET_ADDRESS, 0x07);
        assert_eq!(TAG_WALLET_NETWORK, 0x08);
        assert_eq!(TAG_SLOT, 0x01);
        assert_eq!(TAG_LABEL, 0x02);
        assert_eq!(TAG_ALG_HINT, 0x05);
        assert_eq!(TAG_USAGE_HINT, 0x06);
        assert_eq!(TAG_OATH_NAME, 0x71);
        assert_eq!(TAG_OATH_RESPONSE, 0x75);
        assert_eq!(VENDOR_OP_MIN, 0x20);
        assert_eq!(VENDOR_OP_MAX, 0x27);
        assert_eq!(RESCUE_TRANSPORT_OP, 0x2E);
        assert_eq!(RESCUE_TRANSPORT_OP, rescue::RESCUE_TRANSPORT_OP);
        assert_eq!(FW_LOG_OP, 0x38);
    }

    #[test]
    fn wallet_gen_request_frozen_vector() {
        // GEN req: slot=3, label="btc", network=0x01 — exact wire bytes.
        let frozen: &[u8] = &[
            0x01, 0x01, 0x03, //
            0x02, 0x03, b'b', b't', b'c', //
            0x08, 0x01, 0x01,
        ];
        let mut out = Vec::new();
        write_tlv(&mut out, TAG_WALLET_SLOT, &[3]);
        write_tlv(&mut out, TAG_WALLET_LABEL, b"btc");
        write_tlv(&mut out, TAG_WALLET_NETWORK, &[0x01]);
        assert_eq!(out, frozen);

        let records = parse_tlv_records(frozen).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(slot_id(&records), Some(3));
        assert_eq!(label_bytes(&records), Some(b"btc".as_slice()));
        assert_eq!(single_byte(&records, TAG_WALLET_NETWORK), Some(0x01));
    }

    #[test]
    fn wallet_record_response_frozen_vector() {
        // Response: slot=3, label="btc", address="bc1qxyz".
        let frozen: &[u8] = &[
            0x01, 0x01, 0x03, //
            0x02, 0x03, b'b', b't', b'c', //
            0x07, 0x07, b'b', b'c', b'1', b'q', b'x', b'y', b'z',
        ];
        let mut out = Vec::new();
        append_slot_label(&mut out, 3, b"btc");
        write_tlv(&mut out, TAG_WALLET_ADDRESS, b"bc1qxyz");
        assert_eq!(out, frozen);

        let records = parse_tlv_records(frozen).unwrap();
        assert_eq!(
            find_tlv(&records, TAG_WALLET_ADDRESS),
            Some(b"bc1qxyz".as_slice())
        );
        assert!(is_wallet_tag(TAG_WALLET_SLOT));
        assert!(is_wallet_tag(TAG_WALLET_LABEL));
        assert!(is_wallet_tag(TAG_WALLET_ADDRESS));
        assert!(is_wallet_tag(TAG_WALLET_NETWORK));
        assert!(!is_wallet_tag(0x05));
    }

    #[test]
    fn vendor_key_gen_frozen_vector() {
        // Vendor GEN: slot=8, label="e2e-t1", alg=-7 (0xFF..F9), usage=0x03.
        let frozen: &[u8] = &[
            0x01, 0x01, 0x08, //
            0x02, 0x06, b'e', b'2', b'e', b'-', b't', b'1', //
            0x05, 0x04, 0xFF, 0xFF, 0xFF, 0xF9, //
            0x06, 0x01, 0x03,
        ];
        let mut out = Vec::new();
        append_slot_label(&mut out, 8, b"e2e-t1");
        write_tlv(&mut out, TAG_ALG_HINT, &(-7i32).to_be_bytes());
        write_tlv(&mut out, TAG_USAGE_HINT, &[0x03]);
        assert_eq!(out, frozen);

        let records = parse_tlv_records(frozen).unwrap();
        assert_eq!(slot_id(&records), Some(8));
        assert_eq!(label_bytes(&records), Some(b"e2e-t1".as_slice()));
        assert_eq!(
            find_tlv(&records, TAG_ALG_HINT),
            Some((-7i32).to_be_bytes().as_slice())
        );
        assert_eq!(single_byte(&records, TAG_USAGE_HINT), Some(0x03));
        assert!(is_vendor_op(0x20));
        assert!(is_vendor_op(0x27));
        assert!(!is_vendor_op(0x28));
        assert!(!is_vendor_op(RESCUE_TRANSPORT_OP));
        assert!(!is_vendor_op(FW_LOG_OP));
    }

    #[test]
    fn long_form_lengths_roundtrip() {
        // 0x81 form: 200 bytes of 0xAB.
        let mut frozen_81 = vec![0x02, 0x81, 0xC8];
        frozen_81.extend_from_slice(&[0xABu8; 200]);
        let mut out = Vec::new();
        write_tlv(&mut out, 0x02, &[0xABu8; 200]);
        assert_eq!(out, frozen_81);
        let records = parse_tlv_records(&frozen_81).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, [0xABu8; 200]);

        // 0x82 form: 300 bytes of 0xCD.
        let mut frozen_82 = vec![0x02, 0x82, 0x01, 0x2C];
        frozen_82.extend_from_slice(&[0xCDu8; 300]);
        let mut out = Vec::new();
        write_tlv(&mut out, 0x02, &[0xCDu8; 300]);
        assert_eq!(out, frozen_82);
        let records = parse_tlv_records(&frozen_82).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, [0xCDu8; 300]);
    }

    #[test]
    fn malformed_inputs_rejected() {
        // Truncated tag / length / value.
        assert!(parse_tlv_records(&[0x01]).is_err());
        assert!(parse_tlv_records(&[0x01, 0x01]).is_err());
        // Length overrun.
        assert!(parse_tlv_records(&[0x01, 0x05, 0xAA]).is_err());
        // Indefinite form and reserved long forms rejected (fail-closed).
        assert!(parse_tlv_records(&[0x01, 0x80]).is_err());
        assert!(parse_tlv_records(&[0x01, 0x83, 0x01]).is_err());
        assert!(parse_tlv_records(&[0x01, 0xFF]).is_err());
        // 0x81 truncated value-length byte.
        assert!(parse_tlv_records(&[0x01, 0x81]).is_err());
        // 0x82 truncated value-length bytes.
        assert!(parse_tlv_records(&[0x01, 0x82, 0x01]).is_err());
        // Helpers fail closed on absent / malformed fields.
        let empty = parse_tlv_records(&[]).unwrap();
        assert_eq!(slot_id(&empty), None);
        assert_eq!(label_bytes(&empty), None);
        let bad_slot = parse_tlv_records(&[0x01, 0x02, 0x01, 0x02]).unwrap();
        assert_eq!(slot_id(&bad_slot), None);
        let bad_label = parse_tlv_records(&[0x02, 0x00]).unwrap();
        assert_eq!(label_bytes(&bad_label), None);
    }
}
