extern crate alloc;

use alloc::vec::Vec;
use super::types::OathError;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
