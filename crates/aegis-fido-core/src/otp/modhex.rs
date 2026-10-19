extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub const MODHEX_ALPHABET: &[u8; 16] = b"cbdefghijklnrtuv";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModhexError {
    InvalidCharacter(char),
    InvalidLength,
}

/// Convert a single nibble (0..=15) to its Modhex character
#[inline]
pub fn encode_nibble(nibble: u8) -> char {
    MODHEX_ALPHABET[(nibble & 0x0F) as usize] as char
}

/// Convert a single Modhex character to its nibble value (0..=15)
#[inline]
pub fn decode_char(c: char) -> Result<u8, ModhexError> {
    match c {
        'c' | 'C' => Ok(0x0),
        'b' | 'B' => Ok(0x1),
        'd' | 'D' => Ok(0x2),
        'e' | 'E' => Ok(0x3),
        'f' | 'F' => Ok(0x4),
        'g' | 'G' => Ok(0x5),
        'h' | 'H' => Ok(0x6),
        'i' | 'I' => Ok(0x7),
        'j' | 'J' => Ok(0x8),
        'k' | 'K' => Ok(0x9),
        'l' | 'L' => Ok(0xA),
        'n' | 'N' => Ok(0xB),
        'r' | 'R' => Ok(0xC),
        't' | 'T' => Ok(0xD),
        'u' | 'U' => Ok(0xE),
        'v' | 'V' => Ok(0xF),
        _ => Err(ModhexError::InvalidCharacter(c)),
    }
}

/// Encode raw binary data into a Modhex string
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for &byte in data {
        out.push(encode_nibble(byte >> 4));
        out.push(encode_nibble(byte & 0x0F));
    }
    out
}

/// Decode a Modhex string into raw binary bytes
pub fn decode(s: &str) -> Result<Vec<u8>, ModhexError> {
    if !s.len().is_multiple_of(2) {
        return Err(ModhexError::InvalidLength);
    }

    let mut bytes = Vec::with_capacity(s.len() / 2);
    let mut chars = s.chars();

    while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
        let hi = decode_char(c1)?;
        let lo = decode_char(c2)?;
        bytes.push((hi << 4) | lo);
    }

    Ok(bytes)
}

/// Translate standard hex string to Modhex string
pub fn hex_to_modhex(hex_str: &str) -> Result<String, ModhexError> {
    let mut out = String::with_capacity(hex_str.len());
    for c in hex_str.chars() {
        let val = match c {
            '0'..='9' => c as u8 - b'0',
            'a'..='f' => c as u8 - b'a' + 10,
            'A'..='F' => c as u8 - b'A' + 10,
            _ => return Err(ModhexError::InvalidCharacter(c)),
        };
        out.push(encode_nibble(val));
    }
    Ok(out)
}

/// Translate Modhex string to standard lowercase hex string
pub fn modhex_to_hex(modhex_str: &str) -> Result<String, ModhexError> {
    let mut out = String::with_capacity(modhex_str.len());
    for c in modhex_str.chars() {
        let nibble = decode_char(c)?;
        let hex_char = match nibble {
            0..=9 => (b'0' + nibble) as char,
            10..=15 => (b'a' + (nibble - 10)) as char,
            _ => unreachable!(),
        };
        out.push(hex_char);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modhex_encode_decode() {
        let raw = [0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let encoded = encode(&raw);
        assert_eq!(encoded, "ccbdefghijklnrtuvc");
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, raw);
    }

    #[test]
    fn test_modhex_known_vector() {
        // Hex "000888970111" -> modhex "cccjjjkicbbb"
        let hex = "000888970111";
        let modhex = hex_to_modhex(hex).unwrap();
        assert_eq!(modhex, "cccjjjkicbbb");
        let back_to_hex = modhex_to_hex(&modhex).unwrap();
        assert_eq!(back_to_hex, hex);
    }
}
