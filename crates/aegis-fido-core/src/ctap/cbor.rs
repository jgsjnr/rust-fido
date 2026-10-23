use crate::ctap::status_code::CtapError;
use alloc::vec::Vec;
use ciborium::value::Value;

pub fn decode_cbor_map(data: &[u8]) -> Result<Vec<(Value, Value)>, CtapError> {
    if data.is_empty() {
        return Err(CtapError::MissingParameter);
    }
    let val: Value = ciborium::from_reader(data).map_err(|_| CtapError::InvalidCbor)?;
    match val {
        Value::Map(m) => Ok(m),
        _ => Err(CtapError::CborUnexpectedType),
    }
}

pub fn get_int_key(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    for (k, v) in map {
        if let Value::Integer(i) = k {
            let actual: i128 = (*i).into();
            if actual == key as i128 {
                return Some(v);
            }
        }
    }
    None
}

pub fn get_text_key<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    for (k, v) in map {
        if let Value::Text(s) = k {
            if s == key {
                return Some(v);
            }
        }
    }
    None
}

pub fn get_bytes_field(map: &[(Value, Value)], key: i64) -> Result<Vec<u8>, CtapError> {
    match get_int_key(map, key) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(_) => Err(CtapError::CborUnexpectedType),
        None => Err(CtapError::MissingParameter),
    }
}

pub fn get_opt_bytes_field(map: &[(Value, Value)], key: i64) -> Result<Option<Vec<u8>>, CtapError> {
    match get_int_key(map, key) {
        Some(Value::Bytes(b)) => Ok(Some(b.clone())),
        Some(_) => Err(CtapError::CborUnexpectedType),
        None => Ok(None),
    }
}

pub fn get_int_field(map: &[(Value, Value)], key: i64) -> Result<i64, CtapError> {
    match get_int_key(map, key) {
        Some(Value::Integer(i)) => {
            let val: i128 = (*i).into();
            Ok(val as i64)
        }
        Some(_) => Err(CtapError::CborUnexpectedType),
        None => Err(CtapError::MissingParameter),
    }
}

pub fn get_opt_int_field(map: &[(Value, Value)], key: i64) -> Result<Option<i64>, CtapError> {
    match get_int_key(map, key) {
        Some(Value::Integer(i)) => {
            let val: i128 = (*i).into();
            Ok(Some(val as i64))
        }
        Some(_) => Err(CtapError::CborUnexpectedType),
        None => Ok(None),
    }
}

pub fn encode_cbor_value(val: &Value) -> Result<Vec<u8>, CtapError> {
    encode_canonical_cbor(val)
}

/// Encode a `Value` with RFC 8949 §4.2.1 canonical (core deterministic)
/// ordering: map keys sorted by (length of encoded key, lexicographic
/// order of encoded key bytes), applied recursively. Integers are
/// emitted minimal and maps/arrays use definite lengths (ciborium's
/// default writer behavior); sorting the entry vector before writing is
/// therefore sufficient for canonical output.
pub fn encode_canonical_cbor(val: &Value) -> Result<Vec<u8>, CtapError> {
    let canonical = canonicalize_value(val);
    let mut out = Vec::new();
    ciborium::into_writer(&canonical, &mut out).map_err(|_| CtapError::Processing)?;
    Ok(out)
}

/// Recursively return a copy of `val` with every map's entries sorted
/// in canonical key order.
pub fn canonicalize_value(val: &Value) -> Value {
    match val {
        Value::Map(entries) => {
            let mut sorted: Vec<(Value, Value)> = entries
                .iter()
                .map(|(k, v)| (canonicalize_value(k), canonicalize_value(v)))
                .collect();
            sorted.sort_by(|(ka, _), (kb, _)| canonical_key_order(ka, kb));
            Value::Map(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_value).collect()),
        _ => val.clone(),
    }
}

fn canonical_key_order(a: &Value, b: &Value) -> core::cmp::Ordering {
    let ea = encode_key_for_ordering(a);
    let eb = encode_key_for_ordering(b);
    ea.len().cmp(&eb.len()).then_with(|| ea.cmp(&eb))
}

fn encode_key_for_ordering(key: &Value) -> Vec<u8> {
    // Keys are already canonicalized scalars in practice; a plain
    // ciborium encoding gives the minimal deterministic bytes used
    // for ordering. Fall back to empty on unexpected error so sort
    // stays total without failing the response path.
    let mut out = Vec::new();
    if ciborium::into_writer(key, &mut out).is_ok() {
        out
    } else {
        Vec::new()
    }
}
