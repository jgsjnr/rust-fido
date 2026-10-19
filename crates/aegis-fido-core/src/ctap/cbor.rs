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
    let mut out = Vec::new();
    ciborium::into_writer(val, &mut out).map_err(|_| CtapError::Processing)?;
    Ok(out)
}
