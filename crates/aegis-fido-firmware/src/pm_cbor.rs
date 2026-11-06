//! PM CBOR wire mirrors (F-PM2 firmware side).
//!
//! Split from `pm_dispatch` (dep-track god-split, no behavior change):
//! byte-for-byte DTOs mirroring `universal-device-sdk/src/pm.rs` — put
//! `{label, username, secret, url}`, id bodies `{id}`, list
//! `{cursor, limit}` / `{ids, next_cursor, has_more}`, release
//! `{id, username, secret}`, status `{entry_count, max_entries}`.
//! Field caps mirror the SDK transport mirrors (label 128 / username 256 /
//! secret 1..=512 / url 512 / id 1..=64); policy quotas stay vault-side.
//! `no_std`-compatible (`alloc`-only). No logging of user data, no
//! `unwrap`/`expect` outside `#[cfg(test)]`.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use ciborium::value::Value;

pub(crate) fn to_cbor(val: &Value) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(val, &mut out).ok()?;
    Some(out)
}

pub(crate) fn from_cbor(bytes: &[u8]) -> Option<Vec<(Value, Value)>> {
    let val: Value = ciborium::from_reader(bytes).ok()?;
    match val {
        Value::Map(m) => Some(m),
        _ => None,
    }
}

pub(crate) fn field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries.iter().find_map(|(k, v)| match k {
        Value::Text(s) if s == key => Some(v),
        _ => None,
    })
}

pub(crate) fn get_text(entries: &[(Value, Value)], key: &str) -> Option<String> {
    match field(entries, key)? {
        Value::Text(s) => Some(s.clone()),
        _ => None,
    }
}

pub(crate) fn get_bytes(entries: &[(Value, Value)], key: &str) -> Option<Vec<u8>> {
    match field(entries, key)? {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

pub(crate) fn get_u32(entries: &[(Value, Value)], key: &str, default: u32) -> Option<u32> {
    match field(entries, key) {
        None => Some(default),
        Some(Value::Integer(i)) => u32::try_from(i128::from(*i)).ok(),
        Some(_) => None,
    }
}

pub(crate) fn check_id(id: &[u8]) -> bool {
    !id.is_empty() && id.len() <= 64
}

pub(crate) fn encode_id_body(id: &[u8]) -> Option<Vec<u8>> {
    if !check_id(id) {
        return None;
    }
    to_cbor(&Value::Map(alloc::vec![(
        Value::Text("id".into()),
        Value::Bytes(id.to_vec()),
    )]))
}

pub(crate) fn decode_id_body(bytes: &[u8]) -> Option<Vec<u8>> {
    let entries = from_cbor(bytes)?;
    let id = get_bytes(&entries, "id")?;
    if !check_id(&id) {
        return None;
    }
    Some(id)
}
