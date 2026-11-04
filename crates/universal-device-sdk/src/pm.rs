//! Password-manager blind-transport DTOs (F-PM2).
//!
//! Typed CBOR carriers between the phone and the device vault. This module
//! owns shapes only, mirroring the `secure_guard` / `shamir` style:
//!
//! - Opcodes `0x43..=0x47`: first free vendor range after BLE OOB `0x42`
//!   (neighbors `0x20..=0x39`, `0x3A..=0x3E`, `0x3F` GET_CAPS, `0x40`
//!   SET_UP_POLICY, `0x41` VENDOR_SIGN, `0x42` OOB are all taken; see
//!   firmware `ble/oob.rs::OP_BLE_OOB` audit). No existing wire changes.
//! - Gate denials are *data* here ([`PmStatus`], wire `0x05`/`0x01`/`0x02`);
//!   enforcement lives in `aegis-pm-vault` (`PmGateState`/`PmPolicy`) and the
//!   firmware gates, never in this crate (R5).
//! - The phone is a blind transport: [`PmListResponseDto`] carries opaque
//!   record ids only (no labels); stored secrets cross this edge only as
//!   the punctual, transient [`PmReleaseResponseDto] — never persist it,
//!   zeroize after display. `Debug` is redacted for every DTO that touches
//!   user data, so labels/usernames/secrets/urls never reach logs.
//! - `no_std` + `alloc` only; no `std`, no `esp-idf`, no dependency on
//!   `aegis-pm-vault` or `aegis-fido-core` (DIP: the vault decides
//!   envelope/policy; new record kinds arrive as new DTO variants, OCP).
//!
//! Every symbol here is compiled only with the `pm` Cargo feature
//! (off by default). Without it the only surface is [`crate::require_pm`],
//! which reports [`crate::SdkError::NotCompiled`] (R12).

use crate::error::{require_pm, SdkError};
use crate::status::{STATUS_NEED_BINDING, STATUS_NEED_PIN, STATUS_NEED_UP, STATUS_OK};
use alloc::string::String;
use alloc::vec::Vec;
use ciborium::value::Value;

/// PM put: store (or replace) one login record (device seals on receipt).
pub const OP_PM_PUT: u8 = 0x43;
/// PM get: fetch one sealed record by opaque id (gated release).
pub const OP_PM_GET: u8 = 0x44;
/// PM list: page over opaque record ids (no labels cross this edge).
pub const OP_PM_LIST: u8 = 0x45;
/// PM delete: remove one record by opaque id.
pub const OP_PM_DELETE: u8 = 0x46;
/// PM status: entry-count / quota telemetry (no secrets).
pub const OP_PM_STATUS: u8 = 0x47;
/// First PM opcode (first free byte after BLE OOB `0x42`).
pub const PM_OP_MIN: u8 = OP_PM_PUT;
/// Last PM opcode.
pub const PM_OP_MAX: u8 = OP_PM_STATUS;

/// Transport mirror of the vault structural cap for record ids
/// (`aegis-pm-vault` `PM_ID_MAX_BYTES`). Frames larger than this are
/// rejected here fail-closed before reaching firmware; quota/policy caps
/// stay vault-side.
pub const PM_ID_MAX_BYTES: usize = 64;
/// Transport mirror of the vault label cap (`PM_LABEL_HARD_MAX`).
pub const PM_LABEL_MAX_BYTES: usize = 128;
/// Transport mirror of the vault username cap (`PM_USERNAME_HARD_MAX`).
pub const PM_USERNAME_MAX_BYTES: usize = 256;
/// Transport mirror of the vault secret cap (`PM_SECRET_HARD_MAX`).
pub const PM_SECRET_MAX_BYTES: usize = 512;
/// Transport mirror of the vault URL cap (`PM_URL_HARD_MAX`).
pub const PM_URL_MAX_BYTES: usize = 512;
/// Default page size for [`PmListRequestDto`] when the caller passes `0`.
pub const PM_LIST_DEFAULT_LIMIT: u8 = 32;

/// Fail-closed gate outcome carried as data (R5: no enforcement here).
///
/// Wire mapping preserves §9.5: `Ok` = `0x00`, `NeedBinding` = `0x05`,
/// `PresenceRequired` = `0x01`, `PinRequired` = `0x02`. Any other device
/// failure rides the [`crate::SdkResponse`] status byte directly
/// (e.g. `0x04`); [`PmStatus::from_wire_status`] returns `None` for those.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmStatus {
    /// Success (`0x00`).
    Ok,
    /// No bonded phone on this session (`0x05`, BLE-only).
    NeedBinding,
    /// User presence (button/OLED confirm) missing (`0x01`).
    PresenceRequired,
    /// PIN/UV auth missing where required (`0x02`).
    PinRequired,
}

impl PmStatus {
    /// Maps to the frozen wire status byte.
    pub const fn to_wire_status(self) -> u8 {
        match self {
            Self::Ok => STATUS_OK,
            Self::NeedBinding => STATUS_NEED_BINDING,
            Self::PresenceRequired => STATUS_NEED_UP,
            Self::PinRequired => STATUS_NEED_PIN,
        }
    }

    /// Maps a wire status byte back; `None` for any byte outside the
    /// PM denial set (including `0x03`/`0x04`, which ride `SdkResponse`).
    pub const fn from_wire_status(byte: u8) -> Option<Self> {
        match byte {
            STATUS_OK => Some(Self::Ok),
            STATUS_NEED_BINDING => Some(Self::NeedBinding),
            STATUS_NEED_UP => Some(Self::PresenceRequired),
            STATUS_NEED_PIN => Some(Self::PinRequired),
            _ => None,
        }
    }

    /// Human name for logs (never attached to payloads).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ok => "Ok",
            Self::NeedBinding => "NeedBinding",
            Self::PresenceRequired => "PresenceRequired",
            Self::PinRequired => "PinRequired",
        }
    }
}

/// PM operation family (OCP: new ops arrive as new variants; the opaque
/// [`PmRequest`] carrier and the AEGN envelope are untouched).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PmOp {
    /// Store (or replace) one login record (`0x43`).
    Put,
    /// Fetch one record by opaque id (`0x44`).
    Get,
    /// Page over opaque record ids (`0x45`).
    List,
    /// Remove one record by opaque id (`0x46`).
    Delete,
    /// Entry-count / quota telemetry (`0x47`).
    Status,
}

impl PmOp {
    /// Maps to the wire opcode byte.
    pub const fn opcode(self) -> u8 {
        match self {
            Self::Put => OP_PM_PUT,
            Self::Get => OP_PM_GET,
            Self::List => OP_PM_LIST,
            Self::Delete => OP_PM_DELETE,
            Self::Status => OP_PM_STATUS,
        }
    }

    /// Maps a wire opcode byte back; `None` outside `0x43..=0x47`.
    pub const fn from_opcode(byte: u8) -> Option<Self> {
        match byte {
            OP_PM_PUT => Some(Self::Put),
            OP_PM_GET => Some(Self::Get),
            OP_PM_LIST => Some(Self::List),
            OP_PM_DELETE => Some(Self::Delete),
            OP_PM_STATUS => Some(Self::Status),
            _ => None,
        }
    }
}

/// Opaque PM request carrier: typed op plus CBOR body bytes.
///
/// Bodies are produced/consumed by the `encode_pm_*` / `decode_pm_*`
/// helpers; this crate never interprets secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PmRequest {
    /// PM operation.
    pub op: PmOp,
    /// CBOR body bytes (opaque here).
    pub payload: Vec<u8>,
}

impl PmRequest {
    /// Builds a request from an op and an already-encoded CBOR body.
    pub fn new(op: PmOp, payload: Vec<u8>) -> Self {
        Self { op, payload }
    }

    /// R12 stub mapping: `Ok` only with feature `pm`, else `NotCompiled`.
    pub fn check_compiled(&self) -> Result<(), SdkError> {
        require_pm()
    }
}

/// Put body: user-typed fields, transient on the phone (the device seals
/// on receipt). Redacted `Debug`: never logs label/username/secret/url.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PmPutRequestDto {
    /// Human label ("bank"). Transient only; encrypted at rest device-side.
    pub label: String,
    /// Login username. Transient only.
    pub username: String,
    /// Login password / secret. Transient only; zeroize after encoding.
    pub secret: Vec<u8>,
    /// Optional URL. Transient only.
    pub url: Option<String>,
}

impl core::fmt::Debug for PmPutRequestDto {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmPutRequestDto")
            .field("label", &"[REDACTED]")
            .field("username", &"[REDACTED]")
            .field("secret", &"[REDACTED]")
            .field("url", &"[REDACTED]")
            .field("label_len", &self.label.len())
            .field("secret_len", &self.secret.len())
            .finish()
    }
}

/// Get body: opaque record id chosen by the device.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PmGetRequestDto {
    /// Opaque record id.
    pub id: Vec<u8>,
}

impl core::fmt::Debug for PmGetRequestDto {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmGetRequestDto")
            .field("id", &"[REDACTED]")
            .field("id_len", &self.id.len())
            .finish()
    }
}

/// Delete body: opaque record id chosen by the device.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PmDeleteRequestDto {
    /// Opaque record id.
    pub id: Vec<u8>,
}

impl core::fmt::Debug for PmDeleteRequestDto {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmDeleteRequestDto")
            .field("id", &"[REDACTED]")
            .field("id_len", &self.id.len())
            .finish()
    }
}

/// List body: cursor paging over opaque record ids.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PmListRequestDto {
    /// Opaque cursor (`0` starts; echo `next_cursor` to continue).
    pub cursor: u32,
    /// Max ids to return (`0` means [`PM_LIST_DEFAULT_LIMIT`]).
    pub limit: u8,
}

/// List answer: opaque record ids only — no labels, no secrets — plus the
/// cursor for the next page. Ids are redacted from `Debug`.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PmListResponseDto {
    /// Opaque record ids for this page.
    pub ids: Vec<Vec<u8>>,
    /// Cursor for the next page (`0` when there is none).
    pub next_cursor: u32,
    /// `true` when more pages follow.
    pub has_more: bool,
}

impl core::fmt::Debug for PmListResponseDto {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmListResponseDto")
            .field("ids", &"[REDACTED]")
            .field("id_count", &self.ids.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// Punctual gated release: the single field set the device discloses after
/// binding + UP + PIN inside the 60 s window. TRANSIENT ON THE PHONE:
/// display and zeroize, never persist, never log.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PmReleaseResponseDto {
    /// Opaque record id this release belongs to.
    pub id: Vec<u8>,
    /// Released username (transient display only).
    pub username: String,
    /// Released secret (transient display only; zeroize after use).
    pub secret: Vec<u8>,
}

impl core::fmt::Debug for PmReleaseResponseDto {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmReleaseResponseDto")
            .field("id", &"[REDACTED]")
            .field("username", &"[REDACTED]")
            .field("secret", &"[REDACTED]")
            .field("secret_len", &self.secret.len())
            .finish()
    }
}

/// Status answer: vault census, no secrets.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PmStatusDto {
    /// Records currently stored.
    pub entry_count: u32,
    /// Policy quota (`max_entries`).
    pub max_entries: u32,
}

// --- Internal CBOR helpers (same shape as `secure_guard`) ---

fn to_cbor(val: &Value) -> Result<Vec<u8>, SdkError> {
    let mut out = Vec::new();
    ciborium::into_writer(val, &mut out).map_err(|_| SdkError::Unsupported)?;
    Ok(out)
}

fn from_cbor(bytes: &[u8]) -> Result<Value, SdkError> {
    ciborium::from_reader(bytes).map_err(|_| SdkError::Unsupported)
}

fn as_map(val: Value) -> Result<Vec<(Value, Value)>, SdkError> {
    match val {
        Value::Map(m) => Ok(m),
        _ => Err(SdkError::Unsupported),
    }
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

fn get_bytes(entries: &[(Value, Value)], key: &str) -> Result<Vec<u8>, SdkError> {
    match get_field(entries, key) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(SdkError::Unsupported),
    }
}

fn get_text(entries: &[(Value, Value)], key: &str) -> Result<String, SdkError> {
    match get_field(entries, key) {
        Some(Value::Text(s)) => Ok(s.clone()),
        _ => Err(SdkError::Unsupported),
    }
}

fn get_u32(entries: &[(Value, Value)], key: &str, default: u32) -> Result<u32, SdkError> {
    match get_field(entries, key) {
        None => Ok(default),
        Some(Value::Integer(i)) => i128::from(*i).try_into().map_err(|_| SdkError::Unsupported),
        Some(_) => Err(SdkError::Unsupported),
    }
}

fn get_bool(entries: &[(Value, Value)], key: &str, default: bool) -> Result<bool, SdkError> {
    match get_field(entries, key) {
        None => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(SdkError::Unsupported),
    }
}

fn check_id(id: &[u8]) -> Result<(), SdkError> {
    if id.is_empty() || id.len() > PM_ID_MAX_BYTES {
        return Err(SdkError::Unsupported);
    }
    Ok(())
}

// --- Codecs: put ---

/// Encodes a PM put body. Rejects empty secrets and over-cap fields
/// fail-closed (transport framing; policy quotas stay vault-side).
pub fn encode_pm_put_request(dto: &PmPutRequestDto) -> Result<Vec<u8>, SdkError> {
    if dto.label.len() > PM_LABEL_MAX_BYTES
        || dto.username.len() > PM_USERNAME_MAX_BYTES
        || dto.secret.is_empty()
        || dto.secret.len() > PM_SECRET_MAX_BYTES
        || dto.url.as_ref().is_some_and(|u| u.len() > PM_URL_MAX_BYTES)
    {
        return Err(SdkError::Unsupported);
    }
    let url_val = match &dto.url {
        Some(u) => Value::Text(u.clone()),
        None => Value::Null,
    };
    let map = alloc::vec![
        (
            Value::Text("label".into()),
            Value::Text(dto.label.clone())
        ),
        (
            Value::Text("username".into()),
            Value::Text(dto.username.clone())
        ),
        (
            Value::Text("secret".into()),
            Value::Bytes(dto.secret.clone())
        ),
        (Value::Text("url".into()), url_val),
    ];
    to_cbor(&Value::Map(map))
}

/// Decodes a PM put body (same caps as the encoder).
pub fn decode_pm_put_request(bytes: &[u8]) -> Result<PmPutRequestDto, SdkError> {
    let entries = as_map(from_cbor(bytes)?)?;
    let label = get_text(&entries, "label")?;
    let username = get_text(&entries, "username")?;
    let secret = get_bytes(&entries, "secret")?;
    let url = match get_field(&entries, "url") {
        None | Some(Value::Null) => None,
        Some(Value::Text(s)) => Some(s.clone()),
        Some(_) => return Err(SdkError::Unsupported),
    };
    if label.len() > PM_LABEL_MAX_BYTES
        || username.len() > PM_USERNAME_MAX_BYTES
        || secret.is_empty()
        || secret.len() > PM_SECRET_MAX_BYTES
        || url.as_ref().is_some_and(|u| u.len() > PM_URL_MAX_BYTES)
    {
        return Err(SdkError::Unsupported);
    }
    Ok(PmPutRequestDto {
        label,
        username,
        secret,
        url,
    })
}

// --- Codecs: get / delete (opaque-id bodies) ---

/// Encodes a PM get body.
pub fn encode_pm_get_request(dto: &PmGetRequestDto) -> Result<Vec<u8>, SdkError> {
    check_id(&dto.id)?;
    let map = alloc::vec![(Value::Text("id".into()), Value::Bytes(dto.id.clone()))];
    to_cbor(&Value::Map(map))
}

/// Decodes a PM get body.
pub fn decode_pm_get_request(bytes: &[u8]) -> Result<PmGetRequestDto, SdkError> {
    let entries = as_map(from_cbor(bytes)?)?;
    let id = get_bytes(&entries, "id")?;
    check_id(&id)?;
    Ok(PmGetRequestDto { id })
}

/// Encodes a PM delete body.
pub fn encode_pm_delete_request(dto: &PmDeleteRequestDto) -> Result<Vec<u8>, SdkError> {
    check_id(&dto.id)?;
    let map = alloc::vec![(Value::Text("id".into()), Value::Bytes(dto.id.clone()))];
    to_cbor(&Value::Map(map))
}

/// Decodes a PM delete body.
pub fn decode_pm_delete_request(bytes: &[u8]) -> Result<PmDeleteRequestDto, SdkError> {
    let entries = as_map(from_cbor(bytes)?)?;
    let id = get_bytes(&entries, "id")?;
    check_id(&id)?;
    Ok(PmDeleteRequestDto { id })
}

// --- Codecs: list ---

/// Encodes a PM list body.
pub fn encode_pm_list_request(dto: &PmListRequestDto) -> Result<Vec<u8>, SdkError> {
    let map = alloc::vec![
        (
            Value::Text("cursor".into()),
            Value::from(dto.cursor as u64)
        ),
        (Value::Text("limit".into()), Value::from(dto.limit)),
    ];
    to_cbor(&Value::Map(map))
}

/// Decodes a PM list body.
pub fn decode_pm_list_request(bytes: &[u8]) -> Result<PmListRequestDto, SdkError> {
    let entries = as_map(from_cbor(bytes)?)?;
    let cursor = get_u32(&entries, "cursor", 0)?;
    let limit = get_u32(&entries, "limit", u32::from(PM_LIST_DEFAULT_LIMIT))? as u8;
    Ok(PmListRequestDto { cursor, limit })
}

/// Encodes a PM list answer (opaque ids only; every id is cap-checked).
pub fn encode_pm_list_response(dto: &PmListResponseDto) -> Result<Vec<u8>, SdkError> {
    for id in &dto.ids {
        check_id(id)?;
    }
    let ids_val: Vec<Value> = dto.ids.iter().cloned().map(Value::Bytes).collect();
    let map = alloc::vec![
        (Value::Text("ids".into()), Value::Array(ids_val)),
        (
            Value::Text("next_cursor".into()),
            Value::from(dto.next_cursor as u64)
        ),
        (
            Value::Text("has_more".into()),
            Value::Bool(dto.has_more)
        ),
    ];
    to_cbor(&Value::Map(map))
}

/// Decodes a PM list answer (`next_cursor`/`has_more` default for
/// forward-compat with extended answers; unknown keys are ignored).
pub fn decode_pm_list_response(bytes: &[u8]) -> Result<PmListResponseDto, SdkError> {
    let entries = as_map(from_cbor(bytes)?)?;
    let ids = match get_field(&entries, "ids") {
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Bytes(b) => {
                        check_id(b)?;
                        out.push(b.clone());
                    }
                    _ => return Err(SdkError::Unsupported),
                }
            }
            out
        }
        _ => return Err(SdkError::Unsupported),
    };
    let next_cursor = get_u32(&entries, "next_cursor", 0)?;
    let has_more = get_bool(&entries, "has_more", false)?;
    Ok(PmListResponseDto {
        ids,
        next_cursor,
        has_more,
    })
}

// --- Codecs: release / status answers ---

/// Encodes a punctual gated release (transient: never persist the bytes).
pub fn encode_pm_release_response(dto: &PmReleaseResponseDto) -> Result<Vec<u8>, SdkError> {
    check_id(&dto.id)?;
    if dto.username.len() > PM_USERNAME_MAX_BYTES
        || dto.secret.is_empty()
        || dto.secret.len() > PM_SECRET_MAX_BYTES
    {
        return Err(SdkError::Unsupported);
    }
    let map = alloc::vec![
        (Value::Text("id".into()), Value::Bytes(dto.id.clone())),
        (
            Value::Text("username".into()),
            Value::Text(dto.username.clone())
        ),
        (
            Value::Text("secret".into()),
            Value::Bytes(dto.secret.clone())
        ),
    ];
    to_cbor(&Value::Map(map))
}

/// Decodes a punctual gated release (same caps as the encoder).
pub fn decode_pm_release_response(bytes: &[u8]) -> Result<PmReleaseResponseDto, SdkError> {
    let entries = as_map(from_cbor(bytes)?)?;
    let id = get_bytes(&entries, "id")?;
    let username = get_text(&entries, "username")?;
    let secret = get_bytes(&entries, "secret")?;
    check_id(&id)?;
    if username.len() > PM_USERNAME_MAX_BYTES
        || secret.is_empty()
        || secret.len() > PM_SECRET_MAX_BYTES
    {
        return Err(SdkError::Unsupported);
    }
    Ok(PmReleaseResponseDto {
        id,
        username,
        secret,
    })
}

/// Encodes a PM status answer (census only, no secrets).
pub fn encode_pm_status_response(dto: &PmStatusDto) -> Result<Vec<u8>, SdkError> {
    let map = alloc::vec![
        (
            Value::Text("entry_count".into()),
            Value::from(dto.entry_count as u64)
        ),
        (
            Value::Text("max_entries".into()),
            Value::from(dto.max_entries as u64)
        ),
    ];
    to_cbor(&Value::Map(map))
}

/// Decodes a PM status answer.
pub fn decode_pm_status_response(bytes: &[u8]) -> Result<PmStatusDto, SdkError> {
    let entries = as_map(from_cbor(bytes)?)?;
    let entry_count = get_u32(&entries, "entry_count", 0)?;
    let max_entries = get_u32(&entries, "max_entries", 0)?;
    Ok(PmStatusDto {
        entry_count,
        max_entries,
    })
}

#[cfg(test)]
mod tests {
    use crate::pm::{
        decode_pm_delete_request, decode_pm_get_request, decode_pm_list_request,
        decode_pm_list_response, decode_pm_put_request, decode_pm_release_response,
        decode_pm_status_response, encode_pm_delete_request, encode_pm_get_request,
        encode_pm_list_request, encode_pm_list_response, encode_pm_put_request,
        encode_pm_release_response, encode_pm_status_response, PmDeleteRequestDto,
        PmGetRequestDto, PmListRequestDto, PmListResponseDto, PmOp, PmPutRequestDto,
        PmReleaseResponseDto, PmRequest, PmStatus, PmStatusDto, OP_PM_DELETE, OP_PM_GET,
        OP_PM_LIST, OP_PM_PUT, OP_PM_STATUS, PM_ID_MAX_BYTES, PM_LABEL_MAX_BYTES,
        PM_OP_MAX, PM_OP_MIN, PM_SECRET_MAX_BYTES, PM_URL_MAX_BYTES, PM_USERNAME_MAX_BYTES,
    };
    use crate::status::{STATUS_NEED_BINDING, STATUS_NEED_PIN, STATUS_NEED_UP, STATUS_OK};
    use alloc::string::ToString;
    use alloc::vec;

    fn put_sample() -> PmPutRequestDto {
        PmPutRequestDto {
            label: "bank".to_string(),
            username: "alice".to_string(),
            secret: vec![0xAA; 24],
            url: None,
        }
    }

    #[test]
    fn opcodes_claim_first_free_range() {
        // Neighbors frozen elsewhere: 0x3E Secure Guard end, 0x3F GET_CAPS,
        // 0x40 SET_UP_POLICY, 0x41 VENDOR_SIGN, 0x42 BLE OOB.
        assert_eq!((OP_PM_PUT, OP_PM_GET, OP_PM_LIST, OP_PM_DELETE, OP_PM_STATUS), (0x43, 0x44, 0x45, 0x46, 0x47));
        assert_eq!((PM_OP_MIN, PM_OP_MAX), (0x43, 0x47));
        for (op, byte) in [
            (PmOp::Put, OP_PM_PUT),
            (PmOp::Get, OP_PM_GET),
            (PmOp::List, OP_PM_LIST),
            (PmOp::Delete, OP_PM_DELETE),
            (PmOp::Status, OP_PM_STATUS),
        ] {
            assert_eq!(op.opcode(), byte);
            assert_eq!(PmOp::from_opcode(byte), Some(op));
        }
        assert_eq!(PmOp::from_opcode(0x42), None);
        assert_eq!(PmOp::from_opcode(0x48), None);
    }

    #[test]
    fn status_preserves_wire_bytes() {
        assert_eq!(PmStatus::Ok.to_wire_status(), STATUS_OK);
        assert_eq!(PmStatus::NeedBinding.to_wire_status(), STATUS_NEED_BINDING);
        assert_eq!(
            PmStatus::PresenceRequired.to_wire_status(),
            STATUS_NEED_UP
        );
        assert_eq!(PmStatus::PinRequired.to_wire_status(), STATUS_NEED_PIN);
        assert_eq!(PmStatus::from_wire_status(0x00), Some(PmStatus::Ok));
        assert_eq!(
            PmStatus::from_wire_status(0x05),
            Some(PmStatus::NeedBinding)
        );
        assert_eq!(
            PmStatus::from_wire_status(0x01),
            Some(PmStatus::PresenceRequired)
        );
        assert_eq!(
            PmStatus::from_wire_status(0x02),
            Some(PmStatus::PinRequired)
        );
        assert_eq!(PmStatus::from_wire_status(0x03), None);
        assert_eq!(PmStatus::from_wire_status(0x04), None);
        assert_eq!(PmStatus::from_wire_status(0xFF), None);
        assert_eq!(PmStatus::NeedBinding.name(), "NeedBinding");
        assert_eq!(PmStatus::PresenceRequired.name(), "PresenceRequired");
        assert_eq!(PmStatus::PinRequired.name(), "PinRequired");
    }

    #[test]
    fn request_carrier_checks_compiled_gate() {
        let req = PmRequest::new(PmOp::List, vec![1, 2, 3]);
        assert_eq!(req.op, PmOp::List);
        assert_eq!(req.payload, vec![1u8, 2, 3]);
        // Feature `pm` is on for this test build (see Cargo invocation).
        assert_eq!(req.check_compiled(), Ok(()));
        assert_eq!(crate::require_pm(), Ok(()));
    }

    #[test]
    fn put_roundtrip_with_and_without_url() {
        let with_url = PmPutRequestDto {
            url: Some("https://bank.example".to_string()),
            ..put_sample()
        };
        for dto in [put_sample(), with_url] {
            let bytes = encode_pm_put_request(&dto).unwrap();
            assert_eq!(decode_pm_put_request(&bytes).unwrap(), dto);
        }
    }

    #[test]
    fn put_rejects_empty_secret_and_overcaps() {
        let mut bad = put_sample();
        bad.secret = vec![];
        assert!(encode_pm_put_request(&bad).is_err());
        let mut big = put_sample();
        big.secret = vec![0xAA; PM_SECRET_MAX_BYTES + 1];
        assert!(encode_pm_put_request(&big).is_err());
        let mut big_label = put_sample();
        big_label.label = "l".to_string().repeat(PM_LABEL_MAX_BYTES + 1);
        assert!(encode_pm_put_request(&big_label).is_err());
        let mut big_user = put_sample();
        big_user.username = "u".to_string().repeat(PM_USERNAME_MAX_BYTES + 1);
        assert!(encode_pm_put_request(&big_user).is_err());
        let mut big_url = put_sample();
        big_url.url = Some("u".to_string().repeat(PM_URL_MAX_BYTES + 1));
        assert!(encode_pm_put_request(&big_url).is_err());
        assert!(decode_pm_put_request(b"not-cbor").is_err());
    }

    #[test]
    fn id_bodies_roundtrip_and_reject_empty_or_oversize() {
        let get = PmGetRequestDto { id: vec![0x01; 16] };
        let bytes = encode_pm_get_request(&get).unwrap();
        assert_eq!(decode_pm_get_request(&bytes).unwrap(), get);
        let del = PmDeleteRequestDto { id: vec![0x02; 16] };
        let bytes = encode_pm_delete_request(&del).unwrap();
        assert_eq!(decode_pm_delete_request(&bytes).unwrap(), del);
        assert!(encode_pm_get_request(&PmGetRequestDto { id: vec![] }).is_err());
        assert!(
            encode_pm_delete_request(&PmDeleteRequestDto {
                id: vec![0x01; PM_ID_MAX_BYTES + 1]
            })
            .is_err()
        );
        assert!(decode_pm_get_request(b"junk").is_err());
    }

    #[test]
    fn list_roundtrips_pages_of_opaque_ids() {
        let req = PmListRequestDto {
            cursor: 7,
            limit: 10,
        };
        let bytes = encode_pm_list_request(&req).unwrap();
        assert_eq!(decode_pm_list_request(&bytes).unwrap(), req);
        let resp = PmListResponseDto {
            ids: vec![vec![0x01; 16], vec![0x02; 16]],
            next_cursor: 9,
            has_more: true,
        };
        let bytes = encode_pm_list_response(&resp).unwrap();
        assert_eq!(decode_pm_list_response(&bytes).unwrap(), resp);
        let empty = PmListResponseDto {
            ids: vec![],
            next_cursor: 0,
            has_more: false,
        };
        let bytes = encode_pm_list_response(&empty).unwrap();
        assert_eq!(decode_pm_list_response(&bytes).unwrap(), empty);
        let bad = PmListResponseDto {
            ids: vec![vec![0x01; PM_ID_MAX_BYTES + 1]],
            next_cursor: 0,
            has_more: false,
        };
        assert!(encode_pm_list_response(&bad).is_err());
    }

    #[test]
    fn release_and_status_roundtrip() {
        let rel = PmReleaseResponseDto {
            id: vec![0x01; 16],
            username: "alice".to_string(),
            secret: vec![0xAA; 24],
        };
        let bytes = encode_pm_release_response(&rel).unwrap();
        assert_eq!(decode_pm_release_response(&bytes).unwrap(), rel);
        let st = PmStatusDto {
            entry_count: 3,
            max_entries: 50,
        };
        let bytes = encode_pm_status_response(&st).unwrap();
        assert_eq!(decode_pm_status_response(&bytes).unwrap(), st);
    }

    #[test]
    fn debug_never_logs_user_data() {
        let put_dbg = alloc::format!("{:?}", put_sample());
        for forbidden in ["bank", "alice"] {
            assert!(!put_dbg.contains(forbidden), "leak: {put_dbg}");
        }
        assert!(put_dbg.contains("[REDACTED]"));
        let rel = PmReleaseResponseDto {
            id: vec![0x01; 16],
            username: "alice".to_string(),
            secret: vec![0xAA; 24],
        };
        let rel_dbg = alloc::format!("{:?}", rel);
        assert!(!rel_dbg.contains("alice"), "leak: {rel_dbg}");
        assert!(rel_dbg.contains("[REDACTED]"));
        let list = PmListResponseDto {
            ids: vec![vec![0xAB; 16]],
            next_cursor: 0,
            has_more: false,
        };
        let list_dbg = alloc::format!("{:?}", list);
        assert!(!list_dbg.contains("AB"), "leak: {list_dbg}");
        let get_dbg = alloc::format!(
            "{:?}",
            PmGetRequestDto { id: vec![0xAB; 16] }
        );
        assert!(!get_dbg.contains("AB"), "leak: {get_dbg}");
    }
}
