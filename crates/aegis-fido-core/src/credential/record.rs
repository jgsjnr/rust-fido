use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub id: Vec<u8>,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub algorithm: i32,
    pub private_key: Vec<u8>,
    pub public_key_cose: Vec<u8>,
    pub sign_count: u32,
    pub is_resident: bool,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub is_revoked: bool,
    pub cred_protect: Option<u8>,
    pub large_blob_key: Option<[u8; 32]>,
    pub cred_blob: Option<Vec<u8>>,
    pub hmac_secret_key: Option<[u8; 32]>,
    /// Per-credential user-presence policy (owner-explicit feature).
    ///
    /// `true` (default) = require touch for every use of THIS credential
    /// (existing UP flow unchanged, phishing resistance preserved).
    /// `false` = presence may be skipped for this credential ONLY, but a
    /// live unlocked session (PIN/UV) is still mandatory — silent use on a
    /// locked device is never allowed (see `requires_up` + firmware gate).
    /// Additive optional field: records encoded without it decode as `true`.
    #[serde(default = "default_up_required")]
    pub up_required: bool,
}

/// Default presence policy: require touch (fail-closed for old records).
pub fn default_up_required() -> bool {
    true
}

impl CredentialRecord {
    /// `true` when every use of this credential requires user presence.
    ///
    /// INVARIANT: `false` skips presence ONLY — an unlocked session
    /// (live PIN/UV) is still mandatory; locked-device silent use is
    /// always denied by the firmware gate.
    pub fn requires_up(&self) -> bool {
        self.up_required
    }

    pub fn is_valid(&self, current_time: u64) -> bool {
        if self.is_revoked {
            return false;
        }
        if let Some(exp) = self.expires_at {
            if current_time > exp {
                return false;
            }
        }
        true
    }
}

impl Drop for CredentialRecord {
    fn drop(&mut self) {
        self.private_key.zeroize();
        if let Some(ref mut k) = self.hmac_secret_key {
            k.zeroize();
        }
        if let Some(ref mut lb) = self.large_blob_key {
            lb.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn minimal(up_required: bool) -> CredentialRecord {
        CredentialRecord {
            id: vec![1, 2, 3],
            rp_id: String::from("example.com"),
            rp_name: None,
            user_id: vec![4],
            user_name: None,
            user_display_name: None,
            algorithm: -7,
            private_key: vec![5],
            public_key_cose: vec![6],
            sign_count: 0,
            is_resident: true,
            created_at: 0,
            expires_at: None,
            is_revoked: false,
            cred_protect: None,
            large_blob_key: None,
            cred_blob: None,
            hmac_secret_key: None,
            up_required,
        }
    }

    #[test]
    fn default_policy_requires_touch() {
        assert!(default_up_required());
        assert!(minimal(true).requires_up());
        assert!(!minimal(false).requires_up());
    }

    #[test]
    fn old_record_without_field_decodes_as_require_touch() {
        // Additive optional field: CBOR map without `up_required`
        // MUST decode as `true` (no migration wipe, fail-closed).
        let map = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text(String::from("id")),
                ciborium::value::Value::Bytes(vec![1, 2, 3]),
            ),
            (
                ciborium::value::Value::Text(String::from("rp_id")),
                ciborium::value::Value::Text(String::from("example.com")),
            ),
            (
                ciborium::value::Value::Text(String::from("user_id")),
                ciborium::value::Value::Bytes(vec![4]),
            ),
            (
                ciborium::value::Value::Text(String::from("algorithm")),
                ciborium::value::Value::Integer((-7).into()),
            ),
            (
                ciborium::value::Value::Text(String::from("private_key")),
                ciborium::value::Value::Bytes(vec![5]),
            ),
            (
                ciborium::value::Value::Text(String::from("public_key_cose")),
                ciborium::value::Value::Bytes(vec![6]),
            ),
            (
                ciborium::value::Value::Text(String::from("sign_count")),
                ciborium::value::Value::Integer(0u64.into()),
            ),
            (
                ciborium::value::Value::Text(String::from("is_resident")),
                ciborium::value::Value::Bool(true),
            ),
            (
                ciborium::value::Value::Text(String::from("created_at")),
                ciborium::value::Value::Integer(0u64.into()),
            ),
            (
                ciborium::value::Value::Text(String::from("is_revoked")),
                ciborium::value::Value::Bool(false),
            ),
        ]);
        let mut buf = vec![];
        ciborium::into_writer(&map, &mut buf).expect("encode map");
        let rec: CredentialRecord = ciborium::from_reader(&buf[..]).expect("decode without field");
        assert!(
            rec.up_required,
            "old record without field MUST behave as require-touch"
        );
        assert!(rec.requires_up());
    }

    #[test]
    fn explicit_opt_out_roundtrips() {
        let rec = minimal(false);
        let mut buf = vec![];
        ciborium::into_writer(&rec, &mut buf).expect("encode");
        let back: CredentialRecord = ciborium::from_reader(&buf[..]).expect("decode");
        assert!(!back.up_required);
        assert!(!back.requires_up());
    }
}
