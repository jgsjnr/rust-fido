use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use ciborium::value::Value;
use crate::crypto::cose::CoseKey;
use crate::crypto::ecdh::EcdhKeyAgreement;
use crate::crypto::hash::{hmac_sha256, sha256};
use crate::crypto::pin_protocol::{PinProtocol1, PinProtocol2};

pub const EXT_CRED_PROTECT: &str = "credProtect";
pub const EXT_HMAC_SECRET: &str = "hmac-secret";
pub const EXT_CRED_BLOBS: &str = "credBlob";
pub const EXT_CRED_BLOBS_PLURAL: &str = "credBlobs";
pub const EXT_LARGE_BLOB_KEY: &str = "largeBlobKey";
pub const EXT_MIN_PIN_LENGTH: &str = "minPinLength";
pub const EXT_PIN_COMPLEXITY: &str = "pinComplexity";
pub const EXT_UVM: &str = "uvm";
pub const EXT_THIRD_PARTY_PAYMENT: &str = "thirdPartyPayment";

pub const CRED_PROTECT_OPTIONAL: u8 = 1;
pub const CRED_PROTECT_OPTIONAL_WITH_LIST: u8 = 2;
pub const CRED_PROTECT_REQUIRED: u8 = 3;

#[derive(Clone, Debug, Default)]
pub struct ExtensionInputs {
    pub cred_protect: Option<u8>,
    pub hmac_secret_make_cred: bool,
    pub hmac_secret_get_assertion: Option<HmacSecretGetAssertionInput>,
    pub cred_blob: Option<Vec<u8>>,
    pub cred_blob_requested: bool,
    pub large_blob_key_requested: bool,
    pub min_pin_length_requested: bool,
    pub pin_complexity: Option<bool>,
    pub uvm_requested: bool,
    pub third_party_payment: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct HmacSecretGetAssertionInput {
    pub key_agreement: CoseKey,
    pub salt_enc: Vec<u8>,
    pub salt_auth: Vec<u8>,
    pub pin_uv_protocol: u32,
}

#[derive(Clone, Debug, Default)]
pub struct ExtensionOutputs {
    pub cred_protect: Option<u8>,
    pub hmac_secret_make_cred: bool,
    pub hmac_secret_output_enc: Option<Vec<u8>>,
    pub cred_blob: Option<Vec<u8>>,
    pub large_blob_key: Option<Vec<u8>>,
    pub min_pin_length: Option<u32>,
    pub pin_complexity: Option<bool>,
    pub uvm: Option<Vec<Vec<u32>>>,
    pub third_party_payment: Option<bool>,
}

impl ExtensionInputs {
    pub fn parse(val: &Value) -> Self {
        let mut inputs = Self::default();
        let map = match val {
            Value::Map(m) => m,
            _ => return inputs,
        };

        for (k, v) in map {
            let key_str = match k {
                Value::Text(s) => s.as_str(),
                _ => continue,
            };

            match key_str {
                EXT_CRED_PROTECT => {
                    if let Value::Integer(i) = v {
                        let cp: i128 = (*i).into();
                        if (1..=3).contains(&cp) {
                            inputs.cred_protect = Some(cp as u8);
                        }
                    }
                }
                EXT_HMAC_SECRET => match v {
                    Value::Bool(b) => {
                        inputs.hmac_secret_make_cred = *b;
                    }
                    Value::Map(sub_map) => {
                        inputs.hmac_secret_get_assertion = Self::parse_hmac_secret_get_assertion(sub_map);
                    }
                    _ => {}
                },
                EXT_CRED_BLOBS | EXT_CRED_BLOBS_PLURAL => match v {
                    Value::Bytes(b) => {
                        inputs.cred_blob = Some(b.clone());
                    }
                    Value::Bool(b) => {
                        inputs.cred_blob_requested = *b;
                    }
                    _ => {}
                },
                EXT_LARGE_BLOB_KEY => {
                    if let Value::Bool(b) = v {
                        inputs.large_blob_key_requested = *b;
                    }
                }
                EXT_MIN_PIN_LENGTH => {
                    if let Value::Bool(b) = v {
                        inputs.min_pin_length_requested = *b;
                    }
                }
                EXT_PIN_COMPLEXITY => {
                    if let Value::Bool(b) = v {
                        inputs.pin_complexity = Some(*b);
                    }
                }
                EXT_UVM => {
                    if let Value::Bool(b) = v {
                        inputs.uvm_requested = *b;
                    }
                }
                EXT_THIRD_PARTY_PAYMENT => {
                    if let Value::Bool(b) = v {
                        inputs.third_party_payment = Some(*b);
                    }
                }
                _ => {}
            }
        }

        inputs
    }

    fn parse_hmac_secret_get_assertion(sub_map: &[(Value, Value)]) -> Option<HmacSecretGetAssertionInput> {
        let mut key_agreement = None;
        let mut salt_enc = None;
        let mut salt_auth = None;
        let mut pin_uv_protocol = 1; // default to 1 if not specified

        for (k, v) in sub_map {
            if let Value::Integer(i) = k {
                let id: i128 = (*i).into();
                match id {
                    1 => {
                        if let Ok(ck) = CoseKey::from_cbor_value(v) {
                            key_agreement = Some(ck);
                        }
                    }
                    2 => {
                        if let Value::Bytes(b) = v {
                            salt_enc = Some(b.clone());
                        }
                    }
                    3 => {
                        if let Value::Bytes(b) = v {
                            salt_auth = Some(b.clone());
                        }
                    }
                    4 => {
                        if let Value::Integer(proto) = v {
                            let p: i128 = (*proto).into();
                            pin_uv_protocol = p as u32;
                        }
                    }
                    _ => {}
                }
            }
        }

        Some(HmacSecretGetAssertionInput {
            key_agreement: key_agreement?,
            salt_enc: salt_enc?,
            salt_auth: salt_auth?,
            pin_uv_protocol,
        })
    }
}

impl ExtensionOutputs {
    pub fn to_cbor_value(&self) -> Option<Value> {
        let mut map = Vec::new();

        if let Some(cp) = self.cred_protect {
            map.push((Value::Text(String::from(EXT_CRED_PROTECT)), Value::Integer((cp as i64).into())));
        }

        if self.hmac_secret_make_cred {
            map.push((Value::Text(String::from(EXT_HMAC_SECRET)), Value::Bool(true)));
        }

        if let Some(ref enc) = self.hmac_secret_output_enc {
            map.push((Value::Text(String::from(EXT_HMAC_SECRET)), Value::Bytes(enc.clone())));
        }

        if let Some(ref blob) = self.cred_blob {
            map.push((Value::Text(String::from(EXT_CRED_BLOBS)), Value::Bytes(blob.clone())));
        }

        if let Some(ref lb_key) = self.large_blob_key {
            map.push((Value::Text(String::from(EXT_LARGE_BLOB_KEY)), Value::Bytes(lb_key.clone())));
        }

        if let Some(mpl) = self.min_pin_length {
            map.push((Value::Text(String::from(EXT_MIN_PIN_LENGTH)), Value::Integer((mpl as i64).into())));
        }

        if let Some(comp) = self.pin_complexity {
            map.push((Value::Text(String::from(EXT_PIN_COMPLEXITY)), Value::Bool(comp)));
        }

        if let Some(ref uvm_data) = self.uvm {
            let mut list = Vec::new();
            for item in uvm_data {
                let sub: Vec<Value> = item.iter().map(|&x| Value::Integer((x as i64).into())).collect();
                list.push(Value::Array(sub));
            }
            map.push((Value::Text(String::from(EXT_UVM)), Value::Array(list)));
        }

        if let Some(tpp) = self.third_party_payment {
            map.push((Value::Text(String::from(EXT_THIRD_PARTY_PAYMENT)), Value::Bool(tpp)));
        }

        if map.is_empty() {
            None
        } else {
            Some(Value::Map(map))
        }
    }

    pub fn to_cbor_bytes(&self) -> Option<Vec<u8>> {
        let val = self.to_cbor_value()?;
        let mut bytes = Vec::new();
        ciborium::into_writer(&val, &mut bytes).ok()?;
        Some(bytes)
    }
}

/// Evaluates PIN complexity against basic policies
pub fn check_pin_complexity(pin: &str) -> bool {
    if pin.len() < 4 {
        return false;
    }

    let bytes = pin.as_bytes();
    // Rule 1: Not all identical (e.g. "1111", "000000")
    if bytes.iter().all(|&b| b == bytes[0]) {
        return false;
    }

    // Rule 2: Not simple ascending or descending sequence (e.g. "1234", "9876")
    let is_ascending = bytes.windows(2).all(|w| w[1] as i32 == w[0] as i32 + 1);
    let is_descending = bytes.windows(2).all(|w| w[1] as i32 == w[0] as i32 - 1);
    if is_ascending || is_descending {
        return false;
    }

    true
}
