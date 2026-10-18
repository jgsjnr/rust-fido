use alloc::string::String;
use alloc::vec::Vec;
use ciborium::value::Value;
use crate::ctap::cbor::encode_cbor_value;
use crate::ctap::status_code::CtapError;

pub const DEFAULT_AAGUID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

#[derive(Clone, Debug)]
pub struct AuthenticatorInfoConfig {
    pub aaguid: [u8; 16],
    pub pin_set: bool,
    pub min_pin_length: u32,
    pub force_pin_change: bool,
    pub remaining_resident_credentials: usize,
    pub enterprise_attestation: bool,
}

impl Default for AuthenticatorInfoConfig {
    fn default() -> Self {
        Self {
            aaguid: DEFAULT_AAGUID,
            pin_set: false,
            min_pin_length: 4,
            force_pin_change: false,
            remaining_resident_credentials: 50,
            enterprise_attestation: false,
        }
    }
}

pub struct AuthenticatorInfo;

impl AuthenticatorInfo {
    pub fn build_cbor_value(config: &AuthenticatorInfoConfig) -> Value {
        let mut map = Vec::new();

        // 1: versions: ["FIDO_2_0", "FIDO_2_1", "FIDO_2_1_PRE", "U2F_V2"]
        let versions = vec![
            Value::Text(String::from("FIDO_2_0")),
            Value::Text(String::from("FIDO_2_1")),
            Value::Text(String::from("FIDO_2_1_PRE")),
            Value::Text(String::from("U2F_V2")),
        ];
        map.push((Value::Integer(1.into()), Value::Array(versions)));

        // 2: extensions: ["credProtect", "hmac-secret", "credBlobs", "largeBlobKey", "minPinLength", "pinComplexity", "uvm", "thirdPartyPayment"]
        let extensions = vec![
            Value::Text(String::from("credProtect")),
            Value::Text(String::from("hmac-secret")),
            Value::Text(String::from("credBlobs")),
            Value::Text(String::from("largeBlobKey")),
            Value::Text(String::from("minPinLength")),
            Value::Text(String::from("pinComplexity")),
            Value::Text(String::from("uvm")),
            Value::Text(String::from("thirdPartyPayment")),
        ];
        map.push((Value::Integer(2.into()), Value::Array(extensions)));

        // 3: aaguid: 16 bytes
        map.push((
            Value::Integer(3.into()),
            Value::Bytes(config.aaguid.to_vec()),
        ));

        // 4: options map
        let mut options = Vec::new();
        options.push((Value::Text(String::from("plat")), Value::Bool(false)));
        options.push((Value::Text(String::from("rk")), Value::Bool(true)));
        options.push((Value::Text(String::from("clientPin")), Value::Bool(config.pin_set)));
        options.push((Value::Text(String::from("up")), Value::Bool(true)));
        options.push((Value::Text(String::from("pinUvAuthToken")), Value::Bool(true)));
        options.push((Value::Text(String::from("noMcGaPermissionsWithClientPin")), Value::Bool(true)));
        options.push((Value::Text(String::from("largeBlobs")), Value::Bool(true)));
        options.push((Value::Text(String::from("ep")), Value::Bool(config.enterprise_attestation)));
        options.push((Value::Text(String::from("credMgmt")), Value::Bool(true)));
        options.push((Value::Text(String::from("authnrCfg")), Value::Bool(true)));
        options.push((Value::Text(String::from("setMinPINLength")), Value::Bool(true)));
        options.push((Value::Text(String::from("makeCredUvNotRqd")), Value::Bool(true)));
        options.push((Value::Text(String::from("credentialMgmtPreview")), Value::Bool(true)));
        map.push((Value::Integer(4.into()), Value::Map(options)));

        // 5: maxMsgSize: 2048
        map.push((Value::Integer(5.into()), Value::Integer(2048.into())));

        // 6: pinUvProtocols: [1, 2]
        let pin_uv_protocols = vec![
            Value::Integer(1.into()),
            Value::Integer(2.into()),
        ];
        map.push((Value::Integer(6.into()), Value::Array(pin_uv_protocols)));

        // 7: maxCredentialCountInList: 8
        map.push((Value::Integer(7.into()), Value::Integer(8.into())));

        // 8: maxCredentialIdLength: 128
        map.push((Value::Integer(8.into()), Value::Integer(128.into())));

        // 9: transports: ["usb", "nfc"]
        let transports = vec![
            Value::Text(String::from("usb")),
            Value::Text(String::from("nfc")),
        ];
        map.push((Value::Integer(9.into()), Value::Array(transports)));

        // 10: algorithms: [-7 ES256, -35 ES384, -36 ES512, -47 ES256K, -8 EdDSA]
        let mut algs = Vec::new();
        for &alg in &[-7, -35, -36, -47, -8] {
            let mut alg_map = Vec::new();
            alg_map.push((Value::Text(String::from("type")), Value::Text(String::from("public-key"))));
            alg_map.push((Value::Text(String::from("alg")), Value::Integer((alg as i64).into())));
            algs.push(Value::Map(alg_map));
        }
        map.push((Value::Integer(10.into()), Value::Array(algs)));

        // 11: maxSerializedLargeBlobArray: 2048
        map.push((Value::Integer(11.into()), Value::Integer(2048.into())));

        // 12: forcePINChange
        map.push((Value::Integer(12.into()), Value::Bool(config.force_pin_change)));

        // 13: minPINLength
        map.push((Value::Integer(13.into()), Value::Integer((config.min_pin_length as i64).into())));

        // 15: maxCredBlobLength: 64
        map.push((Value::Integer(15.into()), Value::Integer(64.into())));

        // 19: remainingDiscoverableCredentials
        map.push((Value::Integer(19.into()), Value::Integer((config.remaining_resident_credentials as i64).into())));

        Value::Map(map)
    }

    pub fn handle_get_info(config: &AuthenticatorInfoConfig) -> Result<Vec<u8>, CtapError> {
        let val = Self::build_cbor_value(config);
        encode_cbor_value(&val)
    }
}
