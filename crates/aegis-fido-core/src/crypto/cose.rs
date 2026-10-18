use alloc::vec::Vec;
use ciborium::value::Value;

pub const COSE_ALG_ES256: i32 = -7;
pub const COSE_ALG_EDDSA: i32 = -8;
pub const COSE_ALG_ES384: i32 = -35;
pub const COSE_ALG_ES512: i32 = -36;
pub const COSE_ALG_ES256K: i32 = -47;

pub const COSE_KTY_OKP: i64 = 1;
pub const COSE_KTY_EC2: i64 = 2;

pub const COSE_CRV_P256: i64 = 1;
pub const COSE_CRV_P384: i64 = 2;
pub const COSE_CRV_P521: i64 = 3;
pub const COSE_CRV_ED25519: i64 = 6;
pub const COSE_CRV_SECP256K1: i64 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoseKey {
    Ec2 {
        alg: i32,
        crv: i64,
        x: Vec<u8>,
        y: Vec<u8>,
    },
    Okp {
        alg: i32,
        crv: i64,
        x: Vec<u8>,
    },
}

impl CoseKey {
    /// Creates a P-256 public key COSE structure
    pub fn p256(x: Vec<u8>, y: Vec<u8>) -> Self {
        Self::Ec2 {
            alg: COSE_ALG_ES256,
            crv: COSE_CRV_P256,
            x,
            y,
        }
    }

    /// Creates a P-384 public key COSE structure
    pub fn p384(x: Vec<u8>, y: Vec<u8>) -> Self {
        Self::Ec2 {
            alg: COSE_ALG_ES384,
            crv: COSE_CRV_P384,
            x,
            y,
        }
    }

    /// Creates a P-521 public key COSE structure
    pub fn p521(x: Vec<u8>, y: Vec<u8>) -> Self {
        Self::Ec2 {
            alg: COSE_ALG_ES512,
            crv: COSE_CRV_P521,
            x,
            y,
        }
    }

    /// Creates a secp256k1 public key COSE structure
    pub fn secp256k1(x: Vec<u8>, y: Vec<u8>) -> Self {
        Self::Ec2 {
            alg: COSE_ALG_ES256K,
            crv: COSE_CRV_SECP256K1,
            x,
            y,
        }
    }

    /// Creates an Ed25519 public key COSE structure
    pub fn ed25519(x: Vec<u8>) -> Self {
        Self::Okp {
            alg: COSE_ALG_EDDSA,
            crv: COSE_CRV_ED25519,
            x,
        }
    }

    /// Converts COSE key to ciborium Value::Map in canonical CTAP order
    pub fn to_cbor_value(&self) -> Value {
        match self {
            Self::Ec2 { alg, crv, x, y } => {
                let mut map = Vec::new();
                map.push((Value::Integer(1.into()), Value::Integer(COSE_KTY_EC2.into())));
                map.push((Value::Integer(3.into()), Value::Integer((*alg as i64).into())));
                map.push((Value::Integer((-1).into()), Value::Integer((*crv).into())));
                map.push((Value::Integer((-2).into()), Value::Bytes(x.clone())));
                map.push((Value::Integer((-3).into()), Value::Bytes(y.clone())));
                Value::Map(map)
            }
            Self::Okp { alg, crv, x } => {
                let mut map = Vec::new();
                map.push((Value::Integer(1.into()), Value::Integer(COSE_KTY_OKP.into())));
                map.push((Value::Integer(3.into()), Value::Integer((*alg as i64).into())));
                map.push((Value::Integer((-1).into()), Value::Integer((*crv).into())));
                map.push((Value::Integer((-2).into()), Value::Bytes(x.clone())));
                Value::Map(map)
            }
        }
    }

    /// Serializes COSE key into CBOR byte vector
    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        let val = self.to_cbor_value();
        let mut bytes = Vec::new();
        ciborium::into_writer(&val, &mut bytes).expect("COSE serialization failed");
        bytes
    }

    /// Parses a COSE key from ciborium Value
    pub fn from_cbor_value(val: &Value) -> Result<Self, &'static str> {
        let map = match val {
            Value::Map(m) => m,
            _ => return Err("Expected CBOR Map for COSE key"),
        };

        let mut kty = None;
        let mut alg = None;
        let mut crv = None;
        let mut x = None;
        let mut y = None;

        for (k, v) in map {
            if let Value::Integer(i) = k {
                let key_id: i128 = (*i).into();
                match key_id {
                    1 => {
                        if let Value::Integer(kt) = v {
                            kty = Some(i128::from(*kt) as i64);
                        }
                    }
                    3 => {
                        if let Value::Integer(a) = v {
                            alg = Some(i128::from(*a) as i32);
                        }
                    }
                    -1 => {
                        if let Value::Integer(c) = v {
                            crv = Some(i128::from(*c) as i64);
                        }
                    }
                    -2 => {
                        if let Value::Bytes(b) = v {
                            x = Some(b.clone());
                        }
                    }
                    -3 => {
                        if let Value::Bytes(b) = v {
                            y = Some(b.clone());
                        }
                    }
                    _ => {}
                }
            }
        }

        let kty = kty.ok_or("Missing COSE kty")?;
        let alg = alg.unwrap_or(COSE_ALG_ES256);
        let crv = crv.ok_or("Missing COSE crv")?;
        let x = x.ok_or("Missing COSE x coordinate")?;

        if kty == COSE_KTY_OKP {
            Ok(Self::Okp { alg, crv, x })
        } else if kty == COSE_KTY_EC2 {
            let y = y.ok_or("Missing COSE y coordinate")?;
            Ok(Self::Ec2 { alg, crv, x, y })
        } else {
            Err("Unsupported COSE key type")
        }
    }

    /// Parses COSE key from raw bytes
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let val: Value = ciborium::from_reader(bytes).map_err(|_| "Invalid CBOR")?;
        Self::from_cbor_value(&val)
    }

    pub fn algorithm(&self) -> i32 {
        match self {
            Self::Ec2 { alg, .. } => *alg,
            Self::Okp { alg, .. } => *alg,
        }
    }
}
