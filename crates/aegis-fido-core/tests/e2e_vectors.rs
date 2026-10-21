//! Gera hex de MC/GA para o script e2e (imprime; sempre passa).
use aegis_fido_core::ctap::cbor::encode_cbor_value;
use ciborium::value::Value;

fn mc() -> Vec<u8> {
    let req = vec![
        (Value::Integer(1.into()), Value::Bytes(vec![0x11u8; 32])),
        (
            Value::Integer(2.into()),
            Value::Map(vec![(Value::Text("id".into()), Value::Text("e2e".into()))]),
        ),
        (
            Value::Integer(3.into()),
            Value::Map(vec![
                (Value::Text("id".into()), Value::Bytes(b"u1".to_vec())),
                (Value::Text("name".into()), Value::Text("e2e".into())),
            ]),
        ),
        (
            Value::Integer(4.into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (Value::Text("alg".into()), Value::Integer((-7i64).into())),
            ])]),
        ),
        (
            Value::Integer(7.into()),
            Value::Map(vec![(Value::Text("rk".into()), Value::Bool(true))]),
        ),
    ];
    encode_cbor_value(&Value::Map(req)).unwrap()
}

fn ga() -> Vec<u8> {
    let req = vec![
        (Value::Integer(1.into()), Value::Text("e2e".into())),
        (Value::Integer(2.into()), Value::Bytes(vec![0x11u8; 32])),
    ];
    encode_cbor_value(&Value::Map(req)).unwrap()
}

#[test]
fn print_e2e_vectors() {
    let mc = mc();
    let ga = ga();
    println!("E2E_MC={}", hex_of(&mc));
    println!("E2E_GA={}", hex_of(&ga));
    assert!(!mc.is_empty() && !ga.is_empty());
}

fn hex_of(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}
