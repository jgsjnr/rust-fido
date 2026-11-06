//! OP_KEY_LIST (0x22) `alg`-per-slot tests (item #15: `alg` real por slot).
//!
//! Formato coberto aqui (ver `vendor_dispatch.rs` no braco OP_KEY_LIST):
//! por slot `[0x01 id][0x02 label][0x05 alg i32 BE]`; `alg` e o CoseAlgorithm
//! real do slot, nunca defaultado. Leitores antigos (so 0x01/0x02) seguem
//! parseando (ignorar 0x05); vault vazio = corpo vazio com 0x00.

use super::super::exec_vendor_op;
use super::test_storage;
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::crypto::curves::CoseAlgorithm;
use aegis_fido_core::oath::applet::OathApplet;
use aegis_fido_core::oath::tlv::{write_tlv, TAG_ALG_HINT, TAG_LABEL, TAG_SLOT};

/// #15: OP_KEY_LIST (0x22) expoe o `alg` real por slot (TAG 0x05, i32 BE),
/// mantendo compat: leitores antigos que parseiam so 0x01/0x02 seguem
/// funcionando (ignorar o 0x05), e vault vazio responde corpo vazio com 0x00.
#[test]
fn key_list_expoe_alg_real_por_slot_com_compat() {
    use aegis_fido_core::oath::tlv::parse_tlv_records;
    let mut st = test_storage();
    let mut keys = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    // 3 slots com algs distintos (GEN via executor, gate binding+UP, sem PIN).
    for (slot, alg, label) in [
        (0u8, CoseAlgorithm::ES256, "k-es256"),
        (1u8, CoseAlgorithm::ES384, "k-es384"),
        (2u8, CoseAlgorithm::EdDSA, "k-eddsa"),
    ] {
        let mut payload = Vec::new();
        write_tlv(&mut payload, TAG_SLOT, &[slot]);
        write_tlv(&mut payload, TAG_LABEL, label.as_bytes());
        write_tlv(&mut payload, TAG_ALG_HINT, &(alg.to_i32().to_be_bytes()));
        let (status, _) = exec_vendor_op(
            &mut keys,
            &mut oath,
            &mut st,
            crate::ble_gatt::OP_KEY_GEN_ONDEVICE,
            &payload,
            true,
            false,
            true,
            0,
            &mut rng,
        );
        assert_eq!(status, 0x00, "GEN slot {slot}");
    }
    // LIST: 0x00 + triplas [0x01 id][0x02 label][0x05 alg i32 BE].
    let (status, body) = exec_vendor_op(
        &mut keys,
        &mut oath,
        &mut st,
        crate::ble_gatt::OP_KEY_LIST,
        &[],
        true,
        false,
        true,
        0,
        &mut rng,
    );
    assert_eq!(status, 0x00);
    assert!(!body.is_empty(), "LIST com 3 slots nao e vazio");
    let records = parse_tlv_records(&body).expect("LIST deve ser TLV valido");
    // Agrupa por slot: cada 0x01 inicia; 0x02/0x05 seguintes pertencem a ele.
    let mut slots: Vec<(u8, Vec<u8>, i32)> = Vec::new();
    let mut cur: Option<(u8, Vec<u8>, Option<i32>)> = None;
    for r in &records {
        match r.tag {
            TAG_SLOT => {
                if let Some((id, lb, alg)) = cur.take() {
                    slots.push((id, lb, alg.expect("todo slot tem 0x05 alg")));
                }
                assert_eq!(r.value.len(), 1, "slot 1 B");
                cur = Some((r.value[0], Vec::new(), None));
            }
            TAG_LABEL => {
                cur.as_mut().expect("label sem slot").1 = r.value.to_vec();
            }
            TAG_ALG_HINT => {
                assert_eq!(r.value.len(), 4, "alg i32 BE 4 B");
                let a = i32::from_be_bytes(r.value.try_into().expect("alg 4 B"));
                assert!(
                    matches!(a, -7 | -8 | -35 | -36 | -47),
                    "alg real COSE, nunca fabricado: {a}"
                );
                cur.as_mut().expect("alg sem slot").2 = Some(a);
            }
            other => panic!("tag inesperada no LIST: 0x{other:02X}"),
        }
    }
    if let Some((id, lb, alg)) = cur.take() {
        slots.push((id, lb, alg.expect("todo slot tem 0x05 alg")));
    }
    assert_eq!(slots.len(), 3, "um triple por slot");
    assert_eq!((slots[0].0, slots[0].2), (0, -7));
    assert_eq!(slots[0].1, b"k-es256".to_vec());
    assert_eq!((slots[1].0, slots[1].2), (1, -35));
    assert_eq!(slots[1].1, b"k-es384".to_vec());
    assert_eq!((slots[2].0, slots[2].2), (2, -8));
    assert_eq!(slots[2].1, b"k-eddsa".to_vec());
    // Compat leitor antigo: so 0x01/0x02 (ignora 0x05) => mesmos slots/labels.
    let mut old: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut pending: Option<u8> = None;
    for r in &records {
        if r.tag == TAG_SLOT {
            pending = Some(r.value[0]);
        } else if r.tag == TAG_LABEL {
            if let Some(id) = pending.take() {
                old.push((id, r.value.to_vec()));
            }
        }
    }
    assert_eq!(
        old,
        vec![
            (0u8, b"k-es256".to_vec()),
            (1u8, b"k-es384".to_vec()),
            (2u8, b"k-eddsa".to_vec()),
        ],
        "leitor antigo (0x01/0x02) segue parseando"
    );
    // Vault vazio: 0x00 + corpo vazio.
    let mut empty_keys = KeyManager::new();
    let mut empty_oath = OathApplet::new();
    let (status, body) = exec_vendor_op(
        &mut empty_keys,
        &mut empty_oath,
        &mut st,
        crate::ble_gatt::OP_KEY_LIST,
        &[],
        true,
        false,
        true,
        0,
        &mut rng,
    );
    assert_eq!(status, 0x00);
    assert!(body.is_empty(), "LIST vazio = corpo vazio");
}
