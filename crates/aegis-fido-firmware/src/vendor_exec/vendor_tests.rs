//! Vendor executor tests (move-only split of `vendor_exec::tests`).

use super::*;
use crate::persistence::{FlashStorageBackend, MockFlashBackend, SecureStorage};
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::credential::{KEY_USE_AUTH, KEY_USE_SIGN};
use aegis_fido_core::crypto::curves::CoseAlgorithm;
use aegis_fido_core::ctap::client_pin::ClientPinState;
use aegis_fido_core::oath::applet::OathApplet;
use aegis_fido_core::oath::tlv::{write_tlv, TAG_LABEL, TAG_SLOT};

fn test_storage() -> SecureStorage<MockFlashBackend> {
    SecureStorage::new(MockFlashBackend::new(), &[0x11u8; 32], &[0x22u8; 32])
}

#[test]
fn pin_state_roundtrip_e_ausente_e_padrao() {
    let mut st = test_storage();
    let mut pin = ClientPinState::default();
    // Ausente: padrão (sem PIN, 8 retries), ok=true.
    assert!(load_pin_state(&st, &mut pin));
    assert_eq!(pin.pin_hash, None);
    assert_eq!(pin.pin_retries, 8);
    // Salva hash+retries e recarrega.
    let pin_set = ClientPinState {
        pin_hash: Some([0xABu8; 16]),
        pin_retries: 5,
        ..Default::default()
    };
    assert!(save_pin_state(&mut st, &pin_set));
    let mut pin2 = ClientPinState::default();
    assert!(load_pin_state(&st, &mut pin2));
    assert_eq!(pin2.pin_hash, Some([0xABu8; 16]));
    assert_eq!(pin2.pin_retries, 5);
    // Limpa hash (reset): volta a None.
    let pin_clear = ClientPinState {
        pin_hash: None,
        ..Default::default()
    };
    assert!(save_pin_state(&mut st, &pin_clear));
    let mut pin3 = ClientPinState {
        pin_hash: Some([0u8; 16]),
        ..Default::default()
    };
    assert!(load_pin_state(&st, &mut pin3));
    assert_eq!(pin3.pin_hash, None);
}

fn enroll_req(pin: &[u8], puk: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + pin.len() + puk.len());
    v.push(pin.len() as u8);
    v.extend_from_slice(pin);
    v.extend_from_slice(puk);
    v
}

fn exec_enroll(
    storage: &mut SecureStorage<MockFlashBackend>,
    payload: &[u8],
    binding_ok: bool,
    up: bool,
) -> (u8, Vec<u8>) {
    let mut keys = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    exec_vendor_op(
        &mut keys,
        &mut oath,
        storage,
        crate::ble_gatt::OP_PIV_ENROLL,
        payload,
        binding_ok,
        false,
        up,
        0,
        &mut rng,
    )
}

#[test]
fn piv_enroll_ok_e_segunda_tentativa_nega() {
    let mut st = test_storage();
    let req = enroll_req(b"123456", b"12345678");
    assert_eq!(exec_enroll(&mut st, &req, true, true).0, 0x00);
    // Já provisionado: fail-closed sem oráculo.
    assert_eq!(exec_enroll(&mut st, &req, true, true).0, 0x04);
}

#[test]
fn piv_enroll_exige_up_e_binding() {
    let mut st = test_storage();
    let req = enroll_req(b"123456", b"12345678");
    assert_eq!(exec_enroll(&mut st, &req, true, false).0, 0x01);
    if crate::binding::binding_bypass_enabled() {
        // test-mode: bypass de vínculo documentado (binding.rs); sem
        // vínculo mas com UP, o enroll prossegue e provisiona (0x00).
        assert_eq!(exec_enroll(&mut st, &req, false, true).0, 0x00);
    } else {
        assert_eq!(exec_enroll(&mut st, &req, false, true).0, 0x05);
    }
}

#[test]
fn piv_enroll_rejeita_geometria_invalida() {
    let mut st = test_storage();
    // pin_len mente / puk curto / vazio.
    assert_eq!(exec_enroll(&mut st, &[8, 1, 2, 3], true, true).0, 0x04);
    assert_eq!(
        exec_enroll(&mut st, &enroll_req(b"123", b"12345678"), true, true).0,
        0x04
    );
    assert_eq!(
        exec_enroll(&mut st, &enroll_req(b"123456", b"1234"), true, true).0,
        0x04
    );
    assert_eq!(exec_enroll(&mut st, &[], true, true).0, 0x04);
}

/// Device-side T13: 8 slots "e2e-t1"/ES256 + GEN do 9º via
/// `exec_vendor_op` → `0x00`, com estado final de 534 B.
/// FALHA com o teto antigo de 512 B (save → `BufferOverflow` → `0x04`);
/// passa com o teto 4096 (prova de que 512 era insuficiente).
#[test]
fn gen_nono_slot_apos_oito_e2e_t1_agora_passa() {
    let mut st = test_storage();
    let mut keys = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    for slot in 0..8u8 {
        let mut payload = Vec::new();
        write_tlv(&mut payload, TAG_SLOT, &[slot]);
        write_tlv(&mut payload, TAG_LABEL, b"e2e-t1");
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
    // GEN do 9º slot pelo executor (gate binding + UP, sem PIN).
    let mut payload = Vec::new();
    write_tlv(&mut payload, TAG_SLOT, &[8]);
    write_tlv(&mut payload, TAG_LABEL, b"e2e-t1");
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
    assert_eq!(status, 0x00, "GEN 9o slot via executor");
    // 3 B header + 9 × (21 fixos + 6 label + 32 segredo ES256) = 534 B.
    let blob = keys.export_state();
    assert_eq!(blob.len(), 534);
    // Load/import roundtrip via NVS.
    let mut keys2 = KeyManager::new();
    let mut oath2 = OathApplet::new();
    assert!(load_states(&st, &mut keys2, &mut oath2));
    assert_eq!(keys2.export_state(), blob);
    assert_eq!(keys2.len(), 9);
}

/// Pior caso: 32 slots ES512 (segredo 66 B) + label de 32 B →
/// export de `3 + 32×(21+32+66) = 3811` B, com save/load/import ok.
/// FALHA com o teto antigo de 512 B; passa com o teto 4096.
#[test]
fn trinta_e_dois_slots_pior_caso_es512_label32_roundtrip() {
    let mut st = test_storage();
    let mut keys = KeyManager::new();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let label32 = "0123456789abcdef0123456789abcdef".to_string();
    assert_eq!(label32.len(), 32);
    for slot in 0..32u8 {
        keys.generate(
            slot,
            CoseAlgorithm::ES512,
            label32.clone(),
            KEY_USE_SIGN | KEY_USE_AUTH,
            0,
            true,
            &mut rng,
        )
        .expect("GEN ES512");
    }
    let blob = keys.export_state();
    assert_eq!(blob.len(), 3811);
    assert!(
        save_keys_result(&mut st, &keys).is_ok(),
        "save do pior caso"
    );
    let mut keys2 = KeyManager::new();
    assert!(load_states(&st, &mut keys2, &mut OathApplet::new()));
    assert_eq!(keys2.export_state(), blob);
    assert_eq!(keys2.len(), 32);
}

#[test]
fn result_api_single_path_parity() {
    // Via Result: save/load com as mesmas chaves NVS legadas.
    let mut st = test_storage();
    let mut keys = KeyManager::new();
    let oath = OathApplet::new();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    keys.generate(
        3,
        CoseAlgorithm::ES256,
        "parity".into(),
        KEY_USE_SIGN | KEY_USE_AUTH,
        0,
        true,
        &mut rng,
    )
    .expect("gen");
    save_keys_result(&mut st, &keys).expect("save keys");
    save_oath_result(&mut st, &oath).expect("save oath");
    let mut keys2 = KeyManager::new();
    let mut oath2 = OathApplet::new();
    load_states_result(&st, &mut keys2, &mut oath2).expect("load");
    assert_eq!(keys2.export_state(), keys.export_state());
    // Chaves NVS preservadas (prefixo vazio = chave crua).
    assert!(st.exists(NVS_KEYS_SLOTS));
    assert!(st.exists(NVS_KEYS_OATH));
    // PIN via Result: roundtrip + compativel com os shims bool.
    let pin = ClientPinState {
        pin_hash: Some([0xABu8; 16]),
        pin_retries: 5,
        ..Default::default()
    };
    save_pin_state_result(&mut st, &pin).expect("save pin");
    let mut pin2 = ClientPinState::default();
    load_pin_state_result(&st, &mut pin2).expect("load pin");
    assert_eq!(pin2.pin_hash, Some([0xABu8; 16]));
    assert_eq!(pin2.pin_retries, 5);
    assert!(save_pin_state(&mut st, &pin));
    assert!(load_pin_state(&st, &mut pin2));
}

#[test]
fn result_api_corrupt_denies_fail_closed() {
    // Torn write: adultera o envelope cru; load nega fail-closed.
    let mut st = test_storage();
    let mut keys = KeyManager::new();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    keys.generate(
        1,
        CoseAlgorithm::ES256,
        "torn".into(),
        KEY_USE_SIGN | KEY_USE_AUTH,
        0,
        true,
        &mut rng,
    )
    .expect("gen");
    save_keys_result(&mut st, &keys).expect("save");
    let mut raw = st.backend().read_raw(NVS_KEYS_SLOTS).expect("raw");
    let last = raw.len() - 1;
    raw[last] ^= 0xFF;
    st.backend_mut()
        .write_raw(NVS_KEYS_SLOTS, &raw)
        .expect("tamper");
    let mut keys2 = KeyManager::new();
    let mut oath2 = OathApplet::new();
    assert_eq!(
        load_states_result(&st, &mut keys2, &mut oath2),
        Err(VendorExecError::Storage)
    );
    // Shims bool mantem a semantica antiga (false = WARN do chamador).
    assert!(!load_states(
        &st,
        &mut KeyManager::new(),
        &mut OathApplet::new()
    ));
}
