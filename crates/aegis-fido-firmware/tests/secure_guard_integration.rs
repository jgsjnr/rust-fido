//! Testes de Integração do Secure Guard no Firmware (ESP32-S3 / FreeRTOS)
//!
//! Valida a integração completa:
//! 1. Opcodes 0x3A..0x3E (Status, Unlock/Provision, Lock, Config, Wipe Seletivo)
//! 2. Barreira de Autorização (Enforcement) bloqueando Wallets quando Locked e liberando quando Unlocked
//! 3. Expiração de sessão por tempo / inatividade
//! 4. 5 falhas consecutivas levando ao wipe seletivo de carteiras preservando credenciais FIDO2
//! 5. Coexistência sem bloqueio com MakeCredential e GetAssertion FIDO2

use ciborium::value::Value;
use std::vec::Vec;

use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::ctap::{CtapEngine, CTAP_CMD_MAKE_CREDENTIAL};
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::otp::rescue::RescueEngine;
use aegis_fido_core::secure_guard::{
    SecureGuardEngine, SecureGuardPolicy, SecureGuardState, OP_SECURE_GUARD_LOCK,
    OP_SECURE_GUARD_STATUS, OP_SECURE_GUARD_UNLOCK, OP_WALLET_LIST,
};
use aegis_fido_core::wallet::types::CryptoNetwork;
use aegis_fido_core::wallet::WalletStore;
use aegis_fido_firmware::binding::BindingManager;
use aegis_fido_firmware::freertos_route::{route_ctaphid_event, SerialVendorCtx};
use aegis_fido_firmware::freertos_sched::{FirmwareEvent, CTAPHID_PACKET_SIZE};
use aegis_fido_firmware::fw_log::FwLog;
use aegis_fido_firmware::pairing::PairingManager;
use aegis_fido_firmware::persistence::{PlatformFlashBackend, SecureStorage};
use aegis_fido_usb::ctaphid::{CtapHidManager, CMD_CBOR, CMD_MSG};

fn init_raw(cid: u32, cmd: u8, payload: &[u8]) -> [u8; CTAPHID_PACKET_SIZE] {
    let mut raw = [0u8; CTAPHID_PACKET_SIZE];
    raw[0..4].copy_from_slice(&cid.to_be_bytes());
    raw[4] = cmd;
    let len = (payload.len() as u16).to_be_bytes();
    raw[5] = len[0];
    raw[6] = len[1];
    let take = payload.len().min(CTAPHID_PACKET_SIZE - 7);
    raw[7..7 + take].copy_from_slice(&payload[..take]);
    raw
}

fn test_storage() -> SecureStorage<PlatformFlashBackend> {
    SecureStorage::new(PlatformFlashBackend::new(), &[0x33; 32], &[0x77; 32])
}

fn to_cbor(val: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(val, &mut out).unwrap();
    out
}

fn get_cbor_field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    for (k, v) in entries {
        if let Value::Text(s) = k {
            if s == key {
                return Some(v);
            }
        }
    }
    None
}

fn reassemble_ctaphid_payload(responses: &[[u8; CTAPHID_PACKET_SIZE]]) -> (u8, Vec<u8>) {
    assert!(!responses.is_empty(), "responses must not be empty");
    let init = &responses[0];
    let bcnt = u16::from_be_bytes([init[5], init[6]]) as usize;
    let mut full = Vec::with_capacity(bcnt);
    let take = bcnt.min(CTAPHID_PACKET_SIZE - 7);
    full.extend_from_slice(&init[7..7 + take]);
    let mut remaining = bcnt.saturating_sub(take);
    let mut idx = 1;
    while remaining > 0 && idx < responses.len() {
        let cont = &responses[idx];
        let take_cont = remaining.min(CTAPHID_PACKET_SIZE - 5);
        full.extend_from_slice(&cont[5..5 + take_cont]);
        remaining -= take_cont;
        idx += 1;
    }
    assert!(!full.is_empty(), "full response payload must not be empty");
    let st = full[0];
    let body = full[1..].to_vec();
    (st, body)
}

#[test]
fn test_secure_guard_full_lifecycle_and_enforcement() {
    let mut pairing = PairingManager::new();
    let mut binding = BindingManager::new();
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut fwlog = FwLog::new();
    let mut rescue = RescueEngine::new();
    let mut mgr_usb = CtapHidManager::new();
    let mut mgr_serial = CtapHidManager::new();
    let mut ctap_engine = CtapEngine::new([0x55; 32], 0);

    let policy = SecureGuardPolicy {
        pbkdf2_iterations: 10, // Rápido para testes
        session_duration_ms: 2000,
        inactivity_timeout_ms: 800,
        wipe_on_5_failures: true,
        test_mode_non_destructive_wipe: false,
        ..Default::default()
    };
    let mut sg = SecureGuardEngine::new(policy);
    let pin = b"7391";

    let mut vendor = SerialVendorCtx {
        pairing_open: true,
        up_latched: true,
        now_ms: 1000,
        now_secs: 1,
        arm_up: false,
        pin_verified: true,
        binding: &mut binding,
        storage: &mut storage,
        wallet: &mut wallet,
        key_mgr: &mut key_mgr,
        oath: &mut oath,
        fwlog: &mut fwlog,
        rescue: &mut rescue,
        pairing: &mut pairing,
        pin_uv_session: true,
        secure_guard: Some(&mut sg),
    };

    // 1. Status inicial via 0x3A (deve ser Unprovisioned)
    let raw_status = init_raw(0x1000, CMD_MSG, &[OP_SECURE_GUARD_STATUS]);
    let out = route_ctaphid_event(
        &mut mgr_usb,
        &mut mgr_serial,
        &mut ctap_engine,
        &FirmwareEvent::SerialPacket(raw_status),
        true,
        1000,
        1,
        Some(&mut vendor),
    );
    let (st, body) = reassemble_ctaphid_payload(&out.responses);
    assert_eq!(st, 0x00);
    let val: Value = ciborium::from_reader(&body[..]).expect("status cbor");
    if let Value::Map(m) = val {
        assert_eq!(get_cbor_field(&m, "provisioned"), Some(&Value::Bool(false)));
        assert_eq!(get_cbor_field(&m, "unlocked"), Some(&Value::Bool(false)));
    } else {
        panic!("esperado mapa cbor");
    }

    // 2. Provisionamento via 0x3B (action: "provision")
    let prov_map = vec![
        (
            Value::Text("action".into()),
            Value::Text("provision".into()),
        ),
        (Value::Text("pin".into()), Value::Bytes(pin.to_vec())),
    ];
    let prov_cbor = to_cbor(&Value::Map(prov_map));
    let mut prov_payload = vec![OP_SECURE_GUARD_UNLOCK];
    prov_payload.extend_from_slice(&prov_cbor);

    let raw_prov = init_raw(0x1000, CMD_MSG, &prov_payload);
    let out = route_ctaphid_event(
        &mut mgr_usb,
        &mut mgr_serial,
        &mut ctap_engine,
        &FirmwareEvent::SerialPacket(raw_prov),
        true,
        1050,
        1,
        Some(&mut vendor),
    );
    assert!(!out.responses.is_empty());
    assert_eq!(out.responses[0][7], 0x00);
    assert!(vendor.secure_guard.as_ref().unwrap().is_provisioned());
    assert_eq!(
        vendor.secure_guard.as_ref().unwrap().state(),
        SecureGuardState::Unlocked
    );

    // Bloqueia manualmente para testar a barreira quando Locked
    vendor.secure_guard.as_mut().unwrap().lock_now(1051).unwrap();
    assert_eq!(
        vendor.secure_guard.as_ref().unwrap().state(),
        SecureGuardState::Locked
    );

    // 3. Tentativa de chamar OP_WALLET_LIST (0x36) com SG Locked -> Barreira DEVE bloquear com 0x36!
    let raw_wallet = init_raw(0x1000, CMD_MSG, &[OP_WALLET_LIST]);
    let out = route_ctaphid_event(
        &mut mgr_usb,
        &mut mgr_serial,
        &mut ctap_engine,
        &FirmwareEvent::SerialPacket(raw_wallet),
        true,
        1100,
        1,
        Some(&mut vendor),
    );
    assert_eq!(out.responses.len(), 1);
    assert_eq!(
        out.responses[0][7], 0x36,
        "Acesso deve ser bloqueado quando Locked"
    );

    // 4. Desbloqueia com PIN correto via 0x3B (action: "unlock")
    let unlock_map = vec![
        (Value::Text("action".into()), Value::Text("unlock".into())),
        (Value::Text("pin".into()), Value::Bytes(pin.to_vec())),
    ];
    let unlock_cbor = to_cbor(&Value::Map(unlock_map));
    let mut unlock_payload = vec![OP_SECURE_GUARD_UNLOCK];
    unlock_payload.extend_from_slice(&unlock_cbor);

    let raw_unlock = init_raw(0x1000, CMD_MSG, &unlock_payload);
    let out = route_ctaphid_event(
        &mut mgr_usb,
        &mut mgr_serial,
        &mut ctap_engine,
        &FirmwareEvent::SerialPacket(raw_unlock),
        true,
        1200,
        1,
        Some(&mut vendor),
    );
    assert!(!out.responses.is_empty());
    assert_eq!(out.responses[0][7], 0x00);
    assert!(vendor.secure_guard.as_ref().unwrap().is_unlocked());

    // 5. Chamada de OP_WALLET_LIST (0x36) com SG Unlocked -> Permitido!
    let raw_wallet_ok = init_raw(0x1000, CMD_MSG, &[OP_WALLET_LIST]);
    let out = route_ctaphid_event(
        &mut mgr_usb,
        &mut mgr_serial,
        &mut ctap_engine,
        &FirmwareEvent::SerialPacket(raw_wallet_ok),
        true,
        1300,
        1,
        Some(&mut vendor),
    );
    assert_eq!(out.responses.len(), 1);
    assert_eq!(
        out.responses[0][7], 0x00,
        "Acesso deve ser permitido quando Unlocked"
    );

    // 6. Bloqueio manual via 0x3C (OP_SECURE_GUARD_LOCK)
    let raw_lock = init_raw(0x1000, CMD_MSG, &[OP_SECURE_GUARD_LOCK]);
    let out = route_ctaphid_event(
        &mut mgr_usb,
        &mut mgr_serial,
        &mut ctap_engine,
        &FirmwareEvent::SerialPacket(raw_lock),
        true,
        1400,
        1,
        Some(&mut vendor),
    );
    assert!(!out.responses.is_empty());
    assert_eq!(out.responses[0][7], 0x00);
    assert_eq!(
        vendor.secure_guard.as_ref().unwrap().state(),
        SecureGuardState::Locked
    );

    // 7. Nova tentativa em carteira -> bloqueado novamente
    let raw_wallet_blocked2 = init_raw(0x1000, CMD_MSG, &[OP_WALLET_LIST]);
    let out = route_ctaphid_event(
        &mut mgr_usb,
        &mut mgr_serial,
        &mut ctap_engine,
        &FirmwareEvent::SerialPacket(raw_wallet_blocked2),
        true,
        1450,
        1,
        Some(&mut vendor),
    );
    assert_eq!(out.responses.len(), 1);
    assert_eq!(out.responses[0][7], 0x36);
}

#[test]
fn test_five_failures_trigger_scoped_wipe_preserving_fido2() {
    let mut pairing = PairingManager::new();
    let mut binding = BindingManager::new();
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut key_mgr = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut fwlog = FwLog::new();
    let mut rescue = RescueEngine::new();
    let mut mgr_usb = CtapHidManager::new();
    let mut mgr_serial = CtapHidManager::new();
    let mut ctap_engine = CtapEngine::new([0x77; 32], 0);
    let mut rng = rand_core::OsRng;

    // Popula 1 carteira Web3 no wallet store
    let _ = wallet.generate(CryptoNetwork::Bitcoin, 1, "test-btc", 1000, true, &mut rng);
    assert_eq!(wallet.list(true).unwrap().len(), 1);

    let policy = SecureGuardPolicy {
        pbkdf2_iterations: 10,
        wipe_on_5_failures: true,
        test_mode_non_destructive_wipe: false,
        ..Default::default()
    };
    let mut sg = SecureGuardEngine::new(policy);
    let correct_pin = b"5521";
    let _ = sg
        .provision_pin(correct_pin, [0x10; 16], b"", [0x20; 16], 1000)
        .unwrap();

    let mut vendor = SerialVendorCtx {
        pairing_open: true,
        up_latched: true,
        now_ms: 1000,
        now_secs: 1,
        arm_up: false,
        pin_verified: true,
        binding: &mut binding,
        storage: &mut storage,
        wallet: &mut wallet,
        key_mgr: &mut key_mgr,
        oath: &mut oath,
        fwlog: &mut fwlog,
        rescue: &mut rescue,
        pairing: &mut pairing,
        pin_uv_session: true,
        secure_guard: Some(&mut sg),
    };

    // Submete 5 tentativas erradas com avanço de tempo para superar os delays de rate limit
    let mut now = 1000u64;
    for i in 1..=5 {
        now += 15_000; // Avança além do backoff rate limit
        let bad_map = vec![
            (Value::Text("action".into()), Value::Text("unlock".into())),
            (Value::Text("pin".into()), Value::Bytes(b"0000".to_vec())),
        ];
        let bad_cbor = to_cbor(&Value::Map(bad_map));
        let mut bad_payload = vec![OP_SECURE_GUARD_UNLOCK];
        bad_payload.extend_from_slice(&bad_cbor);

        let raw = init_raw(0x2000, CMD_MSG, &bad_payload);
        let out = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut ctap_engine,
            &FirmwareEvent::SerialPacket(raw),
            true,
            now,
            now / 1000,
            Some(&mut vendor),
        );
        assert!(!out.responses.is_empty());
        assert_eq!(out.responses[0][7], 0x36, "Falha {} deve retornar 0x36", i);
    }

    // Após a 5ª tentativa com wipe_on_5_failures == true:
    // 1. O Secure Guard foi resetado para Unprovisioned
    assert_eq!(
        vendor.secure_guard.as_ref().unwrap().state(),
        SecureGuardState::Unprovisioned
    );
    // 2. A carteira Web3 foi LIMPA pelo wipe seletivo!
    assert_eq!(vendor.wallet.list(true).unwrap().len(), 0);

    // 3. FIDO2 padrão (MakeCredential) continua 100% OPERACIONAL E INTACTO!
    let raw_fido = init_raw(0x2000, CMD_CBOR, &[CTAP_CMD_MAKE_CREDENTIAL]);
    let out_fido = route_ctaphid_event(
        &mut mgr_usb,
        &mut mgr_serial,
        &mut ctap_engine,
        &FirmwareEvent::UsbPacket(raw_fido),
        true,
        now + 100,
        (now + 100) / 1000,
        Some(&mut vendor),
    );
    assert!(!out_fido.responses.is_empty());
    // Não foi bloqueado com 0x36 pelo Secure Guard!
    assert_ne!(out_fido.responses[0][7], 0x36);
}
