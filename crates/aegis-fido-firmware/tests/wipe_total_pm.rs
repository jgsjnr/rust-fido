//! Wipe total cobre o vault PM (decisao do dono: wipe = chaves + senhas).
//!
//! Host-only (sem placa/push, sem eFuse/secure-boot/COMMIT): cada caminho de
//! wipe existente e executado contra NVS simulada e o estado posterior e
//! verificado via LIST:
//! - 0x3E (Secure Guard wipe seletivo/full confirmado): LIST 0x22 vazio E
//!   LIST 0x45 vazio, engine `Unprovisioned`, auditoria com `WipeCompleted`.
//! - 0x2B (`BIND_RELEASE` assinado): binding `Unclaimed` + blob PM ausente e
//!   LIST 0x45 vazio.
//! - wipe-em-5 (`wipe_on_5_failures`): apos 5 PINs errados, LIST 0x45 vazio.

use std::vec::Vec;

use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::oath::tlv::{write_tlv, TAG_LABEL, TAG_SLOT};
use aegis_fido_core::oath::OathApplet;
use aegis_fido_core::secure_guard::{
    SecureGuardEngine, SecureGuardPolicy, SecureGuardState, OP_SECURE_GUARD_LOCK,
    OP_SECURE_GUARD_UNLOCK, OP_SECURE_GUARD_WIPE_SELECTIVE,
};
use aegis_fido_core::wallet::WalletStore;
use aegis_fido_firmware::binding::{BindingManager, BIND_ID_LEN, BIND_OP_RELEASE, BIND_PUB_LEN};
use aegis_fido_firmware::ble::dispatch_bind::dispatch_bind_release;
use aegis_fido_firmware::ble_gatt::{OP_KEY_GEN_ONDEVICE, OP_KEY_LIST};
use aegis_fido_firmware::exec_secure_guard_op;
use aegis_fido_firmware::persistence::{PlatformFlashBackend, SecureStorage};
use aegis_fido_firmware::pm_dispatch::dispatch_pm_op_persist;
use aegis_fido_firmware::pm_store::{
    pm_blob_load, PmGateState, PmStoreError, OP_PM_LIST, OP_PM_PUT,
};
use aegis_fido_firmware::vendor_exec::exec_vendor_op;
use aegis_pm_vault::PmPolicy;
use aegis_secure_guard::SecureGuardAuditEventType;
use ciborium::value::Value;
use sha2::{Digest, Sha256};

fn test_storage() -> SecureStorage<PlatformFlashBackend> {
    SecureStorage::new(PlatformFlashBackend::new(), &[0x33; 32], &[0x77; 32])
}

fn to_cbor(val: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(val, &mut out).unwrap();
    out
}

fn from_cbor(bytes: &[u8]) -> Vec<(Value, Value)> {
    match ciborium::from_reader(bytes).unwrap() {
        Value::Map(m) => m,
        _ => panic!("expected CBOR map"),
    }
}

fn field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries.iter().find_map(|(k, v)| match k {
        Value::Text(s) if s == key => Some(v),
        _ => None,
    })
}

fn pm_gate() -> PmGateState {
    PmGateState::authorized()
}

fn pm_put_body() -> Vec<u8> {
    to_cbor(&Value::Map(Vec::from([
        (Value::Text("label".into()), Value::Text("bank".into())),
        (Value::Text("username".into()), Value::Text("alice".into())),
        (
            Value::Text("secret".into()),
            Value::Bytes(b"s3cr3t".to_vec()),
        ),
        (Value::Text("url".into()), Value::Null),
    ])))
}

fn pm_list_body() -> Vec<u8> {
    to_cbor(&Value::Map(Vec::from([
        (Value::Text("cursor".into()), Value::from(0u64)),
        (Value::Text("limit".into()), Value::from(32u64)),
    ])))
}

/// Executa PUT PM + GEN vendor 0x20; retorna para assercoes pos-wipe.
fn populate_keys_and_pm(
    storage: &mut SecureStorage<PlatformFlashBackend>,
    keys: &mut KeyManager,
    oath: &mut OathApplet,
) {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let policy = PmPolicy::default();
    // Uma senha no vault PM (blob selado `vault-pm/blob` passa a existir).
    let (st, _) = dispatch_pm_op_persist(
        OP_PM_PUT,
        &pm_put_body(),
        &pm_gate(),
        storage,
        &policy,
        1_770_000_000,
        &mut rng,
    );
    assert_eq!(st, 0x00, "PM PUT ok");
    // Uma chave vendor 0x20 (LIST 0x22 nao-vazio antes do wipe).
    let mut payload = Vec::new();
    write_tlv(&mut payload, TAG_SLOT, &[7]);
    write_tlv(&mut payload, TAG_LABEL, b"wipe-total");
    let (st, _) = exec_vendor_op(
        keys,
        oath,
        storage,
        OP_KEY_GEN_ONDEVICE,
        &payload,
        true,
        false,
        true,
        0,
        &mut rng,
    );
    assert_eq!(st, 0x00, "GEN 0x20 ok");
}

fn vendor_list_len(
    storage: &mut SecureStorage<PlatformFlashBackend>,
    keys: &mut KeyManager,
    oath: &mut OathApplet,
) -> Vec<u8> {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let (st, body) = exec_vendor_op(
        keys,
        oath,
        storage,
        OP_KEY_LIST,
        &[],
        true,
        false,
        true,
        0,
        &mut rng,
    );
    assert_eq!(st, 0x00, "LIST 0x22 deve responder 0x00");
    body
}

fn pm_list_ids(storage: &mut SecureStorage<PlatformFlashBackend>) -> Vec<Vec<u8>> {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let policy = PmPolicy::default();
    let (st, body) = dispatch_pm_op_persist(
        OP_PM_LIST,
        &pm_list_body(),
        &pm_gate(),
        storage,
        &policy,
        1_770_000_000,
        &mut rng,
    );
    assert_eq!(st, 0x00, "LIST 0x45 deve responder 0x00");
    let entries = from_cbor(&body);
    match field(&entries, "ids").expect("ids") {
        Value::Array(a) => a
            .iter()
            .map(|v| match v {
                Value::Bytes(b) => b.clone(),
                _ => panic!("id opaco em bytes"),
            })
            .collect(),
        _ => panic!("ids array"),
    }
}

fn provision_engine(
    engine: &mut SecureGuardEngine,
    storage: &mut SecureStorage<PlatformFlashBackend>,
    wallet: &mut WalletStore,
    keys: &mut KeyManager,
    oath: &mut OathApplet,
    wipe_on_5: bool,
    now_ms: u64,
) {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let mut prov = Vec::from([
        (
            Value::Text("action".into()),
            Value::Text("provision".into()),
        ),
        (Value::Text("pin".into()), Value::Bytes(b"4927".to_vec())),
    ]);
    if wipe_on_5 {
        prov.push((Value::Text("wipe_on_5_failures".into()), Value::Bool(true)));
    }
    let (st, _) = exec_secure_guard_op(
        engine,
        storage,
        wallet,
        keys,
        oath,
        OP_SECURE_GUARD_UNLOCK,
        &to_cbor(&Value::Map(prov)),
        now_ms,
        &mut rng,
    );
    assert_eq!(st, 0x00, "provision ok");
    assert!(engine.is_provisioned());
}

fn test_policy(wipe_on_5: bool) -> SecureGuardPolicy {
    SecureGuardPolicy {
        pbkdf2_iterations: 10,
        wipe_on_5_failures: wipe_on_5,
        ..Default::default()
    }
}

#[test]
fn wipe_0x3e_total_empties_key_list_and_pm_list_with_audit() {
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut keys = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut engine = SecureGuardEngine::new(test_policy(false));
    populate_keys_and_pm(&mut storage, &mut keys, &mut oath);
    provision_engine(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut keys,
        &mut oath,
        false,
        1000,
    );

    // Pre-condicao: chave + senha visiveis antes do wipe.
    assert!(!vendor_list_len(&mut storage, &mut keys, &mut oath).is_empty());
    assert_eq!(pm_list_ids(&mut storage).len(), 1);

    // Wipe full confirmado (0x3E).
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let wipe = to_cbor(&Value::Map(Vec::from([
        (Value::Text("confirm".into()), Value::Bool(true)),
        (
            Value::Text("confirmation".into()),
            Value::Text("WIPE-CONFIRMED".into()),
        ),
    ])));
    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut keys,
        &mut oath,
        OP_SECURE_GUARD_WIPE_SELECTIVE,
        &wipe,
        1100,
        &mut rng,
    );
    assert_eq!(st, 0x00, "wipe 0x3E ok");
    assert_eq!(engine.state(), SecureGuardState::Unprovisioned);
    assert!(!engine.is_provisioned());

    // Auditoria: o engine registra o wipe real (nao simulado).
    let last = engine.audit_log().last().expect("audit tem entradas");
    assert!(
        matches!(
            last.event_type,
            SecureGuardAuditEventType::WipeCompleted { simulated: false }
        ),
        "auditoria registra WipeCompleted real, got: {:?}",
        last.event_type
    );

    // Pos-condicao do wipe total: LIST 0x22 vazio E LIST 0x45 vazio.
    assert!(
        vendor_list_len(&mut storage, &mut keys, &mut oath).is_empty(),
        "LIST 0x22 vazio apos wipe total"
    );
    assert_eq!(pm_blob_load(&storage), Err(PmStoreError::NotFound));
    assert!(
        pm_list_ids(&mut storage).is_empty(),
        "LIST 0x45 vazio apos wipe total"
    );
}

#[test]
fn wipe_0x2b_release_clears_pm_blob_and_unclaims() {
    use p256::ecdsa::SigningKey;
    use signature::Signer;

    let mut storage = test_storage();
    let mut keys = KeyManager::new();
    let mut oath = OathApplet::new();
    populate_keys_and_pm(&mut storage, &mut keys, &mut oath);

    // Claim com chave fixa (padrao dos testes de binding).
    let sk = SigningKey::from_slice(&[0x11u8; 32]).expect("scalar valido");
    let pt = sk.verifying_key().to_sec1_point(false);
    let mut sec1 = [0u8; BIND_PUB_LEN];
    sec1.copy_from_slice(pt.as_bytes());
    let id = [0xABu8; BIND_ID_LEN];
    let mut binding = BindingManager::new();
    binding.claim(&sec1, &id, true, true).expect("claim ok");
    binding.persist(&mut storage).expect("persist ok");
    assert_eq!(pm_list_ids(&mut storage).len(), 1);

    // Release assinado 0x2B: challenge + sha256(binding_id) + assinatura P-256.
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let challenge = binding.new_challenge(&mut rng).expect("challenge");
    let id_hash = Sha256::digest(id);
    let mut ph = [0u8; 32];
    ph.copy_from_slice(&id_hash);
    let msg = BindingManager::signed_message(&challenge, BIND_OP_RELEASE, &ph);
    let sig: p256::ecdsa::Signature = sk.sign(&msg);
    let sig_der = sig.to_der().as_bytes().to_vec();
    dispatch_bind_release(&mut binding, &mut storage, &sig_der, &challenge, &ph, true)
        .expect("release 0x2B ok");

    // Wipe total via 0x2B: sem dono + blob PM ausente + LIST 0x45 vazio.
    assert!(!binding.is_claimed());
    assert_eq!(pm_blob_load(&storage), Err(PmStoreError::NotFound));
    assert!(
        pm_list_ids(&mut storage).is_empty(),
        "LIST 0x45 vazio apos release 0x2B"
    );
}

#[test]
fn wipe_em5_clears_pm_blob_after_five_bad_pins() {
    let mut storage = test_storage();
    let mut wallet = WalletStore::new();
    let mut keys = KeyManager::new();
    let mut oath = OathApplet::new();
    let mut engine = SecureGuardEngine::new(test_policy(true));
    populate_keys_and_pm(&mut storage, &mut keys, &mut oath);
    provision_engine(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut keys,
        &mut oath,
        true,
        1000,
    );
    assert_eq!(pm_list_ids(&mut storage).len(), 1);

    // 5 PINs errados com os backoffs da politica (mesma progressao do teste
    // de engine: 100 / 2500 / 5500 / 15500 ms entre tentativas).
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let bad = to_cbor(&Value::Map(Vec::from([
        (Value::Text("action".into()), Value::Text("unlock".into())),
        (Value::Text("pin".into()), Value::Bytes(b"0000".to_vec())),
    ])));
    // Trava via 0x3C (provision deixa Unlocked; sem lock o unlock nem
    // consulta o PIN - mesma sequencia dos testes de wipe do executor).
    let (st_lock, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut keys,
        &mut oath,
        OP_SECURE_GUARD_LOCK,
        &[],
        1100,
        &mut rng,
    );
    assert_eq!(st_lock, 0x00, "lock 0x3C ok");
    assert_eq!(engine.state(), SecureGuardState::Locked);

    let mut time = 2000u64;
    for backoff in [100u64, 2500, 5500, 15500] {
        let (_, _) = exec_secure_guard_op(
            &mut engine,
            &mut storage,
            &mut wallet,
            &mut keys,
            &mut oath,
            OP_SECURE_GUARD_UNLOCK,
            &bad,
            time,
            &mut rng,
        );
        time += backoff;
    }

    let (st, _) = exec_secure_guard_op(
        &mut engine,
        &mut storage,
        &mut wallet,
        &mut keys,
        &mut oath,
        OP_SECURE_GUARD_UNLOCK,
        &bad,
        time,
        &mut rng,
    );
    assert_eq!(st, 0x36, "5a falha nega com PIN_REQUIRED");
    assert_eq!(engine.state(), SecureGuardState::Unprovisioned);
    assert!(!engine.is_provisioned());

    // Wipe-em-5 total: LIST 0x45 vazio.
    assert_eq!(pm_blob_load(&storage), Err(PmStoreError::NotFound));
    assert!(
        pm_list_ids(&mut storage).is_empty(),
        "LIST 0x45 vazio apos wipe-em-5"
    );
}
