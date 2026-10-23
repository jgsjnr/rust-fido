//! T9 — applets OATH/PIV + wallet isolado (offline, vetores congelados).
//!
//! Cobre o que T9 finalizou: OATH end-to-end (PUT/LIST/CODE/DELETE via
//! `exec_vendor_op` + `OathApplet` + `totp_view`), wallet isolado em
//! `KeyManager` dedicado (duas `WalletStore` não se enxergam; o `KeyManager`
//! FIDO alheio fica intacto), PIV nos slots reservados 24-27 (9A/9C/9D/9E,
//! colisão falha sem sobrescrever, RSA = `BadAlg`), `6D 00` honesto p/
//! OATH/FIDO sobre CCID (fora do escopo v1, sem mock) e "segredo nunca sai"
//! (LIST/CODE/log/tela só carregam metadados e código).
//!
//! Host-only: `MockFlashBackend` + vetores RFC (sem hardware, sem flash,
//! sem COM, sem rede). Rollback: deletar este arquivo.

extern crate alloc;

use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::credential::{KEY_USE_AUTH, KEY_USE_SIGN};
use aegis_fido_core::crypto::cose::CoseKey;
use aegis_fido_core::crypto::curves::{CoseAlgorithm, PublicKey};
use aegis_fido_core::oath::tlv::{TAG_OATH_NAME, TAG_OATH_RESPONSE};
use aegis_fido_core::oath::{
    find_tlv, parse_tlv_records, write_tlv, OathAlgorithm, OathApplet, OathDeviceError, OathType,
    OATH_TLV_MAX_BYTES, TAG_CHALLENGE, TAG_KEY, TAG_NAME,
};
use aegis_fido_core::wallet::{CryptoNetwork, WalletError, WalletStore, WALLET_LABEL_PREFIX};
use aegis_fido_firmware::ble_gatt::{
    OP_OATH_CODE, OP_OATH_DELETE, OP_OATH_LIST, OP_OATH_PUT, OP_PIV_ENROLL,
};
use aegis_fido_firmware::ccid_dispatch::process_ccid_frame;
use aegis_fido_firmware::persistence::{MockFlashBackend, SecureStorage};
use aegis_fido_firmware::piv_store::{PivFwBackend, PivNvsStore, PIV_SLOT_BASE};
use aegis_fido_firmware::totp_view::{
    collect_totp_codes, sanitized_code_log, totp_challenge_for_unix_secs,
};
use aegis_fido_firmware::vendor_exec::{exec_vendor_op, load_states};
use aegis_fido_firmware::wallet_exec::{
    wallet_addr, wallet_gen, wallet_list, TAG_WALLET_ADDRESS, TAG_WALLET_LABEL, TAG_WALLET_NETWORK,
    TAG_WALLET_SLOT,
};
use aegis_fido_usb::ccid::CcidTransport;
use aegis_fido_usb::piv::{PivCryptoError, PivKeyBackend, PivRecordStore, PivSlot};

// Vetores congelados (offline, determinísticos).
const SECRET_SHA1_20: &[u8] = b"12345678901234567890";
const SECRET_SHA256_32: &[u8] = b"12345678901234567890123456789012";
// RFC 4226 S5.4 / RFC 6238 T=1 (unix 59s): counter 0 -> 755224, counter 1 -> 287082.
const HOTP_COUNTER_0_CODE: &str = "755224";
const RFC_COUNTER_1_CODE: &str = "287082";
// RFC 6238 SHA-256, T=1, 8 dígitos.
const RFC_SHA256_8D_CODE: &str = "46119246";
const UNIX_T1: u64 = 59;

fn storage() -> SecureStorage<MockFlashBackend> {
    SecureStorage::new(MockFlashBackend::new(), &[0x11u8; 32], &[0x22u8; 32])
}

fn totp_put_tlv(label: &str, secret: &[u8], algo: OathAlgorithm, digits: u8) -> Vec<u8> {
    let type_algo = match algo {
        OathAlgorithm::Sha1 => 0x01,
        OathAlgorithm::Sha256 => 0x02,
        OathAlgorithm::Sha512 => 0x03,
    } | 0x20; // TOTP
    let mut key_val = alloc::vec::Vec::from([type_algo, digits]);
    key_val.extend_from_slice(secret);
    let mut tlv = Vec::new();
    write_tlv(&mut tlv, TAG_NAME, label.as_bytes());
    write_tlv(&mut tlv, TAG_KEY, &key_val);
    tlv
}

fn hotp_put_tlv(label: &str, secret: &[u8], digits: u8) -> Vec<u8> {
    let mut key_val = alloc::vec::Vec::from([0x11u8, digits]); // HOTP/SHA-1
    key_val.extend_from_slice(secret);
    let mut tlv = Vec::new();
    write_tlv(&mut tlv, TAG_NAME, label.as_bytes());
    write_tlv(&mut tlv, TAG_KEY, &key_val);
    tlv
}

fn name_tlv(label: &str) -> Vec<u8> {
    let mut tlv = Vec::new();
    write_tlv(&mut tlv, TAG_NAME, label.as_bytes());
    tlv
}

fn code_req_tlv(label: &str, challenge: &[u8; 8]) -> Vec<u8> {
    let mut tlv = Vec::new();
    write_tlv(&mut tlv, TAG_NAME, label.as_bytes());
    write_tlv(&mut tlv, TAG_CHALLENGE, challenge);
    tlv
}

#[allow(clippy::too_many_arguments)]
fn exec(
    keys: &mut KeyManager,
    oath: &mut OathApplet,
    st: &mut SecureStorage<MockFlashBackend>,
    op: u8,
    payload: &[u8],
    binding_ok: bool,
    pin_ok: bool,
    up: bool,
) -> (u8, Vec<u8>) {
    exec_vendor_op(
        keys,
        oath,
        st,
        op,
        payload,
        binding_ok,
        pin_ok,
        up,
        0,
        &mut rand_core::OsRng,
    )
}

fn enroll_piv(st: &mut SecureStorage<MockFlashBackend>) {
    let mut req = alloc::vec::Vec::from([6u8]);
    req.extend_from_slice(b"123456");
    req.extend_from_slice(b"12345678");
    let mut keys = KeyManager::new();
    let mut oath = OathApplet::new();
    let (status, _) = exec(
        &mut keys,
        &mut oath,
        st,
        OP_PIV_ENROLL,
        &req,
        true,
        false,
        true,
    );
    assert_eq!(status, 0x00, "enroll PIV de apoio");
}

// ---------------------------------------------------------------------------
// OATH end-to-end (vetores RFC congelados)
// ---------------------------------------------------------------------------

#[test]
fn oath_totp_e2e_rfc6238_sha1_put_list_code_delete() {
    let mut applet = OathApplet::new();
    applet
        .device_put(
            &totp_put_tlv("TestService:alice", SECRET_SHA1_20, OathAlgorithm::Sha1, 6),
            true,
            true,
        )
        .expect("put totp");
    let slots = applet.device_list(false, true).expect("list");
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].label, "TestService:alice");
    assert_eq!(slots[0].tipo, OathType::Totp);
    // unix 59s -> T=1 -> HOTP counter 1 -> 287082.
    let res = applet
        .device_code(
            &code_req_tlv("TestService:alice", &1u64.to_be_bytes()),
            false,
            true,
        )
        .expect("code");
    assert_eq!(res.code, RFC_COUNTER_1_CODE);
    assert_eq!(res.digits, 6);
    applet
        .device_delete(&name_tlv("TestService:alice"), true, true)
        .expect("delete");
    assert!(applet.device_list(false, true).expect("list").is_empty());
    assert_eq!(
        applet.device_code(
            &code_req_tlv("TestService:alice", &1u64.to_be_bytes()),
            false,
            true
        ),
        Err(OathDeviceError::NoSlot)
    );
}

#[test]
fn oath_hotp_e2e_counter_avanca_a_cada_code() {
    let mut applet = OathApplet::new();
    applet
        .device_put(&hotp_put_tlv("Hotp:alice", SECRET_SHA1_20, 6), true, true)
        .expect("put hotp");
    let first = applet
        .device_code(&name_tlv("Hotp:alice"), false, true)
        .expect("code 1");
    assert_eq!(first.code, HOTP_COUNTER_0_CODE);
    let second = applet
        .device_code(&name_tlv("Hotp:alice"), false, true)
        .expect("code 2");
    assert_eq!(second.code, RFC_COUNTER_1_CODE);
}

#[test]
fn oath_sha256_8_digitos_rfc6238() {
    let mut applet = OathApplet::new();
    applet
        .device_put(
            &totp_put_tlv("SHA256:alice", SECRET_SHA256_32, OathAlgorithm::Sha256, 8),
            true,
            true,
        )
        .expect("put sha256");
    let res = applet
        .device_code(
            &code_req_tlv("SHA256:alice", &1u64.to_be_bytes()),
            false,
            true,
        )
        .expect("code");
    assert_eq!(res.code, RFC_SHA256_8D_CODE);
    // Mesmo vetor via `totp_view` (tela real do device, sem segredo).
    let entries = collect_totp_codes(&mut applet, UNIX_T1, true);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].code, RFC_SHA256_8D_CODE);
    assert_eq!(entries[0].account, "SHA256:alice");
}

#[test]
fn oath_vendor_exec_fim_a_fim_com_gates_e_persistencia() {
    let mut st = storage();
    let mut keys = KeyManager::new();
    let mut oath = OathApplet::new();
    // PUT exige binding + UP + PIN (release); USO (LIST/CODE) só UP.
    let put = totp_put_tlv("GitHub:alice", SECRET_SHA1_20, OathAlgorithm::Sha1, 6);
    assert_eq!(
        exec(
            &mut keys,
            &mut oath,
            &mut st,
            OP_OATH_PUT,
            &put,
            true,
            true,
            false
        )
        .0,
        0x01
    );
    assert_eq!(
        exec(
            &mut keys,
            &mut oath,
            &mut st,
            OP_OATH_PUT,
            &put,
            true,
            false,
            true
        )
        .0,
        0x02
    );
    assert_eq!(
        exec(
            &mut keys,
            &mut oath,
            &mut st,
            OP_OATH_PUT,
            &put,
            true,
            true,
            true
        )
        .0,
        0x00
    );
    // LIST responde só metadados (0x71), sem vínculo, com UP.
    let (status, body) = exec(
        &mut keys,
        &mut oath,
        &mut st,
        OP_OATH_LIST,
        &[],
        false,
        false,
        true,
    );
    assert_eq!(status, 0x00);
    let recs = parse_tlv_records(&body).expect("list tlv");
    let name_val = find_tlv(&recs, TAG_OATH_NAME).expect("nome listado");
    assert!(name_val
        .windows(b"GitHub:alice".len())
        .any(|w| w == b"GitHub:alice"));
    assert!(!body
        .windows(SECRET_SHA1_20.len())
        .any(|w| w == SECRET_SHA1_20));
    // CODE responde só o código (0x75), sem vínculo, com UP.
    let (status, body) = exec(
        &mut keys,
        &mut oath,
        &mut st,
        OP_OATH_CODE,
        &code_req_tlv("GitHub:alice", &1u64.to_be_bytes()),
        false,
        false,
        true,
    );
    assert_eq!(status, 0x00);
    let recs = parse_tlv_records(&body).expect("code tlv");
    assert_eq!(
        find_tlv(&recs, TAG_OATH_RESPONSE),
        Some(RFC_COUNTER_1_CODE.as_bytes())
    );
    assert!(!body
        .windows(SECRET_SHA1_20.len())
        .any(|w| w == SECRET_SHA1_20));
    // Slot desconhecido vira NO_SLOT (0x03), terminar vira DELETE ok.
    assert_eq!(
        exec(
            &mut keys,
            &mut oath,
            &mut st,
            OP_OATH_CODE,
            &code_req_tlv("nope", &1u64.to_be_bytes()),
            false,
            false,
            true
        )
        .0,
        0x03
    );
    assert_eq!(
        exec(
            &mut keys,
            &mut oath,
            &mut st,
            OP_OATH_DELETE,
            &name_tlv("GitHub:alice"),
            true,
            true,
            true
        )
        .0,
        0x00
    );
    // Persistiu no NVS (PUT salvou): recarrega num applet zerado.
    let mut keys2 = KeyManager::new();
    let mut oath2 = OathApplet::new();
    assert!(load_states(&st, &mut keys2, &mut oath2));
    assert!(oath2.device_list(false, true).expect("list").is_empty());
}

#[test]
fn oath_gates_e_erro_fechado_01_a_04() {
    assert_eq!(OathDeviceError::NeedUp.code(), 0x01);
    assert_eq!(OathDeviceError::NeedPin.code(), 0x02);
    assert_eq!(OathDeviceError::NoSlot.code(), 0x03);
    assert_eq!(OathDeviceError::BadEnvelope.code(), 0x04);
    let mut applet = OathApplet::new();
    let put = totp_put_tlv("A:a", SECRET_SHA1_20, OathAlgorithm::Sha1, 6);
    assert_eq!(
        applet.device_put(&put, true, false),
        Err(OathDeviceError::NeedUp)
    );
    assert_eq!(
        applet.device_put(&put, false, true),
        Err(OathDeviceError::NeedPin)
    );
    assert_eq!(
        applet.device_list(false, false),
        Err(OathDeviceError::NeedUp)
    );
    assert_eq!(
        applet.device_code(&name_tlv("A:a"), false, false),
        Err(OathDeviceError::NeedUp)
    );
    assert_eq!(
        applet.device_delete(&name_tlv("A:a"), false, true),
        Err(OathDeviceError::NeedPin)
    );
    // Presets: dígitos 6-8; TLV total <=512B; label 1..32B.
    assert!(applet
        .device_put(
            &totp_put_tlv("A:a", SECRET_SHA1_20, OathAlgorithm::Sha1, 5),
            true,
            true
        )
        .is_err());
    let oversized = alloc::vec![0x41u8; OATH_TLV_MAX_BYTES + 1];
    assert_eq!(
        applet.device_put(&oversized, true, true),
        Err(OathDeviceError::BadEnvelope)
    );
    let long = "x".repeat(33);
    assert_eq!(
        applet.device_put(
            &totp_put_tlv(&long, SECRET_SHA1_20, OathAlgorithm::Sha1, 6),
            true,
            true
        ),
        Err(OathDeviceError::BadEnvelope)
    );
}

// ---------------------------------------------------------------------------
// Segredo nunca sai do device
// ---------------------------------------------------------------------------

#[test]
fn oath_segredo_nunca_sai_list_code_log_tela() {
    let mut applet = OathApplet::new();
    applet
        .device_put(
            &totp_put_tlv("GitHub:alice", SECRET_SHA1_20, OathAlgorithm::Sha1, 6),
            true,
            true,
        )
        .expect("put");
    // LIST: só tipo+label; CODE: só código.
    let slots = applet.device_list(false, true).expect("list");
    let listed = format!("{:?}", slots);
    assert!(listed.contains("GitHub:alice"));
    assert!(!listed
        .as_bytes()
        .windows(SECRET_SHA1_20.len())
        .any(|w| w == SECRET_SHA1_20));
    let res = applet
        .device_code(
            &code_req_tlv("GitHub:alice", &1u64.to_be_bytes()),
            false,
            true,
        )
        .expect("code");
    assert_eq!(res.code, RFC_COUNTER_1_CODE);
    assert_ne!(res.code.as_bytes(), SECRET_SHA1_20);
    // Tela/log: linha sanitizada carrega conta + código, nunca o segredo.
    let entries = collect_totp_codes(&mut applet, UNIX_T1, true);
    assert_eq!(entries.len(), 1);
    let line = sanitized_code_log(
        &entries[0].account,
        &entries[0].code,
        entries[0].remaining_seconds,
    );
    assert!(line.contains(RFC_COUNTER_1_CODE));
    assert!(!line
        .as_bytes()
        .windows(SECRET_SHA1_20.len())
        .any(|w| w == SECRET_SHA1_20));
    // Challenge deriva de T = t/30 (janela TOTP congelada).
    assert_eq!(totp_challenge_for_unix_secs(UNIX_T1), 1u64.to_be_bytes());
    // Sem UP a tela recebe vazio (nunca código falso).
    assert!(collect_totp_codes(&mut applet, UNIX_T1, false).is_empty());
}

// ---------------------------------------------------------------------------
// Wallet isolado: KeyManager dedicado por WalletStore
// ---------------------------------------------------------------------------

#[test]
fn wallet_keymanager_dedicado_isola_stores_e_fido_alheio() {
    let mut rng = rand_core::OsRng;
    let mut a = WalletStore::new();
    let b = WalletStore::new();
    let rec = a
        .generate(CryptoNetwork::Bitcoin, 3, "btc", 1, true, &mut rng)
        .expect("gen btc");
    assert_eq!(rec.slot_id, 3);
    assert!(rec.label.starts_with(WALLET_LABEL_PREFIX));
    assert!(
        rec.address.starts_with("bc1q"),
        "endereço bech32: {}",
        rec.address
    );
    // B não enxerga nada de A (isolamento por instância dedicada).
    assert!(b.list(true).expect("list b").is_empty());
    assert_eq!(b.address(3, true), Err(WalletError::NoSlot));
    assert_eq!(b.get(3, true), Err(WalletError::NoSlot));
    // O KeyManager FIDO alheio segue intacto (wallet nunca escreve nele).
    let foreign = KeyManager::new();
    assert_eq!(foreign.len(), 0);
    // A lista só metadados (label com prefixo wallet:, endereço, sem bytes privados).
    let listed = a.list(true).expect("list a");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].address, rec.address);
}

#[test]
fn wallet_exec_sessao_sem_segredo_no_fio() {
    let mut rng = rand_core::OsRng;
    let mut store = WalletStore::new();
    let mut payload = Vec::new();
    write_tlv(&mut payload, TAG_WALLET_SLOT, &[3]);
    write_tlv(&mut payload, TAG_WALLET_LABEL, b"btc");
    write_tlv(
        &mut payload,
        TAG_WALLET_NETWORK,
        &[CryptoNetwork::Bitcoin.as_u8()],
    );
    // Sem UP nega com NEED_UP (0x01).
    assert_eq!(wallet_gen(&mut store, &payload, 1, false, &mut rng).0, 0x01);
    let (status, body) = wallet_gen(&mut store, &payload, 1, true, &mut rng);
    assert_eq!(status, 0x00);
    let recs = parse_tlv_records(&body).expect("gen tlv");
    let addr = find_tlv(&recs, TAG_WALLET_ADDRESS).expect("endereço na resposta");
    assert!(addr.starts_with(b"bc1q"));
    // LIST traz o registro; ADDR confere o mesmo endereço; nada além de metadados.
    let (status, list) = wallet_list(&store, true);
    assert_eq!(status, 0x00);
    assert!(list.windows(addr.len()).any(|w| w == addr));
    let mut slot_req = Vec::new();
    write_tlv(&mut slot_req, TAG_WALLET_SLOT, &[3]);
    let (status, abody) = wallet_addr(&store, &slot_req, true);
    assert_eq!(status, 0x00);
    let arecs = parse_tlv_records(&abody).expect("addr tlv");
    assert_eq!(find_tlv(&arecs, TAG_WALLET_ADDRESS), Some(addr));
    // Rede desconhecida / envelope quebrado falham fechado (0x04).
    let mut bad = Vec::new();
    write_tlv(&mut bad, TAG_WALLET_SLOT, &[0]);
    write_tlv(&mut bad, TAG_WALLET_LABEL, b"x");
    write_tlv(&mut bad, TAG_WALLET_NETWORK, &[0x09]);
    assert_eq!(wallet_gen(&mut store, &bad, 1, true, &mut rng).0, 0x04);
    assert_eq!(wallet_gen(&mut store, b"\x01", 1, true, &mut rng).0, 0x04);
    assert_eq!(wallet_list(&store, false).0, 0x01);
}

// ---------------------------------------------------------------------------
// PIV nos slots reservados 24-27
// ---------------------------------------------------------------------------

fn raw_to_der(raw: &[u8]) -> Vec<u8> {
    assert_eq!(raw.len() % 2, 0);
    let n = raw.len() / 2;
    fn enc(v: &[u8]) -> Vec<u8> {
        let t = {
            let i = v
                .iter()
                .position(|b| *b != 0)
                .unwrap_or(v.len().saturating_sub(1));
            &v[i..]
        };
        let t: &[u8] = if t.is_empty() { &[0u8] } else { t };
        let mut o = alloc::vec![0x02u8];
        if t[0] & 0x80 != 0 {
            o.push((t.len() + 1) as u8);
            o.push(0x00);
        } else {
            o.push(t.len() as u8);
        }
        o.extend_from_slice(t);
        o
    }
    let re = enc(&raw[..n]);
    let se = enc(&raw[n..]);
    let mut o = alloc::vec![0x30u8, (re.len() + se.len()) as u8];
    o.extend_from_slice(&re);
    o.extend_from_slice(&se);
    o
}

#[test]
fn piv_slots_24_a_27_p256_e_p384_sem_sobrescrever() {
    assert_eq!(PIV_SLOT_BASE, 24);
    let mut km = KeyManager::new();
    let pub9a = {
        let mut be = PivFwBackend::new(&mut km, 1);
        // 9A/9C/9D/9E -> ids 24/25/26/27 (P-256 nas bordas, P-384 no meio).
        let pub9a = be.generate(PivSlot::Auth9A, 0x11).expect("gen 9a");
        assert_eq!(pub9a.len(), 65);
        assert_eq!(pub9a[0], 0x04);
        let pub9c = be.generate(PivSlot::Sign9C, 0x14).expect("gen 9c");
        assert_eq!(pub9c.len(), 97);
        assert_eq!(pub9c[0], 0x04);
        be.generate(PivSlot::Mgmt9D, 0x11).expect("gen 9d");
        be.generate(PivSlot::Card9E, 0x11).expect("gen 9e");
        pub9a
    };
    let mut ids: Vec<u8> = km.list(true).expect("list").iter().map(|s| s.id).collect();
    ids.sort_unstable();
    assert_eq!(ids, alloc::vec![24u8, 25, 26, 27]);
    // Colisão com slot ocupado falha sem sobrescrever (chave antiga intacta).
    let mut be = PivFwBackend::new(&mut km, 1);
    assert_eq!(
        be.generate(PivSlot::Auth9A, 0x11).unwrap_err(),
        PivCryptoError::Failed
    );
    // AUTH responde R||S cru que verifica contra a pública gerada.
    let chal = b"desafio-piv-t9-fixo-32B.........";
    assert_eq!(chal.len(), 32);
    let resp = be.authenticate(PivSlot::Auth9A, 0x11, chal).expect("auth");
    assert_eq!(resp.len(), 64);
    let vk = {
        let x: [u8; 32] = pub9a[1..33].try_into().expect("x");
        let y: [u8; 32] = pub9a[33..65].try_into().expect("y");
        PublicKey::from_cose_key(&CoseKey::p256(x.to_vec(), y.to_vec())).expect("vk")
    };
    assert!(vk.verify(chal, &raw_to_der(&resp)).is_ok());
    let resp384 = be
        .authenticate(PivSlot::Sign9C, 0x14, chal)
        .expect("auth384");
    assert_eq!(resp384.len(), 96);
    // Slot vazio falha fechado; RSA indisponível neste device.
    assert_eq!(
        be.authenticate(PivSlot::Auth9A, 0x06, chal).unwrap_err(),
        PivCryptoError::BadAlg
    );
    let mut km2 = KeyManager::new();
    let mut be2 = PivFwBackend::new(&mut km2, 1);
    assert_eq!(
        be2.generate(PivSlot::Auth9A, 0x06).unwrap_err(),
        PivCryptoError::BadAlg
    );
    assert_eq!(
        be2.authenticate(PivSlot::Auth9A, 0x11, chal).unwrap_err(),
        PivCryptoError::Failed
    );
}

#[test]
fn piv_nvs_record_store_idempotente_e_paridade_t5() {
    let mut st = storage();
    {
        let mut piv = PivNvsStore::new(&mut st);
        assert_eq!(
            piv.load_record("piv_pin_hash"),
            Err(aegis_fido_usb::piv::PivStoreError::NotFound)
        );
        piv.store_record("piv_pin_hash", b"0123456789abcdef")
            .expect("store");
        assert_eq!(piv.load_record("piv_pin_hash").expect("load").len(), 16);
    }
    assert!(st.exists("piv_pin_hash"));
    {
        let mut piv = PivNvsStore::new(&mut st);
        piv.delete_record("piv_pin_hash").expect("delete");
        piv.delete_record("piv_pin_hash").expect("re-delete ok");
    }
    assert!(!st.exists("piv_pin_hash"));
    // Estado inicial de slots PIV via KeyManager dedicado vazio.
    let km = KeyManager::new();
    assert_eq!(km.len(), 0);
}

// ---------------------------------------------------------------------------
// CCID: OATH/FIDO fora do escopo v1 -> 6D 00 honesto (sem mock)
// ---------------------------------------------------------------------------

fn xfr(seq: u8, apdu: &[u8]) -> Vec<u8> {
    let mut m = alloc::vec![0x6Fu8];
    m.extend_from_slice(&(apdu.len() as u32).to_le_bytes());
    m.push(0);
    m.push(seq);
    m.extend_from_slice(&[0, 0, 0]);
    m.extend_from_slice(apdu);
    m
}

fn select_aid(aid: &[u8]) -> Vec<u8> {
    let mut apdu = alloc::vec![0x00u8, 0xA4, 0x04, 0x00, aid.len() as u8];
    apdu.extend_from_slice(aid);
    apdu
}

#[test]
fn ccid_oath_fido_fora_de_escopo_6d00_honesto_e_piv_servido() {
    let mut st = storage();
    enroll_piv(&mut st);
    let mut keys = KeyManager::new();
    let mut t = CcidTransport::new();
    let on = [0x62u8, 0, 0, 0, 0, 0, 1, 0, 0, 0];
    let r = process_ccid_frame(&mut t, &on, &mut st, &mut keys, 0).expect("atr");
    assert_eq!(r[0], 0x80);
    // PIV segue servido (fronteira do escopo): SELECT PIV -> 90 00.
    let piv_aid = [0xA0u8, 0x00, 0x00, 0x03, 0x08];
    let r = process_ccid_frame(
        &mut t,
        &xfr(2, &select_aid(&piv_aid)),
        &mut st,
        &mut keys,
        0,
    )
    .expect("sel piv");
    assert_eq!((r[r.len() - 2], r[r.len() - 1]), (0x90, 0x00));
    // OATH fora do escopo v1: SELECT YKOATH -> 6D 00 honesto (sem mock).
    let ykoath = [0xA0u8, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
    let r = process_ccid_frame(&mut t, &xfr(3, &select_aid(&ykoath)), &mut st, &mut keys, 0)
        .expect("sel oath");
    assert_eq!((r[r.len() - 2], r[r.len() - 1]), (0x6D, 0x00));
    // CALCULATE roteado ao applet OATH -> 6D 00 honesto (segredo nunca tocado).
    let calc = [0x00u8, 0xA2, 0x00, 0x00, 0x02, 0x71, 0x00];
    let r = process_ccid_frame(&mut t, &xfr(4, &calc), &mut st, &mut keys, 0).expect("calc");
    assert_eq!((r[r.len() - 2], r[r.len() - 1]), (0x6D, 0x00));
    // FIDO fora do escopo v1: SELECT U2F -> 6D 00 honesto.
    let u2f = [0xA0u8, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];
    let r = process_ccid_frame(&mut t, &xfr(5, &select_aid(&u2f)), &mut st, &mut keys, 0)
        .expect("sel u2f");
    assert_eq!((r[r.len() - 2], r[r.len() - 1]), (0x6D, 0x00));
    // Frame curto: sem resposta (nenhum hang, nenhum mock).
    assert!(process_ccid_frame(&mut t, &[0x6F, 0x00], &mut st, &mut keys, 0).is_none());
}

// ---------------------------------------------------------------------------
// KeyManager dedicado: GEN/LIST/DELETE não vaza entre domínios
// ---------------------------------------------------------------------------

#[test]
fn keymanager_dominios_nao_compartilham_estado() {
    let mut rng = rand_core::OsRng;
    // Domínio FIDO (slots baixos) vs domínio PIV (slots 24-27): sem interseção.
    let mut fido = KeyManager::new();
    fido.generate(
        0,
        CoseAlgorithm::ES256,
        "fido-key".into(),
        KEY_USE_SIGN | KEY_USE_AUTH,
        0,
        true,
        &mut rng,
    )
    .expect("gen fido");
    let mut piv_km = KeyManager::new();
    let mut be = PivFwBackend::new(&mut piv_km, 1);
    be.generate(PivSlot::Auth9A, 0x11).expect("gen piv");
    // Cada domínio vê só o seu slot.
    let fido_ids: Vec<u8> = fido
        .list(true)
        .expect("list")
        .iter()
        .map(|s| s.id)
        .collect();
    let piv_ids: Vec<u8> = piv_km
        .list(true)
        .expect("list")
        .iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(fido_ids, alloc::vec![0u8]);
    assert_eq!(piv_ids, alloc::vec![24u8]);
    // Etiquetas não colidem entre domínios (prefixo piv: reservado ao PIV).
    assert!(fido.list(true).expect("list")[0].label != "piv:9a");
    assert_eq!(piv_km.list(true).expect("list")[0].label, "piv:9a");
}
