//! Gates e despachos GATT com binding/storage (apendice Sec.11).
//! (Conteudo movido de `ble_gatt.rs` sem mudanca de comportamento.)

extern crate alloc;

use alloc::vec::Vec;

use super::gatt_core::{
    BleGattError, BIND_MGMT_OP_MAX, BIND_MGMT_OP_MIN, OP_BACKUP_EXPORT, OP_KEY_DELETE,
    OP_KEY_GEN_ONDEVICE, OP_KEY_IMPORT_ENVELOPE, OP_KEY_LIST, OP_OATH_CODE, OP_OATH_DELETE,
    OP_OATH_LIST, OP_OATH_PUT, OP_PIV_ENROLL, VENDOR_OP_MAX, VENDOR_OP_MIN, WALLET_OP_MAX,
    WALLET_OP_MIN,
};
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};
use crate::ota::{
    OtaProvider, OP_OTA_ABORT, OP_OTA_BEGIN, OP_OTA_CHUNK, OP_OTA_COMMIT, OP_OTA_FINISH,
};
use crate::stores::ota_store::{
    dispatch_ota_request, is_ota_op as is_serial_ota_op, FlashOtaSink, OtaRequestCtx,
    OTA_STATUS_FAIL,
};

/// `true` para o enrollment PIV 0x39.
pub fn is_piv_enroll_op(op: u8) -> bool {
    op == OP_PIV_ENROLL
}

/// `true` para ops binding mgmt 0x28-0x2D (reservados, fora de 0x20-0x27 e CTAP-BLE).
pub fn is_bind_mgmt_op(op: u8) -> bool {
    (BIND_MGMT_OP_MIN..=BIND_MGMT_OP_MAX).contains(&op)
}

/// USO (CODE/LIST): nunca exige vinculo, so UP fisico (senao keypass nao funciona).
/// `0x22` KEY_LIST | `0x25` OATH_LIST | `0x26` OATH_CODE.
pub fn is_usage_op(op: u8) -> bool {
    matches!(op, OP_KEY_LIST | OP_OATH_LIST | OP_OATH_CODE)
}

/// CONFIGURAR (GEN/IMPORT/DELETE/PUT/WiFi/claim-mgmt): release exige
/// vinculo+UP(+PIN); teste exige UP(+PIN) com bypass+l trace.
pub fn is_config_op(op: u8) -> bool {
    matches!(
        op,
        OP_KEY_GEN_ONDEVICE | OP_KEY_IMPORT_ENVELOPE | OP_KEY_DELETE | OP_OATH_PUT | OP_OATH_DELETE
    )
}

/// Retorna true para opcodes vendor Fase6 0x20-0x27 (reservados).
pub fn is_vendor_keys_oath_op(op: u8) -> bool {
    (VENDOR_OP_MIN..=VENDOR_OP_MAX).contains(&op)
}

/// Retorna true para opcodes wallet Fase7 0x35-0x37 (reservados).
pub fn is_wallet_op(op: u8) -> bool {
    (WALLET_OP_MIN..=WALLET_OP_MAX).contains(&op)
}

/// `true` para o backup-export 0x3A (fora das faixas vendor/bind/OTA/wallet).
pub fn is_backup_export_op(op: u8) -> bool {
    op == OP_BACKUP_EXPORT
}

// Gates de binding para ops vendor Fase6 (Sec.9.4 + `binding.rs`).
//
// - Privilegiadas `0x21/0x23/0x24/0x27`: binding valido + UP + PIN.
// - `0x20/0x22/0x25/0x26` (GEN/LIST/CODE): binding valido + UP.
// - Ordem canonica: binding -> UP -> PIN (app alheio sempre ve NEED_BINDING).
// - `control_write` e framing Sec.1-Sec.3 intactos; USB/CTAP zero mudanca.

/// `true` quando o op vendor exige UP+PIN (privilegiadas). Demais: so UP.
/// `0x21` IMPORT | `0x23` KEY_DELETE | `0x24` OATH_PUT | `0x27` OATH_DELETE.
pub fn vendor_op_requires_pin(op: u8) -> bool {
    matches!(
        op,
        OP_KEY_IMPORT_ENVELOPE | OP_KEY_DELETE | OP_OATH_PUT | OP_OATH_DELETE
    )
}

/// Gate normativo Sec.9.4 + binding para um op vendor.
///
/// `binding_ok`: `BindingManager::verify` passou para
/// `(challenge, op, payload_hash)` de uso unico. Nao faz I/O nem alloc.
pub fn authorize_vendor_op(
    op: u8,
    binding_ok: bool,
    pin_authenticated: bool,
    presence_confirmed: bool,
) -> Result<(), BleGattError> {
    if !is_vendor_keys_oath_op(op) {
        return Err(BleGattError::InvalidOpcode);
    }
    // Split uso/config (Sec.11): USO nunca exige vinculo, so UP fisico.
    if is_usage_op(op) {
        if !presence_confirmed {
            return Err(BleGattError::PresenceRequired);
        }
        return Ok(());
    }
    // CONFIG: teste faz bypass com ltrace (cripto DESABILITADA); release exige vinculo.
    if crate::binding::binding_bypass_enabled() {
        crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "binding-bypass");
    } else if !binding_ok {
        return Err(BleGattError::NeedBinding);
    }
    if !presence_confirmed {
        return Err(BleGattError::PresenceRequired);
    }
    if vendor_op_requires_pin(op) && !pin_authenticated {
        return Err(BleGattError::PinRequired);
    }
    Ok(())
}

/// Gate normativo carteira Fase7 (R-07): binding valido + UP.
///
/// GEN/LIST/ADDR nao expoem import/delete (sem PIN nesta faixa); a ordem
/// canonica binding -> UP e a mesma de vendor. Executor on-device =
/// follow-up (Wire: gate ok -> `0x04`, como vendor Sec.9.4).
pub fn authorize_wallet_op(
    op: u8,
    binding_ok: bool,
    presence_confirmed: bool,
) -> Result<(), BleGattError> {
    if !is_wallet_op(op) {
        return Err(BleGattError::InvalidOpcode);
    }
    if crate::binding::binding_bypass_enabled() {
        crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "binding-bypass");
    } else if !binding_ok {
        return Err(BleGattError::NeedBinding);
    }
    if !presence_confirmed {
        return Err(BleGattError::PresenceRequired);
    }
    Ok(())
}

/// Gate do backup-export `0x3A`: política CONFIG privilegiada.
///
/// Ordem canônica binding -> UP -> PIN (como `0x21/0x23/0x24/0x27`): o
/// envelope exportado carrega material de chaves/OATH cifrado, então
/// exige o trio completo. Teste faz bypass de vínculo com ltrace (como
/// vendor), mas UP+PIN seguem exigidos nas duas modalidades.
pub fn authorize_backup_export_op(
    binding_ok: bool,
    pin_authenticated: bool,
    presence_confirmed: bool,
) -> Result<(), BleGattError> {
    if crate::binding::binding_bypass_enabled() {
        crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "binding-bypass");
    } else if !binding_ok {
        return Err(BleGattError::NeedBinding);
    }
    if !presence_confirmed {
        return Err(BleGattError::PresenceRequired);
    }
    if !pin_authenticated {
        return Err(BleGattError::PinRequired);
    }
    Ok(())
}

/// Gate do log da firmware (`0x38`, ver `fw_log`).
///
/// Leitura diagnostica sem segredos: exige vinculo no BLE (ordem
/// canonica, app alheio ve `NeedBinding` 0x05), mas nunca UP nem PIN.
/// Serial/USB fisico nem passa por aqui (posse do cabo = livre).
pub fn authorize_fw_log_op(op: u8, bonded: bool) -> Result<(), BleGattError> {
    if !crate::fw_log::is_fw_log_op(op) {
        return Err(BleGattError::InvalidOpcode);
    }
    if !bonded {
        return Err(BleGattError::NeedBinding);
    }
    Ok(())
}

/// Mapeia `BindingError` para `BleGattError` (fiacao GATT Sec.11).
pub fn binding_err_to_gatt(e: crate::binding::BindingError) -> BleGattError {
    use crate::binding::BindingError as B;
    match e {
        B::NotClaimed | B::BadSignature | B::ChallengeMismatch | B::Replay | B::BadPubkey => {
            BleGattError::NeedBinding
        }
        B::PresenceRequired | B::PairingRequired => BleGattError::PresenceRequired,
        B::PinRequired => BleGattError::PinRequired,
        B::AlreadyClaimed | B::Corrupted | B::Storage => BleGattError::InvalidFragment,
    }
}

/// Mapeia `RecoveryError` para `BleGattError` (fiacao GATT Sec.11).
pub fn recovery_err_to_gatt(e: crate::recovery::RecoveryError) -> BleGattError {
    use crate::recovery::RecoveryError as R;
    match e {
        R::PresenceRequired => BleGattError::PresenceRequired,
        R::BadPin | R::Locked => BleGattError::PinRequired,
        R::NotProvisioned | R::Corrupted | R::Storage => BleGattError::InvalidFragment,
    }
}

/// Despacho GATT `OP_BIND_CLAIM` (0x28): `app_pub(65)||binding_id(16)` = 81B.
///
/// Exige `Unclaimed` + janela de pareamento + UP + pubkey valida.
/// Persiste em NVS com verify-after-write. Retorna status wire Sec.9.5+0x05.
pub fn dispatch_bind_claim<B: crate::persistence::FlashStorageBackend>(
    binding: &mut crate::binding::BindingManager,
    storage: &mut crate::persistence::SecureStorage<B>,
    app_pub: &[u8; crate::binding::BIND_PUB_LEN],
    binding_id: &[u8; crate::binding::BIND_ID_LEN],
    pairing_window_open: bool,
    presence_confirmed: bool,
) -> Result<(), BleGattError> {
    binding
        .claim(app_pub, binding_id, pairing_window_open, presence_confirmed)
        .map_err(binding_err_to_gatt)?;
    binding.persist(storage).map_err(binding_err_to_gatt)?;
    Ok(())
}

/// Despacho GATT `OP_BIND_CHALLENGE` (0x29): emite 32B via TRNG.
///
/// Exige Claimed (senao NEED_BINDING); invalida o anterior (so o ultimo vale).
/// Em test-mode o app pode pular o challenge (bypass); o op segue exigindo
/// Claimed nas duas modalidades (sem bypass aqui).
pub fn dispatch_bind_challenge<
    B: crate::persistence::FlashStorageBackend,
    R: rand_core::RngCore + rand_core::CryptoRng,
>(
    binding: &mut crate::binding::BindingManager,
    _storage: &crate::persistence::SecureStorage<B>,
    rng: &mut R,
) -> Result<[u8; crate::binding::BIND_CHALLENGE_LEN], BleGattError> {
    binding.new_challenge(rng).map_err(binding_err_to_gatt)
}

/// Despacho GATT `OP_BIND_VERIFY` (0x2A): checa prova sem executar o op.
///
/// Helper de teste/diagnostico (`op||challenge||payload_hash||sig`).
/// Em test-mode o chamador pode pular (bypass nas CONFIG); a cripto aqui
/// segue valida nas duas modalidades (sem bypass).
pub fn dispatch_bind_verify(
    binding: &mut crate::binding::BindingManager,
    sig: &[u8],
    challenge: &[u8; crate::binding::BIND_CHALLENGE_LEN],
    op: u8,
    payload_hash: &[u8; crate::binding::BIND_PAYLOAD_HASH_LEN],
) -> Result<(), BleGattError> {
    if !is_vendor_keys_oath_op(op) && !is_bind_mgmt_op(op) && op != crate::binding::BIND_OP_RELEASE
    {
        return Err(BleGattError::InvalidOpcode);
    }
    binding
        .verify(sig, challenge, op, payload_hash)
        .map_err(binding_err_to_gatt)
}

/// Despacho GATT `OP_BIND_RELEASE` (0x2B): dono assina e libera re-claim.
///
/// Release exige prova (`challenge||0x52||sha256(binding_id)`); em test-mode
/// faz bypass com ltrace (so UP, wipe direto). Sucesso faz wipe (NVS+RAM).
pub fn dispatch_bind_release<B: crate::persistence::FlashStorageBackend>(
    binding: &mut crate::binding::BindingManager,
    storage: &mut crate::persistence::SecureStorage<B>,
    sig: &[u8],
    challenge: &[u8; crate::binding::BIND_CHALLENGE_LEN],
    payload_hash: &[u8; crate::binding::BIND_PAYLOAD_HASH_LEN],
    presence_confirmed: bool,
) -> Result<(), BleGattError> {
    if !presence_confirmed {
        return Err(BleGattError::PresenceRequired);
    }
    if crate::binding::binding_bypass_enabled() {
        crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "binding-bypass");
        binding.wipe(storage);
        return Ok(());
    }
    binding
        .release_signed(storage, sig, challenge, payload_hash)
        .map_err(binding_err_to_gatt)
}

/// Despacho GATT `OP_RECOVERY_SET` (0x2C): define PIN 4-6 digitos (exige UP).
pub fn dispatch_recovery_set<B: crate::persistence::FlashStorageBackend>(
    storage: &mut crate::persistence::SecureStorage<B>,
    pin: &str,
    presence_confirmed: bool,
) -> Result<(), BleGattError> {
    crate::recovery::set_recovery_pin(storage, pin, presence_confirmed)
        .map_err(recovery_err_to_gatt)
}

/// Despacho GATT `OP_RECOVERY_UNLOCK` (0x2D): UP+PIN => wipe e libera re-claim.
pub fn dispatch_recovery_unlock<B: crate::persistence::FlashStorageBackend>(
    storage: &mut crate::persistence::SecureStorage<B>,
    binding: &mut crate::binding::BindingManager,
    pin: &str,
    presence_confirmed: bool,
) -> Result<(), BleGattError> {
    crate::recovery::recovery_unlock(storage, binding, pin, presence_confirmed)
        .map_err(recovery_err_to_gatt)
}

// ---------------------------------------------------------------------------
// OTA sobre BLE (0x30-0x34): BEGIN/CHUNK/VERIFY executam; COMMIT nega 0x04.
//
// REGRA DE COMMIT (documentada; a janela fisica valida o BOOT fisico + o
// caminho USB): o swap de firmware (`0x33`) executa SOMENTE via USB/CTAPHID.
// Pelo ar (BLE) nao ha como atestar presenca fisica local nem impedir
// acionamento remoto, entao o transporte BLE nega `0x33` com falha generica
// `0x04` SEM tocar a sessao (sem rollback, sem marcador): a sessao
// `Verified` permanece valida para um COMMIT posterior via USB-HID do app. BEGIN (`0x30`, manifesto 104 B), CHUNK (`0x31`,
// `offset BE u32 || dados`) e VERIFY (`0x32`) usam o MESMO dispatch, os
// MESMOS status e os MESMOS gates do serial (`dispatch_ota_request` com
// `OtaRequestCtx` identico: provisionado, UP so no COMMIT, anti-rollback
// via `current_version`, chave negada fail-closed). O teto do control-point
// BLE (512 B, `CONTROL_POINT_LENGTH`) e reforçado aqui: CHUNK com mais de
// 512 B de dados nega fail-closed com rollback, como qualquer `OtaError`.
// ABORT (`0x34`) segue limpeza idempotente, como no serial.
// ---------------------------------------------------------------------------

/// Teto BLE por CHUNK OTA: dados uteis (sem o `offset` de 4 B) por mensagem.
///
/// Defesa em profundidade além do `CONTROL_POINT_LENGTH` (512 B) do
/// reassembler: a mensagem CHUNK inteira (`offset || dados`) ja cabe no
/// control-point por construcao, e este teto nega qualquer dado acima de
/// 512 B fail-closed antes de tocar o sink.
pub const BLE_OTA_MAX_CHUNK_BYTES: usize = 512;

/// `true` para opcodes OTA `0x30-0x34` (espelha `stores::ota_store::is_ota_op`
/// sem acoplar o transporte a maquina de sessao).
pub fn is_ota_op(op: u8) -> bool {
    is_serial_ota_op(op)
}

/// Contexto tipado de uma requisicao OTA sobre BLE (dominio interno; o fio
/// segue `[op:1, len_hi:1, len_lo:1, payload...]`, sem JSON fora de FFI).
///
/// Paridade com o serial: os mesmos quatro campos viram o mesmo
/// `OtaRequestCtx` do dispatch canonico, logo status e gates sao identicos.
pub struct BleOtaCtx {
    /// `load_device_keys` ok (BEGIN nega `Unprovisioned` sem fabrica).
    pub provisioned: bool,
    /// Latch de presenca 1x (so o COMMIT exige; negado no BLE de todo modo).
    pub up: bool,
    /// Pubkey Ed25519 release ativa do build ([`crate::ota::OtaKeyProvider`]).
    pub ota_pubkey: [u8; 32],
    /// `max(firmware, contador anti-rollback NVS)` (FINISH nega downgrade).
    pub current_version: u32,
}

/// Sessao OTA carregada pelo transporte BLE (dono: o loop chamador).
///
/// O `ble_dispatch_complete` recebe `Some` quando o build tem OTA (ESP
/// nao-classic) e `None` fora dele (classic/host): sem sessao, o braco OTA
/// responde `0x04` fail-closed sem executar nada.
pub struct BleOtaSession<'a> {
    /// Maquina `Idle → Staged → Verified → Committed` (mesma do serial/USB).
    pub state: &'a mut crate::ota::OtaState,
    /// `ota_provisioned` do loop (eFuse valido ou lab test-mode).
    pub provisioned: bool,
    /// Pubkey Ed25519 release ativa do build.
    pub ota_pubkey: [u8; 32],
    /// `max(firmware, contador anti-rollback NVS)` (fail-closed).
    pub current_version: u32,
}

/// Braço de execucao OTA sobre BLE (`None` = opcode fora de `0x30-0x34`).
///
/// Generico sobre [`OtaProvider`] (DIP, como `dispatch_ota_request`): o
/// transporte nunca nomeia a maquina concreta. Retorna `(status, corpo)` no
/// padrao status-first do GATT (`0x00` OK | `0x01` NEED_UP | `0x04` falha).
pub fn dispatch_ble_ota<P: OtaProvider, B: crate::persistence::FlashStorageBackend>(
    state: &mut P,
    sink: &mut FlashOtaSink<B>,
    op: u8,
    payload: &[u8],
    ctx: &BleOtaCtx,
) -> Option<(u8, Vec<u8>)> {
    if !is_ota_op(op) {
        return None;
    }
    // COMMIT (`0x33`) SOMENTE via USB: nega `0x04` sem tocar a sessao (sem
    // rollback, sem marcador). A sessao `Verified` segue valida para o
    // COMMIT via USB-HID do app.
    if op == OP_OTA_COMMIT {
        return Some((OTA_STATUS_FAIL, Vec::new()));
    }
    // Teto BLE: CHUNK (`offset BE u32 || dados`) com mais de 512 B de dados
    // nega fail-closed com rollback, como qualquer `OtaError` do serial.
    if op == OP_OTA_CHUNK && payload.len().saturating_sub(4) > BLE_OTA_MAX_CHUNK_BYTES {
        state.rollback();
        sink.discard();
        return Some((OTA_STATUS_FAIL, Vec::new()));
    }
    let req = OtaRequestCtx {
        provisioned: ctx.provisioned,
        up: ctx.up,
        ota_pubkey: ctx.ota_pubkey,
        current_version: ctx.current_version,
    };
    dispatch_ota_request(state, sink, op, payload, &req)
}

/// Garante em compilacao que os opcodes BLE espelham a fonte canonica
/// (`crate::ota`): o transporte valida sem acoplar a maquina OTA.
const _: () = {
    assert!(OP_OTA_BEGIN == 0x30);
    assert!(OP_OTA_CHUNK == 0x31);
    assert!(OP_OTA_FINISH == 0x32);
    assert!(OP_OTA_COMMIT == 0x33);
    assert!(OP_OTA_ABORT == 0x34);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ota::{
        OtaKeyProvider, OtaManifest, OtaPhase, OtaState, OP_OTA_ABORT, OP_OTA_BEGIN, OP_OTA_CHUNK,
        OP_OTA_COMMIT, OP_OTA_FINISH, OTA_MANIFEST_LEN,
    };
    use crate::persistence::{MockFlashBackend, SecureStorage};
    use crate::stores::ota_store::{keys_unchanged, snapshot_keys, OTA_STATUS_FAIL, OTA_STATUS_OK};
    use alloc::vec;
    use alloc::vec::Vec;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest as _, Sha256};
    use signature::Signer as _;

    const BLE_OTA_CURRENT: u32 = 7;
    const BLE_OTA_NEXT: u32 = 8;
    const CRED_KEYS: &[&str] = &["credential_01", "pin_hash"];

    fn ble_image() -> Vec<u8> {
        vec![0xA5u8; 1024]
    }

    fn ble_manifest_raw(version: u32, image: &[u8], sig: &[u8; 64]) -> Vec<u8> {
        let digest = Sha256::digest(image);
        let mut raw = Vec::with_capacity(OTA_MANIFEST_LEN);
        raw.extend_from_slice(&version.to_be_bytes());
        raw.extend_from_slice(&(image.len() as u32).to_be_bytes());
        raw.extend_from_slice(&digest);
        raw.extend_from_slice(sig);
        raw
    }

    fn ble_signed_manifest(version: u32, image: &[u8], sk: &SigningKey) -> Vec<u8> {
        let unsigned = ble_manifest_raw(version, image, &[0x5Eu8; 64]);
        let m = OtaManifest::parse(&unsigned).expect("parse unsigned");
        let sig = sk.sign(&m.signed_bytes());
        ble_manifest_raw(version, image, &sig.to_bytes())
    }

    fn ble_chunk_payload(offset: u32, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + data.len());
        v.extend_from_slice(&offset.to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    fn ble_ctx(provisioned: bool, up: bool, pubkey: [u8; 32]) -> BleOtaCtx {
        BleOtaCtx {
            provisioned,
            up,
            ota_pubkey: pubkey,
            current_version: BLE_OTA_CURRENT,
        }
    }

    fn ble_storage() -> SecureStorage<MockFlashBackend> {
        let mut storage = SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32]);
        let nonce = [0x00u8; 12];
        storage
            .store("credential_01", b"passkey-bytes", &nonce)
            .unwrap();
        storage.store("pin_hash", b"pin-salt-hash", &nonce).unwrap();
        storage
    }

    fn ble_stage_to_verified(
        ota: &mut OtaState,
        sink: &mut FlashOtaSink<MockFlashBackend>,
        manifest: &[u8],
        image: &[u8],
        ctx: &BleOtaCtx,
    ) {
        assert_eq!(
            dispatch_ble_ota(ota, sink, OP_OTA_BEGIN, manifest, ctx),
            Some((OTA_STATUS_OK, Vec::new()))
        );
        let mut off = 0u32;
        for chunk in image.chunks(256) {
            let p = ble_chunk_payload(off, chunk);
            let (st, body) =
                dispatch_ble_ota(ota, sink, OP_OTA_CHUNK, &p, ctx).expect("chunk dispatch");
            assert_eq!(st, OTA_STATUS_OK);
            off += chunk.len() as u32;
            assert_eq!(body, off.to_be_bytes().to_vec());
        }
        assert_eq!(
            dispatch_ble_ota(ota, sink, OP_OTA_FINISH, &[], ctx),
            Some((OTA_STATUS_OK, Vec::new()))
        );
        assert_eq!(ota.phase(), OtaPhase::Verified);
    }

    #[test]
    fn backup_export_gate_ordem_binding_up_pin() {
        // Sem vínculo: release nega NEED_BINDING; test-mode faz bypass.
        let no_bind = authorize_backup_export_op(false, true, true);
        if crate::binding::binding_bypass_enabled() {
            assert!(no_bind.is_ok());
        } else {
            assert_eq!(no_bind, Err(BleGattError::NeedBinding));
        }
        // UP ausente nega mesmo com vínculo+PIN.
        assert_eq!(
            authorize_backup_export_op(true, true, false),
            Err(BleGattError::PresenceRequired)
        );
        // PIN ausente nega mesmo com vínculo+UP.
        assert_eq!(
            authorize_backup_export_op(true, false, true),
            Err(BleGattError::PinRequired)
        );
        // Trio completo passa.
        assert!(authorize_backup_export_op(true, true, true).is_ok());
        // Predicado só casa 0x3A.
        assert!(is_backup_export_op(OP_BACKUP_EXPORT));
        assert!(!is_backup_export_op(0x20));
        assert!(!is_backup_export_op(0x30));
        assert!(!is_backup_export_op(0x2F));
    }

    #[test]
    fn ble_ota_session_carrega_contexto_do_loop() {
        // O transporte monta `BleOtaSession` com a mesma sessão do
        // serial/USB (run loops): valida a construção aqui no host.
        let mut ota = OtaState::new(BLE_OTA_CURRENT);
        let session = BleOtaSession {
            state: &mut ota,
            provisioned: true,
            ota_pubkey: [0x11u8; 32],
            current_version: BLE_OTA_CURRENT,
        };
        assert!(session.provisioned);
        assert_eq!(session.ota_pubkey, [0x11u8; 32]);
        assert_eq!(session.current_version, BLE_OTA_CURRENT);
        assert_eq!(session.state.phase(), OtaPhase::Idle);
    }

    #[test]
    fn ble_ota_opcodes_espelham_serial() {
        // Paridade de faixa (o `const _` acima trava os valores em compilacao).
        for op in [
            OP_OTA_BEGIN,
            OP_OTA_CHUNK,
            OP_OTA_FINISH,
            OP_OTA_COMMIT,
            OP_OTA_ABORT,
        ] {
            assert!(is_ota_op(op), "ota op 0x{op:02X}");
        }
        assert!(!is_ota_op(0x2F));
        assert!(!is_ota_op(0x20));
        assert!(!is_ota_op(0x35));
        // Fora da faixa: sem braço de execução (o chamador cai no `0x04`).
        let mut storage = ble_storage();
        let mut ota = OtaState::new(BLE_OTA_CURRENT);
        let ctx = ble_ctx(true, true, [0x11u8; 32]);
        let mut sink = FlashOtaSink::new(storage.backend_mut());
        assert_eq!(dispatch_ble_ota(&mut ota, &mut sink, 0x2F, &[], &ctx), None);
        assert_eq!(dispatch_ble_ota(&mut ota, &mut sink, 0x35, &[], &ctx), None);
        assert_eq!(ota.phase(), OtaPhase::Idle);
    }

    #[test]
    fn ble_ota_begin_chunk_verify_ok_paridade_serial() {
        // Sessão BLE BEGIN → CHUNK* → VERIFY com os mesmos status do serial.
        let mut storage = ble_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ble_image();
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let manifest = ble_signed_manifest(BLE_OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(BLE_OTA_CURRENT);
        let ctx = ble_ctx(true, true, sk.verifying_key().to_bytes());
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            ble_stage_to_verified(&mut ota, &mut sink, &manifest, &image, &ctx);
            assert_eq!(ota.received(), image.len());
            assert!(sink.exists_staging());
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ble_ota_chunk_acima_512_nega_com_rollback() {
        // Teto BLE: dado de CHUNK > 512 B nega `0x04` e desfaz a sessão,
        // mesmo com offset íntegro e dispositivo provisionado.
        let mut storage = ble_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ble_image();
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let manifest = ble_signed_manifest(BLE_OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(BLE_OTA_CURRENT);
        let ctx = ble_ctx(true, true, sk.verifying_key().to_bytes());
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            assert_eq!(
                dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_BEGIN, &manifest, &ctx),
                Some((OTA_STATUS_OK, Vec::new()))
            );
            let big = vec![0xABu8; BLE_OTA_MAX_CHUNK_BYTES + 1];
            let p = ble_chunk_payload(0, &big);
            assert_eq!(
                dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_CHUNK, &p, &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.exists_staging());
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ble_ota_commit_negado_sessao_intacta() {
        // REGRA DE COMMIT (USB-only): pelo BLE o `0x33` nega `0x04` SEM
        // tocar a sessão — mesmo com UP e chave válida. A sessão `Verified`
        // segue válida para o COMMIT via USB-HID do app.
        let mut storage = ble_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ble_image();
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let manifest = ble_signed_manifest(BLE_OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(BLE_OTA_CURRENT);
        let ctx = ble_ctx(true, true, sk.verifying_key().to_bytes());
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            ble_stage_to_verified(&mut ota, &mut sink, &manifest, &image, &ctx);
            assert_eq!(
                dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_COMMIT, &[], &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Verified);
            assert_eq!(ota.received(), image.len());
            assert!(!sink.has_commit_marker());
            assert_eq!(sink.committed_marker(), None);
            // ABORT segue limpeza idempotente (paridade serial).
            assert_eq!(
                dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_ABORT, &[], &ctx),
                Some((OTA_STATUS_OK, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ble_ota_antiroollback_preservado() {
        // FINISH com versão igual/menor nega e desfaz (anti-rollback); sem
        // vínculo de fábrica, todo op mutante nega e ABORT segue OK.
        let mut storage = ble_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ble_image();
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let pubkey = sk.verifying_key().to_bytes();
        let mut ota = OtaState::new(BLE_OTA_CURRENT);
        let ctx = ble_ctx(true, true, pubkey);
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            let stale = ble_signed_manifest(BLE_OTA_CURRENT, &image, &sk);
            assert_eq!(
                dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_BEGIN, &stale, &ctx),
                Some((OTA_STATUS_OK, Vec::new()))
            );
            let mut off = 0u32;
            for chunk in image.chunks(256) {
                let p = ble_chunk_payload(off, chunk);
                assert_eq!(
                    dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_CHUNK, &p, &ctx).map(|r| r.0),
                    Some(OTA_STATUS_OK)
                );
                off += chunk.len() as u32;
            }
            assert_eq!(
                dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_FINISH, &[], &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.exists_staging());
        }
        // Sem provisionamento: nega BEGIN/CHUNK/VERIFY/COMMIT, ABORT ok.
        let raw = ble_signed_manifest(BLE_OTA_NEXT, &image, &sk);
        let no_factory = ble_ctx(false, true, pubkey);
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            assert_eq!(
                dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_BEGIN, &raw, &no_factory),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            let p = ble_chunk_payload(0, &image[..64]);
            assert_eq!(
                dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_CHUNK, &p, &no_factory),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(
                dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_FINISH, &[], &no_factory),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(
                dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_COMMIT, &[], &no_factory),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert_eq!(
                dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_ABORT, &[], &no_factory),
                Some((OTA_STATUS_OK, Vec::new()))
            );
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ble_ota_chave_negada_nunca_verifica() {
        // NUNCA VERIFY/COMMIT sob chave zerada: FINISH nega + rollback, sem
        // marcador, NVS intacta (paridade com o serial).
        let mut storage = ble_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ble_image();
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let manifest = ble_signed_manifest(BLE_OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(BLE_OTA_CURRENT);
        let real = ble_ctx(true, true, sk.verifying_key().to_bytes());
        let denied = ble_ctx(true, true, OtaKeyProvider::RELEASE_PUBKEY);
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            ble_stage_to_verified(&mut ota, &mut sink, &manifest, &image, &real);
            // Re-estagia sob a sessão real e tenta FINISH sob zeros.
            ota.rollback();
            sink.discard();
            assert_eq!(
                dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_BEGIN, &manifest, &real),
                Some((OTA_STATUS_OK, Vec::new()))
            );
            let mut off = 0u32;
            for chunk in image.chunks(256) {
                let p = ble_chunk_payload(off, chunk);
                assert_eq!(
                    dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_CHUNK, &p, &real).map(|r| r.0),
                    Some(OTA_STATUS_OK)
                );
                off += chunk.len() as u32;
            }
            assert_eq!(
                dispatch_ble_ota(&mut ota, &mut sink, OP_OTA_FINISH, &[], &denied),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.has_commit_marker());
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }
}
