//! Gates e despachos GATT com binding/storage (apendice Sec.11).
//! (Conteudo movido de `ble_gatt.rs` sem mudanca de comportamento.)

use super::gatt_core::{
    BleGattError, BIND_MGMT_OP_MAX, BIND_MGMT_OP_MIN, OP_KEY_DELETE, OP_KEY_GEN_ONDEVICE,
    OP_KEY_IMPORT_ENVELOPE, OP_KEY_LIST, OP_OATH_CODE, OP_OATH_DELETE, OP_OATH_LIST, OP_OATH_PUT,
    OP_PIV_ENROLL, VENDOR_OP_MAX, VENDOR_OP_MIN, WALLET_OP_MAX, WALLET_OP_MIN,
};
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};

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
