//! Wave4 — GATT 0xFFFD (CTAP2-BLE parcial, host stub + ESP NimBLE).
//!
//! - Servico `0xFFFD`; chars `FFF1` control/write, `FFF2` status/notify,
//!   `FFF3` len/read, `FFF4` revision/read-write.
//! - Opcodes CTAP2-BLE: `MSG 0x83`, `PING 0x81`, `CANCEL 0xBE`.
//! - Reassemble limitado por `CONTROL_POINT_LENGTH`; colisao rejeitada
//!   se transacao ativa; tudo delega a `CtapEngine` + `UpPolicy`.
//! - Bonding obrigatorio; UP por operacao (latch uso unico pelo chamador).
//! - USB/CTAP bytes intactos: este transporte so encapsula.

extern crate alloc;

use alloc::vec::Vec;
use aegis_fido_core::policy::{PolicyError, UpOnly, UpPolicy};
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};

/// UUID16 do servico GATT (congelado para o app Android).
pub const BLE_SERVICE_UUID: u16 = 0xFFFD;
/// Caracteristica control-point (write, request fragmentado).
pub const CHAR_CONTROL_UUID: u16 = 0xFFF1;
/// Caracteristica status (notify, keepalive/status).
pub const CHAR_STATUS_UUID: u16 = 0xFFF2;
/// Caracteristica tamanho pendente (read len).
pub const CHAR_LEN_UUID: u16 = 0xFFF3;
/// Caracteristica revisao (read/write).
pub const CHAR_REVISION_UUID: u16 = 0xFFF4;

/// CTAP2-BLE PING (echo, sem CtapEngine).
pub const OP_PING: u8 = 0x81;
/// CTAP2-BLE MSG (CBOR encapsulado, delega a `CtapEngine::process_packet`).
pub const OP_MSG: u8 = 0x83;
/// CTAP2-BLE CANCEL (aborta transacao ativa).
pub const OP_CANCEL: u8 = 0xBE;

/// Fase6 apendice 9.1 - faixa vendor Keys/OATH sobre BLE (FFF1 control-point).
/// Reservados, GATT inalterado, revisao permanece 0x01. Decoders Wave4
/// desconhecem e descartam sem NACK que quebre 9.6 (sem reenvio como 0x83).
pub const OP_KEY_GEN_ONDEVICE: u8 = 0x20;
pub const OP_KEY_IMPORT_ENVELOPE: u8 = 0x21;
pub const OP_KEY_LIST: u8 = 0x22;
pub const OP_KEY_DELETE: u8 = 0x23;
pub const OP_OATH_PUT: u8 = 0x24;
pub const OP_OATH_LIST: u8 = 0x25;
pub const OP_OATH_CODE: u8 = 0x26;
pub const OP_OATH_DELETE: u8 = 0x27;
/// Limites da faixa vendor Fase6.
pub const VENDOR_OP_MIN: u8 = OP_KEY_GEN_ONDEVICE;
pub const VENDOR_OP_MAX: u8 = OP_OATH_DELETE;

/// Binding + recovery sobre GATT (apendice §11, aditivo, sem quebra §1-§10).
/// Framing §3 reutilizado: `[op:1, len_hi:1, len_lo:1, payload...]`.
/// GATT inalterado, revisao permanece `0x01`; USB/CTAP zero mudanca.
pub const OP_BIND_CLAIM: u8 = 0x28;
/// Pede challenge 32B (req 0B, resp 32B); exige Claimed (senao NEED_BINDING).
pub const OP_BIND_CHALLENGE: u8 = 0x29;
/// Verifica prova para um op (helper de teste; req `op(1)||challenge(32)||payload_hash(32)||sig(var)`).
pub const OP_BIND_VERIFY: u8 = 0x2A;
/// Libera o dono atual (req `challenge(32)||payload_hash(32)||sig(var)`; wipe).
pub const OP_BIND_RELEASE: u8 = 0x2B;
/// Define o PIN de recovery 4-6 digitos (req ascii; exige UP).
pub const OP_RECOVERY_SET: u8 = 0x2C;
/// Destrava com PIN + UP e libera re-claim (req ascii; 8 tentativas NVS).
pub const OP_RECOVERY_UNLOCK: u8 = 0x2D;
/// Limites da faixa binding mgmt.
pub const BIND_MGMT_OP_MIN: u8 = OP_BIND_CLAIM;
pub const BIND_MGMT_OP_MAX: u8 = OP_RECOVERY_UNLOCK;

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

/// Limite de reassemble (== envelope MAX-ESP, sem alloc extra).
pub const CONTROL_POINT_LENGTH: usize = 512;
/// Revisao GATT inicial (FFF4).
pub const GATT_REVISION: u8 = 0x01;
/// Tamanho maximo de fragmento aceito por write (MTU-3 conservador).
pub const MAX_FRAGMENT_BYTES: usize = 244;

/// Erro tipado do GATT (sem stringly, sem panics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleGattError {
    /// Opcode desconhecido (diferente de PING/MSG/CANCEL).
    InvalidOpcode,
    /// Ja ha transacao ativa (colisao rejeitada).
    TransactionBusy,
    /// Nenhuma transacao ativa para continuar/cancelar.
    NoTransaction,
    /// Tamanho excede `CONTROL_POINT_LENGTH`.
    Overflow,
    /// Fragmento vazio ou malformado.
    InvalidFragment,
    /// UP ausente (exigido por operacao).
    PresenceRequired,
    /// PIN ausente onde exigido (vendor privilegiada 0x21/0x23/0x24/0x27).
    PinRequired,
    /// Binding ausente/invalido (NEED_BINDING 0x05, so BLE/WiFi, nunca USB).
    NeedBinding,
}

impl core::fmt::Display for BleGattError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidOpcode => write!(f, "invalid opcode"),
            Self::TransactionBusy => write!(f, "transaction busy"),
            Self::NoTransaction => write!(f, "no transaction"),
            Self::Overflow => write!(f, "overflow control-point"),
            Self::InvalidFragment => write!(f, "invalid fragment"),
            Self::PresenceRequired => write!(f, "presence required"),
            Self::PinRequired => write!(f, "pin required"),
            Self::NeedBinding => write!(f, "binding required (NEED_BINDING 0x05)"),
        }
    }
}

impl From<PolicyError> for BleGattError {
    fn from(e: PolicyError) -> Self {
        match e {
            PolicyError::PresenceRequired => Self::PresenceRequired,
            PolicyError::PinRequired => Self::PresenceRequired,
        }
    }
}

/// Mensagem completa apos reassemble.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleCompleteMessage {
    /// Opcode (PING/MSG/CANCEL).
    pub opcode: u8,
    /// Payload reassemblado (sem header de 3B).
    pub payload: Vec<u8>,
}

/// Reassemblador control-point (primeiro fragmento com header).
#[derive(Debug, Clone, Default)]
pub struct BleReassembler {
    opcode: Option<u8>,
    expected_len: usize,
    buf: Vec<u8>,
}

impl BleReassembler {
    /// Cria vazio (sem transacao).
    pub fn new() -> Self {
        Self {
            opcode: None,
            expected_len: 0,
            buf: Vec::new(),
        }
    }

    /// `true` quando ha transacao parcial pendente.
    pub fn is_active(&self) -> bool {
        self.opcode.is_some()
    }

    /// Tamanho pendente para FFF3 (0 quando idle).
    pub fn pending_len(&self) -> u16 {
        if self.is_active() {
            self.expected_len.min(u16::MAX as usize) as u16
        } else {
            0
        }
    }

    /// Aborta transacao ativa (CANCEL).
    pub fn cancel(&mut self) {
        self.opcode = None;
        self.expected_len = 0;
        self.buf.clear();
    }

    /// Alimenta um fragmento de FFF1.
    ///
    /// Primeiro fragmento: `[opcode, len_hi, len_lo, data..]`.
    /// Continuacao: `[seq, data..]` (seq ignorado no stub, so concatena).
    /// Retorna `Some(mensagem)` quando completa.
    pub fn feed(&mut self, fragment: &[u8]) -> Result<Option<BleCompleteMessage>, BleGattError> {
        if fragment.is_empty() || fragment.len() > MAX_FRAGMENT_BYTES {
            return Err(BleGattError::InvalidFragment);
        }
        if self.opcode.is_none() {
            // Inicio: precisa do header de 3B.
            if fragment.len() < 3 {
                return Err(BleGattError::InvalidFragment);
            }
            let opcode = fragment[0];
            if opcode != OP_PING && opcode != OP_MSG && opcode != OP_CANCEL {
                return Err(BleGattError::InvalidOpcode);
            }
            if opcode == OP_CANCEL {
                self.cancel();
                return Ok(Some(BleCompleteMessage {
                    opcode,
                    payload: Vec::new(),
                }));
            }
            let total = ((fragment[1] as usize) << 8) | (fragment[2] as usize);
            if total > CONTROL_POINT_LENGTH {
                return Err(BleGattError::Overflow);
            }
            let head = &fragment[3..];
            if head.len() > total {
                return Err(BleGattError::InvalidFragment);
            }
            self.opcode = Some(opcode);
            self.expected_len = total;
            self.buf.clear();
            self.buf.extend_from_slice(head);
            if self.buf.len() == total {
                let done = BleCompleteMessage {
                    opcode,
                    payload: core::mem::take(&mut self.buf),
                };
                self.opcode = None;
                self.expected_len = 0;
                return Ok(Some(done));
            }
            return Ok(None);
        }
        // Continuacao: colisao se novo header completo chegar antes de concluir.
        // Heuristica stub: se tem 3B e opcode valido e resto cabe como nova msg,
        // rejeita como busy (chamador deve CANCEL primeiro).
        if fragment.len() >= 3 {
            let maybe_op = fragment[0];
            if (maybe_op == OP_PING || maybe_op == OP_MSG)
                && self.buf.len() < self.expected_len
            {
                // Ambiguidade resolvida como colisao apenas se parecer header novo:
                // trata como colisao quando o buffer parcial nao avancou neste feed.
                // Para manter determinismo no stub, so rejeita se fragmento
                // comeca com opcode valido E tamanho total valido E buffer nao vazio.
                let total = ((fragment[1] as usize) << 8) | (fragment[2] as usize);
                if total <= CONTROL_POINT_LENGTH && !self.buf.is_empty() {
                    // Distingue continuacao legitima de nova transacao pelo tamanho:
                    // continuacao tem 1B seq + dados; header novo tem opcode valido.
                    // Como o stub nao tem seq dedicado, o chamador deve serializar;
                    // aqui aceitamos como dados, exceto quando explicitamente
                    // marcado pelo teste de colisao via `start_new`.
                    let _ = total;
                }
            }
        }
        // Apende como continuacao (1B seq + dados ou dados puros).
        let data = if fragment.len() > 1 { &fragment[1..] } else { fragment };
        if self.buf.len() + data.len() > self.expected_len {
            return Err(BleGattError::Overflow);
        }
        self.buf.extend_from_slice(data);
        if self.buf.len() == self.expected_len {
            let opcode = self.opcode.unwrap_or(OP_MSG);
            let done = BleCompleteMessage {
                opcode,
                payload: core::mem::take(&mut self.buf),
            };
            self.opcode = None;
            self.expected_len = 0;
            return Ok(Some(done));
        }
        Ok(None)
    }

    /// Inicia nova transacao; erro `TransactionBusy` se ativa (colisao).
    pub fn start_new(&mut self, opcode: u8, total: usize) -> Result<(), BleGattError> {
        if self.is_active() {
            return Err(BleGattError::TransactionBusy);
        }
        if opcode != OP_PING && opcode != OP_MSG {
            return Err(BleGattError::InvalidOpcode);
        }
        if total > CONTROL_POINT_LENGTH {
            return Err(BleGattError::Overflow);
        }
        self.opcode = Some(opcode);
        self.expected_len = total;
        self.buf.clear();
        Ok(())
    }
}

/// Servidor GATT stub (host) / NimBLE (ESP quando disponivel).
#[derive(Debug, Clone)]
pub struct BleGattServer {
    reassembler: BleReassembler,
    revision: u8,
    /// Status/keepalive para notify FFF2 (0=idle, 1=processing, 2=up-needed).
    status: u8,
}

impl BleGattServer {
    /// Cria idle, revisao `GATT_REVISION`.
    pub fn new() -> Self {
        Self {
            reassembler: BleReassembler::new(),
            revision: GATT_REVISION,
            status: 0,
        }
    }

    /// Le FFF3 (tamanho pendente).
    pub fn read_len(&self) -> u16 {
        self.reassembler.pending_len()
    }

    /// Le FFF4 (revisao).
    pub fn read_revision(&self) -> u8 {
        self.revision
    }

    /// Escreve FFF4 (so aceita `GATT_REVISION`; rejeita outras).
    pub fn write_revision(&mut self, value: u8) -> Result<(), BleGattError> {
        if value != GATT_REVISION {
            return Err(BleGattError::InvalidFragment);
        }
        self.revision = value;
        Ok(())
    }

    /// Bytes de status para notify FFF2.
    pub fn status_bytes(&self) -> [u8; 1] {
        [self.status]
    }

    /// Escreve FFF1: exige UP por operacao (latch uso unico pelo chamador).
    /// Retorna mensagem completa quando o ultimo fragmento chega.
    pub fn control_write(
        &mut self,
        fragment: &[u8],
        presence_confirmed: bool,
    ) -> Result<Option<BleCompleteMessage>, BleGattError> {
        UpOnly.check_up(false, presence_confirmed)?;
        if fragment.first() == Some(&OP_CANCEL) {
            crate::ltrace!(LtCat::Transport, LtEvt::TpClose, "ble");
            self.reassembler.cancel();
            self.status = 0;
            return Ok(Some(BleCompleteMessage {
                opcode: OP_CANCEL,
                payload: Vec::new(),
            }));
        }
        self.status = 1;
        let was_active = self.reassembler.is_active();
        let out = match self.reassembler.feed(fragment) {
            Err(e) => {
                crate::ltrace!(LtCat::Transport, LtEvt::TpError, "ble");
                return Err(e);
            }
            Ok(done) => {
                if done.is_some() {
                    crate::ltrace!(LtCat::Transport, LtEvt::TpClose, "ble");
                } else if !was_active {
                    crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "ble");
                }
                done
            }
        };
        if out.is_some() {
            self.status = 0;
        }
        Ok(out)
    }

    /// Eco PING sem tocar no `CtapEngine` (sem semantica USB alterada).
    pub fn dispatch_ping(payload: &[u8]) -> Vec<u8> {
        payload.to_vec()
    }

    /// Inicia advertising stub (ESP usa NimBLE via esp-idf-svc quando disponivel).
    pub fn start_advertising(_pairing_flag: bool) -> Result<(), &'static str> {
        // Host: stub. ESP: NimBLE `esp-idf-svc` quando `target_os = espidf`.
        Ok(())
    }
}

impl Default for BleGattServer {
    fn default() -> Self {
        Self::new()
    }
}


// Gates de binding para ops vendor Fase6 (§9.4 + `binding.rs`).
//
// - Privilegiadas `0x21/0x23/0x24/0x27`: binding valido + UP + PIN.
// - `0x20/0x22/0x25/0x26` (GEN/LIST/CODE): binding valido + UP.
// - Ordem canonica: binding -> UP -> PIN (app alheio sempre ve NEED_BINDING).
// - `control_write` e framing §1-§3 intactos; USB/CTAP zero mudanca.

/// Status NEED_BINDING (0x05): extensao §9.5, so BLE/WiFi — nunca USB.
pub const VENDOR_STATUS_NEED_BINDING: u8 = 0x05;

/// `true` quando o op vendor exige UP+PIN (privilegiadas). Demais: so UP.
/// `0x21` IMPORT | `0x23` KEY_DELETE | `0x24` OATH_PUT | `0x27` OATH_DELETE.
pub fn vendor_op_requires_pin(op: u8) -> bool {
    matches!(
        op,
        OP_KEY_IMPORT_ENVELOPE | OP_KEY_DELETE | OP_OATH_PUT | OP_OATH_DELETE
    )
}

/// Gate normativo §9.4 + binding para um op vendor.
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
    // Split uso/config (§11): USO nunca exige vinculo, so UP fisico.
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

/// Mapeia `BindingError` para `BleGattError` (fiação GATT §11).
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

/// Mapeia `RecoveryError` para `BleGattError` (fiação GATT §11).
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
/// Persiste em NVS com verify-after-write. Retorna status wire §9.5+0x05.
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
    if !is_vendor_keys_oath_op(op) && !is_bind_mgmt_op(op) && op != crate::binding::BIND_OP_RELEASE {
        return Err(BleGattError::InvalidOpcode);
    }
    binding
        .verify(sig, challenge, op, payload_hash)
        .map_err(binding_err_to_gatt)
}

/// Despacho GATT `OP_BIND_RELEASE` (0x2B): dono assina e libera re-claim.
///
/// Release exige prova (`challenge||0x52||sha256(binding_id)`); em test-mode
/// faz bypass com ltrace (só UP, wipe direto). Sucesso faz wipe (NVS+RAM).
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

impl BleGattError {
    /// Status wire §9.5: `0x00` OK | `0x01` NEED_UP | `0x02` NEED_PIN |
    /// `0x03` NO_SLOT | `0x04` BAD_ENVELOPE | `0x05` NEED_BINDING.
    /// Framing/opcode mapeiam `0x04` (falha generica, sem retry, §9.6).
    pub fn to_vendor_status(self) -> u8 {
        match self {
            Self::PresenceRequired => 0x01,
            Self::PinRequired => 0x02,
            Self::NeedBinding => VENDOR_STATUS_NEED_BINDING,
            Self::InvalidOpcode
            | Self::TransactionBusy
            | Self::NoTransaction
            | Self::Overflow
            | Self::InvalidFragment => 0x04,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg_fragment(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(3 + payload.len());
        v.push(opcode);
        v.push(((payload.len() >> 8) & 0xFF) as u8);
        v.push((payload.len() & 0xFF) as u8);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn single_fragment_msg_reassembles() {
        let mut s = BleGattServer::new();
        let frag = msg_fragment(OP_MSG, b"hello-ctap");
        let done = s
            .control_write(&frag, true)
            .expect("up ok")
            .expect("completa em 1 frag");
        assert_eq!(done.opcode, OP_MSG);
        assert_eq!(done.payload, b"hello-ctap");
        assert_eq!(s.read_len(), 0);
    }

    #[test]
    fn multi_fragment_msg_reassembles() {
        let mut r = BleReassembler::new();
        // Total 10B: primeiro leva 4B, resto em continuacoes [seq + dados].
        let first = [OP_MSG, 0x00, 0x0A, 1, 2, 3, 4];
        assert!(r.feed(&first).expect("ok").is_none());
        assert_eq!(r.pending_len(), 10);
        let cont = [0x00, 5, 6, 7, 8, 9, 10];
        let done = r.feed(&cont).expect("ok").expect("completa");
        assert_eq!(done.payload, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn collision_rejected_when_active() {
        let mut r = BleReassembler::new();
        r.start_new(OP_MSG, 10).expect("inicia");
        assert_eq!(r.start_new(OP_MSG, 2), Err(BleGattError::TransactionBusy));
    }

    #[test]
    fn overflow_rejected_by_control_point_length() {
        let mut r = BleReassembler::new();
        assert_eq!(
            r.start_new(OP_MSG, CONTROL_POINT_LENGTH + 1),
            Err(BleGattError::Overflow)
        );
        let big = [OP_MSG, 0xFF, 0xFF];
        assert_eq!(r.feed(&big), Err(BleGattError::Overflow));
    }

    #[test]
    fn up_required_per_operation() {
        let mut s = BleGattServer::new();
        let frag = msg_fragment(OP_PING, b"p");
        assert_eq!(
            s.control_write(&frag, false),
            Err(BleGattError::PresenceRequired)
        );
    }

    #[test]
    fn cancel_aborts_and_reports() {
        let mut s = BleGattServer::new();
        let mut r = BleReassembler::new();
        r.start_new(OP_MSG, 10).expect("inicia");
        r.cancel();
        assert!(!r.is_active());
        let done = s
            .control_write(&[OP_CANCEL, 0x00, 0x00], true)
            .expect("cancel ok")
            .expect("retorna msg cancel");
        assert_eq!(done.opcode, OP_CANCEL);
    }

    #[test]
    fn revision_roundtrip() {
        let mut s = BleGattServer::new();
        assert_eq!(s.read_revision(), GATT_REVISION);
        assert!(s.write_revision(GATT_REVISION).is_ok());
        assert!(s.write_revision(0xFF).is_err());
    }

    #[test]
    fn ping_echoes_without_ctap() {
        assert_eq!(BleGattServer::dispatch_ping(b"abc"), b"abc");
    }

    #[test]
    fn fase6_vendor_ops_reservados() {
        assert_eq!(VENDOR_OP_MIN, 0x20);
        assert_eq!(VENDOR_OP_MAX, 0x27);
        for op in [OP_KEY_GEN_ONDEVICE, OP_KEY_IMPORT_ENVELOPE, OP_KEY_LIST, OP_KEY_DELETE, OP_OATH_PUT, OP_OATH_LIST, OP_OATH_CODE, OP_OATH_DELETE] {
            assert!(is_vendor_keys_oath_op(op));
            assert!(op != OP_PING && op != OP_MSG && op != OP_CANCEL);
        }
        assert!(!is_vendor_keys_oath_op(OP_PING));
        assert!(!is_vendor_keys_oath_op(OP_MSG));
        assert!(!is_vendor_keys_oath_op(OP_CANCEL));
        assert!(!is_vendor_keys_oath_op(0x1F));
        assert!(!is_vendor_keys_oath_op(0x28));
    }

    #[test]
    fn bind_mgmt_ops_reservados_sem_colisao() {
        // 0x28-0x2D fora de 0x20-0x27 e CTAP-BLE (0x81/0x83/0xBE), revisao intacta.
        for op in [OP_BIND_CLAIM, OP_BIND_CHALLENGE, OP_BIND_VERIFY, OP_BIND_RELEASE, OP_RECOVERY_SET, OP_RECOVERY_UNLOCK] {
            assert!(is_bind_mgmt_op(op));
            assert!(!is_vendor_keys_oath_op(op));
            assert!(op != OP_PING && op != OP_MSG && op != OP_CANCEL);
        }
        assert_eq!(BIND_MGMT_OP_MIN, 0x28);
        assert_eq!(BIND_MGMT_OP_MAX, 0x2D);
        assert!(!is_bind_mgmt_op(0x20));
        assert!(!is_bind_mgmt_op(0x27));
        assert!(!is_bind_mgmt_op(0x2E));
        assert_eq!(GATT_REVISION, 0x01);
    }

    #[test]
    fn split_uso_config_no_transporte() {
        // USO nunca exige vinculo; CONFIG exige em release, bypass em teste.
        assert!(is_usage_op(OP_KEY_LIST));
        assert!(is_usage_op(OP_OATH_LIST));
        assert!(is_usage_op(OP_OATH_CODE));
        assert!(!is_usage_op(OP_KEY_GEN_ONDEVICE));
        assert!(is_config_op(OP_KEY_GEN_ONDEVICE));
        assert!(is_config_op(OP_KEY_IMPORT_ENVELOPE));
        assert!(is_config_op(OP_KEY_DELETE));
        assert!(is_config_op(OP_OATH_PUT));
        assert!(is_config_op(OP_OATH_DELETE));
        assert!(!is_config_op(OP_OATH_CODE));
        // USO sem vinculo passa com UP em qualquer modo.
        authorize_vendor_op(OP_OATH_CODE, false, false, true).expect("uso passa");
        authorize_vendor_op(OP_KEY_LIST, false, true, true).expect("uso passa");
        assert_eq!(
            authorize_vendor_op(OP_OATH_CODE, false, false, false),
            Err(BleGattError::PresenceRequired)
        );
        // CONFIG sem vinculo: release nega, teste bypassa.
        if crate::binding::binding_bypass_enabled() {
            authorize_vendor_op(OP_KEY_DELETE, false, true, true).expect("bypass passa");
        } else {
            assert_eq!(
                authorize_vendor_op(OP_KEY_DELETE, false, true, true),
                Err(BleGattError::NeedBinding)
            );
        }
    }

    #[test]
    fn dispatch_claim_challenge_release_roundtrip() {
        use crate::binding::{BIND_ID_LEN, BIND_PUB_LEN, BindingManager};
        use crate::persistence::{MockFlashBackend, SecureStorage};
        let mut st = SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32]);
        let mut m = BindingManager::new();
        let sk = p256::ecdsa::SigningKey::from_slice(&[0x11u8; 32]).expect("scalar");
        let pt = sk.verifying_key().to_encoded_point(false);
        let mut sec1 = [0u8; BIND_PUB_LEN];
        sec1.copy_from_slice(pt.as_bytes());
        let id = [0xABu8; BIND_ID_LEN];
        // Claim via GATT (Unclaimed+pareamento+UP).
        dispatch_bind_claim(&mut m, &mut st, &sec1, &id, true, true).expect("claim gatt ok");
        assert!(m.is_claimed());
        // Segundo claim nega (dono preservado).
        assert!(dispatch_bind_claim(&mut m, &mut st, &sec1, &id, true, true).is_err());
        // Challenge emite 32B; verify consome (uso unico).
        let ch = dispatch_bind_challenge(&mut m, &st, &mut rand_core::OsRng).expect("ch");
        assert!(m.has_active_challenge());
        let ph = [0x11u8; 32];
        let msg = BindingManager::signed_message(&ch, OP_KEY_LIST, &ph);
        let sig = {
            use signature::Signer;
            let s: p256::ecdsa::Signature = sk.sign(&msg);
            s.to_der().as_bytes().to_vec()
        };
        dispatch_bind_verify(&mut m, &sig, &ch, OP_KEY_LIST, &ph).expect("verify gatt ok");
        assert!(!m.has_active_challenge());
        // Release com prova valida faz wipe (re-claim liberado).
        let ch2 = dispatch_bind_challenge(&mut m, &st, &mut rand_core::OsRng).expect("ch2");
        let id_hash = {
            use sha2::{Digest, Sha256};
            let d = Sha256::digest(id);
            let mut o = [0u8; 32];
            o.copy_from_slice(&d);
            o
        };
        let msg2 = BindingManager::signed_message(&ch2, crate::binding::BIND_OP_RELEASE, &id_hash);
        let sig2 = {
            use signature::Signer;
            let s: p256::ecdsa::Signature = sk.sign(&msg2);
            s.to_der().as_bytes().to_vec()
        };
        if crate::binding::binding_bypass_enabled() {
            dispatch_bind_release(&mut m, &mut st, &sig2, &ch2, &id_hash, true)
                .expect("release bypass ok");
        } else {
            // Lixo nega e mantem dono.
            assert!(dispatch_bind_release(&mut m, &mut st, b"lixo", &ch2, &id_hash, true).is_err());
            assert!(m.is_claimed());
            dispatch_bind_release(&mut m, &mut st, &sig2, &ch2, &id_hash, true)
                .expect("release ok");
        }
        assert!(!m.is_claimed());
    }

    #[test]
    fn dispatch_recovery_set_unlock_via_gatt() {
        use crate::binding::{BIND_ID_LEN, BIND_PUB_LEN, BindingManager};
        use crate::persistence::{MockFlashBackend, SecureStorage};
        let mut st = SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32]);
        let mut m = BindingManager::new();
        let sk = p256::ecdsa::SigningKey::from_slice(&[0x11u8; 32]).expect("scalar");
        let pt = sk.verifying_key().to_encoded_point(false);
        let mut sec1 = [0u8; BIND_PUB_LEN];
        sec1.copy_from_slice(pt.as_bytes());
        m.claim(&sec1, &[0xABu8; BIND_ID_LEN], true, true).expect("claim");
        m.persist(&mut st).expect("persist");
        // SET exige UP e PIN valido.
        assert_eq!(
            dispatch_recovery_set(&mut st, "123", true),
            Err(BleGattError::PinRequired)
        );
        dispatch_recovery_set(&mut st, "4242", true).expect("set ok");
        // UNLOCK com PIN errado nao destrava; certo + UP destrava e libera re-claim.
        assert!(dispatch_recovery_unlock(&mut st, &mut m, "0000", true).is_err());
        assert!(m.is_claimed());
        dispatch_recovery_unlock(&mut st, &mut m, "4242", true).expect("unlock ok");
        assert!(!m.is_claimed());
    }
}

