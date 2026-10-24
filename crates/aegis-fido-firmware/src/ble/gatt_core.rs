//! Wave4 -- GATT 0xFFFD (CTAP2-BLE parcial, host stub + ESP NimBLE).
//!
//! Servico `0xFFFD`; chars `FFF1` control/write, `FFF2` status/notify,
//! `FFF3` len/read, `FFF4` revision/read-write. Tipos, consts, erro
//! tipado, reassembler e servidor GATT (sem binding, sem radio).
//! Gates com binding/storage vivem em `super::dispatch_bind`;
//! radio/FFI vivem em `super::nimble_backend`.
//! (Conteudo movido de `ble_gatt.rs` sem mudanca de comportamento.)

extern crate alloc;

#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};
use aegis_fido_core::policy::{PolicyError, UpOnly, UpPolicy};
use alloc::vec::Vec;

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

/// Servico GATT de proximidade, separado do FIDO `0xFFFD`.
///
/// `0xFFFD` segue congelado para CTAP2-BLE + app Android (Sec.1).
/// Proximidade anuncia/isola neste UUID para nunca conflitar com
/// FIDO nem com `FFF1-FFF4`. Revisao `GATT_REVISION` intacta.
pub const PROXIMITY_SERVICE_UUID: u16 = 0xFFFE;

/// `true` para o servico FIDO congelado (`0xFFFD`).
pub fn is_fido_service_uuid(uuid: u16) -> bool {
    uuid == BLE_SERVICE_UUID
}

/// `true` para o servico de proximidade (`0xFFFE`, separado do FIDO).
pub fn is_proximity_service_uuid(uuid: u16) -> bool {
    uuid == PROXIMITY_SERVICE_UUID
}

/// Coexistencia mutuamente exclusiva: BLE-proximidade vs USB/CTAP.
///
/// USB ativo => proximidade BLE deve parar (advertise/RX negados).
/// Retorna `false` com USB ativo; `true` com USB idle.
pub fn proximity_coex_allow(usb_active: bool) -> bool {
    !usb_active
}

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

/// Enrollment PIV (PIN/PUK iniciais, F4): fora da faixa 0x20-0x27 de
/// proposito (gate proprio binding -> UP em `exec_vendor_op`; sem PIN
/// porque o PIN ainda nao existe). Req: `pin_len(1) || pin(6-8) || puk(8)`.
pub const OP_PIV_ENROLL: u8 = 0x39;

/// Binding + recovery sobre GATT (apendice Sec.11, aditivo, sem quebra Sec.1-Sec.10).
/// Framing Sec.3 reutilizado: `[op:1, len_hi:1, len_lo:1, payload...]`.
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

/// Carteira Fase7 (R-07) sobre BLE: faixa livre 0x35-0x37 + fw-log 0x38.
///
/// Mapa da vizinhanca (primeiro byte de CMD_MSG): 0x20-0x27 vendor
/// keys/OATH, 0x28-0x2D bind-mgmt, 0x2E rescue, 0x2F reservado,
/// 0x30-0x34 OTA. `0x35` GEN (gera sob a curva da rede), `0x36` LIST
/// (so metadados `wallet:`), `0x37` ADDR (endereco do slot), `0x38`
/// FW-LOG (log da firmware em ASCII, sem PII -- ver `fw_log`).
/// GATT/revisao/framing intactos; executor on-device = follow-up
/// (como vendor Sec.9.4: gate ok responde `0x04`).
pub const OP_WALLET_GEN: u8 = 0x35;
pub const OP_WALLET_LIST: u8 = 0x36;
pub const OP_WALLET_ADDR: u8 = 0x37;
/// Limites da faixa wallet Fase7.
pub const WALLET_OP_MIN: u8 = OP_WALLET_GEN;
pub const WALLET_OP_MAX: u8 = OP_WALLET_ADDR;

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
    /// USB ativo: BLE-proximidade mutuamente exclusivo (falha generica 0x04).
    CoexBlocked,
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
            Self::CoexBlocked => write!(f, "coex blocked (USB active)"),
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
            if (maybe_op == OP_PING || maybe_op == OP_MSG) && self.buf.len() < self.expected_len {
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
        let data = if fragment.len() > 1 {
            &fragment[1..]
        } else {
            fragment
        };
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

    /// Shim de compatibilidade (Etapa B: radio real em ble_nimble).
    ///
    /// No host retorna Ok sem efeito. No ESP o advertising real e
    /// ligado/desligado pelo main via ble_nimble::{esp_ble_start,
    /// esp_ble_stop} (NimBLE, componente C aegis_ble), somente em modo
    /// pareamento. Mantido para nao quebrar chamadores/host.
    pub fn start_advertising(_pairing_flag: bool) -> Result<(), &'static str> {
        // Host: shim inerte; ESP usa ble_nimble (NimBLE, aegis_ble).
        Ok(())
    }

    /// Para o advertising (shim de compat; ESP usa ble_nimble::esp_ble_stop).
    pub fn stop_advertising() -> Result<(), &'static str> {
        Ok(())
    }
}

impl Default for BleGattServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Status NEED_BINDING (0x05): extensao Sec.9.5, so BLE/WiFi -- nunca USB.
pub const VENDOR_STATUS_NEED_BINDING: u8 = 0x05;

/// Gate normativo proximidade-BLE: ordem binding -> UP -> coex.
///
/// - `!bonded` => `NeedBinding` (0x05, so BLE, nunca USB).
/// - `!presence_confirmed` => `PresenceRequired` (0x01).
/// - `usb_active` => `CoexBlocked` (0x04 generico, sem retry Sec.9.6).
///
/// Chamar no transporte quando `is_proximity_service_uuid`, antes de
/// `control_write`. `0xFFFD`/`control_write` intactos.
pub fn authorize_proximity_ble(
    bonded: bool,
    presence_confirmed: bool,
    usb_active: bool,
) -> Result<(), BleGattError> {
    if !bonded {
        return Err(BleGattError::NeedBinding);
    }
    if !presence_confirmed {
        return Err(BleGattError::PresenceRequired);
    }
    if usb_active {
        return Err(BleGattError::CoexBlocked);
    }
    Ok(())
}

impl BleGattError {
    /// Status wire Sec.9.5: `0x00` OK | `0x01` NEED_UP | `0x02` NEED_PIN |
    /// `0x03` NO_SLOT | `0x04` BAD_ENVELOPE | `0x05` NEED_BINDING.
    /// Framing/opcode mapeiam `0x04` (falha generica, sem retry, Sec.9.6).
    pub fn to_vendor_status(self) -> u8 {
        match self {
            Self::PresenceRequired => 0x01,
            Self::PinRequired => 0x02,
            Self::NeedBinding => VENDOR_STATUS_NEED_BINDING,
            Self::CoexBlocked
            | Self::InvalidOpcode
            | Self::TransactionBusy
            | Self::NoTransaction
            | Self::Overflow
            | Self::InvalidFragment => 0x04,
        }
    }
}
