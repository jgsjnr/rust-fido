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

/// OTA sobre GATT (faixa livre `0x30-0x34`, aditiva, sem quebra Sec.1-Sec.11).
///
/// Framing Sec.3 reutilizado: `[op:1, len_hi:1, len_lo:1, payload...]` +
/// continuacao `[seq:1, data..]`. Fonte canonica dos valores:
/// `crate::ota::{OP_OTA_BEGIN, OP_OTA_CHUNK, OP_OTA_FINISH, OP_OTA_COMMIT,
/// OP_OTA_ABORT}`; estes limites espelham essa faixa para o transporte
/// validar sem acoplar a maquina OTA. `0x33` COMMIT executa SOMENTE via
/// USB/CTAPHID: o transporte BLE aceita o framing fail-closed (sem braco
/// de execucao no `ble_dispatch`, que responde `0x04` generico), nunca
/// executa swap. `0x2F` reservado segue rejeitado.
pub const OTA_OP_MIN: u8 = 0x30;
/// Limite superior da faixa OTA sobre GATT (ver `OTA_OP_MIN`).
pub const OTA_OP_MAX: u8 = 0x34;

/// `true` para opcodes que abrem transacao no reassembler: CTAP-BLE
/// (`0x81` PING / `0x83` MSG), bind-mgmt `0x28-0x2D`, OTA `0x30-0x34`,
/// carteira `0x35-0x37` + compat `0x48-0x4B` (F4/F6: o funil BLE executa
/// GEN/LIST/ADDR/PENDING/PSBT via `wallet_exec::wallet_dispatch` com os
/// gates canonicos; PSBT exige ainda o recibo de aprovacao mediada pelo
/// app mais PIN),
/// GET_CAPS `0x3F` (advertisement read-only, sem auth) e SET_UP_POLICY
/// `0x40` (management gated: binding + sessao PIN viva, sem latch UP) e
/// VENDOR_SIGN `0x41` (SIGN dedicado, classe GEN: binding + UP, sem PIN) e
/// PM `0x43..=0x47` (password manager device-only: binding -> UP -> PIN ->
/// janela 60 s; fora da capability o reassembler rejeita fail-closed).
///
/// `0xBE` CANCEL tem caminho proprio (aborta a transacao); `0x2E` rescue
/// viaja SOMENTE como payload de `OP_MSG` (`[0x2E, frame...]`), nunca como
/// opcode de fragmento; `0x2F` reservado e demais valores negam fail-closed
/// com `InvalidOpcode`.
pub fn is_ble_fragment_opcode(op: u8) -> bool {
    op == OP_PING
        || op == OP_MSG
        || (BIND_MGMT_OP_MIN..=BIND_MGMT_OP_MAX).contains(&op)
        || (OTA_OP_MIN..=OTA_OP_MAX).contains(&op)
        || (WALLET_OP_MIN..=WALLET_OP_MAX).contains(&op)
        || (WALLET_COMPAT_OP_MIN..=WALLET_COMPAT_OP_MAX).contains(&op)
        || crate::vendor_exec::is_get_caps_op(op)
        || crate::ctap_cmd::is_set_up_policy_op(op)
        || crate::vendor_exec::is_vendor_sign_op(op)
        || is_pm_fragment_opcode(op)
}

/// `true` para a familia PM `0x43..=0x47` no reassembler BLE.
///
/// Diet: fora da capability (`cap-fido-only` / `cap-fido-totp`) sempre
/// `false` (fail-closed `InvalidOpcode`, sem queda silenciosa); o funil
/// BLE responde `UNSUPPORTED_FEATURE` (`0x06`) antes de qualquer gate.
pub fn is_pm_fragment_opcode(op: u8) -> bool {
    #[cfg(not(any(feature = "cap-fido-only", feature = "cap-fido-totp")))]
    {
        crate::pm_store::is_pm_op(op)
    }
    #[cfg(any(feature = "cap-fido-only", feature = "cap-fido-totp"))]
    {
        let _ = op;
        false
    }
}

/// Backoff por op sensivel (PM `0x43..=0x47`): vocabulario compartilhado
/// entre funis, compilado em todos os presets inclusive diet.
///
/// O tipo real ([`crate::pm_store::PmRateLimiter`], RAM por sessao) existe
/// so fora da diet; a diet passa `()` (no-op sempre aberto: o funil diet
/// nega `0x06` antes de qualquer gate, entao o limiter nunca e consultado
/// de verdade). `poll` fail-closed nega `Err(0x04)`; `record` contabiliza
/// so falhas autenticadas (`0x03`/`0x04`), nunca negacoes de gate.
pub trait PmBackoffGate {
    /// Fail-closed durante o backoff (`Err(0x04)`).
    fn poll(&self, now_ms: u64) -> Result<(), u8>;
    /// Contabiliza um desfecho autenticado (`0x00` reseta o orcamento).
    fn record(&mut self, status: u8, now_ms: u64);
}

/// Diet/no-op: sempre aberto, nada contabilizado.
impl PmBackoffGate for () {
    fn poll(&self, _now_ms: u64) -> Result<(), u8> {
        Ok(())
    }
    fn record(&mut self, _status: u8, _now_ms: u64) {}
}

/// Carteira Fase7 (R-07) sobre BLE: faixa livre 0x35-0x37 + fw-log 0x38.
///
/// Mapa da vizinhanca (primeiro byte de CMD_MSG): 0x20-0x27 vendor
/// keys/OATH, 0x28-0x2D bind-mgmt, 0x2E rescue, 0x2F reservado,
/// 0x30-0x34 OTA. `0x35` GEN (gera sob a curva da rede), `0x36` LIST
/// (so metadados `wallet:`), `0x37` ADDR (endereco do slot), `0x38`
/// FW-LOG (log da firmware em ASCII, sem PII -- ver `fw_log`).
/// GATT/revisao/framing intactos; executor on-device via
/// `wallet_exec::wallet_dispatch` (gates binding -> UP; PSBT exige ainda
/// o recibo de aprovacao mediada pelo app mais PIN).
///
/// Compatibilidade F1 (reserva, execucao parcial em F2-F4) + F6 preview:
/// `0x48` DERIVE (derivacao hierarquica, sem execucao no fio), `0x49`
/// XPUB (exportacao de chave publica estendida, sem execucao no fio),
/// `0x4A` PSBT (envelope de assinatura; com aprovacao mediada pelo app
/// em F4 -- sem dependencia de display na placa, por decisao do dono: o
/// app exibe os detalhes e retorna approve/deny, e o firmware so assina
/// apos a aprovacao mais binding -> UP -> PIN), `0x4B` PENDING (F6:
/// expoe o preview `[slot, tx_hash, counts]` para o app exibir antes de
/// decidir; display precede autenticacao, sem PIN). Faixa `0x35`-`0x37`
/// congelada; `0x48`-`0x4B` sao os primeiros bytes livres apos o PM
/// `0x43`-`0x47` (nunca `0x20`-`0x27`, `0x30`-`0x34`, `0x2E`/`0x2F`/`0x38`
/// /`0x39`).
pub const OP_WALLET_GEN: u8 = 0x35;
pub const OP_WALLET_LIST: u8 = 0x36;
pub const OP_WALLET_ADDR: u8 = 0x37;
/// Limites da faixa wallet Fase7 (congelados).
pub const WALLET_OP_MIN: u8 = OP_WALLET_GEN;
pub const WALLET_OP_MAX: u8 = OP_WALLET_ADDR;
/// Reserva F1: derivacao hierarquica (execucao em F2; ate la `0x04`
/// fail-closed apos gate ok, `0x06` nas dietas).
pub const OP_WALLET_DERIVE: u8 = 0x48;
/// Reserva F1: exportacao de chave publica estendida (execucao em F3).
pub const OP_WALLET_XPUB: u8 = 0x49;
/// Reserva F1: envelope de assinatura PSBT (F4 executa via
/// `wallet_exec::wallet_dispatch` com aprovacao mediada pelo app:
/// sem recibo `approve` nao ha assinatura).
pub const OP_WALLET_PSBT: u8 = 0x4A;
/// F6: preview da transacao pendente (firmware expoe `[slot, tx_hash,
/// counts]` para o app exibir antes de decidir approve/deny; display
/// precede autenticacao, entao o gate e binding -> UP, sem PIN).
pub const OP_WALLET_PENDING: u8 = 0x4B;
/// Limites da faixa de compatibilidade wallet F1/F6 (reservada).
pub const WALLET_COMPAT_OP_MIN: u8 = OP_WALLET_DERIVE;
pub const WALLET_COMPAT_OP_MAX: u8 = OP_WALLET_PENDING;

/// Opcodes Secure Guard (0x3A..0x3E).
pub const OP_SECURE_GUARD_STATUS: u8 = 0x3A;
pub const OP_SECURE_GUARD_UNLOCK: u8 = 0x3B;
pub const OP_SECURE_GUARD_LOCK: u8 = 0x3C;
pub const OP_SECURE_GUARD_CONFIG: u8 = 0x3D;
pub const OP_SECURE_GUARD_WIPE_SELECTIVE: u8 = 0x3E;
/// Limites da faixa Secure Guard.
pub const SECURE_GUARD_OP_MIN: u8 = OP_SECURE_GUARD_STATUS;
pub const SECURE_GUARD_OP_MAX: u8 = OP_SECURE_GUARD_WIPE_SELECTIVE;

/// Limite de reassemble (== envelope MAX-ESP, sem alloc extra).
pub const CONTROL_POINT_LENGTH: usize = 512;
/// Revisao GATT inicial (FFF4).
pub const GATT_REVISION: u8 = 0x01;
/// Tamanho maximo de fragmento aceito por write (MTU-3 conservador).
pub const MAX_FRAGMENT_BYTES: usize = 244;

/// Erro tipado do GATT (sem stringly, sem panics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleGattError {
    /// Opcode fora do conjunto de fragmentos (PING/MSG, bind `0x28-0x2D`,
    /// OTA `0x30-0x34`; CANCEL tem caminho proprio).
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
    /// Opcode (PING/MSG, bind-mgmt `0x28-0x2D` ou OTA `0x30-0x34`;
    /// CANCEL e reportado a parte com payload vazio).
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
            if opcode == OP_CANCEL {
                self.cancel();
                return Ok(Some(BleCompleteMessage {
                    opcode,
                    payload: Vec::new(),
                }));
            }
            if !is_ble_fragment_opcode(opcode) {
                return Err(BleGattError::InvalidOpcode);
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
            if is_ble_fragment_opcode(maybe_op) && self.buf.len() < self.expected_len {
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
        if !is_ble_fragment_opcode(opcode) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn single_fragment(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(3 + payload.len());
        v.push(opcode);
        v.push(((payload.len() >> 8) & 0xFF) as u8);
        v.push((payload.len() & 0xFF) as u8);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn fragment_opcodes_cover_bind_and_ota_ranges() {
        // CTAP-BLE classico segue abrindo transacao.
        assert!(is_ble_fragment_opcode(OP_PING));
        assert!(is_ble_fragment_opcode(OP_MSG));
        // Bind-mgmt 0x28-0x2D (Sec.11) abre transacao no reassembler.
        for op in BIND_MGMT_OP_MIN..=BIND_MGMT_OP_MAX {
            assert!(is_ble_fragment_opcode(op), "bind op 0x{op:02X}");
        }
        assert_eq!((BIND_MGMT_OP_MIN, BIND_MGMT_OP_MAX), (0x28, 0x2D));
        // OTA 0x30-0x34 abre transacao no framing; 0x33 COMMIT executa
        // somente via USB (sem braco de execucao no ble_dispatch).
        for op in OTA_OP_MIN..=OTA_OP_MAX {
            assert!(is_ble_fragment_opcode(op), "ota op 0x{op:02X}");
        }
        assert_eq!((OTA_OP_MIN, OTA_OP_MAX), (0x30, 0x34));
        // Paridade com a fonte canonica (crate::ota) sem acoplar o transporte.
        assert_eq!(OTA_OP_MIN, crate::ota::OP_OTA_BEGIN);
        assert_eq!(OTA_OP_MAX, crate::ota::OP_OTA_ABORT);
        assert_eq!(crate::ota::OP_OTA_COMMIT, 0x33);
    }

    #[test]
    fn rescue_and_reserved_never_open_fragment() {
        // 0x2E rescue viaja SOMENTE como payload de OP_MSG 0x83.
        assert!(!is_ble_fragment_opcode(0x2E));
        assert_eq!(
            BleReassembler::new().start_new(0x2E, 1),
            Err(BleGattError::InvalidOpcode)
        );
        // 0x2F reservado segue rejeitado fail-closed.
        assert!(!is_ble_fragment_opcode(0x2F));
        assert_eq!(
            BleReassembler::new().start_new(0x2F, 1),
            Err(BleGattError::InvalidOpcode)
        );
        assert!(!is_ble_fragment_opcode(0x00));
    }

    #[test]
    fn bind_opcode_reassembles_single_fragment() {
        let mut r = BleReassembler::new();
        let payload = [0xABu8; 16];
        let frag = single_fragment(OP_BIND_CLAIM, &payload);
        let done = r.feed(&frag).expect("bind fragment ok").expect("completa");
        assert_eq!(done.opcode, OP_BIND_CLAIM);
        assert_eq!(done.payload, payload);
    }

    #[test]
    fn ota_opcode_reassembles_multi_fragment() {
        let mut r = BleReassembler::new();
        // Total 10B: primeiro leva 4B, resto em continuacao [seq + dados].
        let first = [OTA_OP_MIN, 0x00, 0x0A, 1, 2, 3, 4];
        assert!(r.feed(&first).expect("ota first ok").is_none());
        let cont = [0x00, 5, 6, 7, 8, 9, 10];
        let done = r.feed(&cont).expect("ota cont ok").expect("completa");
        assert_eq!(done.opcode, OTA_OP_MIN);
        assert_eq!(done.payload, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn gatt_contract_frozen_after_fragment_extension() {
        assert_eq!(BLE_SERVICE_UUID, 0xFFFD);
        assert_eq!(CHAR_CONTROL_UUID, 0xFFF1);
        assert_eq!(CHAR_STATUS_UUID, 0xFFF2);
        assert_eq!(CHAR_LEN_UUID, 0xFFF3);
        assert_eq!(CHAR_REVISION_UUID, 0xFFF4);
        assert_eq!(GATT_REVISION, 0x01);
        assert_eq!((OP_PING, OP_MSG, OP_CANCEL), (0x81, 0x83, 0xBE));
    }
}
