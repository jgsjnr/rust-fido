//! USB CCID (Smart Card / PC/SC) Protocol Transport & APDU Parser.
//!
//! Compliant with ISO 7816-4 and USB CCID Specification Rev 1.1.
//! Supports Yubico OATH applet (YKOATH) and FIDO U2F/CTAP applet routing.
//! 100% Native Rust implementation.
//!
//! PIV routing is wired through [`crate::piv::PivApplet`] owned by
//! [`CcidTransport`]; SELECT PIV returns the shared `PIV_FCI` from `piv.rs`
//! (no inline duplicate).
// TODO(Wave 2 E-B2/S-C1): zeroizar CommandApdu.data/ResponseApdu
// (dados sensiveis em memoria; usar `zeroize` com `Zeroizing`/`Drop`).

use crate::piv::{PivApplet, PivKeyBackend, PivRecordStore};

/// Standard ATR (Answer To Reset) for AegisKey SmartCard emulation.
/// SOMENTE T=1 (TD1=0x01, sem oferta de T=0): o UsbCcids ativava T=0
/// (primeiro oferecido) e abortava com SCARD_E_PROTO_MISMATCH, pois só
/// falamos T=1. TCK = XOR de T0..histórico (TCK zerado = cartão "mudo").
pub const AEGIS_ATR: &[u8] = &[
    0x3B, 0x8D, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10,
    0x00, 0x01, 0xF5,
];

// ============================================================================
// CCID Command Message Types (PC -> Reader)
// ============================================================================
pub const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
pub const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
pub const PC_TO_RDR_GET_SLOT_STATUS: u8 = 0x65;
pub const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;
pub const PC_TO_RDR_GET_PARAMETERS: u8 = 0x6C;
pub const PC_TO_RDR_RESET_PARAMETERS: u8 = 0x6D;
pub const PC_TO_RDR_SET_PARAMETERS: u8 = 0x61;
pub const PC_TO_RDR_ESCAPE: u8 = 0x6B;

// ============================================================================
// CCID Response Message Types (Reader -> PC)
// ============================================================================
pub const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
pub const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;
pub const RDR_TO_PC_PARAMETERS: u8 = 0x82;
pub const RDR_TO_PC_ESCAPE: u8 = 0x83;

// ============================================================================
// ISO 7816-4 Status Words (SW1 SW2)
// ============================================================================
pub const SW_OK: (u8, u8) = (0x90, 0x00);
pub const SW_NOT_FOUND: (u8, u8) = (0x6A, 0x82);
pub const SW_WRONG_LENGTH: (u8, u8) = (0x67, 0x00);
pub const SW_CONDITIONS_NOT_SATISFIED: (u8, u8) = (0x69, 0x85);
pub const SW_SECURITY_STATUS_NOT_SATISFIED: (u8, u8) = (0x69, 0x82);
pub const SW_WRONG_P1P2: (u8, u8) = (0x6B, 0x00);
pub const SW_INS_NOT_SUPPORTED: (u8, u8) = (0x6D, 0x00);
pub const SW_CLA_NOT_SUPPORTED: u8 = 0x6E;
pub const SW_UNKNOWN_ERROR: (u8, u8) = (0x6F, 0x00);
/// PIV VERIFY failed, retries remain: SW1 `0x63`, SW2 `0xC0 | remaining`.
/// Use [`sw_retries_left`] to build it (no magic `0xC0` at call sites).
pub const SW_RETRY_BASE: u8 = 0x63;
/// Referenced data not found (e.g. PIV PIN never provisioned): `6A 88`.
pub const SW_REFERENCED_DATA_NOT_FOUND: (u8, u8) = (0x6A, 0x88);
/// Wrong data field content (malformed PIV TLV): `6A 80`.
pub const SW_WRONG_DATA: (u8, u8) = (0x6A, 0x80);
/// Authentication method blocked (PIN blocked → use PUK; PUK exhausted → wiped): `69 83`.
pub const SW_AUTH_BLOCKED: (u8, u8) = (0x69, 0x83);

/// Builds a VERIFY-failed status word: `63 CX` with `X = remaining` (0..=15).
pub fn sw_retries_left(remaining: u8) -> (u8, u8) {
    (SW_RETRY_BASE, 0xC0 | (remaining & 0x0F))
}

// ============================================================================
// Well-known Application IDs (AID)
// ============================================================================
/// Yubico OATH Application ID: A0 00 00 05 27 21 01
pub const AID_YKOATH: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

/// FIDO U2F Application ID: A0 00 00 06 47 2F 00 01
pub const AID_FIDO_U2F: &[u8] = &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

/// PIV (Personal Identity Verification) Application ID: A0 00 00 03 08
pub const AID_PIV: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08];

// ============================================================================
// PIV data-object tags (NIST SP 800-73-4) + MSCP view (PARCIAL, Wave 1 Step 1)
// ============================================================================
//
// MSCP = como o Windows (BaseCSP/minidriver via WinSCard) enxerga o cartão:
// CHUID + CCC + X.509 por slot com SAN/UPN para logon. Status nesta wave:
//
// | Tag        | Objeto (800-73)              | Status Wave 1 Step 1                    |
// |------------|------------------------------|---------------------------------------------|
// | `5F C1 02` | CHUID                      | Servido (mock LAB-ONLY, inalterado)         |
// | `5F C1 07` | CCC                        | Servido (mock LAB-ONLY, inalterado)         |
// | `5F C1 05` | X.509 Certificate          | Servido via PUT DATA (slot = último slot   |
// |            |                            | endereçado por P2, default `9A`)            |
// | `5F C1 06` | Security Object            | TODO: exige certs reais + assinatura do SO  |
// | `7E`       | Discovery Object           | TODO: GET DISCOVERY dedicado (fora do lab)  |
// | biom./face | `5F C1 03`/`5F C1 08`/etc. | TODO: fora do escopo lab                    |
//
// TODO documentados (não inventados aqui): SAN/UPN no cert (enrollment PKI/AD,
// guia futuro), agents Linux/mac (host-side), Security Object assinado. GET DATA
// de tag fora da tabela acima continua `6A 82`, como antes.
//
/// PIV CHUID tag (`5F C1 02`).
pub const PIV_TAG_CHUID: [u8; 3] = [0x5F, 0xC1, 0x02];
/// PIV CCC tag (`5F C1 07`).
pub const PIV_TAG_CCC: [u8; 3] = [0x5F, 0xC1, 0x07];
/// PIV X.509 Certificate tag (`5F C1 05`).
pub const PIV_TAG_X509_CERT: [u8; 3] = [0x5F, 0xC1, 0x05];

/// Active Applet selected on the SmartCard interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedApplet {
    None,
    Oath,
    FidoU2f,
    Piv,
    Other,
}

/// Parsed ISO 7816-4 Command APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandApdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<usize>,
}

impl CommandApdu {
    /// Parses a raw byte buffer into an ISO 7816-4 Command APDU.
    /// Supports short APDUs and extended APDUs.
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 4 {
            return Err("APDU too short, minimum 4 bytes (CLA, INS, P1, P2)");
        }

        let cla = raw[0];
        let ins = raw[1];
        let p1 = raw[2];
        let p2 = raw[3];

        if raw.len() == 4 {
            // Case 1: Header only (No data, no Le)
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: None,
            });
        }

        let b4 = raw[4] as usize;

        if raw.len() == 5 {
            // Case 2S: Header + Le (1 byte, 0 = 256)
            let le = if b4 == 0 { 256 } else { b4 };
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: Some(le),
            });
        }

        if b4 != 0 {
            // Short APDU: Lc = b4
            let lc = b4;
            let data_end = 5 + lc;
            if raw.len() < data_end {
                return Err("Short APDU payload shorter than Lc");
            }
            let data = raw[5..data_end].to_vec();

            let le = if raw.len() > data_end {
                let le_byte = raw[data_end] as usize;
                Some(if le_byte == 0 { 256 } else { le_byte })
            } else {
                None
            };

            Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data,
                le,
            })
        } else {
            // Extended APDU: b4 == 0, followed by 2 bytes Lc or 2 bytes Le
            if raw.len() < 7 {
                return Err("Malformed extended APDU length field");
            }
            let lc = u16::from_be_bytes([raw[5], raw[6]]) as usize;
            if lc == 0 {
                // Extended Le only
                let le = if raw.len() >= 7 {
                    let val = u16::from_be_bytes([raw[5], raw[6]]) as usize;
                    Some(if val == 0 { 65536 } else { val })
                } else {
                    None
                };
                return Ok(Self {
                    cla,
                    ins,
                    p1,
                    p2,
                    data: Vec::new(),
                    le,
                });
            }

            let data_end = 7 + lc;
            if raw.len() < data_end {
                return Err("Extended APDU payload shorter than Lc");
            }
            let data = raw[7..data_end].to_vec();

            let le = if raw.len() >= data_end + 2 {
                let val = u16::from_be_bytes([raw[data_end], raw[data_end + 1]]) as usize;
                Some(if val == 0 { 65536 } else { val })
            } else {
                None
            };

            Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data,
                le,
            })
        }
    }
}

/// Represents an ISO 7816-4 Response APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseApdu {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl ResponseApdu {
    pub fn ok(data: Vec<u8>) -> Self {
        Self {
            data,
            sw1: SW_OK.0,
            sw2: SW_OK.1,
        }
    }

    pub fn status(sw: (u8, u8)) -> Self {
        Self {
            data: Vec::new(),
            sw1: sw.0,
            sw2: sw.1,
        }
    }

    /// Serializes to data + SW1 + SW2.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data.len() + 2);
        out.extend_from_slice(&self.data);
        out.push(self.sw1);
        out.push(self.sw2);
        out
    }
}

/// Trait for dispatching APDU commands to external engines (such as OATH or FIDO).
pub trait CcidApduHandler {
    fn handle_oath_apdu(&mut self, apdu: &CommandApdu) -> ResponseApdu;
    fn handle_fido_apdu(&mut self, apdu: &CommandApdu) -> ResponseApdu;
    /// Handles APDUs routed to the PIV applet. Defaults to `6D 00`
    /// so existing handlers (e.g. `DefaultCcidHandler`) keep working.
    fn handle_piv_apdu(&mut self, _apdu: &CommandApdu) -> ResponseApdu {
        ResponseApdu::status(SW_INS_NOT_SUPPORTED)
    }
}

/// Default dummy handler for standalone testing.
pub struct DefaultCcidHandler;

impl CcidApduHandler for DefaultCcidHandler {
    fn handle_oath_apdu(&mut self, apdu: &CommandApdu) -> ResponseApdu {
        match apdu.ins {
            0xA1 => {
                // LIST OATH credentials (empty example list)
                ResponseApdu::ok(vec![])
            }
            0xA2 => {
                // CALCULATE
                ResponseApdu::status(SW_NOT_FOUND)
            }
            _ => ResponseApdu::status(SW_INS_NOT_SUPPORTED),
        }
    }

    fn handle_fido_apdu(&mut self, _apdu: &CommandApdu) -> ResponseApdu {
        ResponseApdu::status(SW_INS_NOT_SUPPORTED)
    }
}

/// USB CCID Transport Manager.
pub struct CcidTransport {
    pub selected_applet: SelectedApplet,
    pub card_powered: bool,
    pub piv: PivApplet,
}

impl Default for CcidTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl CcidTransport {
    pub fn new() -> Self {
        Self {
            selected_applet: SelectedApplet::None,
            card_powered: false,
            piv: PivApplet::new(),
        }
    }

    /// Processes an incoming USB CCID message (minimum 10-byte header).
    ///
    /// Returns the raw USB response buffer to be sent back on Bulk-IN endpoint.
    pub fn process_ccid_message<H: CcidApduHandler>(
        &mut self,
        packet: &[u8],
        handler: &mut H,
    ) -> Result<Vec<u8>, &'static str> {
        if packet.len() < 10 {
            return Err("CCID packet too short (< 10 bytes)");
        }

        let msg_type = packet[0];
        let length = u32::from_le_bytes([packet[1], packet[2], packet[3], packet[4]]) as usize;
        let slot = packet[5];
        let seq = packet[6];

        if packet.len() < 10 + length {
            return Err("CCID payload length mismatch");
        }

        let payload = &packet[10..10 + length];

        match msg_type {
            PC_TO_RDR_ICC_POWER_ON => {
                self.card_powered = true;
                // Return RDR_to_PC_DataBlock containing ATR
                Ok(Self::build_data_block_response(slot, seq, AEGIS_ATR))
            }

            PC_TO_RDR_ICC_POWER_OFF => {
                self.card_powered = false;
                self.selected_applet = SelectedApplet::None;
                self.piv = PivApplet::new();
                // Slot virtual: cartao sempre presente (remocao nao existe);
                // 0x00 = pronto. 0x02 faria o host concluir 'sem cartao'.
                Ok(Self::build_slot_status_response(slot, seq, 0x00))
            }

            PC_TO_RDR_GET_SLOT_STATUS => {
                // Sempre presente+pronto: o UsbCcids conclui 'sem cartao'
                // com qualquer outro valor e nem chega ao PowerOn.
                Ok(Self::build_slot_status_response(slot, seq, 0x00))
            }

            PC_TO_RDR_GET_PARAMETERS => Ok(Self::parameters_response(slot, seq)),

            PC_TO_RDR_SET_PARAMETERS | PC_TO_RDR_RESET_PARAMETERS => {
                // v1: sem negociação real (`dwFeatures=0`); ecoa os
                // parâmetros T=1 default para o host não travar no caminho
                // feliz (OpenSC/libccid mandam `0x61` explícito após PowerOn).
                Ok(Self::parameters_response(slot, seq))
            }

            PC_TO_RDR_XFR_BLOCK => {
                if !self.card_powered {
                    let mut resp = Self::build_data_block_response(slot, seq, &[]);
                    resp[7] = 0x01; // bStatus: error / slot not powered
                    return Ok(resp);
                }

                let apdu = CommandApdu::parse(payload)?;
                let resp_apdu = self.handle_apdu(&apdu, handler);
                Ok(Self::build_data_block_response(slot, seq, &resp_apdu.to_bytes()))
            }

            _ => {
                // Unsupported CCID command
                let mut resp = Self::build_slot_status_response(slot, seq, 0x01);
                resp[8] = 0x01; // bError: Command not supported
                Ok(resp)
            }
        }
    }

    /// Internal APDU router.
    fn handle_apdu<H: CcidApduHandler>(
        &mut self,
        apdu: &CommandApdu,
        handler: &mut H,
    ) -> ResponseApdu {
        // Check for SELECT APDU (INS = 0xA4)
        if apdu.ins == 0xA4 && apdu.p1 == 0x04 {
            if apdu.data == AID_YKOATH {
                self.selected_applet = SelectedApplet::Oath;
                self.piv = PivApplet::new();
                // Return YKOATH applet version / name: "AegisKey OATH"
                let mut name_resp = Vec::new();
                name_resp.push(0x79); // Name tag
                name_resp.push(13); // Length
                name_resp.extend_from_slice(b"AegisKey OATH");
                return ResponseApdu::ok(name_resp);
            } else if apdu.data == AID_FIDO_U2F {
                self.selected_applet = SelectedApplet::FidoU2f;
                self.piv = PivApplet::new();
                // Return FIDO U2F V2 version string: "U2F_V2"
                return ResponseApdu::ok(b"U2F_V2".to_vec());
            } else if apdu.data == AID_PIV {
                let resp = self.piv.handle(apdu);
                self.selected_applet = if self.piv.is_selected() {
                    SelectedApplet::Piv
                } else {
                    SelectedApplet::None
                };
                return resp;
            } else {
                self.selected_applet = SelectedApplet::None;
                self.piv = PivApplet::new();
                return ResponseApdu::status(SW_NOT_FOUND);
            }
        }

        // Route to the currently selected applet
        let applet = self.selected_applet;
        match applet {
            SelectedApplet::Oath => handler.handle_oath_apdu(apdu),
            SelectedApplet::FidoU2f => handler.handle_fido_apdu(apdu),
            SelectedApplet::Piv => self.piv.handle(apdu),
            _ => ResponseApdu::status(SW_CONDITIONS_NOT_SATISFIED),
        }
    }

    /// Processes one CCID message with PIV served by the transport-owned
    /// applet against real `store` + `crypto` — caminho do firmware (NVS +
    /// `KeyManager`). O estado do applet (seleção/PIN) persiste no
    /// `CcidTransport` entre frames; OATH/FIDO seguem no `handler`.
    /// Framing e CCID idênticos a [`Self::process_ccid_message`].
    pub fn process_ccid_message_store<H, S, B>(
        &mut self,
        packet: &[u8],
        handler: &mut H,
        store: &mut S,
        crypto: &mut B,
    ) -> Result<Vec<u8>, &'static str>
    where
        H: CcidApduHandler,
        S: PivRecordStore,
        B: PivKeyBackend,
    {
        if packet.len() < 10 {
            return Err("CCID packet too short (< 10 bytes)");
        }

        let msg_type = packet[0];
        let length = u32::from_le_bytes([packet[1], packet[2], packet[3], packet[4]]) as usize;
        let slot = packet[5];
        let seq = packet[6];

        if packet.len() < 10 + length {
            return Err("CCID payload length mismatch");
        }

        let payload = &packet[10..10 + length];

        match msg_type {
            PC_TO_RDR_ICC_POWER_ON => {
                self.card_powered = true;
                Ok(Self::build_data_block_response(slot, seq, AEGIS_ATR))
            }

            PC_TO_RDR_ICC_POWER_OFF => {
                self.card_powered = false;
                self.selected_applet = SelectedApplet::None;
                self.piv = PivApplet::new();
                // Slot virtual: cartao sempre presente (remocao nao existe).
                Ok(Self::build_slot_status_response(slot, seq, 0x00))
            }

            PC_TO_RDR_GET_SLOT_STATUS => {
                // Sempre presente+pronto (ver método legado acima).
                Ok(Self::build_slot_status_response(slot, seq, 0x00))
            }

            PC_TO_RDR_GET_PARAMETERS => Ok(Self::parameters_response(slot, seq)),

            PC_TO_RDR_SET_PARAMETERS | PC_TO_RDR_RESET_PARAMETERS => {
                Ok(Self::parameters_response(slot, seq))
            }

            PC_TO_RDR_XFR_BLOCK => {
                if !self.card_powered {
                    let mut resp = Self::build_data_block_response(slot, seq, &[]);
                    resp[7] = 0x01;
                    return Ok(resp);
                }

                let apdu = CommandApdu::parse(payload)?;
                let resp_apdu = self.handle_apdu_store(&apdu, handler, store, crypto);
                // Espelha a seleção do applet interno mesmo quando o
                // handler externo serviu o PIV (SELECT AID_PIV com store).
                if apdu.ins == 0xA4 && apdu.p1 == 0x04 {
                    if apdu.data == AID_PIV {
                        self.selected_applet = SelectedApplet::Piv;
                    } else if apdu.data == AID_YKOATH {
                        self.selected_applet = SelectedApplet::Oath;
                        self.piv = PivApplet::new();
                    } else if apdu.data == AID_FIDO_U2F {
                        self.selected_applet = SelectedApplet::FidoU2f;
                        self.piv = PivApplet::new();
                    } else {
                        self.selected_applet = SelectedApplet::None;
                        self.piv = PivApplet::new();
                    }
                }
                Ok(Self::build_data_block_response(slot, seq, &resp_apdu.to_bytes()))
            }

            _ => {
                let mut resp = Self::build_slot_status_response(slot, seq, 0x01);
                resp[8] = 0x01;
                Ok(resp)
            }
        }
    }

    /// APDU router com PIV no applet do transporte (estado persiste entre
    /// frames) contra store/crypto reais do firmware.
    fn handle_apdu_store<H, S, B>(
        &mut self,
        apdu: &CommandApdu,
        handler: &mut H,
        store: &mut S,
        crypto: &mut B,
    ) -> ResponseApdu
    where
        H: CcidApduHandler,
        S: PivRecordStore,
        B: PivKeyBackend,
    {
        if apdu.ins == 0xA4 && apdu.p1 == 0x04 {
            if apdu.data == AID_YKOATH {
                return handler.handle_oath_apdu(apdu);
            } else if apdu.data == AID_FIDO_U2F {
                return handler.handle_fido_apdu(apdu);
            } else if apdu.data == AID_PIV {
                let resp = self.piv.handle_store(apdu, store, crypto);
                if !self.piv.is_selected() {
                    self.selected_applet = SelectedApplet::None;
                }
                return resp;
            } else {
                return ResponseApdu::status(SW_NOT_FOUND);
            }
        }

        match self.selected_applet {
            SelectedApplet::Oath => handler.handle_oath_apdu(apdu),
            SelectedApplet::FidoU2f => handler.handle_fido_apdu(apdu),
            SelectedApplet::Piv => self.piv.handle_store(apdu, store, crypto),
            _ => ResponseApdu::status(SW_CONDITIONS_NOT_SATISFIED),
        }
    }

    /// Builds a best-effort error RPDU for a malformed frame (header
    /// presente, payload inválido): DataBlock vazio com bStatus de erro.
    /// O host NUNCA pode ficar sem resposta no bulk-IN (trava o
    /// SCardConnect). Retorna `None` só se nem o header existir (< 10B).
    pub fn error_response(packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 10 {
            return None;
        }
        let slot = packet[5];
        let seq = packet[6];
        let mut resp = Self::build_data_block_response(slot, seq, &[]);
        resp[7] = 0x01; // bStatus: erro (slot preservado p/ o host casar)
        resp[8] = 0x01; // bError: comando desconhecido/falhou
        Some(resp)
    }

    fn build_data_block_response(slot: u8, seq: u8, data: &[u8]) -> Vec<u8> {
        let mut resp = Vec::with_capacity(10 + data.len());
        resp.push(RDR_TO_PC_DATA_BLOCK);
        resp.extend_from_slice(&(data.len() as u32).to_le_bytes());
        resp.push(slot);
        resp.push(seq);
        resp.push(0x00); // bStatus: Success
        resp.push(0x00); // bError
        resp.push(0x00); // bChainParameter
        resp.extend_from_slice(data);
        resp
    }

    fn build_slot_status_response(slot: u8, seq: u8, status: u8) -> Vec<u8> {
        let mut resp = vec![0u8; 10];        resp[0] = RDR_TO_PC_SLOT_STATUS;
        resp[1..5].copy_from_slice(&0u32.to_le_bytes());
        resp[5] = slot;
        resp[6] = seq;
        resp[7] = status;
        resp[8] = 0x00;
        resp[9] = 0x00;
        resp
    }

    /// Bloco `RDR_to_PC_Parameters` (T=1 default), servido no GET e ecoado
    /// no SET/RESET (sem negociação real no v1).
    fn parameters_response(slot: u8, seq: u8) -> Vec<u8> {
        let mut resp = vec![0u8; 17];
        resp[0] = RDR_TO_PC_PARAMETERS;
        resp[1..5].copy_from_slice(&7u32.to_le_bytes()); // Length 7
        resp[5] = slot;
        resp[6] = seq;
        resp[7] = 0; // bStatus
        resp[8] = 0; // bError
        resp[9] = 1; // Protocol: T=1
        resp[10] = 0x11; // Fi/Di
        resp[11] = 0x10; // TCCKS
        resp[12] = 0x00; // GuardTime
        resp[13] = 0x4D; // BWI / CWI
        resp[14] = 0x00; // ClockStop
        resp[15] = 0x20; // IFSC (32 bytes)
        resp[16] = 0x00; // NAD
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::piv::{
        provision_pin, PivCryptoError, PivKeyBackend, PivRecordStore, PivSlot, PivStoreError,
    };
    use std::collections::HashMap;

    /// Store em RAM para os testes do caminho firmware (espelha `MemStore`
    /// de `piv::tests`; duplicado aqui porque aquele é privado).
    #[derive(Default)]
    struct TMemStore {
        map: HashMap<String, Vec<u8>>,
    }

    impl PivRecordStore for TMemStore {
        fn load_record(&self, key: &str) -> Result<Vec<u8>, PivStoreError> {
            self.map.get(key).cloned().ok_or(PivStoreError::NotFound)
        }

        fn store_record(&mut self, key: &str, value: &[u8]) -> Result<(), PivStoreError> {
            self.map.insert(key.to_string(), value.to_vec());
            Ok(())
        }

        fn delete_record(&mut self, key: &str) -> Result<(), PivStoreError> {
            self.map.remove(key);
            Ok(())
        }
    }

    /// Backend cripto stub (firma devolve bytes enlatados).
    struct TStubCrypto {
        pubkey: Vec<u8>,
        response: Vec<u8>,
    }

    impl PivKeyBackend for TStubCrypto {
        fn generate(&mut self, _slot: PivSlot, _alg: u8) -> Result<Vec<u8>, PivCryptoError> {
            Ok(self.pubkey.clone())
        }

        fn authenticate(
            &mut self,
            _slot: PivSlot,
            _alg: u8,
            _challenge: &[u8],
        ) -> Result<Vec<u8>, PivCryptoError> {
            Ok(self.response.clone())
        }
    }

    /// Backend que recusa tudo como algoritmo não suportado (RSA no device).
    struct TBadAlgCrypto;

    impl PivKeyBackend for TBadAlgCrypto {
        fn generate(&mut self, _slot: PivSlot, _alg: u8) -> Result<Vec<u8>, PivCryptoError> {
            Err(PivCryptoError::BadAlg)
        }

        fn authenticate(
            &mut self,
            _slot: PivSlot,
            _alg: u8,
            _challenge: &[u8],
        ) -> Result<Vec<u8>, PivCryptoError> {
            Err(PivCryptoError::BadAlg)
        }
    }

    /// Handler mínimo: OATH/FIDO fora do escopo (PIV é servido pelo
    /// applet do transporte com store real).
    struct TOnlyPiv;

    impl CcidApduHandler for TOnlyPiv {
        fn handle_oath_apdu(&mut self, _apdu: &CommandApdu) -> ResponseApdu {
            ResponseApdu::status(SW_INS_NOT_SUPPORTED)
        }

        fn handle_fido_apdu(&mut self, _apdu: &CommandApdu) -> ResponseApdu {
            ResponseApdu::status(SW_INS_NOT_SUPPORTED)
        }
    }

    struct TStore {
        store: TMemStore,
        crypto: TStubCrypto,
    }

    impl TStore {
        fn enrolled() -> Self {
            let mut store = TMemStore::default();
            provision_pin(&mut store, b"123456", b"12345678").expect("enroll");
            Self {
                store,
                crypto: TStubCrypto {
                    pubkey: vec![0x04, 0x11, 0x22, 0x33],
                    response: vec![0xAA, 0xBB],
                },
            }
        }

        fn process(
            &mut self,
            t: &mut CcidTransport,
            frame: &[u8],
        ) -> Result<Vec<u8>, &'static str> {
            let mut h = TOnlyPiv;
            t.process_ccid_message_store(frame, &mut h, &mut self.store, &mut self.crypto)
        }
    }

    fn xfr(seq: u8, apdu: &[u8]) -> Vec<u8> {
        let mut m = vec![PC_TO_RDR_XFR_BLOCK];
        m.extend_from_slice(&(apdu.len() as u32).to_le_bytes());
        m.push(0);
        m.push(seq);
        m.extend_from_slice(&[0, 0, 0]);
        m.extend_from_slice(apdu);
        m
    }

    fn select_piv() -> Vec<u8> {
        let mut a = vec![0x00, 0xA4, 0x04, 0x00, AID_PIV.len() as u8];
        a.extend_from_slice(AID_PIV);
        a
    }

    fn power_on(seq: u8) -> Vec<u8> {
        vec![PC_TO_RDR_ICC_POWER_ON, 0, 0, 0, 0, 0, seq, 0, 0, 0]
    }

    /// Últimos 2 bytes do DataBlock = SW1 SW2.
    fn sw(resp: &[u8]) -> (u8, u8) {
        let n = resp.len();
        assert!(resp[0] == RDR_TO_PC_DATA_BLOCK && n >= 12);
        (resp[n - 2], resp[n - 1])
    }

    #[test]
    fn store_select_verify_generate_ok() {
        let mut t = CcidTransport::new();
        let mut s = TStore::enrolled();
        s.process(&mut t, &power_on(1)).unwrap();
        let r = s.process(&mut t, &xfr(2, &select_piv())).unwrap();
        assert_eq!(sw(&r), SW_OK);
        assert_eq!(t.selected_applet, SelectedApplet::Piv);
        // VERIFY 00 20 00 80 06 "123456".
        let mut v = vec![0x00, 0x20, 0x00, 0x80, 0x06];
        v.extend_from_slice(b"123456");
        let r = s.process(&mut t, &xfr(3, &v)).unwrap();
        assert_eq!(sw(&r), SW_OK);
        assert!(t.piv.is_verified());
        // GENERATE 9A: 00 47 00 9A + AC0301800111.
        let g = [0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11];
        let r = s.process(&mut t, &xfr(4, &g)).unwrap();
        assert_eq!(sw(&r), SW_OK);
        // Corpo = 7F 49 <len> <pubkey enlatada>.
        let body = &r[10..r.len() - 2];
        assert_eq!(&body[..2], &[0x7F, 0x49]);
        assert_eq!(body[2] as usize, body.len() - 3);
        assert_eq!(&body[3..], &[0x04, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn store_generate_sem_verify_nega() {
        let mut t = CcidTransport::new();
        let mut s = TStore::enrolled();
        s.process(&mut t, &power_on(1)).unwrap();
        s.process(&mut t, &xfr(2, &select_piv())).unwrap();
        let g = [0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11];
        let r = s.process(&mut t, &xfr(3, &g)).unwrap();
        assert_eq!(sw(&r), SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn store_verify_pin_errado_devolve_63cx() {
        let mut t = CcidTransport::new();
        let mut s = TStore::enrolled();
        s.process(&mut t, &power_on(1)).unwrap();
        s.process(&mut t, &xfr(2, &select_piv())).unwrap();
        let mut v = vec![0x00, 0x20, 0x00, 0x80, 0x06];
        v.extend_from_slice(b"000000");
        let r = s.process(&mut t, &xfr(3, &v)).unwrap();
        let (sw1, _sw2) = sw(&r);
        assert_eq!(sw1, SW_RETRY_BASE);
        assert!(!t.piv.is_verified());
    }

    #[test]
    fn store_rsa_recusado_como_badalg() {
        let mut t = CcidTransport::new();
        let mut store = TMemStore::default();
        provision_pin(&mut store, b"123456", b"12345678").expect("enroll");
        let mut crypto = TBadAlgCrypto;
        let mut h = TOnlyPiv;
        let mut run = |t: &mut CcidTransport, f: &[u8]| {
            t.process_ccid_message_store(f, &mut h, &mut store, &mut crypto)
        };
        run(&mut t, &power_on(1)).unwrap();
        run(&mut t, &xfr(2, &select_piv())).unwrap();
        let mut v = vec![0x00, 0x20, 0x00, 0x80, 0x06];
        v.extend_from_slice(b"123456");
        assert_eq!(sw(&run(&mut t, &xfr(3, &v)).unwrap()), SW_OK);
        let g = [0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11];
        let r = run(&mut t, &xfr(4, &g)).unwrap();
        assert_eq!(sw(&r), SW_WRONG_DATA);
    }

    #[test]
    fn store_power_off_reseta_selecao() {        let mut t = CcidTransport::new();
        let mut s = TStore::enrolled();
        s.process(&mut t, &power_on(1)).unwrap();
        s.process(&mut t, &xfr(2, &select_piv())).unwrap();
        assert_eq!(t.selected_applet, SelectedApplet::Piv);
        let off = [PC_TO_RDR_ICC_POWER_OFF, 0, 0, 0, 0, 0, 3, 0, 0, 0];
        s.process(&mut t, &off).unwrap();
        assert_eq!(t.selected_applet, SelectedApplet::None);
        assert!(!t.piv.is_verified());
        // Sem power: XFR devolve erro de slot, sem tocar no applet.
        let g = [0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11];
        let r = s.process(&mut t, &xfr(4, &g)).unwrap();
        assert_eq!(r[7], 0x01);
    }


    #[test]
    fn test_power_on_atr() {
        let mut transport = CcidTransport::new();
        let mut handler = DefaultCcidHandler;

        let power_on_cmd = [
            PC_TO_RDR_ICC_POWER_ON,
            0, 0, 0, 0, // dwLength: 0
            0,          // bSlot
            1,          // bSeq
            0, 0, 0,    // PowerSelect / RFU
        ];

        let resp = transport.process_ccid_message(&power_on_cmd, &mut handler).unwrap();
        assert_eq!(resp[0], RDR_TO_PC_DATA_BLOCK);
        assert_eq!(resp[5], 0); // Slot
        assert_eq!(resp[6], 1); // Seq
        assert_eq!(&resp[10..], AEGIS_ATR);
        assert!(transport.card_powered);
    }

    #[test]
    fn test_select_ykoath_applet() {
        let mut transport = CcidTransport::new();
        let mut handler = DefaultCcidHandler;
        transport.card_powered = true;

        // Command: SELECT AID A0 00 00 05 27 21 01
        let mut apdu_bytes = vec![0x00, 0xA4, 0x04, 0x00, 0x07];
        apdu_bytes.extend_from_slice(AID_YKOATH);

        let mut ccid_msg = vec![PC_TO_RDR_XFR_BLOCK];
        ccid_msg.extend_from_slice(&(apdu_bytes.len() as u32).to_le_bytes());
        ccid_msg.push(0); // Slot
        ccid_msg.push(42); // Seq
        ccid_msg.extend_from_slice(&[0, 0, 0]); // RFU
        ccid_msg.extend_from_slice(&apdu_bytes);

        let resp = transport.process_ccid_message(&ccid_msg, &mut handler).unwrap();
        assert_eq!(resp[0], RDR_TO_PC_DATA_BLOCK);
        assert_eq!(resp[6], 42); // Seq
        let apdu_resp = &resp[10..];
        let len = apdu_resp.len();
        assert!(len >= 2);
        assert_eq!(apdu_resp[len - 2], 0x90);
        assert_eq!(apdu_resp[len - 1], 0x00);
        assert_eq!(transport.selected_applet, SelectedApplet::Oath);
    }

    #[test]
    fn test_select_u2f_applet() {
        let mut transport = CcidTransport::new();
        let mut handler = DefaultCcidHandler;
        transport.card_powered = true;

        // Command: SELECT AID A0 00 00 06 47 2F 00 01
        let mut apdu_bytes = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
        apdu_bytes.extend_from_slice(AID_FIDO_U2F);

        let mut ccid_msg = vec![PC_TO_RDR_XFR_BLOCK];
        ccid_msg.extend_from_slice(&(apdu_bytes.len() as u32).to_le_bytes());
        ccid_msg.push(0);
        ccid_msg.push(99);
        ccid_msg.extend_from_slice(&[0, 0, 0]);
        ccid_msg.extend_from_slice(&apdu_bytes);

        let resp = transport.process_ccid_message(&ccid_msg, &mut handler).unwrap();
        let apdu_resp = &resp[10..];
        assert_eq!(&apdu_resp[..6], b"U2F_V2");
        assert_eq!(apdu_resp[6], 0x90);
        assert_eq!(apdu_resp[7], 0x00);
        assert_eq!(transport.selected_applet, SelectedApplet::FidoU2f);
    }

    fn xfr_block(apdu_bytes: &[u8], seq: u8) -> Vec<u8> {
        let mut msg = vec![PC_TO_RDR_XFR_BLOCK];
        msg.extend_from_slice(&(apdu_bytes.len() as u32).to_le_bytes());
        msg.push(0);
        msg.push(seq);
        msg.extend_from_slice(&[0, 0, 0]);
        msg.extend_from_slice(apdu_bytes);
        msg
    }

    #[test]
    fn should_select_piv_and_serve_chuid_via_transport() {
        // Arrange
        let mut transport = CcidTransport::new();
        let mut handler = DefaultCcidHandler;
        transport.card_powered = true;
        let mut select = vec![0x00, 0xA4, 0x04, 0x00, 0x05];
        select.extend_from_slice(AID_PIV);

        // Act: SELECT PIV via CCID
        let resp = transport
            .process_ccid_message(&xfr_block(&select, 1), &mut handler)
            .unwrap();

        // Assert: applet seleciona via PivApplet compartilhado
        let apdu_resp = &resp[10..];
        assert_eq!(transport.selected_applet, SelectedApplet::Piv);
        assert!(transport.piv.is_selected());
        assert_eq!(apdu_resp[apdu_resp.len() - 2..], [0x90, 0x00]);

        // Act: GET DATA CHUID (5C 03 5F C1 02) pelo transporte
        let get_data = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x02];
        let resp = transport
            .process_ccid_message(&xfr_block(&get_data, 2), &mut handler)
            .unwrap();

        // Assert
        let apdu_resp = &resp[10..];
        assert_eq!(apdu_resp[apdu_resp.len() - 2..], [0x90, 0x00]);
        assert_eq!(&apdu_resp[..4], &[0x5F, 0xC1, 0x02, 0x00]);
    }

    #[test]
    fn should_return_6985_for_piv_unselected_via_transport() {
        // Arrange
        let mut transport = CcidTransport::new();
        let mut handler = DefaultCcidHandler;
        transport.card_powered = true;

        // Act: GET DATA sem SELECT previo
        let get_data = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x02];
        let resp = transport
            .process_ccid_message(&xfr_block(&get_data, 7), &mut handler)
            .unwrap();

        // Assert
        let apdu_resp = &resp[10..];
        assert_eq!(apdu_resp[apdu_resp.len() - 2..], [0x69, 0x85]);
    }

    #[test]
    fn should_route_verify_unprovisioned_via_transport() {
        // Arrange
        let mut transport = CcidTransport::new();
        let mut handler = DefaultCcidHandler;
        transport.card_powered = true;
        let mut select = vec![0x00, 0xA4, 0x04, 0x00, 0x05];
        select.extend_from_slice(AID_PIV);
        let _ = transport
            .process_ccid_message(&xfr_block(&select, 1), &mut handler)
            .unwrap();
        assert_eq!(transport.selected_applet, SelectedApplet::Piv);

        // Act: VERIFY sem PIN provisionado (transporte puro, sem NVS)
        let verify = vec![0x00, 0x20, 0x00, 0x80, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36];
        let resp = transport
            .process_ccid_message(&xfr_block(&verify, 2), &mut handler)
            .unwrap();

        // Assert: fail-closed `6A 88` (sem PIN default), applet segue selecionado
        let apdu_resp = &resp[10..];
        assert_eq!(apdu_resp[apdu_resp.len() - 2..], [0x6A, 0x88]);
        assert_eq!(transport.selected_applet, SelectedApplet::Piv);
    }

    #[test]
    fn should_reject_put_without_pin_via_transport() {
        // Arrange
        let mut transport = CcidTransport::new();
        let mut handler = DefaultCcidHandler;
        transport.card_powered = true;
        let mut select = vec![0x00, 0xA4, 0x04, 0x00, 0x05];
        select.extend_from_slice(AID_PIV);
        let _ = transport
            .process_ccid_message(&xfr_block(&select, 1), &mut handler)
            .unwrap();

        // Act: PUT DATA sem VERIFY prévio
        let put = vec![
            0x00, 0xDB, 0x3F, 0x9A, 0x0A, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x03, 0x30, 0x00,
            0x01,
        ];
        let resp = transport
            .process_ccid_message(&xfr_block(&put, 2), &mut handler)
            .unwrap();

        // Assert: gate de PIN `69 82` de ponta a ponta
        let apdu_resp = &resp[10..];
        assert_eq!(apdu_resp[apdu_resp.len() - 2..], [0x69, 0x82]);
    }

    #[test]
    fn should_expose_mscp_tag_table() {
        // Arrange + Act: tabela MSCP (parcial, documentada em `AID_PIV`)

        // Assert: tags distintas, CHUID/CCC/cert cobertos
        assert_ne!(PIV_TAG_CHUID, PIV_TAG_CCC);
        assert_ne!(PIV_TAG_CHUID, PIV_TAG_X509_CERT);
        assert_ne!(PIV_TAG_CCC, PIV_TAG_X509_CERT);
        assert_eq!(PIV_TAG_CHUID, [0x5F, 0xC1, 0x02]);
        assert_eq!(PIV_TAG_CCC, [0x5F, 0xC1, 0x07]);
        assert_eq!(PIV_TAG_X509_CERT, [0x5F, 0xC1, 0x05]);
        assert_eq!(sw_retries_left(3), (0x63, 0xC3));
        assert_eq!(sw_retries_left(0), (0x63, 0xC0));
    }

    fn param_msg(msg_type: u8, seq: u8) -> Vec<u8> {
        vec![msg_type, 7, 0, 0, 0, 0, seq, 0, 0, 0, 1, 0x11, 0x10, 0, 0x4D, 0, 0]
    }

    #[test]
    fn atr_tck_valido() {
        // Percorre a estrutura ISO 7816-3: TS, T0 (Y1|K), bytes de
        // interface seguindo a cadeia de TD; TCK existe se algum TD
        // anuncia protocolo != T=0; TCK = XOR de T0..último histórico.
        let a = AEGIS_ATR;
        assert_eq!(a[0], 0x3B);
        let mut y = a[1] >> 4;
        let k = (a[1] & 0x0F) as usize;
        let mut pos = 2usize;
        let mut tck_present = false;
        loop {
            let mut td = None;
            for bit in 0..4u8 {
                if y & (1 << bit) != 0 {
                    assert!(pos < a.len(), "ATR truncado");
                    let b = a[pos];
                    pos += 1;
                    if bit == 3 {
                        td = Some(b);
                    }
                }
            }
            match td {
                Some(v) => {
                    if v & 0x0F != 0 {
                        tck_present = true;
                    }
                    y = v >> 4;
                }
                None => break,
            }
            if y == 0 {
                break;
            }
        }
        assert!(tck_present, "ATR sem T=1 mas teste espera TCK");
        let hist_end = pos + k;
        assert!(hist_end < a.len(), "ATR sem TCK");
        let mut tck = 0u8;
        for b in &a[1..hist_end] {
            tck ^= b;
        }
        assert_eq!(a[hist_end], tck, "TCK inválido no ATR");
        assert_eq!(hist_end + 1, a.len(), "ATR com sobra após TCK");
    }

    #[test]
    fn frame_malformado_responde_erro_nunca_silencio() {
        // XFR vazio (só header): erro com slot/seq preservados, nunca None.
        let empty_xfr = [PC_TO_RDR_ICC_POWER_ON, 0, 0, 0, 0, 0, 7, 0, 0, 0];
        let r = CcidTransport::error_response(&empty_xfr).expect("erro rsp");
        assert_eq!(r[0], RDR_TO_PC_DATA_BLOCK);
        assert_eq!(r[5], 0);
        assert_eq!(r[6], 7);
        assert_ne!(r[7], 0x00);
        // Sem nem header: aí sim None (C nunca enfileira < 10B).
        assert!(CcidTransport::error_response(&[0x6F, 0x00]).is_none());
        // Comprimento inconsistente: process erra, fallback responde.
        let clipped = [
            PC_TO_RDR_XFR_BLOCK, 5, 0, 0, 0, 0, 8, 0, 0, 0, 0xAA, 0xBB,
        ];
        let mut t = CcidTransport::new();
        let mut s = TStore::enrolled();
        assert!(s.process(&mut t, &clipped).is_err());
        let r = CcidTransport::error_response(&clipped).expect("erro rsp");
        assert_eq!((r[0], r[5], r[6]), (RDR_TO_PC_DATA_BLOCK, 0, 8));
        assert_ne!(r[7], 0x00);
    }

    #[test]
    fn set_reset_parameters_ecoam_t1() {
        // Caminho legado (transporte puro).
        let mut t = CcidTransport::new();
        let mut h = DefaultCcidHandler;
        for (ty, seq) in [
            (PC_TO_RDR_GET_PARAMETERS, 1),
            (PC_TO_RDR_SET_PARAMETERS, 2),
            (PC_TO_RDR_RESET_PARAMETERS, 3),
        ] {
            let r = t
                .process_ccid_message(&param_msg(ty, seq), &mut h)
                .unwrap();
            assert_eq!(r[0], RDR_TO_PC_PARAMETERS);
            assert_eq!(r[6], seq);
            assert_eq!(r[9], 1); // T=1
        }
        // Caminho firmware (store real): mesmo eco.
        let mut s = TStore::enrolled();
        for (ty, seq) in [
            (PC_TO_RDR_SET_PARAMETERS, 4),
            (PC_TO_RDR_RESET_PARAMETERS, 5),
        ] {
            let r = s.process(&mut t, &param_msg(ty, seq)).unwrap();
            assert_eq!(r[0], RDR_TO_PC_PARAMETERS);
            assert_eq!(r[6], seq);
            assert_eq!(r[9], 1);
        }
    }
}
