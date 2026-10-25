//! Roteamento CTAPHID do dispatcher FreeRTOS: dispatch + route.
//!
//! Extraido de `freertos.rs` sem mudanca de comportamento (auditoria
//! riscos 2+3). Contem `CtaphidDispatch`, `SerialVendorCtx`,
//! `dispatch_serial_vendor_msg` (paridade secao D legada) e
//! `route_ctaphid_event` (paridade secao C legada), com origem
//! (`PacketOrigin`) preservada. Gates na ordem binding -> UP -> PIN,
//! fail-closed; UP ausente nega sem espera; erro de protocolo volta
//! enquadrado na mesma origem. Tipos de transporte/fila/etapas vem de
//! `crate::freertos_sched`.

use crate::ble::dispatch_bind::{
    is_backup_export_op, is_bind_mgmt_op, is_piv_enroll_op, is_vendor_keys_oath_op, is_wallet_op,
};
use crate::freertos_sched::{
    packet_bytes, packet_origin, FirmwareEvent, PacketOrigin, CTAPHID_PACKET_SIZE,
};
use crate::ota::{OtaState, OP_OTA_COMMIT};
use crate::ota_store::{
    dispatch_ota_request, is_ota_op, FlashOtaSink, OtaRequestCtx, OTA_STATUS_FAIL, OTA_STATUS_OK,
};
use crate::serial_ctaphid::{
    authorize_serial, deny_response, dispatch_serial_bind_mgmt, dispatch_serial_rescue,
    is_rescue_msg, serial_bind_mgmt_consumes_up, SerialGate,
};
use aegis_fido_core::ctap::{
    CtapEngine, CTAP_CMD_GET_ASSERTION, CTAP_CMD_MAKE_CREDENTIAL, CTAP_CMD_RESET,
};
use aegis_fido_usb::ctaphid::{
    CtapHidFramer, CtapHidManager, CtapHidMessage, CAPABILITY_CBOR, CAPABILITY_WINK, CMD_CBOR,
    CMD_INIT, CMD_MSG, CMD_PING, CMD_WINK,
};

/// Espelho documental dos 7 gaps T8 ainda abertos no small loop FreeRTOS.
///
/// Sem dependencia de tipo da TrustFacade (T12-parte-A nao depende da T8):
/// cada nome espelha uma variante de
/// `crate::binding::FreertosTrustGap` (ver `reason()` la para a peca exata).
/// Status de cada um: `ExternallyBlocked` ate a T8 fiar (BLE/GATT, sensor
/// RSSI HW, NVS `prox_k`, `sync_trust_claimed`, sessao PIN, dispatch
/// `0xFFFD`, coex WiFi). Nunca fabricar valores: ausente = fail-closed.
pub const FREERTOS_TRUST_GAPS_EXTERNALLY_BLOCKED: [&str; 7] = [
    "BleDispatch",
    "RssiSensor",
    "NvsProxK",
    "BindingWire",
    "PinSession",
    "GattDispatch",
    "WifiCoex",
];

/// Resposta do roteamento CTAPHID com origem preservada (domínio tipado).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtaphidDispatch {
    /// Pacotes de 64 B a enviar de volta (vazios = mensagem incompleta/ignorada).
    pub responses: Vec<[u8; CTAPHID_PACKET_SIZE]>,
    /// Transporte de volta (o mesmo do pedido; `None` = sem pacote).
    pub origin: Option<PacketOrigin>,
    /// `true` quando o latch UP foi consumido por esta mensagem.
    pub consumed_up: bool,
}

/// `true` quando o comando CTAP exige presença (UP), espelhando o loop legado.
///
/// `CMD_CBOR`: `makeCredential`/`getAssertion`/`reset`; `CMD_MSG` (U2F):
/// `Register` (`INS=0x01`) ou `Authenticate` com check/sign (`INS=0x02,P1=0x03`).
fn ctaphid_up_required(cmd: u8, payload: &[u8]) -> bool {
    match cmd {
        CMD_CBOR => matches!(
            payload.first(),
            Some(&CTAP_CMD_MAKE_CREDENTIAL) | Some(&CTAP_CMD_GET_ASSERTION) | Some(&CTAP_CMD_RESET)
        ),
        CMD_MSG if payload.len() >= 4 => {
            let ins = payload[1];
            let p1 = payload[2];
            ins == 0x01 || (ins == 0x02 && p1 == 0x03)
        }
        CMD_MSG => false,
        _ => false,
    }
}

/// Contexto vendor serial p/ o dispatcher FreeRTOS (paridade com a seção D
/// legada; sem bloqueio: gates imediatos, `NeedUp` p/ retry do host).
///
/// `None` no roteamento = comportamento só-CTAP (testes de host).
pub struct SerialVendorCtx<'a> {
    /// Janela de pareamento aberta (hold 5 s / TEST_PAIRING_OPEN).
    pub pairing_open: bool,
    /// Latch de presença 1x (BOOT físico ou TEST_UP, 1,5 s).
    pub up_latched: bool,
    /// Relógio ms do dispatcher.
    pub now_ms: u64,
    /// Relógio s do dispatcher.
    pub now_secs: u64,
    /// Binding exclusivo BLE/vendor (claim/release/recovery).
    pub binding: &'a mut crate::binding::BindingManager,
    /// NVS cifrada (chaves vendor/OATH, binding, PIN).
    pub storage:
        &'a mut crate::persistence::SecureStorage<crate::persistence::PlatformFlashBackend>,
    /// Carteira Fase7 (sessão RAM).
    pub wallet: &'a mut aegis_fido_core::wallet::WalletStore,
    /// Chaves vendor on-device (NVS persistente).
    pub key_mgr: &'a mut aegis_fido_core::credential::key_manager::KeyManager,
    /// Applet OATH.
    pub oath: &'a mut aegis_fido_core::oath::OathApplet,
    /// Log do device p/ o app.
    pub fwlog: &'a mut crate::fw_log::FwLog,
    /// Motor rescue/killswitch.
    pub rescue: &'a mut aegis_fido_core::otp::rescue::RescueEngine,
    /// Pareamento (janela + trigger 0x2F).
    pub pairing: &'a mut crate::pairing::PairingManager,
    /// Sessão pinUvAuth viva (ClientPIN).
    pub pin_uv_session: bool,
    /// Sessão OTA staged (espelho da seção C legada; `None` = só-CTAP).
    pub ota_state: Option<&'a mut OtaState>,
    /// `ota_provisioned` do loop (eFuse válido ou lab test-mode).
    pub ota_provisioned: bool,
    /// Pubkey Ed25519 release ativa do build ([`OtaKeyProvider`]).
    pub ota_pubkey: [u8; 32],
    /// `max(firmware, contador anti-rollback NVS)` (fail-closed).
    pub ota_current_version: u32,
    /// Origem do pacote em despacho (o roteador sobrescreve por evento;
    /// COMMIT OTA executa SOMENTE via USB).
    pub origin: PacketOrigin,
}

/// Despacha 1 `CMD_MSG` serial vendor/bind-mgmt/wallet/fw-log/rescue/
/// pairing no dispatcher FreeRTOS (espelho da seção D legada, sem espera).
///
/// Retorna `Some((pacotes_64B, consumed_up))` quando a op é tratada aqui;
/// `None` = cair no engine CTAP genérico (U2F/desconhecido), preservando
/// o comportamento anterior byte a byte.
pub fn dispatch_serial_vendor_msg(
    ctx: &mut SerialVendorCtx<'_>,
    msg: &CtapHidMessage,
) -> Option<(Vec<[u8; CTAPHID_PACKET_SIZE]>, bool)> {
    let payload = &msg.payload;
    if payload.is_empty() {
        return None;
    }
    let op = payload[0];
    // Traço de gate (diagnóstico de campo; 1 linha por op vendor).
    log::info!(
        "[VENDOR] op=0x{:02X} pairing={} up={}",
        op,
        ctx.pairing_open as u8,
        ctx.up_latched as u8
    );
    // Bind-mgmt 0x28-0x2D: mesmos gates do BLE (status-first, sem framing novo).
    if is_bind_mgmt_op(op) {
        let mut rng = rand_core::OsRng;
        let (st, body) = dispatch_serial_bind_mgmt(
            op,
            &payload[1..],
            ctx.pairing_open,
            ctx.up_latched,
            ctx.binding,
            ctx.storage,
            &mut rng,
        );
        let consumed = st == 0x00 && serial_bind_mgmt_consumes_up(op);
        if consumed {
            ctx.rescue.set_user_presence(true);
        }
        let mut resp = Vec::with_capacity(1 + body.len());
        resp.push(st);
        resp.extend_from_slice(&body);
        return Some((
            CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp),
            consumed,
        ));
    }
    // Log da firmware over serial: posse física = livre (sem pairing/UP/latch).
    if op == crate::fw_log::OP_FW_LOG {
        use crate::fw_log as fl;
        ctx.fwlog.record(fl::EV_OP_RX, fl::OP_FW_LOG, ctx.now_ms);
        let body = ctx.fwlog.render_ascii(1024);
        ctx.fwlog.record(fl::EV_OP_RESP, 0x00, ctx.now_ms);
        let mut resp = Vec::with_capacity(1 + body.len());
        resp.push(0x00);
        resp.extend_from_slice(&body);
        return Some((CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp), false));
    }
    // Vendor keys/OATH + carteira + PIV enroll: UP do latch (como o BLE);
    // negação carrega o wire status.
    if is_vendor_keys_oath_op(op) || is_wallet_op(op) || is_piv_enroll_op(op) {
        match authorize_serial(msg.cmd, payload, ctx.pairing_open, ctx.up_latched) {
            SerialGate::NeedPairing => {
                return Some((deny_response(msg), false));
            }
            SerialGate::NeedUp => {
                return Some((
                    CtapHidFramer::frame_message(msg.cid, msg.cmd, &[0x01]),
                    false,
                ));
            }
            SerialGate::Ok => {
                let mut rng = rand_core::OsRng;
                let (st, body) = if is_wallet_op(op) {
                    use crate::ble::gatt_core::{OP_WALLET_ADDR, OP_WALLET_GEN, OP_WALLET_LIST};
                    use crate::wallet_exec as w;
                    match op {
                        OP_WALLET_GEN => {
                            w::wallet_gen(ctx.wallet, &payload[1..], ctx.now_secs, true, &mut rng)
                        }
                        OP_WALLET_LIST => w::wallet_list(ctx.wallet, true),
                        OP_WALLET_ADDR => w::wallet_addr(ctx.wallet, &payload[1..], true),
                        _ => (0x04, Vec::new()),
                    }
                } else {
                    crate::vendor_exec::exec_vendor_op(
                        ctx.key_mgr,
                        ctx.oath,
                        ctx.storage,
                        op,
                        &payload[1..],
                        ctx.binding.is_claimed(),
                        ctx.pin_uv_session,
                        true,
                        ctx.now_secs,
                        &mut rng,
                    )
                };
                ctx.rescue.set_user_presence(true);
                let mut resp = Vec::with_capacity(1 + body.len());
                resp.push(st);
                resp.extend_from_slice(&body);
                return Some((CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp), true));
            }
        }
    }
    // Backup-export 0x3A: envelope AEGN at-rest (cifrado) do store pedido;
    // nunca plaintext/keys. Gates: pairing (CONFIG serial) -> UP via
    // `authorize_serial` acima; binding -> UP -> PIN no dispatch.
    if is_backup_export_op(op) {
        match authorize_serial(msg.cmd, payload, ctx.pairing_open, ctx.up_latched) {
            SerialGate::NeedPairing => {
                return Some((deny_response(msg), false));
            }
            SerialGate::NeedUp => {
                return Some((
                    CtapHidFramer::frame_message(msg.cid, msg.cmd, &[0x01]),
                    false,
                ));
            }
            SerialGate::Ok => {
                let (st, body) = crate::serial_vendor::dispatch_serial_backup_export(
                    ctx.storage,
                    &payload[1..],
                    ctx.binding.is_claimed(),
                    ctx.pin_uv_session,
                    true,
                );
                let consumed = st == 0x00;
                if consumed {
                    ctx.rescue.set_user_presence(true);
                }
                let mut resp = Vec::with_capacity(1 + body.len());
                resp.push(st);
                resp.extend_from_slice(&body);
                return Some((
                    CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp),
                    consumed,
                ));
            }
        }
    }
    // OTA 0x30-0x34: espelho da seção C legada (begin/chunk/verify/commit
    // com manifesto 104 B + checagem anti-rollback via `ota_current_version`).
    // COMMIT executa SOMENTE via USB (regra documentada); serial nega 0x04
    // sem tocar a sessão. Sem sessão no ctx, cai no engine genérico.
    if is_ota_op(op) {
        return dispatch_ota_route(ctx, msg, op, ctx.origin);
    }
    // Pareamento por software (trigger 0x2F): abre a mesma janela de 60 s
    // do hold; UART = posse física.
    if crate::pairing::is_host_pairing_msg(op, payload.len() - 1) {
        ctx.pairing.open_host_window(ctx.now_ms);
        return Some((
            CtapHidFramer::frame_message(msg.cid, msg.cmd, &[0x00]),
            false,
        ));
    }
    // Rescue 0x2E: UP do latch + plumbing ClientPIN, fail-closed sem sessão.
    if is_rescue_msg(msg.cmd, payload) {
        ctx.rescue.set_user_presence(ctx.up_latched);
        ctx.rescue.set_pin_uv_authenticated(ctx.pin_uv_session);
        let (st, body) = dispatch_serial_rescue(ctx.rescue, &payload[1..]);
        let mut resp = Vec::with_capacity(1 + body.len());
        resp.push(st);
        resp.extend_from_slice(&body);
        return Some((CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp), true));
    }
    // U2F/desconhecido: cai no engine genérico (comportamento anterior).
    None
}

/// Despacha 1 op OTA (`0x30-0x34`) na rota FreeRTOS (espelho da seção C legada).
///
/// `None` = sem sessão OTA no ctx (cai no engine CTAP genérico, comportamento
/// anterior). COMMIT executa SOMENTE com origem USB (regra documentada em
/// `ble::gatt_core` + `tools/host_sdk/ops.py`); serial nega `0x04`
/// fail-closed sem tocar a sessão nem o latch. Sucesso no COMMIT consome o
/// latch UP 1x (como o legado).
fn dispatch_ota_route(
    ctx: &mut SerialVendorCtx<'_>,
    msg: &CtapHidMessage,
    op: u8,
    origin: PacketOrigin,
) -> Option<(Vec<[u8; CTAPHID_PACKET_SIZE]>, bool)> {
    let state = ctx.ota_state.as_mut()?;
    if op == OP_OTA_COMMIT && origin != PacketOrigin::Usb {
        log::info!("[OTA] commit fora do USB negado (0x04, sem tocar a sessão).");
        return Some((
            CtapHidFramer::frame_message(msg.cid, msg.cmd, &[OTA_STATUS_FAIL]),
            false,
        ));
    }
    let req = OtaRequestCtx {
        provisioned: ctx.ota_provisioned,
        up: ctx.up_latched,
        ota_pubkey: ctx.ota_pubkey,
        current_version: ctx.ota_current_version,
    };
    let mut sink = FlashOtaSink::new(ctx.storage.backend_mut());
    let (st, body) = match dispatch_ota_request(state, &mut sink, op, &msg.payload[1..], &req) {
        // Pré-filtrado por `is_ota_op` acima: inalcançável fail-closed.
        None => (OTA_STATUS_FAIL, Vec::new()),
        Some(r) => r,
    };
    log::info!(
        "[OTA] op=0x{:02X} status=0x{:02X} phase={:?}",
        op,
        st,
        state.phase()
    );
    let consumed = st == OTA_STATUS_OK && op == OP_OTA_COMMIT;
    if consumed {
        ctx.rescue.set_user_presence(true);
    }
    let mut resp = Vec::with_capacity(1 + body.len());
    resp.push(st);
    resp.extend_from_slice(&body);
    Some((
        CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp),
        consumed,
    ))
}

/// Roteia 1 evento pacote CTAPHID com origem preservada.
///
/// Espelha a seção C legada (`run_authenticator`), adaptada ao dispatcher
/// FreeRTOS sem bloqueio: acumula via [`CtapHidManager`] (um por transporte,
/// como `ctaphid_mgr`/`serial_router` no legado), despacha mensagens completas
/// ao [`CtapEngine`] com os mesmos gates UP/PIN (latch 1x via `up_latched`,
/// sessão pinUvAuth viva dentro do engine, fail-closed sem ela) e enquadra
/// cada resposta em 64 B de volta PELA MESMA origem.
///
/// - `INIT`/`PING`/`WINK`: sem engine (alocação/eco), mesma semântica legada.
/// - `CBOR`/`MSG`: `set_user_presence(up_ok)` + `process_packet` + persistência
///   de PIN em RAM (a NVS `pin_state` do legado é follow-up do scheduler).
/// - UP ausente numa op com gate: fail-closed imediato (`presence=false`, o
///   engine nega); sem espera de 25 s (o loop legado com display/botão mantém
///   a espera limitada; aqui o host retenta após o tap, padrão CTAP).
/// - `Err` de protocolo: pacote de erro enquadrado de volta na mesma origem.
/// - Evento sem pacote: sem resposta, sem consumo de latch.
#[allow(clippy::too_many_arguments)]
pub fn route_ctaphid_event(
    mgr_usb: &mut CtapHidManager,
    mgr_serial: &mut CtapHidManager,
    engine: &mut CtapEngine,
    event: &FirmwareEvent,
    up_latched: bool,
    now_ms: u64,
    now_secs: u64,
    mut vendor: Option<&mut SerialVendorCtx<'_>>,
) -> CtaphidDispatch {
    let origin = packet_origin(event);
    let raw = packet_bytes(event);
    let (Some(origin), Some(raw)) = (origin, raw) else {
        return CtaphidDispatch {
            responses: Vec::new(),
            origin: None,
            consumed_up: false,
        };
    };
    let mgr = match origin {
        PacketOrigin::Usb => mgr_usb,
        PacketOrigin::Serial => mgr_serial,
    };
    match mgr.process_packet(&raw, now_ms) {
        Ok(None) => CtaphidDispatch {
            responses: Vec::new(),
            origin: Some(origin),
            consumed_up: false,
        },
        Err(err) => CtaphidDispatch {
            responses: vec![err.to_packet()],
            origin: Some(origin),
            consumed_up: false,
        },
        Ok(Some(msg)) => {
            if msg.cmd == CMD_INIT {
                if msg.payload.len() < 8 {
                    return CtaphidDispatch {
                        responses: Vec::new(),
                        origin: Some(origin),
                        consumed_up: false,
                    };
                }
                let mut nonce = [0u8; 8];
                nonce.copy_from_slice(&msg.payload[..8]);
                let new_cid = mgr.allocate_cid();
                let pkt = CtapHidFramer::frame_init_response(
                    msg.cid,
                    &nonce,
                    new_cid,
                    1,
                    0,
                    0,
                    CAPABILITY_WINK | CAPABILITY_CBOR,
                );
                return CtaphidDispatch {
                    responses: vec![pkt],
                    origin: Some(origin),
                    consumed_up: false,
                };
            }
            if msg.cmd == CMD_PING {
                return CtaphidDispatch {
                    responses: CtapHidFramer::frame_ping(msg.cid, &msg.payload),
                    origin: Some(origin),
                    consumed_up: false,
                };
            }
            if msg.cmd == CMD_WINK {
                return CtaphidDispatch {
                    responses: CtapHidFramer::frame_message(msg.cid, CMD_WINK, &[]),
                    origin: Some(origin),
                    consumed_up: false,
                };
            }
            // Vendor/bind-mgmt/wallet/fw-log/rescue/pairing serial no
            // dispatcher FreeRTOS (paridade seção D legada) + backup-export
            // 0x3A + OTA 0x30-0x34 (espelho seção C; COMMIT só via USB).
            // `None` = cai no engine CTAP genérico abaixo (U2F/desconhecido).
            if msg.cmd == CMD_MSG && !msg.payload.is_empty() {
                if let Some(ctx) = vendor.as_mut() {
                    // Fonte única da origem (COMMIT OTA só via USB): o
                    // chamador não precisa acertar o campo na construção.
                    ctx.origin = origin;
                    if let Some((responses, consumed)) = dispatch_serial_vendor_msg(ctx, &msg) {
                        return CtaphidDispatch {
                            responses,
                            origin: Some(origin),
                            consumed_up: consumed,
                        };
                    }
                }
            }
            if msg.cmd == CMD_CBOR || msg.cmd == CMD_MSG {
                let up_needed = ctaphid_up_required(msg.cmd, &msg.payload);
                let up_ok = !up_needed || up_latched;
                let consumed = up_needed && up_latched;
                engine.set_user_presence(up_ok);
                let mut rng = rand_core::OsRng;
                let resp = engine.process_packet(&msg.payload, now_secs, &mut rng);
                // CTAP Reset ok (`0x07` in-window + UP → `0x00`): wipe total
                // NVS + espelhos RAM (o engine core já zerou PIN/blobs/store
                // residentes). Sem `vendor` (só-CTAP em teste de host) não há
                // NVS vinculada: nada a apagar além do RAM do engine.
                if msg.cmd == CMD_CBOR
                    && msg.payload.first() == Some(&CTAP_CMD_RESET)
                    && resp.first() == Some(&0x00)
                {
                    if let Some(ctx) = vendor.as_mut() {
                        crate::vendor_exec::ctap_reset_wipe(
                            ctx.storage,
                            ctx.binding,
                            ctx.key_mgr,
                            ctx.oath,
                        );
                        *ctx.key_mgr = aegis_fido_core::credential::key_manager::KeyManager::new();
                        *ctx.oath = aegis_fido_core::oath::OathApplet::new();
                        *ctx.wallet = aegis_fido_core::wallet::WalletStore::new();
                        log::info!("[RESET] wipe total pos-0x00.");
                    }
                }
                return CtaphidDispatch {
                    responses: CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp),
                    origin: Some(origin),
                    consumed_up: consumed,
                };
            }
            CtaphidDispatch {
                responses: vec![CtapHidFramer::frame_error(msg.cid, 0x01)],
                origin: Some(origin),
                consumed_up: false,
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::freertos_sched::{
        packet_bytes, packet_origin, packet_task_step, serial_task_step, usb_task_step,
        FirmwareEvent, CTAPHID_PACKET_SIZE,
    };
    use crate::persistence::FlashStorageBackend;

    fn init_raw(cid: u32, cmd: u8, payload: &[u8]) -> [u8; CTAPHID_PACKET_SIZE] {
        let mut raw = [0u8; CTAPHID_PACKET_SIZE];
        raw[0..4].copy_from_slice(&cid.to_be_bytes());
        raw[4] = cmd | 0x80;
        raw[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let take = payload.len().min(CTAPHID_PACKET_SIZE - 7);
        raw[7..7 + take].copy_from_slice(&payload[..take]);
        raw
    }

    /// Managers USB/serial + engine novos p/ cada caso (sem estado vazado).
    fn new_test_managers() -> (CtapHidManager, CtapHidManager, CtapEngine) {
        (
            CtapHidManager::new(),
            CtapHidManager::new(),
            CtapEngine::new([0x11; 32], 0),
        )
    }

    #[test]
    fn pacote_usb_responde_via_usb() {
        use aegis_fido_usb::ctaphid::CMD_PING;
        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();
        let raw = init_raw(0x1234_5678, CMD_PING, b"oi");
        let ev = FirmwareEvent::UsbPacket(raw);
        assert_eq!(packet_origin(&ev), Some(PacketOrigin::Usb));
        let out = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev,
            false,
            100,
            0,
            None,
        );
        assert_eq!(out.origin, Some(PacketOrigin::Usb));
        assert!(!out.consumed_up);
        assert_eq!(out.responses.len(), 1);
        assert_eq!(&out.responses[0][0..4], &0x1234_5678u32.to_be_bytes());
        assert_eq!(out.responses[0][4], CMD_PING);
        // Serial ficou intocado (sem reassemble pendente).
        assert!(!mgr_serial.has_pending_assembly());
    }

    #[test]
    fn pacote_serial_responde_via_serial() {
        use aegis_fido_usb::ctaphid::CMD_PING;
        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();
        let raw = init_raw(0x0102_0304, CMD_PING, b"ping-serial");
        let ev = FirmwareEvent::SerialPacket(raw);
        assert_eq!(packet_origin(&ev), Some(PacketOrigin::Serial));
        let out = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev,
            false,
            200,
            0,
            None,
        );
        assert_eq!(out.origin, Some(PacketOrigin::Serial));
        assert!(!out.consumed_up);
        assert_eq!(out.responses.len(), 1);
        assert_eq!(&out.responses[0][0..4], &0x0102_0304u32.to_be_bytes());
        assert_eq!(out.responses[0][4], CMD_PING);
        assert!(!mgr_usb.has_pending_assembly());
    }

    #[test]
    fn texto_curto_nunca_vira_pacote() {
        // Texto de diagnóstico (< 64 B) não constrói evento: o passo só
        // aceita `[u8; 64]` completo; `None` = nada a drenar.
        assert_eq!(usb_task_step(None), None);
        assert_eq!(serial_task_step(None), None);
        assert_eq!(packet_task_step(None), None);
        let text = b"TEST_UP\n";
        assert!(text.len() < CTAPHID_PACKET_SIZE);
        // Eventos sem pacote não têm origem nem bytes.
        let tick = FirmwareEvent::Tick10ms(7);
        assert_eq!(packet_origin(&tick), None);
        assert_eq!(packet_bytes(&tick), None);
        let btn = FirmwareEvent::ButtonPress {
            boot: true,
            key: false,
        };
        assert_eq!(packet_origin(&btn), None);
        // Roteamento de não-pacote: sem resposta, sem consumo de latch.
        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();
        let out = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &tick,
            true,
            0,
            0,
            None,
        );
        assert!(out.responses.is_empty());
        assert_eq!(out.origin, None);
        assert!(!out.consumed_up);
    }

    #[test]
    fn up_latch_tem_consumo_unico_no_roteamento() {
        use aegis_fido_usb::ctaphid::CMD_CBOR;
        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();
        // `makeCredential` vazio: engine nega, mas o latch é consumido 1x.
        let raw = init_raw(0x0A0B_0C0D, CMD_CBOR, &[CTAP_CMD_MAKE_CREDENTIAL]);
        let ev = FirmwareEvent::UsbPacket(raw);
        let out = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev,
            false,
            300,
            0,
            None,
        );
        assert!(!out.consumed_up);
        assert_eq!(out.origin, Some(PacketOrigin::Usb));
        assert_eq!(out.responses.len(), 1);
        let raw2 = init_raw(0x0A0B_0C0D, CMD_CBOR, &[CTAP_CMD_MAKE_CREDENTIAL]);
        let ev2 = FirmwareEvent::SerialPacket(raw2);
        let out2 = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev2,
            true,
            310,
            0,
            None,
        );
        assert!(out2.consumed_up);
        assert_eq!(out2.origin, Some(PacketOrigin::Serial));
    }

    #[test]
    fn erro_de_protocolo_volta_na_mesma_origem() {
        // CONT sem INIT: violação de sequência -> pacote de erro enquadrado.
        let mut raw = [0u8; CTAPHID_PACKET_SIZE];
        raw[0..4].copy_from_slice(&0x7777_8888u32.to_be_bytes());
        raw[4] = 0x00; // CONT seq 0 sem INIT prévio.
        let ev = FirmwareEvent::SerialPacket(raw);
        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();
        let out = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev,
            false,
            400,
            0,
            None,
        );
        assert_eq!(out.origin, Some(PacketOrigin::Serial));
        assert!(!out.consumed_up);
        assert_eq!(out.responses.len(), 1);
        assert_eq!(out.responses[0][4], 0xBF); // CMD_ERROR.
    }

    /// Regressão: janela recém-aberta (sem nenhum Tick no meio) tem que
    /// passar no gate vendor — o dispatcher lia um cache atualizado só
    /// 1×/s e devolvia 0x05 indevido no mesmo segundo da abertura.
    #[test]
    fn vendor_enxerga_janela_fresca_sem_tick() {
        use crate::binding::BindingManager;
        use crate::ble::gatt_core::OP_KEY_LIST;
        use crate::fw_log::FwLog;
        use crate::pairing::PairingManager;
        use crate::persistence::{PlatformFlashBackend, SecureStorage};
        use aegis_fido_core::credential::key_manager::KeyManager;
        use aegis_fido_core::oath::OathApplet;
        use aegis_fido_core::otp::rescue::RescueEngine;
        use aegis_fido_core::wallet::WalletStore;
        use aegis_fido_usb::ctaphid::CMD_MSG;

        let mut pairing = PairingManager::new();
        let mut binding = BindingManager::new();
        let backend = PlatformFlashBackend::new();
        let mut storage = SecureStorage::new(backend, &[0x11; 32], &[0x22; 32]);
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();
        let mut fwlog = FwLog::new();
        let mut rescue = RescueEngine::new();
        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();

        // Abre a janela e despacha IMEDIATAMENTE, sem Tick no meio
        // (é exatamente o que o dispatcher fazia de errado: lia sombra).
        pairing.open_host_window(0);
        let raw = init_raw(0x0A0B_0C0D, CMD_MSG, &[OP_KEY_LIST]);
        let ev = FirmwareEvent::SerialPacket(raw);
        // Liveness lida NA HORA, como o dispatcher deve montar o ctx.
        let open_now = pairing.is_pairing_window_open(0);
        let mut vendor = SerialVendorCtx {
            pairing_open: open_now,
            up_latched: true,
            now_ms: 0,
            now_secs: 0,
            binding: &mut binding,
            storage: &mut storage,
            wallet: &mut wallet,
            key_mgr: &mut key_mgr,
            oath: &mut oath,
            fwlog: &mut fwlog,
            rescue: &mut rescue,
            pairing: &mut pairing,
            pin_uv_session: false,
            ota_state: None,
            ota_provisioned: false,
            ota_pubkey: [0u8; 32],
            ota_current_version: 0,
            origin: PacketOrigin::Serial,
        };
        let out = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev,
            true,
            0,
            0,
            Some(&mut vendor),
        );
        assert!(out.consumed_up, "latch UP deve ser consumido");
        assert_eq!(out.responses.len(), 1);
        // KEY_LIST vazio responde 0x00 (nunca 0x05 de gate com janela aberta).
        assert_eq!(out.responses[0][7], 0x00);
    }

    /// Janela fechada continua negando (NeedPairing 0x05), mesmo com UP.
    /// Usa op CONFIG (KEY_GEN exige pairing); USAGE (ex. KEY_LIST) não
    /// tem gate de pairing e responderia 0x00 com UP válido.
    #[test]
    fn vendor_barra_sem_janela_mesmo_com_up() {
        use crate::binding::BindingManager;
        use crate::ble::gatt_core::OP_KEY_GEN_ONDEVICE;
        use crate::fw_log::FwLog;
        use crate::pairing::PairingManager;
        use crate::persistence::{PlatformFlashBackend, SecureStorage};
        use aegis_fido_core::credential::key_manager::KeyManager;
        use aegis_fido_core::oath::OathApplet;
        use aegis_fido_core::otp::rescue::RescueEngine;
        use aegis_fido_core::wallet::WalletStore;
        use aegis_fido_usb::ctaphid::CMD_MSG;

        let mut pairing = PairingManager::new();
        let mut binding = BindingManager::new();
        let backend = PlatformFlashBackend::new();
        let mut storage = SecureStorage::new(backend, &[0x11; 32], &[0x22; 32]);
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();
        let mut fwlog = FwLog::new();
        let mut rescue = RescueEngine::new();
        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();

        // Sem abrir janela: gate deve negar com 0x05 e NÃO consumir o latch.
        // (op CONFIG KEY_GEN exige pairing; USAGE como KEY_LIST não tem
        // gate de pairing e retornaria 0x00 com UP válido.)
        let raw = init_raw(0x0A0B_0C0D, CMD_MSG, &[OP_KEY_GEN_ONDEVICE]);
        let ev = FirmwareEvent::SerialPacket(raw);
        let mut vendor = SerialVendorCtx {
            pairing_open: pairing.is_pairing_window_open(0),
            up_latched: true,
            now_ms: 0,
            now_secs: 0,
            binding: &mut binding,
            storage: &mut storage,
            wallet: &mut wallet,
            key_mgr: &mut key_mgr,
            oath: &mut oath,
            fwlog: &mut fwlog,
            rescue: &mut rescue,
            pairing: &mut pairing,
            pin_uv_session: false,
            ota_state: None,
            ota_provisioned: false,
            ota_pubkey: [0u8; 32],
            ota_current_version: 0,
            origin: PacketOrigin::Serial,
        };
        let out = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev,
            true,
            0,
            0,
            Some(&mut vendor),
        );
        assert!(!out.consumed_up, "latch não deve ser consumido na negação");
        assert_eq!(out.responses.len(), 1);
        assert_eq!(out.responses[0][7], 0x05);
    }

    /// Envia 1 payload `CMD_MSG` pela rota (fragmenta em 64 B, drena o
    /// reassemble do transporte) e devolve o dispatch final.
    #[allow(clippy::too_many_arguments)]
    fn route_msg(
        mgr_usb: &mut CtapHidManager,
        mgr_serial: &mut CtapHidManager,
        engine: &mut CtapEngine,
        vendor: &mut SerialVendorCtx<'_>,
        origin: PacketOrigin,
        cid: u32,
        payload: &[u8],
        now_ms: u64,
    ) -> CtaphidDispatch {
        let pkts = CtapHidFramer::frame_message(cid, CMD_MSG, payload);
        let mut last = CtaphidDispatch {
            responses: Vec::new(),
            origin: Some(origin),
            consumed_up: false,
        };
        for (i, pkt) in pkts.iter().enumerate() {
            let ev = match origin {
                PacketOrigin::Usb => FirmwareEvent::UsbPacket(*pkt),
                PacketOrigin::Serial => FirmwareEvent::SerialPacket(*pkt),
            };
            last = route_ctaphid_event(
                mgr_usb,
                mgr_serial,
                engine,
                &ev,
                true,
                now_ms + i as u64,
                0,
                Some(&mut *vendor),
            );
        }
        last
    }

    /// Monta um contexto vendor de teste (empresta os fixtures do chamador).
    #[allow(clippy::too_many_arguments)]
    fn vendor_with<'a>(
        pairing_open: bool,
        up: bool,
        pin: bool,
        binding: &'a mut crate::binding::BindingManager,
        storage: &'a mut crate::persistence::SecureStorage<
            crate::persistence::PlatformFlashBackend,
        >,
        wallet: &'a mut aegis_fido_core::wallet::WalletStore,
        key_mgr: &'a mut aegis_fido_core::credential::key_manager::KeyManager,
        oath: &'a mut aegis_fido_core::oath::OathApplet,
        fwlog: &'a mut crate::fw_log::FwLog,
        rescue: &'a mut aegis_fido_core::otp::rescue::RescueEngine,
        pairing: &'a mut crate::pairing::PairingManager,
        ota: Option<&'a mut OtaState>,
        ota_provisioned: bool,
        ota_pubkey: [u8; 32],
        ota_current_version: u32,
    ) -> SerialVendorCtx<'a> {
        SerialVendorCtx {
            pairing_open,
            up_latched: up,
            now_ms: 0,
            now_secs: 0,
            binding,
            storage,
            wallet,
            key_mgr,
            oath,
            fwlog,
            rescue,
            pairing,
            pin_uv_session: pin,
            ota_state: ota,
            ota_provisioned,
            ota_pubkey,
            ota_current_version,
            origin: PacketOrigin::Serial,
        }
    }

    /// Reivindica o binding em RAM (janela + UP; sem NVS, basta p/ o gate).
    fn claim_binding(binding: &mut crate::binding::BindingManager) {
        let sk = p256::ecdsa::SigningKey::from_slice(&[0x11u8; 32]).expect("scalar valido");
        let pt = sk.verifying_key().to_encoded_point(false);
        let mut sec1 = [0u8; crate::binding::BIND_PUB_LEN];
        sec1.copy_from_slice(pt.as_bytes());
        binding
            .claim(&sec1, &[0xABu8; crate::binding::BIND_ID_LEN], true, true)
            .expect("claim");
    }

    /// Status wire = 1º byte do payload (resposta pacote único).
    fn resp_status(out: &CtaphidDispatch) -> u8 {
        assert_eq!(out.responses.len(), 1, "resposta pacote único");
        out.responses[0][7]
    }

    /// CTAP Reset (`0x07` in-window + UP → `0x00`) faz wipe total NVS +
    /// espelhos RAM na rota FreeRTOS (prova host do chamador pós-`0x00`).
    #[test]
    fn reset_ok_faz_wipe_total_nvs_e_ram() {
        use crate::oath_store::oath_store_put;
        use aegis_fido_core::credential::key_manager::KeyManager;
        use aegis_fido_core::credential::store::CredentialStore;
        use aegis_fido_core::credential::{KEY_USE_AUTH, KEY_USE_SIGN};
        use aegis_fido_core::crypto::curves::CoseAlgorithm;
        use aegis_fido_core::ctap::client_pin::ClientPinState;
        use aegis_fido_core::oath::tlv::write_tlv;
        use aegis_fido_core::oath::types::{TAG_KEY, TAG_NAME};
        use aegis_fido_core::oath::OathApplet;
        use aegis_fido_usb::ctaphid::CMD_CBOR;

        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();
        let backend = crate::persistence::PlatformFlashBackend::new();
        let mut storage = crate::persistence::SecureStorage::new(backend, &[0x11; 32], &[0x22; 32]);
        // Estado pré-reset: chave vendor (RAM+NVS) + conta OATH (RAM+NVS)
        // + PIN (NVS) + vínculo (RAM+NVS).
        let mut key_mgr = KeyManager::new();
        let mut rng = rand_core::OsRng;
        key_mgr
            .generate(
                0,
                CoseAlgorithm::ES256,
                "rt-k".into(),
                KEY_USE_SIGN | KEY_USE_AUTH,
                0,
                true,
                &mut rng,
            )
            .expect("gen");
        storage
            .store(
                crate::vendor_exec::NVS_KEYS_SLOTS,
                &key_mgr.export_state(),
                &[0u8; 12],
            )
            .expect("nvs keys");
        let mut oath = OathApplet::new();
        let mut put = Vec::new();
        write_tlv(&mut put, TAG_NAME, b"rt-oath");
        let mut kv = vec![0x21u8, 0x06];
        kv.extend_from_slice(&[0x5Au8; 10]);
        write_tlv(&mut put, TAG_KEY, &kv);
        oath.device_put(&put, true, true).expect("oath put");
        storage
            .store(
                crate::vendor_exec::NVS_KEYS_OATH,
                &oath.export_state(),
                &[0u8; 12],
            )
            .expect("nvs oath");
        oath_store_put(&mut storage, "rt-oath", b"oath-blob").expect("oath6 put");
        crate::vendor_exec::save_pin_state_result(
            &mut storage,
            &ClientPinState {
                pin_hash: Some([0xEEu8; 16]),
                pin_retries: 8,
                ..Default::default()
            },
        )
        .expect("nvs pin");
        let mut binding = crate::binding::BindingManager::new();
        claim_binding(&mut binding);
        binding.persist(&mut storage).expect("persist");
        assert!(storage.exists(crate::vendor_exec::NVS_KEYS_SLOTS));
        assert!(binding.is_claimed());

        let mut wallet = aegis_fido_core::wallet::WalletStore::new();
        let mut fwlog = crate::fw_log::FwLog::new();
        let mut rescue = aegis_fido_core::otp::rescue::RescueEngine::new();
        let mut pairing = crate::pairing::PairingManager::new();
        let mut vendor = vendor_with(
            true,
            true,
            false,
            &mut binding,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            &mut fwlog,
            &mut rescue,
            &mut pairing,
            None,
            false,
            [0u8; 32],
            0,
        );
        // CBOR `0x07` pacote único via USB, janela (boot 0, t 0) + UP.
        let pkts = CtapHidFramer::frame_message(0x0A0B_0C0D, CMD_CBOR, &[CTAP_CMD_RESET]);
        assert_eq!(pkts.len(), 1);
        let ev = FirmwareEvent::UsbPacket(pkts[0]);
        let out = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev,
            true,
            100,
            0,
            Some(&mut vendor),
        );
        assert_eq!(resp_status(&out), 0x00);
        assert!(out.consumed_up);
        // Wipe total: NVS zerada + vínculo liberado + espelhos frescos.
        assert!(!vendor.storage.exists(crate::vendor_exec::NVS_KEYS_SLOTS));
        assert!(!vendor.storage.exists(crate::vendor_exec::NVS_KEYS_OATH));
        assert!(!vendor.storage.exists(crate::vendor_exec::NVS_PIN_HASH));
        assert!(!vendor.storage.exists("oath6/rt-oath"));
        assert!(!vendor.binding.is_claimed());
        assert_eq!(vendor.key_mgr.len(), 0);
        assert!(vendor
            .oath
            .device_list(false, true)
            .expect("list")
            .is_empty());
        assert!(!engine.pin_state.is_pin_set());
        assert_eq!(engine.store.count_resident(), 0);
    }

    /// Manifesto 104 B assinado de verdade (compatível com o fio legado).
    fn signed_manifest_for(version: u32, image: &[u8], sk: &ed25519_dalek::SigningKey) -> Vec<u8> {
        use sha2::{Digest as _, Sha256};
        use signature::Signer as _;
        let digest = Sha256::digest(image);
        let mut unsigned = Vec::with_capacity(crate::ota::OTA_MANIFEST_LEN);
        unsigned.extend_from_slice(&version.to_be_bytes());
        unsigned.extend_from_slice(&(image.len() as u32).to_be_bytes());
        unsigned.extend_from_slice(&digest);
        unsigned.extend_from_slice(&[0x5Eu8; 64]);
        let m = crate::ota::OtaManifest::parse(&unsigned).expect("parse unsigned");
        let sig = sk.sign(&m.signed_bytes());
        let mut raw = Vec::with_capacity(crate::ota::OTA_MANIFEST_LEN);
        raw.extend_from_slice(&version.to_be_bytes());
        raw.extend_from_slice(&(image.len() as u32).to_be_bytes());
        raw.extend_from_slice(&digest);
        raw.extend_from_slice(&sig.to_bytes());
        raw
    }

    #[test]
    fn backup_export_sem_up_nega_01() {
        use crate::ble::gatt_core::OP_BACKUP_EXPORT;
        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();
        let backend = crate::persistence::PlatformFlashBackend::new();
        let mut storage = crate::persistence::SecureStorage::new(backend, &[0x11; 32], &[0x22; 32]);
        storage
            .store(crate::vendor_exec::NVS_KEYS_SLOTS, b"SEGREDO1", &[0u8; 12])
            .expect("store keys");
        let mut binding = crate::binding::BindingManager::new();
        claim_binding(&mut binding);
        let mut wallet = aegis_fido_core::wallet::WalletStore::new();
        let mut key_mgr = aegis_fido_core::credential::key_manager::KeyManager::new();
        let mut oath = aegis_fido_core::oath::OathApplet::new();
        let mut fwlog = crate::fw_log::FwLog::new();
        let mut rescue = aegis_fido_core::otp::rescue::RescueEngine::new();
        let mut pairing = crate::pairing::PairingManager::new();
        let mut vendor = vendor_with(
            true,
            false,
            true,
            &mut binding,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            &mut fwlog,
            &mut rescue,
            &mut pairing,
            None,
            false,
            [0u8; 32],
            0,
        );
        // Sem UP (com pairing+binding+PIN): NEED_UP 0x01, latch intacto.
        let out = route_msg(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &mut vendor,
            PacketOrigin::Serial,
            0x0A0B_0C0D,
            &[OP_BACKUP_EXPORT, 0x01],
            1000,
        );
        assert_eq!(resp_status(&out), 0x01);
        assert!(!out.consumed_up);
    }

    #[test]
    fn backup_export_sem_pairing_nega_05() {
        use crate::ble::gatt_core::OP_BACKUP_EXPORT;
        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();
        let backend = crate::persistence::PlatformFlashBackend::new();
        let mut storage = crate::persistence::SecureStorage::new(backend, &[0x11; 32], &[0x22; 32]);
        let mut binding = crate::binding::BindingManager::new();
        claim_binding(&mut binding);
        let mut wallet = aegis_fido_core::wallet::WalletStore::new();
        let mut key_mgr = aegis_fido_core::credential::key_manager::KeyManager::new();
        let mut oath = aegis_fido_core::oath::OathApplet::new();
        let mut fwlog = crate::fw_log::FwLog::new();
        let mut rescue = aegis_fido_core::otp::rescue::RescueEngine::new();
        let mut pairing = crate::pairing::PairingManager::new();
        let mut vendor = vendor_with(
            false,
            true,
            true,
            &mut binding,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            &mut fwlog,
            &mut rescue,
            &mut pairing,
            None,
            false,
            [0u8; 32],
            0,
        );
        // Sem janela (CONFIG serial): NEED_BINDING 0x05, sem consumo.
        let out = route_msg(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &mut vendor,
            PacketOrigin::Serial,
            0x0A0B_0C0D,
            &[OP_BACKUP_EXPORT, 0x01],
            1000,
        );
        assert_eq!(resp_status(&out), 0x05);
        assert!(!out.consumed_up);
    }

    #[test]
    fn backup_export_com_up_retorna_envelope_sem_segredo() {
        use crate::ble::gatt_core::OP_BACKUP_EXPORT;
        use crate::serial_vendor::BACKUP_SELECTOR_KEYS;
        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();
        let backend = crate::persistence::PlatformFlashBackend::new();
        let mut storage = crate::persistence::SecureStorage::new(backend, &[0x11; 32], &[0x22; 32]);
        let marker = b"SEGREDO1";
        storage
            .store(crate::vendor_exec::NVS_KEYS_SLOTS, marker, &[0u8; 12])
            .expect("store keys");
        let mut binding = crate::binding::BindingManager::new();
        claim_binding(&mut binding);
        let mut wallet = aegis_fido_core::wallet::WalletStore::new();
        let mut key_mgr = aegis_fido_core::credential::key_manager::KeyManager::new();
        let mut oath = aegis_fido_core::oath::OathApplet::new();
        let mut fwlog = crate::fw_log::FwLog::new();
        let mut rescue = aegis_fido_core::otp::rescue::RescueEngine::new();
        let mut pairing = crate::pairing::PairingManager::new();
        let mut vendor = vendor_with(
            true,
            true,
            true,
            &mut binding,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            &mut fwlog,
            &mut rescue,
            &mut pairing,
            None,
            false,
            [0u8; 32],
            0,
        );
        let out = route_msg(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &mut vendor,
            PacketOrigin::Serial,
            0x0A0B_0C0D,
            &[OP_BACKUP_EXPORT, BACKUP_SELECTOR_KEYS],
            1000,
        );
        assert_eq!(resp_status(&out), 0x00);
        assert!(out.consumed_up, "sucesso consome o latch 1x");
        // Corpo = envelope AEGN at-rest íntegro: magia + versão + tamanho.
        let expected = vendor
            .storage
            .backend()
            .read_raw(crate::vendor_exec::NVS_KEYS_SLOTS)
            .expect("stored");
        let mut want = Vec::with_capacity(1 + expected.len());
        want.push(0x00);
        want.extend_from_slice(&expected);
        assert_eq!(out.responses[0][7..7 + want.len()], want[..]);
        let env = &want[1..];
        assert_eq!(&env[0..4], b"AEGN");
        assert_eq!(env[4], 0x01);
        assert!(env.len() >= 4 + 1 + 12 + 16);
        // Segredo nunca no fio: o marcador do claro não aparece no envelope.
        let region = &out.responses[0][7..7 + want.len()];
        assert!(!region.windows(marker.len()).any(|w| w == marker));
        // OATH vazio falha fechado (0x04, sem oráculo).
        let out2 = route_msg(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &mut vendor,
            PacketOrigin::Serial,
            0x0A0B_0C0D,
            &[OP_BACKUP_EXPORT, 0x02],
            1010,
        );
        assert_eq!(resp_status(&out2), 0x04);
        assert!(!out2.consumed_up);
    }

    #[test]
    fn backup_export_falha_fechado() {
        use crate::ble::gatt_core::OP_BACKUP_EXPORT;
        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();
        let backend = crate::persistence::PlatformFlashBackend::new();
        let mut storage = crate::persistence::SecureStorage::new(backend, &[0x11; 32], &[0x22; 32]);
        storage
            .store(crate::vendor_exec::NVS_KEYS_SLOTS, b"SEGREDO1", &[0u8; 12])
            .expect("store keys");
        let mut binding = crate::binding::BindingManager::new();
        claim_binding(&mut binding);
        let mut unclaimed = crate::binding::BindingManager::new();
        let mut wallet = aegis_fido_core::wallet::WalletStore::new();
        let mut key_mgr = aegis_fido_core::credential::key_manager::KeyManager::new();
        let mut oath = aegis_fido_core::oath::OathApplet::new();
        let mut fwlog = crate::fw_log::FwLog::new();
        let mut rescue = aegis_fido_core::otp::rescue::RescueEngine::new();
        let mut pairing = crate::pairing::PairingManager::new();
        // Seletor desconhecido e pedido sem seletor: 0x04 mesmo com gates ok.
        let mut vendor = vendor_with(
            true,
            true,
            true,
            &mut binding,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            &mut fwlog,
            &mut rescue,
            &mut pairing,
            None,
            false,
            [0u8; 32],
            0,
        );
        for payload in [vec![OP_BACKUP_EXPORT, 0x09], vec![OP_BACKUP_EXPORT]] {
            let out = route_msg(
                &mut mgr_usb,
                &mut mgr_serial,
                &mut engine,
                &mut vendor,
                PacketOrigin::Serial,
                0x0A0B_0C0D,
                &payload,
                1000,
            );
            assert_eq!(resp_status(&out), 0x04, "payload {payload:02X?}");
            assert!(!out.consumed_up);
        }
        // Sem vínculo: release nega 0x05; test-mode faz bypass (0x00 c/ UP+PIN).
        let mut vendor_nb = vendor_with(
            true,
            true,
            true,
            &mut unclaimed,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            &mut fwlog,
            &mut rescue,
            &mut pairing,
            None,
            false,
            [0u8; 32],
            0,
        );
        let out = route_msg(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &mut vendor_nb,
            PacketOrigin::Serial,
            0x0A0B_0C0D,
            &[OP_BACKUP_EXPORT, 0x01],
            1100,
        );
        if crate::binding::binding_bypass_enabled() {
            assert_eq!(resp_status(&out), 0x00);
        } else {
            assert_eq!(resp_status(&out), 0x05);
            assert!(!out.consumed_up);
        }
    }

    /// Estagia begin->verify pela origem dada (retorna fase p/ o chamador).
    fn stage_to_verified_route(
        mgr_usb: &mut CtapHidManager,
        mgr_serial: &mut CtapHidManager,
        engine: &mut CtapEngine,
        vendor: &mut SerialVendorCtx<'_>,
        origin: PacketOrigin,
        manifest: &[u8],
        image: &[u8],
    ) {
        use crate::ota::{OP_OTA_BEGIN, OP_OTA_CHUNK, OP_OTA_FINISH};
        let mut begin = vec![OP_OTA_BEGIN];
        begin.extend_from_slice(manifest);
        let out = route_msg(
            mgr_usb,
            mgr_serial,
            engine,
            vendor,
            origin,
            0x0B0C_0D0E,
            &begin,
            2000,
        );
        assert_eq!(resp_status(&out), 0x00, "BEGIN");
        let mut off = 0u32;
        for chunk in image.chunks(16) {
            let mut p = vec![OP_OTA_CHUNK];
            p.extend_from_slice(&off.to_be_bytes());
            p.extend_from_slice(chunk);
            let out = route_msg(
                mgr_usb,
                mgr_serial,
                engine,
                vendor,
                origin,
                0x0B0C_0D0E,
                &p,
                2010,
            );
            assert_eq!(resp_status(&out), 0x00, "CHUNK off={off}");
            off += chunk.len() as u32;
        }
        let out = route_msg(
            mgr_usb,
            mgr_serial,
            engine,
            vendor,
            origin,
            0x0B0C_0D0E,
            &[OP_OTA_FINISH],
            2020,
        );
        assert_eq!(resp_status(&out), 0x00, "FINISH");
    }

    #[test]
    fn ota_freertos_begin_verify_e_commit_bloqueado_fora_usb() {
        use crate::ota::{OtaPhase, OP_OTA_COMMIT};
        const CURRENT: u32 = 7;
        const NEXT: u32 = 8;
        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();
        let backend = crate::persistence::PlatformFlashBackend::new();
        let mut storage = crate::persistence::SecureStorage::new(backend, &[0x11; 32], &[0x22; 32]);
        let image = vec![0xA5u8; 64];
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let manifest = signed_manifest_for(NEXT, &image, &sk);
        let pubkey = sk.verifying_key().to_bytes();
        let mut binding = crate::binding::BindingManager::new();
        let mut wallet = aegis_fido_core::wallet::WalletStore::new();
        let mut key_mgr = aegis_fido_core::credential::key_manager::KeyManager::new();
        let mut oath = aegis_fido_core::oath::OathApplet::new();
        let mut fwlog = crate::fw_log::FwLog::new();
        let mut rescue = aegis_fido_core::otp::rescue::RescueEngine::new();
        let mut pairing = crate::pairing::PairingManager::new();
        let mut ota = OtaState::new(CURRENT);
        // Estagia pela serial (permitido: begin/chunk/verify sem swap).
        let mut vendor = vendor_with(
            false,
            true,
            false,
            &mut binding,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            &mut fwlog,
            &mut rescue,
            &mut pairing,
            Some(&mut ota),
            true,
            pubkey,
            CURRENT,
        );
        stage_to_verified_route(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &mut vendor,
            PacketOrigin::Serial,
            &manifest,
            &image,
        );
        assert_eq!(
            vendor.ota_state.as_ref().map(|s| s.phase()),
            Some(OtaPhase::Verified)
        );
        // COMMIT fora do USB: 0x04, sessão Verified intacta, sem marcador.
        let out = route_msg(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &mut vendor,
            PacketOrigin::Serial,
            0x0B0C_0D0E,
            &[OP_OTA_COMMIT],
            2030,
        );
        assert_eq!(resp_status(&out), crate::ota_store::OTA_STATUS_FAIL);
        assert!(!out.consumed_up);
        assert_eq!(
            vendor.ota_state.as_ref().map(|s| s.phase()),
            Some(OtaPhase::Verified)
        );
        assert!(
            !vendor
                .storage
                .backend()
                .exists(crate::ota_store::OTA_COMMIT_MARKER_KEY),
            "serial nunca grava marcador"
        );
        // COMMIT via USB com UP: 0x00 + versão, latch consumido, marcador.
        let out = route_msg(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &mut vendor,
            PacketOrigin::Usb,
            0x0B0C_0D0E,
            &[OP_OTA_COMMIT],
            2040,
        );
        assert_eq!(resp_status(&out), crate::ota_store::OTA_STATUS_OK);
        assert!(out.consumed_up, "COMMIT ok consome o latch 1x");
        assert_eq!(&out.responses[0][8..12], &NEXT.to_be_bytes());
        assert_eq!(
            vendor.ota_state.as_ref().map(|s| s.phase()),
            Some(OtaPhase::Committed)
        );
        assert_eq!(
            vendor
                .storage
                .backend()
                .read_raw(crate::ota_store::OTA_COMMIT_MARKER_KEY)
                .expect("marcador"),
            NEXT.to_be_bytes().to_vec()
        );
    }

    #[test]
    fn ota_freertos_antiroollback_nega_versao_corrente_ou_menor() {
        use crate::ota::{OtaPhase, OP_OTA_ABORT, OP_OTA_BEGIN, OP_OTA_FINISH};
        const CURRENT: u32 = 7;
        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();
        let backend = crate::persistence::PlatformFlashBackend::new();
        let mut storage = crate::persistence::SecureStorage::new(backend, &[0x11; 32], &[0x22; 32]);
        let image = vec![0xA5u8; 32];
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pubkey = sk.verifying_key().to_bytes();
        let mut binding = crate::binding::BindingManager::new();
        let mut wallet = aegis_fido_core::wallet::WalletStore::new();
        let mut key_mgr = aegis_fido_core::credential::key_manager::KeyManager::new();
        let mut oath = aegis_fido_core::oath::OathApplet::new();
        let mut fwlog = crate::fw_log::FwLog::new();
        let mut rescue = aegis_fido_core::otp::rescue::RescueEngine::new();
        let mut pairing = crate::pairing::PairingManager::new();
        let mut ota = OtaState::new(CURRENT);
        let mut vendor = vendor_with(
            false,
            true,
            false,
            &mut binding,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            &mut fwlog,
            &mut rescue,
            &mut pairing,
            Some(&mut ota),
            true,
            pubkey,
            CURRENT,
        );
        // Versão igual à corrente: BEGIN abre, FINISH nega downgrade + rollback.
        let same = signed_manifest_for(CURRENT, &image, &sk);
        let mut begin = vec![OP_OTA_BEGIN];
        begin.extend_from_slice(&same);
        let out = route_msg(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &mut vendor,
            PacketOrigin::Usb,
            0x0B0C_0D0E,
            &begin,
            2000,
        );
        assert_eq!(resp_status(&out), crate::ota_store::OTA_STATUS_OK);
        let out = route_msg(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &mut vendor,
            PacketOrigin::Usb,
            0x0B0C_0D0E,
            &[OP_OTA_FINISH],
            2010,
        );
        assert_eq!(resp_status(&out), crate::ota_store::OTA_STATUS_FAIL);
        assert_eq!(
            vendor.ota_state.as_ref().map(|s| s.phase()),
            Some(OtaPhase::Idle),
            "downgrade desfaz a sessão"
        );
        // Sem provisionamento: BEGIN nega (ABORT segue OK p/ limpeza).
        vendor.ota_provisioned = false;
        let out = route_msg(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &mut vendor,
            PacketOrigin::Usb,
            0x0B0C_0D0E,
            &[OP_OTA_ABORT],
            2020,
        );
        assert_eq!(resp_status(&out), crate::ota_store::OTA_STATUS_OK);
        let out = route_msg(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &mut vendor,
            PacketOrigin::Usb,
            0x0B0C_0D0E,
            &begin,
            2030,
        );
        assert_eq!(resp_status(&out), crate::ota_store::OTA_STATUS_FAIL);
    }

    #[test]
    fn ota_sem_sessao_no_ctx_cai_no_engine_generico() {
        use crate::ota::OP_OTA_BEGIN;
        let (mut mgr_usb, mut mgr_serial, mut engine) = new_test_managers();
        let backend = crate::persistence::PlatformFlashBackend::new();
        let mut storage = crate::persistence::SecureStorage::new(backend, &[0x11; 32], &[0x22; 32]);
        let mut binding = crate::binding::BindingManager::new();
        let mut wallet = aegis_fido_core::wallet::WalletStore::new();
        let mut key_mgr = aegis_fido_core::credential::key_manager::KeyManager::new();
        let mut oath = aegis_fido_core::oath::OathApplet::new();
        let mut fwlog = crate::fw_log::FwLog::new();
        let mut rescue = aegis_fido_core::otp::rescue::RescueEngine::new();
        let mut pairing = crate::pairing::PairingManager::new();
        // Sem sessão OTA: comportamento anterior (engine genérico), sem panic.
        let mut vendor = vendor_with(
            false,
            true,
            false,
            &mut binding,
            &mut storage,
            &mut wallet,
            &mut key_mgr,
            &mut oath,
            &mut fwlog,
            &mut rescue,
            &mut pairing,
            None,
            false,
            [0u8; 32],
            0,
        );
        let out = route_msg(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &mut vendor,
            PacketOrigin::Serial,
            0x0B0C_0D0E,
            &[OP_OTA_BEGIN],
            2000,
        );
        assert_eq!(out.origin, Some(PacketOrigin::Serial));
        assert!(!out.responses.is_empty());
        assert!(!out.consumed_up);
    }

    #[test]
    fn gaps_t8_espelhados_como_externally_blocked() {
        // Espelho documental dos 7 gaps canonicos (sem importar TrustFacade:
        // T12-parte-A nao depende da T8; fiacao ausente = ExternallyBlocked).
        assert_eq!(FREERTOS_TRUST_GAPS_EXTERNALLY_BLOCKED.len(), 7);
        for g in FREERTOS_TRUST_GAPS_EXTERNALLY_BLOCKED {
            assert!(!g.is_empty());
        }
        assert!(FREERTOS_TRUST_GAPS_EXTERNALLY_BLOCKED.contains(&"BleDispatch"));
        assert!(FREERTOS_TRUST_GAPS_EXTERNALLY_BLOCKED.contains(&"RssiSensor"));
        assert!(FREERTOS_TRUST_GAPS_EXTERNALLY_BLOCKED.contains(&"NvsProxK"));
        assert!(FREERTOS_TRUST_GAPS_EXTERNALLY_BLOCKED.contains(&"BindingWire"));
        assert!(FREERTOS_TRUST_GAPS_EXTERNALLY_BLOCKED.contains(&"PinSession"));
        assert!(FREERTOS_TRUST_GAPS_EXTERNALLY_BLOCKED.contains(&"GattDispatch"));
        assert!(FREERTOS_TRUST_GAPS_EXTERNALLY_BLOCKED.contains(&"WifiCoex"));
    }
}
