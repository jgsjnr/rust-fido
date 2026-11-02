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

use crate::ble_gatt::{is_bind_mgmt_op, is_piv_enroll_op, is_vendor_keys_oath_op, is_wallet_op};
use crate::freertos_sched::{
    packet_bytes, packet_origin, FirmwareEvent, PacketOrigin, CTAPHID_PACKET_SIZE,
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
    /// `true` quando a operação armou novo latch UP (ex.: 0x2F trigger de pareamento).
    pub arm_up: bool,
    /// `true` quando o PIN ou recovery foi verificado (ex.: 0x2D ou 0x2F).
    pub pin_verified: bool,
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
    /// Se true, a op disparou armacao de UP latched por 10s (ex.: trigger 0x2F).
    pub arm_up: bool,
    /// Se true, PIN ou recovery foi verificado com sucesso.
    pub pin_verified: bool,
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
    /// Mecanismo do Secure Guard (autoridade local e barreira de autorização).
    pub secure_guard: Option<&'a mut aegis_fido_core::secure_guard::SecureGuardEngine>,
}

/// Despacha 1 `CMD_MSG` serial vendor/bind-mgmt/wallet/fw-log/rescue/
/// pairing no dispatcher FreeRTOS (espelho da seção D legada, sem espera).
///
/// Retorna `Some((pacotes_64B, consumed_up))` quando a op é tratada aqui;
/// `None` = cair no engine CTAP genérico (U2F/OTA/desconhecido), preservando
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
        if st == 0x00 && op == crate::ble_gatt::OP_BIND_RELEASE {
            *ctx.key_mgr = aegis_fido_core::credential::key_manager::KeyManager::new();
            *ctx.wallet = aegis_fido_core::wallet::WalletStore::new();
            *ctx.oath = aegis_fido_core::oath::OathApplet::new();
            let _ = crate::vendor_exec::save_states(ctx.storage, ctx.key_mgr, ctx.oath);
            if let Some(ref mut sg) = ctx.secure_guard {
                **sg = aegis_fido_core::secure_guard::SecureGuardEngine::new(Default::default());
                let _ = crate::secure_guard_storage::save_secure_guard_record(ctx.storage, sg);
            }
        }
        if st == 0x00 && op == crate::ble_gatt::OP_RECOVERY_UNLOCK {
            ctx.pin_verified = true;
        }
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
    // Secure Guard 0x3A-0x3E: protocolo CBOR de status, provisionamento, unlock, lock, config e wipe.
    if crate::ble_gatt::is_secure_guard_op(op) {
        if let Some(ref mut sg) = ctx.secure_guard {
            let mut rng = rand_core::OsRng;
            let (st, body) = crate::secure_guard_exec::exec_secure_guard_op(
                sg,
                ctx.storage,
                ctx.wallet,
                ctx.key_mgr,
                ctx.oath,
                op,
                &payload[1..],
                ctx.now_ms,
                &mut rng,
            );
            if st == 0x00 && sg.is_unlocked() {
                ctx.pin_verified = true;
                ctx.pairing.open_host_window(ctx.now_ms);
                ctx.pairing_open = true;
                ctx.arm_up = true;
            } else if st == 0x00 && op == crate::ble_gatt::OP_SECURE_GUARD_LOCK {
                ctx.pin_verified = false;
                ctx.pairing_open = false;
                ctx.pairing.lock();
            }
            let mut resp = Vec::with_capacity(1 + body.len());
            resp.push(st);
            resp.extend_from_slice(&body);
            return Some((CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp), false));
        } else {
            return Some((
                CtapHidFramer::frame_message(
                    msg.cid,
                    msg.cmd,
                    &[crate::secure_guard_exec::CTAP2_ERR_PIN_REQUIRED],
                ),
                false,
            ));
        }
    }
    // Vendor keys/OATH + carteira + PIV enroll: UP do latch (como o BLE);
    // negação carrega o wire status.
    if is_vendor_keys_oath_op(op) || is_wallet_op(op) || is_piv_enroll_op(op) {
        let sg_unlocked = ctx
            .secure_guard
            .as_ref()
            .map(|sg| sg.is_unlocked())
            .unwrap_or(false);
        // Barreira de Autorização Obrigatória (Enforcement) Secure Guard:
        // Exige que o Secure Guard esteja Unlocked para todas as operações protegidas de chaves/carteiras.
        if let Some(ref mut sg) = ctx.secure_guard {
            if let Err(e) = sg.authorize_vendor_opcode(op, ctx.now_ms) {
                log::warn!(
                    "[SECURE_GUARD] Bloqueado pela barreira de autorização: op=0x{:02X}, estado={:?}, err={:?}",
                    op,
                    sg.state(),
                    e
                );
                return Some((
                    CtapHidFramer::frame_message(
                        msg.cid,
                        msg.cmd,
                        &[crate::secure_guard_exec::CTAP2_ERR_PIN_REQUIRED],
                    ),
                    false,
                ));
            }
        }
        let pairing_open_effective = ctx.pairing_open || sg_unlocked;
        let up_effective = ctx.up_latched || sg_unlocked;
        let gate = if sg_unlocked {
            SerialGate::Ok
        } else {
            authorize_serial(msg.cmd, payload, pairing_open_effective, up_effective)
        };
        match gate {
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
                let binding_claimed_effective =
                    ctx.binding.is_claimed() || sg_unlocked || ctx.pairing_open;
                let pin_effective = ctx.pin_uv_session
                    || ctx.pin_verified
                    || sg_unlocked
                    || (cfg!(feature = "test-mode") && (ctx.pairing_open || ctx.up_latched));
                let (st, body) = if is_wallet_op(op) {
                    use crate::ble_gatt::{OP_WALLET_ADDR, OP_WALLET_GEN, OP_WALLET_LIST};
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
                        binding_claimed_effective,
                        pin_effective,
                        true,
                        ctx.now_secs,
                        &mut rng,
                    )
                };
                ctx.rescue.set_user_presence(true);
                let mut resp = Vec::with_capacity(1 + body.len());
                resp.push(st);
                resp.extend_from_slice(&body);
                let consumed = !sg_unlocked;
                return Some((CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp), consumed));
            }
        }
    }
    // Pareamento por software (trigger 0x2F): abre a mesma janela de 60 s
    // do hold; UART = posse física.
    if crate::pairing::is_host_pairing_msg(op, payload.len() - 1) {
        ctx.pairing.open_host_window(ctx.now_ms);
        ctx.arm_up = true;
        ctx.pin_verified = true;
        ctx.pairing_open = true;
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
    // OTA/U2F/desconhecido: cai no engine genérico (comportamento anterior).
    None
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
    vendor: Option<&mut SerialVendorCtx<'_>>,
) -> CtaphidDispatch {
    let origin = packet_origin(event);
    let raw = packet_bytes(event);
    let (Some(origin), Some(raw)) = (origin, raw) else {
        return CtaphidDispatch {
            responses: Vec::new(),
            origin: None,
            consumed_up: false,
            arm_up: false,
            pin_verified: false,
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
            arm_up: false,
            pin_verified: false,
        },
        Err(err) => CtaphidDispatch {
            responses: vec![err.to_packet()],
            origin: Some(origin),
            consumed_up: false,
            arm_up: false,
            pin_verified: false,
        },
        Ok(Some(msg)) => {
            if msg.cmd == CMD_INIT {
                if msg.payload.len() < 8 {
                    return CtaphidDispatch {
                        responses: Vec::new(),
                        origin: Some(origin),
                        consumed_up: false,
                        arm_up: false,
                        pin_verified: false,
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
                    arm_up: false,
                    pin_verified: false,
                };
            }
            if msg.cmd == CMD_PING {
                return CtaphidDispatch {
                    responses: CtapHidFramer::frame_ping(msg.cid, &msg.payload),
                    origin: Some(origin),
                    consumed_up: false,
                    arm_up: false,
                    pin_verified: false,
                };
            }
            if msg.cmd == CMD_WINK {
                return CtaphidDispatch {
                    responses: CtapHidFramer::frame_message(msg.cid, CMD_WINK, &[]),
                    origin: Some(origin),
                    consumed_up: false,
                    arm_up: false,
                    pin_verified: false,
                };
            }
            // Vendor/bind-mgmt/wallet/fw-log/rescue/pairing serial no
            // dispatcher FreeRTOS (paridade seção D legada). `None` = cai
            // no engine CTAP genérico abaixo (U2F/OTA/desconhecido).
            if msg.cmd == CMD_MSG && !msg.payload.is_empty() {
                if let Some(ctx) = vendor {
                    ctx.now_ms = now_ms;
                    ctx.now_secs = now_secs;
                    if let Some((responses, consumed)) = dispatch_serial_vendor_msg(ctx, &msg) {
                        let arm_up = ctx.arm_up;
                        let pin_verified = ctx.pin_verified;
                        return CtaphidDispatch {
                            responses,
                            origin: Some(origin),
                            consumed_up: consumed,
                            arm_up,
                            pin_verified,
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
                return CtaphidDispatch {
                    responses: CtapHidFramer::frame_message(msg.cid, msg.cmd, &resp),
                    arm_up: false,
                    pin_verified: false,
                    origin: Some(origin),
                    consumed_up: consumed,
                };
            }
            CtaphidDispatch {
                responses: vec![CtapHidFramer::frame_error(msg.cid, 0x01)],
                origin: Some(origin),
                consumed_up: false,
                arm_up: false,
                pin_verified: false,
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

    fn init_raw(cid: u32, cmd: u8, payload: &[u8]) -> [u8; CTAPHID_PACKET_SIZE] {
        let mut raw = [0u8; CTAPHID_PACKET_SIZE];
        raw[0..4].copy_from_slice(&cid.to_be_bytes());
        raw[4] = cmd | 0x80;
        raw[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let take = payload.len().min(CTAPHID_PACKET_SIZE - 7);
        raw[7..7 + take].copy_from_slice(&payload[..take]);
        raw
    }

    #[test]
    fn pacote_usb_responde_via_usb() {
        use aegis_fido_usb::ctaphid::CMD_PING;
        let mut mgr_usb = CtapHidManager::new();
        let mut mgr_serial = CtapHidManager::new();
        let mut engine = CtapEngine::new([0x11; 32], 0);
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
        let mut mgr_usb = CtapHidManager::new();
        let mut mgr_serial = CtapHidManager::new();
        let mut engine = CtapEngine::new([0x11; 32], 0);
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
        let mut mgr_usb = CtapHidManager::new();
        let mut mgr_serial = CtapHidManager::new();
        let mut engine = CtapEngine::new([0x11; 32], 0);
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
        let mut mgr_usb = CtapHidManager::new();
        let mut mgr_serial = CtapHidManager::new();
        let mut engine = CtapEngine::new([0x11; 32], 0);
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
        let mut mgr_usb = CtapHidManager::new();
        let mut mgr_serial = CtapHidManager::new();
        let mut engine = CtapEngine::new([0x11; 32], 0);
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
        use crate::ble_gatt::OP_KEY_LIST;
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
        let mut mgr_usb = CtapHidManager::new();
        let mut mgr_serial = CtapHidManager::new();
        let mut engine = CtapEngine::new([0x11; 32], 0);

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
            arm_up: false,
            pin_verified: false,
            binding: &mut binding,
            storage: &mut storage,
            wallet: &mut wallet,
            key_mgr: &mut key_mgr,
            oath: &mut oath,
            fwlog: &mut fwlog,
            rescue: &mut rescue,
            pairing: &mut pairing,
            pin_uv_session: false,
            secure_guard: None,
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
        use crate::ble_gatt::OP_KEY_GEN_ONDEVICE;
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
        let mut mgr_usb = CtapHidManager::new();
        let mut mgr_serial = CtapHidManager::new();
        let mut engine = CtapEngine::new([0x11; 32], 0);

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
            arm_up: false,
            pin_verified: false,
            binding: &mut binding,
            storage: &mut storage,
            wallet: &mut wallet,
            key_mgr: &mut key_mgr,
            oath: &mut oath,
            fwlog: &mut fwlog,
            rescue: &mut rescue,
            pairing: &mut pairing,
            pin_uv_session: false,
            secure_guard: None,
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

    #[test]
    fn test_secure_guard_enforcement_barrier_on_wallet_ops() {
        use crate::binding::BindingManager;
        use crate::ble_gatt::{OP_SECURE_GUARD_UNLOCK, OP_WALLET_LIST};
        use crate::fw_log::FwLog;
        use crate::pairing::PairingManager;
        use crate::persistence::{PlatformFlashBackend, SecureStorage};
        use aegis_fido_core::credential::key_manager::KeyManager;
        use aegis_fido_core::oath::OathApplet;
        use aegis_fido_core::otp::rescue::RescueEngine;
        use aegis_fido_core::secure_guard::{
            SecureGuardEngine, SecureGuardPolicy, SecureGuardState,
        };
        use aegis_fido_core::wallet::WalletStore;
        use aegis_fido_usb::ctaphid::CMD_MSG;
        use ciborium::value::Value;

        let mut pairing = PairingManager::new();
        let mut binding = BindingManager::new();
        let backend = PlatformFlashBackend::new();
        let mut storage = SecureStorage::new(backend, &[0x11; 32], &[0x22; 32]);
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();
        let mut fwlog = FwLog::new();
        let mut rescue = RescueEngine::new();
        let mut mgr_usb = CtapHidManager::new();
        let mut mgr_serial = CtapHidManager::new();
        let mut engine = CtapEngine::new([0x11; 32], 0);

        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            session_duration_ms: 1000,
            inactivity_timeout_ms: 500,
            ..Default::default()
        };
        let mut sg = SecureGuardEngine::new(policy);
        let pin = b"4829";

        // 0. Tenta OP_WALLET_LIST (0x36) com Secure Guard UNPROVISIONED -> Deve ser BLOQUEADO pela barreira (0x36 PIN_REQUIRED)!
        let raw_unprov = init_raw(0x1122_3344, CMD_MSG, &[OP_WALLET_LIST]);
        let ev_unprov = FirmwareEvent::SerialPacket(raw_unprov);
        let mut vendor_unprov = SerialVendorCtx {
            pairing_open: true,
            up_latched: true,
            now_ms: 500,
            now_secs: 0,
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
        let out_unprov = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev_unprov,
            true,
            500,
            0,
            Some(&mut vendor_unprov),
        );
        assert_eq!(out_unprov.responses.len(), 1);
        assert_eq!(out_unprov.responses[0][7], 0x36); // Bloqueado em Unprovisioned!

        // 1. Provisiona Secure Guard via 0x3B
        let prov_map = vec![
            (
                Value::Text("action".into()),
                Value::Text("provision".into()),
            ),
            (Value::Text("pin".into()), Value::Bytes(pin.to_vec())),
        ];
        let mut prov_cbor = Vec::new();
        ciborium::into_writer(&Value::Map(prov_map), &mut prov_cbor).unwrap();

        let mut prov_payload = Vec::new();
        prov_payload.push(OP_SECURE_GUARD_UNLOCK);
        prov_payload.extend_from_slice(&prov_cbor);

        let raw_prov = init_raw(0x1122_3344, CMD_MSG, &prov_payload);
        let ev_prov = FirmwareEvent::SerialPacket(raw_prov);

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

        let out_prov = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev_prov,
            true,
            1000,
            1,
            Some(&mut vendor),
        );
        assert!(!out_prov.responses.is_empty());
        assert_eq!(out_prov.responses[0][7], 0x00); // Sucesso provisionamento!
        assert_eq!(
            vendor.secure_guard.as_ref().unwrap().state(),
            SecureGuardState::Unlocked
        );
        assert!(vendor.secure_guard.as_ref().unwrap().is_unlocked());
        assert!(vendor.secure_guard.as_ref().unwrap().is_provisioned());
        vendor.secure_guard.as_mut().unwrap().lock_now(1001).unwrap();
        assert_eq!(
            vendor.secure_guard.as_ref().unwrap().state(),
            SecureGuardState::Locked
        );

        // 2. Tenta OP_WALLET_LIST (0x36) com Secure Guard LOCKED -> Deve ser BLOQUEADO pela barreira (0x36 PIN_REQUIRED)!
        let raw_wallet = init_raw(0x1122_3344, CMD_MSG, &[OP_WALLET_LIST]);
        let ev_wallet = FirmwareEvent::SerialPacket(raw_wallet);

        let out_blocked = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev_wallet,
            true,
            1050,
            1,
            Some(&mut vendor),
        );
        assert_eq!(out_blocked.responses.len(), 1);
        assert_eq!(out_blocked.responses[0][7], 0x36); // CTAP2_ERR_PIN_REQUIRED / SECURE_GUARD_LOCKED!

        // 3. Desbloqueia Secure Guard via 0x3B com PIN correto
        let unlock_map = vec![
            (Value::Text("action".into()), Value::Text("unlock".into())),
            (Value::Text("pin".into()), Value::Bytes(pin.to_vec())),
        ];
        let mut unlock_cbor = Vec::new();
        ciborium::into_writer(&Value::Map(unlock_map), &mut unlock_cbor).unwrap();

        let mut unlock_payload = Vec::new();
        unlock_payload.push(OP_SECURE_GUARD_UNLOCK);
        unlock_payload.extend_from_slice(&unlock_cbor);

        let raw_unlock = init_raw(0x1122_3344, CMD_MSG, &unlock_payload);
        let ev_unlock = FirmwareEvent::SerialPacket(raw_unlock);

        let out_unlock = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev_unlock,
            true,
            1100,
            1,
            Some(&mut vendor),
        );
        assert!(!out_unlock.responses.is_empty());
        assert_eq!(out_unlock.responses[0][7], 0x00); // Desbloqueado com sucesso!
        assert_eq!(
            vendor.secure_guard.as_ref().unwrap().state(),
            SecureGuardState::Unlocked
        );

        // 4. Agora chama OP_WALLET_LIST (0x36) com Secure Guard UNLOCKED -> PERMITIDO!
        let raw_wallet_ok = init_raw(0x1122_3344, CMD_MSG, &[OP_WALLET_LIST]);
        let ev_wallet_ok = FirmwareEvent::SerialPacket(raw_wallet_ok);

        let out_allowed = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev_wallet_ok,
            true,
            1200,
            1,
            Some(&mut vendor),
        );
        assert_eq!(out_allowed.responses.len(), 1);
        assert_eq!(out_allowed.responses[0][7], 0x00); // Carteira executada com sucesso!

        // 5. Avança o tempo além da expiração da sessão por inatividade (1200 + 500 = 1700ms)
        // Chama OP_WALLET_LIST em t = 1800ms -> A barreira expira a sessão e NEGA!
        let raw_wallet_exp = init_raw(0x1122_3344, CMD_MSG, &[OP_WALLET_LIST]);
        let ev_wallet_exp = FirmwareEvent::SerialPacket(raw_wallet_exp);

        let out_expired = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev_wallet_exp,
            true,
            1800,
            1,
            Some(&mut vendor),
        );
        assert_eq!(out_expired.responses.len(), 1);
        assert_eq!(out_expired.responses[0][7], 0x36); // Expirou sessão e bloqueou!
        assert_eq!(
            vendor.secure_guard.as_ref().unwrap().state(),
            SecureGuardState::Locked
        );
    }

    #[test]
    fn test_secure_guard_fido2_standard_never_blocked() {
        use crate::binding::BindingManager;
        use crate::pairing::PairingManager;
        use crate::persistence::{PlatformFlashBackend, SecureStorage};
        use aegis_fido_core::credential::key_manager::KeyManager;
        use aegis_fido_core::oath::OathApplet;
        use aegis_fido_core::otp::rescue::RescueEngine;
        use aegis_fido_core::secure_guard::{
            SecureGuardEngine, SecureGuardPolicy, SecureGuardState,
        };
        use aegis_fido_core::wallet::WalletStore;
        use aegis_fido_usb::ctaphid::CMD_CBOR;

        let mut pairing = PairingManager::new();
        let mut binding = BindingManager::new();
        let backend = PlatformFlashBackend::new();
        let mut storage = SecureStorage::new(backend, &[0x11; 32], &[0x22; 32]);
        let mut wallet = WalletStore::new();
        let mut key_mgr = KeyManager::new();
        let mut oath = OathApplet::new();
        let mut fwlog = crate::fw_log::FwLog::new();
        let mut rescue = RescueEngine::new();
        let mut mgr_usb = CtapHidManager::new();
        let mut mgr_serial = CtapHidManager::new();
        let mut engine = CtapEngine::new([0x11; 32], 0);

        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..Default::default()
        };
        let mut sg = SecureGuardEngine::new(policy);
        let _ = sg
            .provision_pin(b"2948", [0x11; 16], b"", [0x22; 16], 1000)
            .expect("prov");
        // Secure Guard está LOCKED e provisionado!
        assert_eq!(sg.state(), SecureGuardState::Locked);

        let mut vendor = SerialVendorCtx {
            pairing_open: false,
            up_latched: true,
            now_ms: 1000,
            now_secs: 1,
            arm_up: false,
            pin_verified: false,
            binding: &mut binding,
            storage: &mut storage,
            wallet: &mut wallet,
            key_mgr: &mut key_mgr,
            oath: &mut oath,
            fwlog: &mut fwlog,
            rescue: &mut rescue,
            pairing: &mut pairing,
            pin_uv_session: false,
            secure_guard: Some(&mut sg),
        };

        // FIDO2 standard MakeCredential / GetAssertion via CMD_CBOR
        // Não é bloqueado com 0x36 (PIN_REQUIRED do SG); o engine CTAP processa o comando FIDO normalmente!
        let raw = init_raw(0x0A0B_0C0D, CMD_CBOR, &[CTAP_CMD_MAKE_CREDENTIAL]);
        let ev = FirmwareEvent::UsbPacket(raw);

        let out = route_ctaphid_event(
            &mut mgr_usb,
            &mut mgr_serial,
            &mut engine,
            &ev,
            true,
            1000,
            1,
            Some(&mut vendor),
        );
        // O comando alcança o CtapEngine (que responde erro CTAP de payload inválido, e NUNCA é interceptado pelo SG)
        assert_eq!(out.responses.len(), 1);
        assert_ne!(out.responses[0][7], 0x36); // Não foi barrado pelo Secure Guard!
    }
}
