//! Etapa B -- BLE real via NimBLE (GATT 0xFFFD, ESP32-S3).
//!
//! - Logica de politica 100% host-testavel, `no_std` compativel: payload de
//!   advertising, quando anunciar, intervalos de coexistencia, moldura de
//!   notify e desfecho do bonding. Zero `std`, zero I/O aqui.
//! - Logica de framing/opcodes reutilizada de [`crate::ble_gatt`]
//!   (`BleGattServer::control_write`, `read_len`, revisao, status wire).
//!   Nada duplicado: este modulo so decide politica e transporta bytes.
//! - Backend de radio no ESP: componente C `components/aegis_ble`
//!   (NimBLE via `esp-idf-sys`, mesmo padrao do `aegis_usb.c`), chamado por
//!   `extern "C"` manual. No host, os `esp_*` sao shims inertes (sem radio).
//!
//! Contrato (congelado, `docs/ble-protocol.md` Sec.1-Sec.4 + Sec.11 + audit Sec.3B):
//! - Servico `0xFFFD`; `FFF1` write -> `control_write`; `FFF2` notify;
//!   `FFF3` read len; `FFF4` read/write revisao `0x01` (congelada).
//! - Fragmentos FFF1 dependem de bonding + cifra link-layer (NimBLE
//!   `ble_store`); SEM cifra app-layer (limite declarado -- link aberto
//!   expoe bytes no ar; gates binding->UP->PIN + `NEED_BINDING` 0x05 valem
//!   acima do link, nunca como substituto da cifra).
//! - Gates: binding -> UP -> PIN (ordem canonica, R6/R7); USO (LIST/CODE)
//!   exige so UP fisico; PING `0x81` tambem exige UP por operacao
//!   (latch single-shot: o chamador consome e limpa por operacao).
//! - `notify_frame` fail-closed: exceder `CONTROL_POINT_LENGTH` (512)
//!   retorna `[op, 0x04]` sem vazar prefixo truncado (R13/R14).
//! - Advertising com UUID de servico + flag de pareamento SOMENTE em modo
//!   pareamento (`PairingBle` com janela aberta). Fora disso: radio mudo
//!   (privacidade + bateria).
//! - Bonding persistido pelo stack NimBLE (`ble_store` em NVS flash).
//! - `complete_pairing` (UP fisico) -> stop advertising + sai do modo
//!   (volta a `Idle` via `PairingManager`) + LED verde solido + tela confirma
//!   (fiacao no `main.rs`).
//! - Coexistencia: prioridade `USB > WiFi > BLE`. BLE cede airtime ao WiFi
//!   (intervalo de advertising lento quando o radio WiFi esta ativo) e nunca
//!   bloqueia o USB.

extern crate alloc;

use alloc::vec::Vec;

use super::gatt_core::{
    BleCompleteMessage, BleGattError, BleGattServer, BLE_SERVICE_UUID, CONTROL_POINT_LENGTH,
    GATT_REVISION,
};
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};
use crate::pairing::{PairingManager, PairingState};

/// Nome curto anunciado (cabe no legacy adv de 31B junto com o resto).
pub const BLE_DEVICE_NAME: &str = "AegisKey";
/// Comprimento maximo do payload de advertising legado (31B).
pub const ADV_MAX_BYTES: usize = 31;

/// Flag de pareamento no service-data: janela fechada (mudo/normal).
pub const ADV_PAIRING_OFF: u8 = 0x00;
/// Flag de pareamento no service-data: janela aberta (app pode conectar).
pub const ADV_PAIRING_ON: u8 = 0x01;

/// Intervalo de advertising normal (unidades 0,625ms): 100ms..150ms.
pub const ADV_ITVL_NORMAL_MIN: u16 = 160;
/// Intervalo de advertising normal (unidades 0,625ms): 100ms..150ms.
pub const ADV_ITVL_NORMAL_MAX: u16 = 240;
/// Intervalo lento p/ coexistencia WiFi (unidades 0,625ms): 250ms..320ms.
///
/// BLE cede airtime ao WiFi (AP fallback ativo durante o pareamento e/ou
/// station conectada). USB nunca e afetado (controlador dedicado).
pub const ADV_ITVL_COEX_MIN: u16 = 400;
/// Intervalo lento p/ coexistencia WiFi (unidades 0,625ms): 250ms..320ms.
pub const ADV_ITVL_COEX_MAX: u16 = 512;

/// Eventos do backend C consumidos por poll no `main.rs` (poll-read-clear).
pub const BLE_EVT_NONE: i32 = 0;
/// Link cifrado com bonding (`ENC_CHANGE` ok): chamar `on_link_secured`.
pub const BLE_EVT_SECURED: i32 = 1;
/// Central desconectou: se a janela segue aberta, reanunciar.
pub const BLE_EVT_DISCONNECTED: i32 = 2;
/// Central conectou (ainda sem bonding): so log, mantem advertising parado.
pub const BLE_EVT_CONNECTED: i32 = 3;

/// Tamanho maximo de 1 fragmento FFF1 aceito do backend C (== MTU-3 conservador).
pub const BLE_RX_FRAGMENT_MAX: usize = 256;

/// Payload de advertising legado montado (`len` bytes validos).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvPayload {
    /// Bytes do payload (AD structures encadeadas).
    pub bytes: [u8; ADV_MAX_BYTES],
    /// Comprimento valido (`<= ADV_MAX_BYTES`).
    pub len: u8,
}

impl AdvPayload {
    /// Fatia valida do payload.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// Monta o payload de advertising legado:
/// `Flags(0x06) + CompleteList16[0xFFFD] + ServiceData16[0xFFFD, flag] + Nome`.
///
/// - UUID de servico `0xFFFD` sempre presente (app filtra por ele).
/// - Flag de pareamento `0x01` SOMENTE com a janela aberta; `0x00` caso
///   contrario (o backend C so anuncia com a janela aberta mesmo assim).
/// - Nunca excede 31B (garantido por construcao; teste trava o layout).
pub fn encode_adv_payload(pairing_open: bool) -> AdvPayload {
    let mut bytes = [0u8; ADV_MAX_BYTES];
    let mut n: usize = 0;
    // Flags: [len=2][type=0x01][LE General Disc + BR/EDR nao suportado].
    bytes[n..n + 3].copy_from_slice(&[0x02, 0x01, 0x06]);
    n += 3;
    // Complete List 16-bit Service UUIDs: [len=3][type=0x03][0xFFFD LE].
    let svc_lo = (BLE_SERVICE_UUID & 0xFF) as u8;
    let svc_hi = ((BLE_SERVICE_UUID >> 8) & 0xFF) as u8;
    bytes[n..n + 4].copy_from_slice(&[0x03, 0x03, svc_lo, svc_hi]);
    n += 4;
    // Service Data 16-bit: [len=4][type=0x16][0xFFFD LE][flag pareamento].
    let flag = if pairing_open {
        ADV_PAIRING_ON
    } else {
        ADV_PAIRING_OFF
    };
    bytes[n..n + 5].copy_from_slice(&[0x04, 0x16, svc_lo, svc_hi, flag]);
    n += 5;
    // Nome curto completo: [len][type=0x09][bytes].
    let name = BLE_DEVICE_NAME.as_bytes();
    let name_len = name.len().min(ADV_MAX_BYTES - n - 2);
    bytes[n] = (name_len + 1) as u8;
    bytes[n + 1] = 0x09;
    bytes[n + 2..n + 2 + name_len].copy_from_slice(&name[..name_len]);
    n += 2 + name_len;
    debug_assert!(n <= ADV_MAX_BYTES);
    AdvPayload {
        bytes,
        len: n as u8,
    }
}

/// `true` somente quando o radio deve anunciar: estado `PairingBle` com a
/// janela de 60s aberta.
///
/// - `PairingAp`: mudo (fallback WiFi AP usa o radio; BLE cede).
/// - `Idle`/`Arming`/`Locked`: mudo (privacidade + bateria).
/// - Janela expirada: mudo (o `tick` ja moveu para `Locked`).
pub fn should_advertise(mgr: &PairingManager, now_ms: u64) -> bool {
    matches!(mgr.state(), PairingState::PairingBle { .. }) && mgr.is_pairing_window_open(now_ms)
}

/// Reconexao de confiavel sem janela (UX, sem botao para reconectar).
///
/// `true` em `Idle` com relacao de confianca (`bonded` da sessao ou
/// `claimed` da NVS): o radio anuncia com flag de pareamento APAGADA
/// (so reconecta; parear de novo exige janela). Device novo/sem vinculo
/// segue mudo. Gates intactos: UP por operacao + bonding; completar um
/// pareamento novo continua exigindo janela + UP.
/// Bateria: anuncio continuo enquanto ocioso+confiavel (troca consciente
/// por nao exigir hold a cada sessao).
pub fn should_advertise_reconnect(state: PairingState, trusted: bool) -> bool {
    trusted && matches!(state, PairingState::Idle)
}

// ---------------------------------------------------------------------------
// F-01 HARDENING (2026-11-02): MITM exigido no link-layer.
//
// Espelho host-testavel da config NimBLE em
// `components/aegis_ble/aegis_ble_nimble.c` (`sm_mitm = 1`, `sm_sc = 1`,
// `sm_bonding = 1`): LE Secure Connections + bonding, JustWorks rejeitado
// fail-closed. Janela de pareamento + UP-por-operacao + vinculo ECDSA
// seguem intactos (defesa em profundidade acima do link).
//
// UX ONE-WAY, owner-authorized: bonds JustWorks antigos nao reencriptam sob
// a nova politica; o dono precisa re-parear dentro da janela com UP
// (`mitm_repair_notice()` = texto p/ superficie de status).
// ---------------------------------------------------------------------------

/// SM NimBLE exige MITM (espelho de `sm_mitm = 1`; teste trava o contrato).
pub const BLE_SM_MITM_REQUIRED: bool = true;
/// SM NimBLE exige LE Secure Connections (espelho de `sm_sc = 1`).
pub const BLE_SM_SC_REQUIRED: bool = true;
/// SM NimBLE exige bonding com cifra (espelho de `sm_bonding = 1`).
pub const BLE_SM_BONDING_REQUIRED: bool = true;

/// Texto de status p/ re-pareamento pos F-01 (one-way, owner-authorized).
///
/// Bonds JustWorks antigos foram invalidados pela politica MITM: o dono
/// re-pareia dentro da janela de 60 s com UP; JustWorks falha fechado.
pub fn mitm_repair_notice() -> &'static str {
    concat!(
        "BLE agora exige pareamento com protecao MITM (LE Secure Connections + bonding): ",
        "vinculos JustWorks antigos foram invalidados. Re-pareie dentro da janela de ",
        "60 s com toque no BOOT (UP). Tentativas JustWorks falham fechado; ",
        "numeric-comparison/OOB eh follow-up.",
    )
}
/// Intervalos de advertising (min, max) em unidades de 0,625ms.
///
/// `wifi_active`: AP fallback ligado ou station conectada -> intervalo lento
/// (BLE cede airtime; prioridade `USB > WiFi > BLE`). Mesmos valores usados
/// pelo backend C (`components/aegis_ble/aegis_ble_nimble.c`).
pub fn adv_intervals(wifi_active: bool) -> (u16, u16) {
    if wifi_active {
        (ADV_ITVL_COEX_MIN, ADV_ITVL_COEX_MAX)
    } else {
        (ADV_ITVL_NORMAL_MIN, ADV_ITVL_NORMAL_MAX)
    }
}

/// Backoff entre tentativas de `esp_ble_start` (igual ao do WiFi AP).
pub const BLE_START_BACKOFF_MS: u64 = 5000;
/// Desiste apos N falhas ate a proxima borda de `want` (janela reaberta).
pub const BLE_START_MAX_TRIES: u32 = 3;
/// HCI Memory Capacity Exceeded (0x200 `BLE_HS_EOS` base | 0x07): controller
/// recusa o adv com instancia residual (`s_advertising=0` nosso vs controller
/// anunciando). Nao consome retry do gate (backoff ate nova borda).
pub const BLE_ADV_RC_NOMEM: i32 = 519;

/// Gate de tentativas do `esp_ble_start` (F5/D08).
///
/// Sem isso, uma falha de `nimble_port_init` (ex.: heap curto no primeiro
/// pareamento) repetia o start a CADA poll: cada tentativa realocava o
/// controlador por cima, vazava heap ate `Malloc failed` e o `emi.c`
/// derrubava o device em panic (Interrupt WDT). Com o gate: 1 tentativa a
/// cada 5s, no maximo 3 por borda de janela.
#[derive(Debug, Clone, Copy)]
pub struct BleStartGate {
    fails: u32,
    last_try_ms: u64,
    want_prev: bool,
}

impl BleStartGate {
    /// Gate fechado (nenhuma tentativa ainda).
    pub fn new() -> Self {
        Self {
            fails: 0,
            last_try_ms: 0,
            want_prev: false,
        }
    }

    /// `true` quando deve chamar `esp_ble_start` neste poll.
    pub fn allow(&mut self, want_adv: bool, now_ms: u64) -> bool {
        if !want_adv {
            self.want_prev = false;
            self.fails = 0;
            return false;
        }
        if !self.want_prev {
            // Borda de subida: janela (re)abriu, zera as falhas.
            self.want_prev = true;
            self.fails = 0;
        }
        if self.fails >= BLE_START_MAX_TRIES {
            return false;
        }
        if self.last_try_ms != 0 && now_ms.saturating_sub(self.last_try_ms) < BLE_START_BACKOFF_MS {
            return false;
        }
        self.last_try_ms = now_ms;
        true
    }

    /// Registra o resultado da tentativa (`true` = adv ligou).
    pub fn on_result(&mut self, ok: bool) {
        if ok {
            self.fails = 0;
        } else {
            self.fails = self.fails.saturating_add(1);
        }
    }

    /// Registra rc=519 (NOMEM residual): NAO consome as 3 tentativas.
    ///
    /// O controller recusou com instancia residual; retry cego so repete a
    /// recusa. Mantem `fails` intacto (backoff de 5 s via `last_try_ms` ja
    /// registrado em `allow`); o Rust loga `EV_ADV_NOMEM` e aguarda a proxima
    /// borda/janela em vez de esgotar o gate.
    pub fn on_nomem(&mut self) {
        // Intencionalmente sem tocar em `fails`: 519 nao e falha contavel.
    }
}

impl Default for BleStartGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Moldura de resposta FFF2 notify: `[opcode, status, payload...]`.
///
/// `status`: `0x00` OK ou `BleGattError::to_vendor_status`.
///
/// Limite fail-closed (Sec.3B): carga limitada a `CONTROL_POINT_LENGTH`.
/// Se `payload` exceder o teto, NENHUM byte de payload e emitido -- retorna
/// `[opcode, 0x04]` (falha generica, sem retry Sec.9.6) em vez de truncar
/// silenciosamente. Truncar corromperia CBOR/CTAP sem sinalizar erro;
/// falhar fechado preserva R13/R14 (integridade do envelope).
///
/// Seguranca de transporte (limite declarado): fragmentos FFF1/notify FFF2
/// dependem EXCLUSIVAMENTE do bonding/cifra link-layer do NimBLE
/// (`ble_store` em NVS). Nao ha cifra app-layer neste transporte -- um link
/// nao-bonded expoe bytes no ar. Gates (binding->UP->PIN, `NEED_BINDING`
/// 0x05) continuam obrigatorios acima do link.
pub fn notify_frame(opcode: u8, status: u8, payload: &[u8]) -> Vec<u8> {
    if payload.len() > CONTROL_POINT_LENGTH {
        // Fail-closed: nunca vaza prefixo truncado como se fosse OK.
        return alloc::vec![opcode, 0x04];
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(opcode);
    out.push(status);
    out.extend_from_slice(payload);
    out
}

/// Alimenta 1 fragmento FFF1 vindo do backend C no `BleGattServer`.
///
/// Reuso direto de `control_write` (UP por operacao, latch de uso unico pelo
/// chamador via `presence_confirmed`). Retorna a mensagem completa quando o
/// ultimo fragmento chega. Fragmento vazio/oversize e rejeitado antes.
pub fn feed_control_write(
    server: &mut BleGattServer,
    fragment: &[u8],
    presence_confirmed: bool,
) -> Result<Option<BleCompleteMessage>, BleGattError> {
    if fragment.is_empty() || fragment.len() > BLE_RX_FRAGMENT_MAX {
        crate::ltrace!(LtCat::Transport, LtEvt::TpError, "ble-frag");
        return Err(BleGattError::InvalidFragment);
    }
    server.control_write(fragment, presence_confirmed)
}

/// Tamanho pendente (FFF3) apos alimentar fragmentos.
pub fn pending_len(server: &BleGattServer) -> u16 {
    server.read_len()
}

/// Revisao GATT esperada (FFF4 permanece `0x01`).
pub fn expected_revision() -> u8 {
    GATT_REVISION
}

/// Desfecho do evento `SECURED` (link cifrado + bonding ok) no `main.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondOutcome {
    /// Pareado: `complete_pairing` ok -> parar advertising + LED verde + tela.
    Paired,
    /// UP fisico ausente no latch: mantem advertising, pede toque.
    DeniedNoPresence,
    /// Fora da janela (corrida com timeout): nada a fazer.
    DeniedNoWindow,
}

/// Trata link seguro: exige janela aberta + UP fisico (latch de uso unico).
///
/// Delega a `PairingManager::complete_pairing` (que emite `PairingPaired` e
/// volta a `Idle`, saindo do modo). O chamador (`main.rs`) para o
/// advertising imediatamente quando o retorno e `Paired`.
pub fn on_link_secured(
    mgr: &mut PairingManager,
    presence_confirmed: bool,
    now_ms: u64,
) -> BondOutcome {
    if !mgr.is_pairing_window_open(now_ms) {
        crate::ltrace!(LtCat::Transport, LtEvt::TpError, "ble-sec-late");
        return BondOutcome::DeniedNoWindow;
    }
    if !presence_confirmed {
        return BondOutcome::DeniedNoPresence;
    }
    if mgr.complete_pairing(true, now_ms) {
        BondOutcome::Paired
    } else {
        BondOutcome::DeniedNoWindow
    }
}

// ---------------------------------------------------------------------------
// Backend de radio: FFI manual com o componente C `aegis_ble`
// (mesmo padrao dos `aegis_usb_*` no `main.rs`; sem bindgen, sem novos deps).
// ---------------------------------------------------------------------------

#[cfg(target_os = "espidf")]
extern "C" {
    fn aegis_ble_start(pairing_flag: i32, coex_slow: i32) -> i32;
    fn aegis_ble_preinit() -> i32;
    fn aegis_ble_stop() -> i32;
    fn aegis_ble_poll_event() -> i32;
    fn aegis_ble_fetch_rx(out_buf: *mut u8, max_len: i32) -> i32;
    fn aegis_ble_notify(data: *const u8, len: i32) -> i32;
    fn aegis_ble_set_pending_len(value: u16);
    fn aegis_ble_conn_active() -> i32;
    fn aegis_ble_own_addr(out: *mut u8) -> i32;
}

/// Liga o advertising NimBLE (init uma vez; idempotente).
/// `pairing_open`: flag de pareamento no service-data.
/// `wifi_active`: intervalo lento (WiFi ativo; BLE cede airtime).
/// Retorna `0` ok, negativo = `esp_err_t`/codigo NimBLE.
#[cfg(target_os = "espidf")]
pub fn esp_ble_start(pairing_open: bool, wifi_active: bool) -> i32 {
    crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "ble-adv");
    unsafe { aegis_ble_start(i32::from(pairing_open), i32::from(wifi_active)) }
}

/// Pre-inicializa o NimBLE no boot (heap fresco), sem anunciar.
///
/// O primeiro pareamento nao paga o `nimble_port_init` sob heap
/// fragmentado (causa raiz dos `hci inits failed` intermitentes que, com
/// retry a cada poll, vazavam o controlador ate o panic). Falha aqui nao
/// trava o boot: o [`BleStartGate`] do loop tenta de novo com backoff.
/// Retorna `0` ok, negativo = codigo do backend C.
#[cfg(target_os = "espidf")]
pub fn esp_ble_preinit() -> i32 {
    unsafe { aegis_ble_preinit() }
}

/// Para o advertising (chamar ao parear, no timeout e ao trocar p/ AP).
/// Retorna `0` ok.
#[cfg(target_os = "espidf")]
pub fn esp_ble_stop() -> i32 {
    crate::ltrace!(LtCat::Transport, LtEvt::TpClose, "ble-adv");
    unsafe { aegis_ble_stop() }
}

/// Consome 1 evento pendente do backend (`BLE_EVT_*`; `NONE` = sem evento).
#[cfg(target_os = "espidf")]
pub fn esp_ble_poll_event() -> i32 {
    unsafe { aegis_ble_poll_event() }
}

/// Copia 1 fragmento FFF1 pendente (`>0` = bytes, `0` = fila vazia,
/// `<0` = backend sem init). `out` deve ter `>= BLE_RX_FRAGMENT_MAX`.
#[cfg(target_os = "espidf")]
pub fn esp_ble_fetch_rx(out: &mut [u8]) -> i32 {
    let max = out.len().min(i32::MAX as usize) as i32;
    unsafe { aegis_ble_fetch_rx(out.as_mut_ptr(), max) }
}

/// Enfileira 1 notify FFF2 (`0` ok, `<0` = sem conexao/inscrito ou erro).
#[cfg(target_os = "espidf")]
pub fn esp_ble_notify(data: &[u8]) -> i32 {
    let len = data.len().min(i32::MAX as usize) as i32;
    unsafe { aegis_ble_notify(data.as_ptr(), len) }
}

/// Espelha o `read_len` no backend C (serve FFF3 entre polls do Rust).
#[cfg(target_os = "espidf")]
pub fn esp_ble_set_pending_len(value: u16) {
    unsafe { aegis_ble_set_pending_len(value) }
}

/// `true` quando ha central conectada (para logs/heartbeat).
#[cfg(target_os = "espidf")]
pub fn esp_ble_conn_active() -> bool {
    unsafe { aegis_ble_conn_active() == 1 }
}

/// MAC publico do NimBLE (6 B) p/ o fob_short_id do beacon de presenca.
///
/// `None` com stack down (init/sync pendente ou erro do C): o chamador NAO
/// anuncia (fail-closed, mesma semantica de `proximity_adv_allowed`).
#[cfg(target_os = "espidf")]
pub fn own_addr() -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let rc = unsafe { aegis_ble_own_addr(out.as_mut_ptr()) };
    if rc == 0 {
        Some(out)
    } else {
        None
    }
}

// Shims host (sem radio): erro fail-closed, nunca 0=ok.
#[cfg(not(target_os = "espidf"))]
pub fn esp_ble_start(_pairing_open: bool, _wifi_active: bool) -> i32 {
    -1
}
#[cfg(not(target_os = "espidf"))]
pub fn esp_ble_stop() -> i32 {
    -1
}
#[cfg(not(target_os = "espidf"))]
pub fn esp_ble_poll_event() -> i32 {
    BLE_EVT_NONE
}
#[cfg(not(target_os = "espidf"))]
pub fn esp_ble_fetch_rx(_out: &mut [u8]) -> i32 {
    -1
}
#[cfg(not(target_os = "espidf"))]
pub fn esp_ble_notify(_data: &[u8]) -> i32 {
    -1
}
#[cfg(not(target_os = "espidf"))]
pub fn esp_ble_set_pending_len(_value: u16) {}
#[cfg(not(target_os = "espidf"))]
pub fn esp_ble_conn_active() -> bool {
    false
}

/// Shim host do MAC BLE (sem radio): sempre `None` (fail-closed, sem adv).
#[cfg(not(target_os = "espidf"))]
pub fn own_addr() -> Option<[u8; 6]> {
    None
}

// ---------------------------------------------------------------------------
// Wave2: anuncio de presenca 0xFFFE (rolling-code), separado do GATT 0xFFFD.
//
// Layout legado (30 B, ver ble_nimble::AdvPayload):
//   Flags(0x06) + CompleteList16[0xFFFE] + ServiceData16[FE FF VER CTR TAG]
//   + Nome "AegisKey".
// O service-data (11 B) e construido por proximity::encode_proximity_svc_data
// (CTR++ ~1 s + TAG AES-CCM). O GATT 0xFFFD segue intacto: este adv usa UUID
// 0xFFFE separado e nao altera o banco ATT (o backend C anuncia um ou outro,
// nunca mistura: pareamento usa 0xFFFD com flag, presenca usa 0xFFFE com
// rolling-code).
//
// Gates: should_adv_proximity exige bonded + Idle + trusted + USB inativo +
// K_prox presente (proximity::proximity_adv_allowed). Coex USB > WiFi > BLE:
// USB veta o adv; WiFi ativo so desacelera o intervalo
// (proximity_adv_intervals); BLE nunca bloqueia o USB.
// ---------------------------------------------------------------------------

/// Comprimento total do adv de presenca em bytes (30 B <= 31 B legado).
#[cfg(feature = "proximity")]
pub const PROXIMITY_ADV_TOTAL_LEN: usize = 30;

/// Monta o payload de presenca: Flags + CompleteList16[0xFFFE] +
/// ServiceData16[0xFFFE + beacon de 9 B] + Nome.
///
/// Nunca excede 31 B (garantido por construcao; teste trava o layout).
/// O UUID e sempre 0xFFFE (nunca 0xFFFD do GATT FIDO).
#[cfg(feature = "proximity")]
pub fn encode_proximity_adv_payload(
    ctr: u32,
    tag: &[u8; crate::proximity::PROXIMITY_BEACON_TAG_LEN],
) -> AdvPayload {
    use super::gatt_core::PROXIMITY_SERVICE_UUID;
    use crate::proximity::encode_proximity_svc_data;
    let svc = encode_proximity_svc_data(ctr, tag);
    let mut bytes = [0u8; ADV_MAX_BYTES];
    let mut n: usize = 0;
    bytes[n..n + 3].copy_from_slice(&[0x02, 0x01, 0x06]);
    n += 3;
    let lo = (PROXIMITY_SERVICE_UUID & 0xFF) as u8;
    let hi = ((PROXIMITY_SERVICE_UUID >> 8) & 0xFF) as u8;
    bytes[n..n + 4].copy_from_slice(&[0x03, 0x03, lo, hi]);
    n += 4;
    bytes[n] = 0x0C;
    bytes[n + 1] = 0x16;
    bytes[n + 2..n + 13].copy_from_slice(&svc);
    n += 13;
    let name = BLE_DEVICE_NAME.as_bytes();
    bytes[n] = (name.len() + 1) as u8;
    bytes[n + 1] = 0x09;
    bytes[n + 2..n + 2 + name.len()].copy_from_slice(name);
    n += 2 + name.len();
    debug_assert!(n <= ADV_MAX_BYTES);
    AdvPayload {
        bytes,
        len: n as u8,
    }
}

/// Verdade somente quando o radio pode anunciar presenca: fob bonded, estado
/// Idle, relacao trusted, USB inativo e K_prox presente.
///
/// state Idle = sem pareamento em curso e sem trava confirmada; fora de Idle
/// (PairingBle, Arming, Locked) o adv de presenca fica mudo.
#[cfg(feature = "proximity")]
pub fn should_adv_proximity(
    state: PairingState,
    bonded: bool,
    trusted: bool,
    usb_active: bool,
    key_present: bool,
) -> bool {
    let idle = matches!(state, PairingState::Idle);
    crate::proximity::proximity_adv_allowed(bonded, idle, trusted, usb_active, key_present)
}

/// Intervalos do adv de presenca (mesmos do pareamento: lento com WiFi).
///
/// Coex USB > WiFi > BLE: USB veta o adv no gate; WiFi ativo desacelera.
#[cfg(feature = "proximity")]
pub fn proximity_adv_intervals(wifi_active: bool) -> (u16, u16) {
    adv_intervals(wifi_active)
}

#[cfg(all(target_os = "espidf", feature = "proximity"))]
extern "C" {
    fn aegis_ble_proximity_start(svc_data: *const u8, svc_len: i32, coex_slow: i32) -> i32;
}

/// Liga o anuncio de presenca 0xFFFE (init uma vez; idempotente).
///
/// svc_data sao os 11 B [FE FF VER CTR TAG] montados por
/// proximity::encode_proximity_svc_data. wifi_active desacelera o intervalo
/// (BLE cede airtime). Retorna 0 ok, negativo = codigo do backend C.
#[cfg(all(target_os = "espidf", feature = "proximity"))]
pub fn esp_ble_proximity_start(svc_data: &[u8], wifi_active: bool) -> i32 {
    let len = svc_data.len().min(i32::MAX as usize) as i32;
    unsafe { aegis_ble_proximity_start(svc_data.as_ptr(), len, i32::from(wifi_active)) }
}

/// Shim host do adv de presenca (sem radio; politica testada por unidade).
#[cfg(all(not(target_os = "espidf"), feature = "proximity"))]
pub fn esp_ble_proximity_start(_svc_data: &[u8], _wifi_active: bool) -> i32 {
    0
}
