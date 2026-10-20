//! Etapa B — BLE real via NimBLE (GATT 0xFFFD, ESP32-S3).
//!
//! - Lógica de política 100% host-testável, `no_std` compatível: payload de
//!   advertising, quando anunciar, intervalos de coexistência, moldura de
//!   notify e desfecho do bonding. Zero `std`, zero I/O aqui.
//! - Lógica de framing/opcodes reutilizada de [`crate::ble_gatt`]
//!   (`BleGattServer::control_write`, `read_len`, revisão, status wire).
//!   Nada duplicado: este módulo só decide política e transporta bytes.
//! - Backend de rádio no ESP: componente C `components/aegis_ble`
//!   (NimBLE via `esp-idf-sys`, mesmo padrão do `aegis_usb.c`), chamado por
//!   `extern "C"` manual. No host, os `esp_*` são shims inertes (sem rádio).
//!
//! Contrato (congelado, `docs/ble-protocol.md` §1-§4 + §11):
//! - Serviço `0xFFFD`; `FFF1` write → `control_write`; `FFF2` notify;
//!   `FFF3` read len; `FFF4` read/write revisão `0x01`.
//! - Advertising com UUID de serviço + flag de pareamento SOMENTE em modo
//!   pareamento (`PairingBle` com janela aberta). Fora disso: rádio mudo
//!   (privacidade + bateria).
//! - Bonding persistido pelo stack NimBLE (`ble_store` em NVS flash).
//! - `complete_pairing` (UP físico) → stop advertising + sai do modo
//!   (volta a `Idle` via `PairingManager`) + LED verde sólido + tela confirma
//!   (fiação no `main.rs`).
//! - Coexistência: prioridade `USB > WiFi > BLE`. BLE cede airtime ao WiFi
//!   (intervalo de advertising lento quando o rádio WiFi está ativo) e nunca
//!   bloqueia o USB.

extern crate alloc;

use alloc::vec::Vec;

use crate::ble_gatt::{
    BleCompleteMessage, BleGattError, BleGattServer, BLE_SERVICE_UUID, CONTROL_POINT_LENGTH,
    GATT_REVISION,
};
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};
use crate::pairing::{PairingManager, PairingState};

/// Nome curto anunciado (cabe no legacy adv de 31B junto com o resto).
pub const BLE_DEVICE_NAME: &str = "AegisKey";
/// Comprimento máximo do payload de advertising legado (31B).
pub const ADV_MAX_BYTES: usize = 31;

/// Flag de pareamento no service-data: janela fechada (mudo/normal).
pub const ADV_PAIRING_OFF: u8 = 0x00;
/// Flag de pareamento no service-data: janela aberta (app pode conectar).
pub const ADV_PAIRING_ON: u8 = 0x01;

/// Intervalo de advertising normal (unidades 0,625ms): 100ms..150ms.
pub const ADV_ITVL_NORMAL_MIN: u16 = 160;
/// Intervalo de advertising normal (unidades 0,625ms): 100ms..150ms.
pub const ADV_ITVL_NORMAL_MAX: u16 = 240;
/// Intervalo lento p/ coexistência WiFi (unidades 0,625ms): 250ms..320ms.
///
/// BLE cede airtime ao WiFi (AP fallback ativo durante o pareamento e/ou
/// station conectada). USB nunca é afetado (controlador dedicado).
pub const ADV_ITVL_COEX_MIN: u16 = 400;
/// Intervalo lento p/ coexistência WiFi (unidades 0,625ms): 250ms..320ms.
pub const ADV_ITVL_COEX_MAX: u16 = 512;

/// Eventos do backend C consumidos por poll no `main.rs` (poll-read-clear).
pub const BLE_EVT_NONE: i32 = 0;
/// Link cifrado com bonding (`ENC_CHANGE` ok): chamar `on_link_secured`.
pub const BLE_EVT_SECURED: i32 = 1;
/// Central desconectou: se a janela segue aberta, reanunciar.
pub const BLE_EVT_DISCONNECTED: i32 = 2;
/// Central conectou (ainda sem bonding): só log, mantém advertising parado.
pub const BLE_EVT_CONNECTED: i32 = 3;

/// Tamanho máximo de 1 fragmento FFF1 aceito do backend C (== MTU-3 conservador).
pub const BLE_RX_FRAGMENT_MAX: usize = 256;

/// Payload de advertising legado montado (`len` bytes válidos).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvPayload {
    /// Bytes do payload (AD structures encadeadas).
    pub bytes: [u8; ADV_MAX_BYTES],
    /// Comprimento válido (`<= ADV_MAX_BYTES`).
    pub len: u8,
}

impl AdvPayload {
    /// Fatia válida do payload.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// Monta o payload de advertising legado:
/// `Flags(0x06) + CompleteList16[0xFFFD] + ServiceData16[0xFFFD, flag] + Nome`.
///
/// - UUID de serviço `0xFFFD` sempre presente (app filtra por ele).
/// - Flag de pareamento `0x01` SOMENTE com a janela aberta; `0x00` caso
///   contrário (o backend C só anuncia com a janela aberta mesmo assim).
/// - Nunca excede 31B (garantido por construção; teste trava o layout).
pub fn encode_adv_payload(pairing_open: bool) -> AdvPayload {
    let mut bytes = [0u8; ADV_MAX_BYTES];
    let mut n: usize = 0;
    // Flags: [len=2][type=0x01][LE General Disc + BR/EDR não suportado].
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

/// `true` somente quando o rádio deve anunciar: estado `PairingBle` com a
/// janela de 60s aberta.
///
/// - `PairingAp`: mudo (fallback WiFi AP usa o rádio; BLE cede).
/// - `Idle`/`Arming`/`Locked`: mudo (privacidade + bateria).
/// - Janela expirada: mudo (o `tick` já moveu para `Locked`).
pub fn should_advertise(mgr: &PairingManager, now_ms: u64) -> bool {
    matches!(mgr.state(), PairingState::PairingBle { .. }) && mgr.is_pairing_window_open(now_ms)
}

/// Reconexão de confiável sem janela (UX, sem botão para reconectar).
///
/// `true` em `Idle` com relação de confiança (`bonded` da sessão ou
/// `claimed` da NVS): o rádio anuncia com flag de pareamento APAGADA
/// (só reconecta; parear de novo exige janela). Device novo/sem vínculo
/// segue mudo. Gates intactos: UP por operação + bonding; completar um
/// pareamento novo continua exigindo janela + UP.
/// Bateria: anúncio contínuo enquanto ocioso+confiável (troca consciente
/// por não exigir hold a cada sessão).
pub fn should_advertise_reconnect(state: PairingState, trusted: bool) -> bool {
    trusted && matches!(state, PairingState::Idle)
}

/// Intervalos de advertising (min, max) em unidades de 0,625ms.
///
/// `wifi_active`: AP fallback ligado ou station conectada → intervalo lento
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
/// Desiste após N falhas até a próxima borda de `want` (janela reaberta).
pub const BLE_START_MAX_TRIES: u32 = 3;

/// Gate de tentativas do `esp_ble_start` (F5/D08).
///
/// Sem isso, uma falha de `nimble_port_init` (ex.: heap curto no primeiro
/// pareamento) repetia o start a CADA poll: cada tentativa realocava o
/// controlador por cima, vazava heap até `Malloc failed` e o `emi.c`
/// derrubava o device em panic (Interrupt WDT). Com o gate: 1 tentativa a
/// cada 5s, no máximo 3 por borda de janela.
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
        if self.last_try_ms != 0
            && now_ms.saturating_sub(self.last_try_ms) < BLE_START_BACKOFF_MS
        {
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
}

impl Default for BleStartGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Moldura de resposta FFF2 notify: `[opcode, status, payload...]`.
///
/// `status`: `0x00` OK ou `BleGattError::to_vendor_status`. Carga limitada
/// a `CONTROL_POINT_LENGTH` (trunca o excedente, sem erro).
pub fn notify_frame(opcode: u8, status: u8, payload: &[u8]) -> Vec<u8> {
    let take = payload.len().min(CONTROL_POINT_LENGTH);
    let mut out = Vec::with_capacity(2 + take);
    out.push(opcode);
    out.push(status);
    out.extend_from_slice(&payload[..take]);
    out
}

/// Alimenta 1 fragmento FFF1 vindo do backend C no `BleGattServer`.
///
/// Reúso direto de `control_write` (UP por operação, latch de uso único pelo
/// chamador via `presence_confirmed`). Retorna a mensagem completa quando o
/// último fragmento chega. Fragmento vazio/oversize é rejeitado antes.
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

/// Tamanho pendente (FFF3) após alimentar fragmentos.
pub fn pending_len(server: &BleGattServer) -> u16 {
    server.read_len()
}

/// Revisão GATT esperada (FFF4 permanece `0x01`).
pub fn expected_revision() -> u8 {
    GATT_REVISION
}

/// Desfecho do evento `SECURED` (link cifrado + bonding ok) no `main.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondOutcome {
    /// Pareado: `complete_pairing` ok → parar advertising + LED verde + tela.
    Paired,
    /// UP físico ausente no latch: mantém advertising, pede toque.
    DeniedNoPresence,
    /// Fora da janela (corrida com timeout): nada a fazer.
    DeniedNoWindow,
}

/// Trata link seguro: exige janela aberta + UP físico (latch de uso único).
///
/// Delega a `PairingManager::complete_pairing` (que emite `PairingPaired` e
/// volta a `Idle`, saindo do modo). O chamador (`main.rs`) para o
/// advertising imediatamente quando o retorno é `Paired`.
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
// Backend de rádio: FFI manual com o componente C `aegis_ble`
// (mesmo padrão dos `aegis_usb_*` no `main.rs`; sem bindgen, sem novos deps).
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
}

/// Liga o advertising NimBLE (init uma vez; idempotente).
/// `pairing_open`: flag de pareamento no service-data.
/// `wifi_active`: intervalo lento (WiFi ativo; BLE cede airtime).
/// Retorna `0` ok, negativo = `esp_err_t`/código NimBLE.
#[cfg(target_os = "espidf")]
pub fn esp_ble_start(pairing_open: bool, wifi_active: bool) -> i32 {
    crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "ble-adv");
    unsafe { aegis_ble_start(i32::from(pairing_open), i32::from(wifi_active)) }
}

/// Pré-inicializa o NimBLE no boot (heap fresco), sem anunciar.
///
/// O primeiro pareamento não paga o `nimble_port_init` sob heap
/// fragmentado (causa raiz dos `hci inits failed` intermitentes que, com
/// retry a cada poll, vazavam o controlador até o panic). Falha aqui não
/// trava o boot: o [`BleStartGate`] do loop tenta de novo com backoff.
/// Retorna `0` ok, negativo = código do backend C.
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

/// Enfileira 1 notify FFF2 (`0` ok, `<0` = sem conexão/inscrito ou erro).
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

/// `true` quando há central conectada (para logs/heartbeat).
#[cfg(target_os = "espidf")]
pub fn esp_ble_conn_active() -> bool {
    unsafe { aegis_ble_conn_active() == 1 }
}

// Shims inertes no host (sem rádio; política testada por unidade).
#[cfg(not(target_os = "espidf"))]
pub fn esp_ble_start(_pairing_open: bool, _wifi_active: bool) -> i32 {
    0
}
#[cfg(not(target_os = "espidf"))]
pub fn esp_ble_stop() -> i32 {
    0
}
#[cfg(not(target_os = "espidf"))]
pub fn esp_ble_poll_event() -> i32 {
    BLE_EVT_NONE
}
#[cfg(not(target_os = "espidf"))]
pub fn esp_ble_fetch_rx(_out: &mut [u8]) -> i32 {
    0
}
#[cfg(not(target_os = "espidf"))]
pub fn esp_ble_notify(_data: &[u8]) -> i32 {
    0
}
#[cfg(not(target_os = "espidf"))]
pub fn esp_ble_set_pending_len(_value: u16) {}
#[cfg(not(target_os = "espidf"))]
pub fn esp_ble_conn_active() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ble_gatt::{OP_CANCEL, OP_MSG, OP_PING};

    #[test]
    fn ble_start_gate_borda_tenta_backoff_desiste_e_rearma() {
        let mut g = BleStartGate::new();
        // Mudo: nunca tenta e zera.
        assert!(!g.allow(false, 1000));
        // Borda de subida: tenta de imediato.
        assert!(g.allow(true, 1000));
        g.on_result(false);
        // Backoff: 1s depois, não tenta.
        assert!(!g.allow(true, 2000));
        // Após 5s: tenta (2ª).
        assert!(g.allow(true, 6000));
        g.on_result(false);
        // 3ª após backoff; 4ª nega (desistiu até nova borda).
        assert!(g.allow(true, 11000));
        g.on_result(false);
        assert!(!g.allow(true, 16000));
        assert!(!g.allow(true, 60000));
        // Janela fechou e reabriu: zera e tenta de novo.
        assert!(!g.allow(false, 61000));
        assert!(g.allow(true, 62000));
        // Sucesso zera a contagem: a próxima falha recomeça do zero.
        g.on_result(true);
        assert!(g.allow(true, 67000));
        g.on_result(false);
        assert!(!g.allow(true, 67500)); // backoff, contando de 1
        assert!(g.allow(true, 72000));
    }

    #[test]
    fn adv_payload_carrega_uuid_e_cabe_em_31b() {
        for pairing in [false, true] {
            let p = encode_adv_payload(pairing);
            assert!((p.len as usize) <= ADV_MAX_BYTES);
            let b = p.as_bytes();
            // Flags AD.
            assert_eq!(&b[0..3], &[0x02, 0x01, 0x06]);
            // CompleteList16 com 0xFFFD.
            assert_eq!(&b[3..7], &[0x03, 0x03, 0xFD, 0xFF]);
            // ServiceData16 com 0xFFFD + flag.
            let flag = if pairing {
                ADV_PAIRING_ON
            } else {
                ADV_PAIRING_OFF
            };
            assert_eq!(&b[7..12], &[0x04, 0x16, 0xFD, 0xFF, flag]);
            // Nome completo presente.
            assert!(b.len() > 12);
            assert_eq!(b[12], (BLE_DEVICE_NAME.len() + 1) as u8);
            assert_eq!(b[13], 0x09);
            assert_eq!(
                &b[14..14 + BLE_DEVICE_NAME.len()],
                BLE_DEVICE_NAME.as_bytes()
            );
        }
    }

    #[test]
    fn flag_pareamento_so_com_janela_aberta() {
        let off = encode_adv_payload(false);
        let on = encode_adv_payload(true);
        // Só o byte de flag difere.
        let bo = off.as_bytes();
        let bn = on.as_bytes();
        assert_eq!(bo.len(), bn.len());
        let mut diffs = 0;
        for (x, y) in bo.iter().zip(bn.iter()) {
            if x != y {
                diffs += 1;
                assert_eq!((*x, *y), (ADV_PAIRING_OFF, ADV_PAIRING_ON));
            }
        }
        assert_eq!(diffs, 1);
    }

    #[test]
    fn so_anuncia_em_pairing_ble_com_janela_aberta() {
        use crate::config::{LONG_PRESS_MS, PAIRING_WINDOW_MS};
        let mut m = PairingManager::new();
        // Idle/Arming: mudo.
        assert!(!should_advertise(&m, 0));
        m.on_button_level(true, 0);
        assert!(!should_advertise(&m, LONG_PRESS_MS - 1));
        // Entrou em PairingBle: anuncia.
        m.on_button_level(true, LONG_PRESS_MS);
        assert!(should_advertise(&m, LONG_PRESS_MS + 1));
        // Janela expirada: mudo.
        m.tick(LONG_PRESS_MS + PAIRING_WINDOW_MS);
        assert!(!should_advertise(&m, LONG_PRESS_MS + PAIRING_WINDOW_MS));
        // AP: mudo (BLE cede o rádio ao WiFi).
        let mut m2 = PairingManager::new();
        m2.on_button_level(true, 0);
        m2.on_button_level(true, LONG_PRESS_MS);
        m2.enter_ap_mode();
        assert!(m2.is_pairing_window_open(LONG_PRESS_MS + 10));
        assert!(!should_advertise(&m2, LONG_PRESS_MS + 10));
    }

    #[test]
    fn reconnect_sem_janela_so_com_confianca() {
        use crate::config::{LONG_PRESS_MS, PAIRING_WINDOW_MS};
        // Novo/sem vínculo: mudo (privacidade preservada).
        let m = PairingManager::new();
        assert!(!should_advertise_reconnect(m.state(), false));
        // Pareado na sessão: anuncia em Idle mesmo sem janela.
        let mut b = PairingManager::new();
        b.on_button_level(true, 0);
        b.on_button_level(true, LONG_PRESS_MS);
        assert!(b.complete_pairing(true, LONG_PRESS_MS + 10));
        assert!(b.is_bonded());
        assert_eq!(b.state(), PairingState::Idle);
        assert!(!should_advertise(&b, LONG_PRESS_MS + 10 + PAIRING_WINDOW_MS));
        assert!(should_advertise_reconnect(b.state(), true));
        // Fora de Idle (ex.: Locked): sem anúncio de reconexão.
        b.lock();
        assert!(!should_advertise_reconnect(b.state(), true));
    }

    #[test]
    fn intervalo_lento_quando_wifi_ativo() {
        assert_eq!(
            adv_intervals(false),
            (ADV_ITVL_NORMAL_MIN, ADV_ITVL_NORMAL_MAX)
        );
        assert_eq!(adv_intervals(true), (ADV_ITVL_COEX_MIN, ADV_ITVL_COEX_MAX));
        // Coex lento de verdade (cede airtime): min lento > max normal.
        // Intentional spec guard on frozen constants (clippy::assertions_on_constants).
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(ADV_ITVL_COEX_MIN > ADV_ITVL_NORMAL_MAX);
        }
    }

    #[test]
    fn notify_frame_layout_e_teto() {
        let f = notify_frame(OP_PING, 0x00, b"abc");
        assert_eq!(f, [OP_PING, 0x00, b'a', b'b', b'c']);
        let big = alloc::vec![0xAAu8; CONTROL_POINT_LENGTH + 100];
        let f2 = notify_frame(OP_MSG, 0x04, &big);
        assert_eq!(f2.len(), 2 + CONTROL_POINT_LENGTH);
        assert_eq!((f2[0], f2[1]), (OP_MSG, 0x04));
    }

    #[test]
    fn glue_repassa_fragmento_e_len() {
        let mut s = BleGattServer::new();
        // Sem UP: nega (UP por operação preservado).
        let frag = [OP_PING, 0x00, 0x01, 0x42];
        assert_eq!(
            feed_control_write(&mut s, &frag, false),
            Err(BleGattError::PresenceRequired)
        );
        // Com UP: completa PING de 1B.
        let done = feed_control_write(&mut s, &frag, true)
            .expect("up ok")
            .expect("completa");
        assert_eq!(done.opcode, OP_PING);
        assert_eq!(done.payload, [0x42]);
        assert_eq!(pending_len(&s), 0);
        assert_eq!(expected_revision(), GATT_REVISION);
    }

    #[test]
    fn glue_rejeita_fragmento_vazio_ou_grande() {
        let mut s = BleGattServer::new();
        assert_eq!(
            feed_control_write(&mut s, &[], true),
            Err(BleGattError::InvalidFragment)
        );
        let big = alloc::vec![0u8; BLE_RX_FRAGMENT_MAX + 1];
        assert_eq!(
            feed_control_write(&mut s, &big, true),
            Err(BleGattError::InvalidFragment)
        );
    }

    #[test]
    fn cancel_via_glue_aborta() {
        let mut s = BleGattServer::new();
        let done = feed_control_write(&mut s, &[OP_CANCEL, 0x00, 0x00], true)
            .expect("cancel ok")
            .expect("retorna cancel");
        assert_eq!(done.opcode, OP_CANCEL);
        assert!(done.payload.is_empty());
    }

    #[test]
    fn link_seguro_exige_janela_e_up() {
        use crate::config::{LONG_PRESS_MS, PAIRING_WINDOW_MS};
        let mut m = PairingManager::new();
        // Fora da janela: nega (mesmo com UP).
        assert_eq!(
            on_link_secured(&mut m, true, 0),
            BondOutcome::DeniedNoWindow
        );
        assert!(!m.is_bonded());
        // Na janela sem UP: nega, mantém advertising.
        m.on_button_level(true, 0);
        m.on_button_level(true, LONG_PRESS_MS);
        assert_eq!(
            on_link_secured(&mut m, false, LONG_PRESS_MS + 10),
            BondOutcome::DeniedNoPresence
        );
        assert!(!m.is_bonded());
        assert!(should_advertise(&m, LONG_PRESS_MS + 10));
        // Janela + UP: pareado, sai do modo (advertising para no main).
        assert_eq!(
            on_link_secured(&mut m, true, LONG_PRESS_MS + 20),
            BondOutcome::Paired
        );
        assert!(m.is_bonded());
        assert_eq!(m.state(), PairingState::Idle);
        assert!(!should_advertise(&m, LONG_PRESS_MS + 20));
        // Corrida com timeout: nega.
        let mut m2 = PairingManager::new();
        m2.on_button_level(true, 0);
        m2.on_button_level(true, LONG_PRESS_MS);
        assert_eq!(
            on_link_secured(&mut m2, true, LONG_PRESS_MS + PAIRING_WINDOW_MS),
            BondOutcome::DeniedNoWindow
        );
    }

    #[test]
    fn host_shims_inertes() {
        assert_eq!(esp_ble_start(true, false), 0);
        assert_eq!(esp_ble_stop(), 0);
        assert_eq!(esp_ble_poll_event(), BLE_EVT_NONE);
        let mut b = [0u8; 8];
        assert_eq!(esp_ble_fetch_rx(&mut b), 0);
        assert_eq!(esp_ble_notify(&[1, 2, 3]), 0);
        esp_ble_set_pending_len(7);
        assert!(!esp_ble_conn_active());
    }
}
