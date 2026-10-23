//! Variante FreeRTOS em Rust para o firmware AegisKey.
//!
//! O firmware legado roda um único super-loop (`run_authenticator` em
//! `main.rs`) sobre o ESP-IDF — que por baixo já usa FreeRTOS, mas sem
//! tarefas explícitas. Este módulo decompõe esse loop em tarefas FreeRTOS
//! de verdade, 100% em Rust:
//!
//! - `usb_ctaphid` — drena pacotes CTAPHID de 64 B, enfileira `FirmwareEvent`.
//! - `ui_button` — debounce + latch de presença (UP) a cada 10 ms.
//! - `housekeeping` — alimenta o [`crate::watchdog::Watchdog`], emite tick.
//!
//! No dispositivo (`target_os = "espidf"`) os atrasos usam `vTaskDelay` e a
//! criação usa `xTaskCreatePinnedToCore`; no host (`cargo test`) o mesmo
//! código roda sobre `std::thread` + canal limitado, preservando a semântica
//! de fila/event-group para testes de regressão.
//!
//!
//! ## Endurecimento T12-parte-A (sem depender da TrustFacade da T8)
//!
//! - **TWDT por task:** cada `spawn_*` subscreve ([`PerTaskWatchdog`]) no
//!   inicio e alimenta por iteracao. No device `esp_task_wdt_add`/`reset`;
//!   no host no-op contavel via [`PerTaskWatchdog::feed_count`].
//! - **Shutdown triplo:** [`FreeRtosScheduler::request_stop`] arma os tres
//!   sinais: flag `stop` + bit [`EVT_SHUTDOWN`] + evento
//!   [`FirmwareEvent::Shutdown`] na fila (com despejo do item mais antigo
//!   se cheia, sem perder o `Shutdown`). As tarefas saem quando
//!   [`FreeRtosScheduler::is_stop_requested`] e `true` (flag **OU** bit);
//!   o dispatcher drena ate `Shutdown` via
//!   [`FreeRtosScheduler::drain_for_shutdown`].
//! - **Fila cheia fail-closed:** [`FreeRtosQueue::send`] nunca bloqueia nem
//!   faz panic; cheia = `false` (mapeado a [`TaskOutcome::Dropped`]).
//!   Nenhum gate de seguranca sofre bypass no descarte: o host retenta
//!   (CTAPHID) e o latch UP so e consumido no roteamento com resposta.
//! - **Timeouts sem busy-loop:** todo idle usa [`task_delay_ms`]
//!   (`vTaskDelay` no device, `sleep` no host); [`FreeRtosQueue::receive`]
//!   e [`EventGroup::wait_bits`] usam `Condvar::wait_timeout`, nunca spin.
//!   `join` nativo cede com atraso de 10 ms por poll.
//!
//! ## Gaps T8 (ExternallyBlocked, sem fiacao nesta lane)
//!
//! A fiacao da TrustFacade (T8) NAO vive aqui por escopo: este modulo nao
//! importa `TrustFacade` e nao fabrica sensor (RSSI/MAC/chave nunca
//! inventados; ausente = fail-closed). Onde faltar fiacao, o status e
//! `ExternallyBlocked`; o canonico vive em
//! `crate::binding::FreertosTrustGap::freertos_open_gaps` (7 gaps).
//! Espelho documental (sem dependencia de tipo) em
//! [`FREERTOS_TRUST_GAPS_EXTERNALLY_BLOCKED`].
//!
//! Notas de conformidade: R12 mutavel (compila com/sem feature `freertos`);
//! R13 stub-only (host sem efeito HW, sem panic); R14 HW-first
//! (`vTaskDelay`/`xTaskCreatePinnedToCore` no device pelo caminho existente,
//! `sleep`/`thread` so no host); R6 sem panics novos (so `expect` em
//! mutex/condvar ja existentes + `spawn`); R7 gated (so `log`, sem
//! segredos). Sem flash/COM7: validacao e host
//! (`cargo test -p aegis-fido-firmware freertos`).
//! Fiação típica (ver `main.rs`, feature `freertos`):
//! ```ignore
//! let sched = freertos::FreeRtosScheduler::new(32);
//! sched.spawn_usb_task(poll_usb_64, queue_clone, events_clone, stop.clone());
//! sched.spawn_button_task(poll_boot, queue_clone, events_clone, stop.clone());
//! sched.spawn_housekeeping_task(queue_clone, events_clone, stop.clone());
//! ```

use crate::ble_gatt::{is_bind_mgmt_op, is_piv_enroll_op, is_vendor_keys_oath_op, is_wallet_op};
use crate::serial_ctaphid::{
    authorize_serial, deny_response, dispatch_serial_bind_mgmt, dispatch_serial_rescue,
    is_rescue_msg, serial_bind_mgmt_consumes_up, SerialGate,
};
use crate::watchdog::Watchdog;
use aegis_fido_core::ctap::{
    CtapEngine, CTAP_CMD_GET_ASSERTION, CTAP_CMD_MAKE_CREDENTIAL, CTAP_CMD_RESET,
};
use aegis_fido_usb::ctaphid::{
    CtapHidFramer, CtapHidManager, CtapHidMessage, CAPABILITY_CBOR, CAPABILITY_WINK, CMD_CBOR,
    CMD_INIT, CMD_MSG, CMD_PING, CMD_WINK,
};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Tick base do escalonador (igual ao super-loop legado: 10 ms).
pub const TICK_MS: u64 = 10;
/// Tamanho do pacote CTAPHID (padronizado FIDO).
pub const CTAPHID_PACKET_SIZE: usize = 64;
/// Profundidade padrão da fila de eventos firmware.
pub const DEFAULT_QUEUE_DEPTH: usize = 32;
/// Poll idle da tarefa USB/pacote em ms (sem busy-loop: idle cede via `task_delay_ms`).
pub const USB_POLL_MS: u64 = 5;
/// Poll do `join` nativo e do dreno de shutdown em ms (cede o nucleo, nunca spin).
pub const SHUTDOWN_POLL_MS: u64 = 10;
/// Timeout padrao do dreno ate `Shutdown` em ms.
pub const SHUTDOWN_DRAIN_DEFAULT_MS: u64 = 500;
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

/// Bits do EventGroup (espelham `xEventGroupSetBits`).
pub const EVT_USB_RX: u32 = 1 << 0;
/// Botão BOOT pressionado (UP).
pub const EVT_BUTTON_UP: u32 = 1 << 1;
/// Fragmento BLE recebido.
pub const EVT_BLE_RX: u32 = 1 << 2;
/// Tick periódico de 10 ms.
pub const EVT_TICK_10MS: u32 = 1 << 3;
/// Desligamento cooperativo das tarefas.
pub const EVT_SHUTDOWN: u32 = 1 << 31;

/// Prioridades FreeRTOS (maior = mais prioritário; idle = 0).
pub const USB_TASK_PRIO: u8 = 5;
/// Tarefa de UI/botão.
pub const UI_TASK_PRIO: u8 = 4;
/// Tarefa de housekeeping/watchdog.
pub const HOUSEKEEPING_TASK_PRIO: u8 = 2;

/// Stacks por tarefa (bytes; ESP32-S3 tem 512 KiB SRAM).
pub const USB_TASK_STACK: usize = 8 * 1024;
/// Stack da tarefa de botão/UI.
pub const UI_TASK_STACK: usize = 8 * 1024;
/// Stack da tarefa de housekeeping.
pub const HOUSEKEEPING_TASK_STACK: usize = 8 * 1024;

/// Origem física de um pacote CTAPHID de 64 B.
///
/// `Usb` = `aegis_usb_pop_packet` (TinyUSB nativo); `Serial` =
/// `aegis_serial_pop_packet` (UART0 diagnóstico, mesmo enquadramento de 64 B).
/// A resposta sempre volta pela mesma origem do pedido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketOrigin {
    /// USB nativo (TinyUSB).
    Usb,
    /// Serial UART0 (diagnóstico, mesmo enquadramento).
    Serial,
}

/// Evento firmware transportado pela fila entre tarefas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirmwareEvent {
    /// Pacote CTAPHID bruto de 64 B vindo do USB nativo.
    UsbPacket([u8; CTAPHID_PACKET_SIZE]),
    /// Pacote CTAPHID bruto de 64 B vindo da serial (UART0, mesmo enquadramento).
    SerialPacket([u8; CTAPHID_PACKET_SIZE]),
    /// Transição de botão amostrada (BOOT = UP, KEY = cancelar/próximo).
    ButtonPress { boot: bool, key: bool },
    /// Fragmento BLE GATT recebido (até 512 B).
    BleFragment([u8; 8], usize),
    /// Tick periódico (contador de 10 ms).
    Tick10ms(u64),
    /// Pedido de desligamento cooperativo.
    Shutdown,
}

/// Configuração de uma tarefa FreeRTOS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskConfig {
    /// Nome visível em `vTaskList` / `uxTaskGetStackHighWaterMark`.
    pub name: &'static str,
    /// Stack em bytes.
    pub stack_size: usize,
    /// Prioridade (0 = idle).
    pub priority: u8,
    /// Núcleo fixo (`None` = sem afinidade).
    pub pinned_core: Option<u8>,
}

impl TaskConfig {
    /// Cria e valida (prioridade 0..=24, stack >= 2 KiB).
    pub fn new(
        name: &'static str,
        stack_size: usize,
        priority: u8,
        pinned_core: Option<u8>,
    ) -> Option<Self> {
        if !(1..=24).contains(&priority) || stack_size < 2048 {
            return None;
        }
        if let Some(c) = pinned_core {
            if c > 1 {
                return None;
            }
        }
        Some(Self {
            name,
            stack_size,
            priority,
            pinned_core,
        })
    }

    /// Config padrão da tarefa USB.
    pub fn usb() -> Self {
        Self {
            name: "usb_ctaphid",
            stack_size: USB_TASK_STACK,
            priority: USB_TASK_PRIO,
            pinned_core: Some(1),
        }
    }

    /// Config padrão da tarefa de botão/UI.
    pub fn button() -> Self {
        Self {
            name: "ui_button",
            stack_size: UI_TASK_STACK,
            priority: UI_TASK_PRIO,
            pinned_core: None,
        }
    }

    /// Config padrão da tarefa de housekeeping.
    pub fn housekeeping() -> Self {
        Self {
            name: "housekeeping",
            stack_size: HOUSEKEEPING_TASK_STACK,
            priority: HOUSEKEEPING_TASK_PRIO,
            pinned_core: None,
        }
    }
}

/// Fila limitada estilo `xQueueCreate` (FIFO, com bloqueio e timeout).
///
/// No host usa `Mutex<VecDeque> + Condvar`; no ESP-IDF o transporte real
/// é a fila nativa (ver [`FreeRtosScheduler`]), mas a semântica — FIFO,
/// capacidade fixa, `send` não-bloqueante com descarte fail-closed e
/// `receive` com timeout — é idêntica e testada aqui.
pub struct FreeRtosQueue<T> {
    inner: Mutex<VecDeque<T>>,
    not_empty: Condvar,
    capacity: usize,
}

impl<T> FreeRtosQueue<T> {
    /// Cria fila com a profundidade dada (mínimo 1).
    pub fn new(depth: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(depth.max(1))),
            not_empty: Condvar::new(),
            capacity: depth.max(1),
        }
    }

    /// Envia sem bloquear; `false` = cheia (descarte fail-closed, sem panic).
    ///
    /// Fail-closed documentado: cheia nunca bloqueia a produtora (o TWDT nao
    /// estoura), nunca faz panic e nunca entrega parcial; o evento e
    /// descartado inteiro e o host retenta (mapeado a `TaskOutcome::Dropped`
    /// no consumo). Latch UP e gates CTAP so mudam no roteamento com
    /// resposta, nunca no descarte. Excecao: `FirmwareEvent::Shutdown` usa
    /// `request_stop`/`drain_for_shutdown` e nunca se perde (despejo + retry).
    pub fn send(&self, item: T) -> bool {
        let mut q = self.inner.lock().expect("queue mutex");
        if q.len() >= self.capacity {
            return false;
        }
        q.push_back(item);
        self.not_empty.notify_one();
        true
    }

    /// Recebe com timeout em ms (`None` = sem espera).
    pub fn receive(&self, timeout_ms: Option<u64>) -> Option<T> {
        let mut q = self.inner.lock().expect("queue mutex");
        if let Some(item) = q.pop_front() {
            return Some(item);
        }
        let ms = timeout_ms?;
        let (guard, _res) = self
            .not_empty
            .wait_timeout(q, Duration::from_millis(ms))
            .expect("queue condvar");
        let mut guard = guard;
        guard.pop_front()
    }

    /// Tamanho atual.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("queue mutex").len()
    }

    /// Capacidade configurada.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Fila vazia?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// EventGroup estilo FreeRTOS (`xEventGroupSetBits/WaitBits`).
///
/// Bits são trwa; `wait_bits` bloqueia até `(current & mask) != 0` ou
/// timeout, opcionalmente limpando os bits na saída (`clear_on_exit`,
/// como `pdTRUE` no `xClearOnExit`).
#[derive(Debug, Default)]
pub struct EventGroup {
    bits: AtomicU32,
    mutex: Mutex<()>,
    cv: Condvar,
}

impl EventGroup {
    /// Cria grupo zerado.
    pub fn new() -> Self {
        Self {
            bits: AtomicU32::new(0),
            mutex: Mutex::new(()),
            cv: Condvar::new(),
        }
    }

    /// Liga bits (OR atômico) e acorda esperas.
    pub fn set_bits(&self, bits: u32) {
        self.bits.fetch_or(bits, Ordering::SeqCst);
        let _g = self.mutex.lock().expect("event mutex");
        self.cv.notify_all();
    }

    /// Desliga bits (AND-NOT atômico).
    pub fn clear_bits(&self, bits: u32) {
        self.bits.fetch_and(!bits, Ordering::SeqCst);
    }

    /// Snapshot atual.
    pub fn get(&self) -> u32 {
        self.bits.load(Ordering::SeqCst)
    }

    /// Espera até algum bit de `mask` ligar, com timeout em ms.
    /// Retorna os bits correntes (podem não conter `mask` se expirou).
    pub fn wait_bits(&self, mask: u32, clear_on_exit: bool, timeout_ms: u64) -> u32 {
        let guard = self.mutex.lock().expect("event mutex");
        let deadline = Duration::from_millis(timeout_ms);
        let mut guard = guard;
        let start = std::time::Instant::now();
        loop {
            let cur = self.bits.load(Ordering::SeqCst);
            if cur & mask != 0 {
                if clear_on_exit {
                    self.bits.fetch_and(!mask, Ordering::SeqCst);
                }
                return cur;
            }
            let elapsed = start.elapsed();
            if elapsed >= deadline {
                return self.bits.load(Ordering::SeqCst);
            }
            let remain = deadline - elapsed;
            let (g, _r) = self.cv.wait_timeout(guard, remain).expect("event condvar");
            guard = g;
        }
    }
}

/// Resultado do roteamento de um evento (observável em testes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskOutcome {
    /// Evento consumido com sucesso.
    Handled,
    /// Fila cheia / evento descartado (fail-closed, sem perda de segurança).
    Dropped,
    /// Pedido de parada recebido.
    Stop,
}

/// Passo puro da tarefa USB: valida 64 B e converte em evento.
///
/// Retorna `None` se `raw` for `None` (nada a drenar neste tick).
pub fn usb_task_step(raw: Option<[u8; CTAPHID_PACKET_SIZE]>) -> Option<FirmwareEvent> {
    raw.map(FirmwareEvent::UsbPacket)
}

/// Passo puro da tarefa serial: valida 64 B e converte em evento.
///
/// Espelha [`usb_task_step`] para o canal UART0 (`aegis_serial_pop_packet`):
/// só pacotes completos de 64 B viram evento; texto de diagnóstico (`< 64 B`,
/// linhas `\n`) nunca chega aqui (drenado pelo caminho de texto test-mode).
pub fn serial_task_step(raw: Option<[u8; CTAPHID_PACKET_SIZE]>) -> Option<FirmwareEvent> {
    raw.map(FirmwareEvent::SerialPacket)
}

/// Passo unificado pacote+origem: preserva o transporte de entrada.
///
/// `poll` drena USB primeiro e serial em seguida; a origem marca por onde a
/// resposta de 64 B deve voltar (mesmo enquadramento nos dois fios).
pub fn packet_task_step(
    raw: Option<([u8; CTAPHID_PACKET_SIZE], PacketOrigin)>,
) -> Option<FirmwareEvent> {
    match raw {
        Some((pkt, PacketOrigin::Usb)) => Some(FirmwareEvent::UsbPacket(pkt)),
        Some((pkt, PacketOrigin::Serial)) => Some(FirmwareEvent::SerialPacket(pkt)),
        None => None,
    }
}

/// Origem de transporte de um evento (`None` = sem pacote).
pub fn packet_origin(ev: &FirmwareEvent) -> Option<PacketOrigin> {
    match ev {
        FirmwareEvent::UsbPacket(_) => Some(PacketOrigin::Usb),
        FirmwareEvent::SerialPacket(_) => Some(PacketOrigin::Serial),
        _ => None,
    }
}

/// Bytes brutos de um evento pacote (`None` = sem pacote).
pub fn packet_bytes(ev: &FirmwareEvent) -> Option<[u8; CTAPHID_PACKET_SIZE]> {
    match ev {
        FirmwareEvent::UsbPacket(pkt) | FirmwareEvent::SerialPacket(pkt) => Some(*pkt),
        _ => None,
    }
}

/// Passo puro da tarefa de botão: borda de subida gera `ButtonPress`.
pub fn button_task_step(boot_pressed: bool, key_pressed: bool) -> Option<FirmwareEvent> {
    if boot_pressed || key_pressed {
        Some(FirmwareEvent::ButtonPress {
            boot: boot_pressed,
            key: key_pressed,
        })
    } else {
        None
    }
}

/// Passo puro do housekeeping: alimenta o watchdog e emite tick.
///
/// Retorna `TaskOutcome::Stop` se `stop` estiver armado.
pub fn housekeeping_step(tick: u64, watchdog: &mut Watchdog, stop: &AtomicBool) -> TaskOutcome {
    if stop.load(Ordering::SeqCst) {
        return TaskOutcome::Stop;
    }
    watchdog.feed(tick);
    TaskOutcome::Handled
}

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
            // dispatcher FreeRTOS (paridade seção D legada). `None` = cai
            // no engine CTAP genérico abaixo (U2F/OTA/desconhecido).
            if msg.cmd == CMD_MSG && !msg.payload.is_empty() {
                if let Some(ctx) = vendor {
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

/// Atrasa a tarefa corrente (`vTaskDelay` no device, `sleep` no host).
pub fn task_delay_ms(ms: u64) {
    #[cfg(target_os = "espidf")]
    // SAFETY: `vTaskDelay` só bloqueia a tarefa corrente pelo nº de ticks;
    // não toca memória partilhada nem invalida ponteiros.
    unsafe {
        // Tick nativo = 10 ms no ESP-IDF padrão (100 Hz); mínimo 1 tick.
        let ticks = ((ms / 10).max(1)) as u32;
        esp_idf_sys::vTaskDelay(ticks);
    }
    #[cfg(not(target_os = "espidf"))]
    std::thread::sleep(Duration::from_millis(ms));
}

/// Atraso da tarefa corrente via FreeRTOS (`vTaskDelay` no device).
///
/// Nome canónico alternativo de [`task_delay_ms`] (mantido sem alteração);
/// ambos partilham a mesma semântica de tick.
pub fn freertos_task_delay_ms(ms: u64) {
    task_delay_ms(ms);
}

/// Contador de ticks desde o boot (`xTaskGetTickCount` no device).
pub fn tick_count_ms() -> u64 {
    #[cfg(target_os = "espidf")]
    // SAFETY: `xTaskGetTickCount` é leitura pura do contador do kernel,
    // sem ponteiros nem efeitos sobre memória partilhada.
    unsafe {
        // `xTaskGetTickCount` retorna ticks de 10 ms; converte p/ ms.
        (esp_idf_sys::xTaskGetTickCount() as u64).saturating_mul(10)
    }
    #[cfg(not(target_os = "espidf"))]
    {
        use std::sync::OnceLock;
        static BOOT: OnceLock<std::time::Instant> = OnceLock::new();
        let t0 = BOOT.get_or_init(std::time::Instant::now);
        t0.elapsed().as_millis() as u64
    }
}

/// Comprimento máximo do nome de tarefa FreeRTOS (`configMAX_TASK_NAME_LEN`).
#[cfg(target_os = "espidf")]
const FREERTOS_MAX_TASK_NAME_LEN: usize = 16;
/// Núcleo sem afinidade fixa (`tskNO_AFFINITY = 0x7FFFFFFF` no ESP-IDF).
#[cfg(target_os = "espidf")]
const FREERTOS_NO_AFFINITY: i32 = 0x7FFF_FFFF;
/// Retorno de sucesso das criações FreeRTOS (`pdPASS = 1`).
#[cfg(target_os = "espidf")]
const FREERTOS_PD_PASS: i32 = 1;
/// Byte por palavra de stack FreeRTOS no ESP32 (32 bits).
#[cfg(target_os = "espidf")]
const FREERTOS_STACK_WORD_BYTES: usize = 4;

// SAFETY: tarefa-sonda sem estado partilhado; `vTaskDelete(NULL)` apaga a
// tarefa corrente por contrato do FreeRTOS, sem desreferenciar ponteiros.
#[cfg(target_os = "espidf")]
unsafe extern "C" fn freertos_probe_task(_param: *mut core::ffi::c_void) {
    // SAFETY: `NULL` seleciona a tarefa corrente; a chamada não retorna.
    unsafe {
        esp_idf_sys::vTaskDelete(core::ptr::null_mut());
    }
}

/// Cria uma tarefa FreeRTOS nativa (`xTaskCreatePinnedToCore` no device).
///
/// Sobe uma tarefa-sonda que se auto-apaga (`vTaskDelete`) apenas para
/// validar o caminho FFI com os parâmetros dados; o firmware real escala
/// via [`FreeRtosScheduler`], cujas threads std no ESP-IDF já nascem como
/// tarefas FreeRTOS. Retorna `true` se a criação foi aceite (`pdPASS`),
/// `false` se os parâmetros forem inválidos (validados via [`TaskConfig`]).
/// No host valida sem efeito colateral (sem panic).
pub fn freertos_task_create(
    name: &'static str,
    stack_bytes: usize,
    priority: u8,
    core: Option<u8>,
) -> bool {
    if TaskConfig::new(name, stack_bytes, priority, core).is_none() {
        return false;
    }
    #[cfg(target_os = "espidf")]
    // SAFETY: nome NUL-terminado em buffer local vivo durante a chamada;
    // stack convertida p/ words (mínimo 512); prioridade/núcleo já validados
    // via `TaskConfig`; handle de saída descartado (`NULL`); `pdPASS` = ok.
    unsafe {
        let mut cname = [0u8; FREERTOS_MAX_TASK_NAME_LEN];
        let bytes = name.as_bytes();
        let take = bytes.len().min(FREERTOS_MAX_TASK_NAME_LEN - 1);
        cname[..take].copy_from_slice(&bytes[..take]);
        let stack_words: u32 = (stack_bytes.div_ceil(FREERTOS_STACK_WORD_BYTES).max(512)) as u32;
        let affinity: i32 = core.map_or(FREERTOS_NO_AFFINITY, i32::from);
        let ret = esp_idf_sys::xTaskCreatePinnedToCore(
            Some(freertos_probe_task),
            cname.as_ptr().cast::<core::ffi::c_char>(),
            stack_words,
            core::ptr::null_mut(),
            u32::from(priority),
            core::ptr::null_mut(),
            affinity,
        );
        ret == FREERTOS_PD_PASS
    }
    #[cfg(not(target_os = "espidf"))]
    {
        // Host: sem FreeRTOS nativo; parâmetros já validados acima.
        true
    }
}

/// Água-alta de stack livre da tarefa corrente, em bytes.
///
/// No device lê `uxTaskGetStackHighWaterMark(NULL)` (retorno em words × 4);
/// no host devolve 4096 (fallback testável, sem panic).
pub fn stack_high_water_mark() -> usize {
    #[cfg(target_os = "espidf")]
    // SAFETY: `NULL` seleciona a tarefa corrente por contrato do FreeRTOS;
    // a chamada só lê o TCB, sem escrever memória.
    unsafe {
        (esp_idf_sys::uxTaskGetStackHighWaterMark(core::ptr::null_mut()) as usize)
            .saturating_mul(FREERTOS_STACK_WORD_BYTES)
    }
    #[cfg(not(target_os = "espidf"))]
    {
        4096
    }
}

/// Número de tarefas FreeRTOS vivas (`uxTaskGetNumberOfTasks` no device).
///
/// No host devolve 3 (as tarefas do [`FreeRtosScheduler`]), sem panic.
pub fn task_count() -> usize {
    #[cfg(target_os = "espidf")]
    // SAFETY: `uxTaskGetNumberOfTasks` é leitura pura do kernel, sem
    // ponteiros nem efeitos sobre memória partilhada.
    unsafe {
        esp_idf_sys::uxTaskGetNumberOfTasks() as usize
    }
    #[cfg(not(target_os = "espidf"))]
    {
        3
    }
}

/// Núcleo que executa a tarefa corrente (`xTaskGetCoreID(NULL)` no device).
///
/// No host devolve -1 (sem afinidade FreeRTOS), sem panic.
pub fn current_core_id() -> i32 {
    #[cfg(target_os = "espidf")]
    // SAFETY: `NULL` seleciona a tarefa corrente; leitura pura, sem escrita.
    unsafe {
        esp_idf_sys::xTaskGetCoreID(core::ptr::null_mut()) as i32
    }
    #[cfg(not(target_os = "espidf"))]
    {
        -1
    }
}

/// Boot info do FreeRTOS via `log` (sem acoplar ao `kprintln` do `main`).
///
/// Só estados e contadores (tarefas, high-water, núcleo): sem segredos.
pub fn log_boot_info() {
    log::info!(
        "[FREERTOS] boot tasks={} stack_high_water={}B core={}",
        task_count(),
        stack_high_water_mark(),
        current_core_id()
    );
}

/// Watchdog por tarefa (TWDT do ESP-IDF).
///
/// Cada `spawn_*` do [`FreeRtosScheduler`] subscreve a tarefa ao iniciar
/// ([`subscribe_current_task`](Self::subscribe_current_task)) e alimenta a
/// cada iteração ([`feed_current_task`](Self::feed_current_task)). No device
/// usa `esp_task_wdt_add(NULL)` + `esp_task_wdt_reset()`; no host é um
/// no-op contável (sem panic), observável via [`feed_count`](Self::feed_count).
#[derive(Debug, Default)]
pub struct PerTaskWatchdog {
    feeds: AtomicU32,
}

impl PerTaskWatchdog {
    /// Subscreve a tarefa corrente ao TWDT.
    ///
    /// No device consulta `esp_task_wdt_status` antes: se a tarefa já está
    /// subscrita (ex. herança do init do IDF), não re-adiciona — sem a
    /// linha `E task_wdt: already subscribed`; no host é no-op.
    pub fn subscribe_current_task() -> Self {
        #[cfg(target_os = "espidf")]
        // SAFETY: `NULL` = tarefa corrente por contrato do IDF; `status`
        // primeiro evita o re-add; o `add` eventual é descartado se falhar.
        unsafe {
            if esp_idf_sys::esp_task_wdt_status(core::ptr::null_mut()) != esp_idf_sys::ESP_OK {
                let _ = esp_idf_sys::esp_task_wdt_add(core::ptr::null_mut());
            }
        }
        Self {
            feeds: AtomicU32::new(0),
        }
    }

    /// Alimenta o TWDT da tarefa corrente (no-op contável no host).
    pub fn feed_current_task(&self) {
        #[cfg(target_os = "espidf")]
        // SAFETY: `esp_task_wdt_reset` atua sobre a subscrição da tarefa
        // corrente criada em `subscribe_current_task`; sem ponteiros.
        unsafe {
            esp_idf_sys::esp_task_wdt_reset();
        }
        self.feeds.fetch_add(1, Ordering::Relaxed);
    }

    /// Número de feeds desde a subscrição (observável em testes/host).
    pub fn feed_count(&self) -> u32 {
        self.feeds.load(Ordering::Relaxed)
    }
}

/// Orquestrador das tarefas FreeRTOS (fila + event-group compartilhados).
///
/// Cada `spawn_*` devolve um `JoinHandle`; o chamador junta com `join_all`.
/// O desligamento é cooperativo via `AtomicBool` + bit [`EVT_SHUTDOWN`].
pub struct FreeRtosScheduler {
    /// Fila de eventos firmware.
    pub queue: Arc<FreeRtosQueue<FirmwareEvent>>,
    /// Event-group compartilhado.
    pub events: Arc<EventGroup>,
    /// Flag de parada cooperativa.
    pub stop: Arc<AtomicBool>,
}

impl FreeRtosScheduler {
    /// Cria escalonador com fila da profundidade dada.
    pub fn new(queue_depth: usize) -> Self {
        Self {
            queue: Arc::new(FreeRtosQueue::new(queue_depth)),
            events: Arc::new(EventGroup::new()),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Pede parada cooperativa: shutdown triplo (flag + bit + dreno).
    ///
    /// Arma `stop` e [`EVT_SHUTDOWN`]; enfileira [`FirmwareEvent::Shutdown`]
    /// para o dispatcher (`drain_for_shutdown`). Se a fila estiver cheia,
    /// despeja o item mais antigo e retenta uma vez: o `Shutdown` nunca se
    /// perde (o despejo descarta dado retryable, nunca gate de seguranca).
    /// Tarefas observam via `is_stop_requested` (flag OU bit); sem busy-loop.
    ///
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.events.set_bits(EVT_SHUTDOWN);
        if !self.queue.send(FirmwareEvent::Shutdown) {
            let _ = self.queue.receive(None);
            let _ = self.queue.send(FirmwareEvent::Shutdown);
        }
    }

    /// `true` se o desligamento triplo foi pedido (flag `stop` OU bit `EVT_SHUTDOWN`).
    ///
    /// Observabilidade dupla: cobre `request_stop` completo e armado parcial
    /// (sinal remanescente). Usado por todas as tarefas a cada iteracao.
    pub fn is_stop_requested(&self) -> bool {
        Self::stop_requested(&self.stop, &self.events)
    }

    /// Predicado compartilhado host/device do shutdown triplo.
    ///
    /// `&Arc<_>` sofre deref para o inner: aceita clones das tarefas e o
    /// `ctx` nativo sem alocar. Sem bloqueio, sem panic novo.
    pub fn stop_requested(stop: &AtomicBool, events: &EventGroup) -> bool {
        stop.load(Ordering::SeqCst) || events.get() & EVT_SHUTDOWN != 0
    }

    /// Drena a fila ate `Shutdown` (terceira perna do shutdown triplo).
    ///
    /// Consome e descarta eventos pre-shutdown ate ver
    /// [`FirmwareEvent::Shutdown`] ou `timeout_ms` expirar. Espera com
    /// `receive(Some(SHUTDOWN_POLL_MS))` (nunca spin). Retorna `true` se o
    /// `Shutdown` foi observado. Chamado apos `request_stop` pelo dispatcher.
    pub fn drain_for_shutdown(&self, timeout_ms: u64) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            if self.queue.receive(Some(SHUTDOWN_POLL_MS)) == Some(FirmwareEvent::Shutdown) {
                return true;
            }
        }
    }

    /// Tarefa USB: drena `poll_64()` a cada `USB_POLL_MS` e enfileira pacotes.
    ///
    /// TWDT alimentado por iteracao; fila cheia = descarte fail-closed
    /// (`TaskOutcome::Dropped`, host reenvia); saida via `stop_requested`
    /// (flag OU `EVT_SHUTDOWN`); idle sempre com `task_delay_ms`, sem spin.
    pub fn spawn_usb_task(
        &self,
        mut poll_64: impl FnMut() -> Option<[u8; CTAPHID_PACKET_SIZE]> + Send + 'static,
    ) -> std::thread::JoinHandle<usize> {
        let queue = Arc::clone(&self.queue);
        let events = Arc::clone(&self.events);
        let stop = Arc::clone(&self.stop);
        std::thread::Builder::new()
            .name("usb_ctaphid".into())
            .stack_size(USB_TASK_STACK)
            .spawn(move || {
                let twdt = PerTaskWatchdog::subscribe_current_task();
                let mut drained = 0usize;
                while !Self::stop_requested(&stop, &events) {
                    twdt.feed_current_task();
                    if let Some(ev) = usb_task_step(poll_64()) {
                        drained += 1;
                        events.set_bits(EVT_USB_RX);
                        if !queue.send(ev) {
                            // Fila cheia: descarta fail-closed (host reenvia).
                        }
                    } else {
                        task_delay_ms(5);
                    }
                }
                drained
            })
            .expect("spawn usb_ctaphid")
    }

    /// Tarefa pacote+origem: drena `poll()` (64 B + [`PacketOrigin`]) e enfileira.
    ///
    /// Variante com origem preservada de [`spawn_usb_task`](Self::spawn_usb_task):
    /// USB marca [`PacketOrigin::Usb`], serial ([`PacketOrigin::Serial`]) o canal
    /// UART0 com o mesmo enquadramento. O dispatcher responde pela mesma origem.
    pub fn spawn_packet_task(
        &self,
        mut poll: impl FnMut() -> Option<([u8; CTAPHID_PACKET_SIZE], PacketOrigin)> + Send + 'static,
    ) -> std::thread::JoinHandle<usize> {
        let queue = Arc::clone(&self.queue);
        let events = Arc::clone(&self.events);
        let stop = Arc::clone(&self.stop);
        std::thread::Builder::new()
            .name("usb_ctaphid".into())
            .stack_size(USB_TASK_STACK)
            .spawn(move || {
                let twdt = PerTaskWatchdog::subscribe_current_task();
                let mut drained = 0usize;
                while !Self::stop_requested(&stop, &events) {
                    twdt.feed_current_task();
                    if let Some(ev) = packet_task_step(poll()) {
                        drained += 1;
                        events.set_bits(EVT_USB_RX);
                        if !queue.send(ev) {
                            // Fila cheia: descarta fail-closed (host reenvia).
                        }
                    } else {
                        task_delay_ms(5);
                    }
                }
                drained
            })
            .expect("spawn usb_ctaphid")
    }

    /// Tarefa de botão: amostra `poll_boot/poll_key` a cada 10 ms, latch UP.
    pub fn spawn_button_task(
        &self,
        mut poll_boot: impl FnMut() -> bool + Send + 'static,
        mut poll_key: impl FnMut() -> bool + Send + 'static,
    ) -> std::thread::JoinHandle<usize> {
        let queue = Arc::clone(&self.queue);
        let events = Arc::clone(&self.events);
        let stop = Arc::clone(&self.stop);
        std::thread::Builder::new()
            .name("ui_button".into())
            .stack_size(UI_TASK_STACK)
            .spawn(move || {
                let twdt = PerTaskWatchdog::subscribe_current_task();
                let mut presses = 0usize;
                while !Self::stop_requested(&stop, &events) {
                    twdt.feed_current_task();
                    let boot = poll_boot();
                    let key = poll_key();
                    if let Some(ev) = button_task_step(boot, key) {
                        presses += 1;
                        events.set_bits(EVT_BUTTON_UP);
                        let _ = queue.send(ev);
                    }
                    task_delay_ms(TICK_MS);
                }
                presses
            })
            .expect("spawn ui_button")
    }

    /// Tarefa de housekeeping: watchdog + tick a cada 10 ms.
    pub fn spawn_housekeeping_task(&self) -> std::thread::JoinHandle<u64> {
        let queue = Arc::clone(&self.queue);
        let events = Arc::clone(&self.events);
        let stop = Arc::clone(&self.stop);
        std::thread::Builder::new()
            .name("housekeeping".into())
            .stack_size(HOUSEKEEPING_TASK_STACK)
            .spawn(move || {
                let twdt = PerTaskWatchdog::subscribe_current_task();
                let mut watchdog = Watchdog::new(300);
                let mut tick: u64 = 0;
                while !Self::stop_requested(&stop, &events)
                    && housekeeping_step(tick, &mut watchdog, &stop) != TaskOutcome::Stop
                {
                    twdt.feed_current_task();
                    if tick.is_multiple_of(100) {
                        events.set_bits(EVT_TICK_10MS);
                        let _ = queue.send(FirmwareEvent::Tick10ms(tick));
                    }
                    tick = tick.saturating_add(1);
                    task_delay_ms(TICK_MS);
                }
                tick
            })
            .expect("spawn housekeeping")
    }
}

/// Handle de tarefa FreeRTOS nativa (`xTaskCreatePinnedToCore` no device).
///
/// Guarda o `TaskHandle_t` devolvido na criação para `delete`, e uma flag
/// `done` para `join` (poll cooperativo com `vTaskDelay`, sem travar o
/// escalonador). O resultado (`drained`, `presses`, `ticks`) é publicado
/// pela tarefa antes de se auto-apagar. Só existe no `target_os = "espidf"`;
/// no host, o equivalente é `std::thread::JoinHandle`.
#[cfg(target_os = "espidf")]
pub struct NativeTaskHandle<R> {
    task: esp_idf_sys::TaskHandle_t,
    result: Arc<Mutex<Option<R>>>,
    done: Arc<AtomicBool>,
}

#[cfg(target_os = "espidf")]
impl<R: Copy> NativeTaskHandle<R> {
    /// Espera a tarefa terminar (poll cooperativo com `vTaskDelay`).
    ///
    /// Lê o resultado publicado pela tarefa; enquanto ausente, cede o
    /// núcleo com atraso de 10 ms (nunca busy-loop). Retorna `None` se a
    /// tarefa foi apagada sem publicar resultado.
    pub fn join(self) -> Option<R> {
        loop {
            if let Ok(guard) = self.result.lock() {
                if let Some(value) = *guard {
                    return Some(value);
                }
            }
            if self.done.load(Ordering::SeqCst) {
                match self.result.lock() {
                    Ok(guard) => return *guard,
                    Err(poison) => return *poison.into_inner(),
                }
            }
            task_delay_ms(10);
        }
    }

    /// Apaga a tarefa (`vTaskDelete`) sem esperar o término.
    pub fn delete(&self) {
        self.done.store(true, Ordering::SeqCst);
        // SAFETY: `task` é o handle vivo devolvido por
        // `xTaskCreatePinnedToCore` para esta tarefa ainda não finalizada.
        unsafe {
            esp_idf_sys::vTaskDelete(self.task);
        }
    }
}

/// Cria tarefa FreeRTOS nativa a partir de um [`TaskConfig`] real.
///
/// Nome NUL em 16 B, stack convertida p/ words (mínimo 512), prioridade e
/// afinidade validadas (`tskNO_AFFINITY` quando `None`). Retorna o handle se
/// `xTaskCreatePinnedToCore` devolveu `pdPASS`; `None` se os parâmetros
/// forem inválidos ou a criação for recusada (o `param` segue do chamador,
/// sem leak em nenhum ramo).
#[cfg(target_os = "espidf")]
fn spawn_native_task(
    config: &TaskConfig,
    entry: unsafe extern "C" fn(*mut core::ffi::c_void),
    param: *mut core::ffi::c_void,
) -> Option<esp_idf_sys::TaskHandle_t> {
    if TaskConfig::new(
        config.name,
        config.stack_size,
        config.priority,
        config.pinned_core,
    )
    .is_none()
    {
        return None;
    }
    let mut cname = [0u8; FREERTOS_MAX_TASK_NAME_LEN];
    let bytes = config.name.as_bytes();
    let take = bytes.len().min(FREERTOS_MAX_TASK_NAME_LEN - 1);
    cname[..take].copy_from_slice(&bytes[..take]);
    let stack_words: u32 = (config
        .stack_size
        .div_ceil(FREERTOS_STACK_WORD_BYTES)
        .max(512)) as u32;
    let affinity: i32 = config.pinned_core.map_or(FREERTOS_NO_AFFINITY, i32::from);
    let mut handle: esp_idf_sys::TaskHandle_t = core::ptr::null_mut();
    // SAFETY: nome NUL em buffer vivo durante a chamada; stack em words e
    // prioridade/afinidade revalidadas via `TaskConfig`; `handle` é escrita
    // válida; `entry`/`param` são o trampolim e o contexto emparelhados.
    let ret = unsafe {
        esp_idf_sys::xTaskCreatePinnedToCore(
            Some(entry),
            cname.as_ptr().cast::<core::ffi::c_char>(),
            stack_words,
            param,
            u32::from(config.priority),
            &mut handle,
            affinity,
        )
    };
    if ret == FREERTOS_PD_PASS {
        Some(handle)
    } else {
        None
    }
}

/// Contexto da tarefa USB nativa (atravessa a FFI como `pvParameters`).
#[cfg(target_os = "espidf")]
struct UsbNativeCtx {
    poll_64: Box<dyn FnMut() -> Option<[u8; CTAPHID_PACKET_SIZE]> + Send + 'static>,
    queue: Arc<FreeRtosQueue<FirmwareEvent>>,
    events: Arc<EventGroup>,
    stop: Arc<AtomicBool>,
    result: Arc<Mutex<Option<usize>>>,
    done: Arc<AtomicBool>,
}

/// Contexto da tarefa pacote+origem nativa (atravessa a FFI como `pvParameters`).
#[cfg(target_os = "espidf")]
struct PacketNativeCtx {
    poll: Box<dyn FnMut() -> Option<([u8; CTAPHID_PACKET_SIZE], PacketOrigin)> + Send + 'static>,
    queue: Arc<FreeRtosQueue<FirmwareEvent>>,
    events: Arc<EventGroup>,
    stop: Arc<AtomicBool>,
    result: Arc<Mutex<Option<usize>>>,
    done: Arc<AtomicBool>,
}

/// Contexto da tarefa de botão nativa (atravessa a FFI como `pvParameters`).
#[cfg(target_os = "espidf")]
struct ButtonNativeCtx {
    poll_boot: Box<dyn FnMut() -> bool + Send + 'static>,
    poll_key: Box<dyn FnMut() -> bool + Send + 'static>,
    queue: Arc<FreeRtosQueue<FirmwareEvent>>,
    events: Arc<EventGroup>,
    stop: Arc<AtomicBool>,
    result: Arc<Mutex<Option<usize>>>,
    done: Arc<AtomicBool>,
}

/// Contexto do housekeeping nativo (atravessa a FFI como `pvParameters`).
#[cfg(target_os = "espidf")]
struct HousekeepingNativeCtx {
    queue: Arc<FreeRtosQueue<FirmwareEvent>>,
    events: Arc<EventGroup>,
    stop: Arc<AtomicBool>,
    result: Arc<Mutex<Option<u64>>>,
    done: Arc<AtomicBool>,
}

// SAFETY: trampolim USB sem estado partilhado além do `Box<UsbNativeCtx>`
// reclamado uma única vez aqui; ao fim publica o resultado, notifica a
// tarefa criadora e auto-apaga com `vTaskDelete(NULL)`.
#[cfg(target_os = "espidf")]
unsafe extern "C" fn usb_task_native_entry(param: *mut core::ffi::c_void) {
    // SAFETY: `param` é o `Box<UsbNativeCtx>` vazado no spawn, reclamado uma
    // única vez nesta tarefa, criada exatamente para ele.
    let mut ctx: Box<UsbNativeCtx> = unsafe { Box::from_raw(param as *mut UsbNativeCtx) };
    let twdt = PerTaskWatchdog::subscribe_current_task();
    twdt.feed_current_task();
    log::info!(
        "[FREERTOS] usb_ctaphid na core {} (prio {})",
        current_core_id(),
        TaskConfig::usb().priority
    );
    let mut drained = 0usize;
    while !FreeRtosScheduler::stop_requested(&ctx.stop, &ctx.events) {
        twdt.feed_current_task();
        if let Some(ev) = usb_task_step((ctx.poll_64)()) {
            drained += 1;
            ctx.events.set_bits(EVT_USB_RX);
            if !ctx.queue.send(ev) {
                // Fila cheia: descarta fail-closed (host reenvia).
            }
        } else {
            task_delay_ms(5);
        }
    }
    if let Ok(mut guard) = ctx.result.lock() {
        *guard = Some(drained);
    }
    ctx.done.store(true, Ordering::SeqCst);
    drop(ctx);
    // SAFETY: `NULL` seleciona a tarefa corrente; a chamada não retorna e o
    // TCB é liberado após o resultado já publicado acima.
    unsafe {
        esp_idf_sys::vTaskDelete(core::ptr::null_mut());
    }
}

// SAFETY: trampolim botão sem estado partilhado além do
// `Box<ButtonNativeCtx>` reclamado uma única vez aqui; ao fim publica o
// resultado, sinaliza `done` e auto-apaga com `vTaskDelete(NULL)`.
// SAFETY: trampolim pacote+origem sem estado partilhado além do
// `Box<PacketNativeCtx>` reclamado uma única vez aqui; ao fim publica o
// resultado, sinaliza `done` e auto-apaga com `vTaskDelete(NULL)`.
#[cfg(target_os = "espidf")]
unsafe extern "C" fn packet_task_native_entry(param: *mut core::ffi::c_void) {
    // SAFETY: `param` é o `Box<PacketNativeCtx>` vazado no spawn, reclamado
    // uma única vez nesta tarefa, criada exatamente para ele.
    let mut ctx: Box<PacketNativeCtx> = unsafe { Box::from_raw(param as *mut PacketNativeCtx) };
    let twdt = PerTaskWatchdog::subscribe_current_task();
    twdt.feed_current_task();
    log::info!(
        "[FREERTOS] usb_ctaphid na core {} (prio {})",
        current_core_id(),
        TaskConfig::usb().priority
    );
    let mut drained = 0usize;
    while !FreeRtosScheduler::stop_requested(&ctx.stop, &ctx.events) {
        twdt.feed_current_task();
        if let Some(ev) = packet_task_step((ctx.poll)()) {
            drained += 1;
            ctx.events.set_bits(EVT_USB_RX);
            if !ctx.queue.send(ev) {
                // Fila cheia: descarta fail-closed (host reenvia).
            }
        } else {
            task_delay_ms(5);
        }
    }
    if let Ok(mut guard) = ctx.result.lock() {
        *guard = Some(drained);
    }
    ctx.done.store(true, Ordering::SeqCst);
    drop(ctx);
    // SAFETY: `NULL` seleciona a tarefa corrente; a chamada não retorna e o
    // TCB é liberado após o resultado já publicado acima.
    unsafe {
        esp_idf_sys::vTaskDelete(core::ptr::null_mut());
    }
}

#[cfg(target_os = "espidf")]
unsafe extern "C" fn button_task_native_entry(param: *mut core::ffi::c_void) {
    // SAFETY: `param` é o `Box<ButtonNativeCtx>` vazado no spawn, reclamado
    // uma única vez nesta tarefa, criada exatamente para ele.
    let mut ctx: Box<ButtonNativeCtx> = unsafe { Box::from_raw(param as *mut ButtonNativeCtx) };
    let twdt = PerTaskWatchdog::subscribe_current_task();
    twdt.feed_current_task();
    log::info!(
        "[FREERTOS] ui_button na core {} (prio {})",
        current_core_id(),
        TaskConfig::button().priority
    );
    let mut presses = 0usize;
    while !FreeRtosScheduler::stop_requested(&ctx.stop, &ctx.events) {
        twdt.feed_current_task();
        let boot = (ctx.poll_boot)();
        let key = (ctx.poll_key)();
        if let Some(ev) = button_task_step(boot, key) {
            presses += 1;
            ctx.events.set_bits(EVT_BUTTON_UP);
            let _ = ctx.queue.send(ev);
        }
        task_delay_ms(TICK_MS);
    }
    if let Ok(mut guard) = ctx.result.lock() {
        *guard = Some(presses);
    }
    ctx.done.store(true, Ordering::SeqCst);
    drop(ctx);
    // SAFETY: `NULL` seleciona a tarefa corrente; a chamada não retorna e o
    // TCB é liberado após o resultado já publicado acima.
    unsafe {
        esp_idf_sys::vTaskDelete(core::ptr::null_mut());
    }
}

// SAFETY: trampolim housekeeping sem estado partilhado além do
// `Box<HousekeepingNativeCtx>` reclamado uma única vez aqui; ao fim publica
// o resultado, sinaliza `done` e auto-apaga com `vTaskDelete(NULL)`.
#[cfg(target_os = "espidf")]
unsafe extern "C" fn housekeeping_task_native_entry(param: *mut core::ffi::c_void) {
    // SAFETY: `param` é o `Box<HousekeepingNativeCtx>` vazado no spawn,
    // reclamado uma única vez nesta tarefa, criada exatamente para ele.
    let ctx: Box<HousekeepingNativeCtx> =
        unsafe { Box::from_raw(param as *mut HousekeepingNativeCtx) };
    let twdt = PerTaskWatchdog::subscribe_current_task();
    twdt.feed_current_task();
    log::info!(
        "[FREERTOS] housekeeping na core {} (prio {})",
        current_core_id(),
        TaskConfig::housekeeping().priority
    );
    let mut watchdog = Watchdog::new(300);
    let mut tick: u64 = 0;
    while !FreeRtosScheduler::stop_requested(&ctx.stop, &ctx.events)
        && housekeeping_step(tick, &mut watchdog, &ctx.stop) != TaskOutcome::Stop
    {
        twdt.feed_current_task();
        if tick.is_multiple_of(100) {
            ctx.events.set_bits(EVT_TICK_10MS);
            let _ = ctx.queue.send(FirmwareEvent::Tick10ms(tick));
        }
        tick = tick.saturating_add(1);
        task_delay_ms(TICK_MS);
    }
    if let Ok(mut guard) = ctx.result.lock() {
        *guard = Some(tick);
    }
    ctx.done.store(true, Ordering::SeqCst);
    drop(ctx);
    // SAFETY: `NULL` seleciona a tarefa corrente; a chamada não retorna e o
    // TCB é liberado após o resultado já publicado acima.
    unsafe {
        esp_idf_sys::vTaskDelete(core::ptr::null_mut());
    }
}

impl FreeRtosScheduler {
    /// Tarefa USB nativa (`usb_ctaphid`: prio 5, 8 KiB, core 1).
    ///
    /// Só no device: cria via `xTaskCreatePinnedToCore` com o
    /// [`TaskConfig::usb`] real; subscreve o TWDT no início e alimenta por
    /// iteração; atrasos só com `vTaskDelay` (nunca `std::thread::sleep`).
    #[cfg(target_os = "espidf")]
    pub fn spawn_usb_task_native(
        &self,
        poll_64: impl FnMut() -> Option<[u8; CTAPHID_PACKET_SIZE]> + Send + 'static,
    ) -> Option<NativeTaskHandle<usize>> {
        let config = TaskConfig::usb();
        let result: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
        let done = Arc::new(AtomicBool::new(false));
        let ctx = Box::new(UsbNativeCtx {
            poll_64: Box::new(poll_64),
            queue: Arc::clone(&self.queue),
            events: Arc::clone(&self.events),
            stop: Arc::clone(&self.stop),
            result: Arc::clone(&result),
            done: Arc::clone(&done),
        });
        let param = Box::into_raw(ctx) as *mut core::ffi::c_void;
        match spawn_native_task(&config, usb_task_native_entry, param) {
            Some(task) => Some(NativeTaskHandle { task, result, done }),
            None => {
                // SAFETY: criação recusada; nenhuma tarefa detém `param`,
                // então reclama o `Box` para não vazar.
                unsafe {
                    drop(Box::from_raw(param as *mut UsbNativeCtx));
                }
                None
            }
        }
    }

    /// Tarefa pacote+origem nativa (`usb_ctaphid` com origem preservada).
    ///
    /// Só no device: mesmo contrato e TWDT da variante
    /// [`Self::spawn_usb_task_native`], mas o `poll` devolve `(pacote, origem)`
    /// e a fila recebe [`FirmwareEvent::UsbPacket`] ou
    /// [`FirmwareEvent::SerialPacket`].
    #[cfg(target_os = "espidf")]
    pub fn spawn_packet_task_native(
        &self,
        poll: impl FnMut() -> Option<([u8; CTAPHID_PACKET_SIZE], PacketOrigin)> + Send + 'static,
    ) -> Option<NativeTaskHandle<usize>> {
        let config = TaskConfig::usb();
        let result: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
        let done = Arc::new(AtomicBool::new(false));
        let ctx = Box::new(PacketNativeCtx {
            poll: Box::new(poll),
            queue: Arc::clone(&self.queue),
            events: Arc::clone(&self.events),
            stop: Arc::clone(&self.stop),
            result: Arc::clone(&result),
            done: Arc::clone(&done),
        });
        let param = Box::into_raw(ctx) as *mut core::ffi::c_void;
        match spawn_native_task(&config, packet_task_native_entry, param) {
            Some(task) => Some(NativeTaskHandle { task, result, done }),
            None => {
                // SAFETY: criação recusada; nenhuma tarefa detém `param`,
                // então reclama o `Box` para não vazar.
                unsafe {
                    drop(Box::from_raw(param as *mut PacketNativeCtx));
                }
                None
            }
        }
    }

    /// Tarefa de botão nativa (`ui_button`: prio 4, 4 KiB, sem afinidade).
    ///
    /// Só no device: mesmos contrato e TWDT da variante [`Self::spawn_button_task`].
    #[cfg(target_os = "espidf")]
    pub fn spawn_button_task_native(
        &self,
        poll_boot: impl FnMut() -> bool + Send + 'static,
        poll_key: impl FnMut() -> bool + Send + 'static,
    ) -> Option<NativeTaskHandle<usize>> {
        let config = TaskConfig::button();
        let result: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
        let done = Arc::new(AtomicBool::new(false));
        let ctx = Box::new(ButtonNativeCtx {
            poll_boot: Box::new(poll_boot),
            poll_key: Box::new(poll_key),
            queue: Arc::clone(&self.queue),
            events: Arc::clone(&self.events),
            stop: Arc::clone(&self.stop),
            result: Arc::clone(&result),
            done: Arc::clone(&done),
        });
        let param = Box::into_raw(ctx) as *mut core::ffi::c_void;
        match spawn_native_task(&config, button_task_native_entry, param) {
            Some(task) => Some(NativeTaskHandle { task, result, done }),
            None => {
                // SAFETY: criação recusada; nenhuma tarefa detém `param`,
                // então reclama o `Box` para não vazar.
                unsafe {
                    drop(Box::from_raw(param as *mut ButtonNativeCtx));
                }
                None
            }
        }
    }

    /// Tarefa de housekeeping nativa (`housekeeping`: prio 2, 4 KiB, sem afinidade).
    ///
    /// Só no device: mesmos contrato e TWDT da variante [`Self::spawn_housekeeping_task`].
    #[cfg(target_os = "espidf")]
    pub fn spawn_housekeeping_task_native(&self) -> Option<NativeTaskHandle<u64>> {
        let config = TaskConfig::housekeeping();
        let result: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
        let done = Arc::new(AtomicBool::new(false));
        let ctx = Box::new(HousekeepingNativeCtx {
            queue: Arc::clone(&self.queue),
            events: Arc::clone(&self.events),
            stop: Arc::clone(&self.stop),
            result: Arc::clone(&result),
            done: Arc::clone(&done),
        });
        let param = Box::into_raw(ctx) as *mut core::ffi::c_void;
        match spawn_native_task(&config, housekeeping_task_native_entry, param) {
            Some(task) => Some(NativeTaskHandle { task, result, done }),
            None => {
                // SAFETY: criação recusada; nenhuma tarefa detém `param`,
                // então reclama o `Box` para não vazar.
                unsafe {
                    drop(Box::from_raw(param as *mut HousekeepingNativeCtx));
                }
                None
            }
        }
    }
}

/// Entrada da variante FreeRTOS (feature `freertos`).
///
/// Demonstra o escalonador sem hardware: drena 3 pacotes sintéticos,
/// injeta 1 UP via botão e roda o housekeeping por ~50 ms. No dispositivo,
/// `main.rs` fia os mesmos `spawn_*` nos drivers reais (TinyUSB, GPIO 0/14,
/// TWDT). Retorna `(usb_drained, button_presses, housekeeping_ticks)`.
pub fn app_main_freertos_demo() -> (usize, usize, u64) {
    use std::sync::atomic::AtomicUsize;
    let sched = FreeRtosScheduler::new(DEFAULT_QUEUE_DEPTH);
    let remaining = Arc::new(AtomicUsize::new(3));
    let rem_clone = Arc::clone(&remaining);
    let usb = sched.spawn_usb_task(move || {
        // Sem wrap: checa antes de decrementar (fetch_sub em 0 embrulha p/ MAX).
        if rem_clone.load(Ordering::SeqCst) == 0 {
            return None;
        }
        if rem_clone.fetch_sub(1, Ordering::SeqCst) > 0 {
            Some([0xAA; CTAPHID_PACKET_SIZE])
        } else {
            None
        }
    });
    let boot_count = Arc::new(AtomicUsize::new(0));
    let boot_clone = Arc::clone(&boot_count);
    let button = sched.spawn_button_task(
        move || boot_clone.fetch_add(1, Ordering::SeqCst) == 2,
        || false,
    );
    let house = sched.spawn_housekeeping_task();
    std::thread::sleep(Duration::from_millis(50));
    sched.request_stop();
    let drained = usb.join().unwrap_or(0);
    let presses = button.join().unwrap_or(0);
    let ticks = house.join().unwrap_or(0);
    (drained, presses, ticks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn task_configs_sao_validas() {
        let usb = TaskConfig::usb();
        let btn = TaskConfig::button();
        let hk = TaskConfig::housekeeping();
        assert_eq!(usb.priority, USB_TASK_PRIO);
        assert_eq!(btn.priority, UI_TASK_PRIO);
        assert_eq!(hk.priority, HOUSEKEEPING_TASK_PRIO);
        assert!(usb.stack_size >= 2048);
        assert!(TaskConfig::new("x", 1024, 5, None).is_none());
        assert!(TaskConfig::new("x", 4096, 0, None).is_none());
        assert!(TaskConfig::new("x", 4096, 25, None).is_none());
        assert!(TaskConfig::new("x", 4096, 5, Some(2)).is_none());
        assert!(TaskConfig::new("ok", 4096, 5, Some(1)).is_some());
    }

    #[test]
    fn event_bits_nao_colidem() {
        let bits = [EVT_USB_RX, EVT_BUTTON_UP, EVT_BLE_RX, EVT_TICK_10MS];
        for (i, a) in bits.iter().enumerate() {
            for (j, b) in bits.iter().enumerate() {
                if i != j {
                    assert_eq!(a & b, 0, "bits {a:#x} e {b:#x} colidem");
                }
            }
        }
        assert_eq!(EVT_SHUTDOWN, 1 << 31);
    }

    #[test]
    fn queue_fifo_com_descarte_fail_closed() {
        let q: FreeRtosQueue<u8> = FreeRtosQueue::new(2);
        assert!(q.is_empty());
        assert!(q.send(1));
        assert!(q.send(2));
        assert!(!q.send(3));
        assert_eq!(q.len(), 2);
        assert_eq!(q.receive(None), Some(1));
        assert_eq!(q.receive(None), Some(2));
        assert_eq!(q.receive(None), None);
    }

    #[test]
    fn queue_receive_com_timeout() {
        let q = Arc::new(FreeRtosQueue::new(4));
        let q2 = Arc::clone(&q);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            q2.send(42u8);
        });
        assert_eq!(q.receive(Some(500)), Some(42u8));
        assert_eq!(q.receive(Some(10)), None);
    }

    #[test]
    fn event_group_set_wait_clear() {
        let eg = EventGroup::new();
        assert_eq!(eg.get(), 0);
        eg.set_bits(EVT_USB_RX | EVT_TICK_10MS);
        let got = eg.wait_bits(EVT_USB_RX, false, 100);
        assert_ne!(got & EVT_USB_RX, 0);
        // Sem clear: bit continua.
        assert_ne!(eg.get() & EVT_USB_RX, 0);
        let got2 = eg.wait_bits(EVT_USB_RX, true, 100);
        assert_ne!(got2 & EVT_USB_RX, 0);
        assert_eq!(eg.get() & EVT_USB_RX, 0);
        eg.clear_bits(EVT_TICK_10MS);
        assert_eq!(eg.get() & EVT_TICK_10MS, 0);
    }

    #[test]
    fn event_group_timeout_sem_bit() {
        let eg = EventGroup::new();
        let got = eg.wait_bits(EVT_BLE_RX, false, 20);
        assert_eq!(got & EVT_BLE_RX, 0);
    }

    #[test]
    fn passos_puros_de_tarefa() {
        assert_eq!(usb_task_step(None), None);
        let pkt = [0x55; CTAPHID_PACKET_SIZE];
        assert_eq!(
            usb_task_step(Some(pkt)),
            Some(FirmwareEvent::UsbPacket(pkt))
        );
        assert_eq!(button_task_step(false, false), None);
        assert_eq!(
            button_task_step(true, false),
            Some(FirmwareEvent::ButtonPress {
                boot: true,
                key: false
            })
        );
        let mut wd = Watchdog::new(300);
        let stop = AtomicBool::new(false);
        assert_eq!(housekeeping_step(7, &mut wd, &stop), TaskOutcome::Handled);
        assert_eq!(wd.last_feed(), 7);
        stop.store(true, Ordering::SeqCst);
        assert_eq!(housekeeping_step(8, &mut wd, &stop), TaskOutcome::Stop);
    }

    #[test]
    fn scheduler_usb_drena_e_para_no_stop() {
        let sched = FreeRtosScheduler::new(8);
        let left = Arc::new(AtomicUsize::new(2));
        let c = Arc::clone(&left);
        let h = sched.spawn_usb_task(move || {
            if c.fetch_sub(1, Ordering::SeqCst) > 0 {
                Some([0x01; CTAPHID_PACKET_SIZE])
            } else {
                // Trava até o stop sem queimar CPU.
                std::thread::sleep(Duration::from_millis(5));
                None
            }
        });
        // Aguarda drenar.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while sched.queue.len() < 2 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(sched.queue.len(), 2);
        assert_ne!(sched.events.get() & EVT_USB_RX, 0);
        sched.request_stop();
        let drained = h.join().expect("usb join");
        assert!(drained >= 2);
    }

    #[test]
    fn scheduler_button_gera_up() {
        let sched = FreeRtosScheduler::new(8);
        let n = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&n);
        let h = sched.spawn_button_task(move || c.fetch_add(1, Ordering::SeqCst) == 1, || false);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut seen = false;
        while std::time::Instant::now() < deadline {
            if let Some(FirmwareEvent::ButtonPress { boot: true, .. }) =
                sched.queue.receive(Some(50))
            {
                seen = true;
                break;
            }
        }
        assert!(seen, "UP de botão não chegou na fila");
        sched.request_stop();
        let presses = h.join().expect("button join");
        assert!(presses >= 1);
    }

    #[test]
    fn scheduler_housekeeping_emite_tick_e_watchdog() {
        let sched = FreeRtosScheduler::new(16);
        let h = sched.spawn_housekeeping_task();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut tick_seen = false;
        while std::time::Instant::now() < deadline {
            if let Some(FirmwareEvent::Tick10ms(_)) = sched.queue.receive(Some(50)) {
                tick_seen = true;
                break;
            }
        }
        assert!(tick_seen);
        sched.request_stop();
        let ticks = h.join().expect("housekeeping join");
        assert!(ticks >= 1);
    }

    #[test]
    fn demo_freertos_end_to_end() {
        for _ in 0..3 {
            let (drained, presses, ticks) = app_main_freertos_demo();
            assert_eq!(drained, 3);
            assert!(presses >= 1);
            assert!(ticks >= 1);
        }
    }

    #[test]
    fn task_delay_e_tick_nao_panican() {
        task_delay_ms(1);
        let _ = tick_count_ms();
    }

    #[test]
    fn request_stop_publica_desligamento_triplo() {
        let sched = FreeRtosScheduler::new(8);
        sched.request_stop();
        assert!(sched.stop.load(Ordering::SeqCst));
        assert_ne!(sched.events.get() & EVT_SHUTDOWN, 0);
        // Drena até achar Shutdown (fila estava vazia, então é o primeiro).
        assert_eq!(sched.queue.receive(None), Some(FirmwareEvent::Shutdown));
    }

    #[test]
    fn queue_depth_zero_clampa_para_um() {
        let q: FreeRtosQueue<u8> = FreeRtosQueue::new(0);
        assert_eq!(q.capacity(), 1);
        assert!(q.send(7));
        assert!(!q.send(8));
        assert_eq!(q.receive(None), Some(7));
    }

    #[test]
    fn request_stop_com_fila_cheia_preserva_shutdown() {
        let sched = FreeRtosScheduler::new(2);
        assert!(sched.queue.send(FirmwareEvent::Tick10ms(1)));
        assert!(sched.queue.send(FirmwareEvent::Tick10ms(2)));
        sched.request_stop();
        let mut seen_shutdown = false;
        while let Some(ev) = sched.queue.receive(None) {
            if ev == FirmwareEvent::Shutdown {
                seen_shutdown = true;
            }
        }
        assert!(seen_shutdown, "Shutdown perdido com fila cheia");
        assert!(sched.stop.load(Ordering::SeqCst));
        assert_ne!(sched.events.get() & EVT_SHUTDOWN, 0);
    }

    #[test]
    fn per_task_watchdog_host_noop_testavel() {
        let wdt = PerTaskWatchdog::subscribe_current_task();
        assert_eq!(wdt.feed_count(), 0);
        wdt.feed_current_task();
        wdt.feed_current_task();
        assert_eq!(wdt.feed_count(), 2);
    }

    #[test]
    fn bindings_host_nao_panican() {
        assert!(freertos_task_create(
            "usb_ctaphid",
            USB_TASK_STACK,
            USB_TASK_PRIO,
            Some(1)
        ));
        assert!(!freertos_task_create("x", 1024, 5, None));
        assert_eq!(stack_high_water_mark(), 4096);
        assert_eq!(task_count(), 3);
        freertos_task_delay_ms(1);
    }

    #[cfg(not(target_os = "espidf"))]
    #[test]
    fn core_id_host_negativo_e_boot_info_nao_panica() {
        assert_eq!(current_core_id(), -1);
        log_boot_info();
    }

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
            binding: &mut binding,
            storage: &mut storage,
            wallet: &mut wallet,
            key_mgr: &mut key_mgr,
            oath: &mut oath,
            fwlog: &mut fwlog,
            rescue: &mut rescue,
            pairing: &mut pairing,
            pin_uv_session: false,
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
            binding: &mut binding,
            storage: &mut storage,
            wallet: &mut wallet,
            key_mgr: &mut key_mgr,
            oath: &mut oath,
            fwlog: &mut fwlog,
            rescue: &mut rescue,
            pairing: &mut pairing,
            pin_uv_session: false,
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
    fn shutdown_triplo_bit_sozinho_para_as_tarefas() {
        // So o bit (sem flag): tarefas observam via stop_requested.
        let sched = FreeRtosScheduler::new(8);
        assert!(!sched.is_stop_requested());
        sched.events.set_bits(EVT_SHUTDOWN);
        assert!(sched.is_stop_requested());
        assert!(FreeRtosScheduler::stop_requested(
            &sched.stop,
            &sched.events
        ));
        // So a flag (sem bit): tambem conta como pedido.
        let sched2 = FreeRtosScheduler::new(8);
        sched2.stop.store(true, Ordering::SeqCst);
        assert!(sched2.is_stop_requested());
    }

    #[test]
    fn shutdown_triplo_tasks_saem_por_bit_ou_flag() {
        // Bit sozinho derruba tarefa USB ociosa.
        let sched = FreeRtosScheduler::new(8);
        let h = sched.spawn_usb_task(|| None);
        sched.events.set_bits(EVT_SHUTDOWN);
        let drained = h.join().expect("usb join");
        assert_eq!(drained, 0);
        // Flag sozinha tambem derruba (sem bit).
        let sched2 = FreeRtosScheduler::new(8);
        let h2 = sched2.spawn_button_task(|| false, || false);
        sched2.stop.store(true, Ordering::SeqCst);
        let presses = h2.join().expect("button join");
        assert_eq!(presses, 0);
    }

    #[test]
    fn drain_for_shutdown_encontra_shutdown_e_timeout_sem_busy_loop() {
        let sched = FreeRtosScheduler::new(4);
        sched.request_stop();
        let t0 = std::time::Instant::now();
        assert!(sched.drain_for_shutdown(SHUTDOWN_DRAIN_DEFAULT_MS));
        assert!(t0.elapsed() < Duration::from_secs(2));
        // Sem Shutdown: timeout limitado, sem spin.
        let sched2 = FreeRtosScheduler::new(4);
        let t1 = std::time::Instant::now();
        assert!(!sched2.drain_for_shutdown(50));
        let el = t1.elapsed();
        assert!(el >= Duration::from_millis(30), "dreno voltou cedo: {el:?}");
        assert!(el < Duration::from_secs(2), "dreno demorou (spin?): {el:?}");
    }

    #[test]
    fn fila_cheia_fail_closed_sem_bypass() {
        // Cheia = false (Dropped), sem panic; nada e roteado no descarte.
        let sched = FreeRtosScheduler::new(1);
        assert!(sched.queue.send(FirmwareEvent::Tick10ms(1)));
        let outcome = if sched.queue.send(FirmwareEvent::Tick10ms(2)) {
            TaskOutcome::Handled
        } else {
            TaskOutcome::Dropped
        };
        assert_eq!(outcome, TaskOutcome::Dropped);
        // O Shutdown triplo nunca se perde mesmo com fila cheia.
        sched.request_stop();
        assert!(sched.is_stop_requested());
        assert!(sched.drain_for_shutdown(SHUTDOWN_DRAIN_DEFAULT_MS));
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
    fn usb_poll_e_shutdown_poll_cedem_sem_busy_loop() {
        // Constantes de cessao: idle sempre via vTaskDelay/sleep, nunca spin.
        const _: () = assert!(USB_POLL_MS >= 1);
        const _: () = assert!(SHUTDOWN_POLL_MS >= 1);
        task_delay_ms(USB_POLL_MS.min(2));
    }
}
