//! FreeRTOS scheduler em Rust: tasks, fila e event-group (T12-parte-A).
//!
//! Extraido de `freertos.rs` sem mudanca de comportamento (auditoria
//! riscos 2+3). Contem a infra do dispatcher: `TaskConfig`,
//! `FreeRtosQueue`, `EventGroup`, passos puros das tarefas, TWDT por task
//! (`PerTaskWatchdog`), shutdown triplo e `FreeRtosScheduler` (variantes
//! host + nativas `target_os = "espidf"` e demo). Sem dependencia da
//! TrustFacade (T8): nao importa `crate::binding` e nao fabrica sensor;
//! ausente = fail-closed. Roteamento CTAPHID vive em
//! `crate::freertos_route`.

use crate::watchdog::Watchdog;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
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
/// Tarefa dedicada do Secure Guard (autoridade local e sessões).
pub const SECURE_GUARD_TASK_PRIO: u8 = 3;
/// Tarefa de housekeeping/watchdog.
pub const HOUSEKEEPING_TASK_PRIO: u8 = 2;

/// Stacks por tarefa (bytes; ESP32-S3 tem 512 KiB SRAM).
pub const USB_TASK_STACK: usize = 32 * 1024;
/// Stack da tarefa de botão/UI.
pub const UI_TASK_STACK: usize = 32 * 1024;
/// Stack da tarefa Secure Guard (32 KiB para acomodar PBKDF2 sem risco de overflow).
pub const SECURE_GUARD_TASK_STACK: usize = 32 * 1024;
/// Stack da tarefa de housekeeping.
pub const HOUSEKEEPING_TASK_STACK: usize = 32 * 1024;

/// Identificadores canônicos das tarefas gerenciadas do FreeRTOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskId {
    UsbCtapHid,
    UiButton,
    Housekeeping,
    SecureGuard,
}

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

    /// Config padrão da tarefa Secure Guard.
    pub fn secure_guard() -> Self {
        Self {
            name: "secure_guard",
            stack_size: SECURE_GUARD_TASK_STACK,
            priority: SECURE_GUARD_TASK_PRIO,
            pinned_core: None,
        }
    }
}

/// Handle nativo (mora em freertos_native; so no device).
#[cfg(target_os = "espidf")]
pub use super::freertos_native::NativeTaskHandle;
/// Fila e event-group (moram em freertos_queue; re-export p/ paridade).
pub use super::freertos_queue::{EventGroup, FreeRtosQueue};

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

/// Passo puro da tarefa de botão: QUALQUER borda gera `ButtonPress`
/// (sobe e desce; o nivel vai no evento). Nivel estavel nao gera nada.
///
/// Borda explicita em vez de nivel + timeout de parede: com ticks em
/// rajada o timeout cortava o Arming antes dos 5s e a janela nunca
/// abria no hold fisico. Soltura e evento proprio (fail-closed sem
/// relogio): sem borda nao ha mudanca de estado.
pub fn button_task_step(
    prev: &mut (bool, bool),
    boot_pressed: bool,
    key_pressed: bool,
) -> Option<FirmwareEvent> {
    let cur = (boot_pressed, key_pressed);
    if cur == *prev {
        return None;
    }
    *prev = cur;
    Some(FirmwareEvent::ButtonPress {
        boot: boot_pressed,
        key: key_pressed,
    })
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
pub(crate) const FREERTOS_MAX_TASK_NAME_LEN: usize = 16;
/// Núcleo sem afinidade fixa (`tskNO_AFFINITY = 0x7FFFFFFF` no ESP-IDF).
#[cfg(target_os = "espidf")]
pub(crate) const FREERTOS_NO_AFFINITY: i32 = 0x7FFF_FFFF;
/// Retorno de sucesso das criações FreeRTOS (`pdPASS = 1`).
#[cfg(target_os = "espidf")]
pub(crate) const FREERTOS_PD_PASS: i32 = 1;
/// Byte por palavra de stack FreeRTOS no ESP32 (32 bits).
#[cfg(target_os = "espidf")]
pub(crate) const FREERTOS_STACK_WORD_BYTES: usize = 4;

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
                // Borda explicita (sobe e desce); sem repeticao em hold.
                let mut prev_levels = (false, false);
                while !Self::stop_requested(&stop, &events) {
                    twdt.feed_current_task();
                    let boot = poll_boot();
                    let key = poll_key();
                    if let Some(ev) = button_task_step(&mut prev_levels, boot, key) {
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

    /// Tarefa periódica dedicada do Secure Guard: executa tick a cada 100 ms com watchdog.
    pub fn spawn_secure_guard_task(
        &self,
        mut on_tick: impl FnMut(u64) + Send + 'static,
    ) -> std::thread::JoinHandle<u64> {
        let events = Arc::clone(&self.events);
        let stop = Arc::clone(&self.stop);
        std::thread::Builder::new()
            .name("secure_guard".into())
            .stack_size(SECURE_GUARD_TASK_STACK)
            .spawn(move || {
                let twdt = PerTaskWatchdog::subscribe_current_task();
                let mut tick: u64 = 0;
                while !Self::stop_requested(&stop, &events) {
                    twdt.feed_current_task();
                    on_tick(tick.saturating_mul(100));
                    tick = tick.saturating_add(1);
                    task_delay_ms(100);
                }
                tick
            })
            .expect("spawn secure_guard")
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
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while (remaining.load(Ordering::SeqCst) > 0 || boot_count.load(Ordering::SeqCst) <= 2)
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    // Sincroniza com o primeiro tick do housekeeping antes do stop:
    // sem isso, `request_stop` podia vencer a corrida com a primeira
    // iteração da tarefa e `ticks` voltava 0 (tick só incrementa
    // após o corpo do loop). Aguarda o bit EVT_TICK_10MS (não
    // destrutivo; não consome a fila nem altera gates de segurança).
    let tick_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while sched.events.get() & EVT_TICK_10MS == 0
        && std::time::Instant::now() < tick_deadline
    {
        std::thread::sleep(Duration::from_millis(5));
    }
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
        let sg = TaskConfig::secure_guard();
        assert_eq!(usb.priority, USB_TASK_PRIO);
        assert_eq!(btn.priority, UI_TASK_PRIO);
        assert_eq!(hk.priority, HOUSEKEEPING_TASK_PRIO);
        assert_eq!(sg.priority, SECURE_GUARD_TASK_PRIO);
        assert!(usb.stack_size >= 2048);
        assert_eq!(sg.stack_size, SECURE_GUARD_TASK_STACK);
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
    fn passos_puros_de_tarefa() {
        assert_eq!(usb_task_step(None), None);
        let pkt = [0x55; CTAPHID_PACKET_SIZE];
        assert_eq!(
            usb_task_step(Some(pkt)),
            Some(FirmwareEvent::UsbPacket(pkt))
        );
        // Borda: nivel estavel nao gera evento; soltura e evento proprio.
        let mut prev = (false, false);
        assert_eq!(button_task_step(&mut prev, false, false), None);
        assert_eq!(
            button_task_step(&mut prev, true, false),
            Some(FirmwareEvent::ButtonPress {
                boot: true,
                key: false
            })
        );
        assert_eq!(button_task_step(&mut prev, true, false), None);
        assert_eq!(
            button_task_step(&mut prev, false, false),
            Some(FirmwareEvent::ButtonPress {
                boot: false,
                key: false
            })
        );
        assert_eq!(
            button_task_step(&mut prev, false, true),
            Some(FirmwareEvent::ButtonPress {
                boot: false,
                key: true
            })
        );
        assert_eq!(button_task_step(&mut prev, false, true), None);
        // Borda combinada tambem gera evento (nivel atual embutido).
        assert_eq!(
            button_task_step(&mut prev, true, true),
            Some(FirmwareEvent::ButtonPress {
                boot: true,
                key: true
            })
        );
        assert_eq!(button_task_step(&mut prev, true, true), None);
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
    fn usb_poll_e_shutdown_poll_cedem_sem_busy_loop() {
        // Constantes de cessao: idle sempre via vTaskDelay/sleep, nunca spin.
        const _: () = assert!(USB_POLL_MS >= 1);
        const _: () = assert!(SHUTDOWN_POLL_MS >= 1);
        task_delay_ms(USB_POLL_MS.min(2));
    }
}
