//! FreeRTOS nativo ESP-IDF em Rust (Fase 2: extraido de `freertos_sched`).
//!
//! Movido verbatim de `freertos_sched.rs` (bloco `cfg(target_os = "espidf")`):
//! `NativeTaskHandle`, `spawn_native_task`, contextos FFI, trampolins
//! `*_native_entry` e os `spawn_*_native` do `FreeRtosScheduler`.
//! So existe no device; `freertos_sched` re-exporta o handle.

use super::freertos_queue::{EventGroup, FreeRtosQueue};
use super::freertos_sched::{
    button_task_step, current_core_id, housekeeping_step, packet_task_step, task_delay_ms,
    usb_task_step, FirmwareEvent, FreeRtosScheduler, PacketOrigin, PerTaskWatchdog, TaskConfig,
    TaskOutcome, CTAPHID_PACKET_SIZE, EVT_BUTTON_UP, EVT_TICK_10MS, EVT_USB_RX,
    FREERTOS_MAX_TASK_NAME_LEN, FREERTOS_NO_AFFINITY, FREERTOS_PD_PASS, FREERTOS_STACK_WORD_BYTES,
    TICK_MS,
};
use crate::watchdog::Watchdog;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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
