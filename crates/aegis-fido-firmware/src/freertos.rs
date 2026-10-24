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

//! Re-export apos split (auditoria riscos 2+3): sched + route sem
//! mudanca de comportamento; caminhos `crate::freertos::*` preservados.
pub use crate::freertos_route::*;
pub use crate::freertos_sched::*;
