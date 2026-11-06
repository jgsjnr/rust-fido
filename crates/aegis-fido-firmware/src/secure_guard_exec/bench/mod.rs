//! MODO BANCADA (test-mode only): sessao estendida sem relock por ociosidade.
//!
//! Procedimento de bancada (firmware `test-mode`, default OFF):
//! 1. `TEST_BENCH_ON` (op explicita de bancada, serial/UART) antes do unlock;
//! 2. unlock normal (UP + PIN seguem exigidos; gates inalterados);
//! 3. a sessao passa a valer 24 h sem relock por ociosidade;
//! 4. `TEST_BENCH_OFF` restaura a policy salva e o idle padrao volta.
//!
//! Garantias:
//! - NUNCA em producao: comportamento so atras de `#[cfg(feature =
//!   "test-mode")]`; release expoe no-ops (`false`/`None`, linha ignorada).
//!   `prod-strict` + `test-mode` nem compila (`prod_strict_guard.rs`).
//! - Default off: flag global comeca desligado; so a op explicita liga.
//! - Disconnect lock continua valendo: `transport_lock` e
//!   `on_transport_disconnect` nao sao tocados (travam com bancada ativa).
//!   Quiescencia WiFi (`TransportMonitor::poll`) e bench-aware: com a
//!   bancada ativa o silencio tolerado estende para 24 h
//!   (`poll_with_bench`); bordas duro ativo-para-inativo travam de
//!   imediato com ou sem bancada.
//! - NVS/keys intactos, sem wipe/eFuse: so policy em RAM, sem
//!   `save_secure_guard_record`; o desligar restaura os valores salvos.
//! - Auditoria: liga/desliga gravam `EV_BENCH` no `FwLog` (arg `0x01` ON /
//!   `0x00` OFF) e `log::info!` com a marca `BENCH`.
//!
//! CI-GREP: TEST-HOOK (test-mode only; absent in release).

pub mod dispatch;
pub mod policy;
#[cfg(test)]
mod tests;

pub use dispatch::dispatch_serial_bench_line;
pub use policy::{
    apply_bench_policy_if_active, bench_disable, bench_enable, is_bench_active,
    BENCH_FWLOG_ARG_OFF, BENCH_FWLOG_ARG_ON, BENCH_INACTIVITY_TIMEOUT_MS,
    BENCH_SESSION_DURATION_MS,
};
#[cfg(feature = "test-mode")]
pub use policy::{TEST_BENCH_OFF_CMD, TEST_BENCH_ON_CMD};
