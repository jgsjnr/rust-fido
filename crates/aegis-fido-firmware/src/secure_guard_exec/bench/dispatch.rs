//! Dispatch serial da bancada (test-mode only): `TEST_BENCH_ON/OFF`.
//!
//! Retorna o ack na batida exata (`BENCH` marcado, `source=software`);
//! `None` caso contrario. Sem `test-mode` sempre `None` (linha ignorada).

/// Roteia `TEST_BENCH_ON` / `TEST_BENCH_OFF` (op explicita de bancada).
#[cfg(feature = "test-mode")]
pub fn dispatch_serial_bench_line(
    line: &str,
    engine: &mut aegis_fido_core::secure_guard::SecureGuardEngine,
    fw_log: &mut crate::fw_log::FwLog,
    now_ms: u64,
) -> Option<std::string::String> {
    let trimmed = line.trim();
    if trimmed == super::policy::TEST_BENCH_ON_CMD {
        let _ = super::policy::bench_enable(engine, fw_log, now_ms);
        Some(std::string::String::from(
            "bench_on BENCH idle=extended source=software\n",
        ))
    } else if trimmed == super::policy::TEST_BENCH_OFF_CMD {
        if super::policy::bench_disable(engine, fw_log, now_ms) {
            Some(std::string::String::from(
                "bench_off BENCH source=software\n",
            ))
        } else {
            Some(std::string::String::from(
                "bench_off BENCH already_off source=software\n",
            ))
        }
    } else {
        None
    }
}

/// Release: `TEST_BENCH_*` nao existem (linhas desconhecidas, sem bancada).
#[cfg(not(feature = "test-mode"))]
pub fn dispatch_serial_bench_line(
    _line: &str,
    _engine: &mut aegis_fido_core::secure_guard::SecureGuardEngine,
    _fw_log: &mut crate::fw_log::FwLog,
    _now_ms: u64,
) -> Option<std::string::String> {
    None
}
