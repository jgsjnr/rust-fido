//! Serial diagnostic text cluster (D5 split from `serial_ctaphid`).
//!
//! `dispatch_serial_text_line` (dump only, metadata only) +
//! `dispatch_serial_pairing_line` (test-mode abre a janela de 60 s via
//! software; release responde `None`). Owner reexporta p/ compat.
//!
//! Contract (R15/R16): move-only; release nunca executa (gate secao 4).
extern crate alloc;
use alloc::string::String;

/// Dispatches one serial diagnostic text line (dump only, metadata only).
///
/// Returns `Some(dump)` solely for the exact `TEST_LIFETIME_DUMP` line when
/// built with `test-mode`; otherwise (or without the feature) `None`.
pub fn dispatch_serial_text_line(line: &str, extra_states: &str) -> Option<String> {
    #[cfg(feature = "test-mode")]
    {
        crate::lifetime_trace::dispatch_test_command(line, extra_states)
    }
    #[cfg(not(feature = "test-mode"))]
    {
        let _ = (line, extra_states);
        None
    }
}

/// Dispatches `TEST_PAIRING_OPEN` / `TEST_PAIRING_CLOSE` (test-mode only).
///
/// Abre a MESMA janela de 60s do hold 5s via
/// [`crate::pairing::PairingManager::open_test_window`]: software abre a
/// janela, NAO confirma presenca (gates UP/bonding seguem exigidos).
/// `TEST_PAIRING_CLOSE` fecha via `close_test_window` (vira `Locked`,
/// mesmo estado do timeout natural; determinismo entre sessões sem reset).
/// Retorna o ack na batida exata, `None` caso contrario; sem `test-mode`
/// os comandos nao existem (sempre `None`, comandos desconhecidos).
#[cfg(feature = "test-mode")]
pub fn dispatch_serial_pairing_line(
    line: &str,
    pairing: &mut crate::pairing::PairingManager,
    now_ms: u64,
) -> Option<String> {
    use crate::pairing::{
        TEST_PAIRING_CLOSE_CMD, TEST_PAIRING_OPEN_300_CMD, TEST_PAIRING_OPEN_300_SECS,
        TEST_PAIRING_OPEN_CMD,
    };
    if line.trim() == TEST_PAIRING_OPEN_CMD {
        pairing.open_test_window(now_ms);
        Some(String::from("pairing_open window_s=60 source=software\n"))
    } else if line.trim() == TEST_PAIRING_OPEN_300_CMD {
        pairing.open_test_window_secs(now_ms, TEST_PAIRING_OPEN_300_SECS);
        Some(String::from("pairing_open window_s=300 source=software\n"))
    } else if line.trim() == TEST_PAIRING_CLOSE_CMD {
        pairing.close_test_window();
        Some(String::from("pairing_closed source=software\n"))
    } else {
        None
    }
}

/// Release: `TEST_PAIRING_OPEN` / `TEST_PAIRING_CLOSE` nao existem (comandos
/// desconhecidos, sem janela).
#[cfg(not(feature = "test-mode"))]
pub fn dispatch_serial_pairing_line(
    _line: &str,
    _pairing: &mut crate::pairing::PairingManager,
    _now_ms: u64,
) -> Option<String> {
    None
}
