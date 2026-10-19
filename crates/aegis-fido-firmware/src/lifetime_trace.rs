//! Wave7 — lifetime debug terminal (monitor) + `test-mode` serial diagnostics.
//!
//! - [`ltrace!`] traces one lifecycle event per line: with the
//!   `debug-terminal` feature it counts (via `aegis-fido-core::lifetime`, the
//!   canonical counters) and prints `[LT][<category>] <event> detail=<detail>`
//!   through the same allocation-free [`crate::watchdog::StaticBuf`] path as
//!   `kprintln!`; without the feature it compiles to nothing (zero-cost release).
//! - Detail is metadata only (slot id, OATH label, retries left, transport
//!   name, monotonic clock) — NEVER a secret, key, PIN or code. Details are
//!   printed, never stored; counters hold only counts (see `write_dump`).
//! - With the `test-mode` feature (default OFF), [`dispatch_test_command`]
//!   answers the `TEST_LIFETIME_DUMP` serial line with counters/states and no
//!   secrets; without the feature the command does not exist.
//! - `no_std` compatible for counting/printing; the `test-mode` dump uses
//!   `alloc::string::String` (diagnostic path only, never the USB hot path).

extern crate alloc;

pub use aegis_fido_core::lifetime::{
    record, snapshot, write_dump, LifetimeCategory, LifetimeEvent, LifetimeSnapshot,
};

/// Emits one monitor line (only exists with `debug-terminal`).
#[cfg(feature = "debug-terminal")]
pub fn emit(category: &str, event: &str, detail: &dyn core::fmt::Display) {
    use core::fmt::Write as _;
    let mut raw = [0u8; 160];
    let mut w = crate::watchdog::StaticBuf::new(&mut raw);
    let _ = write!(w, "[LT][{}] {} detail={}", category, event, detail);
    let s = w.as_str();
    #[cfg(target_os = "espidf")]
    unsafe {
        for b in s.as_bytes() {
            esp_idf_sys::esp_rom_printf(b"%c\0".as_ptr() as *const _, *b as core::ffi::c_int);
        }
        esp_idf_sys::esp_rom_printf(b"\r\n\0".as_ptr() as *const _);
    }
    #[cfg(not(target_os = "espidf"))]
    std::println!("{}", s);
}

/// Lifetime trace: count + monitor line (one line per event at call sites).
///
/// Detail expressions must be side-effect free metadata (ids/labels/counters).
#[cfg(feature = "debug-terminal")]
#[macro_export]
macro_rules! ltrace {
    ($cat:expr, $evt:expr, $detail:expr) => {{
        $crate::lifetime_trace::record($cat, $evt);
        $crate::lifetime_trace::emit($cat.as_str(), $evt.as_str(), &$detail);
    }};
}

/// [`ltrace!`] without `debug-terminal`: compiled out, zero cost.
#[cfg(not(feature = "debug-terminal"))]
#[macro_export]
macro_rules! ltrace {
    ($($t:tt)*) => {{}};
}

/// Serial diagnostic command (only exists with `test-mode`).
#[cfg(feature = "test-mode")]
pub const TEST_LIFETIME_DUMP_CMD: &str = "TEST_LIFETIME_DUMP";

/// Builds the `TEST_LIFETIME_DUMP` answer: counters plus caller `extra_states`.
///
/// `extra_states` lines are echoed verbatim as `lt.state <line>`; the caller
/// contract is metadata only (uptime, latch flags, pairing/AP labels) — never
/// secrets, keys, PINs or codes.
#[cfg(feature = "test-mode")]
pub fn test_lifetime_dump(extra_states: &str) -> alloc::string::String {
    use alloc::string::String;
    use core::fmt::Write as _;
    let snap = snapshot();
    let mut out = String::from("lt_dump v=1\n");
    let _ = write_dump(&snap, &mut out);
    for line in extra_states.lines() {
        let clean = line.trim();
        if !clean.is_empty() {
            out.push_str("lt.state ");
            out.push_str(clean);
            out.push('\n');
        }
    }
    out.push_str("lt_end\n");
    out
}

/// Dispatches one serial diagnostic line.
///
/// Returns `Some(dump)` only for the exact `TEST_LIFETIME_DUMP` line
/// (surrounding whitespace/CRLF tolerated); anything else returns `None`.
#[cfg(feature = "test-mode")]
pub fn dispatch_test_command(
    line: &str,
    extra_states: &str,
) -> Option<alloc::string::String> {
    if line.trim() == TEST_LIFETIME_DUMP_CMD {
        Some(test_lifetime_dump(extra_states))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reexported_labels_match_core() {
        assert_eq!(LifetimeCategory::Transport.as_str(), "transport");
        assert_eq!(LifetimeEvent::TpClose.as_str(), "close");
    }

    #[test]
    fn ltrace_macro_compiles_in_both_modes() {
        crate::ltrace!(LifetimeCategory::Pairing, LifetimeEvent::PairingArming, 6000u64);
        crate::ltrace!(LifetimeCategory::Pin, LifetimeEvent::PinRetry, 7u8);
        crate::ltrace!(LifetimeCategory::Transport, LifetimeEvent::TpOpen, "wifi");
        crate::ltrace!(LifetimeCategory::Oath, LifetimeEvent::OathPut, "GitHub:alice");
    }

    #[cfg(feature = "debug-terminal")]
    #[test]
    fn emit_never_panics_on_metadata() {
        emit("pin", "retry", &7u8);
        emit("oath", "put", &"GitHub:alice");
        emit("transport", "erro", &"ble");
    }

    #[cfg(feature = "test-mode")]
    #[test]
    fn dispatch_answers_only_the_dump_command() {
        assert!(dispatch_test_command("NOPE", "").is_none());
        assert!(dispatch_test_command("TEST_LIFETIME_DUMP_EXTRA", "").is_none());
        assert!(dispatch_test_command("", "").is_none());
        let dump = dispatch_test_command(TEST_LIFETIME_DUMP_CMD, "").expect("dump");
        assert!(dump.starts_with("lt_dump v=1\n"));
        assert!(dump.ends_with("lt_end\n"));
        assert!(dump.contains("lt.pin.retry="));
    }

    #[cfg(feature = "test-mode")]
    #[test]
    fn dispatch_tolerates_crlf_and_echoes_states() {
        let dump =
            dispatch_test_command("  TEST_LIFETIME_DUMP\r\n", "uptime_s=42\nup_latched=false")
                .expect("dump");
        assert!(dump.contains("lt.state uptime_s=42"));
        assert!(dump.contains("lt.state up_latched=false"));
    }

    #[cfg(feature = "test-mode")]
    #[test]
    fn dump_reflects_counters_without_secrets() {
        let before = snapshot();
        record(LifetimeCategory::KeySlot, LifetimeEvent::KeyCreate);
        let dump = test_lifetime_dump("");
        let snap = snapshot();
        assert_eq!(snap.key_create, before.key_create.saturating_add(1));
        assert!(dump.contains("lt.key_slot.create="));
        // Only counts travel: labels/values passed as details are never stored.
        assert!(!dump.contains("GitHub"));
        assert!(!dump.contains("SECRET"));
    }
}
