//! Wave7 — lifetime debug counters (canonical, shared by core + firmware).
//!
//! - Counts lifecycle events per (category, event); details (ids/labels/counters)
//!   are NEVER stored, only counted — secrets/keys/PINs/codes can never leak
//!   through [`snapshot`] or [`write_dump`].
//! - [`ltrace!`] records one event per invocation when the `debug-terminal`
//!   feature is on; without it the macro expands to nothing (zero-cost release).
//! - Firmware (`aegis-fido-firmware/src/lifetime_trace.rs`) re-exports this
//!   module and adds the monitor printing + `test-mode` serial dump.
//! - `no_std` compatible: atomics only, no alloc, no I/O.

use core::sync::atomic::{AtomicU32, Ordering};

/// Lifetime categories traced by [`ltrace!`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifetimeCategory {
    /// On-device key slots (GEN/USE/DELETE/WIPE).
    KeySlot,
    /// OATH credentials (PUT/CODE/DELETE).
    Oath,
    /// Pairing journey (ARMING/PAIRED/TIMEOUT).
    Pairing,
    /// PIN retries / blocked transitions (counts only, never the PIN value).
    Pin,
    /// Transports BLE/WiFi/USB (OPEN/CLOSE/ERROR; transport name is the detail).
    Transport,
}

impl LifetimeCategory {
    /// Stable wire label used in dumps and monitor lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeySlot => "key_slot",
            Self::Oath => "oath",
            Self::Pairing => "pairing",
            Self::Pin => "pin",
            Self::Transport => "transport",
        }
    }
}

/// Lifetime events traced by [`ltrace!`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifetimeEvent {
    /// Key slot created (detail: slot id).
    KeyCreate,
    /// Key slot used to sign (detail: slot id).
    KeyUse,
    /// Key slot deleted (detail: slot id).
    KeyDelete,
    /// Key material wiped (detail: wiped slot count).
    KeyWipe,
    /// OATH credential stored (detail: label only, never the secret).
    OathPut,
    /// OATH code derived (detail: label only, never the code/secret).
    OathCode,
    /// OATH credential deleted (detail: label only).
    OathDelete,
    /// Pairing hold started (detail: monotonic clock ms).
    PairingArming,
    /// Pairing completed with UP+bonding (detail: monotonic clock ms).
    PairingPaired,
    /// Pairing window expired (detail: monotonic clock ms).
    PairingTimeout,
    /// Wrong PIN attempt (detail: retries left, never the PIN value).
    PinRetry,
    /// PIN blocked after last retry (detail: 0).
    PinBlocked,
    /// Transport transaction/session opened (detail: ble/wifi/usb).
    TpOpen,
    /// Transport transaction/session closed (detail: ble/wifi/usb).
    TpClose,
    /// Transport error (detail: ble/wifi/usb).
    TpError,
}

impl LifetimeEvent {
    /// Stable wire label used in dumps and monitor lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeyCreate => "create",
            Self::KeyUse => "use",
            Self::KeyDelete => "delete",
            Self::KeyWipe => "wipe",
            Self::OathPut => "put",
            Self::OathCode => "code",
            Self::OathDelete => "delete",
            Self::PairingArming => "arming",
            Self::PairingPaired => "pairing",
            Self::PairingTimeout => "timeout",
            Self::PinRetry => "retry",
            Self::PinBlocked => "blocked",
            Self::TpOpen => "open",
            Self::TpClose => "close",
            Self::TpError => "erro",
        }
    }
}

/// Global lifetime counters (atomics: lock-free, thread-safe, `no_std`).
pub struct LifetimeCounters {
    key_create: AtomicU32,
    key_use: AtomicU32,
    key_delete: AtomicU32,
    key_wipe: AtomicU32,
    oath_put: AtomicU32,
    oath_code: AtomicU32,
    oath_delete: AtomicU32,
    pairing_arming: AtomicU32,
    pairing_paired: AtomicU32,
    pairing_timeout: AtomicU32,
    pin_retry: AtomicU32,
    pin_blocked: AtomicU32,
    tp_open: AtomicU32,
    tp_close: AtomicU32,
    tp_error: AtomicU32,
    /// Wiring bugs (valid category + unexpected event pairing).
    unknown: AtomicU32,
}

impl LifetimeCounters {
    const fn new() -> Self {
        Self {
            key_create: AtomicU32::new(0),
            key_use: AtomicU32::new(0),
            key_delete: AtomicU32::new(0),
            key_wipe: AtomicU32::new(0),
            oath_put: AtomicU32::new(0),
            oath_code: AtomicU32::new(0),
            oath_delete: AtomicU32::new(0),
            pairing_arming: AtomicU32::new(0),
            pairing_paired: AtomicU32::new(0),
            pairing_timeout: AtomicU32::new(0),
            pin_retry: AtomicU32::new(0),
            pin_blocked: AtomicU32::new(0),
            tp_open: AtomicU32::new(0),
            tp_close: AtomicU32::new(0),
            tp_error: AtomicU32::new(0),
            unknown: AtomicU32::new(0),
        }
    }

    fn inc(&self, slot: &AtomicU32) {
        let _ = slot.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_add(1))
        });
    }

    fn record(&self, category: LifetimeCategory, event: LifetimeEvent) {
        match (category, event) {
            (LifetimeCategory::KeySlot, LifetimeEvent::KeyCreate) => self.inc(&self.key_create),
            (LifetimeCategory::KeySlot, LifetimeEvent::KeyUse) => self.inc(&self.key_use),
            (LifetimeCategory::KeySlot, LifetimeEvent::KeyDelete) => self.inc(&self.key_delete),
            (LifetimeCategory::KeySlot, LifetimeEvent::KeyWipe) => self.inc(&self.key_wipe),
            (LifetimeCategory::Oath, LifetimeEvent::OathPut) => self.inc(&self.oath_put),
            (LifetimeCategory::Oath, LifetimeEvent::OathCode) => self.inc(&self.oath_code),
            (LifetimeCategory::Oath, LifetimeEvent::OathDelete) => self.inc(&self.oath_delete),
            (LifetimeCategory::Pairing, LifetimeEvent::PairingArming) => {
                self.inc(&self.pairing_arming)
            }
            (LifetimeCategory::Pairing, LifetimeEvent::PairingPaired) => {
                self.inc(&self.pairing_paired)
            }
            (LifetimeCategory::Pairing, LifetimeEvent::PairingTimeout) => {
                self.inc(&self.pairing_timeout)
            }
            (LifetimeCategory::Pin, LifetimeEvent::PinRetry) => self.inc(&self.pin_retry),
            (LifetimeCategory::Pin, LifetimeEvent::PinBlocked) => self.inc(&self.pin_blocked),
            (LifetimeCategory::Transport, LifetimeEvent::TpOpen) => self.inc(&self.tp_open),
            (LifetimeCategory::Transport, LifetimeEvent::TpClose) => self.inc(&self.tp_close),
            (LifetimeCategory::Transport, LifetimeEvent::TpError) => self.inc(&self.tp_error),
            _ => self.inc(&self.unknown),
        }
    }

    fn snapshot(&self) -> LifetimeSnapshot {
        let load = |v: &AtomicU32| v.load(Ordering::Relaxed);
        LifetimeSnapshot {
            key_create: load(&self.key_create),
            key_use: load(&self.key_use),
            key_delete: load(&self.key_delete),
            key_wipe: load(&self.key_wipe),
            oath_put: load(&self.oath_put),
            oath_code: load(&self.oath_code),
            oath_delete: load(&self.oath_delete),
            pairing_arming: load(&self.pairing_arming),
            pairing_paired: load(&self.pairing_paired),
            pairing_timeout: load(&self.pairing_timeout),
            pin_retry: load(&self.pin_retry),
            pin_blocked: load(&self.pin_blocked),
            tp_open: load(&self.tp_open),
            tp_close: load(&self.tp_close),
            tp_error: load(&self.tp_error),
            unknown: load(&self.unknown),
        }
    }
}

static GLOBAL: LifetimeCounters = LifetimeCounters::new();

/// Records one lifetime event (saturating, monotonic).
pub fn record(category: LifetimeCategory, event: LifetimeEvent) {
    GLOBAL.record(category, event);
}

/// Copies the current counters (plain data, no secrets — only counts).
pub fn snapshot() -> LifetimeSnapshot {
    GLOBAL.snapshot()
}

/// Plain-data copy of [`LifetimeCounters`] (only counts, `Copy`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LifetimeSnapshot {
    /// `key_slot.create` count.
    pub key_create: u32,
    /// `key_slot.use` count.
    pub key_use: u32,
    /// `key_slot.delete` count.
    pub key_delete: u32,
    /// `key_slot.wipe` count.
    pub key_wipe: u32,
    /// `oath.put` count.
    pub oath_put: u32,
    /// `oath.code` count.
    pub oath_code: u32,
    /// `oath.delete` count.
    pub oath_delete: u32,
    /// `pairing.arming` count.
    pub pairing_arming: u32,
    /// `pairing.pairing` count.
    pub pairing_paired: u32,
    /// `pairing.timeout` count.
    pub pairing_timeout: u32,
    /// `pin.retry` count.
    pub pin_retry: u32,
    /// `pin.blocked` count.
    pub pin_blocked: u32,
    /// `transport.open` count.
    pub tp_open: u32,
    /// `transport.close` count.
    pub tp_close: u32,
    /// `transport.erro` count.
    pub tp_error: u32,
    /// Unexpected (category, event) pairings (wiring bugs).
    pub unknown: u32,
}

/// Writes the dump body (`lt.<category>.<event>=<count>` per line, no secrets).
pub fn write_dump(
    snapshot: &LifetimeSnapshot,
    out: &mut dyn core::fmt::Write,
) -> core::fmt::Result {
    let rows: [(&str, u32); 16] = [
        ("lt.key_slot.create", snapshot.key_create),
        ("lt.key_slot.use", snapshot.key_use),
        ("lt.key_slot.delete", snapshot.key_delete),
        ("lt.key_slot.wipe", snapshot.key_wipe),
        ("lt.oath.put", snapshot.oath_put),
        ("lt.oath.code", snapshot.oath_code),
        ("lt.oath.delete", snapshot.oath_delete),
        ("lt.pairing.arming", snapshot.pairing_arming),
        ("lt.pairing.pairing", snapshot.pairing_paired),
        ("lt.pairing.timeout", snapshot.pairing_timeout),
        ("lt.pin.retry", snapshot.pin_retry),
        ("lt.pin.blocked", snapshot.pin_blocked),
        ("lt.transport.open", snapshot.tp_open),
        ("lt.transport.close", snapshot.tp_close),
        ("lt.transport.erro", snapshot.tp_error),
        ("lt.unknown", snapshot.unknown),
    ];
    for (name, count) in rows {
        out.write_str(name)?;
        out.write_str("=")?;
        let mut digits = [0u8; 10];
        let mut len = 0usize;
        let mut rest = count;
        loop {
            digits[len] = b'0' + (rest % 10) as u8;
            len += 1;
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        for i in (0..len).rev() {
            let b = [digits[i]];
            out.write_str(core::str::from_utf8(&b).unwrap_or("?"))?;
        }
        out.write_str("\n")?;
    }
    Ok(())
}

/// Lifetime trace: one event per invocation.
///
/// Detail is metadata only (slot id, label, remaining retries, transport name,
/// monotonic clock) — NEVER a secret, key, PIN or code. Details are not stored;
/// only the per-(category, event) counter moves. With `debug-terminal` off this
/// expands to nothing (zero-cost release).
#[cfg(feature = "debug-terminal")]
#[macro_export]
macro_rules! ltrace {
    ($cat:expr, $evt:expr, $detail:expr) => {{
        $crate::lifetime::record($cat, $evt);
        let _ = &$detail;
    }};
}

/// [`ltrace!`] without `debug-terminal`: compiled out, zero cost.
#[cfg(not(feature = "debug-terminal"))]
#[macro_export]
macro_rules! ltrace {
    ($($t:tt)*) => {{}};
}

#[cfg(test)]
mod tests {
    use super::*;
    

    #[test]
    fn labels_are_stable_wire_strings() {
        assert_eq!(LifetimeCategory::KeySlot.as_str(), "key_slot");
        assert_eq!(LifetimeCategory::Oath.as_str(), "oath");
        assert_eq!(LifetimeCategory::Pairing.as_str(), "pairing");
        assert_eq!(LifetimeCategory::Pin.as_str(), "pin");
        assert_eq!(LifetimeCategory::Transport.as_str(), "transport");
        assert_eq!(LifetimeEvent::KeyCreate.as_str(), "create");
        assert_eq!(LifetimeEvent::OathCode.as_str(), "code");
        assert_eq!(LifetimeEvent::PairingTimeout.as_str(), "timeout");
        assert_eq!(LifetimeEvent::PinBlocked.as_str(), "blocked");
        assert_eq!(LifetimeEvent::TpError.as_str(), "erro");
    }

    #[test]
    fn record_moves_only_its_counter() {
        let before = snapshot();
        record(LifetimeCategory::Pin, LifetimeEvent::PinRetry);
        record(LifetimeCategory::Pin, LifetimeEvent::PinRetry);
        let after = snapshot();
        assert_eq!(after.pin_retry, before.pin_retry.saturating_add(2));
        assert_eq!(after.pin_blocked, before.pin_blocked);
        assert_eq!(after.key_create, before.key_create);
        assert_eq!(after.unknown, before.unknown);
    }

    #[test]
    fn unexpected_pairing_counts_unknown() {
        let before = snapshot();
        record(LifetimeCategory::Pin, LifetimeEvent::KeyCreate);
        let after = snapshot();
        assert_eq!(after.unknown, before.unknown.saturating_add(1));
        assert_eq!(after.key_create, before.key_create);
    }

    #[test]
    fn dump_has_counts_and_never_details() {
        let before = snapshot();
        record(LifetimeCategory::Oath, LifetimeEvent::OathPut);
        let snap = snapshot();
        let mut text = alloc::string::String::new();
        write_dump(&snap, &mut text).unwrap();
        assert!(text.contains("lt.oath.put="));
        assert!(text.contains("lt.key_slot.create="));
        assert!(text.contains("lt.transport.erro="));
        // Details are never stored: even a label-looking detail cannot leak.
        assert!(!text.contains("GitHub"));
        assert!(!text.contains("alice"));
        assert_eq!(snap.oath_put, before.oath_put.saturating_add(1));
    }

    #[test]
    fn snapshot_is_copy_plain_data() {
        let a = snapshot();
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn ltrace_macro_compiles_in_both_modes() {
        crate::ltrace!(LifetimeCategory::KeySlot, LifetimeEvent::KeyCreate, 3u8);
        crate::ltrace!(LifetimeCategory::Oath, LifetimeEvent::OathPut, "GitHub:alice");
        crate::ltrace!(LifetimeCategory::Transport, LifetimeEvent::TpError, "ble");
    }

    struct StrBuf<'a> {
        buf: &'a mut [u8],
        len: usize,
    }

    impl core::fmt::Write for StrBuf<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let take = s.len().min(self.buf.len().saturating_sub(self.len));
            self.buf[self.len..self.len + take].copy_from_slice(&s.as_bytes()[..take]);
            self.len += take;
            Ok(())
        }
    }

    #[test]
    fn dump_renders_without_alloc() {
        let snap = LifetimeSnapshot {
            key_create: 12,
            ..LifetimeSnapshot::default()
        };
        let mut raw = [0u8; 512];
        let len = {
            let mut w = StrBuf {
                buf: &mut raw,
                len: 0,
            };
            write_dump(&snap, &mut w).unwrap();
            w.len
        };
        let text = core::str::from_utf8(&raw[..len]).unwrap();
        assert!(text.contains("lt.key_slot.create=12\n"));
        assert!(text.contains("lt.pin.retry=0\n"));
    }
}
