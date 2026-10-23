//! Lab test-hook names for the python bridge — types only, `test-mode` only.
//!
//! R7 hard rule (firmware owns the behavior; this crate only names it):
//! new hook = name in manifest `src/test_hooks.rs` (`TEST_COMMANDS`) +
//! handler `#[cfg(feature = "test-mode")]` + row in `docs/test-hooks.md` +
//! `CI-GREP: TEST-HOOK` mark on the handler. Release is proven by
//! `scripts/check-release-clean.py`: no `test-mode` = no `TEST_` strings,
//! no handler. No hook ever leaks into release.
//! - Source of truth for names: firmware `TEST_COMMANDS`. This enum mirrors
//!   exactly those 13 commands; drift is fixed here (never invent a name:
//!   no variant = no send = fail-closed).
//! - `TEST_BYPASSES` (`binding_bypass`, …) are firmware-internal `cfg!`
//!   paths, not bridge traffic — intentionally outside this enum.
//! - `TEST_PAIRING_CLOSE` (close pairing window via `close_test_window`):
//!   manifest + gated handler + doc row landed in the firmware lane, so the
//!   `PairingClose` variant below is liberated (was fail-closed gap).
//! - Bridge needs otherwise covered, no new hook required: `TEST_UP` is the
//!   1x latch, `TEST_PAIRING_OPEN_300` is the 300 s window.
//! - Zero business logic: names plus `NotCompiled` mapping via `cfg`.
//!   Sending, latching and ack parsing belong to the python bridge against
//!   test-mode firmware, never here.
//! - R12/R4: `test-mode` is never in `default`; lab surface OFF in the
//!   artefact. Without this feature, `require_test_mode()` is `NotCompiled`.

/// Test-hook commands mirrored 1:1 from firmware `TEST_COMMANDS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestHookId {
    /// `TEST_UP`: one software BOOT tap (single-use 1.5 s latch).
    Up,
    /// `TEST_DOWNLOAD`: RTC_CNTL download-mode for `esptool --before no-reset`.
    Download,
    /// `TEST_USB_RECONNECT`: USB reconnect cycle.
    UsbReconnect,
    /// `TEST_PAIRING_OPEN`: 60 s pairing window (same as hold-5s BOOT).
    PairingOpen,
    /// `TEST_PAIRING_OPEN_300`: 300 s window (zero-press E2E).
    PairingOpen300,
    /// `TEST_PAIRING_CLOSE`: close pairing window (lab teardown/determinism).
    PairingClose,
    /// `TEST_LIFETIME_DUMP`: counters/states, no secrets.
    LifetimeDump,
    /// `TEST_LED_STATE`: read-only LED snapshot.
    LedState,
    /// `TEST_LED_RED`: lab LED drive.
    LedRed,
    /// `TEST_LED_GREEN`: lab LED drive.
    LedGreen,
    /// `TEST_LED_BLUE`: lab LED drive.
    LedBlue,
    /// `TEST_LED_OFF`: lab LED drive.
    LedOff,
    /// `TEST_LED_RELEASE`: back to product LED control.
    LedRelease,
}

impl TestHookId {
    /// Exact wire bytes (D1/UART text line) — name table, no behavior.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Up => "TEST_UP",
            Self::Download => "TEST_DOWNLOAD",
            Self::UsbReconnect => "TEST_USB_RECONNECT",
            Self::PairingOpen => "TEST_PAIRING_OPEN",
            Self::PairingOpen300 => "TEST_PAIRING_OPEN_300",
            Self::PairingClose => "TEST_PAIRING_CLOSE",
            Self::LifetimeDump => "TEST_LIFETIME_DUMP",
            Self::LedState => "TEST_LED_STATE",
            Self::LedRed => "TEST_LED_RED",
            Self::LedGreen => "TEST_LED_GREEN",
            Self::LedBlue => "TEST_LED_BLUE",
            Self::LedOff => "TEST_LED_OFF",
            Self::LedRelease => "TEST_LED_RELEASE",
        }
    }

    /// All mirrored hooks, manifest order.
    pub const ALL: &'static [Self] = &[
        Self::Up,
        Self::Download,
        Self::UsbReconnect,
        Self::PairingOpen,
        Self::PairingOpen300,
        Self::PairingClose,
        Self::LifetimeDump,
        Self::LedState,
        Self::LedRed,
        Self::LedGreen,
        Self::LedBlue,
        Self::LedOff,
        Self::LedRelease,
    ];
}

#[cfg(test)]
mod tests {
    use crate::test_hooks::TestHookId;

    #[test]
    fn names_match_manifest() {
        const EXPECTED: &[(&str, TestHookId)] = &[
            ("TEST_UP", TestHookId::Up),
            ("TEST_DOWNLOAD", TestHookId::Download),
            ("TEST_USB_RECONNECT", TestHookId::UsbReconnect),
            ("TEST_PAIRING_OPEN", TestHookId::PairingOpen),
            ("TEST_PAIRING_OPEN_300", TestHookId::PairingOpen300),
            ("TEST_PAIRING_CLOSE", TestHookId::PairingClose),
            ("TEST_LIFETIME_DUMP", TestHookId::LifetimeDump),
            ("TEST_LED_STATE", TestHookId::LedState),
            ("TEST_LED_RED", TestHookId::LedRed),
            ("TEST_LED_GREEN", TestHookId::LedGreen),
            ("TEST_LED_BLUE", TestHookId::LedBlue),
            ("TEST_LED_OFF", TestHookId::LedOff),
            ("TEST_LED_RELEASE", TestHookId::LedRelease),
        ];
        assert_eq!(TestHookId::ALL.len(), EXPECTED.len());
        for (i, (name, id)) in EXPECTED.iter().enumerate() {
            let got = TestHookId::ALL[i];
            assert_eq!(got, *id);
            assert_eq!(got.as_str(), *name);
        }
    }

    #[test]
    fn no_duplicate_no_empty() {
        for (i, a) in TestHookId::ALL.iter().enumerate() {
            assert!(!a.as_str().is_empty());
            for b in &TestHookId::ALL[..i] {
                assert!(a != b, "duplicate hook");
            }
        }
    }
}
