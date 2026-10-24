//! T-OT-03 HID typing gate: UP per typing operation.
//!
//! Single reason: require a fresh physical presence grant for every HID
//! typing operation without editing `keyboard.rs` (delegates to `OtpTyper`).
//!
//! - `confirm_presence` arms one single-use grant (physical button event).
//! - `queue_code_only` / `queue_otp` consume exactly one grant per call,
//!   on success or on invalid input (no probing with one touch, no replay).
//! - Without an armed grant both queue paths fail closed with
//!   `KbdDeny::PresenceRequired` and leave the typer idle (no partial
//!   typing, secret bytes never reach the wire or logs).
//! - Section 9: invalid/truncated inputs denied, size bounded, UP bound to
//!   the single queued operation, no secret in `Debug`/logs.
//!
//! Wire mapping: `PresenceRequired` -> vendor status `0x01 NEED_UP` (§9.5).

use crate::keyboard::{ascii_to_keycode, KeyboardReport, OtpTyper};

/// Bound for one typing operation (chars). Caps reports at 65 keys x 2.
pub const KBD_MAX_CHARS: usize = 64;

/// Typed denial. Carries no secret bytes (safe to log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KbdDeny {
    /// No fresh physical presence for this typing operation.
    PresenceRequired,
    /// Input rejected fail-closed (shape/charset/size).
    InvalidCode,
}

/// Single-use UP gate around `OtpTyper`. Does not edit `keyboard.rs`.
#[derive(Default)]
pub struct KbdGate {
    typer: OtpTyper,
    presence_armed: bool,
}

impl KbdGate {
    /// Creates an idle gate with no armed presence.
    pub fn new() -> Self {
        Self {
            typer: OtpTyper::new(),
            presence_armed: false,
        }
    }

    /// Arms one single-use presence grant (call on physical button event).
    pub fn confirm_presence(&mut self) {
        self.presence_armed = true;
    }

    /// Returns true when a presence grant is armed and not yet consumed.
    pub fn is_armed(&self) -> bool {
        self.presence_armed
    }

    /// Cancels typing and disarms any grant. Fail-closed, no output.
    pub fn cancel(&mut self) {
        self.typer.cancel();
        self.presence_armed = false;
    }

    /// Returns true while keystroke reports remain.
    pub fn is_active(&self) -> bool {
        self.typer.is_active()
    }

    /// Queues an OATH code (6-8 ASCII digits) for typing.
    ///
    /// Consumes exactly one presence grant per call. Fails closed with
    /// `PresenceRequired` when disarmed, or `InvalidCode` for any shape
    /// outside 6-8 ASCII digits. Never types a prefix of a bad input.
    pub fn queue_code_only(&mut self, code: &str, append_enter: bool) -> Result<(), KbdDeny> {
        if !self.presence_armed {
            return Err(KbdDeny::PresenceRequired);
        }
        self.presence_armed = false;
        if !(6..=8).contains(&code.len()) || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(KbdDeny::InvalidCode);
        }
        self.typer.queue_code_only(code, append_enter);
        if !self.typer.is_active() {
            return Err(KbdDeny::InvalidCode);
        }
        Ok(())
    }

    /// Queues a generic OTP string (modhex/digits) for typing.
    ///
    /// Consumes exactly one presence grant per call. Every char must map
    /// to a HID keycode via `ascii_to_keycode`, input non-empty and within
    /// `KBD_MAX_CHARS`; otherwise fails closed with `InvalidCode`.
    pub fn queue_otp(&mut self, otp: &str, append_enter: bool) -> Result<(), KbdDeny> {
        if !self.presence_armed {
            return Err(KbdDeny::PresenceRequired);
        }
        self.presence_armed = false;
        if otp.is_empty()
            || otp.len() > KBD_MAX_CHARS
            || !otp.chars().all(|c| ascii_to_keycode(c).is_some())
        {
            return Err(KbdDeny::InvalidCode);
        }
        self.typer.queue_otp(otp, append_enter);
        if !self.typer.is_active() {
            return Err(KbdDeny::InvalidCode);
        }
        Ok(())
    }

    /// Next 8-byte HID report, or `None` when idle.
    pub fn next_report(&mut self) -> Option<KeyboardReport> {
        self.typer.next_report()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_without_presence() {
        let mut gate = KbdGate::new();
        assert!(!gate.is_armed());
        assert_eq!(
            gate.queue_code_only("287082", false),
            Err(KbdDeny::PresenceRequired)
        );
        assert!(!gate.is_active());
        assert_eq!(
            gate.queue_otp("cbdefg", false),
            Err(KbdDeny::PresenceRequired)
        );
        assert!(!gate.is_active());
    }

    #[test]
    fn single_use_grant_no_replay() {
        let mut gate = KbdGate::new();
        gate.confirm_presence();
        assert!(gate.is_armed());
        gate.queue_code_only("287082", false).expect("UP armed");
        assert!(!gate.is_armed());
        assert!(gate.is_active());
        // Same touch does not authorize a second operation.
        assert_eq!(
            gate.queue_code_only("461192", false),
            Err(KbdDeny::PresenceRequired)
        );
        gate.confirm_presence();
        gate.queue_code_only("461192", false).expect("fresh UP");
    }

    #[test]
    fn invalid_input_consumes_grant_fail_closed() {
        let mut gate = KbdGate::new();
        for bad in ["", "12345", "123456789", "28a082", "abcdefgh", "123 456"] {
            gate.confirm_presence();
            assert_eq!(
                gate.queue_code_only(bad, true),
                Err(KbdDeny::InvalidCode),
                "bad {bad:?} must fail closed"
            );
            assert!(!gate.is_active(), "no partial typing for {bad:?}");
            assert!(!gate.is_armed(), "grant consumed even on invalid");
        }
        // Consumed grant cannot be reused for a valid code.
        assert_eq!(
            gate.queue_code_only("287082", false),
            Err(KbdDeny::PresenceRequired)
        );
        gate.confirm_presence();
        gate.queue_code_only("287082", false)
            .expect("valid after re-arm");
        assert!(gate.is_active());
    }

    fn pump_reports(gate: &mut KbdGate) -> usize {
        // `OtpTyper` inserts idle poll frames between press/release;
        // pump until idle with a bound (no sleep, no busy wait on I/O).
        let mut n = 0;
        let mut guard = 0;
        while gate.is_active() && guard < 1000 {
            guard += 1;
            if gate.next_report().is_some() {
                n += 1;
            }
        }
        n
    }

    #[test]
    fn valid_vectors_report_counts() {
        let mut gate = KbdGate::new();
        gate.confirm_presence();
        gate.queue_code_only("287082", false).expect("6 digits");
        assert_eq!(pump_reports(&mut gate), 12);
        assert!(!gate.is_active());

        gate.confirm_presence();
        gate.queue_code_only("46119246", true)
            .expect("8 digits + enter");
        assert_eq!(pump_reports(&mut gate), 18);
    }

    #[test]
    fn otp_path_gated_and_bounded() {
        let mut gate = KbdGate::new();
        assert_eq!(
            gate.queue_otp("cbdefg", false),
            Err(KbdDeny::PresenceRequired)
        );
        gate.confirm_presence();
        gate.queue_otp("cbdefg", false).expect("modhex typable");
        assert!(gate.is_active());
        gate.cancel();
        assert!(!gate.is_active());
        assert!(!gate.is_armed());

        // Unsupported charset fails closed and consumes the grant.
        gate.confirm_presence();
        assert_eq!(gate.queue_otp("ab~cd", false), Err(KbdDeny::InvalidCode));
        assert!(!gate.is_active());

        // Size bound fails closed.
        gate.confirm_presence();
        let big = "1".repeat(KBD_MAX_CHARS + 1);
        assert_eq!(gate.queue_otp(&big, false), Err(KbdDeny::InvalidCode));
        assert!(!gate.is_active());
    }

    #[test]
    fn denial_carries_no_secret() {
        let dbg = format!("{:?}", KbdDeny::InvalidCode);
        assert!(!dbg.contains("287082"));
        let dbg = format!("{:?}", KbdDeny::PresenceRequired);
        assert!(!dbg.contains("287082"));
    }
}
