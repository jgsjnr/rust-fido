//! Continuous security monitor (secmon) — types and gates only.
//!
//! - R12: compiled only with feature `secmon`. Off yields
//!   `SdkError::NotCompiled` via `require_secmon` (stable stub, same as
//!   `hardwallet`), never `todo!()`, never a broken build.
//! - R13 stub-only: this module never enables secure-boot and never burns
//!   eFuse (reads only). The isolated implementation — ESP32-S3 FreeRTOS
//!   task pinned to the dedicated APP core, high priority, 8 KiB stack,
//!   own TWDT, MPU/stack-guard, separate from USB/BLE/dispatch — is wired
//!   in T12/T13 with HIL, never in this crate.
//! - R14 HW-first: tamper sources name the real peripherals that must
//!   report them (TRNG/HW-RNG, eFuse read, TWDT, anti-rollback version).
//!   Emulation/shim only under `cfg(test)` on host.
//! - Validator core: every op passes through `policy_check(op, ctx)`
//!   (contract `PolicyGate`) before executing — canonical order
//!   `binding -> UP -> PIN`, active PIN session (TTL or single-use,
//!   re-ask after unlock), 60 s pairing window, monotonic counters, NVS
//!   verify, monotonic time, coex USB > WiFi > BLE. Abnormal input
//!   (expired session, replay, corrupt store, clock rollback) denies
//!   fail-closed + `TamperEvent` + session zeroize. Types here,
//!   enforcement in firmware (T8/T12).
//! - Zero business logic: types plus `NotCompiled` mapping via `cfg`.
//!   Policy evaluation, heartbeat freshness and lockdown sequencing live
//!   in the T13 firmware task, not here.

use crate::auth::AuthContext;

/// Monitor health as last reported by the isolated secmon task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityStatus {
    /// No tamper observed; heartbeat fresh.
    Nominal,
    /// Degraded (e.g. missed heartbeat) but tamper not confirmed.
    Degraded,
    /// Tamper observed; containment follows `LockdownPolicy` (T13).
    Tampered,
    /// Device locked down pending power-cycle/re-provision (T13).
    LockedDown,
}

/// Tamper source, named after the HW peripheral that reports it (R14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TamperEvent {
    /// Secmon's own TWDT fired (dedicated watchdog, wired in T12/T13).
    WatchdogTimeout,
    /// Anti-rollback version mismatch on staged image.
    RollbackDetected,
    /// TRNG/HW-RNG health test failed.
    EntropyFault,
    /// Brownout / voltage-glitch detector trip.
    VoltageGlitch,
    /// Reset cause inconsistent with the orderly reboot path.
    UnexpectedReset,
    /// PIN session presented after expiry (TTL elapsed or single-use
    /// consumed and reused): deny + re-ask.
    SessionExpired,
    /// Monotonic/replay counter mismatch on this op.
    ReplayDetected,
    /// NVS verify-after-write/read failed for touched keys.
    StoreCorrupted,
    /// Monotonic clock went backwards between observations.
    ClockRollback,
}

/// Containment policy applied on tamper (evaluated by the T13 task;
///
/// data only here — this crate never enforces, wipes, or locks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockdownPolicy {
    /// Wipe NVS secrets (via the confirmed path) on confirmed tamper.
    pub wipe_on_confirmed_tamper: bool,
    /// Require power-cycle before leaving `LockedDown`.
    pub require_power_cycle: bool,
    /// Consecutive tamper events that confirm lockdown.
    pub confirm_after_events: u8,
}

impl LockdownPolicy {
    /// Build a policy from explicit containment facts.
    pub const fn new(
        wipe_on_confirmed_tamper: bool,
        require_power_cycle: bool,
        confirm_after_events: u8,
    ) -> Self {
        Self {
            wipe_on_confirmed_tamper,
            require_power_cycle,
            confirm_after_events,
        }
    }

    /// Fail-closed default: wipe + power-cycle, confirmed on first event.
    pub const STRICT: Self = Self::new(true, true, 1);
    /// Observing default: report only, confirmed only at saturation.
    pub const OBSERVE: Self = Self::new(false, false, u8::MAX);
}

/// Freshness + health snapshot emitted by the secmon task.
///
/// `sequence` ordering and staleness thresholds are enforced by firmware
/// (T13), never here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityHeartbeat {
    /// Monotonic sequence number (opaque here).
    pub sequence: u32,
    /// Health at emission time.
    pub status: SecurityStatus,
    /// FreeRTOS tick count at emission (opaque here).
    pub uptime_ticks: u64,
}

impl SecurityHeartbeat {
    /// Build a heartbeat snapshot.
    pub const fn new(sequence: u32, status: SecurityStatus, uptime_ticks: u64) -> Self {
        Self {
            sequence,
            status,
            uptime_ticks,
        }
    }
}

/// Operation class under validation (R5).
///
/// `Config` covers privileged ops (GEN/IMPORT/DELETE/PUT/WiFi/claim-mgmt):
/// full `binding -> UP -> PIN` chain. `Usage` covers unprivileged ops
/// (CODE/LIST/GetAssertion/display): never requires binding, UP only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyOpClass {
    /// Privileged configuration: binding -> UP -> PIN.
    Config,
    /// Unprivileged use: UP-gated, binding never required.
    Usage,
}

/// PIN-session facts: active session with TTL or single-use.
///
/// Firmware converts wall time via its tick rate (e.g. 60 s TTL);
/// re-ask is required after unlock/expiry. Ticks are opaque here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinSession {
    /// A session is currently issued (not yet expired/consumed).
    pub active: bool,
    /// Tick count at issuance.
    pub issued_at_ticks: u64,
    /// Session lifetime in ticks (e.g. 60 s worth).
    pub ttl_ticks: u64,
    /// Remaining single uses (`0` = exhausted).
    pub uses_left: u8,
}

impl PinSession {
    /// No session issued.
    pub const fn inactive() -> Self {
        Self {
            active: false,
            issued_at_ticks: 0,
            ttl_ticks: 0,
            uses_left: 0,
        }
    }

    /// Issue a session expiring after `ttl_ticks` or `uses_left` uses.
    pub const fn new(issued_at_ticks: u64, ttl_ticks: u64, uses_left: u8) -> Self {
        Self {
            active: true,
            issued_at_ticks,
            ttl_ticks,
            uses_left,
        }
    }
}

/// Pairing-window facts (60 s after hold-5s BOOT; durations in ticks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingWindow {
    /// Window currently open.
    pub open: bool,
    /// Tick count at opening.
    pub opened_at_ticks: u64,
    /// Window length in ticks (e.g. 60 s worth).
    pub len_ticks: u64,
}

impl PairingWindow {
    /// Window closed.
    pub const fn closed() -> Self {
        Self {
            open: false,
            opened_at_ticks: 0,
            len_ticks: 0,
        }
    }

    /// Open a window of `len_ticks` starting at `opened_at_ticks`.
    pub const fn new(opened_at_ticks: u64, len_ticks: u64) -> Self {
        Self {
            open: true,
            opened_at_ticks,
            len_ticks,
        }
    }
}

/// Replay/monotonic counter facts (anti-replay; judged by firmware).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterState {
    /// Last accepted counter value.
    pub last_accepted: u64,
    /// Counter value presented with this op.
    pub presented: u64,
}

impl CounterState {
    /// Build counter facts.
    pub const fn new(last_accepted: u64, presented: u64) -> Self {
        Self {
            last_accepted,
            presented,
        }
    }
}

/// NVS integrity for the keys this op touches (verify-after-write/read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreIntegrity {
    /// Verify passed.
    Verified,
    /// Verify/read failed: fail-closed + `TamperEvent::StoreCorrupted`.
    Corrupted,
}

/// Monotonic-time facts (clock-rollback detection; ticks opaque).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockState {
    /// Current tick count.
    pub now_ticks: u64,
    /// Tick count at the previous observation.
    pub last_ticks: u64,
}

impl ClockState {
    /// Build clock facts.
    pub const fn new(now_ticks: u64, last_ticks: u64) -> Self {
        Self {
            now_ticks,
            last_ticks,
        }
    }
}

/// Transport under validation (coexistence priority USB > WiFi > BLE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// USB/CTAP (highest priority, never sees NEED_BINDING).
    Usb,
    /// WiFi mgmt/AP.
    Wifi,
    /// BLE-GATT (lowest priority).
    Ble,
}

/// Coexistence facts: one transport owns the link at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoexState {
    /// Transport currently owning the link (`None` = idle).
    pub active: Option<Transport>,
    /// Transport requesting this op.
    pub requested: Transport,
}

impl CoexState {
    /// Build coexistence facts.
    pub const fn new(active: Option<Transport>, requested: Transport) -> Self {
        Self { active, requested }
    }
}

/// Facts the firmware T8/T12 gate feeds into `policy_check`.
///
/// Everything here is caller-observed data: this crate never reads
/// clocks, NVS, counters, or transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyContext {
    /// Ownership / presence / PIN facts.
    pub auth: AuthContext,
    /// PIN-session facts (TTL or single-use).
    pub pin_session: PinSession,
    /// Pairing-window facts (60 s).
    pub pairing: PairingWindow,
    /// Replay/monotonic counter facts.
    pub counters: CounterState,
    /// NVS integrity for touched keys.
    pub store: StoreIntegrity,
    /// Monotonic-time facts.
    pub clock: ClockState,
    /// Transport coexistence facts.
    pub coex: CoexState,
}

impl PolicyContext {
    /// Build the full fact set (all caller-observed, all `Copy`).
    pub const fn new(
        auth: AuthContext,
        pin_session: PinSession,
        pairing: PairingWindow,
        counters: CounterState,
        store: StoreIntegrity,
        clock: ClockState,
        coex: CoexState,
    ) -> Self {
        Self {
            auth,
            pin_session,
            pairing,
            counters,
            store,
            clock,
            coex,
        }
    }
}

/// Fail-closed denial reason (wire mapping owned by firmware T8/T12
/// gates, never here — this crate only names the reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// Binding missing: canonical first check (wire `0x05`, never USB).
    NeedBinding,
    /// User presence missing (wire `0x01`).
    NeedUp,
    /// PIN required (wire `0x02`).
    NeedPin,
    /// PIN session expired (TTL elapsed or single-use consumed): re-ask.
    SessionExpired,
    /// Pairing window (60 s) closed for a privileged op.
    PairingWindowClosed,
    /// Replay/monotonic counter mismatch.
    ReplayDetected,
    /// NVS verify-after-write/read failed for touched keys.
    StoreCorrupted,
    /// Monotonic clock went backwards.
    ClockRollback,
    /// Higher-priority transport owns the link (USB > WiFi > BLE).
    CoexPreempted,
}

/// Validator verdict for one op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Execute.
    Allow,
    /// Refuse fail-closed.
    Deny(DenyReason),
}

/// Full validator outcome: verdict plus abnormal-containment facts.
///
/// `tamper` is `Some` only for abnormal denies (expired session, replay,
/// corrupt store, clock rollback): firmware must emit the event, and
/// `zeroize_session` tells it to zeroize the session before returning.
/// Enforcement lives in firmware (T8/T12); this is data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyOutcome {
    /// Verdict.
    pub decision: PolicyDecision,
    /// Tamper event to emit (`None` for clean gate denies).
    pub tamper: Option<TamperEvent>,
    /// Firmware must zeroize the session before returning.
    pub zeroize_session: bool,
}

impl PolicyOutcome {
    /// Clean allow: no event, no zeroize.
    pub const fn allow() -> Self {
        Self {
            decision: PolicyDecision::Allow,
            tamper: None,
            zeroize_session: false,
        }
    }

    /// Clean gate deny (missing binding/UP/PIN, closed window, coex):
    /// no event, session kept.
    pub const fn deny(reason: DenyReason) -> Self {
        Self {
            decision: PolicyDecision::Deny(reason),
            tamper: None,
            zeroize_session: false,
        }
    }

    /// Abnormal deny (expired session, replay, corrupt store, clock
    /// rollback): fail-closed + `TamperEvent` + session zeroize.
    pub const fn deny_tamper(reason: DenyReason, event: TamperEvent) -> Self {
        Self {
            decision: PolicyDecision::Deny(reason),
            tamper: Some(event),
            zeroize_session: true,
        }
    }

    /// `true` only for `Allow`.
    pub const fn is_allow(&self) -> bool {
        match self.decision {
            PolicyDecision::Allow => true,
            PolicyDecision::Deny(_) => false,
        }
    }
}

/// Validator-core contract: every op passes through `policy_check(op, ctx)`
/// before executing.
///
/// The firmware T8/T12 gate implements this: canonical order
/// `binding -> UP -> PIN`, active PIN session (TTL or single-use),
/// 60 s pairing window, monotonic counters, NVS verify, monotonic time,
/// coex USB > WiFi > BLE. Declared here so all transports share one typed
/// shape; no default body, no logic, no eFuse/secure-boot (R13 stub).
pub trait PolicyGate {
    /// Validate one op against caller-observed facts; abnormal input
    /// yields fail-closed deny + `TamperEvent` + session zeroize.
    fn policy_check(op: PolicyOpClass, ctx: PolicyContext) -> PolicyOutcome;
}

#[cfg(test)]
mod tests {
    use crate::auth::AuthContext;
    use crate::secmon::{
        ClockState, CoexState, CounterState, DenyReason, LockdownPolicy, PairingWindow, PinSession,
        PolicyContext, PolicyDecision, PolicyGate, PolicyOpClass, PolicyOutcome, SecurityHeartbeat,
        SecurityStatus, StoreIntegrity, TamperEvent, Transport,
    };

    #[test]
    fn const_constructible() {
        const HB: SecurityHeartbeat = SecurityHeartbeat::new(7, SecurityStatus::Nominal, 1_000);
        let hb = HB;
        assert_eq!(hb.sequence, 7);
        assert_eq!(hb.status, SecurityStatus::Nominal);
        assert_eq!(hb.uptime_ticks, 1_000);
    }

    #[test]
    fn all_statuses_and_events_reachable() {
        for status in [
            SecurityStatus::Nominal,
            SecurityStatus::Degraded,
            SecurityStatus::Tampered,
            SecurityStatus::LockedDown,
        ] {
            let hb = SecurityHeartbeat::new(0, status, 0);
            assert_eq!(hb.status, status);
        }
        for event in [
            TamperEvent::WatchdogTimeout,
            TamperEvent::RollbackDetected,
            TamperEvent::EntropyFault,
            TamperEvent::VoltageGlitch,
            TamperEvent::UnexpectedReset,
            TamperEvent::SessionExpired,
            TamperEvent::ReplayDetected,
            TamperEvent::StoreCorrupted,
            TamperEvent::ClockRollback,
        ] {
            let _ = event;
        }
    }

    #[test]
    fn policies_are_const_and_distinct() {
        const STRICT: LockdownPolicy = LockdownPolicy::STRICT;
        const OBSERVE: LockdownPolicy = LockdownPolicy::OBSERVE;
        let strict = STRICT;
        let observe = OBSERVE;
        assert!(strict.wipe_on_confirmed_tamper);
        assert!(strict.require_power_cycle);
        assert_eq!(strict.confirm_after_events, 1);
        assert!(!observe.wipe_on_confirmed_tamper);
        assert!(!observe.require_power_cycle);
        assert_ne!(strict, observe);
    }

    #[test]
    fn policy_outcomes_are_const_data() {
        const ALLOW: PolicyOutcome = PolicyOutcome::allow();
        const DENY: PolicyOutcome = PolicyOutcome::deny(DenyReason::NeedUp);
        const TAMPER: PolicyOutcome =
            PolicyOutcome::deny_tamper(DenyReason::ReplayDetected, TamperEvent::ReplayDetected);
        let allow = ALLOW;
        let deny = DENY;
        let tamper = TAMPER;
        assert!(allow.is_allow());
        assert_eq!(allow.tamper, None);
        assert!(!allow.zeroize_session);
        assert!(!deny.is_allow());
        assert_eq!(deny.decision, PolicyDecision::Deny(DenyReason::NeedUp));
        assert_eq!(deny.tamper, None);
        assert!(!deny.zeroize_session);
        assert!(!tamper.is_allow());
        assert_eq!(tamper.tamper, Some(TamperEvent::ReplayDetected));
        assert!(tamper.zeroize_session);
    }

    #[test]
    fn all_deny_reasons_deny() {
        for reason in [
            DenyReason::NeedBinding,
            DenyReason::NeedUp,
            DenyReason::NeedPin,
            DenyReason::SessionExpired,
            DenyReason::PairingWindowClosed,
            DenyReason::ReplayDetected,
            DenyReason::StoreCorrupted,
            DenyReason::ClockRollback,
            DenyReason::CoexPreempted,
        ] {
            let outcome = PolicyOutcome::deny(reason);
            assert!(!outcome.is_allow());
            assert_eq!(outcome.tamper, None);
        }
    }

    #[test]
    fn policy_context_const_builds() {
        const CTX: PolicyContext = PolicyContext::new(
            AuthContext::new(true, true, true),
            PinSession::new(100, 60_000, 1),
            PairingWindow::new(50, 60_000),
            CounterState::new(4, 5),
            StoreIntegrity::Verified,
            ClockState::new(200, 100),
            CoexState::new(None, Transport::Usb),
        );
        let ctx = CTX;
        assert!(ctx.auth.binding_verified);
        assert!(ctx.pin_session.active);
        assert_eq!(ctx.pin_session.uses_left, 1);
        assert!(ctx.pairing.open);
        assert_eq!(ctx.counters.presented, 5);
        assert_eq!(ctx.store, StoreIntegrity::Verified);
        assert_eq!(ctx.clock.now_ticks, 200);
        assert_eq!(ctx.coex.requested, Transport::Usb);
        assert_eq!(ctx.coex.active, None);
        let _ = PolicyOpClass::Config;
        let _ = PolicyOpClass::Usage;
        let _ = PinSession::inactive();
        let _ = PairingWindow::closed();
        let _ = StoreIntegrity::Corrupted;
        let _ = Transport::Wifi;
        let _ = Transport::Ble;
    }

    #[test]
    fn gate_contract_implementable() {
        struct Passthrough;
        impl PolicyGate for Passthrough {
            fn policy_check(_op: PolicyOpClass, _ctx: PolicyContext) -> PolicyOutcome {
                PolicyOutcome::allow()
            }
        }
        let ctx = PolicyContext::new(
            AuthContext::anonymous(),
            PinSession::inactive(),
            PairingWindow::closed(),
            CounterState::new(0, 0),
            StoreIntegrity::Verified,
            ClockState::new(0, 0),
            CoexState::new(None, Transport::Usb),
        );
        let out = Passthrough::policy_check(PolicyOpClass::Usage, ctx);
        assert!(out.is_allow());
    }
}
