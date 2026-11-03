//! Secure Guard Audit Logging
//!
//! Fixed-capacity audit ring buffer guaranteeing Zero Secrets in Logs.
//! Records state transitions, authentication outcomes, and session life cycles.

use super::resource::SecureGuardWipeScope;
use super::state::SecureGuardState;

/// Capacity of the internal ring buffer for audit events.
pub const AUDIT_LOG_CAPACITY: usize = 32;

/// Structured audit event recording a lifecycle or security occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureGuardAuditEvent {
    /// Monotonic timestamp in milliseconds when the event occurred.
    pub timestamp_ms: u64,
    /// Specific typed event payload (never contains passwords or cryptographic keys).
    pub event_type: SecureGuardAuditEventType,
}

/// Category and metadata for an audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureGuardAuditEventType {
    /// State machine transitioned between states.
    StateTransition {
        from: SecureGuardState,
        to: SecureGuardState,
    },
    /// An unauthorized or invalid state transition was rejected.
    InvalidTransitionAttempt {
        from: SecureGuardState,
        target: SecureGuardState,
    },
    /// PIN and initial recovery secret were provisioned.
    PinProvisioned,
    /// PIN verification succeeded and session unlocked.
    PinVerificationSuccess,
    /// PIN verification failed.
    PinVerificationFailed {
        failed_attempts: u8,
        remaining_attempts: u8,
    },
    /// Progressive backoff rate-limit initiated.
    RateLimitStarted { delay_ms: u64, until_ms: u64 },
    /// Rate limit delay expired, returning to Locked state.
    RateLimitExpired,
    /// Legitimate recovery code validated and new credentials established.
    RecoverySuccess,
    /// Recovery code verification failed.
    RecoveryFailed { failed_attempts: u8 },
    /// DEV-only automatic recovery from the on-device code cache attempted.
    ///
    /// Compiled and emitted ONLY under `test-mode`; release builds never
    /// contain this event. Carries no secrets (success flag only).
    #[cfg(feature = "test-mode")]
    DevAutoRecovery { success: bool },
    /// Transactional PIN change completed.
    PinChanged,
    /// Active session unlocked with deadline.
    SessionUnlocked { expires_at_ms: u64 },
    /// Session touched by authorized activity.
    SessionTouched { last_activity_ms: u64 },
    /// Session expired or terminated.
    SessionExpired { reason: SessionExpiryReason },
    /// Scoped wipe triggered by policy.
    WipeTriggered {
        scope: SecureGuardWipeScope,
        simulated: bool,
    },
    /// Scoped wipe completed.
    WipeCompleted { simulated: bool },
    /// Persistent storage integrity check failure detected.
    IntegrityFailure { detail_code: u8 },
}

/// Reason for session termination or expiration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionExpiryReason {
    /// Exceeded maximum inactivity timeout without user interaction.
    Inactivity,
    /// Reached hard maximum session lifetime limit.
    AbsoluteTimeout,
    /// User or host explicitly requested lock.
    ManualLock,
    /// Physical or logical transport disconnected.
    TransportDisconnect,
    /// Registered Bluetooth proximity device moved away.
    BleProximityAway,
}

/// Fixed-size ring buffer for audit events to ensure predictable memory usage in `no_std`.
#[derive(Debug, Clone)]
pub struct AuditRingBuffer {
    events: [Option<SecureGuardAuditEvent>; AUDIT_LOG_CAPACITY],
    head: usize,
    count: usize,
}

impl Default for AuditRingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditRingBuffer {
    /// Creates a new empty audit ring buffer.
    pub const fn new() -> Self {
        const NONE_EVENT: Option<SecureGuardAuditEvent> = None;
        Self {
            events: [NONE_EVENT; AUDIT_LOG_CAPACITY],
            head: 0,
            count: 0,
        }
    }

    /// Appends a new event, overwriting the oldest entry when capacity is reached.
    pub fn push(&mut self, timestamp_ms: u64, event_type: SecureGuardAuditEventType) {
        self.events[self.head] = Some(SecureGuardAuditEvent {
            timestamp_ms,
            event_type,
        });
        self.head = (self.head + 1) % AUDIT_LOG_CAPACITY;
        if self.count < AUDIT_LOG_CAPACITY {
            self.count += 1;
        }
    }

    /// Returns the number of events currently held.
    pub fn len(&self) -> usize {
        self.count
    }

    /// True if no events have been recorded.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the most recently pushed event, if any.
    pub fn last(&self) -> Option<&SecureGuardAuditEvent> {
        if self.count == 0 {
            None
        } else {
            let idx = if self.head == 0 {
                AUDIT_LOG_CAPACITY - 1
            } else {
                self.head - 1
            };
            self.events[idx].as_ref()
        }
    }

    /// Clears the ring buffer.
    pub fn clear(&mut self) {
        for slot in self.events.iter_mut() {
            *slot = None;
        }
        self.head = 0;
        self.count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_overwriting() {
        let mut buffer = AuditRingBuffer::new();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);

        // Push AUDIT_LOG_CAPACITY + 5 events
        for i in 0..(AUDIT_LOG_CAPACITY + 5) {
            buffer.push(
                i as u64,
                SecureGuardAuditEventType::SessionTouched {
                    last_activity_ms: i as u64,
                },
            );
        }

        assert_eq!(buffer.len(), AUDIT_LOG_CAPACITY);
        let last = buffer.last().unwrap();
        assert_eq!(last.timestamp_ms, (AUDIT_LOG_CAPACITY + 4) as u64);
    }
}
