//! Secure Guard Protocol Engine
//!
//! Central domain orchestrator enforcing the 10-state machine, PBKDF2 credential management,
//! session timeouts, 5-attempt lockout/wipe policy, and resource authorization barriers.

use super::audit::{AuditRingBuffer, SecureGuardAuditEventType, SessionExpiryReason};
use super::crypto::{constant_time_eq_32, derive_verifier, hmac_sha256};
use super::error::SecureGuardError;
use super::persistence::{SecureGuardPersistentRecord, PERSISTENT_RECORD_SIZE};
use super::policy::{SecureGuardPolicy, MAX_ATTEMPTS};
use super::resource::{ProtectedResourceClass, SecureGuardWipeScope};
use super::state::SecureGuardState;
use zeroize::Zeroize;

/// The primary Secure Guard domain engine.
#[derive(Debug, Clone)]
pub struct SecureGuardEngine {
    state: SecureGuardState,
    policy: SecureGuardPolicy,
    is_provisioned: bool,
    pin_salt: [u8; 16],
    pin_verifier: [u8; 32],
    recovery_salt: [u8; 16],
    recovery_verifier: [u8; 32],
    failed_attempts: u8,
    rate_limit_until_ms: u64,
    session_expires_at_ms: u64,
    last_activity_ms: u64,
    last_wipe_simulated: bool,
    last_rotated_recovery_code: Option<[u8; 16]>,
    audit_log: AuditRingBuffer,
    paired_ble_mac: [u8; 6],
    paired_ble_name: [u8; 24],
    ble_proximity_registered: bool,
    last_ble_rssi_dbm: i8,
    ble_proximity_away: bool,
    auto_lock_on_ble_away: bool,
}

impl Default for SecureGuardEngine {
    fn default() -> Self {
        Self::new(SecureGuardPolicy::default())
    }
}

impl SecureGuardEngine {
    /// Creates a new unprovisioned Secure Guard engine with the given policy.
    pub fn new(policy: SecureGuardPolicy) -> Self {
        Self {
            state: SecureGuardState::Unprovisioned,
            policy,
            is_provisioned: false,
            pin_salt: [0u8; 16],
            pin_verifier: [0u8; 32],
            recovery_salt: [0u8; 16],
            recovery_verifier: [0u8; 32],
            failed_attempts: 0,
            rate_limit_until_ms: 0,
            session_expires_at_ms: 0,
            last_activity_ms: 0,
            last_wipe_simulated: false,
            last_rotated_recovery_code: None,
            audit_log: AuditRingBuffer::new(),
            paired_ble_mac: [0u8; 6],
            paired_ble_name: [0u8; 24],
            ble_proximity_registered: false,
            last_ble_rssi_dbm: 0,
            ble_proximity_away: false,
            auto_lock_on_ble_away: true,
        }
    }

    /// Initializes an engine from a persisted record.
    ///
    /// Adheres to reboot rules:
    /// - If provisioned, session is NEVER restored as Unlocked; it always starts in Locked
    ///   (or RecoveryRequired / RateLimited / WipePending if previous failures warrant it).
    /// - Preserves failed attempts count and rate-limiting across reboots.
    pub fn from_persisted_record(record: &SecureGuardPersistentRecord, now_ms: u64) -> Self {
        let mut engine = Self::new(record.policy.clone());
        engine.is_provisioned = record.is_provisioned;
        engine.pin_salt = record.pin_salt;
        engine.pin_verifier = record.pin_verifier;
        engine.recovery_salt = record.recovery_salt;
        engine.recovery_verifier = record.recovery_verifier;
        engine.failed_attempts = record.failed_attempts;
        engine.rate_limit_until_ms = record.rate_limit_until_ms;
        engine.last_wipe_simulated = record.last_wipe_simulated;
        engine.paired_ble_mac = record.paired_ble_mac;
        engine.paired_ble_name = record.paired_ble_name;
        engine.ble_proximity_registered = record.ble_proximity_registered;
        engine.auto_lock_on_ble_away = record.auto_lock_on_ble_away;

        if !record.is_provisioned {
            engine.state = SecureGuardState::Unprovisioned;
        } else if record.failed_attempts >= MAX_ATTEMPTS {
            if record.policy.wipe_on_5_failures {
                engine.state = SecureGuardState::WipePending;
            } else {
                engine.state = SecureGuardState::RecoveryRequired;
            }
        } else if record.rate_limit_until_ms > now_ms {
            engine.state = SecureGuardState::RateLimited;
        } else {
            engine.state = SecureGuardState::Locked;
        }

        engine
    }

    /// Initializes an engine from raw persisted bytes, failing closed to ErrorLocked if corrupted.
    pub fn from_persisted_bytes(bytes: &[u8; PERSISTENT_RECORD_SIZE], now_ms: u64) -> Self {
        match SecureGuardPersistentRecord::from_bytes(bytes) {
            Ok(record) => Self::from_persisted_record(&record, now_ms),
            Err(_) => {
                let mut engine = Self::new(SecureGuardPolicy::default());
                engine.is_provisioned = true;
                engine.state = SecureGuardState::ErrorLocked;
                engine.audit_log.push(
                    now_ms,
                    SecureGuardAuditEventType::IntegrityFailure { detail_code: 0x01 },
                );
                engine
            }
        }
    }

    /// Converts current engine state to a serializable persistent record.
    pub fn to_persistent_record(&self) -> SecureGuardPersistentRecord {
        SecureGuardPersistentRecord {
            is_provisioned: self.is_provisioned,
            state_wire: self.state.wire_code(),
            failed_attempts: self.failed_attempts,
            last_wipe_simulated: self.last_wipe_simulated,
            rate_limit_until_ms: self.rate_limit_until_ms,
            pin_salt: self.pin_salt,
            pin_verifier: self.pin_verifier,
            recovery_salt: self.recovery_salt,
            recovery_verifier: self.recovery_verifier,
            policy: self.policy.clone(),
            ..Default::default()
        }
    }

    // --- State & Getters ---

    /// Current canonical state.
    pub fn state(&self) -> SecureGuardState {
        self.state
    }

    /// Active security policy.
    pub fn policy(&self) -> &SecureGuardPolicy {
        &self.policy
    }

    /// Mutable reference to policy for configuration updates.
    pub fn policy_mut(&mut self) -> &mut SecureGuardPolicy {
        &mut self.policy
    }

    /// True if PIN has been provisioned.
    pub fn is_provisioned(&self) -> bool {
        self.is_provisioned
    }

    /// Current count of consecutive failed authentication attempts.
    pub fn failed_attempts(&self) -> u8 {
        self.failed_attempts
    }

    /// Rate-limit penalty expiry timestamp in milliseconds.
    pub fn rate_limit_until_ms(&self) -> u64 {
        self.rate_limit_until_ms
    }

    /// True if the engine is currently unlocked with an unexpired session.
    pub fn is_unlocked(&self) -> bool {
        self.state == SecureGuardState::Unlocked
    }

    /// True if the last wipe was executed in non-destructive test mode.
    pub fn last_wipe_simulated(&self) -> bool {
        self.last_wipe_simulated
    }

    /// Returns the most recently generated or rotated recovery code, if available.
    pub fn last_rotated_recovery_code(&self) -> Option<[u8; 16]> {
        self.last_rotated_recovery_code
    }

    /// Read-only access to the audit log ring buffer.
    pub fn audit_log(&self) -> &AuditRingBuffer {
        &self.audit_log
    }

    /// 6-byte MAC address of paired Bluetooth device registered via App.
    pub fn paired_ble_mac(&self) -> &[u8; 6] {
        &self.paired_ble_mac
    }

    /// 24-byte name of paired Bluetooth device registered in memory.
    pub fn paired_ble_name(&self) -> &[u8; 24] {
        &self.paired_ble_name
    }

    /// True if a Bluetooth proximity device is registered.
    pub fn ble_proximity_registered(&self) -> bool {
        self.ble_proximity_registered
    }

    /// Last observed RSSI in dBm.
    pub fn last_ble_rssi_dbm(&self) -> i8 {
        self.last_ble_rssi_dbm
    }

    /// True if the registered Bluetooth device is currently away.
    pub fn ble_proximity_away(&self) -> bool {
        self.ble_proximity_away
    }

    /// True if auto-lock on Bluetooth away is enabled.
    pub fn auto_lock_on_ble_away(&self) -> bool {
        self.auto_lock_on_ble_away
    }

    /// Enables or disables auto-lock on Bluetooth away.
    pub fn set_auto_lock_on_ble_away(&mut self, enabled: bool) {
        self.auto_lock_on_ble_away = enabled;
    }

    /// Registers a Bluetooth proximity device in memory (and for persistence).
    pub fn register_ble_proximity_device(&mut self, mac: [u8; 6], name: &[u8]) {
        self.paired_ble_mac = mac;
        let mut n = [0u8; 24];
        let copy_len = name.len().min(24);
        n[..copy_len].copy_from_slice(&name[..copy_len]);
        self.paired_ble_name = n;
        self.ble_proximity_registered = true;
        self.auto_lock_on_ble_away = true;
        self.ble_proximity_away = false;
    }

    /// Continuous observation of registered Bluetooth proximity.
    ///
    /// If the registered Bluetooth device moves away (`is_away == true` or `rssi_dbm < threshold_dbm`
    /// or disconnection), and the Secure Guard engine is Unlocked:
    /// - Immediately locks the session (Locked), instantly revoking access to vault keys,
    ///   wallets, TOTP, KeePassXC, and SSH!
    ///
    /// Returns Ok(true) if this update triggered an immediate lock, or Ok(false) otherwise.
    pub fn on_ble_proximity_update(
        &mut self,
        mac: &[u8; 6],
        rssi_dbm: i8,
        is_away: bool,
        now_ms: u64,
    ) -> Result<bool, SecureGuardError> {
        // If registered, match MAC or accept if wildcard [0; 6]
        if self.ble_proximity_registered && self.paired_ble_mac != [0u8; 6] && self.paired_ble_mac != *mac {
            return Ok(false);
        }

        self.last_ble_rssi_dbm = rssi_dbm;
        self.ble_proximity_away = is_away;

        if is_away && self.auto_lock_on_ble_away && self.state == SecureGuardState::Unlocked {
            self.session_expires_at_ms = 0;
            self.transition_to(SecureGuardState::Locked, now_ms)?;
            self.audit_log.push(
                now_ms,
                SecureGuardAuditEventType::SessionExpired {
                    reason: SessionExpiryReason::BleProximityAway,
                },
            );
            return Ok(true);
        }

        Ok(false)
    }

    // --- State Machine Transitions ---

    /// Internal deterministic state transition with audit logging.
    fn transition_to(
        &mut self,
        target: SecureGuardState,
        now_ms: u64,
    ) -> Result<(), SecureGuardError> {
        if !self.state.can_transition_to(target) {
            self.audit_log.push(
                now_ms,
                SecureGuardAuditEventType::InvalidTransitionAttempt {
                    from: self.state,
                    target,
                },
            );
            return Err(SecureGuardError::InvalidStateTransition {
                from: self.state,
                to: target,
            });
        }

        if self.state != target {
            let from = self.state;
            self.state = target;
            self.audit_log.push(
                now_ms,
                SecureGuardAuditEventType::StateTransition { from, to: target },
            );
        }

        Ok(())
    }

    // --- Lifecycle Operations ---

    /// Provisions the initial PIN and generates/registers the recovery secret.
    ///
    /// Returns the 16-byte recovery code that must be shown to the user.
    pub fn provision_pin(
        &mut self,
        pin: &[u8],
        pin_salt: [u8; 16],
        recovery_code: &[u8],
        recovery_salt: [u8; 16],
        now_ms: u64,
    ) -> Result<[u8; 16], SecureGuardError> {
        if self.state == SecureGuardState::ErrorLocked {
            return Err(SecureGuardError::InvalidStateForOperation {
                current: self.state,
                expected: "Unprovisioned",
            });
        }

        if self.is_provisioned {
            return Err(SecureGuardError::AlreadyProvisioned);
        }

        self.transition_to(SecureGuardState::Provisioning, now_ms)?;

        if let Err(err) = self.policy.validate_pin(pin) {
            let _ = self.transition_to(SecureGuardState::Unprovisioned, now_ms);
            return Err(err);
        }

        // Establish recovery code (use input or derive from salt)
        let rec_code = if recovery_code.len() == 16 {
            let mut code = [0u8; 16];
            code.copy_from_slice(recovery_code);
            code
        } else if !recovery_code.is_empty() {
            let digest = hmac_sha256(&recovery_salt, recovery_code);
            let mut code = [0u8; 16];
            code.copy_from_slice(&digest[0..16]);
            code
        } else {
            let digest = hmac_sha256(&recovery_salt, b"AEGIS_RECOVERY_CODE_INITIAL");
            let mut code = [0u8; 16];
            code.copy_from_slice(&digest[0..16]);
            code
        };

        // Derive verifiers
        let pin_verifier = derive_verifier(pin, &pin_salt, self.policy.pbkdf2_iterations);
        let recovery_verifier =
            derive_verifier(&rec_code, &recovery_salt, self.policy.pbkdf2_iterations);

        self.pin_salt = pin_salt;
        self.pin_verifier = pin_verifier;
        self.recovery_salt = recovery_salt;
        self.recovery_verifier = recovery_verifier;
        self.is_provisioned = true;
        self.failed_attempts = 0;
        self.rate_limit_until_ms = 0;
        self.last_rotated_recovery_code = Some(rec_code);

        self.transition_to(SecureGuardState::Locked, now_ms)?;
        self.audit_log
            .push(now_ms, SecureGuardAuditEventType::PinProvisioned);

        Ok(rec_code)
    }

    /// Verifies the submitted PIN in constant time and unlocks the session.
    pub fn unlock_with_pin(&mut self, pin: &[u8], now_ms: u64) -> Result<(), SecureGuardError> {
        if self.state == SecureGuardState::ErrorLocked {
            return Err(SecureGuardError::InvalidStateForOperation {
                current: self.state,
                expected: "Locked",
            });
        }

        if !self.is_provisioned {
            return Err(SecureGuardError::NotProvisioned);
        }

        if self.state == SecureGuardState::Unlocked {
            self.check_and_touch_session(now_ms)?;
            return Ok(());
        }

        if self.state == SecureGuardState::RecoveryRequired {
            return Err(SecureGuardError::MaxAttemptsReachedRecoveryRequired);
        }

        if matches!(
            self.state,
            SecureGuardState::WipePending | SecureGuardState::WipeInProgress
        ) {
            return Err(SecureGuardError::MaxAttemptsWipeTriggered {
                simulated: self.last_wipe_simulated,
            });
        }

        // Check if rate limited
        if self.state == SecureGuardState::RateLimited {
            if now_ms < self.rate_limit_until_ms {
                return Err(SecureGuardError::RateLimited {
                    remaining_ms: self.rate_limit_until_ms - now_ms,
                });
            }
            // Rate limit expired
            self.transition_to(SecureGuardState::Locked, now_ms)?;
            self.audit_log
                .push(now_ms, SecureGuardAuditEventType::RateLimitExpired);
        }

        if self.ble_proximity_registered && self.ble_proximity_away && self.auto_lock_on_ble_away {
            return Err(SecureGuardError::BleProximityLocked);
        }

        if self.state != SecureGuardState::Locked {
            return Err(SecureGuardError::InvalidStateForOperation {
                current: self.state,
                expected: "Locked",
            });
        }

        self.transition_to(SecureGuardState::Authenticating, now_ms)?;

        let mut candidate_verifier =
            derive_verifier(pin, &self.pin_salt, self.policy.pbkdf2_iterations);
        let valid = constant_time_eq_32(&candidate_verifier, &self.pin_verifier);
        candidate_verifier.zeroize();

        if valid {
            self.failed_attempts = 0;
            self.rate_limit_until_ms = 0;
            self.transition_to(SecureGuardState::Unlocked, now_ms)?;

            self.session_expires_at_ms = now_ms.saturating_add(self.policy.session_duration_ms);
            self.last_activity_ms = now_ms;

            self.audit_log
                .push(now_ms, SecureGuardAuditEventType::PinVerificationSuccess);
            self.audit_log.push(
                now_ms,
                SecureGuardAuditEventType::SessionUnlocked {
                    expires_at_ms: self.session_expires_at_ms,
                },
            );

            Ok(())
        } else {
            self.failed_attempts = self.failed_attempts.saturating_add(1);
            let failed = self.failed_attempts;
            let remaining = MAX_ATTEMPTS.saturating_sub(failed);

            self.audit_log.push(
                now_ms,
                SecureGuardAuditEventType::PinVerificationFailed {
                    failed_attempts: failed,
                    remaining_attempts: remaining,
                },
            );

            if failed >= MAX_ATTEMPTS {
                if self.policy.wipe_on_5_failures {
                    self.transition_to(SecureGuardState::WipePending, now_ms)?;
                    let _ = self.execute_wipe(now_ms);
                    Err(SecureGuardError::MaxAttemptsWipeTriggered {
                        simulated: self.last_wipe_simulated,
                    })
                } else {
                    self.transition_to(SecureGuardState::RecoveryRequired, now_ms)?;
                    Err(SecureGuardError::MaxAttemptsReachedRecoveryRequired)
                }
            } else {
                let delay_ms = self.policy.compute_backoff_ms(failed);
                if delay_ms > 0 {
                    self.rate_limit_until_ms = now_ms.saturating_add(delay_ms);
                    self.transition_to(SecureGuardState::RateLimited, now_ms)?;
                    self.audit_log.push(
                        now_ms,
                        SecureGuardAuditEventType::RateLimitStarted {
                            delay_ms,
                            until_ms: self.rate_limit_until_ms,
                        },
                    );
                    Err(SecureGuardError::RateLimited {
                        remaining_ms: delay_ms,
                    })
                } else {
                    self.transition_to(SecureGuardState::Locked, now_ms)?;
                    Err(SecureGuardError::InvalidPin {
                        remaining_attempts: remaining,
                    })
                }
            }
        }
    }


    /// Verifies PIN for a critical action in constant time, applying failure policies and renewing active session on success.
    pub fn verify_pin_for_critical_action(
        &mut self,
        pin: &[u8],
        now_ms: u64,
    ) -> Result<(), SecureGuardError> {
        if self.state == SecureGuardState::ErrorLocked {
            return Err(SecureGuardError::InvalidStateForOperation {
                current: self.state,
                expected: "Locked",
            });
        }

        if !self.is_provisioned {
            return Err(SecureGuardError::NotProvisioned);
        }

        if self.state == SecureGuardState::RecoveryRequired {
            return Err(SecureGuardError::MaxAttemptsReachedRecoveryRequired);
        }

        if matches!(
            self.state,
            SecureGuardState::WipePending | SecureGuardState::WipeInProgress
        ) {
            return Err(SecureGuardError::MaxAttemptsWipeTriggered {
                simulated: self.last_wipe_simulated,
            });
        }

        // Check if rate limited
        if self.state == SecureGuardState::RateLimited {
            if now_ms < self.rate_limit_until_ms {
                return Err(SecureGuardError::RateLimited {
                    remaining_ms: self.rate_limit_until_ms - now_ms,
                });
            }
            // Rate limit expired
            self.transition_to(SecureGuardState::Locked, now_ms)?;
            self.audit_log
                .push(now_ms, SecureGuardAuditEventType::RateLimitExpired);
        }

        if self.state == SecureGuardState::Locked || self.state == SecureGuardState::Unlocked {
            self.transition_to(SecureGuardState::Authenticating, now_ms)?;
        }

        let mut candidate_verifier =
            derive_verifier(pin, &self.pin_salt, self.policy.pbkdf2_iterations);
        let valid = constant_time_eq_32(&candidate_verifier, &self.pin_verifier);
        candidate_verifier.zeroize();

        if valid {
            self.failed_attempts = 0;
            self.rate_limit_until_ms = 0;
            self.transition_to(SecureGuardState::Unlocked, now_ms)?;

            self.session_expires_at_ms = now_ms.saturating_add(self.policy.session_duration_ms);
            self.last_activity_ms = now_ms;

            self.audit_log
                .push(now_ms, SecureGuardAuditEventType::PinVerificationSuccess);
            self.audit_log.push(
                now_ms,
                SecureGuardAuditEventType::SessionUnlocked {
                    expires_at_ms: self.session_expires_at_ms,
                },
            );

            Ok(())
        } else {
            self.failed_attempts = self.failed_attempts.saturating_add(1);
            let failed = self.failed_attempts;
            let remaining = MAX_ATTEMPTS.saturating_sub(failed);

            self.audit_log.push(
                now_ms,
                SecureGuardAuditEventType::PinVerificationFailed {
                    failed_attempts: failed,
                    remaining_attempts: remaining,
                },
            );

            if failed >= MAX_ATTEMPTS {
                if self.policy.wipe_on_5_failures {
                    self.transition_to(SecureGuardState::WipePending, now_ms)?;
                    let _ = self.execute_wipe(now_ms);
                    Err(SecureGuardError::MaxAttemptsWipeTriggered {
                        simulated: self.last_wipe_simulated,
                    })
                } else {
                    self.transition_to(SecureGuardState::RecoveryRequired, now_ms)?;
                    Err(SecureGuardError::MaxAttemptsReachedRecoveryRequired)
                }
            } else {
                let delay_ms = self.policy.compute_backoff_ms(failed);
                if delay_ms > 0 {
                    self.rate_limit_until_ms = now_ms.saturating_add(delay_ms);
                    self.transition_to(SecureGuardState::RateLimited, now_ms)?;
                    self.audit_log.push(
                        now_ms,
                        SecureGuardAuditEventType::RateLimitStarted {
                            delay_ms,
                            until_ms: self.rate_limit_until_ms,
                        },
                    );
                    Err(SecureGuardError::RateLimited {
                        remaining_ms: delay_ms,
                    })
                } else {
                    self.transition_to(SecureGuardState::Locked, now_ms)?;
                    Err(SecureGuardError::InvalidPin {
                        remaining_attempts: remaining,
                    })
                }
            }
        }
    }

    /// Verifies PIN if provided, or validates active unexpired Unlocked session.
    pub fn verify_pin_or_active_session(
        &mut self,
        pin: Option<&[u8]>,
        now_ms: u64,
    ) -> Result<(), SecureGuardError> {
        if !self.is_provisioned {
            return Ok(());
        }
        if let Some(p) = pin {
            self.verify_pin_for_critical_action(p, now_ms)
        } else {
            let _ = self.check_and_touch_session(now_ms);
            if self.is_unlocked() {
                Ok(())
            } else {
                Err(SecureGuardError::NoActiveSession)
            }
        }
    }
    /// Validates session deadlines (absolute and inactivity), locking automatically if expired.
    pub fn check_and_touch_session(&mut self, now_ms: u64) -> Result<bool, SecureGuardError> {
        if self.state != SecureGuardState::Unlocked {
            return Ok(false);
        }

        if self.ble_proximity_registered && self.ble_proximity_away && self.auto_lock_on_ble_away {
            self.session_expires_at_ms = 0;
            self.transition_to(SecureGuardState::Locked, now_ms)?;
            self.audit_log.push(
                now_ms,
                SecureGuardAuditEventType::SessionExpired {
                    reason: SessionExpiryReason::BleProximityAway,
                },
            );
            return Ok(false);
        }

        // 1. Check absolute session expiration
        if now_ms >= self.session_expires_at_ms {
            self.session_expires_at_ms = 0;
            self.transition_to(SecureGuardState::Locked, now_ms)?;
            self.audit_log.push(
                now_ms,
                SecureGuardAuditEventType::SessionExpired {
                    reason: SessionExpiryReason::AbsoluteTimeout,
                },
            );
            return Ok(false);
        }

        // 2. Check inactivity timeout
        if now_ms.saturating_sub(self.last_activity_ms) >= self.policy.inactivity_timeout_ms {
            self.session_expires_at_ms = 0;
            self.transition_to(SecureGuardState::Locked, now_ms)?;
            self.audit_log.push(
                now_ms,
                SecureGuardAuditEventType::SessionExpired {
                    reason: SessionExpiryReason::Inactivity,
                },
            );
            return Ok(false);
        }

        // 3. Session is valid; touch timestamp
        self.last_activity_ms = now_ms;
        self.audit_log.push(
            now_ms,
            SecureGuardAuditEventType::SessionTouched {
                last_activity_ms: now_ms,
            },
        );
        Ok(true)
    }

    /// Immediately terminates the active session and transitions to Locked.
    pub fn lock_now(&mut self, now_ms: u64) -> Result<(), SecureGuardError> {
        if self.state == SecureGuardState::Unlocked {
            self.session_expires_at_ms = 0;
            self.transition_to(SecureGuardState::Locked, now_ms)?;
            self.audit_log.push(
                now_ms,
                SecureGuardAuditEventType::SessionExpired {
                    reason: SessionExpiryReason::ManualLock,
                },
            );
        }
        Ok(())
    }

    /// Invalidates session on transport disconnection (USB unplug / BLE disconnect).
    pub fn on_transport_disconnect(&mut self, now_ms: u64) -> Result<(), SecureGuardError> {
        if self.state == SecureGuardState::Unlocked {
            self.session_expires_at_ms = 0;
            self.transition_to(SecureGuardState::Locked, now_ms)?;
            self.audit_log.push(
                now_ms,
                SecureGuardAuditEventType::SessionExpired {
                    reason: SessionExpiryReason::TransportDisconnect,
                },
            );
        }
        Ok(())
    }

    /// Transactionally updates the PIN without corrupting the previous credentials on error.
    pub fn change_pin(
        &mut self,
        current_pin: &[u8],
        new_pin: &[u8],
        new_pin_salt: [u8; 16],
        now_ms: u64,
    ) -> Result<(), SecureGuardError> {
        if matches!(
            self.state,
            SecureGuardState::RecoveryRequired
                | SecureGuardState::RateLimited
                | SecureGuardState::WipePending
                | SecureGuardState::WipeInProgress
                | SecureGuardState::ErrorLocked
        ) {
            return Err(SecureGuardError::InvalidStateForOperation {
                current: self.state,
                expected: "Locked or Unlocked",
            });
        }

        if !self.is_provisioned {
            return Err(SecureGuardError::NotProvisioned);
        }

        // 1. Verify current PIN in constant time
        let mut candidate =
            derive_verifier(current_pin, &self.pin_salt, self.policy.pbkdf2_iterations);
        let valid = constant_time_eq_32(&candidate, &self.pin_verifier);
        candidate.zeroize();

        if !valid {
            self.failed_attempts = self.failed_attempts.saturating_add(1);
            let remaining = MAX_ATTEMPTS.saturating_sub(self.failed_attempts);
            return Err(SecureGuardError::InvalidPin {
                remaining_attempts: remaining,
            });
        }

        // 2. Validate new PIN policy
        self.policy.validate_pin(new_pin)?;

        // 3. Transactional update
        let new_verifier = derive_verifier(new_pin, &new_pin_salt, self.policy.pbkdf2_iterations);
        self.pin_salt = new_pin_salt;
        self.pin_verifier = new_verifier;
        self.failed_attempts = 0;
        self.rate_limit_until_ms = 0;

        self.audit_log
            .push(now_ms, SecureGuardAuditEventType::PinChanged);
        Ok(())
    }

    /// Recovers access using a legitimate single-use recovery code.
    ///
    /// Validates code in constant time, resets failures, sets new PIN, rotates recovery secret,
    /// and restores the engine to Locked state.
    pub fn recover_with_code(
        &mut self,
        recovery_code: &[u8],
        new_pin: &[u8],
        new_recovery_salt: [u8; 16],
        now_ms: u64,
    ) -> Result<SecureGuardState, SecureGuardError> {
        if self.state == SecureGuardState::ErrorLocked {
            return Err(SecureGuardError::InvalidStateForOperation {
                current: self.state,
                expected: "RecoveryRequired or Locked",
            });
        }

        if !self.is_provisioned {
            return Err(SecureGuardError::NotProvisioned);
        }

        // 1. Constant-time recovery code check
        let mut candidate = derive_verifier(
            recovery_code,
            &self.recovery_salt,
            self.policy.pbkdf2_iterations,
        );
        let valid = constant_time_eq_32(&candidate, &self.recovery_verifier);
        candidate.zeroize();

        if !valid {
            self.failed_attempts = self.failed_attempts.saturating_add(1);
            self.audit_log.push(
                now_ms,
                SecureGuardAuditEventType::RecoveryFailed {
                    failed_attempts: self.failed_attempts,
                },
            );
            return Err(SecureGuardError::InvalidRecoveryCode);
        }

        // 2. Validate new PIN
        self.policy.validate_pin(new_pin)?;

        // 3. Derive new PIN salt and verifier
        let pin_salt_digest = hmac_sha256(&new_recovery_salt, b"AEGIS_PIN_SALT_RECOVERY");
        let mut new_pin_salt = [0u8; 16];
        new_pin_salt.copy_from_slice(&pin_salt_digest[0..16]);
        let new_pin_verifier =
            derive_verifier(new_pin, &new_pin_salt, self.policy.pbkdf2_iterations);

        // 4. Rotate recovery code so previous code is invalidated
        let rec_code_digest = hmac_sha256(&new_recovery_salt, b"AEGIS_ROTATED_RECOVERY_CODE");
        let mut rotated_code = [0u8; 16];
        rotated_code.copy_from_slice(&rec_code_digest[0..16]);
        let new_rec_verifier = derive_verifier(
            &rotated_code,
            &new_recovery_salt,
            self.policy.pbkdf2_iterations,
        );

        // 5. Commit state transactionally
        self.pin_salt = new_pin_salt;
        self.pin_verifier = new_pin_verifier;
        self.recovery_salt = new_recovery_salt;
        self.recovery_verifier = new_rec_verifier;
        self.last_rotated_recovery_code = Some(rotated_code);
        self.failed_attempts = 0;
        self.rate_limit_until_ms = 0;

        self.transition_to(SecureGuardState::Locked, now_ms)?;
        self.audit_log
            .push(now_ms, SecureGuardAuditEventType::RecoverySuccess);

        Ok(SecureGuardState::Locked)
    }

    /// Executes scoped wipe of protected resources.
    ///
    /// In non-destructive test mode, performs the entire rite and marks `last_wipe_simulated = true`
    /// without erasing real key material. In standard mode, zeroes verifiers and returns Unprovisioned.
    pub fn execute_wipe(&mut self, now_ms: u64) -> Result<SecureGuardWipeScope, SecureGuardError> {
        let _ = self.transition_to(SecureGuardState::WipeInProgress, now_ms);

        let simulated = self.policy.test_mode_non_destructive_wipe;
        self.last_wipe_simulated = simulated;

        self.audit_log.push(
            now_ms,
            SecureGuardAuditEventType::WipeTriggered {
                scope: SecureGuardWipeScope::ProtectedResourcesOnly,
                simulated,
            },
        );

        if !simulated {
            self.pin_salt.zeroize();
            self.pin_verifier.zeroize();
            self.recovery_salt.zeroize();
            self.recovery_verifier.zeroize();
            self.is_provisioned = false;
            self.failed_attempts = 0;
            self.rate_limit_until_ms = 0;
            self.last_rotated_recovery_code = None;
        }

        self.audit_log.push(
            now_ms,
            SecureGuardAuditEventType::WipeCompleted { simulated },
        );

        self.transition_to(SecureGuardState::Unprovisioned, now_ms)?;
        Ok(SecureGuardWipeScope::ProtectedResourcesOnly)
    }

    // --- Authorization Barriers ---

    /// Authorizes a generic operation by resource classification with anti-glitching barrier (`GAP-06`).
    pub fn authorize_operation(
        &mut self,
        resource: ProtectedResourceClass,
        now_ms: u64,
    ) -> Result<(), SecureGuardError> {
        // FIDO2 standard flow is always permitted regardless of Secure Guard lock
        if matches!(resource, ProtectedResourceClass::FidoStandardFlow) {
            return Ok(());
        }

        let _ = self.check_and_touch_session(now_ms);

        let needs_unlock = resource.requires_unlock(&self.policy);
        let is_unlocked = self.state == SecureGuardState::Unlocked;
        let authorized = !needs_unlock || is_unlocked;
        let authorized_inv = !authorized;

        let jitter = (now_ms as u32) ^ 0xACE1;
        let check = super::glitch_guard::double_check_authorization(authorized, authorized_inv, jitter)?;
        if !check.is_true() {
            return Err(SecureGuardError::AccessDeniedLocked {
                state: self.state,
                opcode: 0x00,
            });
        }

        Ok(())
    }

    /// Authorizes execution of a vendor opcode byte with anti-glitching barrier (`GAP-06`).
    pub fn authorize_vendor_opcode(
        &mut self,
        opcode: u8,
        now_ms: u64,
    ) -> Result<(), SecureGuardError> {
        let resource = ProtectedResourceClass::from_vendor_opcode(opcode);
        let _ = self.check_and_touch_session(now_ms);

        let needs_unlock = resource.requires_unlock(&self.policy);
        let is_unlocked = self.state == SecureGuardState::Unlocked;
        let authorized = !needs_unlock || is_unlocked;
        let authorized_inv = !authorized;

        let jitter = (now_ms as u32) ^ (opcode as u32);
        let check = super::glitch_guard::double_check_authorization(authorized, authorized_inv, jitter)?;
        if !check.is_true() {
            return Err(SecureGuardError::AccessDeniedLocked {
                state: self.state,
                opcode,
            });
        }

        Ok(())
    }
}
