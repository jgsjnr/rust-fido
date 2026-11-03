//! Secure Guard Protocol Engine
//!
//! Central domain orchestrator enforcing the 10-state machine, PBKDF2 credential management,
//! session timeouts, 5-attempt lockout/wipe policy, and resource authorization barriers.

use super::audit::{AuditRingBuffer, SecureGuardAuditEventType, SessionExpiryReason};
use super::crypto::{constant_time_eq_32, derive_verifier, hmac_sha256};
use super::error::SecureGuardError;
use super::persistence::{SecureGuardPersistentRecord, PERSISTENT_RECORD_SIZE};
use super::policy::{SecureGuardPolicy, MAX_ATTEMPTS};
use super::recovery::{SecureGuardRecoveryEnvelope, RECOVERY_ENVELOPE_SIZE};
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
    /// RAM-only cache of the device-key-independent recovery envelope, sealed
    /// at provision / recovery rotation. Deliberately NOT part of the 256-byte
    /// persistent record: the envelope must be stored by firmware in a separate
    /// NVS blob outside the device-key envelope, otherwise it would be lost in
    /// exactly the reboot scenario it rescues from. Rebuilt from NVS bytes via
    /// [`Self::recover_with_envelope`]; `None` after a fresh reboot until then.
    recovery_envelope: Option<SecureGuardRecoveryEnvelope>,
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
            recovery_envelope: None,
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
        // The recovery envelope is RAM-only and travels in a separate NVS blob
        // outside the device-key envelope (see `recovery_envelope_bytes`); it
        // is never restored from the 256-byte record. After a reboot it is
        // `None` until `recover_with_envelope` (or a refresh) rebuilds it.

        if !record.is_provisioned {
            engine.state = SecureGuardState::Unprovisioned;
        } else if record.failed_attempts >= MAX_ATTEMPTS {
            if record.policy.wipe_on_5_failures {
                engine.state = SecureGuardState::WipePending;
            } else if record.rate_limit_until_ms > now_ms {
                engine.state = SecureGuardState::RateLimited;
            } else {
                engine.state = SecureGuardState::Locked;
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
        // Se a proximidade BLE não estiver registrada/ativada, ignora qualquer evento e nunca tranca
        if !self.ble_proximity_registered {
            self.ble_proximity_away = false;
            return Ok(false);
        }

        // If registered, match MAC or accept if wildcard [0; 6]
        if self.paired_ble_mac != [0u8; 6] && self.paired_ble_mac != *mac {
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

        // Cache the device-key-independent rescue envelope while the fresh code
        // is still in hand. Firmware persists `recovery_envelope_bytes()` in a
        // separate NVS blob outside the device-key envelope.
        if let Ok(envelope) = SecureGuardRecoveryEnvelope::seal(
            &rec_code,
            &recovery_salt,
            &self.pin_salt,
            &self.pin_verifier,
            self.policy.pbkdf2_iterations,
        ) {
            self.recovery_envelope = Some(envelope);
        }

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
            if now_ms < self.rate_limit_until_ms {
                return Err(SecureGuardError::RateLimited {
                    remaining_ms: self.rate_limit_until_ms - now_ms,
                });
            }
            // Cooldown passed: transition to Locked and allow trying PIN again
            self.transition_to(SecureGuardState::Locked, now_ms)?;
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
            let mut candidate_verifier =
                derive_verifier(pin, &self.pin_salt, self.policy.pbkdf2_iterations);
            let valid = constant_time_eq_32(&candidate_verifier, &self.pin_verifier);
            candidate_verifier.zeroize();

            if valid {
                self.failed_attempts = 0;
                self.rate_limit_until_ms = 0;
                let _ = self.transition_to(SecureGuardState::Locked, now_ms);
                self.transition_to(SecureGuardState::Authenticating, now_ms)?;
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

                return Ok(());
            }

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
                    let delay_ms = 15_000;
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
            if now_ms < self.rate_limit_until_ms {
                return Err(SecureGuardError::RateLimited {
                    remaining_ms: self.rate_limit_until_ms - now_ms,
                });
            }
            // Cooldown passed: transition to Locked and allow trying PIN again
            self.transition_to(SecureGuardState::Locked, now_ms)?;
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
            let mut candidate_verifier =
                derive_verifier(pin, &self.pin_salt, self.policy.pbkdf2_iterations);
            let valid = constant_time_eq_32(&candidate_verifier, &self.pin_verifier);
            candidate_verifier.zeroize();

            if valid {
                self.failed_attempts = 0;
                self.rate_limit_until_ms = 0;
                let _ = self.transition_to(SecureGuardState::Locked, now_ms);
                self.transition_to(SecureGuardState::Authenticating, now_ms)?;
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

                return Ok(());
            }

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
                    let delay_ms = 15_000;
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

    /// Immediately terminates any active session or penalty and transitions to Locked.
    pub fn lock_now(&mut self, now_ms: u64) -> Result<(), SecureGuardError> {
        self.session_expires_at_ms = 0;
        self.rate_limit_until_ms = 0;
        self.failed_attempts = 0;

        match self.state {
            SecureGuardState::Unlocked
            | SecureGuardState::Authenticating
            | SecureGuardState::RateLimited
            | SecureGuardState::RecoveryRequired
            | SecureGuardState::Locked => {
                let from = self.state;
                if from != SecureGuardState::Locked {
                    let _ = self.transition_to(SecureGuardState::Locked, now_ms);
                }
                self.audit_log.push(
                    now_ms,
                    SecureGuardAuditEventType::SessionExpired {
                        reason: SessionExpiryReason::ManualLock,
                    },
                );
            }
            _ => {}
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

        // Re-seal the rescue envelope under the rotated code while it is in
        // hand; the previous envelope is superseded along with the old code.
        if let Ok(envelope) = SecureGuardRecoveryEnvelope::seal(
            &rotated_code,
            &new_recovery_salt,
            &new_pin_salt,
            &new_pin_verifier,
            self.policy.pbkdf2_iterations,
        ) {
            self.recovery_envelope = Some(envelope);
        }

        self.transition_to(SecureGuardState::Locked, now_ms)?;
        self.audit_log
            .push(now_ms, SecureGuardAuditEventType::RecoverySuccess);

        Ok(SecureGuardState::Locked)
    }

    /// Returns the cached device-key-independent recovery envelope bytes.
    ///
    /// Firmware must persist these in a **separate NVS blob outside the
    /// device-key envelope** (plaintext + internal CRC, e.g. `sg_recovery_v1`)
    /// at provision / rotation time. `None` when no envelope was sealed yet
    /// (e.g. engines restored from the 256-byte record after a reboot, until
    /// `recover_with_envelope` or `refresh_recovery_envelope` rebuilds it).
    /// Absent envelope is reported as `None`, never as empty bytes.
    pub fn recovery_envelope_bytes(&self) -> Option<[u8; RECOVERY_ENVELOPE_SIZE]> {
        self.recovery_envelope.as_ref().map(|env| env.to_bytes())
    }

    /// Rebuilds the cached recovery envelope from the live verifiers.
    ///
    /// Used after [`Self::change_pin`] (which the envelope cannot otherwise
    /// observe) whenever the recovery code is available. Verifies the code in
    /// constant time against the stored verifier first; KDF strength is never
    /// weakened. Returns fresh envelope bytes for NVS persistence.
    ///
    /// The seal reuses the iteration count bound to the live material (carried
    /// by the cached envelope when present): re-wrapping must not silently
    /// rebind material to a different KDF count.
    pub fn refresh_recovery_envelope(
        &mut self,
        recovery_code: &[u8],
    ) -> Result<[u8; RECOVERY_ENVELOPE_SIZE], SecureGuardError> {
        if self.state == SecureGuardState::ErrorLocked {
            return Err(SecureGuardError::InvalidStateForOperation {
                current: self.state,
                expected: "Locked",
            });
        }
        if !self.is_provisioned {
            return Err(SecureGuardError::NotProvisioned);
        }

        let mut candidate = derive_verifier(
            recovery_code,
            &self.recovery_salt,
            self.policy.pbkdf2_iterations,
        );
        let valid = constant_time_eq_32(&candidate, &self.recovery_verifier);
        candidate.zeroize();
        if !valid {
            return Err(SecureGuardError::InvalidRecoveryCode);
        }

        let iterations = self
            .recovery_envelope
            .as_ref()
            .map(|env| env.pbkdf2_iterations)
            .unwrap_or(self.policy.pbkdf2_iterations);
        let envelope = SecureGuardRecoveryEnvelope::seal(
            recovery_code,
            &self.recovery_salt,
            &self.pin_salt,
            &self.pin_verifier,
            iterations,
        )?;
        let bytes = envelope.to_bytes();
        self.recovery_envelope = Some(envelope);
        Ok(bytes)
    }

    /// Recovers provisioned state from the device-key-independent envelope.
    ///
    /// This is the DEV-reboot rescue: after ephemeral device keys rotate, the
    /// NVS `sg_record` bytes are undecryptable and the engine boots
    /// `ErrorLocked` with zeroed verifiers. Given the recovery code captured
    /// at provision time plus the separately-stored envelope bytes, this
    /// re-authenticates the code (constant time, no device key involved),
    /// restores the provision-time credential material, and returns to
    /// `Locked` — the original PIN then unlocks the session. Never weakens
    /// KDF iterations; tampered envelopes and wrong codes fail closed.
    ///
    /// The envelope's authentic (KEK-bound) iteration count is adopted into
    /// the live policy: verifiers are meaningless without the count that
    /// created them, and the count cannot be forged without the code.
    pub fn recover_with_envelope(
        &mut self,
        recovery_code: &[u8],
        envelope_bytes: &[u8; RECOVERY_ENVELOPE_SIZE],
        now_ms: u64,
    ) -> Result<SecureGuardState, SecureGuardError> {
        let envelope = SecureGuardRecoveryEnvelope::from_bytes(envelope_bytes)?;

        let (pin_salt, pin_verifier) =
            envelope.verify_and_unwrap(recovery_code).inspect_err(|_| {
                self.failed_attempts = self.failed_attempts.saturating_add(1);
                self.audit_log.push(
                    now_ms,
                    SecureGuardAuditEventType::RecoveryFailed {
                        failed_attempts: self.failed_attempts,
                    },
                );
            })?;

        // Rebuild live state from the envelope. The iteration count travels
        // with the material (see above); the stored recovery verifier is then
        // recomputed in the crate-standard PBKDF2 form so later
        // `recover_with_code` / `refresh` calls keep working with the same
        // code under the adopted count.
        self.policy.pbkdf2_iterations = envelope.pbkdf2_iterations;
        let recovery_verifier = derive_verifier(
            recovery_code,
            &envelope.recovery_salt,
            self.policy.pbkdf2_iterations,
        );
        self.pin_salt = pin_salt;
        self.pin_verifier = pin_verifier;
        self.recovery_salt = envelope.recovery_salt;
        self.recovery_verifier = recovery_verifier;
        self.is_provisioned = true;
        self.failed_attempts = 0;
        self.rate_limit_until_ms = 0;
        self.session_expires_at_ms = 0;
        self.last_rotated_recovery_code = None;
        self.recovery_envelope = Some(envelope);

        if self.state == SecureGuardState::Unprovisioned {
            self.transition_to(SecureGuardState::Provisioning, now_ms)?;
        }
        self.transition_to(SecureGuardState::Locked, now_ms)?;
        self.audit_log
            .push(now_ms, SecureGuardAuditEventType::RecoverySuccess);

        Ok(SecureGuardState::Locked)
    }

    /// Returns the DEV-only cached recovery-code blob for NVS persistence.
    ///
    /// Compiled ONLY under `test-mode`. Encodes the last recovery code issued
    /// at provision / rotation (`recover_with_code`) so firmware can persist
    /// it in a separate plaintext NVS blob outside the device-key envelope.
    /// `None` when no code is cached (absent cache is `None`, never zeroes).
    /// Release builds contain no such path.
    #[cfg(feature = "test-mode")]
    pub fn dev_recovery_code_blob_bytes(
        &self,
    ) -> Option<[u8; super::dev_recovery_cache::DEV_RECOVERY_CODE_BLOB_SIZE]> {
        self.last_rotated_recovery_code
            .map(|code| super::dev_recovery_cache::DevRecoveryCodeCache::new(code).to_bytes())
    }

    /// DEV-ONLY single-attempt automatic recovery from the on-device code cache.
    ///
    /// Compiled ONLY under `#[cfg(feature = "test-mode")]`; release builds
    /// contain no such path (any release reference is a compile error).
    /// NEVER enable outside `test-mode`: release uses eFuse-provisioned keys
    /// and eFuse burns require an explicit owner ceremony. This method performs
    /// NO eFuse operation of any kind.
    ///
    /// Requires `ErrorLocked`; parses the cached-code blob, then attempts one
    /// `recover_with_envelope` using the cached code. Audit-logged as
    /// dev-auto-recovery (`DevAutoRecovery { success }`, no secrets). A wrong
    /// or tampered cache fails closed to normal `ErrorLocked` with no retry
    /// loop — the caller must not loop on failure.
    #[cfg(feature = "test-mode")]
    pub fn try_dev_auto_recover(
        &mut self,
        code_blob: &[u8; super::dev_recovery_cache::DEV_RECOVERY_CODE_BLOB_SIZE],
        envelope_bytes: &[u8; RECOVERY_ENVELOPE_SIZE],
        now_ms: u64,
    ) -> Result<SecureGuardState, SecureGuardError> {
        if self.state != SecureGuardState::ErrorLocked {
            return Err(SecureGuardError::InvalidStateForOperation {
                current: self.state,
                expected: "ErrorLocked",
            });
        }
        let mut code = match super::dev_recovery_cache::DevRecoveryCodeCache::from_bytes(code_blob)
        {
            Ok(cache) => cache.code(),
            Err(err) => {
                self.audit_log.push(
                    now_ms,
                    SecureGuardAuditEventType::DevAutoRecovery { success: false },
                );
                return Err(err);
            }
        };
        let res = self.recover_with_envelope(&code, envelope_bytes, now_ms);
        code.zeroize();
        match res {
            Ok(state) => {
                self.audit_log.push(
                    now_ms,
                    SecureGuardAuditEventType::DevAutoRecovery { success: true },
                );
                Ok(state)
            }
            Err(err) => {
                self.audit_log.push(
                    now_ms,
                    SecureGuardAuditEventType::DevAutoRecovery { success: false },
                );
                Err(err)
            }
        }
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
            // A real wipe destroys the rescue path too; otherwise the wiped
            // credentials could be resurrected from the cached envelope.
            self.recovery_envelope = None;
        }

        self.audit_log.push(
            now_ms,
            SecureGuardAuditEventType::WipeCompleted { simulated },
        );

        self.transition_to(SecureGuardState::Unprovisioned, now_ms)?;
        Ok(SecureGuardWipeScope::ProtectedResourcesOnly)
    }

    /// Unconditionally resets the engine back to factory fresh Unprovisioned state.
    ///
    /// Clears all credentials, salts, verifiers, rate limits, session timers,
    /// failed attempt counters, and paired BLE proximity devices.
    pub fn reset_to_factory(&mut self) {
        self.pin_salt.zeroize();
        self.pin_verifier.zeroize();
        self.recovery_salt.zeroize();
        self.recovery_verifier.zeroize();
        self.is_provisioned = false;
        self.failed_attempts = 0;
        self.rate_limit_until_ms = 0;
        self.session_expires_at_ms = 0;
        self.last_activity_ms = 0;
        self.last_wipe_simulated = false;
        self.last_rotated_recovery_code = None;
        self.recovery_envelope = None;
        self.paired_ble_mac = [0u8; 6];
        self.paired_ble_name = [0u8; 24];
        self.ble_proximity_registered = false;
        self.ble_proximity_away = false;
        self.state = SecureGuardState::Unprovisioned;
        self.audit_log.push(
            0,
            SecureGuardAuditEventType::WipeCompleted { simulated: false },
        );
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
        let check =
            super::glitch_guard::double_check_authorization(authorized, authorized_inv, jitter)?;
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
        let check =
            super::glitch_guard::double_check_authorization(authorized, authorized_inv, jitter)?;
        if !check.is_true() {
            return Err(SecureGuardError::AccessDeniedLocked {
                state: self.state,
                opcode,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::recovery::RECOVERY_ENVELOPE_SIZE;
    use super::*;

    const TEST_PIN: &[u8] = b"4927";
    const TEST_PIN_SALT: [u8; 16] = [0x10; 16];
    const TEST_REC_SALT: [u8; 16] = [0x20; 16];

    fn test_policy() -> SecureGuardPolicy {
        SecureGuardPolicy {
            pbkdf2_iterations: 10,
            ..Default::default()
        }
    }

    /// Host reboot simulation for the DEV (no-eFuse) production symptom:
    /// every reboot mints fresh ephemeral device keys, so the NVS `sg_record`
    /// bytes can no longer be opened and firmware boots `ErrorLocked`.
    /// Provision, capture the recovery code + the separately-stored envelope,
    /// reboot into `ErrorLocked`, rescue with code + envelope, and prove the
    /// engine ends provisioned + unlocked with the original credentials — with
    /// no device key involved at any step.
    #[test]
    fn test_dev_reboot_recovery_with_code_no_device_key() {
        // 1. Provision and capture code + both NVS artifacts.
        let mut engine = SecureGuardEngine::new(test_policy());
        let rec_code = engine
            .provision_pin(TEST_PIN, TEST_PIN_SALT, b"", TEST_REC_SALT, 1000)
            .expect("provision");
        let record_bytes = engine.to_persistent_record().to_bytes();
        let envelope_bytes = engine
            .recovery_envelope_bytes()
            .expect("envelope sealed at provision");
        // KDF params travel inside the envelope, never weakened.
        assert_eq!(
            SecureGuardRecoveryEnvelope::from_bytes(&envelope_bytes)
                .unwrap()
                .pbkdf2_iterations,
            10
        );

        // 2. Control: same device keys (healthy reboot) restores Locked.
        let healthy = SecureGuardEngine::from_persisted_bytes(&record_bytes, 1500);
        assert_eq!(healthy.state(), SecureGuardState::Locked);
        assert!(healthy.is_provisioned());

        // 3. Fresh ephemeral device keys + same NVS bytes: the device-key
        // envelope cannot be opened -> firmware boots ErrorLocked with zeroed
        // verifiers (simulated here with undecryptable bytes).
        let mut rescued = SecureGuardEngine::from_persisted_bytes(&[0xFF; 256], 1500);
        assert_eq!(rescued.state(), SecureGuardState::ErrorLocked);
        assert!(rescued.is_provisioned());
        // The pre-existing code path cannot rescue: nothing to check against.
        assert!(matches!(
            rescued.recover_with_code(&rec_code, b"7412", [0x40; 16], 1600),
            Err(SecureGuardError::InvalidStateForOperation { .. })
        ));

        // 4. Rescue with code + envelope (no device key): back to Locked...
        assert_eq!(
            rescued
                .recover_with_envelope(&rec_code, &envelope_bytes, 1600)
                .unwrap(),
            SecureGuardState::Locked
        );
        assert_eq!(rescued.state(), SecureGuardState::Locked);
        assert!(rescued.is_provisioned());

        // 5. ...and the ORIGINAL credentials unlock the session.
        rescued
            .unlock_with_pin(TEST_PIN, 1700)
            .expect("original PIN");
        assert_eq!(rescued.state(), SecureGuardState::Unlocked);
        assert!(rescued.is_unlocked());
    }

    #[test]
    fn test_recover_with_envelope_rejects_wrong_code_and_tamper() {
        let mut engine = SecureGuardEngine::new(test_policy());
        let rec_code = engine
            .provision_pin(TEST_PIN, TEST_PIN_SALT, b"", TEST_REC_SALT, 1000)
            .unwrap();
        let envelope_bytes = engine.recovery_envelope_bytes().unwrap();

        // Wrong code from ErrorLocked: fail closed, stays ErrorLocked.
        let mut rebooted = SecureGuardEngine::from_persisted_bytes(&[0xFF; 256], 1500);
        assert_eq!(
            rebooted.recover_with_envelope(b"wrong-code-000000", &envelope_bytes, 1600),
            Err(SecureGuardError::InvalidRecoveryCode)
        );
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);
        assert_eq!(rebooted.failed_attempts(), 1);

        // Tampered envelope (valid CRC, broken KEK tag) with the RIGHT code:
        // still fail closed.
        let mut tampered = envelope_bytes;
        tampered[70] ^= 0xFF;
        let crc = super::super::crypto::crc32(&tampered[0..142]);
        tampered[142..146].copy_from_slice(&crc.to_be_bytes());
        let mut rebooted2 = SecureGuardEngine::from_persisted_bytes(&[0xFF; 256], 1500);
        assert_eq!(
            rebooted2.recover_with_envelope(&rec_code, &tampered, 1600),
            Err(SecureGuardError::InvalidRecoveryCode)
        );
        assert_eq!(rebooted2.state(), SecureGuardState::ErrorLocked);
    }

    #[test]
    fn test_recovery_envelope_refresh_after_pin_change() {
        let mut engine = SecureGuardEngine::new(test_policy());
        let rec_code = engine
            .provision_pin(TEST_PIN, TEST_PIN_SALT, b"", TEST_REC_SALT, 1000)
            .unwrap();
        let stale = engine.recovery_envelope_bytes().unwrap();

        // Change PIN, then refresh the envelope while the code is available.
        engine
            .change_pin(TEST_PIN, b"9182", [0x30; 16], 2000)
            .unwrap();
        // change_pin cannot re-wrap without the code: the cached envelope is
        // untouched (still rescues to the provision-time PIN below).
        assert_eq!(engine.recovery_envelope_bytes().unwrap(), stale);
        let fresh = engine.refresh_recovery_envelope(&rec_code).unwrap();
        assert_ne!(fresh, stale);

        // Reboot into ErrorLocked, rescue, unlock with the NEW PIN.
        let mut rebooted = SecureGuardEngine::from_persisted_bytes(&[0xFF; 256], 2500);
        rebooted
            .recover_with_envelope(&rec_code, &fresh, 2600)
            .unwrap();
        rebooted.unlock_with_pin(b"9182", 2700).expect("new PIN");
        assert_eq!(rebooted.state(), SecureGuardState::Unlocked);

        // Without a refresh, the stale envelope still rescues (durable rescue
        // to the provision-time credentials), proving the code path itself
        // never depended on the changed PIN.
        let mut rebooted_stale = SecureGuardEngine::from_persisted_bytes(&[0xFF; 256], 2500);
        rebooted_stale
            .recover_with_envelope(&rec_code, &stale, 2600)
            .unwrap();
        rebooted_stale
            .unlock_with_pin(TEST_PIN, 2700)
            .expect("old PIN");
        assert_eq!(rebooted_stale.state(), SecureGuardState::Unlocked);

        // Refresh with a wrong code is rejected and keeps the cached envelope.
        let before = engine.recovery_envelope_bytes().unwrap();
        assert_eq!(
            engine.refresh_recovery_envelope(b"wrong-code-000000"),
            Err(SecureGuardError::InvalidRecoveryCode)
        );
        assert_eq!(engine.recovery_envelope_bytes().unwrap(), before);
    }

    #[test]
    fn test_recover_with_envelope_from_healthy_locked_and_unprovisioned() {
        let mut engine = SecureGuardEngine::new(test_policy());
        let rec_code = engine
            .provision_pin(TEST_PIN, TEST_PIN_SALT, b"", TEST_REC_SALT, 1000)
            .unwrap();
        let envelope_bytes: [u8; RECOVERY_ENVELOPE_SIZE] =
            engine.recovery_envelope_bytes().unwrap();

        // Healthy Locked engine: envelope rescue also works (same outcome).
        engine
            .recover_with_envelope(&rec_code, &envelope_bytes, 1500)
            .unwrap();
        assert_eq!(engine.state(), SecureGuardState::Locked);
        engine.unlock_with_pin(TEST_PIN, 1600).unwrap();
        assert_eq!(engine.state(), SecureGuardState::Unlocked);

        // Factory-fresh engine (e.g. after a firmware update wiped RAM and the
        // record): envelope + code re-provisions to Locked with the original
        // PIN, even under a different live policy iteration count.
        let mut fresh = SecureGuardEngine::new(SecureGuardPolicy {
            pbkdf2_iterations: 12,
            ..Default::default()
        });
        assert_eq!(fresh.state(), SecureGuardState::Unprovisioned);
        assert_eq!(fresh.recovery_envelope_bytes(), None);
        fresh
            .recover_with_envelope(&rec_code, &envelope_bytes, 1700)
            .unwrap();
        assert_eq!(fresh.state(), SecureGuardState::Locked);
        assert!(fresh.is_provisioned());
        fresh.unlock_with_pin(TEST_PIN, 1800).unwrap();
        assert_eq!(fresh.state(), SecureGuardState::Unlocked);
    }

    #[test]
    fn test_wipe_destroys_cached_envelope() {
        let mut engine = SecureGuardEngine::new(SecureGuardPolicy {
            pbkdf2_iterations: 10,
            test_mode_non_destructive_wipe: false,
            ..Default::default()
        });
        engine
            .provision_pin(TEST_PIN, TEST_PIN_SALT, b"", TEST_REC_SALT, 1000)
            .unwrap();
        assert!(engine.recovery_envelope_bytes().is_some());

        engine.execute_wipe(2000).ok();
        assert_eq!(engine.state(), SecureGuardState::Unprovisioned);
        // Rescue material is gone with the wipe: no resurrection.
        assert_eq!(engine.recovery_envelope_bytes(), None);
    }

    /// DEV reboot -> auto-recover -> unlocked with the ORIGINAL PIN.
    ///
    /// Provision captures the code blob + envelope (both persisted outside the
    /// device-key envelope in test-mode builds); a reboot with rotated device
    /// keys boots `ErrorLocked`; a single `try_dev_auto_recover` restores
    /// `Locked` and the original PIN unlocks the session. Audit-logged as
    /// dev-auto-recovery. No eFuse operation is involved at any step.
    #[cfg(feature = "test-mode")]
    #[test]
    fn test_dev_reboot_auto_recover_unlocks_with_original_pin() {
        use super::super::audit::SecureGuardAuditEventType;
        use super::super::dev_recovery_cache::DevRecoveryCodeCache;

        let mut engine = SecureGuardEngine::new(test_policy());
        let rec_code = engine
            .provision_pin(TEST_PIN, TEST_PIN_SALT, b"", TEST_REC_SALT, 1000)
            .expect("provision");
        let code_blob = engine
            .dev_recovery_code_blob_bytes()
            .expect("DEV code blob cached at provision");
        assert_eq!(
            DevRecoveryCodeCache::from_bytes(&code_blob).unwrap().code(),
            rec_code
        );
        let envelope_bytes = engine.recovery_envelope_bytes().expect("envelope");

        // Reboot with rotated device keys: undecryptable record -> ErrorLocked.
        let mut rebooted = SecureGuardEngine::from_persisted_bytes(&[0xFF; 256], 1500);
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);

        // Single auto-recovery attempt using the on-device cached code.
        assert_eq!(
            rebooted
                .try_dev_auto_recover(&code_blob, &envelope_bytes, 1600)
                .unwrap(),
            SecureGuardState::Locked
        );
        assert_eq!(rebooted.state(), SecureGuardState::Locked);
        assert!(matches!(
            rebooted.audit_log().last().map(|e| &e.event_type),
            Some(SecureGuardAuditEventType::DevAutoRecovery { success: true })
        ));

        // The ORIGINAL PIN unlocks the session.
        rebooted
            .unlock_with_pin(TEST_PIN, 1700)
            .expect("original PIN");
        assert_eq!(rebooted.state(), SecureGuardState::Unlocked);
        assert!(rebooted.is_unlocked());
    }

    /// Tampered or wrong DEV cache stays `ErrorLocked`: no rescue, no retry.
    #[cfg(feature = "test-mode")]
    #[test]
    fn test_dev_auto_recover_tampered_cache_stays_error_locked() {
        use super::super::audit::SecureGuardAuditEventType;
        use super::super::dev_recovery_cache::{DevRecoveryCodeCache, DEV_RECOVERY_CODE_BLOB_SIZE};

        let mut engine = SecureGuardEngine::new(test_policy());
        engine
            .provision_pin(TEST_PIN, TEST_PIN_SALT, b"", TEST_REC_SALT, 1000)
            .unwrap();
        let code_blob = engine.dev_recovery_code_blob_bytes().unwrap();
        let envelope_bytes = engine.recovery_envelope_bytes().unwrap();

        // 1. Tampered code blob (broken CRC, no fix): parse fails closed.
        let mut tampered_blob = code_blob;
        tampered_blob[12] ^= 0xFF;
        let mut rebooted = SecureGuardEngine::from_persisted_bytes(&[0xFF; 256], 1500);
        assert!(rebooted
            .try_dev_auto_recover(&tampered_blob, &envelope_bytes, 1600)
            .is_err());
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);
        assert!(matches!(
            rebooted.audit_log().last().map(|e| &e.event_type),
            Some(SecureGuardAuditEventType::DevAutoRecovery { success: false })
        ));
        assert!(rebooted.unlock_with_pin(TEST_PIN, 1700).is_err());

        // 2. Well-formed blob for the WRONG code: KEK check fails closed.
        let wrong_blob = DevRecoveryCodeCache::new([0x77u8; 16]).to_bytes();
        assert_eq!(wrong_blob.len(), DEV_RECOVERY_CODE_BLOB_SIZE);
        let mut rebooted2 = SecureGuardEngine::from_persisted_bytes(&[0xFF; 256], 1500);
        assert_eq!(
            rebooted2.try_dev_auto_recover(&wrong_blob, &envelope_bytes, 1600),
            Err(SecureGuardError::InvalidRecoveryCode)
        );
        assert_eq!(rebooted2.state(), SecureGuardState::ErrorLocked);

        // 3. Tampered envelope with the RIGHT code: tag check fails closed.
        let mut tampered_env = envelope_bytes;
        tampered_env[70] ^= 0xFF;
        let crc = super::super::crypto::crc32(&tampered_env[0..142]);
        tampered_env[142..146].copy_from_slice(&crc.to_be_bytes());
        let mut rebooted3 = SecureGuardEngine::from_persisted_bytes(&[0xFF; 256], 1500);
        assert_eq!(
            rebooted3.try_dev_auto_recover(&code_blob, &tampered_env, 1600),
            Err(SecureGuardError::InvalidRecoveryCode)
        );
        assert_eq!(rebooted3.state(), SecureGuardState::ErrorLocked);
    }

    /// Release-build proof: no auto-recovery path exists without `test-mode`.
    ///
    /// Without the cached code, an `ErrorLocked` engine fails closed: an
    /// attempt without a code is rejected and the state never leaves
    /// `ErrorLocked`. (`try_dev_auto_recover` does not exist in this build;
    /// any reference to it is a compile error.)
    #[cfg(not(feature = "test-mode"))]
    #[test]
    fn test_release_build_has_no_dev_auto_recovery() {
        // Compile-time gate proof, not a runtime check: fails the build if
        // `test-mode` ever leaks into a release configuration.
        const { assert!(!cfg!(feature = "test-mode")) };
        let mut engine = SecureGuardEngine::new(test_policy());
        engine
            .provision_pin(TEST_PIN, TEST_PIN_SALT, b"", TEST_REC_SALT, 1000)
            .unwrap();
        let envelope_bytes = engine.recovery_envelope_bytes().unwrap();

        let mut rebooted = SecureGuardEngine::from_persisted_bytes(&[0xFF; 256], 1500);
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);
        // Attempt without a code fails closed; no rescue, no transition.
        assert_eq!(
            rebooted.recover_with_envelope(b"", &envelope_bytes, 1600),
            Err(SecureGuardError::InvalidRecoveryCode)
        );
        assert_eq!(rebooted.state(), SecureGuardState::ErrorLocked);
        assert!(rebooted.unlock_with_pin(TEST_PIN, 1700).is_err());
    }
}
