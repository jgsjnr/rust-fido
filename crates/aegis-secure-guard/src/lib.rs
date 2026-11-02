//! Secure Guard Subsystem
//!
//! Hardened Zero-Trust authority for cryptographic assets (Web3 Wallets, On-Device Keys, OATH)
//! with formal 10-state lifecycle, PBKDF2 verifiers, progressive backoff rate-limiting,
//! strict 5-attempt lockout/wipe enforcement, autonomous firmware session authority, and
//! non-blocking passkey FIDO2 coexistence.

#![no_std]
extern crate alloc;

pub mod audit;
pub mod crypto;
pub mod engine;
pub mod error;
pub mod glitch_guard;
pub mod persistence;
pub mod policy;
pub mod resource;
pub mod secure_channel;
pub mod state;

pub use audit::{
    AuditRingBuffer, SecureGuardAuditEvent, SecureGuardAuditEventType, SessionExpiryReason,
    AUDIT_LOG_CAPACITY,
};
pub use crypto::{
    constant_time_eq_32, crc32, derive_verifier, derive_verifier_hardware_anchored, hkdf_sha256, hmac_sha256,
    pbkdf2_hmac_sha256, HardwareHmacPeripheral, SimulatedDevHardwareHmac,
    DO_NOT_BURN_EFUSE_BLOCK7_WARNING, PBKDF2_DEFAULT_ITERATIONS,
};
pub use engine::SecureGuardEngine;
pub use error::SecureGuardError;
pub use glitch_guard::{double_check_authorization, GlitchResistantBool};
pub use persistence::{
    SecureGuardPersistentRecord, PERSISTENCE_MAGIC, PERSISTENCE_VERSION, PERSISTENT_RECORD_SIZE,
};
pub use policy::{SecureGuardPolicy, MAX_ATTEMPTS};
pub use resource::{
    ProtectedResourceClass, SecureGuardAdminOp, SecureGuardWipeScope, OP_KEY_DELETE,
    OP_KEY_GEN_ONDEVICE, OP_KEY_IMPORT_ENVELOPE, OP_KEY_LIST, OP_OATH_CODE, OP_OATH_DELETE,
    OP_OATH_LIST, OP_OATH_PUT, OP_SECURE_GUARD_CONFIG, OP_SECURE_GUARD_LOCK,
    OP_SECURE_GUARD_STATUS, OP_SECURE_GUARD_UNLOCK, OP_SECURE_GUARD_WIPE_SELECTIVE, OP_WALLET_ADDR,
    OP_WALLET_GEN, OP_WALLET_LIST,
};
pub use secure_channel::{
    SealedPinPayload, SecureGuardEcdhChannel, SECURE_CHANNEL_HKDF_INFO, SECURE_CHANNEL_HKDF_SALT,
};
pub use state::SecureGuardState;

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SALT_PIN: [u8; 16] = [0x10; 16];
    const TEST_SALT_REC: [u8; 16] = [0x20; 16];
    const TEST_PIN: &[u8] = b"4927";
    const TEST_WRONG_PIN: &[u8] = b"8301";

    fn create_test_engine() -> (SecureGuardEngine, [u8; 16]) {
        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10, // Fast for unit tests
            ..Default::default()
        };
        let mut engine = SecureGuardEngine::new(policy);
        let rec_code = engine
            .provision_pin(TEST_PIN, TEST_SALT_PIN, b"", TEST_SALT_REC, 1000)
            .expect("provision should succeed");
        (engine, rec_code)
    }

    #[test]
    fn test_provision_valid_and_invalid_pins() {
        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            reject_trivial_pins: true,
            ..Default::default()
        };
        let mut engine = SecureGuardEngine::new(policy);

        assert_eq!(engine.state(), SecureGuardState::Unprovisioned);

        // Invalid: too short
        let err = engine.provision_pin(b"12", TEST_SALT_PIN, b"", TEST_SALT_REC, 1000);
        assert!(matches!(err, Err(SecureGuardError::PinTooShort { .. })));
        assert_eq!(engine.state(), SecureGuardState::Unprovisioned);

        // Invalid: trivial repeating
        let err = engine.provision_pin(b"1111", TEST_SALT_PIN, b"", TEST_SALT_REC, 1000);
        assert!(matches!(err, Err(SecureGuardError::TrivialPinRejected)));
        assert_eq!(engine.state(), SecureGuardState::Unprovisioned);

        // Invalid: sequential
        let err = engine.provision_pin(b"1234", TEST_SALT_PIN, b"", TEST_SALT_REC, 1000);
        assert!(matches!(err, Err(SecureGuardError::TrivialPinRejected)));
        assert_eq!(engine.state(), SecureGuardState::Unprovisioned);

        // Valid PIN
        let rec_code = engine
            .provision_pin(TEST_PIN, TEST_SALT_PIN, b"", TEST_SALT_REC, 1000)
            .unwrap();
        assert_eq!(rec_code.len(), 16);
        assert_eq!(engine.state(), SecureGuardState::Locked);
        assert!(engine.is_provisioned());

        // Already provisioned error
        let err2 = engine.provision_pin(b"5829", TEST_SALT_PIN, b"", TEST_SALT_REC, 1000);
        assert!(matches!(err2, Err(SecureGuardError::AlreadyProvisioned)));
    }

    #[test]
    fn test_unlock_correct_and_incorrect_pin() {
        let (mut engine, _) = create_test_engine();

        // 1. Wrong PIN attempt 1 (0 ms backoff)
        let res1 = engine.unlock_with_pin(TEST_WRONG_PIN, 2000);
        assert!(matches!(
            res1,
            Err(SecureGuardError::InvalidPin {
                remaining_attempts: 4
            })
        ));
        assert_eq!(engine.failed_attempts(), 1);
        assert_eq!(engine.state(), SecureGuardState::Locked);

        // 2. Correct PIN resets failed_attempts and unlocks session
        assert!(engine.unlock_with_pin(TEST_PIN, 2100).is_ok());
        assert_eq!(engine.state(), SecureGuardState::Unlocked);
        assert_eq!(engine.failed_attempts(), 0);
        assert!(engine.is_unlocked());
    }

    #[test]
    fn test_five_failures_to_recovery_required() {
        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            wipe_on_5_failures: false,
            ..Default::default()
        };
        let mut engine = SecureGuardEngine::new(policy);
        engine
            .provision_pin(TEST_PIN, TEST_SALT_PIN, b"", TEST_SALT_REC, 1000)
            .unwrap();

        let mut time = 2000u64;

        // Failure 1: delay 0ms
        let err1 = engine.unlock_with_pin(TEST_WRONG_PIN, time);
        assert!(matches!(
            err1,
            Err(SecureGuardError::InvalidPin {
                remaining_attempts: 4
            })
        ));
        assert_eq!(engine.state(), SecureGuardState::Locked);

        // Failure 2: delay 2000ms
        time += 100;
        let err2 = engine.unlock_with_pin(TEST_WRONG_PIN, time);
        assert!(matches!(
            err2,
            Err(SecureGuardError::RateLimited { remaining_ms: 2000 })
        ));
        assert_eq!(engine.state(), SecureGuardState::RateLimited);

        // Attempt with wrong PIN during rate limit is rejected immediately
        let early_err = engine.unlock_with_pin(TEST_WRONG_PIN, time + 500);
        assert!(matches!(
            early_err,
            Err(SecureGuardError::RateLimited { .. })
        ));

        // Advance past delay 2000ms
        time += 2500;

        // Failure 3: delay 5000ms
        let err3 = engine.unlock_with_pin(TEST_WRONG_PIN, time);
        assert!(matches!(
            err3,
            Err(SecureGuardError::RateLimited { remaining_ms: 5000 })
        ));
        assert_eq!(engine.state(), SecureGuardState::RateLimited);

        // Advance past delay 5000ms
        time += 5500;

        // Failure 4: delay 15000ms
        let err4 = engine.unlock_with_pin(TEST_WRONG_PIN, time);
        assert!(matches!(
            err4,
            Err(SecureGuardError::RateLimited {
                remaining_ms: 15000
            })
        ));
        assert_eq!(engine.state(), SecureGuardState::RateLimited);

        // Advance past delay 15000ms
        time += 15500;

        // Failure 5: triggers 15-second RateLimited (NEVER locks forever!)
        let err5 = engine.unlock_with_pin(TEST_WRONG_PIN, time);
        assert!(matches!(
            err5,
            Err(SecureGuardError::RateLimited { remaining_ms: 15000 })
        ));
        assert_eq!(engine.state(), SecureGuardState::RateLimited);
        assert_eq!(engine.failed_attempts(), 5);

        // Subsequent attempt with wrong PIN within 15s is rate-limited
        let blocked = engine.unlock_with_pin(TEST_WRONG_PIN, time + 100);
        assert!(matches!(
            blocked,
            Err(SecureGuardError::RateLimited { .. })
        ));

        // After 15s cooldown, correct PIN unlocks!
        time += 15500;
        let unlocked = engine.unlock_with_pin(TEST_PIN, time);
        assert!(unlocked.is_ok());
        assert_eq!(engine.state(), SecureGuardState::Unlocked);
        assert_eq!(engine.failed_attempts(), 0);
    }

    #[test]
    fn test_five_failures_to_wipe_pending_and_scoped_wipe() {
        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            wipe_on_5_failures: true,
            test_mode_non_destructive_wipe: false,
            ..Default::default()
        };
        let mut engine = SecureGuardEngine::new(policy);
        engine
            .provision_pin(TEST_PIN, TEST_SALT_PIN, b"", TEST_SALT_REC, 1000)
            .unwrap();

        let mut time = 2000u64;
        for i in 1..=4 {
            let _ = engine.unlock_with_pin(TEST_WRONG_PIN, time);
            let backoff = match i {
                1 => 100,
                2 => 2500,
                3 => 5500,
                4 => 15500,
                _ => 100,
            };
            time += backoff;
        }

        // 5th failure triggers wipe
        let err5 = engine.unlock_with_pin(TEST_WRONG_PIN, time);
        assert!(matches!(
            err5,
            Err(SecureGuardError::MaxAttemptsWipeTriggered { simulated: false })
        ));

        // State is now Unprovisioned after wipe
        assert_eq!(engine.state(), SecureGuardState::Unprovisioned);
        assert!(!engine.is_provisioned());
        assert!(!engine.last_wipe_simulated());
    }

    #[test]
    fn test_test_mode_non_destructive_wipe() {
        let policy = SecureGuardPolicy {
            pbkdf2_iterations: 10,
            wipe_on_5_failures: true,
            test_mode_non_destructive_wipe: true, // Non-destructive test mode
            ..Default::default()
        };
        let mut engine = SecureGuardEngine::new(policy);
        engine
            .provision_pin(TEST_PIN, TEST_SALT_PIN, b"", TEST_SALT_REC, 1000)
            .unwrap();

        let mut time = 2000u64;
        for i in 1..=4 {
            let _ = engine.unlock_with_pin(TEST_WRONG_PIN, time);
            time += match i {
                1 => 100,
                2 => 2500,
                3 => 5500,
                4 => 15500,
                _ => 100,
            };
        }

        let err5 = engine.unlock_with_pin(TEST_WRONG_PIN, time);
        assert!(matches!(
            err5,
            Err(SecureGuardError::MaxAttemptsWipeTriggered { simulated: true })
        ));

        assert!(engine.last_wipe_simulated());
    }

    #[test]
    fn test_persistence_and_reboot_restoration() {
        let (mut engine, _) = create_test_engine();

        // 2 failed attempts
        let _ = engine.unlock_with_pin(TEST_WRONG_PIN, 2000);
        let _ = engine.unlock_with_pin(TEST_WRONG_PIN, 2100);
        assert_eq!(engine.failed_attempts(), 2);

        // Serialize persistent record
        let record = engine.to_persistent_record();
        let bytes = record.to_bytes();

        // Simulate reboot: restore engine from bytes at time 2500 (still within backoff 2000ms from 2100 -> until 4100)
        let restored = SecureGuardEngine::from_persisted_bytes(&bytes, 2500);
        assert_eq!(restored.failed_attempts(), 2);
        assert_eq!(restored.state(), SecureGuardState::RateLimited);

        // Simulate reboot after rate limit expired (time 5000): starts in Locked
        let restored_later = SecureGuardEngine::from_persisted_bytes(&bytes, 5000);
        assert_eq!(restored_later.failed_attempts(), 2);
        assert_eq!(restored_later.state(), SecureGuardState::Locked);

        // Now unlock engine, serialize while Unlocked
        engine.unlock_with_pin(TEST_PIN, 5000).unwrap();
        assert_eq!(engine.state(), SecureGuardState::Unlocked);

        let unlocked_bytes = engine.to_persistent_record().to_bytes();

        // Reboot: must NEVER restore as Unlocked; must always start in Locked!
        let rebooted_engine = SecureGuardEngine::from_persisted_bytes(&unlocked_bytes, 6000);
        assert_eq!(rebooted_engine.state(), SecureGuardState::Locked);
        assert!(!rebooted_engine.is_unlocked());
    }

    #[test]
    fn test_session_expiration_absolute_and_inactivity() {
        let (mut engine, _) = create_test_engine();
        engine.policy_mut().session_duration_ms = 300_000; // 5 min
        engine.policy_mut().inactivity_timeout_ms = 120_000; // 2 min

        engine.unlock_with_pin(TEST_PIN, 10_000).unwrap();
        assert_eq!(engine.state(), SecureGuardState::Unlocked);

        // Touch after 60s (< 120s inactivity): still unlocked
        assert_eq!(engine.check_and_touch_session(70_000), Ok(true));
        assert_eq!(engine.state(), SecureGuardState::Unlocked);

        // Touch after 130s of inactivity (> 120s): expires by inactivity!
        assert_eq!(engine.check_and_touch_session(200_000), Ok(false));
        assert_eq!(engine.state(), SecureGuardState::Locked);

        // Unlock again at 210_000
        engine.unlock_with_pin(TEST_PIN, 210_000).unwrap();
        assert_eq!(engine.state(), SecureGuardState::Unlocked);

        // Continuous activity touches
        assert_eq!(engine.check_and_touch_session(300_000), Ok(true));
        assert_eq!(engine.check_and_touch_session(400_000), Ok(true));

        // Absolute duration expires at 210_000 + 300_000 = 510_000
        assert_eq!(engine.check_and_touch_session(510_001), Ok(false));
        assert_eq!(engine.state(), SecureGuardState::Locked);
    }

    #[test]
    fn test_lock_now_and_transport_disconnect() {
        let (mut engine, _) = create_test_engine();

        engine.unlock_with_pin(TEST_PIN, 1000).unwrap();
        assert!(engine.is_unlocked());

        engine.lock_now(2000).unwrap();
        assert_eq!(engine.state(), SecureGuardState::Locked);

        // Re-unlock
        engine.unlock_with_pin(TEST_PIN, 3000).unwrap();
        assert!(engine.is_unlocked());

        // Transport disconnect terminates session
        engine.on_transport_disconnect(4000).unwrap();
        assert_eq!(engine.state(), SecureGuardState::Locked);

        // Rate-limit can be cleared by lock_now
        let _ = engine.unlock_with_pin(TEST_WRONG_PIN, 5000);
        let _ = engine.unlock_with_pin(TEST_WRONG_PIN, 5100);
        assert_eq!(engine.state(), SecureGuardState::RateLimited);
        engine.lock_now(5200).unwrap();
        assert_eq!(engine.state(), SecureGuardState::Locked);
        assert_eq!(engine.failed_attempts(), 0);
        assert_eq!(engine.rate_limit_until_ms(), 0);

        // While RateLimited, correct PIN unlocks immediately
        let _ = engine.unlock_with_pin(TEST_WRONG_PIN, 6000);
        let _ = engine.unlock_with_pin(TEST_WRONG_PIN, 6100);
        assert_eq!(engine.state(), SecureGuardState::RateLimited);
        engine.unlock_with_pin(TEST_PIN, 6200).unwrap();
        assert_eq!(engine.state(), SecureGuardState::Unlocked);
        assert_eq!(engine.failed_attempts(), 0);
        assert_eq!(engine.rate_limit_until_ms(), 0);
    }

    #[test]
    fn test_transactional_change_pin() {
        let (mut engine, _) = create_test_engine();

        // 1. Wrong current PIN fails and preserves old PIN
        let err1 = engine.change_pin(TEST_WRONG_PIN, b"9182", [0x30; 16], 2000);
        assert!(matches!(err1, Err(SecureGuardError::InvalidPin { .. })));

        // Verify old PIN still works
        assert!(engine.unlock_with_pin(TEST_PIN, 2100).is_ok());

        // 2. Trivial new PIN fails and preserves old PIN
        engine.policy_mut().reject_trivial_pins = true;
        let err2 = engine.change_pin(TEST_PIN, b"1111", [0x30; 16], 3000);
        assert!(matches!(err2, Err(SecureGuardError::TrivialPinRejected)));

        // Verify old PIN still works
        engine.lock_now(3100).unwrap();
        assert!(engine.unlock_with_pin(TEST_PIN, 3200).is_ok());

        // 3. Valid change PIN
        assert!(engine
            .change_pin(TEST_PIN, b"9182", [0x30; 16], 4000)
            .is_ok());

        engine.lock_now(4100).unwrap();

        // Old PIN no longer works
        assert!(matches!(
            engine.unlock_with_pin(TEST_PIN, 4200),
            Err(SecureGuardError::InvalidPin { .. })
        ));

        // New PIN works!
        assert!(engine.unlock_with_pin(b"9182", 4300).is_ok());
    }

    #[test]
    fn test_legitimate_recovery_flow() {
        let (mut engine, recovery_code) = create_test_engine();

        // Lockout to RecoveryRequired with 5 failures
        let mut time = 2000u64;
        for i in 1..=5 {
            let _ = engine.unlock_with_pin(TEST_WRONG_PIN, time);
            time += match i {
                1 => 100,
                2 => 2500,
                3 => 5500,
                4 => 15500,
                _ => 100,
            };
        }
        assert_eq!(engine.state(), SecureGuardState::RateLimited);

        // 1. Wrong recovery code fails
        let bad_rec = engine.recover_with_code(b"wrong_code", b"7412", [0x40; 16], time);
        assert!(matches!(
            bad_rec,
            Err(SecureGuardError::InvalidRecoveryCode)
        ));
        assert_eq!(engine.state(), SecureGuardState::RateLimited);

        // 2. Legitimate recovery with valid code
        let ok_rec = engine.recover_with_code(&recovery_code, b"7412", [0x40; 16], time + 500);
        assert_eq!(ok_rec, Ok(SecureGuardState::Locked));
        assert_eq!(engine.state(), SecureGuardState::Locked);
        assert_eq!(engine.failed_attempts(), 0);

        // Rotated recovery code is established
        let new_rec_code = engine.last_rotated_recovery_code().unwrap();
        assert_ne!(new_rec_code, recovery_code);

        // Old recovery code is now invalid!
        let reuse_old = engine.recover_with_code(&recovery_code, b"9999", [0x50; 16], time + 1000);
        assert!(matches!(
            reuse_old,
            Err(SecureGuardError::InvalidRecoveryCode)
        ));

        // New PIN unlocks the engine
        assert!(engine.unlock_with_pin(b"7412", time + 1500).is_ok());
        assert_eq!(engine.state(), SecureGuardState::Unlocked);
    }

    #[test]
    fn test_resource_authorization_and_fido_standard_always_allowed() {
        let (mut engine, _) = create_test_engine();
        assert_eq!(engine.state(), SecureGuardState::Locked);

        // 1. FIDO Standard Flow is ALWAYS allowed even when Locked
        assert_eq!(
            engine.authorize_operation(ProtectedResourceClass::FidoStandardFlow, 1000),
            Ok(())
        );

        // 2. Wallets are protected and denied when Locked
        assert!(matches!(
            engine.authorize_vendor_opcode(OP_WALLET_GEN, 1000),
            Err(SecureGuardError::AccessDeniedLocked {
                state: SecureGuardState::Locked,
                opcode: OP_WALLET_GEN
            })
        ));
        assert!(matches!(
            engine.authorize_vendor_opcode(OP_WALLET_LIST, 1000),
            Err(SecureGuardError::AccessDeniedLocked { .. })
        ));
        assert!(matches!(
            engine.authorize_vendor_opcode(OP_WALLET_ADDR, 1000),
            Err(SecureGuardError::AccessDeniedLocked { .. })
        ));

        // 3. Protected Keys (0x20..0x23) are protected by default
        assert!(matches!(
            engine.authorize_vendor_opcode(OP_KEY_GEN_ONDEVICE, 1000),
            Err(SecureGuardError::AccessDeniedLocked { .. })
        ));
        assert!(matches!(
            engine.authorize_vendor_opcode(OP_KEY_IMPORT_ENVELOPE, 1000),
            Err(SecureGuardError::AccessDeniedLocked { .. })
        ));

        // 4. OATH is not protected by default
        assert_eq!(engine.authorize_vendor_opcode(OP_OATH_CODE, 1000), Ok(()));

        // 5. Unlock session: all protected resources now authorized
        engine.unlock_with_pin(TEST_PIN, 2000).unwrap();
        assert_eq!(engine.authorize_vendor_opcode(OP_WALLET_GEN, 2100), Ok(()));
        assert_eq!(
            engine.authorize_vendor_opcode(OP_KEY_GEN_ONDEVICE, 2100),
            Ok(())
        );

        // 6. Force RateLimited state with 5 failures: FIDO Standard STILL allowed!
        engine.lock_now(3000).unwrap();
        let mut time = 3000u64;
        for i in 1..=5 {
            let _ = engine.unlock_with_pin(TEST_WRONG_PIN, time);
            time += match i {
                1 => 100,
                2 => 2500,
                3 => 5500,
                4 => 15500,
                _ => 100,
            };
        }
        assert_eq!(engine.state(), SecureGuardState::RateLimited);

        // FIDO Standard Flow STILL PERMITTED!
        assert_eq!(
            engine.authorize_operation(ProtectedResourceClass::FidoStandardFlow, time + 100),
            Ok(())
        );
        // Wallets DENIED!
        assert!(engine
            .authorize_vendor_opcode(OP_WALLET_GEN, time + 100)
            .is_err());
    }

    #[test]
    fn test_corrupted_persistent_record_enters_error_locked() {
        let (engine, _) = create_test_engine();
        let mut bytes = engine.to_persistent_record().to_bytes();

        // Corrupt byte in payload
        bytes[50] ^= 0xAA;

        // from_persisted_bytes fails closed to ErrorLocked
        let restored = SecureGuardEngine::from_persisted_bytes(&bytes, 5000);
        assert_eq!(restored.state(), SecureGuardState::ErrorLocked);
        assert!(!restored.is_unlocked());

        // Operations fail in ErrorLocked
        let mut locked_engine = restored;
        assert!(matches!(
            locked_engine.unlock_with_pin(TEST_PIN, 6000),
            Err(SecureGuardError::InvalidStateForOperation { .. })
        ));
    }

    #[test]
    fn test_verify_pin_for_critical_action() {
        let (mut engine, _) = create_test_engine();
        assert_eq!(engine.state(), SecureGuardState::Locked);

        // 1. Wrong PIN fails and increments failed_attempts
        let err = engine.verify_pin_for_critical_action(TEST_WRONG_PIN, 1500);
        assert!(matches!(err, Err(SecureGuardError::InvalidPin { .. })));
        assert_eq!(engine.failed_attempts(), 1);
        assert_eq!(engine.state(), SecureGuardState::Locked);

        // 2. Correct PIN succeeds, resets failed_attempts, unlocks session
        let ok = engine.verify_pin_for_critical_action(TEST_PIN, 1600);
        assert!(ok.is_ok());
        assert_eq!(engine.failed_attempts(), 0);
        assert_eq!(engine.state(), SecureGuardState::Unlocked);

        // 3. While Unlocked, verifying correct PIN renews session and succeeds
        let ok2 = engine.verify_pin_for_critical_action(TEST_PIN, 2000);
        assert!(ok2.is_ok());
        assert_eq!(engine.state(), SecureGuardState::Unlocked);

        // 4. While Unlocked, entering wrong PIN fails and increments failed_attempts
        let err2 = engine.verify_pin_for_critical_action(TEST_WRONG_PIN, 2100);
        assert!(matches!(err2, Err(SecureGuardError::InvalidPin { .. })));
        assert_eq!(engine.failed_attempts(), 1);

        // 5. Helper verify_pin_or_active_session
        assert!(engine.verify_pin_or_active_session(Some(TEST_PIN), 2200).is_ok());
        assert!(engine.verify_pin_or_active_session(None, 2300).is_ok());
    }

    #[test]
    fn test_ble_proximity_registration_and_walk_away_lock() {
        let (mut engine, _) = create_test_engine();
        assert_eq!(engine.state(), SecureGuardState::Locked);

        // 1. Register device in memory
        let phone_mac = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        engine.register_ble_proximity_device(phone_mac, b"Junior Phone");
        assert!(engine.ble_proximity_registered());
        assert_eq!(engine.paired_ble_mac(), &phone_mac);
        assert!(engine.auto_lock_on_ble_away());
        assert!(!engine.ble_proximity_away());

        // 2. Unlock with PIN while near
        assert!(engine.unlock_with_pin(TEST_PIN, 1500).is_ok());
        assert_eq!(engine.state(), SecureGuardState::Unlocked);

        // 3. Proximity update: near (-35 dBm)
        let locked = engine.on_ble_proximity_update(&phone_mac, -35, false, 1600).unwrap();
        assert!(!locked);
        assert_eq!(engine.state(), SecureGuardState::Unlocked);

        // 4. Proximity update: away (-92 dBm, is_away = true) -> IMMEDIATELY LOCKS
        let locked2 = engine.on_ble_proximity_update(&phone_mac, -92, true, 2000).unwrap();
        assert!(locked2, "Must trigger immediate lock when moving away");
        assert_eq!(engine.state(), SecureGuardState::Locked);
        assert!(engine.ble_proximity_away());

        // 5. While away, unlock is rejected with BleProximityLocked
        let unlock_err = engine.unlock_with_pin(TEST_PIN, 2100);
        assert_eq!(unlock_err, Err(SecureGuardError::BleProximityLocked));

        // 6. Returns near (-40 dBm, is_away = false)
        let locked3 = engine.on_ble_proximity_update(&phone_mac, -40, false, 2500).unwrap();
        assert!(!locked3);
        assert!(!engine.ble_proximity_away());

        // 7. Now unlock succeeds
        assert!(engine.unlock_with_pin(TEST_PIN, 2600).is_ok());
        assert_eq!(engine.state(), SecureGuardState::Unlocked);
    }
}