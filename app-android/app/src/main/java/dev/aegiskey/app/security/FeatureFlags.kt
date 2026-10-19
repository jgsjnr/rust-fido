package dev.aegiskey.app.security

/**
 * Wave7 compile-time gates (all default OFF, per zero-cost/feature-off policy).
 *
 * - ENABLE_APP_LOCK: password LockScreen (bridge PBKDF2 verifier) in front of
 *   Vault/Accounts/Auth. Enroll on first run, verify afterwards.
 * - ENABLE_DEVICE_PRESS: PressDeviceSheet while the device reports up-needed
 *   (FFF2 STATUS_UP_NEEDED), with CANCEL (0xBE) support.
 *
 * Flip to true only for dev/test builds; release stays locked out.
 */
object FeatureFlags {
    const val ENABLE_APP_LOCK = false
    const val ENABLE_DEVICE_PRESS = false
}
