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
 *
 * SDK capability flags (A1): every per-domain boolean below derives from
 * [capabilityBits] — never an independent hardcoded switch. Bit positions
 * mirror the frozen `CapabilitySet` ABI in
 * `crates/universal-device-sdk/src/capabilities.rs` (R12). The compiled set
 * mirrors `capabilities()` as built: `default = ["fido", "hardwallet",
 * "secmon"]` (see `crates/universal-device-sdk/Cargo.toml`) over the
 * always-compiled VENDOR/BINDING/SYSTEM base. Phase-0 families
 * (ota/piv/otp/proximity/oath/backup/audit/policy) declare no Cargo feature,
 * so their `option_env!` probes are never set: they read NotCompiled here,
 * honestly, until the SDK owner declares the features.
 */
object FeatureFlags {
    const val ENABLE_APP_LOCK = false
    const val ENABLE_DEVICE_PRESS = false

    // SDK CapabilitySet bit ABI (frozen; source: capabilities.rs). Protocol
    // constants, not app state: the flags below derive from capabilityBits().
    const val CAP_FIDO = 1 shl 0
    const val CAP_HARDWALLET = 1 shl 1
    const val CAP_VENDOR = 1 shl 2
    const val CAP_BINDING = 1 shl 3
    const val CAP_SYSTEM = 1 shl 4
    const val CAP_SECMON = 1 shl 5
    const val CAP_TEST_MODE = 1 shl 6
    const val CAP_OTA = 1 shl 7
    const val CAP_PIV = 1 shl 8
    const val CAP_OTP = 1 shl 9
    const val CAP_PROXIMITY = 1 shl 10
    const val CAP_OATH = 1 shl 11
    const val CAP_BACKUP = 1 shl 12
    const val CAP_AUDIT = 1 shl 13
    const val CAP_POLICY = 1 shl 14

    /**
     * Compiled-in SDK set for this build: fido + hardwallet + secmon over
     * the always-compiled vendor/binding/system base.
     */
    const val SDK_COMPILED_MASK: Int =
        CAP_FIDO or CAP_HARDWALLET or CAP_VENDOR or CAP_BINDING or CAP_SYSTEM or CAP_SECMON

    /**
     * Test-only mask injection (fakes live in tests, never in release).
     * Production always reads [SDK_COMPILED_MASK].
     */
    @Volatile
    internal var capabilityOverride: Int? = null

    /** Single authority for every per-domain flag (no per-domain literals). */
    fun capabilityBits(): Int = capabilityOverride ?: SDK_COMPILED_MASK

    fun isEnabled(bit: Int): Boolean = (capabilityBits() and bit) == bit

    // Per-domain flags, all derived from capabilityBits().
    val fidoEnabled: Boolean get() = isEnabled(CAP_FIDO)
    val walletEnabled: Boolean get() = isEnabled(CAP_HARDWALLET)
    val oathEnabled: Boolean get() = isEnabled(CAP_OATH)
    val otaEnabled: Boolean get() = isEnabled(CAP_OTA)
    val otpEnabled: Boolean get() = isEnabled(CAP_OTP)

    /** Rescue rides the otp gate (see SdkRequest::check_compiled: Rescue -> require_otp). */
    val rescueEnabled: Boolean get() = isEnabled(CAP_OTP)
    val pivEnabled: Boolean get() = isEnabled(CAP_PIV)
    val policyEnabled: Boolean get() = isEnabled(CAP_POLICY)
    val proximityEnabled: Boolean get() = isEnabled(CAP_PROXIMITY)
    val backupEnabled: Boolean get() = isEnabled(CAP_BACKUP)
    val auditEnabled: Boolean get() = isEnabled(CAP_AUDIT)
}
