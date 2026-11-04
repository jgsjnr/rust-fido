package dev.aegiskey.app.domain.model

/**
 * 10 estados canônicos do cofre on-device Secure Guard (UX Seção 11.2).
 */
enum class SecureGuardStateEnum(val wireCode: Int, val displayName: String) {
    UNPROVISIONED(0x00, "Unprovisioned"),
    PROVISIONING(0x01, "Provisioning"),
    LOCKED(0x02, "Locked"),
    AUTHENTICATING(0x03, "Authenticating"),
    UNLOCKED(0x04, "Unlocked"),
    RECOVERY_REQUIRED(0x05, "RecoveryRequired"),
    RATE_LIMITED(0x06, "RateLimited"),
    WIPE_PENDING(0x07, "WipePending"),
    WIPE_IN_PROGRESS(0x08, "WipeInProgress"),
    ERROR_LOCKED(0x09, "ErrorLocked"),
    DEVICE_UNAVAILABLE(0xFF, "DeviceUnavailable");

    companion object {
        fun fromWireCode(code: Int): SecureGuardStateEnum =
            entries.find { it.wireCode == code } ?: DEVICE_UNAVAILABLE

        fun fromString(name: String): SecureGuardStateEnum =
            entries.find { it.displayName.equals(name, ignoreCase = true) || it.name.equals(name, ignoreCase = true) }
                ?: DEVICE_UNAVAILABLE
    }
}

/**
 * Parâmetros de política ativa do Secure Guard.
 */
data class SecureGuardPolicy(
    val wipeOn5Failures: Boolean = false,
    val sessionDurationMs: Long = 300_000L,
    val inactivityTimeoutMs: Long = 300_000L,
    val protectKeysAndAegn: Boolean = true,
    val protectOath: Boolean = false,
    val testModeNonDestructiveWipe: Boolean = false
)

/**
 * Telemetria, estado FSM, contadores de tentativas e penalidade de backoff do Secure Guard.
 *
 * `benchActive` traduz o contrato `bench_active: bool` do status `0x3A`
 * (ausente = false). Puro read-only: nunca inventado aqui, só decide o
 * selo de bancada via `benchmode.BenchSession`.
 */
data class SecureGuardStatus(
    val state: SecureGuardStateEnum = SecureGuardStateEnum.UNPROVISIONED,
    val isProvisioned: Boolean = false,
    val isUnlocked: Boolean = false,
    val failedAttempts: Int = 0,
    val remainingAttempts: Int = 5,
    val maxAttempts: Int = 5,
    val rateLimitRemainingMs: Long = 0L,
    val sessionRemainingMs: Long = 0L,
    val policy: SecureGuardPolicy = SecureGuardPolicy(),
    val lastWipeSimulated: Boolean = false,
    val auditCount: Long = 0L,
    val lastGeneratedRecoveryCode: String? = null,
    val deviceBleMac: String? = null,
    val deviceBleName: String? = null,
    val benchActive: Boolean = false
)
