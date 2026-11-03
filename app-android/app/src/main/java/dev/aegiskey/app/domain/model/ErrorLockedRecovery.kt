package dev.aegiskey.app.domain.model

/**
 * Routing rules for the ErrorLocked device state (wire code 0x09,
 * reported by the 0x3A status query).
 *
 * Single entrypoint for ErrorLocked UX decisions. When the secure
 * record is stale or unreadable the engine rejects every request
 * before the PIN oracle runs, so the attempt counters stay frozen
 * ("5/5 never changes") and every PIN "fails". The app must therefore
 * route to a dedicated recovery screen instead of looping a PIN
 * prompt, and must never suggest retrying the PIN.
 */
object ErrorLockedRecovery {

    /** True only for the frozen ErrorLocked state. */
    fun isErrorLocked(state: SecureGuardStateEnum): Boolean =
        state == SecureGuardStateEnum.ERROR_LOCKED

    /** 0x3A status wire code for the given state. */
    fun isErrorLockedWireCode(code: Int): Boolean =
        SecureGuardStateEnum.fromWireCode(code) == SecureGuardStateEnum.ERROR_LOCKED

    /**
     * Whether the state may offer a PIN entry prompt. ErrorLocked
     * must never prompt for a PIN: no PIN can succeed while the
     * secure record is unreadable.
     */
    fun shouldPromptPin(state: SecureGuardStateEnum): Boolean =
        when (state) {
            SecureGuardStateEnum.LOCKED,
            SecureGuardStateEnum.RATE_LIMITED -> true
            else -> false
        }

    /**
     * Whether the state routes to a recovery screen instead of PIN
     * entry. Covers both the frozen ErrorLocked record and the
     * standard recovery-required flow.
     */
    fun isRecoveryRoute(state: SecureGuardStateEnum): Boolean =
        when (state) {
            SecureGuardStateEnum.ERROR_LOCKED,
            SecureGuardStateEnum.RECOVERY_REQUIRED -> true
            else -> false
        }

    /**
     * Whether the failed/remaining attempt counters are frozen by the
     * device. Only ErrorLocked freezes the counters with reason;
     * every other state shows live counter values.
     */
    fun isAttemptsCounterFrozen(state: SecureGuardStateEnum): Boolean =
        state == SecureGuardStateEnum.ERROR_LOCKED
}
