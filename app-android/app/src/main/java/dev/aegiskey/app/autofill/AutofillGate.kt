package dev.aegiskey.app.autofill

import dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl

/**
 * Fail-closed session gate for the autofill entrypoint.
 *
 * The vault session is the RAM-only Secure Guard session PIN
 * ([SecureGuardRepositoryImpl.isSessionPinValid], refreshed from the
 * authoritative `session_remaining_ms` of a fresh 0x3A and wiped on
 * lock/transport loss). No unlocked session -> no datasets, never a
 * cached secret: the service has no secret store of its own.
 */
object AutofillGate {

    /** Pure conjunction, unit-tested: both must hold. */
    fun canFill(autofillEnabled: Boolean, sessionUnlocked: Boolean): Boolean =
        autofillEnabled && sessionUnlocked

    /** Live session probe. Any failure reads as locked (fail-closed). */
    fun isSessionUnlocked(): Boolean =
        try {
            SecureGuardRepositoryImpl.isSessionPinValid()
        } catch (_: Throwable) {
            false
        }
}
