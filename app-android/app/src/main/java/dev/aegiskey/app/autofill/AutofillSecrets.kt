package dev.aegiskey.app.autofill

/**
 * Transient-secret hygiene for the autofill path.
 *
 * Releases ([dev.aegiskey.app.pm.PmCbor.PmRelease]) already wipe via
 * `wipe()`; this helper covers the working copies the service keeps
 * while building framework datasets (secret bytes decoded for
 * `AutofillValue`, char buffers). Framework-owned copies
 * (`AutofillValue.forText`) cannot be wiped — ours are, immediately
 * after the response is built or on any failure.
 */
object AutofillSecrets {

    fun wipe(vararg arrays: ByteArray) {
        for (a in arrays) a.fill(0)
    }

    fun wipe(vararg arrays: CharArray) {
        for (a in arrays) a.fill('\u0000')
    }

    fun isWiped(array: ByteArray): Boolean = array.all { it == 0.toByte() }

    fun isWiped(array: CharArray): Boolean = array.all { it == '\u0000' }
}
