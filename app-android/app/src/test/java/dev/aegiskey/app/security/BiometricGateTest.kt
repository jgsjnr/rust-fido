package dev.aegiskey.app.security

import org.junit.Assert.assertNull
import org.junit.Test

/**
 * BiometricGate KeyStore binding (host unit, no board, no device).
 *
 * On the JVM host there is no "AndroidKeyStore" provider and no biometric
 * sensor, so [BiometricGate.cryptoObject] must fail closed (null) instead of
 * throwing. The legacy [BiometricGate.stubCryptoObject] alias delegates to
 * the same fail-closed path.
 */
class BiometricGateTest {

    @Test
    fun cryptoObject_failClosed_withoutKeyStore() {
        assertNull(BiometricGate.cryptoObject())
    }

    @Test
    fun stubCryptoObject_delegates_failClosed() {
        @Suppress("DEPRECATION")
        assertNull(BiometricGate.stubCryptoObject())
    }
}
