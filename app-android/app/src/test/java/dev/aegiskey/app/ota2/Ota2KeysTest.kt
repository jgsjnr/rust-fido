package dev.aegiskey.app.ota2

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Ota2Keys plumbing: release fail-closed, lab default-off/test-only.
 *
 * No real key material: the nonzero vectors below are format-only
 * placeholders (never used to sign/verify), and the denied all-zeros key
 * is the firmware OtaKeyProvider::RELEASE_PUBKEY mirror.
 */
class Ota2KeysTest {

    private val nonzeroHex = "11".repeat(32)

    @Test
    fun releaseDefaultsToDeniedFailClosed() {
        Ota2Keys.clearReleaseKey()
        val active = Ota2Keys.activePubkey()
        assertTrue(Ota2Keys.isDeniedKey(active))
    }

    @Test
    fun releaseConfigureAndClearRoundTrip() {
        try {
            Ota2Keys.configureReleaseKey(nonzeroHex)
            assertFalse(Ota2Keys.isDeniedKey(Ota2Keys.activePubkey()))
        } finally {
            Ota2Keys.clearReleaseKey()
        }
        assertTrue(Ota2Keys.isDeniedKey(Ota2Keys.activePubkey()))
    }

    @Test
    fun releaseRejectsMalformedHex() {
        try {
            Ota2Keys.configureReleaseKey("zz")
            fail("expected bad release key")
        } catch (_: IllegalArgumentException) {
        } finally {
            Ota2Keys.clearReleaseKey()
        }
    }

    @Test
    fun labDefaultsToOff() {
        Ota2Keys.clearLabKey()
        assertFalse(Ota2Keys.isLabConfigured())
        assertNull(Ota2Keys.labPubkeyOrNull())
    }

    @Test
    fun labZerosStayOff() {
        try {
            Ota2Keys.configureLabKey(Ota2Keys.LAB_PUBKEY_HEX)
            assertFalse(Ota2Keys.isLabConfigured())
            assertNull(Ota2Keys.labPubkeyOrNull())
        } finally {
            Ota2Keys.clearLabKey()
        }
    }

    @Test
    fun labNonzeroConfiguresAndClears() {
        try {
            Ota2Keys.configureLabKey(nonzeroHex)
            assertTrue(Ota2Keys.isLabConfigured())
            assertEquals(32, Ota2Keys.labPubkeyOrNull()!!.size)
        } finally {
            Ota2Keys.clearLabKey()
        }
        assertFalse(Ota2Keys.isLabConfigured())
    }

    @Test
    fun releasePathIgnoresLabSlot() {
        try {
            Ota2Keys.configureLabKey(nonzeroHex)
            Ota2Keys.clearReleaseKey()
            assertTrue(Ota2Keys.isDeniedKey(Ota2Keys.activePubkey()))
        } finally {
            Ota2Keys.clearLabKey()
            Ota2Keys.clearReleaseKey()
        }
    }
}
