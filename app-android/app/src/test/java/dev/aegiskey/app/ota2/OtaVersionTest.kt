package dev.aegiskey.app.ota2

import dev.aegiskey.app.caps.CapsReport
import dev.aegiskey.app.caps.CapsResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * OtaVersion resolution: device GET_CAPS first, local default second.
 *
 * No hardware: [CapsResult] values are constructed in-memory (same shapes
 * the CapsRepository returns for live vs old firmware).
 */
class OtaVersionTest {

    private fun known(fw: String) = CapsResult.Known(
        CapsReport(fwVersion = fw, preset = "full", caps = emptyList(), unsupportedCount = 0),
    )

    @Test
    fun parseReadsLeadingInteger() {
        assertEquals(1L, parseOtaCurrentVersion("1.0.0"))
        assertEquals(7L, parseOtaCurrentVersion("7"))
        assertEquals(12L, parseOtaCurrentVersion("  12b "))
    }

    @Test
    fun parseRejectsNonNumeric() {
        assertNull(parseOtaCurrentVersion(""))
        assertNull(parseOtaCurrentVersion("abc"))
        assertNull(parseOtaCurrentVersion("v1"))
    }

    @Test
    fun resolvePrefersDeviceCaps() {
        assertEquals(3L, resolveOtaCurrentVersion(known("3.4.0"), 1))
    }

    @Test
    fun resolveFallsBackToLocalDefault() {
        assertEquals(1L, resolveOtaCurrentVersion(CapsResult.Unknown, 1))
        assertEquals(1L, resolveOtaCurrentVersion(known(""), 1))
        assertEquals(1L, resolveOtaCurrentVersion(null, 1))
    }

    @Test
    fun resolveFallsBackToZero() {
        assertEquals(0L, resolveOtaCurrentVersion(CapsResult.Unknown, null))
        assertEquals(0L, resolveOtaCurrentVersion(null, null))
        assertEquals(0L, resolveOtaCurrentVersion(CapsResult.Unknown, -1))
    }
}
