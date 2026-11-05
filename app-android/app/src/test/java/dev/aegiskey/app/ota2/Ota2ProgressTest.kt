package dev.aegiskey.app.ota2

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * ota2 screen progress mapping (pure JVM, no Android framework): the percent
 * shown is translated from device-acked CHUNK counts only — 0 / 50 / 100,
 * incoherent ack (error), and missing denominator (unsupported).
 */
class Ota2ProgressTest {

    @Test
    fun progress_zero_atSessionStart() {
        assertEquals(0, otaProgressPercent(received = 0, total = 1024))
    }

    @Test
    fun progress_halfway() {
        assertEquals(50, otaProgressPercent(received = 512, total = 1024))
    }

    @Test
    fun progress_full_onLastAck() {
        assertEquals(100, otaProgressPercent(received = 1024, total = 1024))
    }

    @Test
    fun progress_error_ackOutOfRangeIsNull() {
        assertNull(otaProgressPercent(received = 1025, total = 1024))
        assertNull(otaProgressPercent(received = -1, total = 1024))
    }

    @Test
    fun progress_unsupported_denominatorIsNull() {
        assertNull(otaProgressPercent(received = 0, total = 0))
        assertNull(otaProgressPercent(received = 0, total = -8))
    }
}
