package dev.aegiskey.app.caps

import dev.aegiskey.app.data.transport.KeyTransport
import dev.aegiskey.app.domain.model.ConnectionTransportType
import java.io.ByteArrayOutputStream
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * caps query tests (offline, fake transport, canned CBOR).
 *
 * Authority mirrored: GET_CAPS 0x3F empty request, (0x00 + CBOR map)
 * reply {fw_version, preset, caps[], unsupported_count}; preset caps
 * match scripts/capability-catalog.json presets.<preset>.includes
 * (same ids, same order). No Android framework beyond pure paths:
 * the fake implements KeyTransport with canned replies.
 */
class CapsQueryTest {

    private val fullCaps = listOf(
        "ctap-makecred", "ctap-getassert", "ctap-clientpin", "ccid", "piv",
        "openpgp", "oath-totp", "oath-hotp", "otp-challenge-response",
        "wallet", "vault", "ble", "wifi-sntp", "display", "proximity",
        "vendor-mgmt", "debug-terminal", "test-hooks",
    )
    private val fidoOnlyCaps = listOf(
        "ctap-makecred", "ctap-getassert", "ctap-clientpin", "ccid", "piv",
        "openpgp", "vendor-mgmt",
    )
    private val fidoTotpCaps = listOf(
        "ctap-makecred", "ctap-getassert", "ctap-clientpin", "ccid", "piv",
        "openpgp", "oath-totp", "oath-hotp", "otp-challenge-response",
        "vendor-mgmt",
    )

    /** Fake key transport: records the request, replays one canned reply. */
    private open class FakeKeyTransport(var reply: ByteArray?) : KeyTransport {
        override val transportType: ConnectionTransportType = ConnectionTransportType.USB
        override val isConnected: StateFlow<Boolean> = MutableStateFlow(true)
        var lastOpcode: Int = -1
        var lastPayload: ByteArray = ByteArray(0)

        override suspend fun connect(target: String): Result<Unit> = Result.success(Unit)
        override suspend fun disconnect() {}
        override suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray? {
            lastOpcode = opcode
            lastPayload = payload
            return reply
        }
        override suspend fun sendMsg(payload: ByteArray): ByteArray? = null
        override suspend fun cancel(): Boolean = true
    }

    // --- Test-only CBOR encoder (definite lengths; production is decode-only). ---

    private fun header(out: ByteArrayOutputStream, major: Int, value: Long) {
        val mt = (major and 0x07) shl 5
        when {
            value < 24 -> out.write(mt or value.toInt())
            value <= 0xFF -> {
                out.write(mt or 24)
                out.write(value.toInt() and 0xFF)
            }
            value <= 0xFFFF -> {
                out.write(mt or 25)
                out.write(((value ushr 8) and 0xFF).toInt())
                out.write((value and 0xFF).toInt())
            }
            else -> {
                out.write(mt or 26)
                out.write(((value ushr 24) and 0xFF).toInt())
                out.write(((value ushr 16) and 0xFF).toInt())
                out.write(((value ushr 8) and 0xFF).toInt())
                out.write((value and 0xFF).toInt())
            }
        }
    }

    private fun text(out: ByteArrayOutputStream, s: String) {
        val b = s.toByteArray(Charsets.UTF_8)
        header(out, 3, b.size.toLong())
        out.write(b)
    }

    private fun cannedBody(fw: String, preset: String, caps: List<String>, unsupported: Long): ByteArray {
        val out = ByteArrayOutputStream()
        header(out, 5, 4)
        text(out, "fw_version"); text(out, fw)
        text(out, "preset"); text(out, preset)
        text(out, "caps")
        header(out, 4, caps.size.toLong())
        caps.forEach { text(out, it) }
        text(out, "unsupported_count"); header(out, 0, unsupported)
        return out.toByteArray()
    }

    private fun opFrame(status: Int, body: ByteArray): ByteArray =
        byteArrayOf(CapsConstants.OP_GET_CAPS.toByte(), status.toByte()) + body

    private fun bridgeFrame(status: Int, body: ByteArray): ByteArray =
        byteArrayOf(status.toByte()) + body

    // --- Parse + query: known presets ---

    @Test
    fun fullPreset_parsesAllCapsAndZeroUnsupported() = runBlocking {
        val body = cannedBody("3.4.0", "full", fullCaps, 0)
        val t = FakeKeyTransport(opFrame(0x00, body))
        val result = CapsRepository.query(t)
        assertEquals(CapsConstants.OP_GET_CAPS, t.lastOpcode)
        assertTrue(t.lastPayload.isEmpty())
        val known = result as CapsResult.Known
        assertEquals("3.4.0", known.report.fwVersion)
        assertEquals("full", known.report.preset)
        assertEquals(fullCaps, known.report.caps)
        assertEquals(0, known.report.unsupportedCount)
    }

    @Test
    fun fidoOnlyPreset_parsesSevenCapsAndSevenUnsupported() = runBlocking {
        val body = cannedBody("3.4.0", "fido-only", fidoOnlyCaps, 7)
        val t = FakeKeyTransport(opFrame(0x00, body))
        val known = CapsRepository.query(t) as CapsResult.Known
        assertEquals(fidoOnlyCaps, known.report.caps)
        assertEquals(7, known.report.unsupportedCount)
    }

    @Test
    fun fidoTotpPreset_parsesTenCapsAndThreeUnsupported() = runBlocking {
        val body = cannedBody("3.4.0", "fido-totp", fidoTotpCaps, 3)
        val t = FakeKeyTransport(opFrame(0x00, body))
        val known = CapsRepository.query(t) as CapsResult.Known
        assertEquals(fidoTotpCaps, known.report.caps)
        assertEquals(3, known.report.unsupportedCount)
    }

    @Test
    fun bridgeFraming_statusOnlyPrefix_parses() = runBlocking {
        val body = cannedBody("3.4.0", "full", fullCaps, 0)
        val t = FakeKeyTransport(bridgeFrame(0x00, body))
        val known = CapsRepository.query(t) as CapsResult.Known
        assertEquals(fullCaps, known.report.caps)
    }

    @Test
    fun emptyCapsArray_parsesToEmptyList() = runBlocking {
        val body = cannedBody("3.4.0", "full", emptyList(), 0)
        val t = FakeKeyTransport(opFrame(0x00, body))
        val known = CapsRepository.query(t) as CapsResult.Known
        assertTrue(known.report.caps.isEmpty())
    }

    @Test
    fun unknownCapId_preservedRaw() {
        val body = cannedBody("9.9.9", "full", listOf("future-cap"), 0)
        val report = CapsParser.parseCapsResponse(body)
        assertEquals(listOf("future-cap"), report?.caps)
    }

    @Test
    fun extraMapKeys_ignored() {
        val out = ByteArrayOutputStream()
        header(out, 5, 5)
        text(out, "fw_version"); text(out, "3.4.0")
        text(out, "preset"); text(out, "full")
        text(out, "caps")
        header(out, 4, 1); text(out, "ccid")
        text(out, "unsupported_count"); header(out, 0, 0)
        text(out, "next_fw"); text(out, "9.9.9")
        val report = CapsParser.parseCapsResponse(out.toByteArray())
        assertEquals(listOf("ccid"), report?.caps)
    }

    // --- Fail-soft: never invented data, always Unknown ---

    @Test
    fun nullReply_isUnknown() = runBlocking {
        assertEquals(CapsResult.Unknown, CapsRepository.query(FakeKeyTransport(null)))
    }

    @Test
    fun predatingFirmware_status04_isUnknown() = runBlocking {
        val t = FakeKeyTransport(opFrame(0x04, ByteArray(0)))
        assertEquals(CapsResult.Unknown, CapsRepository.query(t))
    }

    @Test
    fun unsupportedOp_status06_isUnknown() = runBlocking {
        val t = FakeKeyTransport(opFrame(0x06, ByteArray(0)))
        assertEquals(CapsResult.Unknown, CapsRepository.query(t))
    }

    @Test
    fun truncatedCbor_isUnknown() = runBlocking {
        val body = cannedBody("3.4.0", "full", fullCaps, 0)
        val t = FakeKeyTransport(opFrame(0x00, body.copyOf(body.size / 2)))
        assertEquals(CapsResult.Unknown, CapsRepository.query(t))
    }

    @Test
    fun garbageBytes_areUnknown() = runBlocking {
        val t = FakeKeyTransport(byteArrayOf(0x01, 0x02, 0x03))
        assertEquals(CapsResult.Unknown, CapsRepository.query(t))
    }

    @Test
    fun wrongFieldTypes_areUnknown() {
        // caps holds an int instead of text.
        val out = ByteArrayOutputStream()
        header(out, 5, 4)
        text(out, "fw_version"); text(out, "3.4.0")
        text(out, "preset"); text(out, "full")
        text(out, "caps")
        header(out, 4, 1); header(out, 0, 7)
        text(out, "unsupported_count"); header(out, 0, 0)
        assertEquals(null, CapsParser.parseCapsResponse(out.toByteArray()))

        // unsupported_count holds text instead of uint.
        val out2 = ByteArrayOutputStream()
        header(out2, 5, 4)
        text(out2, "fw_version"); text(out2, "3.4.0")
        text(out2, "preset"); text(out2, "full")
        text(out2, "caps")
        header(out2, 4, 0)
        text(out2, "unsupported_count"); text(out2, "zero")
        assertEquals(null, CapsParser.parseCapsResponse(out2.toByteArray()))
    }

    @Test
    fun missingKeys_areUnknown() {
        val out = ByteArrayOutputStream()
        header(out, 5, 2)
        text(out, "fw_version"); text(out, "3.4.0")
        text(out, "preset"); text(out, "full")
        assertEquals(null, CapsParser.parseCapsResponse(out.toByteArray()))
    }

    @Test
    fun hugeUnsupportedCount_isUnknown() {
        val body = cannedBody("3.4.0", "full", fullCaps, 0xFFFFFFFFL)
        assertEquals(null, CapsParser.parseCapsResponse(body))
    }

    @Test
    fun throwingTransport_isUnknown() = runBlocking {
        val t = object : FakeKeyTransport(null) {
            override suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray? {
                throw IllegalArgumentException("operação inválida")
            }
        }
        assertEquals(CapsResult.Unknown, CapsRepository.query(t))
    }
}
