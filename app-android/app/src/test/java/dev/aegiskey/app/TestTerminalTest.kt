package dev.aegiskey.app

import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import dev.aegiskey.app.testterminal.TestTerminal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Terminal de Testes (lab, test-mode only): catálogo, gate e parse de acks.
 *
 * - Catálogo 1:1 com o manifesto do firmware (`TEST_COMMANDS`, 16 linhas,
 *   mesma ordem): nenhum nome inventado, nenhum nome faltando.
 * - Gate: visível só com autoridade test-mode (`bench_active` ou flag
 *   test-mode); release/produção some (fail-closed).
 * - Parse: acks documentados classificam Ok; corpo vazio = release
 *   ignorou; resto = sem interpretação.
 */
class TestTerminalTest {

    private fun status(
        testMode: Boolean = false,
        lastWipeSimulated: Boolean = false,
        benchActive: Boolean = false,
        state: SecureGuardStateEnum = SecureGuardStateEnum.LOCKED,
    ) = SecureGuardStatus(
        state = state,
        isProvisioned = state != SecureGuardStateEnum.UNPROVISIONED,
        isUnlocked = state == SecureGuardStateEnum.UNLOCKED,
        policy = SecureGuardPolicy(testModeNonDestructiveWipe = testMode),
        lastWipeSimulated = lastWipeSimulated,
        benchActive = benchActive,
    )

    @Test
    fun catalog_matches_firmware_manifest_exactly() {
        // Espelho exato de `TEST_COMMANDS` (test_hooks.rs) + docs/test-hooks.md.
        val expected = listOf(
            "TEST_UP",
            "TEST_DOWNLOAD",
            "TEST_USB_RECONNECT",
            "TEST_PAIRING_OPEN",
            "TEST_PAIRING_OPEN_300",
            "TEST_PAIRING_CLOSE",
            "TEST_LIFETIME_DUMP",
            "TEST_LED_STATE",
            "TEST_LED_RED",
            "TEST_LED_GREEN",
            "TEST_LED_BLUE",
            "TEST_LED_OFF",
            "TEST_LED_RELEASE",
            "TEST_BENCH_ON",
            "TEST_BENCH_OFF",
            "TEST_OTA_COMMIT_HOOK",
        )
        assertEquals(expected, TestTerminal.CATALOG.map { it.line })
    }

    @Test
    fun catalog_no_duplicates_no_empty() {
        val lines = TestTerminal.CATALOG.map { it.line }
        assertEquals(lines.size, lines.distinct().size)
        TestTerminal.CATALOG.forEach { hook ->
            assertTrue(hook.line.isNotEmpty())
            assertTrue(hook.title.isNotEmpty())
            assertTrue(hook.description.isNotEmpty())
            assertTrue(hook.expectedAck.isNotEmpty())
        }
    }

    @Test
    fun gate_benchActive_isVisible() {
        assertTrue(TestTerminal.isVisible(status(benchActive = true)))
        assertTrue(
            TestTerminal.isVisible(
                status(benchActive = true, state = SecureGuardStateEnum.UNLOCKED),
            ),
        )
    }

    @Test
    fun gate_testMode_isVisible() {
        assertTrue(TestTerminal.isVisible(status(testMode = true)))
    }

    @Test
    fun gate_lastWipeSimulated_isVisible() {
        assertTrue(TestTerminal.isVisible(status(lastWipeSimulated = true)))
    }

    @Test
    fun gate_production_isHidden_inEveryTransport() {
        val production = status()
        assertFalse(TestTerminal.isVisible(production))
        assertFalse(TestTerminal.isVisible(production, ConnectionTransportType.BLE))
        assertFalse(TestTerminal.isVisible(production, ConnectionTransportType.USB))
        assertFalse(TestTerminal.isVisible(production, ConnectionTransportType.WIFI))
        assertFalse(TestTerminal.isVisible(production, null))
        assertFalse(TestTerminal.isVisible(SecureGuardStatus()))
    }

    @Test
    fun gate_isPure_doesNotMutateStatus() {
        val bench = status(benchActive = true, state = SecureGuardStateEnum.LOCKED)
        val before = bench.copy()
        assertTrue(TestTerminal.isVisible(bench))
        assertEquals(before, bench)
    }

    @Test
    fun classifyAck_knownAcks_areOk() {
        val samples = mapOf(
            "TEST_UP" to "up_latched source=software\n",
            "TEST_DOWNLOAD" to "download_mode source=software\n",
            "TEST_USB_RECONNECT" to "usb_reconnect source=software\n",
            "TEST_PAIRING_OPEN" to "pairing_open window_s=60\n",
            "TEST_PAIRING_OPEN_300" to "pairing_open window_s=300\n",
            "TEST_PAIRING_CLOSE" to "pairing_closed source=software\n",
            "TEST_LIFETIME_DUMP" to "lt_dump v=1\nuptime_s=42\n",
            "TEST_LED_STATE" to "led_state screen=freertos pairing=idle up_pending=0 touch=0 uptime_s=42\n",
            "TEST_LED_RED" to "led_set TEST_LED_RED\n",
            "TEST_LED_GREEN" to "led_set TEST_LED_GREEN\n",
            "TEST_LED_BLUE" to "led_set TEST_LED_BLUE\n",
            "TEST_LED_OFF" to "led_set TEST_LED_OFF\n",
            "TEST_LED_RELEASE" to "led_set released\n",
            "TEST_BENCH_ON" to "bench_on BENCH idle=extended source=software\n",
            "TEST_BENCH_OFF" to "bench_off BENCH source=software\n",
            "TEST_OTA_COMMIT_HOOK" to "ota_commit_hook armed\n",
        )
        assertEquals(TestTerminal.CATALOG.map { it.line }.toSet(), samples.keys)
        samples.forEach { (line, body) ->
            val ack = TestTerminal.classifyAck(line, body)
            assertTrue("ack de $line deve ser Ok: $ack", ack is TestTerminal.Ack.Ok)
            assertEquals(body.trim(), (ack as TestTerminal.Ack.Ok).body)
        }
    }

    @Test
    fun classifyAck_blank_isIgnoredRelease() {
        listOf(null, "", "   ", "\n  \n").forEach { body ->
            assertTrue(
                TestTerminal.classifyAck("TEST_UP", body) is TestTerminal.Ack.IgnoredRelease,
            )
        }
    }

    @Test
    fun classifyAck_unknown_isUnrecognized() {
        assertTrue(
            TestTerminal.classifyAck("TEST_UP", "something unexpected v=9")
                is TestTerminal.Ack.Unrecognized,
        )
    }

    @Test
    fun classifyAck_unknownLine_withKnownMarker_isOk() {
        // Linha fora do catálogo nunca é enviada; se a ponte devolver um
        // marcador conhecido, ainda conta como resposta válida (crua).
        assertTrue(
            TestTerminal.classifyAck("TEST_NOPE", "up_latched source=software")
                is TestTerminal.Ack.Ok,
        )
        assertTrue(
            TestTerminal.classifyAck("TEST_NOPE", "garbage")
                is TestTerminal.Ack.Unrecognized,
        )
    }

    @Test
    fun bridgeContract_constants() {
        assertEquals("/bridge/text_line", TestTerminal.BRIDGE_PATH)
        assertEquals("ponte sem suporte", TestTerminal.BRIDGE_UNSUPPORTED_LABEL)
        assertEquals("> TEST_UP", TestTerminal.txLine("TEST_UP"))
        assertEquals("< up_latched source=software", TestTerminal.rxLine("up_latched source=software\n"))
        assertEquals("< ponte sem suporte", TestTerminal.unsupportedLine())
        assertTrue(TestTerminal.ignoredLine().startsWith("< "))
        assertTrue(TestTerminal.transportErrorLine().startsWith("< "))
    }
}
