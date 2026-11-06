package dev.aegiskey.app

import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.log.TerminalLogStyle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Mapeamento do viewer de logs estilo terminal (somente leitura):
 * tag curta + cor por categoria + linha formatada, sem emojis.
 */
class TerminalLogStyleTest {

    @Before
    fun setUp() {
        DeviceLog.clear()
    }

    @Test
    fun testTagMapping() {
        assertEquals("ble", TerminalLogStyle.tagFor(DeviceLog.Category.BLE))
        assertEquals("wifi", TerminalLogStyle.tagFor(DeviceLog.Category.WIFI))
        assertEquals("pair", TerminalLogStyle.tagFor(DeviceLog.Category.PAIRING))
        assertEquals("lock", TerminalLogStyle.tagFor(DeviceLog.Category.LOCK))
        assertEquals("sys", TerminalLogStyle.tagFor(DeviceLog.Category.SYSTEM))
    }

    @Test
    fun testColorMappingIsDistinctAndOpaque() {
        val colors = DeviceLog.Category.values().map { TerminalLogStyle.colorArgbFor(it) }
        assertEquals(5, colors.toSet().size)
        colors.forEach { argb ->
            assertTrue("cor deve ser opaca (alpha FF)", (argb shr 24) == 0xFFL)
        }
    }

    @Test
    fun testFormatLineUsesTerminalLayout() {
        DeviceLog.append(DeviceLog.Category.BLE, "RX FFF2 status=OK")
        val entry = DeviceLog.entries.value.single()
        val line = TerminalLogStyle.formatLine(entry)
        assertTrue(line.contains("[ble] RX FFF2 status=OK"))
        assertTrue(line.matches(Regex("\\d{2}:\\d{2}:\\d{2}\\.\\d{3} \\[ble\\] .*")))
    }
}
