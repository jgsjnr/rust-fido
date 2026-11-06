package dev.aegiskey.app.log

/**
 * Mapeamento visual do viewer de logs em estilo terminal (opencode).
 * Puro (sem Compose): tag curta + cor ARGB por categoria + linha formatada.
 * A UI converte [colorArgb] para androidx.compose.ui.graphics.Color.
 */
object TerminalLogStyle {
    const val BACKGROUND_ARGB: Long = 0xFF0D1117
    const val SURFACE_ARGB: Long = 0xFF161B22
    const val TEXT_ARGB: Long = 0xFFE6EDF3
    const val DIM_ARGB: Long = 0xFF8B949E
    const val PROMPT_ARGB: Long = 0xFF3FB950

    fun tagFor(category: DeviceLog.Category): String = when (category) {
        DeviceLog.Category.BLE -> "ble"
        DeviceLog.Category.WIFI -> "wifi"
        DeviceLog.Category.PAIRING -> "pair"
        DeviceLog.Category.LOCK -> "lock"
        DeviceLog.Category.SYSTEM -> "sys"
    }

    fun colorArgbFor(category: DeviceLog.Category): Long = when (category) {
        DeviceLog.Category.BLE -> 0xFF79C0FF
        DeviceLog.Category.WIFI -> 0xFFA5D6FF
        DeviceLog.Category.PAIRING -> 0xFFD29922
        DeviceLog.Category.LOCK -> 0xFFF778BA
        DeviceLog.Category.SYSTEM -> 0xFF7EE787
    }

    fun formatLine(entry: DeviceLog.Entry): String =
        DeviceLog.formatTime(entry.ts) + " [" + tagFor(entry.category) + "] " + entry.line
}
