package dev.aegiskey.app.log

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Live device-traffic log (debug): texto ao vivo de tudo que o app observa
 * do device conectado. Fonte real = trafego observado (BLE FFF1/FFF2 + HTTP
 * WiFi + eventos locais de pairing/lock). Sem payload sensivel: opcodes,
 * status e tamanhos apenas. Para ltrace completo use serial (live_monitor.py).
 *
 * Singleton com StateFlow, mesmo padrao de AegisBleClient.state:
 * a UI observa via collectAsState, sem novo cliente e sem nova dependencia.
 */
object DeviceLog {
    enum class Category { BLE, WIFI, PAIRING, LOCK, SYSTEM }

    data class Entry(val id: Long, val ts: Long, val category: Category, val line: String)

    private const val MAX_ENTRIES = 300
    private const val MAX_LINE = 160

    private var nextId = 0L
    private val _entries = MutableStateFlow<List<Entry>>(emptyList())
    val entries: StateFlow<List<Entry>> = _entries.asStateFlow()

    @Synchronized
    fun append(category: Category, line: String) {
        val clean = line.take(MAX_LINE).replace('\n', ' ').trim()
        if (clean.isEmpty()) return
        nextId += 1
        val entry = Entry(nextId, System.currentTimeMillis(), category, clean)
        val current = _entries.value
        _entries.value = if (current.size >= MAX_ENTRIES) {
            current.drop(current.size - MAX_ENTRIES + 1) + entry
        } else {
            current + entry
        }
    }

    @Synchronized
    fun clear() {
        _entries.value = emptyList()
    }

    /** Texto sanitizado para copiar (ja sem PII na origem). */
    fun snapshotText(limit: Int = 300): String =
        _entries.value.takeLast(limit).joinToString("\n") {
            formatTime(it.ts) + " [" + it.category + "] " + it.line
        }

    internal fun formatTime(ts: Long): String {
        val total = ts % 86_400_000
        val hh = total / 3_600_000
        val mm = (total % 3_600_000) / 60_000
        val ss = (total % 60_000) / 1000
        val ms = total % 1000
        return String.format("%02d:%02d:%02d.%03d", hh, mm, ss, ms)
    }
}
