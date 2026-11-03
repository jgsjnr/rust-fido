package dev.aegiskey.app.caps

/**
 * GET_CAPS CBOR parser (decode-only, self-contained).
 *
 * Contract: response body is a definite-length CBOR map with
 * `fw_version` (text), `preset` (text), `caps` (array of text,
 * exactly presets.<preset>.includes, same order), `unsupported_count`
 * (uint). Extra map keys are ignored (forward compat). Anything
 * else — wrong types, empty text, oversized values, truncated or
 * indefinite-length CBOR — decodes to null so the caller reports
 * [CapsResult.Unknown] (fail-soft, no invented data).
 *
 * Framing ([CapsParser.parseFrame]) accepts both authority shapes
 * produced by the existing key-transport helpers: `[op, status,
 * body...]` (USB CTAPHID + BLE, see VendorOps.parseResponse) and
 * `[status, body...]` (host bridge fallback). A bare CBOR map with
 * no status prefix is treated as status 0x00.
 */
object CapsParser {

    private sealed interface Cbor {
        data class UInt(val v: Long) : Cbor
        data class Text(val s: String) : Cbor
        data class Arr(val items: List<Cbor>) : Cbor
        data class Map(val entries: LinkedHashMap<String, Cbor>) : Cbor
    }

    /** Splits a raw sendVendor reply into (status, cborBody). Null = not a caps frame. */
    fun parseFrame(op: Int, raw: ByteArray): Pair<Int, ByteArray>? {
        if (raw.size >= 2 && (raw[0].toInt() and 0xFF) == op) {
            val body = raw.copyOfRange(2, raw.size)
            if (!isMapHead(body, 0)) return null
            return ((raw[1].toInt() and 0xFF) to body)
        }
        if (raw.size >= 2 && isMapHead(raw, 1)) {
            return ((raw[0].toInt() and 0xFF) to raw.copyOfRange(1, raw.size))
        }
        if (raw.isNotEmpty() && isMapHead(raw, 0)) {
            return (CapsConstants.STATUS_OK to raw)
        }
        return null
    }

    /** Decodes a GET_CAPS CBOR body into authority data. Null = fail-soft. */
    fun parseCapsResponse(body: ByteArray): CapsReport? {
        val root = decode(body) as? Cbor.Map ?: return null
        val fw = (root.entries["fw_version"] as? Cbor.Text)?.s
            ?.takeIf { it.isNotEmpty() && it.length <= CapsConstants.MAX_TEXT_LEN }
            ?: return null
        val preset = (root.entries["preset"] as? Cbor.Text)?.s
            ?.takeIf { it.isNotEmpty() && it.length <= CapsConstants.MAX_TEXT_LEN }
            ?: return null
        val capsRaw = (root.entries["caps"] as? Cbor.Arr)?.items ?: return null
        if (capsRaw.size > CapsConstants.MAX_CAPS_ENTRIES) return null
        val caps = capsRaw.map { item ->
            (item as? Cbor.Text)?.s
                ?.takeIf { it.isNotEmpty() && it.length <= CapsConstants.MAX_TEXT_LEN }
                ?: return null
        }
        val unsupported = (root.entries["unsupported_count"] as? Cbor.UInt)?.v
            ?.takeIf { it in 0..CapsConstants.MAX_UNSUPPORTED_COUNT }
            ?.toInt()
            ?: return null
        return CapsReport(fwVersion = fw, preset = preset, caps = caps, unsupportedCount = unsupported)
    }

    private fun isMapHead(bytes: ByteArray, at: Int): Boolean {
        if (at >= bytes.size) return false
        val b = bytes[at].toInt() and 0xFF
        return b in 0xA0..0xBB
    }

    private fun decode(bytes: ByteArray): Cbor? {
        if (bytes.isEmpty()) return null
        return runCatching { Reader(bytes).readValue() }.getOrNull()
    }

    private class Reader(private val bytes: ByteArray, private var offset: Int = 0) {
        fun readValue(): Cbor? {
            if (offset >= bytes.size) return null
            val initial = bytes[offset++].toInt() and 0xFF
            val major = initial ushr 5
            val info = initial and 0x1F
            if (info == 31) return null // indefinite length: reject (fail-soft)
            val arg: Long = when {
                info < 24 -> info.toLong()
                info == 24 -> {
                    if (offset >= bytes.size) return null
                    (bytes[offset++].toInt() and 0xFF).toLong()
                }
                info == 25 -> {
                    if (offset + 1 >= bytes.size) return null
                    val b0 = (bytes[offset++].toInt() and 0xFF).toLong()
                    val b1 = (bytes[offset++].toInt() and 0xFF).toLong()
                    (b0 shl 8) or b1
                }
                info == 26 -> {
                    if (offset + 3 >= bytes.size) return null
                    var res = 0L
                    repeat(4) { res = (res shl 8) or (bytes[offset++].toInt() and 0xFF).toLong() }
                    res
                }
                info == 27 -> {
                    if (offset + 7 >= bytes.size) return null
                    var res = 0L
                    repeat(8) { res = (res shl 8) or (bytes[offset++].toInt() and 0xFF).toLong() }
                    if (res < 0) return null
                    res
                }
                else -> return null
            }
            return when (major) {
                0 -> Cbor.UInt(arg)
                1 -> null // negative int: never valid in this schema
                2 -> {
                    val len = arg.coerceAtMost((bytes.size - offset).toLong()).toInt()
                    val slice = bytes.copyOfRange(offset, offset + len)
                    offset += len
                    // byte strings never appear in this schema; keep opaque as failure
                    if (slice.isEmpty() && arg != 0L) return null
                    return null
                }
                3 -> {
                    if (arg > CapsConstants.MAX_TEXT_LEN + 64) return null
                    val len = arg.coerceAtMost((bytes.size - offset).toLong()).toInt()
                    if (len.toLong() != arg) return null
                    val s = runCatching { String(bytes, offset, len, Charsets.UTF_8) }.getOrNull()
                        ?: return null
                    offset += len
                    Cbor.Text(s)
                }
                4 -> {
                    if (arg > CapsConstants.MAX_CAPS_ENTRIES + 8) return null
                    val count = arg.toInt()
                    val items = ArrayList<Cbor>(count)
                    repeat(count) { items.add(readValue() ?: return null) }
                    Cbor.Arr(items)
                }
                5 -> {
                    if (arg > 16) return null
                    val count = arg.toInt()
                    val map = LinkedHashMap<String, Cbor>(count)
                    repeat(count) {
                        val key = readValue() as? Cbor.Text ?: return null
                        map[key.s] = readValue() ?: return null
                    }
                    Cbor.Map(map)
                }
                else -> null // simple/float: never valid in this schema
            }
        }
    }
}
