package dev.aegiskey.app.ble

import org.json.JSONObject

/**
 * Finding A3: fail-closed User Presence (UP) surfacing.
 *
 * Single entrypoint for NEED_UP (0x01) detection and propagation. The device
 * is the authority on presence: any vendor op may answer NEED_UP when the user
 * has not touched the key. Callers must surface the existing "touch the key"
 * prompt instead of closing the sheet or showing locally-computeddata as if
 * it came from the device.
 *
 * Bridge flag tolerance (Finding A2): the host hardware bridge may report a
 * denial as JSON (`{"ok": false, "status": 1, "need_up": true, ...}`, HTTP
 * 428) instead of raw `[op, status, ...]` bytes. When the flag is present it
 * wins; when absent, the raw status byte decides. Never invents telemetry:
 * unknown shapes are not presence denials.
 *
 * No secrets cross this object: only opcodes, status bytes and fixed labels.
 */
object DevicePresence {
    /** Wire status for "user presence required" (frozen S9.5). */
    const val STATUS_NEED_UP: Int = VendorOps.STATUS_NEED_UP

    /**
     * Typed carrier for a device presence denial. Thrown by repositories when
     * the device answers NEED_UP so UI layers can keep the originating sheet
     * open and show the presence prompt instead of succeeding silently.
     */
    class NeedUpRequiredException(
        val opLabel: String,
        val status: Int = VendorOps.STATUS_NEED_UP,
    ) : IllegalStateException(
        "Device denied $opLabel: " + VendorOps.statusLabel(VendorOps.STATUS_NEED_UP),
    )

    /** True when this failure (or any cause) is a device presence denial. */
    fun Throwable.isNeedUpDenial(): Boolean {
        var t: Throwable? = this
        while (t != null) {
            if (t is NeedUpRequiredException) return true
            t = t.cause
        }
        return false
    }

    /** Status byte of a raw `[op, status, TLV...]` response, or null. */
    fun statusOf(raw: ByteArray?): Int? =
        if (raw != null && raw.size >= 2) raw[1].toInt() and 0xFF else null

    /** Raw status-code check (fallback when no bridge flag is present). */
    fun isNeedUpStatus(status: Int?): Boolean = status == VendorOps.STATUS_NEED_UP

    /**
     * Bridge-aware check: an explicit `need_up` flag wins when present;
     * otherwise falls back to the raw status byte. Absent flag + absent
     * status is never a denial.
     */
    fun isNeedUp(status: Int?, needUpFlag: Boolean?): Boolean =
        needUpFlag ?: isNeedUpStatus(status)

    /** Combined check over a raw response plus an optional bridge flag. */
    fun isNeedUpResponse(raw: ByteArray?, needUpFlag: Boolean? = null): Boolean =
        isNeedUp(statusOf(raw), needUpFlag)

    /**
     * Reads the A2 `need_up` flag from a host-bridge JSON body. Returns null
     * when the body carries no flag (caller must fall back to the status
     * byte), so a missing flag never masks a denial and never invents one.
     */
    fun needUpFlagFromBridgeJson(body: String?): Boolean? {
        if (body.isNullOrBlank()) return null
        return try {
            val json = JSONObject(body)
            when {
                json.has("need_up") -> json.optBoolean("need_up")
                json.has("needUp") -> json.optBoolean("needUp")
                else -> null
            }
        } catch (_: Throwable) {
            null
        }
    }

    /** Throws [NeedUpRequiredException] when the response is a UP denial. */
    fun throwIfNeedUp(opLabel: String, raw: ByteArray?, needUpFlag: Boolean? = null) {
        if (isNeedUpResponse(raw, needUpFlag)) throw NeedUpRequiredException(opLabel)
    }
}
