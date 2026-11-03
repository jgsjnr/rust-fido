package dev.aegiskey.app.domain.model

/**
 * Resolves which transport label the connection status must display.
 *
 * Single entrypoint for transport-label decisions. The label is always
 * derived from the link actually carrying the session (USB HID first,
 * then BLE) — never from the stored last-used transport. When no link
 * is live, the result is null so the UI shows the interface name
 * neutrally instead of guessing (and never claims Bluetooth for a
 * USB-carried session).
 */
object ActiveTransport {

    /**
     * Returns the transport carrying the live session, or null when it
     * cannot be determined. USB wins over BLE because a physically
     * attached USB HID link is the authoritative wired session even if
     * a BLE advertisement for the same key is visible.
     *
     * WIFI/SIMULATOR have no live probe here, so a stored value for
     * those is trusted; a stored BLE/USB value is NOT trusted without
     * a live link (that would report the last-used transport instead
     * of the active one).
     */
    fun resolve(
        stored: ConnectionTransportType?,
        usbPresent: Boolean,
        bleReady: Boolean
    ): ConnectionTransportType? {
        if (usbPresent) return ConnectionTransportType.USB
        if (bleReady) return ConnectionTransportType.BLE
        return when (stored) {
            ConnectionTransportType.WIFI,
            ConnectionTransportType.SIMULATOR -> stored
            else -> null
        }
    }

    /**
     * Parses a persisted transport name. Returns null for missing or
     * unrecognized values instead of defaulting to Bluetooth.
     */
    fun parseStoredOrNull(name: String?): ConnectionTransportType? {
        if (name.isNullOrBlank()) return null
        return runCatching { ConnectionTransportType.valueOf(name) }.getOrNull()
    }

    /**
     * Infers the transport from a hardware identifier when the stored
     * name is missing or corrupt. Returns null when the identifier
     * says nothing conclusive.
     */
    fun inferFromHardwareId(hardwareId: String?): ConnectionTransportType? {
        if (hardwareId.isNullOrBlank()) return null
        val id = hardwareId.trim()
        return when {
            id.startsWith("usb:", ignoreCase = true) -> ConnectionTransportType.USB
            id.startsWith("BRIDGE:", ignoreCase = true) -> ConnectionTransportType.USB
            id.startsWith("WIFI:", ignoreCase = true) -> ConnectionTransportType.WIFI
            id.startsWith("SIM", ignoreCase = true) -> ConnectionTransportType.SIMULATOR
            id.startsWith("RENODE", ignoreCase = true) -> ConnectionTransportType.SIMULATOR
            id.startsWith("VIRTUAL", ignoreCase = true) -> ConnectionTransportType.SIMULATOR
            id.equals("BLE-BRIDGE", ignoreCase = true) -> ConnectionTransportType.BLE
            id.count { it == ':' } == 5 -> ConnectionTransportType.BLE
            else -> null
        }
    }
}
