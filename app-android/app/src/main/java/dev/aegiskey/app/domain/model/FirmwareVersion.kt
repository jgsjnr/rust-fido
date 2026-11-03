package dev.aegiskey.app.domain.model

import dev.aegiskey.app.BuildConfig

/**
 * Single source of truth for firmware/app version display (click-through F7).
 *
 * Rule: device-reported where available, app version otherwise.
 *
 * - Device-reported: `GET_STATUS` / `GET_CAPS 0x3F` / ping payload parsed by
 *   repositories and screens. When a diagnostics object carries a non-blank
 *   [HardwareDeviceDiagnostics.firmwareVersion], that value wins.
 * - Otherwise: [appVersion] (`BuildConfig.VERSION_NAME`, e.g. `0.1.0-wave5`).
 *   Previous per-screen fallbacks (`v0.2.1-esp32s3`) are retired; they caused
 *   the v0.2.1 / v2.4.1-rc1 / v3.4.0 drift across Vault / Settings / OTA.
 * - OTA channel metadata (`OTA_CHANNEL_LATEST`, e.g. `v3.4.0-esp32s3`) is NOT
 *   a device version. It labels the release channel and must be rendered with
 *   a channel label, never as the connected key version.
 *
 * Slot capacity: [MAX_SLOTS] (32). The `16` fallback in the vault summary was
 * stale mixed default/live data; every "x used, y available" line derives
 * `y = MAX_SLOTS - used`.
 */
object FirmwareVersion {
    /** Total hardware credential slots. */
    const val MAX_SLOTS: Int = 32

    /**
     * Latest release published on the OTA channel (channel metadata, NOT the
     * connected key version). Render only beside a channel label.
     */
    const val OTA_CHANNEL_LATEST: String = "v3.4.0-esp32s3"

    /** App version used when no device-reported version is available. */
    val appVersion: String get() = runCatching { BuildConfig.VERSION_NAME }.getOrDefault("0.1.0-wave5")

    /**
     * Resolves the version to display: device-reported wins, app version is
     * the documented fallback.
     */
    fun resolve(deviceReported: String?): String {
        val reported = deviceReported?.trim()
        return if (reported.isNullOrEmpty()) appVersion else reported
    }

    /** Free slots from an occupied count, clamped at zero. */
    fun freeSlots(totalOccupied: Int, capacity: Int = MAX_SLOTS): Int =
        (capacity - totalOccupied.coerceAtLeast(0)).coerceAtLeast(0)
}
