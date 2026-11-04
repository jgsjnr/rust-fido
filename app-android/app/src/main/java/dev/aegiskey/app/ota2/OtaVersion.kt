package dev.aegiskey.app.ota2

import dev.aegiskey.app.caps.CapsResult

/**
 * Device-reported OTA base version (authority-first, never invented).
 *
 * Prefers the live GET_CAPS `fw_version` where available (read-only, no
 * auth, same visibility class as the fw-log opcode): the firmware reports
 * its crate version text (e.g. "1.0.0") while OTA manifests carry a
 * monotonic u32, so [parseOtaCurrentVersion] reads the leading integer
 * best-effort. A non-numeric or absent device version falls back to the
 * local cached `firmwareRevision` default, else 0L (fail-closed downgrade
 * gate in [Ota2Engine] then denies stale manifests; nothing is fabricated).
 */
fun parseOtaCurrentVersion(fwVersion: String): Long? {
    val head = fwVersion.trim().takeWhile { it.isDigit() }
    return head.takeIf { it.isNotEmpty() }?.toLongOrNull()
}

/**
 * Resolves the OTA `currentVersion`: live GET_CAPS first, local cached
 * revision second, 0L last. Old firmware without 0x3F answers
 * [CapsResult.Unknown], which lands on the local default by construction.
 */
fun resolveOtaCurrentVersion(caps: CapsResult?, fallbackRevision: Int?): Long {
    val device = (caps as? CapsResult.Known)?.report?.fwVersion?.let(::parseOtaCurrentVersion)
    if (device != null) return device
    // Local default: cached device record (may lag behind the live key);
    // negative values are corrupt input, never a version.
    val fallback = fallbackRevision?.toLong()?.takeIf { it >= 0 }
    if (fallback != null) return fallback
    return 0L
}
