package dev.aegiskey.app.ota2

/**
 * Device-authority OTA reception progress (ota2 screen).
 *
 * Wire truth: the session opcodes are 0x30 BEGIN / 0x31 CHUNK / 0x32 FINISH /
 * 0x34 ABORT only — there is NO `ota_progress` status field or poll opcode
 * on the wire (firmware `ota.rs` + `stores/ota_store.rs`). The only
 * device-reported progress is the CHUNK reply body: total bytes received as
 * u32 BE ([Ota2Engine.parseAck]), surfaced per round-trip through
 * [Ota2Engine.run]'s `onProgress(sent, total)`. Each CHUNK send/ack
 * round-trip IS the reception poll; the app never estimates from local
 * writes and never invents a percentage.
 *
 * This file translates those acked counts into screen values only:
 * [otaProgressPercent] is pure + JVM-testable, null when the device gave no
 * usable denominator (unsupported) or the counts are incoherent (error).
 * Labels stay in `ota_strings.xml`; 0x33 COMMIT is never sent here.
 */

/**
 * Real device-acked reception percent (0..100), or null when unknown.
 *
 * - `total <= 0`: no denominator from the staged manifest (unsupported).
 * - `received < 0 || received > total`: incoherent ack (error); the engine
 *   already fails such sessions as [Ota2Failure.DeviceRejected].
 */
fun otaProgressPercent(received: Int, total: Int): Int? {
    if (total <= 0) return null
    if (received < 0 || received > total) return null
    return ((received.toLong() * 100L) / total.toLong()).toInt()
}
