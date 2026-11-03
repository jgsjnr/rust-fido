package dev.aegiskey.app.caps

import dev.aegiskey.app.data.transport.KeyTransport

/**
 * GET_CAPS query (caps module entry seam for transports).
 *
 * Sends the empty request via the existing [KeyTransport] helpers
 * (USB + BLE share this seam; see Ota2Transport.asOta2Transport).
 * No auth is required device-side (read-only, same visibility class
 * as 0x38 fw-log). Every failure — null reply, unexpected opcode or
 * status (e.g. 0x04/0x06 on firmware predating 0x3F), malformed CBOR
 * — collapses to [CapsResult.Unknown]. The repository never invents
 * telemetry, state, values, prose, or effects.
 */
object CapsRepository {

    suspend fun query(transport: KeyTransport): CapsResult {
        return try {
            val raw = transport.sendVendor(CapsConstants.OP_GET_CAPS, ByteArray(0))
                ?: return CapsResult.Unknown
            val (status, body) = CapsParser.parseFrame(CapsConstants.OP_GET_CAPS, raw)
                ?: return CapsResult.Unknown
            if (status != CapsConstants.STATUS_OK) return CapsResult.Unknown
            val report = CapsParser.parseCapsResponse(body) ?: return CapsResult.Unknown
            CapsResult.Known(report)
        } catch (_: Throwable) {
            CapsResult.Unknown
        }
    }
}
