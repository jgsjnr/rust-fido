package dev.aegiskey.app.domain.usecase

import dev.aegiskey.app.data.transport.KeyTransport
import dev.aegiskey.app.oob.OobPairing

/**
 * Arms the firmware OOB latch (`0x42`) over the existing USB transport.
 *
 * A fresh 16 B TK is sampled per call ([OobPairing.generateTk]), sent
 * as the `sendVendor` payload (the transport frames `[0x42, tk...]`
 * on `CMD_MSG`), then wiped from memory along with the framing copy.
 * Takes ownership of [tk]: the buffer is zeroed before return. The BLE
 * GATT path is never used: `0x42` is serial/USB-only by firmware
 * construction and `AegisBleClient.sendVendor` rejects it fail-closed.
 *
 * Returns the structured authority answer ([OobPairing.ArmResult]);
 * never throws for device denials. An invalid TK or a transport miss
 * maps to a failure result, never to success.
 */
class ArmBleOobUseCase(
    private val usbTransport: KeyTransport
) {
    suspend operator fun invoke(tk: ByteArray = OobPairing.generateTk()): OobPairing.ArmResult {
        try {
            if (!OobPairing.isValidTk(tk)) return OobPairing.ArmResult.BadEnvelope(-1)
            val payload = OobPairing.armPayload(tk)
            try {
                val raw = usbTransport.sendVendor(OobPairing.OP_BLE_OOB_ARM, payload)
                return OobPairing.parseArmResponse(raw)
            } catch (_: Throwable) {
                return OobPairing.ArmResult.TransportFailure
            } finally {
                payload.fill(0)
            }
        } finally {
            tk.fill(0)
        }
    }
}
