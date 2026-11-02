package dev.aegiskey.app.ota2

import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.data.transport.KeyTransport

/** Authority device reply: vendor [op, status, body...] (S9.5 parity). */
data class Ota2Reply(
    val op: Int,
    val status: Int,
    val body: ByteArray,
)

/**
 * Minimal OTA transport seam. BLE preferred (BleKeyTransport), USB
 * fallback (UsbKeyTransport): both implement KeyTransport, so the engine
 * stays transport-agnostic. Null reply = link lost (resumable), never
 * a faked success.
 */
interface Ota2Transport {
    suspend fun send(opcode: Int, payload: ByteArray): Ota2Reply?
}

/**
 * Reuses the shared helpers (KeyTransport sender patterns +
 * VendorOps.parseResponse), no duplication. Response shape [op, status,
 * TLV...] matches AegisBleClient.sendVendor / UsbCtaphid.sendVendor.
 */
fun KeyTransport.asOta2Transport(): Ota2Transport = object : Ota2Transport {
    override suspend fun send(opcode: Int, payload: ByteArray): Ota2Reply? {
        val raw = sendVendor(opcode, payload) ?: return null
        val resp = VendorOps.parseResponse(raw) ?: return null
        return Ota2Reply(op = resp.op, status = resp.status, body = resp.tlv)
    }
}
