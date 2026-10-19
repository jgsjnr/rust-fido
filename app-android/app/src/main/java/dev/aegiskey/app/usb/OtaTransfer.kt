package dev.aegiskey.app.usb

import dev.aegiskey.app.log.DeviceLog
import java.io.ByteArrayOutputStream

/**
 * OTA USB transfer (Wave 1 Task A, traces R-03): app is transport-only, it
 * never sees keys. Splits a firmware image into 64B CTAPHID packets with the
 * exact UsbCtaphid.frameMessage layout (init: 7B header CID/CMD/BCNT + 57B;
 * continuation: 5B header CID/SEQ + 59B), reassembles for verification, and
 * pushes via [OtaUsbTransport] with per-packet write-fail abort.
 *
 * Firmware chunk opcode family 0x30 (matches firmware ota.rs, Task F):
 * [splitBinary] frames one CTAPHID message whose CMD byte is
 * (opBegin or 0x80); multi-chunk begin/data/end sequencing on top of
 * [pushImage] is Step-4 wiring, once Task F's chunk protocol lands.
 *
 * WIRING TODO (Step-4 app wiring): UsbCtaphid.kt owns its UsbDeviceConnection
 * + endpoints privately and is deliberately untouched here. Wire-up options:
 *  (a) expose connection/endpoints from UsbCtaphid behind an OtaUsbTransport
 *      impl, or (b) implement OtaUsbTransport in the wiring layer by delegating
 *      write() to UsbDeviceConnection.bulkTransfer(epOut, packet, 64,
 *      WRITE_TIMEOUT_MS). Full CTAPHID INIT (negotiated CID) also belongs to
 *      that step; [DEFAULT_CID] mirrors UsbCtaphid's initial channel id.
 */
interface OtaUsbTransport {
    fun write(packet: ByteArray): Boolean
    fun read(timeoutMs: Int): ByteArray?
}

object OtaTransfer {
    const val PACKET_SIZE = 64
    const val FIRST_DATA_BYTES = 57
    const val CONT_DATA_BYTES = 59
    const val DEFAULT_CID = 0x01020304
    const val OP_BEGIN = 0x30
    const val MAX_IMAGE_BYTES = 4 * 1024 * 1024

    /**
     * Pure + JVM-testable: frame [binary] as one CTAPHID message.
     * Rejects empty (IllegalArgumentException) and oversize images.
     */
    fun splitBinary(binary: ByteArray, opBegin: Int = OP_BEGIN): List<ByteArray> {
        require(binary.isNotEmpty()) { "empty firmware image" }
        require(binary.size <= MAX_IMAGE_BYTES) { "firmware image oversize" }
        require(opBegin in 0..0xFF) { "bad opcode" }
        val out = ArrayList<ByteArray>(binary.size / CONT_DATA_BYTES + 1)
        val total = binary.size
        val first = ByteArray(PACKET_SIZE)
        first[0] = ((DEFAULT_CID shr 24) and 0xFF).toByte()
        first[1] = ((DEFAULT_CID shr 16) and 0xFF).toByte()
        first[2] = ((DEFAULT_CID shr 8) and 0xFF).toByte()
        first[3] = (DEFAULT_CID and 0xFF).toByte()
        first[4] = ((opBegin or 0x80) and 0xFF).toByte()
        first[5] = ((total shr 8) and 0xFF).toByte()
        first[6] = (total and 0xFF).toByte()
        val head = minOf(FIRST_DATA_BYTES, total)
        binary.copyInto(first, 7, 0, head)
        out.add(first)
        var off = head
        var seq = 0
        while (off < total) {
            val pkt = ByteArray(PACKET_SIZE)
            pkt[0] = first[0]
            pkt[1] = first[1]
            pkt[2] = first[2]
            pkt[3] = first[3]
            pkt[4] = (seq and 0x7F).toByte()
            val n = minOf(CONT_DATA_BYTES, total - off)
            binary.copyInto(pkt, 5, off, off + n)
            out.add(pkt)
            off += n
            seq += 1
        }
        DeviceLog.append(
            DeviceLog.Category.SYSTEM,
            "OTA split packets=" + out.size + " bytes=" + total,
        )
        return out
    }

    /**
     * Pure + JVM-testable inverse of [splitBinary] for verification:
     * checks 64B sizes, CID continuity, SEQ order and BCNT truncation.
     * Throws IllegalArgumentException on malformed input.
     */
    fun reassemble(packets: List<ByteArray>): ByteArray {
        require(packets.isNotEmpty()) { "no packets" }
        val first = packets[0]
        require(first.size == PACKET_SIZE) { "bad init packet size" }
        val total = ((first[5].toInt() and 0xFF) shl 8) or (first[6].toInt() and 0xFF)
        require(total in 1..MAX_IMAGE_BYTES) { "bad image length" }
        val cid = first.copyOfRange(0, 4)
        val out = ByteArrayOutputStream(total)
        val head = minOf(FIRST_DATA_BYTES, total)
        out.write(first, 7, head)
        var off = head
        var seq = 0
        var i = 1
        while (off < total) {
            require(i < packets.size) { "truncated packets" }
            val pkt = packets[i]
            require(pkt.size == PACKET_SIZE) { "bad cont packet size" }
            require(pkt.copyOfRange(0, 4).contentEquals(cid)) { "cid mismatch" }
            require((pkt[4].toInt() and 0x7F) == (seq and 0x7F)) { "seq mismatch" }
            val n = minOf(CONT_DATA_BYTES, total - off)
            out.write(pkt, 5, n)
            off += n
            seq += 1
            i += 1
        }
        return out.toByteArray()
    }

    /**
     * Pushes [binary] packet-by-packet; aborts (returns false) on the first
     * write failure. Returns true only when every packet was accepted.
     * Empty/oversize images are rejected by [splitBinary] before any write.
     */
    fun pushImage(
        transport: OtaUsbTransport,
        binary: ByteArray,
        onProgress: ((sent: Int, total: Int) -> Unit)? = null,
    ): Boolean {
        val packets = splitBinary(binary)
        var i = 0
        while (i < packets.size) {
            if (!transport.write(packets[i])) {
                DeviceLog.append(
                    DeviceLog.Category.SYSTEM,
                    "OTA push abort sent=" + i + "/" + packets.size,
                )
                return false
            }
            i += 1
            onProgress?.invoke(i, packets.size)
        }
        DeviceLog.append(
            DeviceLog.Category.SYSTEM,
            "OTA push ok packets=" + packets.size + " bytes=" + binary.size,
        )
        return true
    }
}
