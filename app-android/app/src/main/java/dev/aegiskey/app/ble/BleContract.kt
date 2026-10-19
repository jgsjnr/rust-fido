package dev.aegiskey.app.ble

import java.util.UUID

/**
 * Frozen BLE contract — mirrors docs/ble-protocol.md and firmware/src/ble_gatt.rs.
 * Single source of truth for 128-bit UUIDs expanded from the 16-bit handles.
 */
object BleContract {
    const val SERVICE_UUID16 = 0xFFFD
    const val CHAR_CONTROL16 = 0xFFF1
    const val CHAR_STATUS16 = 0xFFF2
    const val CHAR_LEN16 = 0xFFF3
    const val CHAR_REVISION16 = 0xFFF4

    const val GATT_REVISION = 0x01

    // CTAP2-BLE opcodes (first-fragment byte).
    const val OP_PING = 0x81
    const val OP_MSG = 0x83
    const val OP_CANCEL = 0xBE

    // FFF2 status/keepalive values.
    const val STATUS_IDLE = 0
    const val STATUS_PROCESSING = 1
    const val STATUS_UP_NEEDED = 2

    // CTAP2 command bytes carried inside OP_MSG as [cmd, CBOR...].
    const val CTAP_CMD_MAKE_CREDENTIAL = 0x01
    const val CTAP_CMD_GET_ASSERTION = 0x02
    const val CTAP_CMD_GET_INFO = 0x04

    fun uuid16(short: Int): UUID =
        UUID.fromString(String.format("0000%04X-0000-1000-8000-00805F9B34FB", short))

    val SERVICE_UUID: UUID = uuid16(SERVICE_UUID16)
    val CHAR_CONTROL: UUID = uuid16(CHAR_CONTROL16)
    val CHAR_STATUS: UUID = uuid16(CHAR_STATUS16)
    val CHAR_LEN: UUID = uuid16(CHAR_LEN16)
    val CHAR_REVISION: UUID = uuid16(CHAR_REVISION16)
    val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805F9B34FB")

    fun statusLabel(status: Int): String = when (status) {
        STATUS_IDLE -> "idle"
        STATUS_PROCESSING -> "processing"
        STATUS_UP_NEEDED -> "up-needed (press device button)"
        else -> "unknown"
    }
}
