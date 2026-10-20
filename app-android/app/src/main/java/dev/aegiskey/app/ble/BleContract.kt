package dev.aegiskey.app.ble

import java.util.UUID

/**
 * Frozen BLE contract — mirrors docs/ble-protocol.md and firmware/src/ble_gatt.rs.
 * Single source of truth for 128-bit UUIDs expanded from the 16-bit handles.
 * Fase6 apendice 9 (vendor 0x20-0x27): GATT inalterado, revisao permanece 0x01.
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

    // Fase6 vendor ops (FFF1 control-point, framing S3 reutilizado).
    const val OP_KEY_GEN_ONDEVICE = 0x20
    const val OP_KEY_IMPORT_ENVELOPE = 0x21
    const val OP_KEY_LIST = 0x22
    const val OP_KEY_DELETE = 0x23
    const val OP_OATH_PUT = 0x24
    const val OP_OATH_LIST = 0x25
    const val OP_OATH_CODE = 0x26
    const val OP_OATH_DELETE = 0x27

    // Carteira Fase7 (0x35-0x37) + log da firmware (0x38, ASCII sem PII).
    const val OP_WALLET_GEN = 0x35
    const val OP_WALLET_LIST = 0x36
    const val OP_WALLET_ADDR = 0x37
    const val OP_FW_LOG = 0x38

    // Vendor status set (fechado, S9.5).
    const val VENDOR_OK = 0x00
    const val VENDOR_NEED_UP = 0x01
    const val VENDOR_NEED_PIN = 0x02
    const val VENDOR_NO_SLOT = 0x03
    const val VENDOR_BAD_ENVELOPE = 0x04

    fun uuid16(short: Int): UUID =
        UUID.fromString(String.format("0000%04X-0000-1000-8000-00805F9B34FB", short))

    val SERVICE_UUID: UUID = uuid16(SERVICE_UUID16)
    val CHAR_CONTROL: UUID = uuid16(CHAR_CONTROL16)
    val CHAR_STATUS: UUID = uuid16(CHAR_STATUS16)
    val CHAR_LEN: UUID = uuid16(CHAR_LEN16)
    val CHAR_REVISION: UUID = uuid16(CHAR_REVISION16)
    val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805F9B34FB")

    fun statusLabel(status: Int): String = when (status) {
        STATUS_IDLE -> "livre"
        STATUS_PROCESSING -> "processando"
        STATUS_UP_NEEDED -> "toque no botão do dispositivo"
        else -> "desconhecido"
    }

    fun isVendorOp(op: Int): Boolean =
        op in OP_KEY_GEN_ONDEVICE..OP_OATH_DELETE || op in OP_WALLET_GEN..OP_FW_LOG

    fun vendorOpName(op: Int): String = when (op) {
        OP_KEY_GEN_ONDEVICE -> "0x20 key-gen-ondevice"
        OP_KEY_IMPORT_ENVELOPE -> "0x21 key-import"
        OP_KEY_LIST -> "0x22 key-list"
        OP_KEY_DELETE -> "0x23 key-delete"
        OP_OATH_PUT -> "0x24 oath-put"
        OP_OATH_LIST -> "0x25 oath-list"
        OP_OATH_CODE -> "0x26 oath-code"
        OP_OATH_DELETE -> "0x27 oath-delete"
        OP_WALLET_GEN -> "0x35 wallet-gen"
        OP_WALLET_LIST -> "0x36 wallet-list"
        OP_WALLET_ADDR -> "0x37 wallet-addr"
        OP_FW_LOG -> "0x38 fw-log"
        else -> "0x" + String.format("%02X", op)
    }
}
