package dev.aegiskey.app.usb

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.os.Build
import dev.aegiskey.app.log.DeviceLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

/**
 * USB host CTAPHID (firmware usb_descriptors.rs):
 * VID 0x303A, PID 0xAE61, interface 0 HID com 2 endpoints interrupt 64B.
 * Pacotes 64B: init [CID(4), CMD|0x80, BCNT(2 BE), 57B] + continuacao
 * [CID(4), SEQ, 59B] — mesmo framing do firmware (CtapHidFramer).
 * Permissao via UsbManager.requestPermission (runtime, dialogo sistema).
 * Sem Log com PII: so status/tamanhos.
 */
class UsbCtaphid(private val context: Context) {

    enum class State { IDLE, PERMISSION_NEEDED, CONNECTED, ERROR }

    data class UiState(
        val state: State = State.IDLE,
        val label: String = "desconectado",
        val error: String? = null,
    )

    companion object {
        const val VID: Int = 0x303A
        const val PID: Int = 0xAE61
        const val ACTION_USB_PERMISSION: String = "dev.aegiskey.app.USB_PERMISSION"
        const val PACKET_SIZE: Int = 64
        const val CMD_PING: Int = 0x81
        const val CMD_MSG: Int = 0x83
        const val CMD_INIT: Int = 0x86
    }

    private val usb: UsbManager =
        context.getSystemService(Context.USB_SERVICE) as UsbManager

    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    private var connection: UsbDeviceConnection? = null
    private var claimed: UsbInterface? = null
    private var epIn: UsbEndpoint? = null
    private var epOut: UsbEndpoint? = null
    private var channelId: Int = 0x01020304

    private val permissionReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            if (intent.action != ACTION_USB_PERMISSION) return
            val device: UsbDevice? = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
            val granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)
            if (granted && device != null) {
                openDevice(device)
            } else {
                _ui.value = UiState(State.ERROR, "permissao USB negada", "permissao negada no dialogo do sistema")
                DeviceLog.append(DeviceLog.Category.SYSTEM, "USB permission denied")
            }
        }
    }

    init {
        runCatching {
            context.registerReceiver(permissionReceiver, IntentFilter(ACTION_USB_PERMISSION))
        }
    }

    fun release() {
        runCatching { context.unregisterReceiver(permissionReceiver) }
        close()
    }

    fun findDevice(): UsbDevice? =
        usb.deviceList.values.firstOrNull { it.vendorId == VID && it.productId == PID }

    fun requestPermission(device: UsbDevice) {
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }
        val intent = Intent(ACTION_USB_PERMISSION).setPackage(context.packageName)
        val pi = PendingIntent.getBroadcast(context, 0, intent, flags)
        usb.requestPermission(device, pi)
        _ui.value = UiState(State.PERMISSION_NEEDED, "confirme no dialogo do sistema")
        DeviceLog.append(DeviceLog.Category.SYSTEM, "USB permission requested")
    }

    fun openDevice(device: UsbDevice) {
        val conn = usb.openDevice(device) ?: run {
            _ui.value = UiState(State.ERROR, "nao abriu o dispositivo", "openDevice retornou null")
            return
        }
        var picked: UsbInterface? = null
        var i = 0
        while (i < device.interfaceCount) {
            val itf = device.getInterface(i)
            if (itf.interfaceClass == UsbConstants.USB_CLASS_HID && itf.endpointCount >= 2) {
                picked = itf
                break
            }
            i += 1
        }
        val ctaphid = picked ?: device.getInterface(0)
        if (!conn.claimInterface(ctaphid, true)) {
            conn.close()
            _ui.value = UiState(State.ERROR, "interface ocupada", "claimInterface falhou (talvez em uso)")
            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB claim failed")
            return
        }
        var inEp: UsbEndpoint? = null
        var outEp: UsbEndpoint? = null
        var e = 0
        while (e < ctaphid.endpointCount) {
            val ep = ctaphid.getEndpoint(e)
            if (ep.maxPacketSize == PACKET_SIZE && ep.type == UsbConstants.USB_ENDPOINT_XFER_INT) {
                if (ep.direction == UsbConstants.USB_DIR_IN) inEp = ep
                else outEp = ep
            }
            e += 1
        }
        if (inEp == null || outEp == null) {
            conn.releaseInterface(ctaphid)
            conn.close()
            _ui.value = UiState(State.ERROR, "endpoints 64B nao achados", "interface sem par interrupt 64B")
            return
        }
        connection = conn
        claimed = ctaphid
        epIn = inEp
        epOut = outEp
        _ui.value = UiState(State.CONNECTED, "conectado via USB (CTAPHID 64B)")
        DeviceLog.append(DeviceLog.Category.SYSTEM, "USB connected CTAPHID 64B")
    }

    fun close() {
        runCatching {
            claimed?.let { connection?.releaseInterface(it) }
            connection?.close()
        }
        connection = null
        claimed = null
        epIn = null
        epOut = null
        _ui.value = UiState(State.IDLE, "desconectado")
    }

    fun frameMessage(cid: Int, cmd: Int, payload: ByteArray): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        val total = payload.size
        val first = ByteArray(PACKET_SIZE)
        first[0] = ((cid shr 24) and 0xFF).toByte()
        first[1] = ((cid shr 16) and 0xFF).toByte()
        first[2] = ((cid shr 8) and 0xFF).toByte()
        first[3] = (cid and 0xFF).toByte()
        first[4] = ((cmd or 0x80) and 0xFF).toByte()
        first[5] = ((total shr 8) and 0xFF).toByte()
        first[6] = (total and 0xFF).toByte()
        val head = minOf(57, total)
        payload.copyInto(first, 7, 0, head)
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
            val n = minOf(59, total - off)
            payload.copyInto(pkt, 5, off, off + n)
            out.add(pkt)
            off += n
            seq += 1
        }
        return out
    }

    suspend fun pingTest(payload: ByteArray = byteArrayOf(1, 2, 3, 4)): Boolean =
        withContext(Dispatchers.IO) {
            val conn = connection
            val outEp = epOut
            val inEp = epIn
            if (conn == null || outEp == null || inEp == null) return@withContext false
            val packets = frameMessage(channelId, CMD_PING, payload)
            for (pkt in packets) {
                if (conn.bulkTransfer(outEp, pkt, pkt.size, 2000) != PACKET_SIZE) {
                    DeviceLog.append(DeviceLog.Category.SYSTEM, "USB write failed")
                    return@withContext false
                }
            }
            val buf = ByteArray(PACKET_SIZE)
            val n = conn.bulkTransfer(inEp, buf, buf.size, 3000)
            if (n <= 0) {
                DeviceLog.append(DeviceLog.Category.SYSTEM, "USB read timeout")
                return@withContext false
            }
            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB ping bytes=" + n)
            true
        }
}
