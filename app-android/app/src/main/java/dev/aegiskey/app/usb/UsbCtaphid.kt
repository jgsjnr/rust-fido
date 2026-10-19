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
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

/**
 * USB host CTAPHID (firmware usb_descriptors.rs):
 * VID 0x303A, PID 0xAE61, interface 0 HID com 2 endpoints interrupt 64B.
 * Pacotes 64B: init [CID(4), CMD|0x80, BCNT(2 BE), 57B] + continuacao
 * [CID(4), SEQ, 59B] — mesmo framing do firmware (CtapHidFramer).
 * Permissao via UsbManager.requestPermission (runtime, dialogo sistema).
 * Sem Log com PII: so status/tamanhos (nunca nome/serial/payload).
 */
class UsbCtaphid(private val context: Context) {

    enum class State { IDLE, SEARCHING, PERMISSION_NEEDED, CONNECTED, ERROR }

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
        const val WRITE_TIMEOUT_MS: Int = 2000
        const val READ_TIMEOUT_MS: Int = 3000
        const val PING_TIMEOUT_MS: Long = 6000L
        const val MAX_PING_BYTES: Int = 1024
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

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            when (intent.action) {
                ACTION_USB_PERMISSION -> {
                    val device: UsbDevice? =
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                        } else {
                            @Suppress("DEPRECATION")
                            intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                        }
                    val granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)
                    if (granted && device != null) {
                        DeviceLog.append(DeviceLog.Category.SYSTEM, "USB permission granted")
                        openDevice(device)
                    } else {
                        _ui.value = UiState(
                            State.ERROR,
                            "permissao USB negada",
                            "Permissao negada. Toque em Desconectar e tente de novo, ou use BLE.",
                        )
                        DeviceLog.append(DeviceLog.Category.SYSTEM, "USB permission denied")
                    }
                }
                UsbManager.ACTION_USB_DEVICE_ATTACHED -> {
                    val device: UsbDevice? =
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                        } else {
                            @Suppress("DEPRECATION")
                            intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                        }
                    if (device != null && device.vendorId == VID && device.productId == PID) {
                        DeviceLog.append(DeviceLog.Category.SYSTEM, "USB attached")
                        if (usb.hasPermission(device)) {
                            openDevice(device)
                        } else {
                            _ui.value = UiState(
                                State.IDLE,
                                "dispositivo plugado — toque em Procurar",
                            )
                        }
                    }
                }
                UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                    val device: UsbDevice? =
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                        } else {
                            @Suppress("DEPRECATION")
                            intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                        }
                    if (device != null && device.vendorId == VID && device.productId == PID) {
                        DeviceLog.append(DeviceLog.Category.SYSTEM, "USB detached")
                        close()
                    }
                }
            }
        }
    }

    init {
        runCatching {
            val filter = IntentFilter().apply {
                addAction(ACTION_USB_PERMISSION)
                addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
                addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.registerReceiver(usbReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                context.registerReceiver(usbReceiver, filter)
            }
        }.onFailure {
            _ui.value = UiState(State.ERROR, "receiver USB falhou", "Reinicie o app e tente de novo, ou use BLE.")
        }
    }

    fun release() {
        runCatching { context.unregisterReceiver(usbReceiver) }
        close()
    }

    fun findDevice(): UsbDevice? =
        usb.deviceList.values.firstOrNull { it.vendorId == VID && it.productId == PID }

    fun markSearching() {
        _ui.value = UiState(State.SEARCHING, "procurando AegisKey USB...")
        DeviceLog.append(DeviceLog.Category.SYSTEM, "USB search started")
    }

    fun noteNotFound() {
        _ui.value = UiState(
            State.ERROR,
            "AegisKey nao achada",
            "Confira o cabo OTG. Tente de novo ou use BLE.",
        )
        DeviceLog.append(DeviceLog.Category.SYSTEM, "USB search miss")
    }

    fun requestPermission(device: UsbDevice) {
        if (usb.hasPermission(device)) {
            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB already granted")
            openDevice(device)
            return
        }
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
        DeviceLog.append(DeviceLog.Category.SYSTEM, "USB open started")
        val conn = usb.openDevice(device) ?: run {
            _ui.value = UiState(
                State.ERROR,
                "nao abriu o dispositivo",
                "Tente de novo ou use BLE.",
            )
            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB open failed")
            return
        }
        var picked: UsbInterface? = null
        var pickedIdx = -1
        var i = 0
        while (i < device.interfaceCount) {
            val itf = device.getInterface(i)
            if (itf.interfaceClass == UsbConstants.USB_CLASS_HID && itf.endpointCount >= 2) {
                picked = itf
                pickedIdx = i
                break
            }
            i += 1
        }
        val ctaphid = picked ?: run {
            if (device.interfaceCount > 0) device.getInterface(0) else null
        }
        if (ctaphid == null) {
            conn.close()
            _ui.value = UiState(
                State.ERROR,
                "sem interface USB",
                "Tente de novo ou use BLE.",
            )
            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB no interface")
            return
        }
        val cls = ctaphid.interfaceClass
        DeviceLog.append(
            DeviceLog.Category.SYSTEM,
            "USB iface idx=" + pickedIdx + " class=" + cls + " eps=" + ctaphid.endpointCount,
        )
        if (!conn.claimInterface(ctaphid, true)) {
            conn.close()
            _ui.value = UiState(
                State.ERROR,
                "interface ocupada",
                "Feche outro app USB e tente de novo, ou use BLE.",
            )
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
        DeviceLog.append(
            DeviceLog.Category.SYSTEM,
            "USB eps in=" + (inEp != null) + " out=" + (outEp != null) + " size=" + PACKET_SIZE,
        )
        if (inEp == null || outEp == null) {
            conn.releaseInterface(ctaphid)
            conn.close()
            _ui.value = UiState(
                State.ERROR,
                "endpoints 64B nao achados",
                "Tente de novo ou use BLE.",
            )
            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB endpoints missing")
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
        val wasActive = connection != null || _ui.value.state != State.IDLE
        runCatching {
            claimed?.let { connection?.releaseInterface(it) }
            connection?.close()
        }
        connection = null
        claimed = null
        epIn = null
        epOut = null
        _ui.value = UiState(State.IDLE, "desconectado")
        if (wasActive) {
            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB disconnected (app)")
        }
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
            if (payload.isEmpty() || payload.size > MAX_PING_BYTES) return@withContext false
            val conn = connection
            val outEp = epOut
            val inEp = epIn
            if (conn == null || outEp == null || inEp == null) return@withContext false
            try {
                withTimeout(PING_TIMEOUT_MS) {
                    DeviceLog.append(DeviceLog.Category.SYSTEM, "USB ping bytes=" + payload.size)
                    val packets = frameMessage(channelId, CMD_PING, payload)
                    for (pkt in packets) {
                        if (conn.bulkTransfer(outEp, pkt, pkt.size, WRITE_TIMEOUT_MS) != PACKET_SIZE) {
                            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB write failed")
                            return@withTimeout false
                        }
                    }
                    val buf = ByteArray(PACKET_SIZE)
                    val n = conn.bulkTransfer(inEp, buf, buf.size, READ_TIMEOUT_MS)
                    if (n <= 0) {
                        DeviceLog.append(DeviceLog.Category.SYSTEM, "USB read timeout")
                        return@withTimeout false
                    }
                    DeviceLog.append(DeviceLog.Category.SYSTEM, "USB ping ok bytes=" + n)
                    true
                }
            } catch (_: TimeoutCancellationException) {
                DeviceLog.append(DeviceLog.Category.SYSTEM, "USB ping timeout")
                false
            }
        }
}
