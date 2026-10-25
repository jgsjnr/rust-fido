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
import androidx.core.content.ContextCompat
import dev.aegiskey.app.log.DeviceLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.security.SecureRandom

/**
 * USB host CTAPHID (firmware usb_descriptors.rs):
 * Suporta VID 0x303A:PID 0xAE61 (nativo) e VID 0x0483:PID 0xA2CA (OTG PHY GPIO 19/20).
 * Interface HID com 2 endpoints interrupt 64B.
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
        const val VID_ALT: Int = 0x0483
        const val PID_ALT: Int = 0xA2CA

        const val ACTION_USB_PERMISSION: String = "dev.aegiskey.app.USB_PERMISSION"
        const val PACKET_SIZE: Int = 64
        const val BROADCAST_CID: Int = -1 // 0xFFFFFFFF
        const val CMD_PING: Int = 0x81
        const val CMD_MSG: Int = 0x83
        const val CMD_INIT: Int = 0x86
        const val CTAPHID_KEEPALIVE: Int = 0xBB
        const val CTAPHID_ERROR: Int = 0xBF
        const val OP_TRIGGER_PAIRING_OPEN: Int = 0x2F
        const val STATUS_NEED_UP: Int = 0x01
        const val STATUS_NEED_PIN: Int = 0x02
        const val STATUS_NEED_BINDING: Int = 0x05
        const val WRITE_TIMEOUT_MS: Int = 2000
        const val READ_TIMEOUT_MS: Int = 3000
        const val PING_TIMEOUT_MS: Long = 6000L
        const val MAX_PING_BYTES: Int = 1024

        fun isMatchingDevice(device: UsbDevice?): Boolean {
            if (device == null) return false
            val vid = device.vendorId
            val pid = device.productId
            return (vid == VID && pid == PID) || (vid == VID_ALT && pid == PID_ALT)
        }
    }

    val isConnected: Boolean
        get() = connection != null && epIn != null && epOut != null

    private val usb: UsbManager? =
        try { context.getSystemService(Context.USB_SERVICE) as? UsbManager } catch (_: Throwable) { null }

    private val _isHardwareAttached = MutableStateFlow(findDevice() != null)
    val isHardwareAttached: StateFlow<Boolean> = _isHardwareAttached.asStateFlow()

    fun isUsbPhysicallyPresent(): Boolean = findAegisDevice() != null

    fun findAegisDevice(): UsbDevice? = findDevice()

    fun open(): Boolean {
        val dev = findAegisDevice() ?: return false
        val u = usb ?: return false
        if (!u.hasPermission(dev)) {
            requestPermission(dev)
            return false
        }
        openDevice(dev)
        return isConnected
    }

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
                    if (isMatchingDevice(device) && device != null) {
                        _isHardwareAttached.value = true
                        DeviceLog.append(DeviceLog.Category.SYSTEM, "USB attached")
                        val u = usb
                        if (u != null && u.hasPermission(device)) {
                            openDevice(device)
                        } else {
                            requestPermission(device)
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
                    if (isMatchingDevice(device) || findDevice() == null) {
                        _isHardwareAttached.value = false
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
            ContextCompat.registerReceiver(
                context,
                usbReceiver,
                filter,
                ContextCompat.RECEIVER_NOT_EXPORTED,
            )
        }.onFailure {
            _ui.value = UiState(State.ERROR, "receiver USB falhou", "Reinicie o app e tente de novo, ou use BLE.")
        }
    }

    fun release() {
        runCatching { context.unregisterReceiver(usbReceiver) }
        close()
    }

    fun findDevice(): UsbDevice? =
        usb?.deviceList?.values?.firstOrNull { isMatchingDevice(it) }

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
        val u = usb ?: return
        if (u.hasPermission(device)) {
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
        u.requestPermission(device, pi)
        _ui.value = UiState(State.PERMISSION_NEEDED, "confirme no dialogo do sistema")
        DeviceLog.append(DeviceLog.Category.SYSTEM, "USB permission requested")
    }

    fun openDevice(device: UsbDevice) {
        DeviceLog.append(DeviceLog.Category.SYSTEM, "USB open started")
        val u = usb ?: run {
            _ui.value = UiState(
                State.ERROR,
                "servico USB indisponivel",
                "Tente de novo ou use BLE.",
            )
            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB manager null")
            return
        }
        val conn = u.openDevice(device) ?: run {
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
        _isHardwareAttached.value = true
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
        _isHardwareAttached.value = findAegisDevice() != null
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
                        val written = conn.bulkTransfer(outEp, pkt, pkt.size, WRITE_TIMEOUT_MS)
                        if (written != PACKET_SIZE) {
                            if (written < 0) close()
                            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB write failed")
                            return@withTimeout false
                        }
                    }
                    val buf = ByteArray(PACKET_SIZE)
                    val n = conn.bulkTransfer(inEp, buf, buf.size, READ_TIMEOUT_MS)
                    if (n <= 0) {
                        if (n < 0) close()
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

    private suspend fun ensureChannelInitialized(conn: UsbDeviceConnection, outEp: UsbEndpoint, inEp: UsbEndpoint): Boolean {
        if (channelId != 0x01020304 && channelId != -1 && channelId != 0) {
            return true
        }
        val nonce = ByteArray(8).also { SecureRandom().nextBytes(it) }
        val initPacket = ByteArray(PACKET_SIZE)
        initPacket[0] = 0xFF.toByte()
        initPacket[1] = 0xFF.toByte()
        initPacket[2] = 0xFF.toByte()
        initPacket[3] = 0xFF.toByte()
        initPacket[4] = CMD_INIT.toByte()
        initPacket[5] = 0x00
        initPacket[6] = 0x08
        nonce.copyInto(initPacket, 7, 0, 8)

        val sent = conn.bulkTransfer(outEp, initPacket, PACKET_SIZE, WRITE_TIMEOUT_MS)
        if (sent != PACKET_SIZE) {
            if (sent < 0) close()
            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB init write failed")
            return false
        }

        val buf = ByteArray(PACKET_SIZE)
        val read = conn.bulkTransfer(inEp, buf, PACKET_SIZE, READ_TIMEOUT_MS)
        if (read < 0) {
            close()
            return false
        }
        if (read == PACKET_SIZE && (buf[4].toInt() and 0xFF) == CMD_INIT) {
            val nonceOk = (0..7).all { buf[7 + it] == nonce[it] }
            if (nonceOk) {
                val newCid = ((buf[15].toInt() and 0xFF) shl 24) or
                    ((buf[16].toInt() and 0xFF) shl 16) or
                    ((buf[17].toInt() and 0xFF) shl 8) or
                    (buf[18].toInt() and 0xFF)
                channelId = newCid
                DeviceLog.append(DeviceLog.Category.SYSTEM, "USB CTAPHID channel negotiated CID=0x%08X".format(newCid))
                return true
            }
        }
        DeviceLog.append(DeviceLog.Category.SYSTEM, "USB init negotiation fallback to default CID")
        channelId = 0x01020304
        return true
    }

    suspend fun sendCtapMessage(cmd: Int, payload: ByteArray, timeoutMs: Long = 15000L): ByteArray? = withContext(Dispatchers.IO) {
        val conn = connection ?: return@withContext null
        val outEp = epOut ?: return@withContext null
        val inEp = epIn ?: return@withContext null

        ensureChannelInitialized(conn, outEp, inEp)

        val packets = frameMessage(channelId, cmd, payload)
        for (pkt in packets) {
            val written = conn.bulkTransfer(outEp, pkt, PACKET_SIZE, WRITE_TIMEOUT_MS)
            if (written != PACKET_SIZE) {
                if (written < 0) close()
                DeviceLog.append(DeviceLog.Category.SYSTEM, "USB write packet failed")
                return@withContext null
            }
        }

        val deadline = System.currentTimeMillis() + timeoutMs
        val firstBuf = ByteArray(PACKET_SIZE)
        var totalLength = 0
        var received = 0
        var resultBytes: ByteArray? = null

        while (System.currentTimeMillis() < deadline) {
            val n = conn.bulkTransfer(inEp, firstBuf, PACKET_SIZE, 1000)
            if (n < 0) {
                close()
                return@withContext null
            }
            if (n == 0) continue

            val respCmd = firstBuf[4].toInt() and 0xFF
            if (respCmd == CTAPHID_KEEPALIVE) {
                val status = firstBuf[7].toInt() and 0xFF
                DeviceLog.append(DeviceLog.Category.SYSTEM, "USB CTAPHID KEEPALIVE status=$status")
                continue
            }

            if (respCmd == CTAPHID_ERROR) {
                val errCode = firstBuf[7].toInt() and 0xFF
                DeviceLog.append(DeviceLog.Category.SYSTEM, "USB CTAPHID ERROR code=$errCode")
                return@withContext null
            }

            if (respCmd == (cmd or 0x80)) {
                totalLength = ((firstBuf[5].toInt() and 0xFF) shl 8) or (firstBuf[6].toInt() and 0xFF)
                resultBytes = ByteArray(totalLength)
                val headBytes = minOf(57, totalLength)
                firstBuf.copyInto(resultBytes, 0, 7, 7 + headBytes)
                received = headBytes
                break
            }
        }

        if (resultBytes == null) {
            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB timeout waiting for CTAP response")
            return@withContext null
        }

        var expectedSeq = 0
        val contBuf = ByteArray(PACKET_SIZE)
        while (received < totalLength && System.currentTimeMillis() < deadline) {
            val n = conn.bulkTransfer(inEp, contBuf, PACKET_SIZE, 1000)
            if (n < 0) {
                close()
                return@withContext null
            }
            if (n == 0) continue

            val seq = contBuf[4].toInt() and 0x7F
            if (seq == expectedSeq) {
                val chunk = minOf(59, totalLength - received)
                contBuf.copyInto(resultBytes, received, 5, 5 + chunk)
                received += chunk
                expectedSeq++
            }
        }

        if (received >= totalLength) {
            resultBytes
        } else {
            null
        }
    }

    suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray? = withContext(Dispatchers.IO) {
        val reqPayload = byteArrayOf(opcode.toByte()) + payload
        var rawResp = sendCtapMessage(CMD_MSG, reqPayload) ?: return@withContext null

        var status = if (rawResp.isNotEmpty()) rawResp[0].toInt() and 0xFF else -1

        // Rito 1 — Janela de Pareamento: Se status 0x05 (NEED_BINDING), envia 0x2F (TRIGGER_PAIRING_OPEN) e reenvia
        if (status == STATUS_NEED_BINDING) {
            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB status 0x05 NEED_BINDING -> disparando 0x2F TRIGGER_PAIRING_OPEN")
            sendCtapMessage(CMD_MSG, byteArrayOf(OP_TRIGGER_PAIRING_OPEN.toByte()))
            val retryResp = sendCtapMessage(CMD_MSG, reqPayload)
            if (retryResp != null) {
                rawResp = retryResp
                status = if (rawResp.isNotEmpty()) rawResp[0].toInt() and 0xFF else -1
            }
        }

        // Rito 2 — Toque Físico de Presença (UP): Se status 0x01 (STATUS_NEED_UP), aguarda toque por até 15s (polling a cada 400ms)
        if (status == STATUS_NEED_UP) {
            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB status 0x01 NEED_UP -> aguardando toque físico no botão (até 15s)...")
            val start = System.currentTimeMillis()
            while (System.currentTimeMillis() - start < 15000L) {
                delay(400)
                val retry = sendCtapMessage(CMD_MSG, reqPayload)
                if (retry != null && retry.isNotEmpty()) {
                    val retryStatus = retry[0].toInt() and 0xFF
                    if (retryStatus != STATUS_NEED_UP) {
                        rawResp = retry
                        status = retryStatus
                        break
                    }
                    rawResp = retry
                }
            }
        }

        // Rito 3 — PIN Automático: Se status 0x02 (STATUS_NEED_PIN), abre sessão com 0x2D / 0x2C
        if (status == STATUS_NEED_PIN) {
            DeviceLog.append(DeviceLog.Category.SYSTEM, "USB status 0x02 NEED_PIN -> autenticando PIN de recuperação...")
            val pinBytes = "12345678".toByteArray(Charsets.UTF_8)
            val verifyResp = sendCtapMessage(CMD_MSG, byteArrayOf(0x2D.toByte()) + pinBytes)
            val verifyStatus = if (verifyResp != null && verifyResp.isNotEmpty()) verifyResp[0].toInt() and 0xFF else -1
            if (verifyStatus != 0x00) {
                sendCtapMessage(CMD_MSG, byteArrayOf(0x2C.toByte()) + pinBytes)
                sendCtapMessage(CMD_MSG, byteArrayOf(0x2D.toByte()) + pinBytes)
            }
            val retryResp = sendCtapMessage(CMD_MSG, reqPayload)
            if (retryResp != null) {
                rawResp = retryResp
            }
        }

        byteArrayOf(opcode.toByte()) + rawResp
    }

    inner class CtaphidOtaTransport : OtaUsbTransport {
        override fun write(packet: ByteArray): Boolean {
            val conn = connection
            val outEp = epOut
            if (conn == null || outEp == null) return false
            if (packet.size != PACKET_SIZE) return false
            val written = conn.bulkTransfer(outEp, packet, packet.size, WRITE_TIMEOUT_MS)
            if (written < 0) close()
            return written == PACKET_SIZE
        }

        override fun read(timeoutMs: Int): ByteArray? {
            val conn = connection
            val inEp = epIn
            if (conn == null || inEp == null) return null
            val buf = ByteArray(PACKET_SIZE)
            val n = conn.bulkTransfer(inEp, buf, buf.size, timeoutMs.coerceAtLeast(100))
            if (n < 0) {
                close()
                return null
            }
            if (n == 0) return null
            return buf.copyOf(n)
        }
    }

    /** Transporte OTA sobre a conexao CTAPHID aberta (exige CONNECTED). */
    fun otaTransport(): OtaUsbTransport = CtaphidOtaTransport()

    suspend fun pushOtaImage(
        binary: ByteArray,
        onProgress: ((sent: Int, total: Int) -> Unit)? = null,
    ): Boolean =
        withContext(Dispatchers.IO) {
            OtaTransfer.pushImage(otaTransport(), binary, onProgress)
        }
}

/**
 * Cliente para compatibilidade com fluxos diretos CTAP/Vendor sobre USB nativo ou Host Bridge.
 */
class UsbCtapClient(
    val usb: UsbCtaphid,
    private val hostBridgeClient: dev.aegiskey.app.data.transport.HostUsbUartBridgeClient = dev.aegiskey.app.data.transport.HostUsbUartBridgeClient()
) {
    suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray? {
        if (usb.isConnected) {
            val resp = usb.sendVendor(opcode, payload)
            if (resp != null) return resp
        }
        val device = usb.findAegisDevice() ?: usb.findDevice()
        if (device != null) {
            usb.openDevice(device)
            if (usb.isConnected) {
                val resp = usb.sendVendor(opcode, payload)
                if (resp != null) return resp
            }
        }
        return hostBridgeClient.sendVendor(opcode, payload)
    }

    suspend fun sendMsg(payload: ByteArray): ByteArray? {
        if (usb.isConnected) {
            val resp = usb.sendCtapMessage(UsbCtaphid.CMD_MSG, payload)
            if (resp != null) return resp
        }
        return hostBridgeClient.sendVendor(0x83, payload)
    }
}
