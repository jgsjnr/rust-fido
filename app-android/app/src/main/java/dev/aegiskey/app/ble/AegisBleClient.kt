package dev.aegiskey.app.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.ParcelUuid
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.SanitizedLog
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull

/**
 * BLE transport for GATT 0xFFFD (see docs/ble-protocol.md).
 *
 * Flow: scan (0xFFFD filter) -> connect -> bond (JustWorks+bonding+UP) ->
 * read FFF4 revision (must be 0x01) -> subscribe FFF2 -> write FFF1 fragments.
 * UP itself always comes from the device button (hold 5s); the app never
 * asserts presence, it only surfaces `STATUS_UP_NEEDED`.
 *
 * Legacy GATT callbacks are used deliberately: they work on API 31-34
 * without version branches. No PII is logged (see SanitizedLog).
 */
@SuppressLint("MissingPermission") // UI layer holds BLUETOOTH_SCAN/CONNECT (A12+ runtime).
class AegisBleClient(private val context: Context) {

    enum class Connection { IDLE, SCANNING, CONNECTING, READY, ERROR }

    data class FoundDevice(val name: String, val address: String)

    data class UiState(
        val connection: Connection = Connection.IDLE,
        val devices: List<FoundDevice> = emptyList(),
        val bonded: Boolean = false,
        val revision: Int? = null,
        val status: Int = BleContract.STATUS_IDLE,
        val lastResponseSize: Int = 0,
        val error: String? = null,
    )

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val deviceCache = mutableMapOf<String, BluetoothDevice>()
    private var gatt: BluetoothGatt? = null
    private val ioLock = Mutex()
    private var pendingWrite: CompletableDeferred<Boolean>? = null
    private var pendingRead: CompletableDeferred<ByteArray>? = null
    private var pendingSubscribe: CompletableDeferred<Boolean>? = null
    private val notifyBuffer = mutableListOf<Byte>()

    companion object {
        const val GATT_IO_TIMEOUT_MS = 4000L
        const val SUBSCRIBE_TIMEOUT_MS = 4000L
        const val RESPONSE_POLL_INTERVAL_MS = 50L
        const val NEED_UP_POLL_INTERVAL_MS = 250L
        const val DEFAULT_MSG_TIMEOUT_MS = 15000L
        const val DEFAULT_VENDOR_TIMEOUT_MS = 25000L
    }

    /** Pronto para operar (pos-pareamento com FFF2 assinado). */
    fun isReady(): Boolean = _state.value.connection == Connection.READY

    /** Dispositivo pede toque no botao (FFF2 UP_NEEDED). */
    fun needsUp(): Boolean = _state.value.status == BleContract.STATUS_UP_NEEDED

    /** Re-assina FFF2 sem reconectar (pos-pareamento / reconexao / erro). */
    fun resubscribe() {
        scope.launch {
            ensureSubscribed()
        }
    }

    /** Re-assinatura suspensa com timeout; atualiza estado e loga sem PII. */
    suspend fun ensureSubscribed(): Boolean {
        val g = gatt ?: return false
        if (!subscribeStatus(g)) {
            _state.update { it.copy(connection = Connection.ERROR, error = "falha ao assinar — toque em tentar de novo") }
            DeviceLog.append(DeviceLog.Category.BLE, "SUB FFF2 retry failed")
            return false
        }
        _state.update { it.copy(connection = Connection.READY, error = null) }
        DeviceLog.append(DeviceLog.Category.BLE, "SUB FFF2 re-ok")
        return true
    }

    /**
     * Polling leve pos-pareamento: le FFF3 uma vez para manter o link
     * vivo enquanto aguarda UP (o FFF2 so notifica; nao precisa ler).
     * Retorna tamanho pendente ou -1 sem conexao. Nunca trava sem timeout.
     */
    suspend fun pollPendingOnce(): Int {
        if (gatt == null || _state.value.connection != Connection.READY) return -1
        return pendingLen()
    }

    private fun adapter() =
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter

    private val bondReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            if (intent.action != BluetoothDevice.ACTION_BOND_STATE_CHANGED) return
            val device: BluetoothDevice? = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)
            val bond = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, -1)
            _state.update { it.copy(bonded = device?.bondState == BluetoothDevice.BOND_BONDED || bond == BluetoothDevice.BOND_BONDED) }
            SanitizedLog.record(SanitizedLog.Event.BOND_CHANGED)
            DeviceLog.append(DeviceLog.Category.PAIRING, "bond state=" + bond)
        }
    }

    init {
        context.registerReceiver(bondReceiver, IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED))
    }

    fun release() {
        runCatching { context.unregisterReceiver(bondReceiver) }
        disconnect()
    }

    // -- scan -----------------------------------------------------------------

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device ?: return
            deviceCache[device.address] = device
            val label = result.scanRecord?.deviceName ?: device.name ?: "AegisKey"
            var isNew = false
            _state.update { current ->
                if (current.devices.any { it.address == device.address }) current
                else {
                    isNew = true
                    current.copy(devices = current.devices + FoundDevice(label.take(48), device.address))
                }
            }
            // Só o primeiro avistamento (filtro 0xFFFD já é no hardware).
            if (isNew) DeviceLog.append(DeviceLog.Category.BLE, "scan achou: " + label.take(24))
        }
    }

    fun startScan() {
        val scanner = adapter()?.bluetoothLeScanner ?: return
        _state.update { it.copy(connection = Connection.SCANNING, devices = emptyList(), error = null) }
        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(BleContract.SERVICE_UUID))
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()
        scanner.startScan(listOf(filter), settings, scanCallback)
        SanitizedLog.record(SanitizedLog.Event.SCAN_STARTED)
        DeviceLog.append(DeviceLog.Category.BLE, "scan 0xFFFD started")
    }

    fun stopScan() {
        runCatching { adapter()?.bluetoothLeScanner?.stopScan(scanCallback) }
        val found = _state.value.devices.size
        _state.update { it.copy(connection = Connection.IDLE) }
        DeviceLog.append(DeviceLog.Category.BLE, "scan stopped (" + found + " na lista)")
    }

    // -- connect / bond ---------------------------------------------------------

    fun connect(address: String) {
        val device = deviceCache[address] ?: adapter()?.getRemoteDevice(address) ?: return
        deviceCache[address] = device
        _state.update { it.copy(connection = Connection.CONNECTING, error = null) }
        stopScan()
        gatt = device.connectGatt(context, false, gattCallback)
        DeviceLog.append(DeviceLog.Category.BLE, "BLE connect requested")
    }

    fun ensureBonded(address: String) {
        deviceCache[address]?.let { device ->
            if (device.bondState != BluetoothDevice.BOND_BONDED) {
                DeviceLog.append(DeviceLog.Category.PAIRING, "bond solicitado")
                device.createBond()
            } else {
                DeviceLog.append(DeviceLog.Category.PAIRING, "ja pareado")
            }
        }
    }

    fun disconnect() {
        runCatching { gatt?.disconnect() }
        runCatching { gatt?.close() }
        gatt = null
        synchronized(notifyBuffer) { notifyBuffer.clear() }
        pendingRead?.cancel()
        pendingRead = null
        pendingWrite?.cancel()
        pendingWrite = null
        pendingSubscribe?.cancel()
        pendingSubscribe = null
        _state.update { it.copy(connection = Connection.IDLE, revision = null, status = BleContract.STATUS_IDLE) }
        DeviceLog.append(DeviceLog.Category.BLE, "GATT disconnected (app)")
    }

    // -- GATT -------------------------------------------------------------------

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothGatt.STATE_CONNECTED) {
                DeviceLog.append(DeviceLog.Category.BLE, "GATT connected, discovering services")
                g.discoverServices()
            } else if (newState == BluetoothGatt.STATE_DISCONNECTED) {
                DeviceLog.append(DeviceLog.Category.BLE, "GATT disconnected")
                synchronized(notifyBuffer) { notifyBuffer.clear() }
                _state.update { it.copy(connection = Connection.IDLE, revision = null, status = BleContract.STATUS_IDLE) }
            } else if (status != BluetoothGatt.GATT_SUCCESS) {
                DeviceLog.append(DeviceLog.Category.BLE, "GATT erro status=" + status)
            }
        }

        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
            scope.launch { afterServices(g) }
        }

        override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) {
            pendingRead?.complete(c.value ?: ByteArray(0))
            pendingRead = null
        }

        override fun onCharacteristicWrite(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) {
            pendingWrite?.complete(status == BluetoothGatt.GATT_SUCCESS)
            pendingWrite = null
        }

        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic) {
            val bytes = c.value ?: return
            if (c.uuid == BleContract.CHAR_STATUS && bytes.isNotEmpty()) {
                val statusByte = bytes[0].toInt() and 0xFF
                _state.update { it.copy(status = statusByte) }
                val statusLabel = BleContract.statusLabel(statusByte)
                val kind = if (statusByte == BleContract.STATUS_PROCESSING) "keepalive" else "notify"
                DeviceLog.append(DeviceLog.Category.BLE, "RX FFF2 " + kind + " status=" + statusLabel + " (0x" + String.format("%02X", statusByte) + ")")
                SanitizedLog.record(SanitizedLog.Event.STATUS_NOTIFY)
            } else {
                synchronized(notifyBuffer) {
                    bytes.forEach { notifyBuffer.add(it) }
                }
            }
        }

        override fun onDescriptorWrite(g: BluetoothGatt, d: BluetoothGattDescriptor, status: Int) {
            pendingSubscribe?.complete(status == BluetoothGatt.GATT_SUCCESS)
            pendingSubscribe = null
        }
    }

    private suspend fun afterServices(g: BluetoothGatt) {
        val revision = readBytes(char(BleContract.CHAR_REVISION))?.firstOrNull()?.toInt()?.and(0xFF)
        if (revision != BleContract.GATT_REVISION) {
            _state.update { it.copy(connection = Connection.ERROR, error = "versão incompatível — volte e tente de novo") }
            SanitizedLog.record(SanitizedLog.Event.REVISION_MISMATCH)
            DeviceLog.append(DeviceLog.Category.BLE, "revisao incompatível")
            disconnect()
            return
        }
        _state.update { it.copy(revision = revision, bonded = bondedOf()) }
        SanitizedLog.record(SanitizedLog.Event.REVISION_OK)
        DeviceLog.append(DeviceLog.Category.BLE, "revisao ok bonded=" + bondedOf())
        if (subscribeStatus(g)) {
            _state.update { it.copy(connection = Connection.READY, error = null) }
            DeviceLog.append(DeviceLog.Category.BLE, "SUB FFF2 ok")
            SanitizedLog.record(SanitizedLog.Event.DEVICE_CONNECTED)
        } else {
            _state.update { it.copy(connection = Connection.ERROR, error = "falha ao assinar — toque em tentar de novo") }
            DeviceLog.append(DeviceLog.Category.BLE, "SUB FFF2 failed")
        }
    }

    private fun bondedOf(): Boolean =
        gatt?.device?.bondState == BluetoothDevice.BOND_BONDED

    private fun char(uuid: java.util.UUID): BluetoothGattCharacteristic? =
        gatt?.getService(BleContract.SERVICE_UUID)?.getCharacteristic(uuid)

    private suspend fun readBytes(c: BluetoothGattCharacteristic?): ByteArray? {
        if (c == null || gatt == null) return null
        return ioLock.withLock {
            val gate = CompletableDeferred<ByteArray>()
            pendingRead = gate
            if (gatt?.readCharacteristic(c) != true) {
                pendingRead = null
                return null
            }
            withTimeoutOrNull(GATT_IO_TIMEOUT_MS) { gate.await() }
        }
    }

    private suspend fun writeBytes(c: BluetoothGattCharacteristic?, bytes: ByteArray): Boolean {
        if (c == null || gatt == null) return false
        return ioLock.withLock {
            val gate = CompletableDeferred<Boolean>()
            pendingWrite = gate
            c.value = bytes
            c.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            if (gatt?.writeCharacteristic(c) != true) {
                pendingWrite = null
                return false
            }
            withTimeoutOrNull(GATT_IO_TIMEOUT_MS) { gate.await() } ?: false
        }
    }

    private suspend fun subscribeStatus(g: BluetoothGatt): Boolean {
        val statusChar = char(BleContract.CHAR_STATUS) ?: return false
        g.setCharacteristicNotification(statusChar, true)
        val cccd = statusChar.getDescriptor(BleContract.CCCD_UUID) ?: return false
        return ioLock.withLock {
            val gate = CompletableDeferred<Boolean>()
            pendingSubscribe = gate
            cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            if (!g.writeDescriptor(cccd)) {
                pendingSubscribe = null
                return false
            }
            withTimeoutOrNull(SUBSCRIBE_TIMEOUT_MS) { gate.await() } ?: false
        }
    }

    /**
     * Aguarda resposta FFF1 com polling NEED_UP consciente:
     * - PROCESSING / UP_NEEDED apenas mantem a espera (polling lento p/ UP).
     * - Timeout total sempre aplicado: nunca trava sem saida.
     * - Retorna bytes ou null (timeout). Sem PII no log (chamador loga).
     */
    private suspend fun awaitNotify(timeoutMs: Long): ByteArray? {
        return withTimeoutOrNull(timeoutMs) {
            while (notifySize() == 0) {
                if (_state.value.status == BleContract.STATUS_UP_NEEDED) {
                    delay(NEED_UP_POLL_INTERVAL_MS)
                } else {
                    delay(RESPONSE_POLL_INTERVAL_MS)
                }
            }
            // Aguarda IDLE apos dados chegarem (device terminou o envio).
            while (_state.value.status != BleContract.STATUS_IDLE && notifySize() > 0) {
                delay(RESPONSE_POLL_INTERVAL_MS)
            }
            drainNotify()
        }
    }

    // -- CTAP2-BLE ops ------------------------------------------------------------

    /** FFF3 pending length (u16 LE, 0 = idle). */
    suspend fun pendingLen(): Int {
        val raw = readBytes(char(BleContract.CHAR_LEN)) ?: return 0
        if (raw.size < 2) return 0
        return (raw[0].toInt() and 0xFF) or ((raw[1].toInt() and 0xFF) shl 8)
    }

    /** Envia OP_MSG [payload] (`[cmd, CBOR...]`) e aguarda resposta CTAP. */
    suspend fun sendMsg(payload: ByteArray, timeoutMs: Long = DEFAULT_MSG_TIMEOUT_MS): ByteArray? {
        val frags = AegisBridge.splitFragments(BleContract.OP_MSG, payload).getOrNull()
            ?: run {
                _state.update { it.copy(error = "falha ao preparar — tente de novo") }
                DeviceLog.append(DeviceLog.Category.BLE, "TX FFF1 OP_MSG(0x83) fragment failed")
                return null
            }
        val cmdName = ctapName(payload.firstOrNull()?.toInt()?.and(0xFF))
        DeviceLog.append(DeviceLog.Category.BLE, "TX FFF1 OP_MSG(0x83) cmd=" + cmdName + " frags=" + frags.size + " bytes=" + payload.size)
        synchronized(notifyBuffer) { notifyBuffer.clear() }
        val control = char(BleContract.CHAR_CONTROL) ?: run {
            _state.update { it.copy(error = "sem conexão — volte e reconecte") }
            return null
        }
        for (frag in frags) {
            if (!writeBytes(control, frag)) {
                _state.update { it.copy(error = "falha ao enviar — toque em tentar de novo") }
                DeviceLog.append(DeviceLog.Category.BLE, "TX FFF1 OP_MSG(0x83) write failed")
                return null
            }
        }
        SanitizedLog.record(SanitizedLog.Event.CTAP_SENT)
        val response = awaitNotify(timeoutMs) ?: run {
            _state.update { it.copy(error = "sem resposta — toque no botão e tente de novo") }
            DeviceLog.append(DeviceLog.Category.BLE, "RX FFF1 no response (timeout/UP?)")
            return null
        }
        _state.update { it.copy(lastResponseSize = response.size) }
        DeviceLog.append(DeviceLog.Category.BLE, "RX FFF1 bytes=" + response.size)
        SanitizedLog.record(SanitizedLog.Event.CTAP_RESPONSE)
        return response
    }

    /**
     * Fase6 vendor op (0x20-0x27): fragmenta [op + TLV] via bridge (mesmo
     * framing S3) e aguarda [op, status, TLV...]. Retorna null em timeout.
     * Loga so opcode/status/tamanho (nunca TLV sensivel).
     */
    suspend fun sendVendor(opcode: Int, tlv: ByteArray, timeoutMs: Long = DEFAULT_VENDOR_TIMEOUT_MS): ByteArray? {
        require(BleContract.isVendorOp(opcode) || BindingOps.isBindingOp(opcode)) {
            "operação inválida"
        }
        val frags = AegisBridge.splitFragments(opcode, tlv).getOrNull()
            ?: run {
                _state.update { it.copy(error = "falha ao preparar — tente de novo") }
                DeviceLog.append(DeviceLog.Category.BLE, "TX FFF1 vendor fragment failed")
                return null
            }
        val opName = if (BindingOps.isBindingOp(opcode)) BindingOps.opName(opcode) else BleContract.vendorOpName(opcode)
        DeviceLog.append(DeviceLog.Category.BLE, "TX FFF1 " + opName + " frags=" + frags.size + " bytes=" + tlv.size)
        synchronized(notifyBuffer) { notifyBuffer.clear() }
        val control = char(BleContract.CHAR_CONTROL) ?: run {
            _state.update { it.copy(error = "sem conexão — volte e reconecte") }
            return null
        }
        for (frag in frags) {
            if (!writeBytes(control, frag)) {
                _state.update { it.copy(error = "falha ao enviar — toque em tentar de novo") }
                DeviceLog.append(DeviceLog.Category.BLE, "TX FFF1 " + opName + " write failed")
                return null
            }
        }
        SanitizedLog.record(SanitizedLog.Event.CTAP_SENT)
        val response = awaitNotify(timeoutMs) ?: run {
            _state.update { it.copy(error = "sem resposta — toque no botão e tente de novo") }
            DeviceLog.append(DeviceLog.Category.BLE, "RX FFF1 no response (timeout/UP?)")
            return null
        }
        _state.update { it.copy(lastResponseSize = response.size) }
        val statusByte = if (response.size >= 2) (response[1].toInt() and 0xFF) else -1
        DeviceLog.append(DeviceLog.Category.BLE, "RX FFF1 vendor bytes=" + response.size + " status=" + statusByte)
        SanitizedLog.record(SanitizedLog.Event.CTAP_RESPONSE)
        return response
    }

    /** Single-byte CANCEL (0xBE): aborts the active transaction. */
    suspend fun cancel(): Boolean {
        DeviceLog.append(DeviceLog.Category.BLE, "TX FFF1 OP_CANCEL(0xBE)")
        val control = char(BleContract.CHAR_CONTROL) ?: return false
        return writeBytes(control, byteArrayOf(BleContract.OP_CANCEL.toByte()))
    }

    /** PING echo (no CtapEngine involved, per contract). */
    suspend fun ping(payload: ByteArray): ByteArray? {
        val frags = AegisBridge.splitFragments(BleContract.OP_PING, payload).getOrNull() ?: return null
        DeviceLog.append(DeviceLog.Category.BLE, "TX FFF1 OP_PING(0x81) bytes=" + payload.size)
        val control = char(BleContract.CHAR_CONTROL) ?: return null
        synchronized(notifyBuffer) { notifyBuffer.clear() }
        for (frag in frags) {
            if (!writeBytes(control, frag)) return null
        }
        val echoed = awaitNotify(GATT_IO_TIMEOUT_MS)
        if (echoed != null) DeviceLog.append(DeviceLog.Category.BLE, "RX FFF1 PING bytes=" + echoed.size)
        return echoed
    }

    private fun ctapName(cmd: Int?): String = when (cmd) {
        BleContract.CTAP_CMD_MAKE_CREDENTIAL -> "0x01 make-credential"
        BleContract.CTAP_CMD_GET_ASSERTION -> "0x02 get-assertion"
        BleContract.CTAP_CMD_GET_INFO -> "0x04 get-info"
        null -> "none"
        else -> "0x" + String.format("%02X", cmd)
    }

    private fun notifySize(): Int = synchronized(notifyBuffer) { notifyBuffer.size }

    private fun drainNotify(): ByteArray = synchronized(notifyBuffer) {
        val out = notifyBuffer.toByteArray()
        notifyBuffer.clear()
        out
    }
}

