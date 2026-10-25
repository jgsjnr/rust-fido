package dev.aegiskey.app.data.transport

import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.ui.BindingWire
import dev.aegiskey.app.ui.RescueOps
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Transporte para ambiente de emulador Android e testes integrados com Renode.
 * - Conecta via TCP (por padrão em 10.0.2.2:5678, alias do host no emulador Android).
 * - Se o socket Renode não estiver ativo ou em testes offline, executa simulação determinística
 *   do protocolo AegisKey firmware (incluindo simulação de botão físico hold 5s e UP single-shot).
 */
class SimulatedRenodeTransport(
    private val defaultHost: String = "10.0.2.2",
    private val defaultPort: Int = 5678
) : KeyTransport {

    override val transportType: ConnectionTransportType = ConnectionTransportType.SIMULATOR

    private val _isConnected = MutableStateFlow(true)
    override val isConnected: StateFlow<Boolean> = _isConnected.asStateFlow()

    private val _buttonHoldSimulated = MutableStateFlow(false)
    val buttonHoldSimulated: StateFlow<Boolean> = _buttonHoldSimulated.asStateFlow()

    private val _lastTouchEpochMs = MutableStateFlow(0L)
    val lastTouchEpochMs: StateFlow<Long> = _lastTouchEpochMs.asStateFlow()

    private var socket: Socket? = null
    private var socketIn: InputStream? = null
    private var socketOut: OutputStream? = null

    // Simulação de banco de chaves e OATH em memória determinística
    private val mockKeys = mutableListOf<VendorOps.KeyEntry>()
    private val mockOathAccounts = mutableListOf<String>()

    init {
        // Inicializa com chaves de exemplo para testes locais do emulador
        mockKeys.add(VendorOps.KeyEntry(0, "Passkey Google"))
        mockKeys.add(VendorOps.KeyEntry(1, "Passkey GitHub"))
        mockOathAccounts.add("GitHub:developer")
        mockOathAccounts.add("Google:test@aegiskey.dev")
    }

    override suspend fun connect(target: String): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val parts = target.split(":")
            val host = if (parts.isNotEmpty() && parts[0].isNotBlank()) parts[0] else defaultHost
            val port = if (parts.size > 1) parts[1].toIntOrNull() ?: defaultPort else defaultPort

            try {
                val s = Socket()
                s.connect(InetSocketAddress(host, port), 800)
                s.soTimeout = 2000
                socket = s
                socketIn = s.getInputStream()
                socketOut = s.getOutputStream()
            } catch (_: Throwable) {
                // Renode TCP indisponível; permanece em modo determinístico local
                socket = null
            }
            _isConnected.value = true
        }
    }

    override suspend fun disconnect() = withContext(Dispatchers.IO) {
        try {
            socket?.close()
        } catch (_: Throwable) {
            // ignore
        }
        socket = null
        socketIn = null
        socketOut = null
        _isConnected.value = false
    }

    fun simulatePhysicalButtonHold5s(): Result<Unit> {
        _buttonHoldSimulated.value = true
        return Result.success(Unit)
    }

    fun simulatePhysicalButtonSingleTouch(): Result<Unit> {
        _lastTouchEpochMs.value = System.currentTimeMillis()
        return Result.success(Unit)
    }

    override suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray? = withContext(Dispatchers.IO) {
        val s = socket
        if (s != null && s.isConnected && !s.isClosed) {
            val responseFromSocket = trySendTcp(opcode, payload)
            if (responseFromSocket != null) return@withContext responseFromSocket
        }

        // Simulação determinística conforme a especificação do firmware
        handleDeterministicVendor(opcode, payload)
    }

    override suspend fun sendMsg(payload: ByteArray): ByteArray? = withContext(Dispatchers.IO) {
        val s = socket
        if (s != null && s.isConnected && !s.isClosed) {
            val responseFromSocket = trySendTcp(BleContractConstants.OP_MSG, payload)
            if (responseFromSocket != null) return@withContext responseFromSocket
        }

        handleDeterministicMsg(payload)
    }

    override suspend fun cancel(): Boolean {
        _buttonHoldSimulated.value = false
        return true
    }

    private fun trySendTcp(opcode: Int, payload: ByteArray): ByteArray? {
        return try {
            val out = socketOut ?: return null
            val input = socketIn ?: return null

            val frame = byteArrayOf(
                opcode.toByte(),
                ((payload.size shr 8) and 0xFF).toByte(),
                (payload.size and 0xFF).toByte()
            ) + payload
            out.write(frame)
            out.flush()

            val header = ByteArray(3)
            var read = 0
            while (read < 3) {
                val r = input.read(header, read, 3 - read)
                if (r < 0) return null
                read += r
            }
            val respOp = header[0].toInt() and 0xFF
            val len = ((header[1].toInt() and 0xFF) shl 8) or (header[2].toInt() and 0xFF)
            val body = ByteArray(len)
            var bodyRead = 0
            while (bodyRead < len) {
                val r = input.read(body, bodyRead, len - bodyRead)
                if (r < 0) return null
                bodyRead += r
            }
            byteArrayOf(respOp.toByte()) + body
        } catch (_: Throwable) {
            null
        }
    }

    private fun handleDeterministicVendor(opcode: Int, payload: ByteArray): ByteArray {
        return when (opcode) {
            // Claim (0x28): retorna [op, 0x00, binding_id(16)]
            0x28 -> {
                val bindingId = if (payload.size >= BindingWire.PUBKEY_BYTES + BindingWire.BINDING_ID_BYTES) {
                    payload.copyOfRange(BindingWire.PUBKEY_BYTES, BindingWire.PUBKEY_BYTES + BindingWire.BINDING_ID_BYTES)
                } else {
                    ByteArray(16) { 0xAA.toByte() }
                }
                byteArrayOf(0x28.toByte(), 0x00.toByte()) + bindingId
            }
            // Challenge (0x29): retorna [op, 0x00, challenge(32)]
            0x29 -> {
                val challenge = ByteArray(32) { (it + 1).toByte() }
                byteArrayOf(0x29.toByte(), 0x00.toByte()) + challenge
            }
            // Release (0x2B): retorna [op, 0x00]
            0x2B -> {
                byteArrayOf(0x2B.toByte(), 0x00.toByte())
            }
            // Key Gen (0x20): gera e adiciona ao mock
            VendorOps.OP_KEY_GEN_ONDEVICE -> {
                val records = VendorOps.parseTlvRecords(payload)
                val slot = VendorOps.findTlv(records, VendorOps.TAG_SLOT)?.firstOrNull()?.toInt()?.and(0xFF) ?: mockKeys.size
                val labelBytes = VendorOps.findTlv(records, VendorOps.TAG_LABEL)
                val label = labelBytes?.toString(Charsets.UTF_8) ?: "Chave $slot"
                mockKeys.removeAll { it.slot == slot }
                mockKeys.add(VendorOps.KeyEntry(slot, label))
                byteArrayOf(0x20.toByte(), 0x00.toByte())
            }
            // Key List (0x22): lista todas
            VendorOps.OP_KEY_LIST -> {
                var tlv = ByteArray(0)
                for (k in mockKeys) {
                    tlv += VendorOps.writeTlv(VendorOps.TAG_SLOT, byteArrayOf(k.slot.toByte()))
                    tlv += VendorOps.writeTlv(VendorOps.TAG_LABEL, k.label.toByteArray(Charsets.UTF_8))
                }
                byteArrayOf(0x22.toByte(), 0x00.toByte()) + tlv
            }
            // Key Delete (0x23)
            VendorOps.OP_KEY_DELETE -> {
                val records = VendorOps.parseTlvRecords(payload)
                val slot = VendorOps.findTlv(records, VendorOps.TAG_SLOT)?.firstOrNull()?.toInt()?.and(0xFF)
                if (slot != null) {
                    mockKeys.removeAll { it.slot == slot }
                }
                byteArrayOf(0x23.toByte(), 0x00.toByte())
            }
            // OATH Put (0x24)
            VendorOps.OP_OATH_PUT -> {
                val records = VendorOps.parseTlvRecords(payload)
                val name = VendorOps.findTlv(records, VendorOps.TAG_OATH_NAME)?.toString(Charsets.UTF_8) ?: "conta"
                mockOathAccounts.removeAll { it == name }
                mockOathAccounts.add(name)
                byteArrayOf(0x24.toByte(), 0x00.toByte())
            }
            // OATH List (0x25)
            VendorOps.OP_OATH_LIST -> {
                var tlv = ByteArray(0)
                for (acc in mockOathAccounts) {
                    val rawName = byteArrayOf(0x21.toByte()) + acc.toByteArray(Charsets.UTF_8)
                    tlv += VendorOps.writeTlv(VendorOps.TAG_OATH_NAME, rawName)
                }
                byteArrayOf(0x25.toByte(), 0x00.toByte()) + tlv
            }
            // OATH Code (0x26)
            VendorOps.OP_OATH_CODE -> {
                val records = VendorOps.parseTlvRecords(payload)
                val name = VendorOps.findTlv(records, VendorOps.TAG_OATH_NAME)?.toString(Charsets.UTF_8)
                val codeStr = if (name?.contains("VPN", true) == true || name?.contains("admin", true) == true) "12345678" else "123456"
                val tlv = VendorOps.writeTlv(VendorOps.TAG_OATH_RESPONSE, codeStr.toByteArray(Charsets.UTF_8))
                byteArrayOf(0x26.toByte(), 0x00.toByte()) + tlv
            }
            // OATH Delete (0x27)
            VendorOps.OP_OATH_DELETE -> {
                val records = VendorOps.parseTlvRecords(payload)
                val name = VendorOps.findTlv(records, VendorOps.TAG_OATH_NAME)?.toString(Charsets.UTF_8)
                if (name != null) {
                    mockOathAccounts.removeAll { it == name }
                }
                byteArrayOf(0x27.toByte(), 0x00.toByte())
            }
            // FW Log (0x38)
            VendorOps.OP_FW_LOG -> {
                val logText = "0001 EV=01 ARG=00 T=120\n0002 EV=02 ARG=01 T=240\n0003 EV=10 ARG=00 T=400\n"
                byteArrayOf(0x38.toByte(), 0x00.toByte()) + logText.toByteArray(Charsets.UTF_8)
            }
            else -> {
                byteArrayOf(opcode.toByte(), 0x00.toByte())
            }
        }
    }

    private fun handleDeterministicMsg(payload: ByteArray): ByteArray {
        // Se for comando de Rescue (primeiro byte 0x2E)
        if (payload.isNotEmpty() && (payload[0].toInt() and 0xFF) == RescueOps.TRANSPORT_OP) {
            val cmd = if (payload.size >= 7) payload[6].toInt() and 0xFF else RescueOps.CMD_PING
            return when (cmd) {
                // Ping: [VER(1) | panic u32be | wipe u32be | recovery(1)] = 10B
                RescueOps.CMD_PING -> {
                    byteArrayOf(
                        RescueOps.OP_MSG.toByte(),
                        RescueOps.STATUS_OK.toByte(),
                        RescueOps.VERSION.toByte(),
                        0, 0, 0, 0, // panicCount = 0
                        0, 0, 0, 0, // wipeCount = 0
                        0           // recoveryMode = false
                    )
                }
                // Diagnostics: [flags(1) | reservado(7)] = 8B
                RescueOps.CMD_DIAGNOSTICS -> {
                    val flags = (RescueOps.DIAG_CRYPTO_OK or
                        RescueOps.DIAG_FLASH_OK or
                        RescueOps.DIAG_RNG_OK or
                        RescueOps.DIAG_BUTTON_OK).toByte()
                    byteArrayOf(
                        RescueOps.OP_MSG.toByte(),
                        RescueOps.STATUS_OK.toByte(),
                        flags,
                        0, 0, 0, 0, 0, 0, 0
                    )
                }
                else -> byteArrayOf(RescueOps.OP_MSG.toByte(), RescueOps.STATUS_OK.toByte())
            }
        }

        // Resposta genérica CTAP / OP_MSG
        return byteArrayOf(0x83.toByte(), 0x00.toByte())
    }

    private object BleContractConstants {
        const val OP_MSG = 0x83
    }
}
