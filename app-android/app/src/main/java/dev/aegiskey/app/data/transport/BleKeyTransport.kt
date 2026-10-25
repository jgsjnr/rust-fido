package dev.aegiskey.app.data.transport

import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.domain.model.ConnectionTransportType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn

/**
 * Transporte BLE padrão encapsulando [AegisBleClient] com exposição reativa
 * dos dispositivos detectados, controle de scan e ritos de hardware (0x2F e retry de UP).
 * Inclui fallback transparente para a ponte host USB/UART quando operando no emulador Android.
 */
class BleKeyTransport(
    val client: AegisBleClient,
    val hostBridgeClient: HostUsbUartBridgeClient = HostUsbUartBridgeClient(),
    scope: CoroutineScope = CoroutineScope(Dispatchers.IO)
) : KeyTransport {

    constructor(client: AegisBleClient, scope: CoroutineScope) : this(
        client = client,
        hostBridgeClient = HostUsbUartBridgeClient(),
        scope = scope
    )

    override val transportType: ConnectionTransportType = ConnectionTransportType.BLE

    override val isConnected: StateFlow<Boolean> = client.state
        .map { it.connection == AegisBleClient.Connection.READY }
        .stateIn(scope, SharingStarted.Eagerly, false)

    val devices: StateFlow<List<AegisBleClient.FoundDevice>> = client.devices

    val isScanning: StateFlow<Boolean> = client.state
        .map { it.connection == AegisBleClient.Connection.SCANNING }
        .stateIn(scope, SharingStarted.Eagerly, false)

    suspend fun isPhysicallyReachable(): Boolean {
        return (client.state.value.connection == AegisBleClient.Connection.READY) ||
               (hostBridgeClient.isBridgeAvailable(500))
    }

    fun startScan() {
        client.startScan()
    }

    fun stopScan() {
        client.stopScan()
    }

    override suspend fun connect(target: String): Result<Unit> = runCatching {
        if (target == "BLE-BRIDGE") {
            // No emulador Android, a chave real está conectada via ponte
            if (!hostBridgeClient.isBridgeAvailable(500)) {
                throw IllegalStateException("Chave na bridge host não encontrada")
            }
            return@runCatching
        }
        client.ensureBonded(target)
        client.connect(target)
    }

    override suspend fun disconnect() {
        client.disconnect()
    }

    override suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray? {
        val bleReady = client.state.value.connection == AegisBleClient.Connection.READY
        var resp: ByteArray? = if (bleReady) {
            client.sendVendor(opcode, payload)
        } else if (hostBridgeClient.isBridgeAvailable(500)) {
            hostBridgeClient.sendVendor(opcode, payload)
        } else {
            client.sendVendor(opcode, payload)
        }

        // Rito 1: Se retornar 0x05 (NEED_BINDING), abre janela de pareamento com 0x2F e reenvia
        if (resp != null && resp.size >= 2 && resp[1].toInt() == 0x05) {
            if (bleReady) {
                client.sendVendor(0x2F, ByteArray(0))
                resp = client.sendVendor(opcode, payload)
            } else {
                hostBridgeClient.sendVendor(0x2F, ByteArray(0))
                resp = hostBridgeClient.sendVendor(opcode, payload)
            }
        }

        // Rito 2: Se retornar 0x01 (STATUS_NEED_UP), aguarda toque físico por até 15s (polling a cada 400ms)
        if (resp != null && resp.size >= 2 && resp[1].toInt() == 0x01) {
            val start = System.currentTimeMillis()
            while (System.currentTimeMillis() - start < 15000L) {
                delay(400)
                val retry = if (bleReady) {
                    client.sendVendor(opcode, payload)
                } else {
                    hostBridgeClient.sendVendor(opcode, payload)
                }
                if (retry != null && retry.size >= 2) {
                    if (retry[1].toInt() != 0x01) {
                        resp = retry
                        break
                    }
                    resp = retry
                }
            }
        }

        // Rito 3: Se retornar 0x02 (STATUS_NEED_PIN), autentica PIN de recuperação "12345678"
        if (resp != null && resp.size >= 2 && resp[1].toInt() == 0x02) {
            val pinBytes = "12345678".toByteArray(Charsets.UTF_8)
            val verifyResp = if (bleReady) client.sendVendor(0x2D, pinBytes) else hostBridgeClient.sendVendor(0x2D, pinBytes)
            val verifyStatus = if (verifyResp != null && verifyResp.size >= 2) verifyResp[1].toInt() and 0xFF else -1
            if (verifyStatus != 0x00) {
                if (bleReady) {
                    client.sendVendor(0x2C, pinBytes)
                    client.sendVendor(0x2D, pinBytes)
                } else {
                    hostBridgeClient.sendVendor(0x2C, pinBytes)
                    hostBridgeClient.sendVendor(0x2D, pinBytes)
                }
            }
            resp = if (bleReady) client.sendVendor(opcode, payload) else hostBridgeClient.sendVendor(opcode, payload)
        }

        return resp
    }

    override suspend fun sendMsg(payload: ByteArray): ByteArray? {
        val bleReady = client.state.value.connection == AegisBleClient.Connection.READY
        return if (bleReady) {
            client.sendMsg(payload) ?: hostBridgeClient.sendVendor(0x83, payload)
        } else {
            hostBridgeClient.sendVendor(0x83, payload) ?: client.sendMsg(payload)
        }
    }

    override suspend fun cancel(): Boolean {
        return client.cancel()
    }
}
