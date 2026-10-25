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
 */
class BleKeyTransport(
    val client: AegisBleClient,
    scope: CoroutineScope = CoroutineScope(Dispatchers.IO)
) : KeyTransport {

    override val transportType: ConnectionTransportType = ConnectionTransportType.BLE

    override val isConnected: StateFlow<Boolean> = client.state
        .map { it.connection == AegisBleClient.Connection.READY }
        .stateIn(scope, SharingStarted.Eagerly, false)

    val devices: StateFlow<List<AegisBleClient.FoundDevice>> = client.devices

    val isScanning: StateFlow<Boolean> = client.state
        .map { it.connection == AegisBleClient.Connection.SCANNING }
        .stateIn(scope, SharingStarted.Eagerly, false)

    fun startScan() {
        client.startScan()
    }

    fun stopScan() {
        client.stopScan()
    }

    override suspend fun connect(target: String): Result<Unit> = runCatching {
        client.ensureBonded(target)
        client.connect(target)
    }

    override suspend fun disconnect() {
        client.disconnect()
    }

    override suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray? {
        var resp = client.sendVendor(opcode, payload)

        // Rito 1: Se retornar 0x05 (NEED_BINDING), abre janela de pareamento com 0x2F e reenvia
        if (resp != null && resp.size >= 2 && resp[1].toInt() == 0x05) {
            client.sendVendor(0x2F, ByteArray(0))
            resp = client.sendVendor(opcode, payload)
        }

        // Rito 2: Se retornar 0x01 (STATUS_NEED_UP), aguarda toque físico por até 15s (polling a cada 400ms)
        if (resp != null && resp.size >= 2 && resp[1].toInt() == 0x01) {
            val start = System.currentTimeMillis()
            while (System.currentTimeMillis() - start < 15000L) {
                delay(400)
                val retry = client.sendVendor(opcode, payload)
                if (retry != null && retry.size >= 2) {
                    if (retry[1].toInt() != 0x01) {
                        return retry
                    }
                    resp = retry
                }
            }
        }

        return resp
    }

    override suspend fun sendMsg(payload: ByteArray): ByteArray? {
        return client.sendMsg(payload)
    }

    override suspend fun cancel(): Boolean {
        return client.cancel()
    }
}
