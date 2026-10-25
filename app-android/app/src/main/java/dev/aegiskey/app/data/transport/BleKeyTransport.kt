package dev.aegiskey.app.data.transport

import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.domain.model.ConnectionTransportType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn

/**
 * Transporte BLE padrão encapsulando [AegisBleClient] com exposição reativa
 * dos dispositivos detectados e controle de scan.
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
        return client.sendVendor(opcode, payload)
    }

    override suspend fun sendMsg(payload: ByteArray): ByteArray? {
        return client.sendMsg(payload)
    }

    override suspend fun cancel(): Boolean {
        return client.cancel()
    }
}
