package dev.aegiskey.app.data.transport

import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.usb.UsbCtaphid
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn

/**
 * Transporte USB host encapsulando [UsbCtaphid].
 */
class UsbKeyTransport(
    val usb: UsbCtaphid,
    scope: CoroutineScope = CoroutineScope(Dispatchers.IO)
) : KeyTransport {

    override val transportType: ConnectionTransportType = ConnectionTransportType.USB

    override val isConnected: StateFlow<Boolean> = usb.ui
        .map { it.state == UsbCtaphid.State.CONNECTED }
        .stateIn(scope, SharingStarted.Eagerly, false)

    override suspend fun connect(target: String): Result<Unit> = runCatching {
        val device = usb.findDevice() ?: throw IllegalStateException("dispositivo USB não encontrado")
        usb.requestPermission(device)
    }

    override suspend fun disconnect() {
        usb.close()
    }

    override suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray? {
        // USB transport delegates vendor frame encapsulado em CTAPHID MSG
        return null
    }

    override suspend fun sendMsg(payload: ByteArray): ByteArray? {
        val ok = usb.pingTest(payload)
        return if (ok) byteArrayOf(0x83.toByte(), 0x00.toByte()) else null
    }

    override suspend fun cancel(): Boolean {
        return true
    }
}
