package dev.aegiskey.app.data.transport

import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.usb.UsbCtaphid
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.withContext

/**
 * Transporte USB host encapsulando [UsbCtaphid] com fallback automático para [HostUsbUartBridgeClient].
 */
class UsbKeyTransport(
    val usb: UsbCtaphid,
    val hostBridgeClient: HostUsbUartBridgeClient = HostUsbUartBridgeClient(),
    scope: CoroutineScope = CoroutineScope(Dispatchers.IO)
) : KeyTransport {

    override val transportType: ConnectionTransportType = ConnectionTransportType.USB

    override val isConnected: StateFlow<Boolean> = usb.ui
        .map { it.state == UsbCtaphid.State.CONNECTED }
        .stateIn(scope, SharingStarted.Eagerly, false)

    suspend fun isPhysicallyReachable(): Boolean = withContext(Dispatchers.IO) {
        if (usb.isUsbPhysicallyPresent() && (usb.isConnected || usb.open())) {
            return@withContext true
        }
        return@withContext hostBridgeClient.isBridgeAvailable(500)
    }

    override suspend fun connect(target: String): Result<Unit> = runCatching {
        val device = usb.findAegisDevice() ?: usb.findDevice()
        if (device != null) {
            usb.requestPermission(device)
        } else {
            val bridgeInfo = hostBridgeClient.probeRealHardware()
            if (bridgeInfo == null || !bridgeInfo.connected) {
                throw IllegalStateException("Dispositivo USB ou Host Bridge não encontrado")
            }
        }
    }

    override suspend fun disconnect() {
        usb.close()
    }

    override suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray? {
        if (usb.isConnected) {
            val resp = usb.sendVendor(opcode, payload)
            if (resp != null) return resp
        } else {
            val device = usb.findAegisDevice() ?: usb.findDevice()
            if (device != null) {
                usb.openDevice(device)
                if (usb.isConnected) {
                    val resp = usb.sendVendor(opcode, payload)
                    if (resp != null) return resp
                }
            }
        }

        // Fallback transparente para Host USB/UART Bridge (Emulador Android / Bancada de Testes)
        return hostBridgeClient.sendVendor(opcode, payload)
    }

    override suspend fun sendMsg(payload: ByteArray): ByteArray? {
        if (usb.isConnected) {
            val resp = usb.sendCtapMessage(UsbCtaphid.CMD_MSG, payload)
            if (resp != null) return resp
        }
        return hostBridgeClient.sendVendor(0x83, payload)
    }

    suspend fun notifySecureGuardUnlocked() {
        runCatching {
            sendVendor(0x2F, byteArrayOf())
        }
    }

    override suspend fun cancel(): Boolean {
        return true
    }
}
