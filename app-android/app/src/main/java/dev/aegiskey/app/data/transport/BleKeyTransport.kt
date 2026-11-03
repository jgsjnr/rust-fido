package dev.aegiskey.app.data.transport

import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.data.cbor.SecureGuardCbor
import dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl
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

        // Rito 0: Se retornar 0x36 ou 0x02 com PIN ativo, desbloqueia e arma 0x2F
        val activePin = dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl.lastVerifiedSessionPin
        if (resp != null && resp.size >= 2 && ((resp[1].toInt() and 0xFF == 0x36) || (resp[1].toInt() and 0xFF == 0x02)) && !activePin.isNullOrBlank()) {
            val pinBytes = activePin.toByteArray(Charsets.UTF_8)
            val unlockCbor = dev.aegiskey.app.data.cbor.SecureGuardCbor.encodeUnlockRequest(pinBytes)
            val unlockResp = if (bleReady) client.sendVendor(0x3B, unlockCbor) else hostBridgeClient.sendVendor(0x3B, unlockCbor)
            val unlockSt = if (unlockResp != null && unlockResp.size >= 2) unlockResp[1].toInt() and 0xFF else -1
            if (unlockSt != 0x00) {
                val provCbor = dev.aegiskey.app.data.cbor.SecureGuardCbor.encodeProvisionRequest(pinBytes, null, null)
                if (bleReady) client.sendVendor(0x3B, provCbor) else hostBridgeClient.sendVendor(0x3B, provCbor)
            }
            if (bleReady) client.sendVendor(0x2F, ByteArray(0)) else hostBridgeClient.sendVendor(0x2F, ByteArray(0))
            resp = if (bleReady) client.sendVendor(opcode, payload) else hostBridgeClient.sendVendor(opcode, payload)
        }

        // Rito 1: Se retornar 0x05 (NEED_BINDING) ou 0x27 (OPERATION_DENIED), abre janela de pareamento com 0x2F e reenvia
        if (resp != null && resp.size >= 2 && ((resp[1].toInt() and 0xFF == 0x05) || (resp[1].toInt() and 0xFF == 0x27))) {
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

        // Rito 3: Se retornar 0x02 (STATUS_NEED_PIN), autentica via 0x3B + CBOR
        // (mesma semântica do USB em UsbCtaphid.sendVendor rito 0/3). NUNCA
        // 0x2D + PIN cru: 0x2D é recovery-unlock no firmware (wipe + re-claim).
        if (resp != null && resp.size >= 2 && resp[1].toInt() == 0x02) {
            val sessionPin = SecureGuardRepositoryImpl.lastVerifiedSessionPin
            if (!sessionPin.isNullOrBlank()) {
                val (verifyOp, verifyPayload) = pinVerifyRequest(sessionPin)
                val verifyResp = if (bleReady) client.sendVendor(verifyOp, verifyPayload) else hostBridgeClient.sendVendor(verifyOp, verifyPayload)
                val verifyStatus = if (verifyResp != null && verifyResp.size >= 2) verifyResp[1].toInt() and 0xFF else -1
                if (verifyStatus == 0x00) {
                    resp = if (bleReady) client.sendVendor(opcode, payload) else hostBridgeClient.sendVendor(opcode, payload)
                }
            }
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

    val bridgeClient: HostUsbUartBridgeClient get() = hostBridgeClient

    companion object {
        /**
         * Monta a requisição de verificação de PIN do rito 3: sempre
         * 0x3B + `SecureGuardCbor.encodeUnlockRequest` (semântica USB em
         * `UsbCtaphid.sendVendor` ritos 0/3). Nunca 0x2D + PIN cru:
         * 0x2D é recovery-unlock no firmware (wipe + re-claim).
         */
        internal fun pinVerifyRequest(sessionPin: String): Pair<Int, ByteArray> {
            val pinBytes = sessionPin.toByteArray(Charsets.UTF_8)
            return 0x3B to SecureGuardCbor.encodeUnlockRequest(pinBytes)
        }
    }

    suspend fun fetchProximityStatus(): HostUsbUartBridgeClient.ProximityLockStatus =
        hostBridgeClient.fetchProximityStatus()

    suspend fun sendPhoneRssiAndEvaluate(rssiDbm: Int, elapsedSeconds: Double = 2.0): HostUsbUartBridgeClient.ProximityLockStatus =
        hostBridgeClient.sendPhoneRssiAndEvaluate(rssiDbm, elapsedSeconds)

    suspend fun configureProximityLock(
        enabled: Boolean,
        thresholdDbm: Int = -75,
        lockSeconds: Int = 10,
        enforceWindowsLock: Boolean = false
    ): Boolean = hostBridgeClient.configureProximityLock(enabled, thresholdDbm, lockSeconds, enforceWindowsLock)

    suspend fun notifySecureGuardUnlocked() {
        runCatching {
            sendVendor(0x2F, byteArrayOf())
        }
    }

    suspend fun unlockProximitySession(pin: String): Boolean =
        hostBridgeClient.unlockProximitySession(pin)
}
