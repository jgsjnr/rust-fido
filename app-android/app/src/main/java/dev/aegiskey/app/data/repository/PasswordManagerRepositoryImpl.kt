package dev.aegiskey.app.data.repository

import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.data.cbor.SecureGuardCbor
import dev.aegiskey.app.data.transport.BleKeyTransport
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.data.transport.UsbKeyTransport
import dev.aegiskey.app.domain.repository.PasswordManagerRepository
import dev.aegiskey.app.domain.repository.PmGateError
import dev.aegiskey.app.domain.repository.PmListResult
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.pm.PmCbor
import dev.aegiskey.app.usb.UsbCtaphid
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Blind-transport implementation: reuses the live hardware transports
 * (USB OTG → BLE → host bridge vendor endpoint, same priority as
 * [SecureGuardRepositoryImpl]) and parses status-first frames with
 * [SecureGuardCbor.parseTransportFrame]. No cache, no disk, no logs of
 * payloads — only opcode + status name (log-only) reach [DeviceLog].
 */
class PasswordManagerRepositoryImpl(
    private val hostBridgeClient: HostUsbUartBridgeClient,
    private val usbCtaphid: UsbCtaphid? = null,
    private val bleKeyTransport: BleKeyTransport? = null,
) : PasswordManagerRepository {

    private suspend fun sendPm(opcode: Int, payload: ByteArray): ByteArray? {
        require(PmCbor.isPmOpcode(opcode)) { "non-PM opcode rejected" }
        // 1. USB OTG when physically present.
        val usb = usbCtaphid
        if (usb != null && usb.isUsbPhysicallyPresent()) {
            val resp = runCatching { usb.sendVendor(opcode, payload) }.getOrNull()
            if (resp != null && resp.isNotEmpty()) return resp
        }
        // 2. BLE when ready.
        val ble = bleKeyTransport
        if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
            val resp = runCatching { ble.sendVendor(opcode, payload) }.getOrNull()
            if (resp != null && resp.isNotEmpty()) return resp
        }
        // 3. Host bridge vendor endpoint (emulator / Wi-Fi bridge path).
        val bridgeResp = runCatching { hostBridgeClient.sendVendor(opcode, payload) }.getOrNull()
        if (bridgeResp != null && bridgeResp.isNotEmpty()) return bridgeResp
        return null
    }

    private fun gateError(status: Int): PmGateError {
        val gate = PmCbor.gateOf(status)
        val name = PmCbor.statusName(status)
        val kind = when (gate) {
            is PmCbor.PmGate.NeedBinding -> PmGateError.Kind.NEED_BINDING
            is PmCbor.PmGate.PresenceRequired -> PmGateError.Kind.PRESENCE_REQUIRED
            is PmCbor.PmGate.PinRequired -> PmGateError.Kind.PIN_REQUIRED
            else -> PmGateError.Kind.DENIED
        }
        return PmGateError(kind, status, name, "Password vault denied: $name")
    }

    private fun frameFor(opcode: Int, raw: ByteArray): SecureGuardCbor.TransportFrame {
        val frame = SecureGuardCbor.parseTransportFrame(opcode, raw)
        if (frame.status < 0) {
            throw PmGateError(
                PmGateError.Kind.INVALID_ENVELOPE, -1, "Unknown",
                "Password vault frame rejected (no status)",
            )
        }
        return frame
    }

    override suspend fun listPage(cursor: Long, limit: Int): Result<PmListResult> =
        withContext(Dispatchers.IO) {
            runCatching {
                val req = PmCbor.encodeListRequest(cursor, limit)
                val raw = sendPm(PmCbor.OP_PM_LIST, req)
                    ?: throw PmGateError(
                        PmGateError.Kind.NO_TRANSPORT, -1, "Unknown",
                        "Password vault unreachable (no transport)",
                    )
                val frame = frameFor(PmCbor.OP_PM_LIST, raw)
                DeviceLog.append(
                    DeviceLog.Category.SYSTEM,
                    "pm list op=0x45 status=" + PmCbor.statusName(frame.status),
                )
                if (frame.status != PmCbor.STATUS_OK) throw gateError(frame.status)
                PmListResult(PmCbor.decodeListResponse(frame.cborPayload), frame.status)
            }
        }

    override suspend fun getRelease(id: ByteArray): Result<PmCbor.PmRelease> =
        withContext(Dispatchers.IO) {
            runCatching {
                val req = PmCbor.encodeGetRequest(id.copyOf())
                val raw = sendPm(PmCbor.OP_PM_GET, req)
                    ?: throw PmGateError(
                        PmGateError.Kind.NO_TRANSPORT, -1, "Unknown",
                        "Password vault unreachable (no transport)",
                    )
                val frame = frameFor(PmCbor.OP_PM_GET, raw)
                DeviceLog.append(
                    DeviceLog.Category.SYSTEM,
                    "pm get op=0x44 status=" + PmCbor.statusName(frame.status),
                )
                if (frame.status != PmCbor.STATUS_OK) throw gateError(frame.status)
                PmCbor.decodeReleaseResponse(frame.cborPayload)
            }
        }

    override suspend fun getStatus(): Result<PmCbor.PmStatus> =
        withContext(Dispatchers.IO) {
            runCatching {
                val raw = sendPm(PmCbor.OP_PM_STATUS, PmCbor.encodeStatusRequest())
                    ?: throw PmGateError(
                        PmGateError.Kind.NO_TRANSPORT, -1, "Unknown",
                        "Password vault unreachable (no transport)",
                    )
                val frame = frameFor(PmCbor.OP_PM_STATUS, raw)
                DeviceLog.append(
                    DeviceLog.Category.SYSTEM,
                    "pm status op=0x47 status=" + PmCbor.statusName(frame.status),
                )
                if (frame.status != PmCbor.STATUS_OK) throw gateError(frame.status)
                PmCbor.decodeStatusResponse(frame.cborPayload)
            }
        }
}
