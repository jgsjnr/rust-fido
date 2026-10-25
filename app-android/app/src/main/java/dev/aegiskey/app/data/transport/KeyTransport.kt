package dev.aegiskey.app.data.transport

import dev.aegiskey.app.domain.model.ConnectionTransportType
import kotlinx.coroutines.flow.StateFlow

/**
 * Contrato unificado de transporte para comunicação com a chave AegisKey.
 */
interface KeyTransport {
    val transportType: ConnectionTransportType
    val isConnected: StateFlow<Boolean>

    suspend fun connect(target: String): Result<Unit>
    suspend fun disconnect()
    suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray?
    suspend fun sendMsg(payload: ByteArray): ByteArray?
    suspend fun cancel(): Boolean
}
