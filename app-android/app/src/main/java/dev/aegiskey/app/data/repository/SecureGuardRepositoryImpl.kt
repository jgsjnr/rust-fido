package dev.aegiskey.app.data.repository

import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.data.cbor.SecureGuardCbor
import dev.aegiskey.app.data.transport.BleKeyTransport
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import dev.aegiskey.app.domain.repository.SecureGuardRepository
import dev.aegiskey.app.usb.UsbCtaphid
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Implementação do repositório Secure Guard para Android.
 *
 * Despacha ordens via HostUsbUartBridgeClient (quando bridge estiver ativa),
 * UsbCtaphid (OTG direto com opcodes 0x3A..0x3E) ou BleKeyTransport (BLE direto).
 *
 * Imune a erros de com.sun.jna.Native: utiliza o parser CBOR puro de SecureGuardCbor
 * para empacotar requisições e decodificar envelopes binários retornados pelo hardware.
 * Nunca persiste PIN ou Recovery Code em armazenamento local.
 */
class SecureGuardRepositoryImpl(
    private val hostBridgeClient: HostUsbUartBridgeClient,
    private val usbCtaphid: UsbCtaphid? = null,
    private val bleKeyTransport: BleKeyTransport? = null
) : SecureGuardRepository {

    private val _statusFlow = MutableStateFlow(SecureGuardStatus())
    override val statusFlow: StateFlow<SecureGuardStatus> = _statusFlow.asStateFlow()

    private suspend fun sendHardwareVendor(opcode: Int, payload: ByteArray): ByteArray? {
        // 1. Tenta USB OTG se conectado fisicamente
        val usb = usbCtaphid
        if (usb != null && usb.isUsbPhysicallyPresent()) {
            val resp = usb.sendVendor(opcode, payload)
            if (resp != null && resp.isNotEmpty()) return resp
        }

        // 2. Tenta BLE se pronto
        val ble = bleKeyTransport
        if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
            val resp = ble.sendVendor(opcode, payload)
            if (resp != null && resp.isNotEmpty()) return resp
        }

        // 3. Fallback: Host Bridge via vendor endpoint
        val bridgeResp = hostBridgeClient.sendVendor(opcode, payload)
        if (bridgeResp != null && bridgeResp.isNotEmpty()) return bridgeResp

        // 4. Última tentativa nos transportes caso conexão estivesse em transição
        if (usb != null) {
            val resp = usb.sendVendor(opcode, payload)
            if (resp != null && resp.isNotEmpty()) return resp
        }
        if (ble != null) {
            val resp = ble.sendVendor(opcode, payload)
            if (resp != null && resp.isNotEmpty()) return resp
        }

        return null
    }

    override suspend fun getStatus(): Result<SecureGuardStatus> = withContext(Dispatchers.IO) {
        runCatching {
            // 1. Tenta USB OTG se fisicamente presente
            val usb = usbCtaphid
            if (usb != null && usb.isUsbPhysicallyPresent()) {
                val req = SecureGuardCbor.encodeStatusRequest()
                val resp = usb.sendVendor(0x3A, req)
                if (resp != null && resp.isNotEmpty()) {
                    val frame = SecureGuardCbor.parseTransportFrame(0x3A, resp)
                    val parsed = SecureGuardCbor.parseStatus(frame.cborPayload)
                    if (parsed != null) {
                        _statusFlow.value = parsed
                        return@runCatching parsed
                    }
                }
            }

            // 2. Tenta BLE se conectado
            val ble = bleKeyTransport
            if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
                val req = SecureGuardCbor.encodeStatusRequest()
                val resp = ble.sendVendor(0x3A, req)
                if (resp != null && resp.isNotEmpty()) {
                    val frame = SecureGuardCbor.parseTransportFrame(0x3A, resp)
                    val parsed = SecureGuardCbor.parseStatus(frame.cborPayload)
                    if (parsed != null) {
                        _statusFlow.value = parsed
                        return@runCatching parsed
                    }
                }
            }

            // 3. Tenta HTTP bridge client
            val json = hostBridgeClient.fetchSecureGuardStatus()
            if (json != null && (json.optBoolean("ok", true) || json.has("state") || json.has("state_name"))) {
                val parsed = parseStatusFromJson(json)
                _statusFlow.value = parsed
                return@runCatching parsed
            }

            // 4. Fallback genérico de hardware
            val req = SecureGuardCbor.encodeStatusRequest()
            val resp = sendHardwareVendor(0x3A, req)
            if (resp != null && resp.isNotEmpty()) {
                val frame = SecureGuardCbor.parseTransportFrame(0x3A, resp)
                val parsed = SecureGuardCbor.parseStatus(frame.cborPayload)
                if (parsed != null) {
                    _statusFlow.value = parsed
                    return@runCatching parsed
                }
            }

            _statusFlow.value
        }
    }

    override suspend fun provision(
        pin: String,
        recoveryCode: String?,
        policy: SecureGuardPolicy?
    ): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            if (pin.length < 4) throw IllegalArgumentException("PIN deve ter no mínimo 4 caracteres")

            val polJson = policy?.let {
                JSONObject().apply {
                    put("wipe_on_5_failures", it.wipeOn5Failures)
                    put("protect_keys_and_aegn", it.protectKeysAndAegn)
                    put("protect_oath", it.protectOath)
                    put("test_mode_non_destructive_wipe", it.testModeNonDestructiveWipe)
                    put("session_duration_ms", it.sessionDurationMs)
                    put("inactivity_timeout_ms", it.inactivityTimeoutMs)
                }
            }

            // 1. Tenta HTTP bridge se ativa
            val json = hostBridgeClient.provisionSecureGuard(pin, recoveryCode, polJson)
            if (json != null && (json.optBoolean("ok", false) || json.optString("status") == "provisioned")) {
                val rc = json.optString("recovery_code", "")
                getStatus()
                return@runCatching rc
            }

            // 2. Tenta Hardware direto via CBOR (USB OTG, BLE ou Bridge Vendor)
            val encReq = SecureGuardCbor.encodeProvisionRequest(
                pin = pin.toByteArray(Charsets.UTF_8),
                recoveryCode = recoveryCode?.toByteArray(Charsets.UTF_8),
                policy = policy
            )
            val resp = sendHardwareVendor(0x3B, encReq)
            if (resp != null && resp.isNotEmpty()) {
                val frame = SecureGuardCbor.parseTransportFrame(0x3B, resp)
                val provRes = SecureGuardCbor.parseProvisionResult(frame.cborPayload)
                val generatedRc = provRes?.recoveryCode?.takeIf { it.isNotEmpty() }
                    ?: recoveryCode
                    ?: "GEN-RECOVERY-CODE"
                getStatus()
                return@runCatching generatedRc
            }

            throw IllegalStateException(json?.optString("error") ?: "Falha ao provisionar Secure Guard")
        }
    }

    override suspend fun unlock(pin: String): Result<SecureGuardStatus> = withContext(Dispatchers.IO) {
        runCatching {
            if (pin.length < 4) throw IllegalArgumentException("PIN deve ter no mínimo 4 caracteres")

            // Auto-provisionamento transparente: se estiver Unprovisioned, provisiona com o PIN informado
            val currentStatus = runCatching { getStatus().getOrNull() }.getOrNull() ?: _statusFlow.value
            if (currentStatus.state == SecureGuardStateEnum.UNPROVISIONED || !currentStatus.isProvisioned) {
                provision(pin = pin, recoveryCode = null, policy = null).getOrThrow()
            }

            // 1. Tenta HTTP bridge se ativa
            val json = hostBridgeClient.unlockSecureGuard(pin)
            if (json != null) {
                val success = json.optBoolean("success", false) || json.optBoolean("ok", false)
                val st = getStatus().getOrDefault(_statusFlow.value)
                if (!success) {
                    val err = json.optString("error", "PIN incorreto")
                    throw SecurityException(err)
                }
                return@runCatching st
            }

            // 2. Hardware direto via CBOR (USB OTG, BLE ou Bridge Vendor)
            val pinBytes = pin.toByteArray(Charsets.UTF_8)
            val encReq = SecureGuardCbor.encodeUnlockRequest(pinBytes)
            val resp = sendHardwareVendor(0x3B, encReq)
            if (resp != null && resp.isNotEmpty()) {
                val frame = SecureGuardCbor.parseTransportFrame(0x3B, resp)
                val unlockRes = SecureGuardCbor.parseUnlockResult(frame.status, frame.cborPayload)

                if (unlockRes.success) {
                    val updated = getStatus().getOrDefault(
                        _statusFlow.value.copy(
                            state = SecureGuardStateEnum.UNLOCKED,
                            isUnlocked = true,
                            failedAttempts = 0,
                            remainingAttempts = 5
                        )
                    )
                    _statusFlow.value = updated
                    return@runCatching updated
                } else {
                    val updated = _statusFlow.value.copy(
                        state = unlockRes.state,
                        isUnlocked = false,
                        failedAttempts = unlockRes.failedAttempts,
                        remainingAttempts = unlockRes.remainingAttempts,
                        rateLimitRemainingMs = unlockRes.rateLimitRemainingMs
                    )
                    _statusFlow.value = updated
                    val err = unlockRes.errorMessage ?: (
                        if (unlockRes.remainingAttempts == 0) "Limite de tentativas excedido"
                        else "PIN incorreto. Restam ${unlockRes.remainingAttempts} tentativas."
                    )
                    throw SecurityException(err)
                }
            }

            throw IllegalStateException("Hardware indisponível para validar PIN")
        }
    }

    override suspend fun lock(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val json = hostBridgeClient.lockSecureGuard()
            if (json != null && json.optBoolean("ok", true)) {
                getStatus()
                return@runCatching Unit
            }

            val encReq = SecureGuardCbor.encodeLockRequest()
            val resp = sendHardwareVendor(0x3C, encReq)
            if (resp != null && resp.isNotEmpty()) {
                getStatus()
                return@runCatching Unit
            }

            getStatus()
            Unit
        }
    }

    override suspend fun changePin(currentPin: String, newPin: String): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            if (newPin.length < 4) throw IllegalArgumentException("Novo PIN deve ter no mínimo 4 dígitos")
            val json = hostBridgeClient.changeSecureGuardPin(currentPin, newPin)
            if (json != null && (json.optBoolean("ok", false) || json.optString("status") == "pin_changed")) {
                getStatus()
                return@runCatching Unit
            }

            val encReq = SecureGuardCbor.encodeChangePinRequest(
                currentPin.toByteArray(Charsets.UTF_8),
                newPin.toByteArray(Charsets.UTF_8)
            )
            val resp = sendHardwareVendor(0x3B, encReq)
            if (resp != null && resp.isNotEmpty()) {
                getStatus()
                return@runCatching Unit
            }

            throw IllegalStateException(json?.optString("error") ?: "Falha ao alterar PIN")
        }
    }

    override suspend fun recover(recoveryCode: String, newPin: String): Result<String?> = withContext(Dispatchers.IO) {
        runCatching {
            if (newPin.length < 4) throw IllegalArgumentException("Novo PIN deve ter no mínimo 4 dígitos")
            val json = hostBridgeClient.recoverSecureGuard(recoveryCode, newPin)
            if (json != null && (json.optBoolean("ok", false) || json.optString("status") == "recovered")) {
                val newRc = if (json.has("new_recovery_code")) json.optString("new_recovery_code") else null
                getStatus()
                return@runCatching newRc
            }

            val encReq = SecureGuardCbor.encodeRecoverRequest(
                recoveryCode.toByteArray(Charsets.UTF_8),
                newPin.toByteArray(Charsets.UTF_8)
            )
            val resp = sendHardwareVendor(0x3B, encReq)
            if (resp != null && resp.isNotEmpty()) {
                val frame = SecureGuardCbor.parseTransportFrame(0x3B, resp)
                val decoded = SecureGuardCbor.decode(frame.cborPayload) as? Map<*, *>
                val newRc = decoded?.get("new_recovery_code") as? String
                getStatus()
                return@runCatching newRc
            }

            throw IllegalStateException(json?.optString("error") ?: "Falha na recuperação de emergência")
        }
    }

    override suspend fun updatePolicy(policy: SecureGuardPolicy): Result<SecureGuardPolicy> = withContext(Dispatchers.IO) {
        runCatching {
            val body = JSONObject().apply {
                put("wipe_on_5_failures", policy.wipeOn5Failures)
                put("protect_keys_and_aegn", policy.protectKeysAndAegn)
                put("protect_oath", policy.protectOath)
                put("test_mode_non_destructive_wipe", policy.testModeNonDestructiveWipe)
                put("session_duration_ms", policy.sessionDurationMs)
                put("inactivity_timeout_ms", policy.inactivityTimeoutMs)
            }
            val json = hostBridgeClient.configureSecureGuard(body)
            if (json != null && json.optBoolean("ok", false)) {
                getStatus()
                return@runCatching policy
            }

            val encReq = SecureGuardCbor.encodeConfigRequest(policy)
            val resp = sendHardwareVendor(0x3D, encReq)
            if (resp != null && resp.isNotEmpty()) {
                getStatus()
                return@runCatching policy
            }

            throw IllegalStateException(json?.optString("error") ?: "Falha ao configurar políticas")
        }
    }

    override suspend fun wipeSelective(scope: Int, confirmationToken: String): Result<Boolean> = withContext(Dispatchers.IO) {
        runCatching {
            val json = hostBridgeClient.wipeSelectiveSecureGuard(scope, confirmationToken)
            if (json != null && (json.optBoolean("ok", false) || json.optString("status") == "wiped")) {
                getStatus()
                return@runCatching json.optBoolean("simulated", false)
            }

            val encReq = SecureGuardCbor.encodeWipeRequest(scope, confirmationToken)
            val resp = sendHardwareVendor(0x3E, encReq)
            if (resp != null && resp.isNotEmpty()) {
                val frame = SecureGuardCbor.parseTransportFrame(0x3E, resp)
                val decoded = SecureGuardCbor.decode(frame.cborPayload) as? Map<*, *>
                val simulated = decoded?.get("simulated") as? Boolean ?: false
                getStatus()
                return@runCatching simulated
            }

            throw IllegalStateException(json?.optString("error") ?: "Falha ao executar wipe")
        }
    }

    private fun parseStatusFromJson(json: JSONObject): SecureGuardStatus {
        val stateName = json.optString("state_name", "Unprovisioned")
        val stateCode = json.optInt("state", 0)
        val stateEnum = SecureGuardStateEnum.fromString(stateName).let {
            if (it == SecureGuardStateEnum.DEVICE_UNAVAILABLE) SecureGuardStateEnum.fromWireCode(stateCode) else it
        }

        val policy = SecureGuardPolicy(
            wipeOn5Failures = json.optBoolean("wipe_on_5_failures", false),
            sessionDurationMs = json.optLong("session_duration_ms", 300_000L),
            inactivityTimeoutMs = json.optLong("inactivity_timeout_ms", 120_000L),
            protectKeysAndAegn = json.optBoolean("protect_keys_and_aegn", true),
            protectOath = json.optBoolean("protect_oath", false),
            testModeNonDestructiveWipe = json.optBoolean("test_mode_non_destructive_wipe", false)
        )

        return SecureGuardStatus(
            state = stateEnum,
            isProvisioned = json.optBoolean("provisioned", stateEnum != SecureGuardStateEnum.UNPROVISIONED),
            isUnlocked = json.optBoolean("unlocked", stateEnum == SecureGuardStateEnum.UNLOCKED),
            failedAttempts = json.optInt("failed_attempts", 0),
            remainingAttempts = json.optInt("remaining_attempts", 5),
            maxAttempts = json.optInt("max_attempts", 5),
            rateLimitRemainingMs = json.optLong("rate_limit_remaining_ms", 0L),
            sessionRemainingMs = json.optLong("session_remaining_ms", 0L),
            policy = policy,
            lastWipeSimulated = json.optBoolean("last_wipe_simulated", false),
            auditCount = json.optLong("audit_count", 0L),
            lastGeneratedRecoveryCode = if (json.has("last_generated_recovery_code")) json.optString("last_generated_recovery_code") else null
        )
    }
}
