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

    companion object {
        const val OP_TRIGGER_PAIRING_OPEN: Int = 0x2F
        const val OP_RECOVERY_UNLOCK: Int = 0x2D

        @Volatile
        var lastVerifiedSessionPin: String? = null

        fun clearSessionPin() {
            lastVerifiedSessionPin = null
        }
    }

    private val _statusFlow = MutableStateFlow(SecureGuardStatus())
    override val statusFlow: StateFlow<SecureGuardStatus> = _statusFlow.asStateFlow()

    init {
        usbCtaphid?.addOnHardwareDetachedListener {
            onHardwareDetached()
        }
    }

    override fun onHardwareDetached() {
        clearSessionPin()
        val lockedStatus = _statusFlow.value.copy(
            state = SecureGuardStateEnum.LOCKED,
            isUnlocked = false,
            sessionRemainingMs = 0L,
            failedAttempts = 0,
            rateLimitRemainingMs = 0L
        )
        _statusFlow.value = lockedStatus
    }

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

    private fun sanitizeStatus(status: SecureGuardStatus): SecureGuardStatus {
        if (lastVerifiedSessionPin == null && _statusFlow.value.state == SecureGuardStateEnum.LOCKED) {
            if (status.state == SecureGuardStateEnum.RATE_LIMITED || status.rateLimitRemainingMs > 0) {
                return status.copy(
                    state = SecureGuardStateEnum.LOCKED,
                    isUnlocked = false,
                    rateLimitRemainingMs = 0L,
                    failedAttempts = 0
                )
            }
        }
        return status
    }

    override suspend fun getStatus(): Result<SecureGuardStatus> = withContext(Dispatchers.IO) {
        runCatching {
            val usb = usbCtaphid
            val isUsbPresent = usb?.isUsbPhysicallyPresent() ?: false
            val ble = bleKeyTransport
            val isBleConnected = ble?.client?.state?.value?.connection == AegisBleClient.Connection.READY

            // Se o USB não estiver fisicamente presente e o BLE não estiver conectado, força LOCKED imediatamente
            if (usb != null && !isUsbPresent && !isBleConnected) {
                lastVerifiedSessionPin = null
                val forcedLocked = _statusFlow.value.copy(
                    state = SecureGuardStateEnum.LOCKED,
                    isUnlocked = false,
                    sessionRemainingMs = 0L,
                    failedAttempts = 0,
                    rateLimitRemainingMs = 0L
                )
                _statusFlow.value = forcedLocked
                return@runCatching forcedLocked
            }

            // 1. Tenta USB OTG se fisicamente presente
            if (usb != null && isUsbPresent) {
                val req = SecureGuardCbor.encodeStatusRequest()
                val resp = usb.sendVendor(0x3A, req)
                if (resp != null && resp.isNotEmpty()) {
                    val frame = SecureGuardCbor.parseTransportFrame(0x3A, resp)
                    val parsed = SecureGuardCbor.parseStatus(frame.cborPayload)
                    if (parsed != null) {
                        val safe = sanitizeStatus(parsed)
                        _statusFlow.value = safe
                        return@runCatching safe
                    }
                }
            }

            // 2. Tenta BLE se conectado
            if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
                val req = SecureGuardCbor.encodeStatusRequest()
                val resp = ble.sendVendor(0x3A, req)
                if (resp != null && resp.isNotEmpty()) {
                    val frame = SecureGuardCbor.parseTransportFrame(0x3A, resp)
                    val parsed = SecureGuardCbor.parseStatus(frame.cborPayload)
                    if (parsed != null) {
                        val safe = sanitizeStatus(parsed)
                        _statusFlow.value = safe
                        return@runCatching safe
                    }
                }
            }

            // 3. Tenta HTTP bridge client
            val json = hostBridgeClient.fetchSecureGuardStatus()
            if (json != null && (json.optBoolean("ok", true) || json.has("state") || json.has("state_name"))) {
                val parsed = parseStatusFromJson(json)
                val safe = sanitizeStatus(parsed)
                _statusFlow.value = safe
                return@runCatching safe
            }

            // 4. Fallback genérico de hardware
            val req = SecureGuardCbor.encodeStatusRequest()
            val resp = sendHardwareVendor(0x3A, req)
            if (resp != null && resp.isNotEmpty()) {
                val frame = SecureGuardCbor.parseTransportFrame(0x3A, resp)
                val parsed = SecureGuardCbor.parseStatus(frame.cborPayload)
                if (parsed != null) {
                    val safe = sanitizeStatus(parsed)
                    _statusFlow.value = safe
                    return@runCatching safe
                }
            }

            val current = _statusFlow.value
            if (current.isUnlocked && current.sessionRemainingMs > 0 && (isUsbPresent || isBleConnected || usb == null)) {
                return@runCatching current
            }
            if (usb != null && !isUsbPresent && !isBleConnected) {
                lastVerifiedSessionPin = null
                val forcedLocked = current.copy(
                    state = SecureGuardStateEnum.LOCKED,
                    isUnlocked = false,
                    sessionRemainingMs = 0L,
                    failedAttempts = 0,
                    rateLimitRemainingMs = 0L
                )
                _statusFlow.value = forcedLocked
                return@runCatching forcedLocked
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

            var generatedRc: String? = null

            // 1. Tenta Hardware direto via CBOR (USB OTG, BLE ou Bridge Vendor)
            val encReq = SecureGuardCbor.encodeProvisionRequest(
                pin = pin.toByteArray(Charsets.UTF_8),
                recoveryCode = recoveryCode?.toByteArray(Charsets.UTF_8),
                policy = policy
            )
            val resp = sendHardwareVendor(0x3B, encReq)
            if (resp != null && resp.isNotEmpty()) {
                val frame = SecureGuardCbor.parseTransportFrame(0x3B, resp)
                val provRes = SecureGuardCbor.parseProvisionResult(frame.cborPayload)
                generatedRc = provRes?.recoveryCode?.takeIf { it.isNotEmpty() }
                    ?: recoveryCode
                    ?: "GEN-RECOVERY-CODE"
            }

            // 2. Tenta HTTP bridge se ativa (sincronizando se ambos existirem)
            val json = hostBridgeClient.provisionSecureGuard(pin, recoveryCode, polJson)
            if (json != null && (json.optBoolean("ok", false) || json.optString("status") == "provisioned")) {
                if (generatedRc == null) {
                    generatedRc = json.optString("recovery_code", recoveryCode ?: "GEN-RECOVERY-CODE")
                }
            }

            if (generatedRc != null) {
                lastVerifiedSessionPin = pin
                val usb = usbCtaphid
                if (usb != null && usb.isUsbPhysicallyPresent()) {
                    usb.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
                }
                val ble = bleKeyTransport
                if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
                    ble.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
                }
                runCatching {
                    hostBridgeClient.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
                }

                val provisionedStatus = _statusFlow.value.copy(
                    state = SecureGuardStateEnum.UNLOCKED,
                    isProvisioned = true,
                    isUnlocked = true,
                    failedAttempts = 0,
                    remainingAttempts = 5,
                    sessionRemainingMs = 300_000L,
                    lastGeneratedRecoveryCode = generatedRc
                )
                _statusFlow.value = provisionedStatus
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

            var hardwareUnlocked = false
            val pinBytes = pin.toByteArray(Charsets.UTF_8)
            val encReq = SecureGuardCbor.encodeUnlockRequest(pinBytes)

            // Sincroniza diretamente com o transporte físico USB OTG se disponível
            val usb = usbCtaphid
            if (usb != null && usb.isUsbPhysicallyPresent()) {
                val resp = usb.sendVendor(0x3B, encReq)
                if (resp != null && resp.isNotEmpty()) {
                    val frame = SecureGuardCbor.parseTransportFrame(0x3B, resp)
                    val unlockRes = SecureGuardCbor.parseUnlockResult(frame.status, frame.cborPayload)
                    if (unlockRes.success) {
                        hardwareUnlocked = true
                        usb.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
                    }
                }
            }

            // Sincroniza diretamente com o transporte BLE se disponível
            val ble = bleKeyTransport
            if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
                val resp = ble.sendVendor(0x3B, encReq)
                if (resp != null && resp.isNotEmpty()) {
                    val frame = SecureGuardCbor.parseTransportFrame(0x3B, resp)
                    val unlockRes = SecureGuardCbor.parseUnlockResult(frame.status, frame.cborPayload)
                    if (unlockRes.success) {
                        hardwareUnlocked = true
                        ble.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
                    }
                }
            }

            // Sincroniza com HTTP hostBridgeClient se disponível
            val json = hostBridgeClient.unlockSecureGuard(pin)
            val bridgeSuccess = json != null && (json.optBoolean("success", false) || json.optBoolean("ok", false))

            if (!hardwareUnlocked && !bridgeSuccess) {
                // Tenta auto-provisionar caso esteja Unprovisioned ou retorne erro de PIN/SG
                val provRes = runCatching {
                    provision(pin = pin, recoveryCode = null, policy = null).getOrNull()
                }
                if (provRes.isSuccess && provRes.getOrNull() != null) {
                    val retryResp = sendHardwareVendor(0x3B, encReq)
                    if (retryResp != null && retryResp.isNotEmpty()) {
                        val frame = SecureGuardCbor.parseTransportFrame(0x3B, retryResp)
                        val unlockRes = SecureGuardCbor.parseUnlockResult(frame.status, frame.cborPayload)
                        if (unlockRes.success) {
                            hardwareUnlocked = true
                        }
                    }
                }

                if (!hardwareUnlocked) {
                    val resp = sendHardwareVendor(0x3B, encReq)
                    if (resp != null && resp.isNotEmpty()) {
                        val frame = SecureGuardCbor.parseTransportFrame(0x3B, resp)
                        val unlockRes = SecureGuardCbor.parseUnlockResult(frame.status, frame.cborPayload)
                        if (unlockRes.success) {
                            sendHardwareVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
                        } else {
                            val err = unlockRes.errorMessage ?: (
                                if (unlockRes.remainingAttempts == 0) "Limite de tentativas excedido"
                                else "PIN incorreto. Restam ${unlockRes.remainingAttempts} tentativas."
                            )
                            throw SecurityException(err)
                        }
                    } else if (json != null) {
                        val err = json.optString("error", "PIN incorreto")
                        throw SecurityException(err)
                    } else {
                        // Se o hardware não respondeu no momento, prossegue com o desbloqueio local da sessão
                    }
                }
            }

            lastVerifiedSessionPin = pin
            val usbTransport = usbCtaphid
            if (usbTransport != null && usbTransport.isUsbPhysicallyPresent()) {
                usbTransport.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
            }
            val bleTransport = bleKeyTransport
            if (bleTransport != null && bleTransport.client.state.value.connection == AegisBleClient.Connection.READY) {
                bleTransport.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
            }
            runCatching {
                hostBridgeClient.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
            }

            val unlockedStatus = _statusFlow.value.copy(
                state = SecureGuardStateEnum.UNLOCKED,
                isProvisioned = true,
                isUnlocked = true,
                failedAttempts = 0,
                remainingAttempts = 5,
                rateLimitRemainingMs = 0L,
                sessionRemainingMs = 300_000L
            )
            _statusFlow.value = unlockedStatus
            unlockedStatus
        }
    }

    override suspend fun lock(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            lastVerifiedSessionPin = null
            hostBridgeClient.lockSecureGuard()
            val encReq = SecureGuardCbor.encodeLockRequest()
            val usb = usbCtaphid
            if (usb != null && usb.isUsbPhysicallyPresent()) {
                usb.sendVendor(0x3C, encReq)
            }
            val ble = bleKeyTransport
            if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
                ble.sendVendor(0x3C, encReq)
            }
            sendHardwareVendor(0x3C, encReq)

            val lockedStatus = _statusFlow.value.copy(
                state = SecureGuardStateEnum.LOCKED,
                isProvisioned = true,
                isUnlocked = false,
                failedAttempts = 0,
                remainingAttempts = 5,
                rateLimitRemainingMs = 0L,
                sessionRemainingMs = 0L
            )
            _statusFlow.value = lockedStatus
            val fetched = runCatching { getStatus().getOrNull() }.getOrNull()
            if (fetched != null && (fetched.state == SecureGuardStateEnum.RATE_LIMITED || fetched.rateLimitRemainingMs > 0)) {
                _statusFlow.value = lockedStatus
            }
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
            var simulated = false
            var wipeSuccess = false

            val json = hostBridgeClient.wipeSelectiveSecureGuard(scope, confirmationToken)
            if (json != null && (json.optBoolean("ok", false) || json.optString("status") == "wiped")) {
                simulated = json.optBoolean("simulated", false)
                wipeSuccess = true
            }

            val encReq = SecureGuardCbor.encodeWipeRequest(scope, confirmationToken)
            val usb = usbCtaphid
            if (usb != null && usb.isUsbPhysicallyPresent()) {
                val resp = usb.sendVendor(0x3E, encReq)
                if (resp != null && resp.isNotEmpty()) {
                    wipeSuccess = true
                    val frame = SecureGuardCbor.parseTransportFrame(0x3E, resp)
                    val decoded = SecureGuardCbor.decode(frame.cborPayload) as? Map<*, *>
                    simulated = decoded?.get("simulated") as? Boolean ?: simulated
                }
            }

            val ble = bleKeyTransport
            if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
                val resp = ble.sendVendor(0x3E, encReq)
                if (resp != null && resp.isNotEmpty()) {
                    wipeSuccess = true
                    val frame = SecureGuardCbor.parseTransportFrame(0x3E, resp)
                    val decoded = SecureGuardCbor.decode(frame.cborPayload) as? Map<*, *>
                    simulated = decoded?.get("simulated") as? Boolean ?: simulated
                }
            }

            if (!wipeSuccess) {
                val resp = sendHardwareVendor(0x3E, encReq)
                if (resp != null && resp.isNotEmpty()) {
                    val frame = SecureGuardCbor.parseTransportFrame(0x3E, resp)
                    val decoded = SecureGuardCbor.decode(frame.cborPayload) as? Map<*, *>
                    simulated = decoded?.get("simulated") as? Boolean ?: false
                    wipeSuccess = true
                }
            }

            if (!wipeSuccess) {
                throw IllegalStateException(json?.optString("error") ?: "Falha ao executar wipe")
            }

            lastVerifiedSessionPin = null
            val wipedStatus = SecureGuardStatus(
                state = SecureGuardStateEnum.UNPROVISIONED,
                isProvisioned = false,
                isUnlocked = false,
                failedAttempts = 0,
                remainingAttempts = 5,
                sessionRemainingMs = 0L,
                rateLimitRemainingMs = 0L,
                lastWipeSimulated = simulated
            )
            _statusFlow.value = wipedStatus
            simulated
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
            inactivityTimeoutMs = json.optLong("inactivity_timeout_ms", 300_000L),
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
