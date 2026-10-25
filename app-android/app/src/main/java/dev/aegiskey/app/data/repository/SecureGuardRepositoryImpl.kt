package dev.aegiskey.app.data.repository

import dev.aegiskey.app.bridge.AegisBridge
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
 * Despacha ordens via HostUsbUartBridgeClient (quando bridge estiver ativa) ou
 * via UsbCtaphid (OTG direto com opcodes 0x3A..0x3E).
 * Nunca persiste PIN ou Recovery Code em armazenamento local.
 */
class SecureGuardRepositoryImpl(
    private val hostBridgeClient: HostUsbUartBridgeClient,
    private val usbCtaphid: UsbCtaphid? = null
) : SecureGuardRepository {

    private val _statusFlow = MutableStateFlow(SecureGuardStatus())
    val statusFlow: StateFlow<SecureGuardStatus> = _statusFlow.asStateFlow()

    override suspend fun getStatus(): Result<SecureGuardStatus> = withContext(Dispatchers.IO) {
        runCatching {
            // 1. Tenta HTTP bridge client
            val json = hostBridgeClient.fetchSecureGuardStatus()
            if (json != null && json.optBoolean("ok", true)) {
                val parsed = parseStatusFromJson(json)
                _statusFlow.value = parsed
                return@runCatching parsed
            }

            // 2. Tenta USB CTAPHID direto
            val usb = usbCtaphid
            if (usb != null && usb.isUsbPhysicallyPresent()) {
                val req = AegisBridge.secureGuardEncodeLock().getOrNull() ?: ByteArray(0)
                val resp = usb.sendVendor(0x3A, req)
                if (resp != null && resp.isNotEmpty()) {
                    val dto = AegisBridge.secureGuardParseStatus(resp).getOrNull()
                    if (dto != null) {
                        val parsed = parseStatusFromDto(dto)
                        _statusFlow.value = parsed
                        return@runCatching parsed
                    }
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

            val json = hostBridgeClient.provisionSecureGuard(pin, recoveryCode, polJson)
            if (json != null && (json.optBoolean("ok", false) || json.optString("status") == "provisioned")) {
                val rc = json.optString("recovery_code", "")
                getStatus()
                return@runCatching rc
            }

            val usb = usbCtaphid
            if (usb != null && usb.isUsbPhysicallyPresent()) {
                val encReq = AegisBridge.secureGuardEncodeProvision(
                    pin = pin.toByteArray(Charsets.UTF_8),
                    recoveryCode = recoveryCode?.toByteArray(Charsets.UTF_8) ?: ByteArray(0),
                    wipeOn5Failures = policy?.wipeOn5Failures ?: false,
                    testMode = policy?.testModeNonDestructiveWipe ?: false
                ).getOrThrow()
                val resp = usb.sendVendor(0x3B, encReq)
                if (resp != null && resp.isNotEmpty()) {
                    getStatus()
                    return@runCatching recoveryCode ?: "GEN-RECOVERY-CODE"
                }
            }

            throw IllegalStateException(json?.optString("error") ?: "Falha ao provisionar Secure Guard")
        }
    }

    override suspend fun unlock(pin: String): Result<SecureGuardStatus> = withContext(Dispatchers.IO) {
        runCatching {
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

            val usb = usbCtaphid
            if (usb != null && usb.isUsbPhysicallyPresent()) {
                val encReq = AegisBridge.secureGuardEncodeUnlock(pin.toByteArray(Charsets.UTF_8)).getOrThrow()
                val resp = usb.sendVendor(0x3B, encReq)
                if (resp != null && resp.isNotEmpty()) {
                    return@runCatching getStatus().getOrThrow()
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

            val usb = usbCtaphid
            if (usb != null && usb.isUsbPhysicallyPresent()) {
                val encReq = AegisBridge.secureGuardEncodeLock().getOrThrow()
                usb.sendVendor(0x3C, encReq)
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
            isProvisioned = json.optBoolean("provisioned", false),
            isUnlocked = json.optBoolean("unlocked", false),
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

    private fun parseStatusFromDto(dto: uniffi.aegis_bridge.SecureGuardStatusDto): SecureGuardStatus {
        val stateEnum = SecureGuardStateEnum.fromWireCode(dto.state.toInt())
        val policy = SecureGuardPolicy(
            wipeOn5Failures = dto.policy.wipeOn5Failures,
            sessionDurationMs = dto.policy.sessionDurationMs.toLong(),
            inactivityTimeoutMs = dto.policy.inactivityTimeoutMs.toLong(),
            protectKeysAndAegn = dto.policy.protectKeysAndAegn,
            protectOath = dto.policy.protectOath,
            testModeNonDestructiveWipe = dto.policy.testModeNonDestructiveWipe
        )
        return SecureGuardStatus(
            state = stateEnum,
            isProvisioned = dto.isProvisioned,
            isUnlocked = dto.isUnlocked,
            failedAttempts = dto.failedAttempts.toInt(),
            remainingAttempts = dto.remainingAttempts.toInt(),
            maxAttempts = dto.maxAttempts.toInt(),
            rateLimitRemainingMs = dto.rateLimitRemainingMs.toLong(),
            sessionRemainingMs = dto.sessionRemainingMs.toLong(),
            policy = policy,
            lastWipeSimulated = dto.lastWipeSimulated,
            auditCount = dto.auditCount.toLong()
        )
    }
}
