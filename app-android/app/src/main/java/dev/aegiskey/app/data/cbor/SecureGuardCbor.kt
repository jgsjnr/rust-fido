package dev.aegiskey.app.data.cbor

import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import java.io.ByteArrayOutputStream
import java.io.OutputStream

/**
 * Codificador e decodificador CBOR nativo puro (RFC 8949) para o protocolo Secure Guard (0x3A..0x3E).
 * Totalmente desacoplado de bibliotecas JNI / JNA, garantindo imunidade total contra falhas de classe
 * ou de linking nativo (como com.sun.jna.Native).
 */
object SecureGuardCbor {

    data class TransportFrame(
        val opcode: Int?,
        val status: Int,
        val cborPayload: ByteArray
    )

    data class UnlockResult(
        val success: Boolean,
        val state: SecureGuardStateEnum,
        val failedAttempts: Int,
        val remainingAttempts: Int,
        val rateLimitRemainingMs: Long,
        val errorMessage: String?
    )

    data class ProvisionResult(
        val status: String,
        val recoveryCode: String,
        val state: SecureGuardStateEnum,
        val unlocked: Boolean
    )

    // --- ENCODING ---

    fun encodeStatusRequest(): ByteArray {
        val out = ByteArrayOutputStream()
        writeHeader(out, 5, 0) // mapa vazio {}
        return out.toByteArray()
    }

    fun encodeUnlockRequest(pin: ByteArray): ByteArray {
        val map = linkedMapOf<String, Any?>(
            "action" to "unlock",
            "pin" to pin
        )
        return encodeMap(map)
    }

    fun encodeProvisionRequest(
        pin: ByteArray,
        recoveryCode: ByteArray? = null,
        policy: SecureGuardPolicy? = null
    ): ByteArray {
        val map = linkedMapOf<String, Any?>(
            "action" to "provision",
            "pin" to pin
        )
        if (recoveryCode != null && recoveryCode.isNotEmpty()) {
            map["recovery_code"] = recoveryCode
        }
        if (policy != null) {
            map["wipe_on_5_failures"] = policy.wipeOn5Failures
            map["protect_keys_and_aegn"] = policy.protectKeysAndAegn
            map["protect_oath"] = policy.protectOath
            map["test_mode_non_destructive_wipe"] = policy.testModeNonDestructiveWipe
            map["session_duration_ms"] = policy.sessionDurationMs
            map["inactivity_timeout_ms"] = policy.inactivityTimeoutMs
        }
        return encodeMap(map)
    }

    fun encodeChangePinRequest(currentPin: ByteArray, newPin: ByteArray): ByteArray {
        val map = linkedMapOf<String, Any?>(
            "action" to "change_pin",
            "current_pin" to currentPin,
            "new_pin" to newPin
        )
        return encodeMap(map)
    }

    fun encodeRecoverRequest(recoveryCode: ByteArray, newPin: ByteArray): ByteArray {
        val map = linkedMapOf<String, Any?>(
            "action" to "recover",
            "recovery_code" to recoveryCode,
            "new_pin" to newPin
        )
        return encodeMap(map)
    }

    fun encodeLockRequest(): ByteArray {
        val out = ByteArrayOutputStream()
        writeHeader(out, 5, 0) // mapa vazio {}
        return out.toByteArray()
    }

    fun encodeConfigRequest(policy: SecureGuardPolicy, pin: ByteArray? = null): ByteArray {
        val map = linkedMapOf<String, Any?>(
            "wipe_on_5_failures" to policy.wipeOn5Failures,
            "protect_keys_and_aegn" to policy.protectKeysAndAegn,
            "protect_oath" to policy.protectOath,
            "test_mode_non_destructive_wipe" to policy.testModeNonDestructiveWipe,
            "session_duration_ms" to policy.sessionDurationMs,
            "inactivity_timeout_ms" to policy.inactivityTimeoutMs
        )
        if (pin != null && pin.isNotEmpty()) {
            map["pin"] = pin
        }
        return encodeMap(map)
    }

    fun encodeWipeRequest(scope: Int, confirmationToken: String, pin: ByteArray? = null): ByteArray {
        val map = linkedMapOf<String, Any?>(
            "scope" to (if (scope == 1) "protected_resources" else "all"),
            "confirm" to true,
            "confirmation" to confirmationToken
        )
        if (pin != null && pin.isNotEmpty()) {
            map["pin"] = pin
        }
        return encodeMap(map)
    }

    fun encodeMap(map: Map<String, Any?>): ByteArray {
        val out = ByteArrayOutputStream()
        writeHeader(out, 5, map.size.toLong())
        for ((k, v) in map) {
            writeString(out, k)
            writeValue(out, v)
        }
        return out.toByteArray()
    }

    private fun writeValue(out: OutputStream, value: Any?) {
        when (value) {
            null -> out.write(0xF6)
            is Boolean -> out.write(if (value) 0xF5 else 0xF4)
            is Byte -> if (value >= 0) writeHeader(out, 0, value.toLong()) else writeHeader(out, 1, (-1 - value).toLong())
            is Short -> if (value >= 0) writeHeader(out, 0, value.toLong()) else writeHeader(out, 1, (-1 - value).toLong())
            is Int -> if (value >= 0) writeHeader(out, 0, value.toLong()) else writeHeader(out, 1, (-1 - value).toLong())
            is Long -> if (value >= 0) writeHeader(out, 0, value) else writeHeader(out, 1, -1 - value)
            is String -> writeString(out, value)
            is ByteArray -> writeBytes(out, value)
            is List<*> -> {
                writeHeader(out, 4, value.size.toLong())
                for (item in value) writeValue(out, item)
            }
            is Map<*, *> -> {
                writeHeader(out, 5, value.size.toLong())
                for ((k, v) in value) {
                    writeValue(out, k)
                    writeValue(out, v)
                }
            }
            else -> writeString(out, value.toString())
        }
    }

    private fun writeString(out: OutputStream, s: String) {
        val b = s.toByteArray(Charsets.UTF_8)
        writeHeader(out, 3, b.size.toLong())
        out.write(b)
    }

    private fun writeBytes(out: OutputStream, b: ByteArray) {
        writeHeader(out, 2, b.size.toLong())
        out.write(b)
    }

    private fun writeHeader(out: OutputStream, majorType: Int, value: Long) {
        val major = (majorType and 0x07) shl 5
        when {
            value < 24 -> {
                out.write(major or value.toInt())
            }
            value <= 0xFF -> {
                out.write(major or 24)
                out.write(value.toInt() and 0xFF)
            }
            value <= 0xFFFF -> {
                out.write(major or 25)
                out.write((value ushr 8).toInt() and 0xFF)
                out.write(value.toInt() and 0xFF)
            }
            value <= 0xFFFFFFFFL -> {
                out.write(major or 26)
                out.write((value ushr 24).toInt() and 0xFF)
                out.write((value ushr 16).toInt() and 0xFF)
                out.write((value ushr 8).toInt() and 0xFF)
                out.write(value.toInt() and 0xFF)
            }
            else -> {
                out.write(major or 27)
                for (i in 7 downTo 0) {
                    out.write((value ushr (i * 8)).toInt() and 0xFF)
                }
            }
        }
    }

    // --- DECODING & FRAMING ---

    /**
     * Localiza e extrai o envelope de transporte:
     * Aceita [opcode, status, ...payload], [status, ...payload] ou payload CBOR direto.
     */
    fun parseTransportFrame(expectedOpcode: Int, raw: ByteArray): TransportFrame {
        if (raw.isEmpty()) return TransportFrame(null, -1, ByteArray(0))

        // Caso 1: [opcode, status, ...body]
        if (raw.size >= 2 && (raw[0].toInt() and 0xFF) == expectedOpcode) {
            val status = raw[1].toInt() and 0xFF
            val body = if (raw.size > 2) raw.copyOfRange(2, raw.size) else ByteArray(0)
            return TransportFrame(expectedOpcode, status, body)
        }

        // Caso 2: [status, ...body] onde body começa com CBOR map (0xA0..0xBF ou 0xB8/0xB9)
        if (raw.size >= 2) {
            val b1 = raw[1].toInt() and 0xFF
            if ((b1 and 0xE0) == 0xA0 || b1 == 0xB8 || b1 == 0xB9) {
                val status = raw[0].toInt() and 0xFF
                val body = raw.copyOfRange(1, raw.size)
                return TransportFrame(null, status, body)
            }
        }

        // Caso 3: body CBOR map direto
        val b0 = raw[0].toInt() and 0xFF
        if ((b0 and 0xE0) == 0xA0 || b0 == 0xB8 || b0 == 0xB9) {
            return TransportFrame(null, 0x00, raw)
        }

        // Caso 4: varredura do primeiro marcador CBOR map no buffer
        for (i in raw.indices) {
            val b = raw[i].toInt() and 0xFF
            if ((b and 0xE0) == 0xA0 || b == 0xB8 || b == 0xB9) {
                val st = if (i > 0) (raw[i - 1].toInt() and 0xFF) else 0x00
                val op = if (i > 1 && (raw[0].toInt() and 0xFF) == expectedOpcode) expectedOpcode else null
                return TransportFrame(op, st, raw.copyOfRange(i, raw.size))
            }
        }

        return TransportFrame(null, if (raw.isNotEmpty()) raw[0].toInt() and 0xFF else -1, raw)
    }

    /**
     * Decodifica qualquer dado CBOR básico para tipos Kotlin padrão.
     */
    fun decode(bytes: ByteArray): Any? {
        if (bytes.isEmpty()) return null
        return try {
            CborReader(bytes).readValue()
        } catch (_: Throwable) {
            null
        }
    }

    fun parseStatus(cborBytes: ByteArray): SecureGuardStatus? {
        val decoded = decode(cborBytes) as? Map<*, *> ?: return null
        val stateCode = (decoded["state"] as? Number)?.toInt() ?: 0
        val stateName = decoded["state_name"] as? String ?: "Unprovisioned"
        val stateEnum = SecureGuardStateEnum.fromString(stateName).let {
            if (it == SecureGuardStateEnum.DEVICE_UNAVAILABLE) SecureGuardStateEnum.fromWireCode(stateCode) else it
        }

        val policy = SecureGuardPolicy(
            wipeOn5Failures = decoded["wipe_on_5_failures"] as? Boolean ?: false,
            sessionDurationMs = (decoded["session_duration_ms"] as? Number)?.toLong() ?: 300_000L,
            inactivityTimeoutMs = (decoded["inactivity_timeout_ms"] as? Number)?.toLong() ?: 300_000L,
            protectKeysAndAegn = decoded["protect_keys_and_aegn"] as? Boolean ?: true,
            protectOath = decoded["protect_oath"] as? Boolean ?: false,
            testModeNonDestructiveWipe = decoded["test_mode_non_destructive_wipe"] as? Boolean ?: false
        )

        val rawDeviceMac = decoded["device_ble_mac"]
        val deviceMacBytes = when (rawDeviceMac) {
            is ByteArray -> rawDeviceMac
            is List<*> -> rawDeviceMac.mapNotNull { (it as? Number)?.toByte() }.toByteArray()
            else -> null
        }
        val deviceBleMac = deviceMacBytes?.takeIf { it.size == 6 }?.joinToString(":") { "%02X".format(it) }
        val deviceBleName = decoded["device_ble_name"] as? String

        return SecureGuardStatus(
            state = stateEnum,
            isProvisioned = decoded["provisioned"] as? Boolean ?: (stateEnum != SecureGuardStateEnum.UNPROVISIONED),
            isUnlocked = decoded["unlocked"] as? Boolean ?: (stateEnum == SecureGuardStateEnum.UNLOCKED),
            failedAttempts = (decoded["failed_attempts"] as? Number)?.toInt() ?: 0,
            remainingAttempts = (decoded["remaining_attempts"] as? Number)?.toInt() ?: 5,
            maxAttempts = (decoded["max_attempts"] as? Number)?.toInt() ?: 5,
            rateLimitRemainingMs = (decoded["rate_limit_remaining_ms"] as? Number)?.toLong() ?: 0L,
            sessionRemainingMs = (decoded["session_remaining_ms"] as? Number)?.toLong() ?: 0L,
            policy = policy,
            lastWipeSimulated = decoded["last_wipe_simulated"] as? Boolean ?: false,
            auditCount = (decoded["audit_count"] as? Number)?.toLong() ?: 0L,
            lastGeneratedRecoveryCode = decoded["recovery_code"] as? String ?: decoded["new_recovery_code"] as? String,
            deviceBleMac = deviceBleMac,
            deviceBleName = deviceBleName,
            // Contrato 0x3A `bench_active: bool` (firmware bench policy);
            // ausente = false. Puro read-only, sem efeito de lock/wipe.
            benchActive = decoded["bench_active"] as? Boolean ?: false
        )
    }

    fun parseUnlockResult(statusByte: Int, cborBytes: ByteArray): UnlockResult {
        val decoded = decode(cborBytes) as? Map<*, *>
        val success = (statusByte == 0x00) && (decoded?.get("success") as? Boolean ?: true)
        val stateCode = (decoded?.get("state") as? Number)?.toInt() ?: (if (success) 2 else 1)
        val stateName = decoded?.get("state_name") as? String ?: (if (success) "Unlocked" else "Locked")
        val stateEnum = SecureGuardStateEnum.fromString(stateName).let {
            if (it == SecureGuardStateEnum.DEVICE_UNAVAILABLE) SecureGuardStateEnum.fromWireCode(stateCode) else it
        }

        val failedAttempts = (decoded?.get("failed_attempts") as? Number)?.toInt() ?: 0
        val remainingAttempts = (decoded?.get("remaining_attempts") as? Number)?.toInt() ?: 5
        val rateLimitRemainingMs = (decoded?.get("rate_limit_remaining_ms") as? Number)?.toLong() ?: 0L
        val errorMsg = decoded?.get("error") as? String

        return UnlockResult(
            success = success,
            state = stateEnum,
            failedAttempts = failedAttempts,
            remainingAttempts = remainingAttempts,
            rateLimitRemainingMs = rateLimitRemainingMs,
            errorMessage = errorMsg
        )
    }

    fun parseProvisionResult(cborBytes: ByteArray): ProvisionResult? {
        val decoded = decode(cborBytes) as? Map<*, *> ?: return null
        val status = decoded["status"] as? String ?: "provisioned"
        val recoveryCode = decoded["recovery_code"] as? String ?: ""
        val stateCode = (decoded["state"] as? Number)?.toInt() ?: 1
        val unlocked = decoded["unlocked"] as? Boolean ?: false

        return ProvisionResult(
            status = status,
            recoveryCode = recoveryCode,
            state = SecureGuardStateEnum.fromWireCode(stateCode),
            unlocked = unlocked
        )
    }

    private class CborReader(private val bytes: ByteArray, private var offset: Int = 0) {
        fun hasRemaining(): Boolean = offset < bytes.size

        fun readValue(): Any? {
            if (!hasRemaining()) return null
            val initialByte = bytes[offset++].toInt() and 0xFF
            val majorType = initialByte ushr 5
            val additionalInfo = initialByte and 0x1F

            val lengthOrValue: Long = when {
                additionalInfo < 24 -> additionalInfo.toLong()
                additionalInfo == 24 -> {
                    if (offset >= bytes.size) return null
                    bytes[offset++].toLong() and 0xFF
                }
                additionalInfo == 25 -> {
                    if (offset + 1 >= bytes.size) return null
                    val b0 = bytes[offset++].toLong() and 0xFF
                    val b1 = bytes[offset++].toLong() and 0xFF
                    (b0 shl 8) or b1
                }
                additionalInfo == 26 -> {
                    if (offset + 3 >= bytes.size) return null
                    var res = 0L
                    for (i in 0..3) {
                        res = (res shl 8) or (bytes[offset++].toLong() and 0xFF)
                    }
                    res
                }
                additionalInfo == 27 -> {
                    if (offset + 7 >= bytes.size) return null
                    var res = 0L
                    for (i in 0..7) {
                        res = (res shl 8) or (bytes[offset++].toLong() and 0xFF)
                    }
                    res
                }
                else -> 0L
            }

            return when (majorType) {
                0 -> lengthOrValue
                1 -> -1 - lengthOrValue
                2 -> {
                    val len = lengthOrValue.toInt().coerceAtMost(bytes.size - offset)
                    val slice = bytes.copyOfRange(offset, offset + len)
                    offset += len
                    slice
                }
                3 -> {
                    val len = lengthOrValue.toInt().coerceAtMost(bytes.size - offset)
                    val str = String(bytes, offset, len, Charsets.UTF_8)
                    offset += len
                    str
                }
                4 -> {
                    val count = lengthOrValue.toInt()
                    val list = ArrayList<Any?>(count)
                    for (i in 0 until count) {
                        if (!hasRemaining()) break
                        list.add(readValue())
                    }
                    list
                }
                5 -> {
                    val count = lengthOrValue.toInt()
                    val map = LinkedHashMap<String, Any?>()
                    for (i in 0 until count) {
                        if (!hasRemaining()) break
                        val key = readValue()?.toString() ?: "key_$i"
                        val value = readValue()
                        map[key] = value
                    }
                    map
                }
                7 -> {
                    when (additionalInfo) {
                        20 -> false
                        21 -> true
                        22 -> null
                        else -> null
                    }
                }
                else -> null
            }
        }
    }
}
