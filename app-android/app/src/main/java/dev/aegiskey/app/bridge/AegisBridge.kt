package dev.aegiskey.app.bridge

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.net.URLDecoder
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Facade over the UniFFI-generated bindings for `aegis_bridge` (crates/uniffi-bridge).
 *
 * Provides resilient access to native methods with 100% pure Kotlin/JVM fallbacks
 * if the native library or JNA runtime is unavailable (e.g. missing JNA AAR on Android,
 * symbol mismatch, LinkageError, NoClassDefFoundError, or UnsatisfiedLinkError).
 *
 * Contract: only envelopes (AEGN), TOTP codes and account labels cross JNI.
 * Keys are transient caller buffers, zeroized after use. This facade never
 * retains key material, secrets or codes beyond the returning call frame.
 * Failure messages are capped and carry no payloads (never secrets/PII).
 */
object AegisBridge {
    /** Display-only TOTP entry (mirrors the `OathCode` UDL record). */
    data class OathEntry(val account: String, val code: String, val remainingSeconds: Int)

    /** Parsed OTP input (URI or raw Base32 secret). */
    data class ParsedOtpInput(
        val issuer: String,
        val accountName: String,
        val secretBase32: String,
        val digits: Int,
        val period: Int,
        val isHotp: Boolean = false,
    ) {
        val periodSeconds: Int get() = period
    }

    private const val OP_PING = 0x81
    private const val OP_MSG = 0x83
    private const val OP_CANCEL = 0xBE
    private const val BIND_MGMT_OP_MIN = 0x28
    private const val BIND_MGMT_OP_MAX = 0x2D
    private const val OTA_OP_MIN = 0x30
    private const val OTA_OP_MAX = 0x34
    private const val MAX_FRAGMENT_BYTES = 244
    private const val CONTROL_POINT_LENGTH = 512

    private val ENVELOPE_MAGIC = byteArrayOf(0x41, 0x45, 0x47, 0x4E) // "AEGN"
    private const val ENVELOPE_VERSION: Byte = 0x01
    private const val MIN_ENVELOPE_LEN = 33
    private const val MAX_PLAINTEXT_BYTES = 4096
    private const val MAX_ENVELOPE_BYTES = 4129

    val nativeLoaded: Boolean =
        try {
            System.loadLibrary("aegis_bridge")
            true
        } catch (_: Throwable) {
            false
        }

    private fun sanitize(e: Throwable): IllegalStateException =
        IllegalStateException(e.message?.take(64) ?: "bridge error")

    /** Frozen BLE constants from Rust (mirrors docs/ble-protocol.md). */
    fun constants(): Result<uniffi.aegis_bridge.BleInfo> {
        if (nativeLoaded) {
            try {
                return Result.success(uniffi.aegis_bridge.bleConstants())
            } catch (_: Throwable) {}
        }
        return Result.success(
            uniffi.aegis_bridge.BleInfo(
                serviceUuid = 0xFFFDu,
                controlUuid = 0xFFF1u,
                statusUuid = 0xFFF2u,
                lenUuid = 0xFFF3u,
                revisionUuid = 0xFFF4u,
                gattRevision = 0x01u,
                opPing = 0x81u,
                opMsg = 0x83u,
                opCancel = 0xBEu,
                maxFragmentBytes = 244u,
                controlPointLength = 512u
            )
        )
    }

    /** FFF1 fragments for [opcode] + [payload] (first `[op,hi,lo,..]`, then `[seq,..]`). */
    fun splitFragments(opcode: Int, payload: ByteArray): Result<List<ByteArray>> {
        if (nativeLoaded) {
            try {
                val res = uniffi.aegis_bridge.bleSplitFragments(
                    opcode.toUByte(),
                    payload.map { it.toUByte() }
                ).map { frag -> frag.map { it.toByte() }.toByteArray() }
                return Result.success(res)
            } catch (t: Throwable) {
                if (t is uniffi.aegis_bridge.BridgeException) {
                    return Result.failure(sanitize(t))
                }
            }
        }
        return runCatching {
            splitFragmentsFallback(opcode, payload)
        }.recoverCatching { throw sanitize(it) }
    }

    /** Validates a POST /ctap AEGN envelope; returns ciphertext length. */
    fun envelopeValidate(envelope: ByteArray): Result<Int> {
        if (nativeLoaded) {
            try {
                return Result.success(uniffi.aegis_bridge.envelopeValidate(envelope.map { it.toUByte() }).toInt())
            } catch (t: Throwable) {
                if (t is uniffi.aegis_bridge.BridgeException) {
                    return Result.failure(sanitize(t))
                }
            }
        }
        return runCatching {
            envelopeValidateFallback(envelope)
        }.recoverCatching { throw sanitize(it) }
    }

    /** Parses a GET /oath/code JSON body into display-only fields. */
    fun oathParse(json: String): Result<OathEntry> {
        if (nativeLoaded) {
            try {
                val parsed = uniffi.aegis_bridge.oathParseResponse(json)
                return Result.success(OathEntry(parsed.account, parsed.code, parsed.remainingSeconds.toInt()))
            } catch (t: Throwable) {
                if (t is uniffi.aegis_bridge.BridgeException) {
                    return Result.failure(sanitize(t))
                }
            }
        }
        return runCatching {
            oathParseFallback(json)
        }.recoverCatching { throw sanitize(it) }
    }

    /** Derives the app-lock verifier via PBKDF2 (fail closed). */
    fun appLockDerive(password: ByteArray, salt: ByteArray): Result<ByteArray> {
        if (nativeLoaded) {
            try {
                val res = uniffi.aegis_bridge.appLockDerive(
                    password.map { it.toUByte() },
                    salt.map { it.toUByte() }
                ).map { it.toByte() }.toByteArray()
                return Result.success(res)
            } catch (t: Throwable) {
                if (t is uniffi.aegis_bridge.BridgeException) {
                    return Result.failure(sanitize(t))
                }
            }
        }
        return runCatching {
            appLockDeriveFallback(password, salt)
        }.recoverCatching { throw sanitize(it) }
    }

    /** Local 6-8 digit check (device JSON is re-validated in Rust). */
    fun codeValid(code: String): Boolean =
        code.length in 6..8 && code.all { it.isDigit() }

    /** Seconds left in the 30s window (mirrors firmware `totp_code_for_secret`). */
    fun remainingSeconds(unixSeconds: Long): Int =
        (30 - (unixSeconds % 30)).toInt()

    /** Local WPA2 hint (device enforces bounds + UP+PIN again). */
    fun wifiPasswordValid(password: String): Boolean =
        password.length in 8..63 && password.all { it.code < 128 }

    /** Extracts `account` from a `/oath/code?account=` path (mirrors firmware). */
    fun accountFromPath(path: String): String? =
        path.substringAfter('?', "").split('&')
            .firstOrNull { it.startsWith("account=") }
            ?.removePrefix("account=")?.takeIf { it.isNotEmpty() }

    /**
     * Formata um código numérico de 6 a 8 dígitos para exibição amigável (ex: "123456" -> "123 456", "12345678" -> "1234 5678").
     * Usa o bridge nativo UniFFI se carregado, com fallback seguro e puro em Kotlin.
     */
    fun formatTotpDisplay(code: String): String {
        if (nativeLoaded) {
            try {
                return uniffi.aegis_bridge.totpFormatDisplay(code)
            } catch (_: Throwable) {}
        }
        val clean = code.filter { !it.isWhitespace() }
        return if (clean.length in 6..8 && clean.all { it.isDigit() }) {
            val mid = clean.length / 2
            clean.substring(0, mid) + " " + clean.substring(mid)
        } else {
            code
        }
    }

    /**
     * Faz parse seguro tanto de uma URI `otpauth://totp/...` quanto de um segredo Base32 puro
     * digitado/colado pelo usuário, limpando espaços e convertendo para maiúsculas.
     * Retorna `ParsedOtpInput` ou `null` se a entrada for inválida.
     * Usa o bridge nativo UniFFI se carregado, com fallback seguro e puro em Kotlin.
     */
    fun parseOtpInput(raw: String): ParsedOtpInput? {
        val isHotp = raw.trim().startsWith("otpauth://hotp", ignoreCase = true)
        if (nativeLoaded) {
            try {
                val p = uniffi.aegis_bridge.otpauthExtractLabelAndSecret(raw)
                return ParsedOtpInput(
                    issuer = p.issuer,
                    accountName = p.accountName,
                    secretBase32 = p.secretBase32,
                    digits = p.digits.toInt(),
                    period = p.period.toInt(),
                    isHotp = isHotp
                )
            } catch (_: Throwable) {}
        }
        return parseOtpInputFallback(raw)
    }

    private fun parseOtpInputFallback(raw: String): ParsedOtpInput? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null

        fun cleanBase32(s: String): String? {
            val clean = s.filter { !it.isWhitespace() && it != '-' }.uppercase()
            val unpadded = clean.trimEnd('=')
            if (unpadded.isEmpty()) return null
            val valid = unpadded.all { it in 'A'..'Z' || it in '2'..'7' }
            return if (valid) unpadded else null
        }

        if (trimmed.startsWith("otpauth://", ignoreCase = true)) {
            val rest = trimmed.substring(10)
            val slashIdx = rest.indexOf('/')
            if (slashIdx < 0) return null
            val type = rest.substring(0, slashIdx).trim().lowercase()
            if (type != "totp" && type != "hotp") return null

            val afterType = rest.substring(slashIdx + 1).trimStart('/')
            val qIdx = afterType.indexOf('?')
            val rawLabel = if (qIdx >= 0) afterType.substring(0, qIdx) else afterType
            val queryStr = if (qIdx >= 0) afterType.substring(qIdx + 1) else ""

            val decodedLabel = runCatching { URLDecoder.decode(rawLabel, "UTF-8") }.getOrDefault(rawLabel)
            val colonIdx = decodedLabel.indexOf(':')
            val (lblIssuer, lblAccount) = if (colonIdx >= 0) {
                decodedLabel.substring(0, colonIdx).trim() to decodedLabel.substring(colonIdx + 1).trim()
            } else {
                "" to decodedLabel.trim()
            }

            var queryIssuer = ""
            var rawSecret = ""
            var digits = 6
            var period = 30

            for (pair in queryStr.split('&')) {
                if (pair.isEmpty()) continue
                val eqIdx = pair.indexOf('=')
                val key = (if (eqIdx >= 0) pair.substring(0, eqIdx) else pair).trim().lowercase()
                val value = if (eqIdx >= 0) pair.substring(eqIdx + 1).trim() else ""
                val decodedVal = runCatching { URLDecoder.decode(value, "UTF-8") }.getOrDefault(value)
                when (key) {
                    "secret" -> rawSecret = decodedVal
                    "issuer" -> queryIssuer = decodedVal.trim()
                    "digits" -> decodedVal.toIntOrNull()?.let { if (it in 6..8) digits = it }
                    "period" -> decodedVal.toIntOrNull()?.let { if (it > 0) period = it }
                }
            }

            val secretBase32 = cleanBase32(rawSecret) ?: return null
            val issuer = if (queryIssuer.isNotEmpty()) queryIssuer else lblIssuer
            val isHotp = type == "hotp"
            return ParsedOtpInput(
                issuer = issuer,
                accountName = lblAccount,
                secretBase32 = secretBase32,
                digits = digits,
                period = period,
                isHotp = isHotp
            )
        } else {
            val secretBase32 = cleanBase32(trimmed) ?: return null
            return ParsedOtpInput(
                issuer = "",
                accountName = "",
                secretBase32 = secretBase32,
                digits = 6,
                period = 30
            )
        }
    }

    /**
     * Sela [plaintext] num envelope AEGN (chave/nonce transitorios do chamador;
     * o app deve passar nonce fresco a cada selagem). Falhas sem payload
     * (nunca segredos/PII).
     */
    fun envelopeSeal(key: ByteArray, plaintext: ByteArray, aad: ByteArray, nonce: ByteArray): Result<ByteArray> {
        if (nativeLoaded) {
            try {
                val res = uniffi.aegis_bridge.envelopeSeal(
                    key.map { it.toUByte() },
                    plaintext.map { it.toUByte() },
                    aad.map { it.toUByte() },
                    nonce.map { it.toUByte() },
                ).map { it.toByte() }.toByteArray()
                return Result.success(res)
            } catch (t: Throwable) {
                if (t is uniffi.aegis_bridge.BridgeException) {
                    return Result.failure(sanitize(t))
                }
            }
        }
        return runCatching {
            envelopeSealFallback(key, plaintext, aad, nonce)
        }.recoverCatching { throw sanitize(it) }
    }

    /** Zera buffers transitorios (chamar em finally apos cada send). */
    fun wipe(vararg buffers: ByteArray) {
        for (b in buffers) b.fill(0)
    }

    /**
     * Deriva endereco da carteira a partir de pubkey PUBLICA (computacao
     * local, sem segredos): "bitcoin"/"ethereum"/"solana" + hex da pubkey
     * (33B comprimida / 64B x||y / 32B Ed25519). O device nunca e perguntado.
     */
    fun walletAddress(network: String, pubkeyHex: String): Result<String> {
        if (nativeLoaded) {
            try {
                return Result.success(uniffi.aegis_bridge.walletAddress(network, pubkeyHex))
            } catch (t: Throwable) {
                if (t is uniffi.aegis_bridge.BridgeException) {
                    return Result.failure(sanitize(t))
                }
            }
        }
        return runCatching {
            walletAddressFallback(network, pubkeyHex)
        }.recoverCatching { throw sanitize(it) }
    }

    /**
     * Abre um envelope AEGN com chave transitoria (par do envelopeSeal;
     * base do restore A5). A chave e zerada antes do retorno;
     * este facade nunca retem segredo alem do frame: o chamador deve usar
     * wipe nos buffers em finally, como no selo.
     */
    fun envelopeOpen(key: ByteArray, envelope: ByteArray, aad: ByteArray): Result<ByteArray> {
        if (nativeLoaded) {
            try {
                val res = uniffi.aegis_bridge.envelopeOpen(
                    key.map { it.toUByte() },
                    envelope.map { it.toUByte() },
                    aad.map { it.toUByte() },
                ).map { it.toByte() }.toByteArray()
                return Result.success(res)
            } catch (t: Throwable) {
                if (t is uniffi.aegis_bridge.BridgeException) {
                    return Result.failure(sanitize(t))
                }
            }
        }
        return runCatching {
            envelopeOpenFallback(key, envelope, aad)
        }.recoverCatching { throw sanitize(it) }
    }

    @Volatile
    private var cachedMaxPlaintext: Int? = null

    fun maxPlaintextBytes(): Result<Int> {
        cachedMaxPlaintext?.let { return Result.success(it) }
        if (nativeLoaded) {
            try {
                val v = probePlaintextCeiling()
                cachedMaxPlaintext = v
                return Result.success(v)
            } catch (_: Throwable) {}
        }
        cachedMaxPlaintext = MAX_PLAINTEXT_BYTES
        return Result.success(MAX_PLAINTEXT_BYTES)
    }

    private fun probePlaintextCeiling(): Int {
        val header = byteArrayOf(0x41, 0x45, 0x47, 0x4E, 0x01) + ByteArray(12) { 0x11 }
        fun validates(total: Int): Boolean {
            if (total < header.size) return false
            val probe = header + ByteArray(total - header.size)
            return try {
                uniffi.aegis_bridge.envelopeValidate(probe.map { it.toUByte() })
                true
            } catch (_: Throwable) {
                false
            }
        }
        var floor = -1
        for (n in header.size..header.size + 256) {
            if (validates(n)) {
                floor = n
                break
            }
        }
        require(floor > header.size) { "bridge ceiling probe has no floor" }
        var ok = floor
        var step = 1
        var capped = ok + step
        while (true) {
            val next = ok + step
            if (next < 0 || next > SEARCH_GUARD_BYTES) break
            if (!validates(next)) {
                capped = next
                break
            }
            ok = next
            step *= 2
        }
        require(!validates(capped) && validates(ok)) { "bridge ceiling probe inconclusive" }
        while (capped - ok > 1) {
            val mid = ok + (capped - ok) / 2
            if (validates(mid)) ok = mid else capped = mid
        }
        return ok - floor
    }

    private const val SEARCH_GUARD_BYTES = 1048576

    fun secureGuardParseStatus(payload: ByteArray): Result<uniffi.aegis_bridge.SecureGuardStatusDto> {
        if (nativeLoaded) {
            try {
                return Result.success(uniffi.aegis_bridge.secureGuardParseStatus(payload.map { it.toUByte() }))
            } catch (_: Throwable) {}
        }
        return runCatching {
            secureGuardParseStatusFallback(payload)
        }.recoverCatching { throw sanitize(it) }
    }

    fun secureGuardEncodeProvision(
        pin: ByteArray,
        recoveryCode: ByteArray = ByteArray(0),
        wipeOn5Failures: Boolean = false,
        testMode: Boolean = false
    ): Result<ByteArray> {
        if (nativeLoaded) {
            try {
                val res = uniffi.aegis_bridge.secureGuardEncodeProvision(
                    pin.map { it.toUByte() },
                    recoveryCode.map { it.toUByte() },
                    wipeOn5Failures,
                    testMode
                ).map { it.toByte() }.toByteArray()
                return Result.success(res)
            } catch (_: Throwable) {}
        }
        return runCatching {
            secureGuardEncodeProvisionFallback(pin, recoveryCode, wipeOn5Failures, testMode)
        }.recoverCatching { throw sanitize(it) }
    }

    fun secureGuardEncodeUnlock(pin: ByteArray): Result<ByteArray> {
        if (nativeLoaded) {
            try {
                val res = uniffi.aegis_bridge.secureGuardEncodeUnlock(pin.map { it.toUByte() })
                    .map { it.toByte() }.toByteArray()
                return Result.success(res)
            } catch (_: Throwable) {}
        }
        return runCatching {
            secureGuardEncodeUnlockFallback(pin)
        }.recoverCatching { throw sanitize(it) }
    }

    fun secureGuardEncodeChangePin(currentPin: ByteArray, newPin: ByteArray): Result<ByteArray> {
        if (nativeLoaded) {
            try {
                val res = uniffi.aegis_bridge.secureGuardEncodeChangePin(
                    currentPin.map { it.toUByte() },
                    newPin.map { it.toUByte() }
                ).map { it.toByte() }.toByteArray()
                return Result.success(res)
            } catch (_: Throwable) {}
        }
        return runCatching {
            secureGuardEncodeChangePinFallback(currentPin, newPin)
        }.recoverCatching { throw sanitize(it) }
    }

    fun secureGuardEncodeRecover(recoveryCode: ByteArray, newPin: ByteArray): Result<ByteArray> {
        if (nativeLoaded) {
            try {
                val res = uniffi.aegis_bridge.secureGuardEncodeRecover(
                    recoveryCode.map { it.toUByte() },
                    newPin.map { it.toUByte() }
                ).map { it.toByte() }.toByteArray()
                return Result.success(res)
            } catch (_: Throwable) {}
        }
        return runCatching {
            secureGuardEncodeRecoverFallback(recoveryCode, newPin)
        }.recoverCatching { throw sanitize(it) }
    }

    fun secureGuardEncodeLock(): Result<ByteArray> {
        if (nativeLoaded) {
            try {
                val res = uniffi.aegis_bridge.secureGuardEncodeLock().map { it.toByte() }.toByteArray()
                return Result.success(res)
            } catch (_: Throwable) {}
        }
        return runCatching {
            secureGuardEncodeLockFallback()
        }.recoverCatching { throw sanitize(it) }
    }

    fun secureGuardEncodeConfig(policy: uniffi.aegis_bridge.SecureGuardPolicyDto): Result<ByteArray> {
        if (nativeLoaded) {
            try {
                val res = uniffi.aegis_bridge.secureGuardEncodeConfig(policy).map { it.toByte() }.toByteArray()
                return Result.success(res)
            } catch (_: Throwable) {}
        }
        return runCatching {
            secureGuardEncodeConfigFallback(policy)
        }.recoverCatching { throw sanitize(it) }
    }

    fun secureGuardEncodeWipe(scope: Int, confirmToken: String): Result<ByteArray> {
        if (nativeLoaded) {
            try {
                val res = uniffi.aegis_bridge.secureGuardEncodeWipe(scope.toUByte(), confirmToken).map { it.toByte() }.toByteArray()
                return Result.success(res)
            } catch (_: Throwable) {}
        }
        return runCatching {
            secureGuardEncodeWipeFallback(scope, confirmToken)
        }.recoverCatching { throw sanitize(it) }
    }

    // =========================================================================
    // Pure Kotlin / JVM Fallback Implementations
    // =========================================================================

    private fun isBleFragmentOpcode(opcode: Int): Boolean {
        val op = opcode and 0xFF
        return op == OP_PING ||
               op == OP_MSG ||
               (op in BIND_MGMT_OP_MIN..BIND_MGMT_OP_MAX) ||
               (op in OTA_OP_MIN..OTA_OP_MAX)
    }

    fun splitFragmentsFallback(opcode: Int, payload: ByteArray): List<ByteArray> {
        val op = opcode and 0xFF
        if (!isBleFragmentOpcode(op)) {
            throw IllegalStateException("invalid opcode")
        }
        if (payload.size > CONTROL_POINT_LENGTH) {
            throw IllegalStateException("overflow control-point")
        }
        val total = payload.size
        val firstCapacity = minOf(MAX_FRAGMENT_BYTES - 3, total)
        val out = ArrayList<ByteArray>()
        val first = ByteArray(3 + firstCapacity)
        first[0] = op.toByte()
        first[1] = ((total ushr 8) and 0xFF).toByte()
        first[2] = (total and 0xFF).toByte()
        System.arraycopy(payload, 0, first, 3, firstCapacity)
        out.add(first)

        var offset = firstCapacity
        var seq = 0
        while (offset < total) {
            val chunk = minOf(MAX_FRAGMENT_BYTES - 1, total - offset)
            val frag = ByteArray(1 + chunk)
            frag[0] = (seq and 0xFF).toByte()
            System.arraycopy(payload, offset, frag, 1, chunk)
            out.add(frag)
            offset += chunk
            seq = (seq + 1) and 0xFF
        }
        return out
    }

    fun envelopeValidateFallback(envelope: ByteArray): Int {
        if (envelope.size < MIN_ENVELOPE_LEN) {
            throw IllegalStateException("invalid ctap envelope")
        }
        if (envelope.size > MAX_ENVELOPE_BYTES) {
            throw IllegalStateException("overflow control-point")
        }
        for (i in 0 until 4) {
            if (envelope[i] != ENVELOPE_MAGIC[i]) {
                throw IllegalStateException("invalid ctap envelope")
            }
        }
        if (envelope[4] != ENVELOPE_VERSION) {
            throw IllegalStateException("invalid ctap envelope")
        }
        var allZero = true
        for (i in 5 until 17) {
            if (envelope[i] != 0.toByte()) {
                allZero = false
                break
            }
        }
        if (allZero) {
            throw IllegalStateException("invalid ctap envelope")
        }
        return envelope.size - (4 + 1 + 12)
    }

    fun envelopeSealFallback(key: ByteArray, plaintext: ByteArray, aad: ByteArray, nonce: ByteArray): ByteArray {
        if (key.size != 32 || nonce.size != 12) {
            throw IllegalStateException("crypto operation failed")
        }
        if (nonce.all { it == 0.toByte() }) {
            throw IllegalStateException("crypto operation failed")
        }
        if (plaintext.size > MAX_PLAINTEXT_BYTES) {
            throw IllegalStateException("overflow control-point")
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        if (aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }
        val ct = cipher.doFinal(plaintext)
        val env = ByteArray(4 + 1 + 12 + ct.size)
        System.arraycopy(ENVELOPE_MAGIC, 0, env, 0, 4)
        env[4] = ENVELOPE_VERSION
        System.arraycopy(nonce, 0, env, 5, 12)
        System.arraycopy(ct, 0, env, 17, ct.size)
        return env
    }

    fun envelopeOpenFallback(key: ByteArray, envelope: ByteArray, aad: ByteArray): ByteArray {
        envelopeValidateFallback(envelope)
        if (key.size != 32) {
            throw IllegalStateException("crypto operation failed")
        }
        val nonce = envelope.copyOfRange(5, 17)
        val ct = envelope.copyOfRange(17, envelope.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        if (aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }
        return cipher.doFinal(ct)
    }

    fun appLockDeriveFallback(password: ByteArray, salt: ByteArray): ByteArray {
        if (password.isEmpty() || password.size > 128 || salt.size !in 16..64) {
            throw IllegalStateException("crypto operation failed")
        }
        return pbkdf2HmacSha1(password, salt, 1000, 32)
    }

    private fun pbkdf2HmacSha1(password: ByteArray, salt: ByteArray, iterations: Int, outputLen: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA1")
        val keySpec = SecretKeySpec(password, "HmacSHA1")
        val out = ByteArray(outputLen)
        var outOffset = 0
        var blockIndex = 1

        while (outOffset < outputLen) {
            mac.init(keySpec)
            mac.update(salt)
            mac.update(
                byteArrayOf(
                    ((blockIndex ushr 24) and 0xFF).toByte(),
                    ((blockIndex ushr 16) and 0xFF).toByte(),
                    ((blockIndex ushr 8) and 0xFF).toByte(),
                    (blockIndex and 0xFF).toByte()
                )
            )
            var u = mac.doFinal()
            val t = u.clone()

            for (i in 1 until iterations) {
                mac.init(keySpec)
                u = mac.doFinal(u)
                for (j in t.indices) {
                    t[j] = (t[j].toInt() xor u[j].toInt()).toByte()
                }
            }

            val needed = minOf(outputLen - outOffset, t.size)
            System.arraycopy(t, 0, out, outOffset, needed)
            outOffset += needed
            blockIndex++
        }
        return out
    }

    fun oathParseFallback(json: String): OathEntry {
        fun extractString(key: String): String? {
            val pattern = "\"$key\""
            val idx = json.indexOf(pattern)
            if (idx < 0) return null
            val colonIdx = json.indexOf(':', idx + pattern.length)
            if (colonIdx < 0) return null
            val quoteStart = json.indexOf('"', colonIdx + 1)
            if (quoteStart < 0) return null
            val sb = StringBuilder()
            var escaped = false
            var i = quoteStart + 1
            while (i < json.length) {
                val c = json[i]
                if (escaped) {
                    sb.append(c)
                    escaped = false
                } else if (c == '\\') {
                    escaped = true
                } else if (c == '"') {
                    return sb.toString()
                } else {
                    sb.append(c)
                }
                i++
            }
            return null
        }

        fun extractU32(key: String): Int? {
            val pattern = "\"$key\""
            val idx = json.indexOf(pattern)
            if (idx < 0) return null
            val colonIdx = json.indexOf(':', idx + pattern.length)
            if (colonIdx < 0) return null
            var i = colonIdx + 1
            while (i < json.length && json[i].isWhitespace()) i++
            val start = i
            while (i < json.length && json[i].isDigit()) i++
            if (start == i) return null
            return json.substring(start, i).toIntOrNull()
        }

        val account = extractString("account")?.takeIf { it.isNotEmpty() && it.length <= 128 }
            ?: throw IllegalStateException("invalid oath response")
        val code = extractString("code")?.takeIf { codeValid(it) }
            ?: throw IllegalStateException("invalid oath response")
        val remainingSeconds = extractU32("remaining_seconds")?.takeIf { it in 0..30 }
            ?: throw IllegalStateException("invalid oath response")

        return OathEntry(account, code, remainingSeconds)
    }

    fun walletAddressFallback(network: String, pubkeyHex: String): String {
        val net = network.trim().lowercase()
        val raw = decodeEvenHex(pubkeyHex) ?: throw IllegalStateException("invalid wallet address input")
        return when (net) {
            "bitcoin", "btc" -> {
                if (raw.size != 33 || (raw[0] != 0x02.toByte() && raw[0] != 0x03.toByte())) {
                    throw IllegalStateException("invalid wallet address input")
                }
                bitcoinAddress(raw)
            }
            "ethereum", "evm", "eth" -> {
                if (raw.size != 64) {
                    throw IllegalStateException("invalid wallet address input")
                }
                ethereumAddress(raw)
            }
            "solana", "sol" -> {
                if (raw.size != 32) {
                    throw IllegalStateException("invalid wallet address input")
                }
                base58Encode(raw)
            }
            else -> throw IllegalStateException("invalid wallet address input")
        }
    }

    private fun decodeEvenHex(s: String): ByteArray? {
        val clean = s.trim()
        if (clean.isEmpty() || clean.length % 2 != 0) return null
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(clean[i * 2], 16)
            val lo = Character.digit(clean[i * 2 + 1], 16)
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    private const val BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    private fun base58Encode(input: ByteArray): String {
        if (input.isEmpty()) return ""
        var zeros = 0
        while (zeros < input.size && input[zeros].toInt() == 0) {
            zeros++
        }
        var num = BigInteger(1, input)
        val sb = StringBuilder()
        val base = BigInteger.valueOf(58)
        while (num > BigInteger.ZERO) {
            val rem = num.remainder(base)
            num = num.divide(base)
            sb.append(BASE58_ALPHABET[rem.toInt()])
        }
        repeat(zeros) { sb.append('1') }
        return sb.reverse().toString()
    }

    private fun ethereumAddress(pubkey64: ByteArray): String {
        val hash = keccak256(pubkey64)
        val addressBytes = hash.copyOfRange(12, 32)
        val lowerHex = addressBytes.joinToString("") { "%02x".format(it) }
        val hash2 = keccak256(lowerHex.toByteArray(Charsets.US_ASCII))
        val sb = StringBuilder("0x")
        for (i in 0 until 40) {
            val c = lowerHex[i]
            val nibble = if (i % 2 == 0) {
                (hash2[i / 2].toInt() ushr 4) and 0x0F
            } else {
                hash2[i / 2].toInt() and 0x0F
            }
            if (c in 'a'..'f' && nibble >= 8) {
                sb.append(c.uppercaseChar())
            } else {
                sb.append(c)
            }
        }
        return sb.toString()
    }

    private fun keccak256(input: ByteArray): ByteArray {
        val state = LongArray(25)
        val rate = 136
        var offset = 0
        while (offset < input.size) {
            val blockLen = minOf(rate, input.size - offset)
            for (i in 0 until blockLen) {
                val lane = i / 8
                val byteInLane = i % 8
                state[lane] = state[lane] xor ((input[offset + i].toLong() and 0xFFL) shl (byteInLane * 8))
            }
            offset += blockLen
            if (blockLen == rate) {
                keccakF1600(state)
            }
        }
        val rem = input.size % rate
        val pLane = rem / 8
        val pByte = rem % 8
        state[pLane] = state[pLane] xor (0x01L shl (pByte * 8))
        state[(rate - 1) / 8] = state[(rate - 1) / 8] xor (0x80L shl 56)
        keccakF1600(state)

        val out = ByteArray(32)
        for (i in 0 until 32) {
            val lane = i / 8
            val byteInLane = i % 8
            out[i] = ((state[lane] ushr (byteInLane * 8)) and 0xFFL).toByte()
        }
        return out
    }

    private val KECCAK_ROUNDS = longArrayOf(
        0x0000000000000001L, 0x0000000000008082L, -0x7FFFFFFFFFFF7F78L, -0x7FFFFFFFFF7F8000L,
        0x000000000000808bL, 0x0000000080000001L, -0x7FFFFFFF7FFF7F7FL, -0x7FFFFFFFFFFF7F77L,
        0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, -0x7FFFFFFFFFFFFFFEL, -0x7FFFFFFFFFFF7F75L, -0x7FFFFFFFFFFF7F79L,
        -0x7FFFFFFFFFFF7F70L, -0x7FFFFFFFFFFFFFF0L, -0x7FFFFFFFFFFF7FEEL, -0x7FFFFFFF7FFFFFE0L,
        -0x7FFFFFFF7FFF7F7FL, -0x7FFFFFFFFFFF7F80L, 0x0000000080000001L, -0x7FFFFFFF7FFF7F78L
    )

    private val ROT_SHIFTS = intArrayOf(
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
    )

    private val ROT_INDEX = intArrayOf(
        0, 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    )

    private fun keccakF1600(a: LongArray) {
        val c = LongArray(5)
        val d = LongArray(5)
        val b = LongArray(25)
        for (round in 0 until 24) {
            for (x in 0 until 5) {
                c[x] = a[x] xor a[x + 5] xor a[x + 10] xor a[x + 15] xor a[x + 20]
            }
            for (x in 0 until 5) {
                d[x] = c[(x + 4) % 5] xor java.lang.Long.rotateLeft(c[(x + 1) % 5], 1)
            }
            for (i in 0 until 25) {
                a[i] = a[i] xor d[i % 5]
            }
            for (i in 0 until 25) {
                b[ROT_INDEX[i]] = java.lang.Long.rotateLeft(a[i], ROT_SHIFTS[i])
            }
            for (y in 0 until 5) {
                val y5 = y * 5
                for (x in 0 until 5) {
                    a[y5 + x] = b[y5 + x] xor ((b[y5 + ((x + 1) % 5)].inv()) and b[y5 + ((x + 2) % 5)])
                }
            }
            a[0] = a[0] xor KECCAK_ROUNDS[round]
        }
    }

    private fun bitcoinAddress(pubkey33: ByteArray): String {
        val sha = MessageDigest.getInstance("SHA-256").digest(pubkey33)
        val r160 = ripemd160(sha)
        return bech32SegwitV0("bc", r160)
    }

    private fun ripemd160(msg: ByteArray): ByteArray {
        val h = intArrayOf(
            0x67452301, -0x10325477, -0x67452302, 0x10325476, -0x3c2d1e10
        )
        val bitLen = msg.size.toLong() * 8L
        val rem = msg.size % 64
        val padLen = if (rem < 56) 56 - rem else 120 - rem
        val padded = ByteArray(msg.size + padLen + 8)
        System.arraycopy(msg, 0, padded, 0, msg.size)
        padded[msg.size] = 0x80.toByte()
        for (i in 0 until 8) {
            padded[padded.size - 8 + i] = ((bitLen ushr (i * 8)) and 0xFFL).toByte()
        }

        val rl = intArrayOf(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
            4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
        )
        val rr = intArrayOf(
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
            12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
        )
        val sl = intArrayOf(
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
            9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
        )
        val sr = intArrayOf(
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
            8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
        )

        val x = IntArray(16)
        var chunk = 0
        while (chunk < padded.size) {
            for (i in 0 until 16) {
                val p = chunk + i * 4
                x[i] = (padded[p].toInt() and 0xFF) or
                       ((padded[p + 1].toInt() and 0xFF) shl 8) or
                       ((padded[p + 2].toInt() and 0xFF) shl 16) or
                       ((padded[p + 3].toInt() and 0xFF) shl 24)
            }
            var al = h[0]; var bl = h[1]; var cl = h[2]; var dl = h[3]; var el = h[4]
            var ar = h[0]; var br = h[1]; var cr = h[2]; var dr = h[3]; var er = h[4]

            for (j in 0 until 80) {
                val tl = Integer.rotateLeft(al + fR160(j, bl, cl, dl) + x[rl[j]] + klR160(j), sl[j]) + el
                al = el; el = dl; dl = Integer.rotateLeft(cl, 10); cl = bl; bl = tl

                val tr = Integer.rotateLeft(ar + fR160(79 - j, br, cr, dr) + x[rr[j]] + krR160(j), sr[j]) + er
                ar = er; er = dr; dr = Integer.rotateLeft(cr, 10); cr = br; br = tr
            }

            val t = h[1] + cl + dr
            h[1] = h[2] + dl + er
            h[2] = h[3] + el + ar
            h[3] = h[4] + al + br
            h[4] = h[0] + bl + cr
            h[0] = t

            chunk += 64
        }

        val out = ByteArray(20)
        for (i in 0 until 5) {
            out[i * 4] = (h[i] and 0xFF).toByte()
            out[i * 4 + 1] = ((h[i] ushr 8) and 0xFF).toByte()
            out[i * 4 + 2] = ((h[i] ushr 16) and 0xFF).toByte()
            out[i * 4 + 3] = ((h[i] ushr 24) and 0xFF).toByte()
        }
        return out
    }

    private fun fR160(j: Int, x: Int, y: Int, z: Int): Int = when (j) {
        in 0..15 -> x xor y xor z
        in 16..31 -> (x and y) or (x.inv() and z)
        in 32..47 -> (x or y.inv()) xor z
        in 48..63 -> (x and z) or (y and z.inv())
        else -> x xor (y or z.inv())
    }

    private fun klR160(j: Int): Int = when (j) {
        in 0..15 -> 0
        in 16..31 -> 0x5a827999
        in 32..47 -> 0x6ed9eba1
        in 48..63 -> -0x70e44324
        else -> -0x559e51b6
    }

    private fun krR160(j: Int): Int = when (j) {
        in 0..15 -> 0x50a28be6
        in 16..31 -> 0x5c4dd124
        in 32..47 -> 0x6d703ef3
        in 48..63 -> 0x7a6d76e9
        else -> 0
    }

    private const val BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    private fun bech32Polymod(values: IntArray): Int {
        var chk = 1
        val gen = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
        for (v in values) {
            val b = chk ushr 25
            chk = ((chk and 0x1ffffff) shl 5) xor v
            for (i in 0 until 5) {
                if (((b ushr i) and 1) != 0) {
                    chk = chk xor gen[i]
                }
            }
        }
        return chk
    }

    private fun bech32HrpExpand(hrp: String): IntArray {
        val ret = IntArray(hrp.length * 2 + 1)
        for (i in hrp.indices) {
            ret[i] = hrp[i].code ushr 5
            ret[i + hrp.length + 1] = hrp[i].code and 31
        }
        ret[hrp.length] = 0
        return ret
    }

    private fun bech32SegwitV0(hrp: String, program20: ByteArray): String {
        val data = IntArray(33)
        data[0] = 0 // witness version 0
        var acc = 0
        var bits = 0
        var outIdx = 1
        for (b in program20) {
            acc = (acc shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                data[outIdx++] = (acc ushr bits) and 31
            }
        }
        if (bits > 0) {
            data[outIdx] = (acc shl (5 - bits)) and 31
        }
        val hrpExpanded = bech32HrpExpand(hrp)
        val values = IntArray(hrpExpanded.size + data.size + 6)
        System.arraycopy(hrpExpanded, 0, values, 0, hrpExpanded.size)
        System.arraycopy(data, 0, values, hrpExpanded.size, data.size)
        val polymod = bech32Polymod(values) xor 1
        val checksum = IntArray(6)
        for (i in 0 until 6) {
            checksum[i] = (polymod ushr (5 * (5 - i))) and 31
        }
        val sb = StringBuilder(hrp).append("1")
        for (d in data) sb.append(BECH32_CHARSET[d])
        for (c in checksum) sb.append(BECH32_CHARSET[c])
        return sb.toString()
    }

    private fun stateNameFromCode(code: Int): String = when (code) {
        0 -> "Unprovisioned"
        1 -> "Provisioning"
        2 -> "Locked"
        3 -> "Authenticating"
        4 -> "Unlocked"
        5 -> "RecoveryRequired"
        6 -> "RateLimited"
        7 -> "WipePending"
        8 -> "WipeInProgress"
        9 -> "ErrorLocked"
        else -> "Unknown"
    }

    fun secureGuardParseStatusFallback(payload: ByteArray): uniffi.aegis_bridge.SecureGuardStatusDto {
        if (payload.isEmpty()) {
            throw IllegalStateException("secure guard operation failed: empty payload")
        }

        // Support both CBOR map and binary short response if status prefix 0x00
        val cborOffset = when {
            payload.size > 1 && payload[0] == 0x00.toByte() && ((payload[1].toInt() and 0xE0) == 0xA0) -> 1
            (payload[0].toInt() and 0xE0) == 0xA0 -> 0
            else -> -1
        }

        if (cborOffset >= 0) {
            val map = MiniCbor.decodeMap(payload, cborOffset)
            if (map.isNotEmpty()) {
                val stateCode = ((map["state"] as? Number)?.toInt() ?: 0)
                val stateUByte = (stateCode and 0xFF).toUByte()
                val stateName = (map["state_name"] as? String) ?: stateNameFromCode(stateCode)
                val isProv = (map["provisioned"] as? Boolean) ?: false
                val isUnlk = (map["unlocked"] as? Boolean) ?: false
                val failed = (((map["failed_attempts"] as? Number)?.toInt() ?: 0) and 0xFF).toUByte()
                val rem = (((map["remaining_attempts"] as? Number)?.toInt() ?: 5) and 0xFF).toUByte()
                val maxAtt = (((map["max_attempts"] as? Number)?.toInt() ?: 5) and 0xFF).toUByte()
                val rateLim = ((map["rate_limit_remaining_ms"] as? Number)?.toLong() ?: 0L).toULong()
                val sessRem = ((map["session_remaining_ms"] as? Number)?.toLong() ?: 0L).toULong()
                val lastWipeSim = (map["last_wipe_simulated"] as? Boolean) ?: false
                val audit = ((map["audit_count"] as? Number)?.toLong() ?: 0L).toULong()

                val pol = uniffi.aegis_bridge.SecureGuardPolicyDto(
                    wipeOn5Failures = (map["wipe_on_5_failures"] as? Boolean) ?: false,
                    sessionDurationMs = ((map["session_duration_ms"] as? Number)?.toLong() ?: 300000L).toULong(),
                    inactivityTimeoutMs = ((map["inactivity_timeout_ms"] as? Number)?.toLong() ?: 300000L).toULong(),
                    protectKeysAndAegn = (map["protect_keys_and_aegn"] as? Boolean) ?: true,
                    protectOath = (map["protect_oath"] as? Boolean) ?: false,
                    testModeNonDestructiveWipe = (map["test_mode_non_destructive_wipe"] as? Boolean) ?: false
                )

                return uniffi.aegis_bridge.SecureGuardStatusDto(
                    state = stateUByte,
                    stateName = stateName,
                    isProvisioned = isProv,
                    isUnlocked = isUnlk,
                    failedAttempts = failed,
                    remainingAttempts = rem,
                    maxAttempts = maxAtt,
                    rateLimitRemainingMs = rateLim,
                    sessionRemainingMs = sessRem,
                    policy = pol,
                    lastWipeSimulated = lastWipeSim,
                    auditCount = audit
                )
            }
        }

        // Fallback binary response (e.g. [0x00, stateByte...] or [0x00])
        val stateCode = if (payload.size >= 2 && payload[0] == 0x00.toByte()) {
            payload[1].toInt() and 0xFF
        } else {
            payload[0].toInt() and 0xFF
        }
        val stateUByte = stateCode.toUByte()
        val isUnlk = (stateCode == 4)
        val isProv = (stateCode != 0)

        return uniffi.aegis_bridge.SecureGuardStatusDto(
            state = stateUByte,
            stateName = stateNameFromCode(stateCode),
            isProvisioned = isProv,
            isUnlocked = isUnlk,
            failedAttempts = 0u,
            remainingAttempts = 5u,
            maxAttempts = 5u,
            rateLimitRemainingMs = 0uL,
            sessionRemainingMs = if (isUnlk) 300000uL else 0uL,
            policy = uniffi.aegis_bridge.SecureGuardPolicyDto(
                wipeOn5Failures = false,
                sessionDurationMs = 300000uL,
                inactivityTimeoutMs = 300000uL,
                protectKeysAndAegn = true,
                protectOath = false,
                testModeNonDestructiveWipe = false
            ),
            lastWipeSimulated = false,
            auditCount = 0uL
        )
    }

    fun secureGuardEncodeUnlockFallback(pin: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        MiniCbor.encodeMapHeader(2, out)
        MiniCbor.encodeText("action", out)
        MiniCbor.encodeText("unlock", out)
        MiniCbor.encodeText("pin", out)
        MiniCbor.encodeBytes(pin, out)
        return out.toByteArray()
    }

    fun secureGuardEncodeLockFallback(): ByteArray {
        val out = ByteArrayOutputStream()
        MiniCbor.encodeMapHeader(0, out)
        return out.toByteArray()
    }

    fun secureGuardEncodeProvisionFallback(
        pin: ByteArray,
        recoveryCode: ByteArray = ByteArray(0),
        wipeOn5Failures: Boolean = false,
        testMode: Boolean = false
    ): ByteArray {
        val out = ByteArrayOutputStream()
        val hasRc = recoveryCode.isNotEmpty()
        val pairCount = 2 + (if (hasRc) 1 else 0) + 6
        MiniCbor.encodeMapHeader(pairCount, out)
        MiniCbor.encodeText("action", out)
        MiniCbor.encodeText("provision", out)
        MiniCbor.encodeText("pin", out)
        MiniCbor.encodeBytes(pin, out)
        if (hasRc) {
            MiniCbor.encodeText("recovery_code", out)
            MiniCbor.encodeBytes(recoveryCode, out)
        }
        MiniCbor.encodeText("wipe_on_5_failures", out)
        MiniCbor.encodeBool(wipeOn5Failures, out)
        MiniCbor.encodeText("protect_keys_and_aegn", out)
        MiniCbor.encodeBool(true, out)
        MiniCbor.encodeText("protect_oath", out)
        MiniCbor.encodeBool(false, out)
        MiniCbor.encodeText("test_mode_non_destructive_wipe", out)
        MiniCbor.encodeBool(testMode, out)
        MiniCbor.encodeText("session_duration_ms", out)
        MiniCbor.encodeUint(300000L, out)
        MiniCbor.encodeText("inactivity_timeout_ms", out)
        MiniCbor.encodeUint(300000L, out)
        return out.toByteArray()
    }

    fun secureGuardEncodeChangePinFallback(currentPin: ByteArray, newPin: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        MiniCbor.encodeMapHeader(3, out)
        MiniCbor.encodeText("action", out)
        MiniCbor.encodeText("change_pin", out)
        MiniCbor.encodeText("current_pin", out)
        MiniCbor.encodeBytes(currentPin, out)
        MiniCbor.encodeText("new_pin", out)
        MiniCbor.encodeBytes(newPin, out)
        return out.toByteArray()
    }

    fun secureGuardEncodeRecoverFallback(recoveryCode: ByteArray, newPin: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        MiniCbor.encodeMapHeader(3, out)
        MiniCbor.encodeText("action", out)
        MiniCbor.encodeText("recover", out)
        MiniCbor.encodeText("recovery_code", out)
        MiniCbor.encodeBytes(recoveryCode, out)
        MiniCbor.encodeText("new_pin", out)
        MiniCbor.encodeBytes(newPin, out)
        return out.toByteArray()
    }

    fun secureGuardEncodeConfigFallback(policy: uniffi.aegis_bridge.SecureGuardPolicyDto): ByteArray {
        val out = ByteArrayOutputStream()
        MiniCbor.encodeMapHeader(6, out)
        MiniCbor.encodeText("wipe_on_5_failures", out)
        MiniCbor.encodeBool(policy.wipeOn5Failures, out)
        MiniCbor.encodeText("protect_keys_and_aegn", out)
        MiniCbor.encodeBool(policy.protectKeysAndAegn, out)
        MiniCbor.encodeText("protect_oath", out)
        MiniCbor.encodeBool(policy.protectOath, out)
        MiniCbor.encodeText("test_mode_non_destructive_wipe", out)
        MiniCbor.encodeBool(policy.testModeNonDestructiveWipe, out)
        MiniCbor.encodeText("session_duration_ms", out)
        MiniCbor.encodeUint(policy.sessionDurationMs.toLong(), out)
        MiniCbor.encodeText("inactivity_timeout_ms", out)
        MiniCbor.encodeUint(policy.inactivityTimeoutMs.toLong(), out)
        return out.toByteArray()
    }

    fun secureGuardEncodeWipeFallback(scope: Int, confirmToken: String): ByteArray {
        val out = ByteArrayOutputStream()
        MiniCbor.encodeMapHeader(2, out)
        MiniCbor.encodeText("scope", out)
        MiniCbor.encodeUint((scope and 0xFF).toLong(), out)
        MiniCbor.encodeText("confirmation", out)
        MiniCbor.encodeText(confirmToken, out)
        return out.toByteArray()
    }

    // =========================================================================
    // Mini CBOR RFC 7049 Codec (Pure Kotlin)
    // =========================================================================

    private object MiniCbor {
        fun encodeUint(v: Long, out: ByteArrayOutputStream) {
            when {
                v in 0..23 -> out.write(v.toInt())
                v <= 0xFFL -> {
                    out.write(0x18)
                    out.write(v.toInt())
                }
                v <= 0xFFFFL -> {
                    out.write(0x19)
                    out.write(((v ushr 8) and 0xFF).toInt())
                    out.write((v and 0xFF).toInt())
                }
                v <= 0xFFFF_FFFFL -> {
                    out.write(0x1A)
                    out.write(((v ushr 24) and 0xFF).toInt())
                    out.write(((v ushr 16) and 0xFF).toInt())
                    out.write(((v ushr 8) and 0xFF).toInt())
                    out.write((v and 0xFF).toInt())
                }
                else -> {
                    out.write(0x1B)
                    for (i in 7 downTo 0) {
                        out.write(((v ushr (i * 8)) and 0xFF).toInt())
                    }
                }
            }
        }

        fun encodeBytes(b: ByteArray, out: ByteArrayOutputStream) {
            val len = b.size.toLong()
            when {
                len in 0..23 -> out.write(0x40 or len.toInt())
                len <= 0xFFL -> {
                    out.write(0x58)
                    out.write(len.toInt())
                }
                len <= 0xFFFFL -> {
                    out.write(0x59)
                    out.write(((len ushr 8) and 0xFF).toInt())
                    out.write((len and 0xFF).toInt())
                }
                else -> {
                    out.write(0x5A)
                    out.write(((len ushr 24) and 0xFF).toInt())
                    out.write(((len ushr 16) and 0xFF).toInt())
                    out.write(((len ushr 8) and 0xFF).toInt())
                    out.write((len and 0xFF).toInt())
                }
            }
            out.write(b)
        }

        fun encodeText(s: String, out: ByteArrayOutputStream) {
            val b = s.toByteArray(Charsets.UTF_8)
            val len = b.size.toLong()
            when {
                len in 0..23 -> out.write(0x60 or len.toInt())
                len <= 0xFFL -> {
                    out.write(0x78)
                    out.write(len.toInt())
                }
                len <= 0xFFFFL -> {
                    out.write(0x79)
                    out.write(((len ushr 8) and 0xFF).toInt())
                    out.write((len and 0xFF).toInt())
                }
                else -> {
                    out.write(0x7A)
                    out.write(((len ushr 24) and 0xFF).toInt())
                    out.write(((len ushr 16) and 0xFF).toInt())
                    out.write(((len ushr 8) and 0xFF).toInt())
                    out.write((len and 0xFF).toInt())
                }
            }
            out.write(b)
        }

        fun encodeBool(b: Boolean, out: ByteArrayOutputStream) {
            out.write(if (b) 0xF5 else 0xF4)
        }

        fun encodeMapHeader(count: Int, out: ByteArrayOutputStream) {
            when {
                count in 0..23 -> out.write(0xA0 or count)
                count <= 0xFF -> {
                    out.write(0xB8)
                    out.write(count)
                }
                else -> {
                    out.write(0xB9)
                    out.write((count ushr 8) and 0xFF)
                    out.write(count and 0xFF)
                }
            }
        }

        fun decodeMap(bytes: ByteArray, startOffset: Int = 0): Map<String, Any?> {
            val (res, _) = decodeValue(bytes, startOffset)
            @Suppress("UNCHECKED_CAST")
            return (res as? Map<String, Any?>) ?: emptyMap()
        }

        private fun decodeLength(additional: Int, bytes: ByteArray, cur: Int): Pair<Long, Int> {
            return when (additional) {
                in 0..23 -> additional.toLong() to cur
                24 -> {
                    if (cur >= bytes.size) return 0L to cur
                    ((bytes[cur].toInt() and 0xFF).toLong()) to (cur + 1)
                }
                25 -> {
                    if (cur + 1 >= bytes.size) return 0L to cur
                    val v = (((bytes[cur].toInt() and 0xFF) shl 8) or
                             (bytes[cur + 1].toInt() and 0xFF)).toLong()
                    v to (cur + 2)
                }
                26 -> {
                    if (cur + 3 >= bytes.size) return 0L to cur
                    var v = 0L
                    for (i in 0 until 4) {
                        v = (v shl 8) or (bytes[cur + i].toInt() and 0xFF).toLong()
                    }
                    v to (cur + 4)
                }
                27 -> {
                    if (cur + 7 >= bytes.size) return 0L to cur
                    var v = 0L
                    for (i in 0 until 8) {
                        v = (v shl 8) or (bytes[cur + i].toInt() and 0xFF).toLong()
                    }
                    v to (cur + 8)
                }
                else -> 0L to cur
            }
        }

        private fun decodeValue(bytes: ByteArray, offset: Int): Pair<Any?, Int> {
            if (offset >= bytes.size) return null to offset
            val initial = bytes[offset].toInt() and 0xFF
            val major = initial ushr 5
            val additional = initial and 0x1F
            val cur = offset + 1

            return when (major) {
                0 -> decodeLength(additional, bytes, cur)
                1 -> {
                    val (len, next) = decodeLength(additional, bytes, cur)
                    (-1L - len) to next
                }
                2 -> {
                    val (len, next) = decodeLength(additional, bytes, cur)
                    val l = len.toInt().coerceAtMost(bytes.size - next)
                    bytes.copyOfRange(next, next + l) to (next + l)
                }
                3 -> {
                    val (len, next) = decodeLength(additional, bytes, cur)
                    val l = len.toInt().coerceAtMost(bytes.size - next)
                    String(bytes, next, l, Charsets.UTF_8) to (next + l)
                }
                4 -> {
                    val (count, next) = decodeLength(additional, bytes, cur)
                    var p = next
                    val list = ArrayList<Any?>()
                    for (i in 0 until count.toInt()) {
                        val (item, nextP) = decodeValue(bytes, p)
                        list.add(item)
                        p = nextP
                    }
                    list to p
                }
                5 -> {
                    val (count, next) = decodeLength(additional, bytes, cur)
                    var p = next
                    val map = LinkedHashMap<String, Any?>()
                    for (i in 0 until count.toInt()) {
                        val (k, p1) = decodeValue(bytes, p)
                        val (v, p2) = decodeValue(bytes, p1)
                        if (k is String) {
                            map[k] = v
                        }
                        p = p2
                    }
                    map to p
                }
                7 -> {
                    when (additional) {
                        20 -> false to cur
                        21 -> true to cur
                        22 -> null to cur
                        else -> null to cur
                    }
                }
                else -> null to cur
            }
        }
    }
}
