package dev.aegiskey.app.bridge

/**
 * Facade over the UniFFI-generated bindings for `aegis_bridge` (crates/uniffi-bridge).
 *
 * Generate before building the app:
 *   cargo run -p uniffi-bindgen -- generate crates/uniffi-bridge/src/aegis_bridge.udl \
 *     --language kotlin --out-dir app-android/app/src/main/java
 * which produces package `uniffi.aegis_bridge` (functions + BleInfo/OathCode records).
 *
 * Contract: only envelopes (AEGN), TOTP codes and account labels cross JNI.
 * Keys are transient caller buffers, zeroized inside Rust. This facade never
 * retains key material, secrets or codes beyond the returning call frame.
 * Failure messages are capped and carry no payloads (never secrets/PII).
 */
object AegisBridge {
    /** Display-only TOTP entry (mirrors the `OathCode` UDL record). */
    data class OathEntry(val account: String, val code: String, val remainingSeconds: Int)

    val nativeLoaded: Boolean =
        try {
            System.loadLibrary("aegis_bridge")
            true
        } catch (_: UnsatisfiedLinkError) {
            false
        }

    private fun checkNative() {
        check(nativeLoaded) { "native lib missing (build the cdylib + bindgen first)" }
    }

    private fun sanitize(e: Throwable): IllegalStateException =
        IllegalStateException(e.message?.take(64) ?: "bridge error")

    /** Frozen BLE constants from Rust (mirrors docs/ble-protocol.md). */
    fun constants(): Result<uniffi.aegis_bridge.BleInfo> = runCatching {
        checkNative()
        uniffi.aegis_bridge.bleConstants()
    }.recoverCatching { throw sanitize(it) }

    /** FFF1 fragments for [opcode] + [payload] (first `[op,hi,lo,..]`, then `[seq,..]`). */
    fun splitFragments(opcode: Int, payload: ByteArray): Result<List<ByteArray>> = runCatching {
        checkNative()
        uniffi.aegis_bridge.bleSplitFragments(
            opcode.toUByte(),
            payload.map { it.toUByte() }
        ).map { frag -> frag.map { it.toByte() }.toByteArray() }
    }.recoverCatching { throw sanitize(it) }

    /** Validates a POST /ctap AEGN envelope; returns ciphertext length. */
    fun envelopeValidate(envelope: ByteArray): Result<Int> = runCatching {
        checkNative()
        uniffi.aegis_bridge.envelopeValidate(envelope.map { it.toUByte() }).toInt()
    }.recoverCatching { throw sanitize(it) }

    /** Parses a GET /oath/code JSON body into display-only fields. */
    fun oathParse(json: String): Result<OathEntry> = runCatching {
        checkNative()
        val parsed = uniffi.aegis_bridge.oathParseResponse(json)
        OathEntry(parsed.account, parsed.code, parsed.remainingSeconds.toInt())
    }.recoverCatching { throw sanitize(it) }

    /** Derives the app-lock verifier via the Rust bridge PBKDF2 (fail closed). */
    fun appLockDerive(password: ByteArray, salt: ByteArray): Result<ByteArray> = runCatching {
        checkNative()
        uniffi.aegis_bridge.appLockDerive(
            password.map { it.toUByte() },
            salt.map { it.toUByte() }
        ).map { it.toByte() }.toByteArray()
    }.recoverCatching { throw sanitize(it) }

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
     * Sela [plaintext] num envelope AEGN (chave/nonce transitorios do chamador;
     * o app deve passar nonce fresco a cada selagem). Falhas sem payload
     * (nunca segredos/PII).
     */
    fun envelopeSeal(key: ByteArray, plaintext: ByteArray, aad: ByteArray, nonce: ByteArray): Result<ByteArray> = runCatching {
        checkNative()
        uniffi.aegis_bridge.envelopeSeal(
            key.map { it.toUByte() },
            plaintext.map { it.toUByte() },
            aad.map { it.toUByte() },
            nonce.map { it.toUByte() },
        ).map { it.toByte() }.toByteArray()
    }.recoverCatching { throw sanitize(it) }

    /** Zera buffers transitorios (chamar em finally apos cada send). */
    fun wipe(vararg buffers: ByteArray) {
        for (b in buffers) b.fill(0)
    }

    /**
     * Deriva endereco da carteira a partir de pubkey PUBLICA (computacao
     * local, sem segredos): "bitcoin"/"ethereum"/"solana" + hex da pubkey
     * (33B comprimida / 64B x||y / 32B Ed25519). O device nunca e perguntado.
     */
    fun walletAddress(network: String, pubkeyHex: String): Result<String> = runCatching {
        checkNative()
        uniffi.aegis_bridge.walletAddress(network, pubkeyHex)
    }.recoverCatching { throw sanitize(it) }

    /**
     * Abre um envelope AEGN com chave transitoria (par do envelopeSeal;
     * base do restore A5). A chave e zerada dentro do Rust antes do retorno;
     * este facade nunca retem segredo alem do frame: o chamador deve usar
     * wipe nos buffers em finally, como no selo.
     */
    fun envelopeOpen(key: ByteArray, envelope: ByteArray, aad: ByteArray): Result<ByteArray> = runCatching {
        checkNative()
        uniffi.aegis_bridge.envelopeOpen(
            key.map { it.toUByte() },
            envelope.map { it.toUByte() },
            aad.map { it.toUByte() },
        ).map { it.toByte() }.toByteArray()
    }.recoverCatching { throw sanitize(it) }

    /**
     * Teto de plaintext do selo AEGN, medido no proprio bridge (o teto vive no
     * SDK, em envelope MAX_PLAINTEXT_BYTES, e e aplicado pelo Rust com
     * Overflow fail-closed). Nenhum literal do teto vive no Kotlin: o menor
     * envelope bem-formado aceito e o maior sao sondados via
     * envelopeValidate (framing puro, sem cripto e sem segredo); o teto e a
     * diferenca entre eles. Calculado uma vez e cacheado (o .so nao muda).
     */
    @Volatile
    private var cachedMaxPlaintext: Int? = null

    fun maxPlaintextBytes(): Result<Int> = runCatching {
        checkNative()
        cachedMaxPlaintext ?: probePlaintextCeiling().also { cachedMaxPlaintext = it }
    }.recoverCatching { throw sanitize(it) }

    private fun probePlaintextCeiling(): Int {
        // Sonda com cabecalho AEGN bem-formado e nonce fixo nao-zero (sem
        // segredo): o bridge rejeita qualquer tamanho acima do teto com
        // Overflow e aceita framing valido numa faixa fechada [min, max].
        val header = byteArrayOf(0x41, 0x45, 0x47, 0x4E, 0x01) + ByteArray(12) { 0x11 }
        fun validates(total: Int): Boolean {
            if (total < header.size) return false
            val probe = header + ByteArray(total - header.size)
            return try {
                uniffi.aegis_bridge.envelopeValidate(probe.map { it.toUByte() })
                true
            } catch (_: uniffi.aegis_bridge.BridgeException) {
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

    /**
     * Guarda de busca da sonda de teto (nao e politica: o teto real vem do
     * bridge; este limite so impede sondagem sem fim se o nativo estiver
     * inconsistente).
     */
    private const val SEARCH_GUARD_BYTES = 1048576
}
