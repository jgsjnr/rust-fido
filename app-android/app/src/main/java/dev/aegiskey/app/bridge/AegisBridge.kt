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
}
