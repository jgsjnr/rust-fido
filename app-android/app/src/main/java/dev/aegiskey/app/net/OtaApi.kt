package dev.aegiskey.app.net

import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.FeatureFlags
import dev.aegiskey.app.security.SdkGate
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest

/**
 * OTA download transport (Wave 1 Task A, traces R-03): app is transport-only,
 * it never sees keys. Downloads manifest/binary with sha/size checks plus an
 * online allow-check against the update server (Task S contract):
 * GET /api/ota/manifest, GET <manifest.url> (binary), POST /api/ota/validate.
 *
 * Mirrors WifiApi.kt: HttpURLConnection, 8s timeouts, DeviceLog with
 * sizes/status only (never serial/aaguid/bodies). Runs on Dispatchers.IO
 * callers; throws sanitized errors (no bodies echoed).
 *
 * A6 staged session (item A6, plan APP-PLANO-NOVOS-MODULOS): stage via
 * BEGIN (0x30) + CHUNKs (0x31) and verify via FINISH (0x32), with the
 * 104 B manifest validated BEFORE any stage request (length + staged
 * budget + version ordering). Every staged action passes through
 * `SdkGate.requireOta()` first (compiled-off reads NotCompiled, missing
 * native lib reads ExternalBlocked; lab-mocks OFF by default, never a
 * faked Success). COMMIT (0x33) has no constant, builder, parameter or
 * flag in this file BY DESIGN: commit is a USB-only ritual (offline
 * release key + physical UP latch) owned by the bootloader / rollback
 * path, so there is no BLE path (GATT never dispatches 0x30-0x34) and no
 * serial path here either; without UP the device answers NEED_UP (0x01)
 * and keeps the Verified session. ABORT (0x34) discards staged state
 * back to Idle. Logs carry opcodes/sizes only, never manifest bytes,
 * keys, signatures or digests.
 */
object OtaApi {
    const val PATH_MANIFEST = "/api/ota/manifest"
    const val PATH_VALIDATE = "/api/ota/validate"
    const val TIMEOUT_MS = 8000
    const val MAX_MANIFEST_BYTES = 8 * 1024
    const val MAX_IMAGE_BYTES = 4 * 1024 * 1024
    private const val MAX_VALIDATE_BYTES = 4 * 1024

    private val SHA_HEX = Regex("[0-9a-f]{64}")

    /** GET /api/ota/manifest?serial=..&fw=... Offline -> IOException. */
    fun fetchManifest(baseUrl: String, serial: String, currentFw: String): OtaManifest {
        require(baseUrl.isNotBlank()) { "bad baseUrl" }
        require(serial.length in 1..128) { "bad serial" }
        require(currentFw.length in 1..64) { "bad currentFw" }
        val query = "serial=" + URLEncoder.encode(serial, "UTF-8") +
            "&fw=" + URLEncoder.encode(currentFw, "UTF-8")
        val conn = open(trimSlash(baseUrl) + PATH_MANIFEST + "?" + query, "GET")
        try {
            val code = conn.responseCode
            DeviceLog.append(DeviceLog.Category.SYSTEM, "OTA manifest -> HTTP " + code)
            if (code == 403) throw SecurityException("device not registered for OTA")
            if (code !in 200..299) throw IOException("manifest fetch failed: HTTP $code")
            val body = conn.inputStream.use { readCapped(it, MAX_MANIFEST_BYTES) }
                .toString(Charsets.UTF_8)
            val manifest = parseManifestJson(body).withAbsoluteUrl(trimSlash(baseUrl))
            DeviceLog.append(
                DeviceLog.Category.SYSTEM,
                "OTA manifest ok body=" + body.length + " size=" + manifest.size,
            )
            return manifest
        } finally {
            conn.disconnect()
        }
    }

    /**
     * GET <manifest.url> streaming with running SHA-256 + size cap.
     * Throws IOException on oversize/empty/http-error, SecurityException on
     * sha256 mismatch. Pure transport: signature check is the device's job.
     */
    fun fetchBinary(
        manifestUrl: String,
        expectedSha256: String,
        maxBytes: Int = MAX_IMAGE_BYTES,
    ): ByteArray {
        require(isHttp(manifestUrl)) { "bad url" }
        require(expectedSha256.trim().lowercase().matches(SHA_HEX)) { "bad sha256" }
        require(maxBytes in 1..16 * 1024 * 1024) { "bad maxBytes" }
        val want = expectedSha256.trim().lowercase()
        val conn = open(manifestUrl, "GET")
        try {
            val code = conn.responseCode
            DeviceLog.append(DeviceLog.Category.SYSTEM, "OTA binary -> HTTP " + code)
            if (code == 403) throw SecurityException("device not registered for OTA")
            if (code !in 200..299) throw IOException("binary fetch failed: HTTP $code")
            val digest = MessageDigest.getInstance("SHA-256")
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            var total = 0
            conn.inputStream.use { ins ->
                while (true) {
                    val n = ins.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > maxBytes) throw IOException("firmware oversize (cap " + maxBytes + ")")
                    digest.update(buf, 0, n)
                    out.write(buf, 0, n)
                }
            }
            if (total == 0) throw IOException("empty firmware binary")
            if (digest.digest().toHex() != want) throw SecurityException("firmware sha256 mismatch")
            DeviceLog.append(DeviceLog.Category.SYSTEM, "OTA binary ok bytes=" + total)
            return out.toByteArray()
        } finally {
            conn.disconnect()
        }
    }

    /**
     * POST /api/ota/validate {"serial","aaguid","nonce"} -> true only on 2xx
     * {allowed:true}. False on 401/403/offline (no exception for offline);
     * other HTTP errors throw. Never logs serial/aaguid.
     */
    fun validateOnline(baseUrl: String, serial: String, aaguid: String): Boolean {
        require(baseUrl.isNotBlank()) { "bad baseUrl" }
        require(serial.length in 1..128) { "bad serial" }
        require(aaguid.length in 1..64) { "bad aaguid" }
        return try {
            postValidate(trimSlash(baseUrl) + PATH_VALIDATE, serial, aaguid)
        } catch (_: IOException) {
            DeviceLog.append(DeviceLog.Category.SYSTEM, "OTA validate offline")
            false
        }
    }

    /**
     * Pure + JVM-testable: parses a manifest body. Key aliases follow the
     * landed Task-S server (tools/ota_server.py): sha256, sig_ed25519 (also
     * accepts sha256Hex/signature/signatureHex). The server emits [url] as a
     * relative path ("/api/ota/firmware/..."); [fetchManifest] resolves it to
     * absolute via [OtaManifest.withAbsoluteUrl], so [fetchBinary] always gets
     * an http(s) URL. Strict on value shapes.
     */
    fun parseManifestJson(body: String): OtaManifest {
        val obj = try {
            org.json.JSONObject(body)
        } catch (_: Exception) {
            throw IOException("bad manifest json")
        }
        val version = obj.optString("version", "").trim()
        val sha = obj.optString("sha256", obj.optString("sha256Hex", "")).trim().lowercase()
        val sig = obj.optString(
            "sig_ed25519",
            obj.optString("signature", obj.optString("signatureHex", "")),
        ).trim().lowercase()
        val url = obj.optString("url", "").trim()
        val size = obj.optLong("size", -1L)
        require(version.isNotEmpty() && version.length <= 64) { "bad manifest version" }
        require(sha.matches(SHA_HEX)) { "bad manifest sha256" }
        require(sig.isNotEmpty() && sig.length <= 4096) { "bad manifest signature" }
        require(isHttp(url) || (url.startsWith("/") && url.length <= 256)) { "bad manifest url" }
        require(size in 1..MAX_IMAGE_BYTES) { "bad manifest size" }
        return OtaManifest(
            version = version,
            sha256Hex = sha,
            signatureHex = sig,
            url = url,
            size = size,
        )
    }

    private fun postValidate(url: String, serial: String, aaguid: String): Boolean {
        val conn = open(url, "POST")
        try {
            // The Task-S server requires a nonce (replay protection); a fresh
            // client random per call is the standard shape and needs no caller
            // state, so the spec'd 3-arg validateOnline signature is kept.
            val nonceBytes = ByteArray(16)
            java.security.SecureRandom().nextBytes(nonceBytes)
            val payload = org.json.JSONObject()
                .put("serial", serial)
                .put("aaguid", aaguid)
                .put("nonce", nonceBytes.toHex())
                .toString()
                .toByteArray(Charsets.UTF_8)
            conn.outputStream.use { it.write(payload) }
            val code = conn.responseCode
            DeviceLog.append(DeviceLog.Category.SYSTEM, "OTA validate -> HTTP " + code)
            if (code == 401 || code == 403) return false
            if (code !in 200..299) throw IOException("validate failed: HTTP $code")
            val body = conn.inputStream.use { readCapped(it, MAX_VALIDATE_BYTES) }
                .toString(Charsets.UTF_8)
            return try {
                org.json.JSONObject(body).optBoolean("allowed", false)
            } catch (_: Exception) {
                false
            }
        } finally {
            conn.disconnect()
        }
    }

    private fun open(url: String, method: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            setRequestProperty("Content-Type", "application/json")
            connectTimeout = TIMEOUT_MS
            readTimeout = TIMEOUT_MS
            doInput = true
            if (method == "POST") doOutput = true
        }

    private fun readCapped(ins: InputStream, cap: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(1024)
        var total = 0
        while (true) {
            val n = ins.read(buf)
            if (n < 0) break
            total += n
            if (total > cap) throw IOException("response oversize (cap " + cap + ")")
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private fun trimSlash(baseUrl: String): String = baseUrl.trimEnd('/')

    private fun isHttp(url: String): Boolean =
        url.startsWith("http://") || url.startsWith("https://")

    private fun ByteArray.toHex(): String {
        val chars = CharArray(size * 2)
        val hex = "0123456789abcdef"
        var i = 0
        for (b in this) {
            val v = b.toInt() and 0xFF
            chars[i++] = hex[v shr 4]
            chars[i++] = hex[v and 0x0F]
        }
        return String(chars)
    }

    // ------------------------------------------------------------------
    // A6 staged OTA session (device owns the session; app is transport).
    //
    // Wire authority: firmware `ota.rs` + `stores/ota_store.rs` (+ frozen
    // T6 vectors in `otakey_provider_t6.rs`):
    // - BEGIN (0x30) carries the fixed 104 B manifest:
    //   version u32 BE || size u32 BE || sha256 (32) || signature (64).
    // - CHUNK (0x31) carries offset u32 BE || data (in-order, non-empty,
    //   never past the manifest size).
    // - FINISH (0x32) verifies staged bytes device-side (release Ed25519
    //   over the 40 signed bytes version || size || sha256, then digest,
    //   then version > current). Empty payload.
    // - ABORT (0x34) discards staged state back to Idle, preserving NVS
    //   (only `ota_*` flash keys are ever touched). Empty payload.
    // - 0x33 COMMIT HAS NO CONSTANT, BUILDER, PARAMETER OR FLAG IN THIS
    //   FILE BY DESIGN (not merely disabled): commit is a USB-only ritual
    //   (offline release key + physical UP latch) owned by the bootloader
    //   / rollback path. There is no BLE path (GATT never dispatches
    //   0x30-0x34) and no serial path here either; without UP the device
    //   answers NEED_UP (0x01) and keeps the Verified session so the host
    //   can re-try after the user taps BOOT. See [mapStatus].
    //
    // Rules: the 104 B manifest is validated BEFORE any stage request
    // (length + staged budget + version ordering); every action below
    // passes through `SdkGate.requireOta()` first, so a compiled-off OTA
    // reads NotCompiled and a missing native lib reads ExternalBlocked
    // (lab-mocks OFF by default: never a faked Success). The lab key
    // exists device-side under test-mode builds only; the release default
    // is all-zeros fail-closed (see [isDeniedKey], [labKeyAllowed]).
    // Logs carry opcodes/sizes only, never manifest bytes, keys, sigs or
    // digests.
    // ------------------------------------------------------------------

    /** OTA vendor opcode: open a staged session with the 104 B manifest. */
    const val OP_BEGIN = 0x30
    /** OTA vendor opcode: stream one chunk (offset u32 BE || data). */
    const val OP_CHUNK = 0x31
    /** OTA vendor opcode: verify staged image (signature + digest + version). */
    const val OP_FINISH = 0x32
    /** OTA vendor opcode: discard staged state, back to Idle. */
    const val OP_ABORT = 0x34
    // NOTE: 0x33 (COMMIT) is intentionally absent here. See the block above.

    /** Wire length of the staged manifest (version || size || sha256 || sig). */
    const val MANIFEST_WIRE_LEN = 104
    /** Signed prefix of the manifest (version BE || size BE || sha256). */
    const val MANIFEST_SIGNED_LEN = 40
    /** Manifest sha256 field length. */
    const val MANIFEST_SHA_LEN = 32
    /** Manifest Ed25519 signature field length. */
    const val MANIFEST_SIG_LEN = 64
    /** CHUNK offset prefix length (u32 BE). */
    const val CHUNK_OFFSET_LEN = 4
    /** Offline release/lab pubkey length (firmware `OtaKeyProvider`). */
    const val OTA_PUBKEY_LEN = 32
    /**
     * Effective staging budget (bytes): the `storage` NVS partition holds
     * 896 KiB, so BEGIN above this fails fast device-side (`ota_store.rs`
     * `OTA_STORAGE_BUDGET_BYTES`); the 2 MiB protocol ceiling
     * (`MAX_OTA_IMAGE_BYTES`) still applies on the wire but never admits
     * more than this sink budget. The download path ([fetchBinary]
     * [MAX_IMAGE_BYTES]) is untouched transport generosity; the staged
     * gate below is the honest one.
     */
    const val MAX_STAGED_IMAGE_BYTES = 896 * 1024

    /**
     * UI pre-check: the single gate for every staged action below.
     * NotCompiled (feature off) and ExternalBlocked (lab-mocks off / no
     * native lib) are honest fail-closed answers, never faked Success.
     */
    fun otaGate(): SdkGate.GateOutcome = SdkGate.requireOta()

    /**
     * Pure + JVM-testable: parses the fixed 104 B wire manifest and
     * enforces the staged size budget. Throws IllegalArgumentException on
     * length mismatch or zero/over-budget size. Version ordering is NOT
     * checked here; call [checkManifestVersion] (or [beginOp], which does
     * both) before staging anything.
     */
    fun parseStagedManifest(raw: ByteArray): StagedManifest {
        require(raw.size == MANIFEST_WIRE_LEN) { "bad manifest length" }
        val version = u32Be(raw, 0)
        val size = u32Be(raw, 4)
        require(size >= 1 && size <= MAX_STAGED_IMAGE_BYTES) { "manifest size over budget" }
        return StagedManifest(
            version = version,
            size = size.toInt(),
            sha256 = raw.copyOfRange(8, 8 + MANIFEST_SHA_LEN),
            signature = raw.copyOfRange(8 + MANIFEST_SHA_LEN, MANIFEST_WIRE_LEN),
        )
    }

    /**
     * Pure + JVM-testable: rejects version 0 and any version that is not
     * strictly newer than [currentVersion] (firmware `Downgrade`
     * fail-closed). Returns the same manifest for chaining.
     */
    fun checkManifestVersion(manifest: StagedManifest, currentVersion: Long): StagedManifest {
        require(currentVersion >= 0) { "bad current version" }
        require(manifest.version != 0L && manifest.version > currentVersion) {
            "ota version not newer than current"
        }
        return manifest
    }

    /**
     * Gated BEGIN (0x30): validates the 104 B manifest (size + version)
     * BEFORE opening any staged session. Ready carries a private copy of
     * the manifest bytes as payload; Blocked carries the honest gate
     * outcome (nothing was staged). Contract misuse throws
     * IllegalArgumentException (same style as the download path above).
     */
    fun beginOp(manifestRaw: ByteArray, currentVersion: Long): OtaOp {
        val gate = SdkGate.requireOta()
        if (gate != SdkGate.GateOutcome.Success && gate != SdkGate.GateOutcome.RealVerified) {
            return OtaOp.Blocked(gate)
        }
        val manifest = checkManifestVersion(parseStagedManifest(manifestRaw), currentVersion)
        DeviceLog.append(DeviceLog.Category.SYSTEM, "OTA stage begin ok size=" + manifest.size)
        return OtaOp.Ready(OP_BEGIN, manifestRaw.copyOf())
    }

    /**
     * Gated CHUNK (0x31): one in-order non-empty slice of the staged
     * image. [stagedSize] is the manifest size already validated by
     * [beginOp]; the device re-enforces order + budget and answers with
     * the total received (u32 BE, see [parseChunkAck]). Ready payload is
     * offset u32 BE || data.
     */
    fun chunkOp(offset: Int, data: ByteArray, stagedSize: Int): OtaOp {
        val gate = SdkGate.requireOta()
        if (gate != SdkGate.GateOutcome.Success && gate != SdkGate.GateOutcome.RealVerified) {
            return OtaOp.Blocked(gate)
        }
        require(offset >= 0) { "bad chunk offset" }
        require(data.isNotEmpty()) { "empty chunk" }
        require(stagedSize in 1..MAX_STAGED_IMAGE_BYTES) { "bad staged size" }
        val end = offset.toLong() + data.size.toLong()
        require(end <= stagedSize.toLong()) { "chunk over staged size" }
        val payload = ByteArray(CHUNK_OFFSET_LEN + data.size)
        payload[0] = ((offset shr 24) and 0xFF).toByte()
        payload[1] = ((offset shr 16) and 0xFF).toByte()
        payload[2] = ((offset shr 8) and 0xFF).toByte()
        payload[3] = (offset and 0xFF).toByte()
        data.copyInto(payload, CHUNK_OFFSET_LEN)
        DeviceLog.append(
            DeviceLog.Category.SYSTEM,
            "OTA stage chunk ok off=" + offset + " len=" + data.size,
        )
        return OtaOp.Ready(OP_CHUNK, payload)
    }

    /**
     * Gated FINISH (0x32): asks the device to verify the staged image
     * (release signature, then digest, then version). The offline release
     * key lives device-side: lab key under test-mode builds only, release
     * default all-zeros fail-closed (`BadSignature`, phase stays Staged).
     * The app never handles key material here. Empty payload.
     */
    fun finishOp(): OtaOp {
        val gate = SdkGate.requireOta()
        if (gate != SdkGate.GateOutcome.Success && gate != SdkGate.GateOutcome.RealVerified) {
            return OtaOp.Blocked(gate)
        }
        DeviceLog.append(DeviceLog.Category.SYSTEM, "OTA verify finish queued")
        return OtaOp.Ready(OP_FINISH, ByteArray(0))
    }

    /**
     * Gated ABORT (0x34): discards the staged session on both ends back
     * to Idle (device rolls back + discards staging, preserving NVS;
     * the app drops any cursor derived from [parseChunkAck]). Still gated
     * here so a compiled-off OTA never emits wire bytes. Empty payload.
     */
    fun abortOp(): OtaOp {
        val gate = SdkGate.requireOta()
        if (gate != SdkGate.GateOutcome.Success && gate != SdkGate.GateOutcome.RealVerified) {
            return OtaOp.Blocked(gate)
        }
        DeviceLog.append(DeviceLog.Category.SYSTEM, "OTA abort queued")
        return OtaOp.Ready(OP_ABORT, ByteArray(0))
    }

    /**
     * Pure + JVM-testable: renders the CHUNK reply (total received, u32
     * BE) as authority data. Throws IllegalArgumentException unless the
     * reply is exactly 4 bytes within the staging budget.
     */
    fun parseChunkAck(reply: ByteArray): Int {
        require(reply.size == CHUNK_OFFSET_LEN) { "bad chunk ack" }
        val received = u32Be(reply, 0)
        require(received <= MAX_STAGED_IMAGE_BYTES) { "chunk ack over budget" }
        return received.toInt()
    }

    /**
     * Frozen wire byte to R4 (parity with firmware `ble_gatt` S9.5, which
     * `ota_store.rs` mirrors: 0x00 OK, 0x01 NEED_UP, 0x04 FAIL): 0x00 ->
     * Success; 0x01 (COMMIT without the physical UP latch; the only commit
     * path is the USB ritual, absent from this file) -> PermissionDenied;
     * anything else -> Unsupported.
     */
    fun mapStatus(status: Int): SdkGate.GateOutcome = SdkGate.mapWireStatus(status)

    /**
     * Pure + JVM-testable: mirrors firmware `OtaKeyProvider::is_denied`
     * (release default). True only for the all-zeros 32 B key, which
     * fail-closes every FINISH/COMMIT before any Ed25519 math. Any other
     * shape (including wrong length) is NOT an allow: it is simply not
     * the denied key; verification itself stays device-side.
     */
    fun isDeniedKey(pubkey: ByteArray): Boolean =
        pubkey.size == OTA_PUBKEY_LEN && pubkey.all { it == 0.toByte() }

    /**
     * Single authority for lab-key permission: the test-mode capability
     * bit ([FeatureFlags.CAP_TEST_MODE]). False in production (the bit is
     * absent from [FeatureFlags.SDK_COMPILED_MASK]), so lab signatures
     * never verify outside test-mode builds. No lab key material lives in
     * this app: the key itself stays device-side / off-repo.
     */
    fun labKeyAllowed(): Boolean = FeatureFlags.isEnabled(FeatureFlags.CAP_TEST_MODE)

    private fun u32Be(raw: ByteArray, off: Int): Long =
        ((raw[off].toInt() and 0xFF).toLong() shl 24) or
            ((raw[off + 1].toInt() and 0xFF).toLong() shl 16) or
            ((raw[off + 2].toInt() and 0xFF).toLong() shl 8) or
            (raw[off + 3].toInt() and 0xFF).toLong()
}

/** Update-server manifest: version + integrity + where to fetch the image. */
data class OtaManifest(
    val version: String,
    val sha256Hex: String,
    val signatureHex: String,
    val url: String,
    val size: Long,
) {
    /**
     * Pure: resolves a server-relative manifest path ("/api/ota/firmware/..")
     * against [baseUrl]; absolute URLs pass through unchanged.
     */
    fun withAbsoluteUrl(baseUrl: String): OtaManifest {
        if (url.startsWith("http://") || url.startsWith("https://")) return this
        return copy(url = baseUrl.trimEnd('/') + url)
    }
}

/**
 * Staged 104 B manifest (firmware `ota.rs` wire layout): monotonically
 * increasing version (u32, 0 invalid), exact image size, expected sha256
 * over the full image, offline release Ed25519 signature over
 * version BE || size BE || sha256 (40 B).
 */
data class StagedManifest(
    val version: Long,
    val size: Int,
    val sha256: ByteArray,
    val signature: ByteArray,
)

/**
 * Gated OTA vendor request: either ready-to-send wire bytes
 * ([Ready.opcode] + [Ready.payload]) or honestly [Blocked] by
 * `SdkGate.requireOta()` (nothing staged, nothing sent). There is no
 * COMMIT variant by design (see [OtaApi]): commit is a USB-only ritual
 * (offline release key + physical UP) with no BLE/serial path in code.
 */
sealed interface OtaOp {
    data class Ready(val opcode: Int, val payload: ByteArray) : OtaOp
    data class Blocked(val outcome: SdkGate.GateOutcome) : OtaOp
}
