package dev.aegiskey.app.net

import dev.aegiskey.app.log.DeviceLog
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
