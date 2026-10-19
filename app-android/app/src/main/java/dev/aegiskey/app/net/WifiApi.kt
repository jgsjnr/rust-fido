package dev.aegiskey.app.net

import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.SanitizedLog
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * WiFi AP transport — mirrors firmware/src/wifi_ap.rs endpoints:
 * POST /ctap (AEGN envelope), POST /config/wifi (UP+PIN), GET /oath/code (UP).
 * Runs on Dispatchers.IO callers; throws sanitized errors (no bodies echoed).
 */
object WifiApi {
    const val PATH_CTAP = "/ctap"
    const val PATH_WIFI = "/config/wifi"
    const val PATH_OATH = "/oath/code"

    /** POST /ctap: envelope validated locally, content handled by the device. */
    fun postCtap(baseUrl: String, envelope: ByteArray): ByteArray {
        AegisBridge.envelopeValidate(envelope).getOrThrow()
        val conn = open("$baseUrl$PATH_CTAP", "POST", "application/octet-stream")
        try {
            conn.outputStream.use { it.write(envelope) }
            val out = readOrThrow(conn)
            DeviceLog.append(DeviceLog.Category.WIFI, "HTTP POST /ctap -> 2xx bytes=" + out.size + " (envelope " + envelope.size + "B)")
            return out
        } catch (e: Exception) {
            DeviceLog.append(DeviceLog.Category.WIFI, "HTTP POST /ctap -> fail " + ((e.message ?: "error").take(48)))
            throw e
        } finally {
            conn.disconnect()
        }
    }

    /**
     * POST /config/wifi: AP password swap.
     * Device enforces UP+PIN (HTTP 401 otherwise) and keeps NVS intact on reject.
     * The local bounds check is only a hint; the device decides.
     */
    fun postWifiPassword(baseUrl: String, newPassword: String) {
        require(AegisBridge.wifiPasswordValid(newPassword)) { "password outside 8..63 ASCII" }
        val conn = open("$baseUrl$PATH_WIFI", "POST", "text/plain")
        try {
            conn.outputStream.use { it.write(newPassword.toByteArray(Charsets.US_ASCII)) }
            val code = conn.responseCode
            DeviceLog.append(DeviceLog.Category.WIFI, "HTTP POST /config/wifi -> HTTP " + code)
            if (code == 401) throw SecurityException("UP+PIN required (device button + PIN)")
            if (code !in 200..299) throw IOException("wifi password change failed: HTTP $code")
            SanitizedLog.record(SanitizedLog.Event.WIFI_PASSWORD_CHANGED)
        } finally {
            conn.disconnect()
        }
    }

    /**
     * GET /oath/code: TOTP generated ON the device; only the code returns,
     * never the secret. Requires presence (button) on the device.
     */
    fun getOathCode(baseUrl: String, account: String): AegisBridge.OathEntry {
        require(account.isNotEmpty() && account.length <= 128) { "bad account" }
        val query = URLEncoder.encode(account, "UTF-8")
        val conn = open("$baseUrl$PATH_OATH?account=$query", "GET", "application/json")
        try {
            val code = conn.responseCode
            DeviceLog.append(DeviceLog.Category.WIFI, "HTTP GET /oath/code -> HTTP " + code)
            if (code == 401) throw SecurityException("presence required (press device button)")
            if (code == 404) throw NoSuchElementException("unknown account")
            if (code !in 200..299) throw IOException("oath fetch failed: HTTP $code")
            val body = conn.inputStream.bufferedReader().use { it.readText() }.take(512)
            val entry = AegisBridge.oathParse(body).getOrThrow()
            SanitizedLog.record(SanitizedLog.Event.OATH_FETCHED)
            return entry
        } finally {
            conn.disconnect()
        }
    }

    private fun open(url: String, method: String, contentType: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            setRequestProperty("Content-Type", contentType)
            connectTimeout = 8000
            readTimeout = 8000
            doInput = true
            if (method == "POST") doOutput = true
        }

    private fun readOrThrow(conn: HttpURLConnection): ByteArray {
        val code = conn.responseCode
        if (code !in 200..299) throw IOException("ctap post failed: HTTP $code")
        return conn.inputStream.use { it.readBytes() }
    }
}

/**
 * TLS pinning hook (stub, fail-closed TODO).
 * The AEGN envelope is E2E (AES-256-GCM), so a hostile AP still cannot read
 * CTAP bytes; pinning hardens the transport. Before release: pin the device
 * certificate (burned at provisioning) and fail closed on mismatch.
 */
object DevicePinning {
    fun install() {
        // TODO(release): X509TrustManager pinned to the device cert; fail closed.
    }
}
