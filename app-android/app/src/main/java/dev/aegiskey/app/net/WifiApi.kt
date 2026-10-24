package dev.aegiskey.app.net

import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.SanitizedLog
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

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

    /**
     * GET /wifi/nets: redes salvas no device.
     * Aceita `{"nets":["casa","lab"]}` ou `["casa","lab"]`.
     * Firmware atual ainda nao expoe (404 = vazio amigavel, sem erro).
     * Loga so a contagem, nunca SSIDs (sem PII).
     */
    fun getWifiNets(baseUrl: String): List<String> {
        val conn = open("$baseUrl/wifi/nets", "GET", "application/json")
        try {
            val code = conn.responseCode
            DeviceLog.append(DeviceLog.Category.WIFI, "HTTP GET /wifi/nets -> HTTP " + code)
            if (code == 404) return emptyList()
            if (code !in 200..299) throw IOException("wifi nets failed: HTTP $code")
            val body = conn.inputStream.bufferedReader().use { it.readText() }.take(4096)
            val nets = parseNetsJson(body)
            DeviceLog.append(DeviceLog.Category.WIFI, "HTTP GET /wifi/nets count=" + nets.size)
            return nets
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Teste de conexao: qualquer resposta HTTP (ate 404) = alcancavel;
     * so IOException/timeout = inal Cancavel. Nao loga corpo.
     */
    fun testConnection(baseUrl: String): Boolean {
        return try {
            val conn = open("$baseUrl/wifi/nets", "GET", "application/json")
            try {
                conn.connectTimeout = 3000
                val code = conn.responseCode
                DeviceLog.append(DeviceLog.Category.WIFI, "HTTP test -> HTTP " + code)
                code in 200..599
            } finally {
                conn.disconnect()
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun parseNetsJson(body: String): List<String> {
        return try {
            val trimmed = body.trim()
            if (trimmed.startsWith("{")) {
                val obj = org.json.JSONObject(trimmed)
                val arr = obj.optJSONArray("nets") ?: return emptyList()
                readJsonStrings(arr)
            } else if (trimmed.startsWith("[")) {
                readJsonStrings(org.json.JSONArray(trimmed))
            } else {
                emptyList()
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun readJsonStrings(arr: org.json.JSONArray): List<String> {
        val out = mutableListOf<String>()
        var i = 0
        while (i < arr.length() && out.size < 32) {
            val s = arr.optString(i, "").trim()
            if (s.isNotEmpty()) out.add(s.take(64))
            i += 1
        }
        return out
    }

    private fun open(url: String, method: String, contentType: String): HttpURLConnection {
        // Fail-closed: HTTPS sem pins instalados e negado aqui (o AP usa
        // HTTP puro e passa direto; ver DevicePinning).
        DevicePinning.guard(url)
        val conn = URL(url).openConnection() as HttpURLConnection
        // Pinning por-conexao (sem default global): nao afeta outros usos
        // de TLS no processo. HostnameVerifier do sistema e mantido.
        if (conn is HttpsURLConnection) conn.sslSocketFactory = DevicePinning.pinnedFactory()
        return conn.apply {
            requestMethod = method
            setRequestProperty("Content-Type", contentType)
            connectTimeout = 8000
            readTimeout = 8000
            doInput = true
            if (method == "POST") doOutput = true
        }
    }

    private fun readOrThrow(conn: HttpURLConnection): ByteArray {
        val code = conn.responseCode
        if (code !in 200..299) throw IOException("ctap post failed: HTTP $code")
        return conn.inputStream.use { it.readBytes() }
    }
}

/**
 * Pinning TLS real (SPKI SHA-256, fail-closed).
 *
 * O envelope AEGN ja e E2E (AES-256-GCM), entao um AP hostil nao le CTAP;
 * o pinning endurece o transporte quando ha TLS. Uso:
 * - [install] com os pins base64(SHA-256(SPKI)) gravados no provisioning;
 *   sem pins, [guard] nega HTTPS (HTTP do AP passa direto).
 * - [pinnedFactory] rende um SSLSocketFactory por-conexao (sem default
 *   global): cadeia validada pelo trust do sistema + pin da folha.
 * Qualquer mismatch = SSLPeerUnverifiedException (nunca fallback silencioso).
 * Loga so contagem/evento, nunca pins, hosts ou corpos.
 */
object DevicePinning {
    @Volatile
    private var pins: Set<String>? = null

    /** base64(32B) = 44 chars com `=` final. */
    private val PIN_RE = Regex("[A-Za-z0-9+/]{43}=")

    /**
     * Instala os pins (base64 do SHA-256 do SPKI da folha). Forma rigida;
     * vazio/formato ruim = IllegalArgumentException (nada instalado).
     */
    fun install(vararg sha256Base64Pins: String) {
        require(sha256Base64Pins.isNotEmpty()) { "pins vazios" }
        require(sha256Base64Pins.all { PIN_RE.matchEntire(it) != null }) {
            "pin fora do formato base64(sha256)"
        }
        pins = sha256Base64Pins.toSet()
        DeviceLog.append(DeviceLog.Category.WIFI, "pinning instalado pins=" + sha256Base64Pins.size)
    }

    fun isConfigured(): Boolean = pins != null

    /** Rearma o estado negado (testes/dev); HTTPS volta a ser recusado. */
    fun clearPins() {
        pins = null
        DeviceLog.append(DeviceLog.Category.WIFI, "pinning desinstalado")
    }

    /**
     * Fail-closed p/ [WifiApi.open]: HTTPS exige pins instalados.
     * HTTP (AP local) nao e pinado e passa direto.
     */
    fun guard(url: String) {
        if (url.startsWith("https://") && pins == null) {
            throw SecurityException("pinning não configurado (HTTPS negado)")
        }
    }

    /** SocketFactory com trust do sistema + pin da folha (por-conexao). */
    fun pinnedFactory(): SSLSocketFactory {
        val want = pins ?: throw SecurityException("pinning não configurado (HTTPS negado)")
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(null as KeyStore?) }
        val system = tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
            ?: throw IllegalStateException("sem X509TrustManager")
        val ctx = SSLContext.getInstance("TLS")
            .apply { init(null, arrayOf(PinningTrustManager(system, want)), SecureRandom()) }
        return ctx.socketFactory
    }

    private class PinningTrustManager(
        private val delegate: X509TrustManager,
        private val want: Set<String>,
    ) : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
            delegate.checkClientTrusted(chain, authType)

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            delegate.checkServerTrusted(chain, authType)
            val leaf = chain.firstOrNull() ?: throw CertificateException("cadeia vazia")
            val spkiHash = MessageDigest.getInstance("SHA-256").digest(leaf.publicKey.encoded)
            val pin = android.util.Base64.encodeToString(spkiHash, android.util.Base64.NO_WRAP)
            if (!want.contains(pin)) throw SSLPeerUnverifiedException("pin mismatch")
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers
    }
}
