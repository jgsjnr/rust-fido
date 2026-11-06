package dev.aegiskey.app.net

import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.SanitizedLog
import org.json.JSONObject
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
 * WiFi AP transport — espelha endpoints firmware/src/wifi_ap.rs:
 * POST /ctap (AEGN envelope), POST /config/wifi (UP+PIN), GET /oath/code (UP),
 * com fallback automático para emulador Android (10.0.2.2:5678 e 127.0.0.1:5678).
 * Roda em chamadores Dispatchers.IO; lança erros sanitizados.
 */
object WifiApi {
    const val DEFAULT_BASE_URL = "http://192.168.4.1"
    const val PATH_CTAP = "/ctap"
    const val PATH_WIFI = "/config/wifi"
    const val PATH_OATH = "/oath/code"

    private val FALLBACK_URLS = listOf("http://10.0.2.2:5678", "http://127.0.0.1:5678")

    fun candidateUrls(primaryBaseUrl: String): List<String> {
        val clean = primaryBaseUrl.trim().trimEnd('/')
        return (listOf(clean) + FALLBACK_URLS).distinct()
    }

    /** POST /ctap: envelope validado localmente, processado pelo dispositivo físico. */
    fun postCtap(baseUrl: String = DEFAULT_BASE_URL, envelope: ByteArray): ByteArray {
        AegisBridge.envelopeValidate(envelope).getOrThrow()
        return executeWithFallback(baseUrl) { targetUrl ->
            val conn = open("$targetUrl$PATH_CTAP", "POST", "application/octet-stream")
            try {
                conn.outputStream.use { it.write(envelope) }
                val out = readOrThrow(conn)
                DeviceLog.append(DeviceLog.Category.WIFI, "HTTP POST /ctap -> 2xx bytes=" + out.size + " (envelope " + envelope.size + "B)")
                out
            } finally {
                conn.disconnect()
            }
        }
    }

    /**
     * POST /config/wifi: Alteração de senha do AP.
     * O dispositivo exige UP+PIN (HTTP 401 caso contrário) e preserva a NVS em rejeições.
     */
    fun postWifiPassword(baseUrl: String = DEFAULT_BASE_URL, newPassword: String) {
        require(AegisBridge.wifiPasswordValid(newPassword)) { "password outside 8..63 ASCII" }
        executeWithFallback(baseUrl) { targetUrl ->
            val conn = open("$targetUrl$PATH_WIFI", "POST", "text/plain")
            try {
                conn.outputStream.use { it.write(newPassword.toByteArray(Charsets.US_ASCII)) }
                val code = conn.responseCode
                DeviceLog.append(DeviceLog.Category.WIFI, "HTTP POST /config/wifi -> HTTP $code")
                if (code == 401) throw SecurityException("UP+PIN required (device button + PIN)")
                if (code !in 200..299) throw IOException("wifi password change failed: HTTP $code")
                SanitizedLog.record(SanitizedLog.Event.WIFI_PASSWORD_CHANGED)
            } finally {
                conn.disconnect()
            }
        }
    }

    /**
     * POST /wifi/config: Configuração interativa completa da rede Wi-Fi da chave
     * (SSID, Senha WPA2, Canal, Modo de economia de energia).
     */
    fun configureWifi(
        baseUrl: String = DEFAULT_BASE_URL,
        ssid: String,
        password: String,
        channel: Int = 6,
        powerSave: Boolean = false
    ): Result<String> = runCatching {
        require(ssid.isNotBlank() && ssid.length <= 32) { "SSID deve ter entre 1 e 32 caracteres" }
        require(password.length in 8..63) { "Senha WPA2 deve ter entre 8 e 63 caracteres" }
        require(channel in listOf(1, 6, 11)) { "Canal Wi-Fi deve ser 1, 6 ou 11" }

        executeWithFallback(baseUrl) { targetUrl ->
            val payload = JSONObject().apply {
                put("ssid", ssid.trim())
                put("password", password)
                put("channel", channel)
                put("power_save", powerSave)
            }.toString()

            val conn = open("$targetUrl/wifi/config", "POST", "application/json")
            try {
                conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
                val code = conn.responseCode
                if (code !in 200..299) throw IOException("Configuração Wi-Fi rejeitada: HTTP $code")
                val responseText = conn.inputStream.bufferedReader().use { it.readText() }
                val obj = runCatching { JSONObject(responseText) }.getOrNull()
                val msg = obj?.optString("message") ?: "Rede Wi-Fi $ssid (Canal $channel) configurada com sucesso no hardware!"
                msg
            } finally {
                conn.disconnect()
            }
        }
    }

    /**
     * GET /oath/code: TOTP gerado NO dispositivo; somente o código retorna,
     * nunca o segredo compartilhado. Requer presença física (botão).
     */
    fun getOathCode(baseUrl: String = DEFAULT_BASE_URL, account: String): AegisBridge.OathEntry {
        require(account.isNotEmpty() && account.length <= 128) { "bad account" }
        val query = URLEncoder.encode(account, "UTF-8")
        return executeWithFallback(baseUrl) { targetUrl ->
            val conn = open("$targetUrl$PATH_OATH?account=$query", "GET", "application/json")
            try {
                val code = conn.responseCode
                DeviceLog.append(DeviceLog.Category.WIFI, "HTTP GET /oath/code -> HTTP $code")
                if (code == 401) throw SecurityException("presence required (press device button)")
                if (code == 404) throw NoSuchElementException("unknown account")
                if (code !in 200..299) throw IOException("oath fetch failed: HTTP $code")
                val body = conn.inputStream.bufferedReader().use { it.readText() }.take(512)
                // Fail-closed: only a strictly-validated device code is
                // accepted. No lenient fallback parsing — without a live
                // session there is no code, never a guessed one.
                val entry = AegisBridge.oathParse(body).getOrThrow()
                require(AegisBridge.codeValid(entry.code)) { "invalid oath code" }
                SanitizedLog.record(SanitizedLog.Event.OATH_FETCHED)
                entry
            } finally {
                conn.disconnect()
            }
        }
    }

    /** Helper amigável que retorna Result<OathEntry> para consumo direto em UI */
    fun fetchOathCode(baseUrl: String = DEFAULT_BASE_URL, account: String = "AegisKey:admin"): Result<AegisBridge.OathEntry> =
        runCatching { getOathCode(baseUrl, account) }

    /**
     * GET /wifi/nets: redes salvas no dispositivo.
     */
    fun getWifiNets(baseUrl: String = DEFAULT_BASE_URL): List<String> {
        return runCatching {
            executeWithFallback(baseUrl) { targetUrl ->
                val conn = open("$targetUrl/wifi/nets", "GET", "application/json")
                try {
                    val code = conn.responseCode
                    DeviceLog.append(DeviceLog.Category.WIFI, "HTTP GET /wifi/nets -> HTTP $code")
                    if (code == 404) return@executeWithFallback emptyList<String>()
                    if (code !in 200..299) throw IOException("wifi nets failed: HTTP $code")
                    val body = conn.inputStream.bufferedReader().use { it.readText() }.take(4096)
                    val nets = parseNetsJson(body)
                    DeviceLog.append(DeviceLog.Category.WIFI, "HTTP GET /wifi/nets count=" + nets.size)
                    nets
                } finally {
                    conn.disconnect()
                }
            }
        }.getOrDefault(emptyList())
    }

    /**
     * Teste de conexão com fallback rápido (1200ms por host) para suportar
     * tanto conexões diretas ao SoftAP (192.168.4.1) quanto emulador (10.0.2.2:5678).
     */
    fun testConnection(baseUrl: String = DEFAULT_BASE_URL): Boolean =
        testConnectionDetailed(baseUrl).reachable

    /**
     * Click-through F3: bounded Wi-Fi test that ALWAYS surfaces a visible
     * result. Returns reachability plus which endpoint answered and which
     * networks the key currently sees (best-effort `GET /wifi/nets`).
     * Per-attempt timeouts are short and the whole probe is capped so the
     * settings card never hangs silently past the observation window.
     */
    data class WifiTestReport(
        val reachable: Boolean,
        val endpoint: String? = null,
        val latencyMs: Long = 0L,
        val networksSeen: List<String> = emptyList(),
    )

    fun testConnectionDetailed(
        baseUrl: String = DEFAULT_BASE_URL,
        perAttemptTimeoutMs: Int = 900,
        overallTimeoutMs: Long = 4000L,
    ): WifiTestReport {
        val deadline = System.currentTimeMillis() + overallTimeoutMs
        for (targetUrl in candidateUrls(baseUrl)) {
            val endpoints = listOf("/status", "/bridge/info", "/wifi/nets")
            for (ep in endpoints) {
                if (System.currentTimeMillis() > deadline) {
                    return WifiTestReport(reachable = false, networksSeen = emptyList())
                }
                val start = System.currentTimeMillis()
                try {
                    val conn = open("$targetUrl$ep", "GET", "application/json").apply {
                        connectTimeout = perAttemptTimeoutMs
                        readTimeout = perAttemptTimeoutMs
                    }
                    val code = conn.responseCode
                    conn.disconnect()
                    if (code in 200..599) {
                        val nets = runCatching {
                            if (System.currentTimeMillis() > deadline) emptyList()
                            else getWifiNets(baseUrl)
                        }.getOrDefault(emptyList())
                        return WifiTestReport(
                            reachable = true,
                            endpoint = "$targetUrl$ep",
                            latencyMs = System.currentTimeMillis() - start,
                            networksSeen = nets,
                        )
                    }
                } catch (_: Exception) {}
            }
        }
        return WifiTestReport(reachable = false, networksSeen = emptyList())
    }

    private fun <T> executeWithFallback(baseUrl: String, block: (String) -> T): T {
        val candidates = candidateUrls(baseUrl)
        var lastErr: Exception? = null
        for (targetUrl in candidates) {
            try {
                return block(targetUrl)
            } catch (e: Exception) {
                lastErr = e
                if (e is SecurityException || e is IllegalArgumentException || e is NoSuchElementException) {
                    throw e
                }
            }
        }
        throw lastErr ?: IOException("Nenhum host Wi-Fi acessível para $baseUrl")
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
        DevicePinning.guard(url)
        val conn = URL(url).openConnection() as HttpURLConnection
        if (conn is HttpsURLConnection) conn.sslSocketFactory = DevicePinning.pinnedFactory()
        return conn.apply {
            requestMethod = method
            setRequestProperty("Content-Type", contentType)
            connectTimeout = 5000
            readTimeout = 5000
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
 */
object DevicePinning {
    @Volatile
    private var pins: Set<String>? = null

    private val PIN_RE = Regex("[A-Za-z0-9+/]{43}=")

    fun install(vararg sha256Base64Pins: String) {
        require(sha256Base64Pins.isNotEmpty()) { "pins vazios" }
        require(sha256Base64Pins.all { PIN_RE.matchEntire(it) != null }) {
            "pin fora do formato base64(sha256)"
        }
        pins = sha256Base64Pins.toSet()
        DeviceLog.append(DeviceLog.Category.WIFI, "pinning instalado pins=" + sha256Base64Pins.size)
    }

    fun isConfigured(): Boolean = pins != null

    fun clearPins() {
        pins = null
        DeviceLog.append(DeviceLog.Category.WIFI, "pinning desinstalado")
    }

    fun guard(url: String) {
        if (url.startsWith("https://") && pins == null) {
            throw SecurityException("pinning não configurado (HTTPS negado)")
        }
    }

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
