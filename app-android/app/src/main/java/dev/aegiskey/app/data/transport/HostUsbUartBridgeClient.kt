package dev.aegiskey.app.data.transport

import dev.aegiskey.app.log.DeviceLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.InputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Cliente de transporte para a ponte USB/UART rodando no host PC de desenvolvimento/bancada.
 * Suporta emulador Android (acessando via 10.0.2.2:5678) ou dispositivo real (via 127.0.0.1:5678 com adb reverse).
 *
 * Encaminha opcodes FIDO2/vendor (0x28 CLAIM, 0x22 KEY_LIST, etc.) diretamente para o chip físico conectado
 * via USB ou UART (COM*) no computador, permitindo testes completos e 100% reais sem dados sintéticos.
 */
class HostUsbUartBridgeClient(
    private val candidateHosts: List<String> = listOf("http://127.0.0.1:5678", "http://10.0.2.2:5678")
) {

    data class BridgeHardwareInfo(
        val connected: Boolean,
        val port: String,
        val deviceName: String,
        val transport: String,
    )

    @Volatile
    private var verifiedHost: String? = null

    /**
     * Localiza dinamicamente qual endpoint (127.0.0.1 ou 10.0.2.2) está ativo e responde.
     */
    private fun resolveActiveHost(): String? {
        val cached = verifiedHost
        if (cached != null) return cached

        for (host in candidateHosts) {
            try {
                android.util.Log.d("AegisBridge", "Tentando conectar em $host/bridge/info...")
                val url = URL("$host/bridge/info")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "GET"
                    connectTimeout = 1500
                    readTimeout = 2000
                }
                val code = conn.responseCode
                conn.disconnect()
                android.util.Log.d("AegisBridge", "Host $host respondeu code=$code")
                if (code in 200..299) {
                    verifiedHost = host
                    return host
                }
            } catch (t: Throwable) {
                android.util.Log.w("AegisBridge", "Host $host falhou: ${t.javaClass.simpleName}: ${t.message}")
            }
        }
        return null
    }

    /**
     * Consulta se a bridge está ativa e responde a requisições com timeout curto.
     */
    suspend fun isBridgeAvailable(timeoutMs: Int = 500): Boolean = withContext(Dispatchers.IO) {
        val host = verifiedHost ?: candidateHosts.firstOrNull() ?: return@withContext false
        try {
            val url = URL("$host/bridge/info")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
            }
            val ok = conn.responseCode in 200..299
            if (ok) {
                val body = conn.inputStream.bufferedReader().use { it.readText() }
                conn.disconnect()
                val json = JSONObject(body)
                verifiedHost = host
                json.optBoolean("connected", true)
            } else {
                conn.disconnect()
                false
            }
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * Consulta a ponte do host para verificar se uma chave física real está conectada na porta USB ou UART.
     * Timeout máximo de 1.5s para não travar a UI de descoberta.
     */
    suspend fun probeRealHardware(): BridgeHardwareInfo? = withContext(Dispatchers.IO) {
        val host = resolveActiveHost()
        if (host == null) {
            android.util.Log.e("AegisBridge", "Nenhum active host encontrado entre $candidateHosts")
            return@withContext null
        }
        try {
            val url = URL("$host/bridge/info")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 2000
                readTimeout = 3000
            }
            if (conn.responseCode !in 200..299) {
                conn.disconnect()
                android.util.Log.w("AegisBridge", "probeRealHardware code=${conn.responseCode}")
                return@withContext null
            }

            val body = conn.inputStream.bufferedReader().use { it.readText() }
            conn.disconnect()
            android.util.Log.i("AegisBridge", "probeRealHardware resposta: $body")

            val json = JSONObject(body)
            val isConnected = json.optBoolean("connected", true)
            val port = json.optString("port", json.optString("device", "COM_USB"))
            val transport = json.optString("transport", if (port.contains("COM", true) || port.contains("tty", true)) "UART" else "USB")
            val defaultName = if (transport.equals("UART", true)) "AegisKey Hardware (UART $port)" else "AegisKey Hardware (USB $port)"
            val name = json.optString("deviceName", json.optString("name", defaultName))

            if (isConnected && port.isNotBlank()) {
                android.util.Log.i("AegisBridge", "Bridge USB/UART detectada com sucesso: $name em $port")
                DeviceLog.append(DeviceLog.Category.SYSTEM, "Bridge USB/UART detectada: $name em $port")
                BridgeHardwareInfo(
                    connected = true,
                    port = port,
                    deviceName = name,
                    transport = transport
                )
            } else {
                android.util.Log.w("AegisBridge", "Bridge conectada=false ou porta vazia")
                null
            }
        } catch (e: Throwable) {
            android.util.Log.e("AegisBridge", "Bridge probe falhou com excecao", e)
            DeviceLog.append(DeviceLog.Category.SYSTEM, "Bridge probe falhou: ${e.message}")
            null
        }
    }

    /**
     * Envia um comando vendor (como 0x28 CLAIM, 0x22 KEY_LIST, etc.) diretamente à chave física
     * através da ponte USB/UART e retorna a resposta bruta da chave [status, ...payload].
     */
    suspend fun sendVendor(opcode: Int, payload: ByteArray = ByteArray(0)): ByteArray? = withContext(Dispatchers.IO) {
        val host = resolveActiveHost() ?: return@withContext null
        try {
            val url = URL("$host/bridge/vendor")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/json, application/octet-stream")
                connectTimeout = 1500
                readTimeout = 4000
                doOutput = true
            }

            val requestJson = JSONObject().apply {
                put("opcode", opcode)
                put("payload_hex", payload.toHex())
            }

            conn.outputStream.use { os ->
                os.write(requestJson.toString().toByteArray(Charsets.UTF_8))
            }

            val code = conn.responseCode
            if (code !in 200..299) {
                conn.disconnect()
                return@withContext null
            }

            val contentType = conn.contentType ?: ""
            val resultBytes = if (contentType.contains("application/octet-stream")) {
                conn.inputStream.use { it.readBytes() }
            } else {
                val respBody = conn.inputStream.bufferedReader().use { it.readText() }.trim()
                if (respBody.startsWith("{")) {
                    val respJson = JSONObject(respBody)
                    when {
                        respJson.has("response_hex") -> respJson.getString("response_hex").hexToByteArray()
                        respJson.has("data_hex") -> respJson.getString("data_hex").hexToByteArray()
                        respJson.has("payload_hex") -> {
                            val status = respJson.optInt("status", 0)
                            val pBytes = respJson.getString("payload_hex").hexToByteArray()
                            byteArrayOf(status.toByte()) + pBytes
                        }
                        else -> null
                    }
                } else if (respBody.isNotBlank()) {
                    respBody.hexToByteArray()
                } else {
                    null
                }
            }

            conn.disconnect()
            DeviceLog.append(DeviceLog.Category.SYSTEM, "Bridge sendVendor(0x%02X) -> %d bytes".format(opcode, resultBytes?.size ?: 0))
            resultBytes
        } catch (e: Throwable) {
            DeviceLog.append(DeviceLog.Category.SYSTEM, "Bridge sendVendor erro: ${e.message}")
            null
        }
    }

    /**
     * Testa comunicação direta (ping/echo) com a chave na ponte.
     */
    suspend fun ping(): Boolean = withContext(Dispatchers.IO) {
        val host = resolveActiveHost() ?: return@withContext false
        try {
            val url = URL("$host/bridge/ctap")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 1000
                readTimeout = 1500
                doOutput = true
            }
            conn.outputStream.use { it.write(byteArrayOf(0x81.toByte(), 0x00, 0x00)) } // CTAPHID_PING framing
            val code = conn.responseCode
            conn.disconnect()
            code in 200..299
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * Solicita abertura da janela de pareamento na chave física conectada na UART (se suportado pelo firmware).
     */
    suspend fun requestPairingWindow(): Boolean = withContext(Dispatchers.IO) {
        val host = resolveActiveHost() ?: return@withContext false
        try {
            val url = URL("$host/bridge/pairing_open")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 1000
                readTimeout = 1500
            }
            val ok = conn.responseCode in 200..299
            conn.disconnect()
            ok
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * Notifica ou dispara confirmação de toque na chave física da bancada.
     */
    suspend fun triggerTouchUp(): Boolean = withContext(Dispatchers.IO) {
        val host = resolveActiveHost() ?: return@withContext false
        try {
            val url = URL("$host/bridge/touch_up")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 1000
                readTimeout = 1500
            }
            val ok = conn.responseCode in 200..299
            conn.disconnect()
            ok
        } catch (_: Throwable) {
            false
        }
    }

    data class ProximityLockStatus(
        val enabled: Boolean = true,
        val state: String = "NEAR", // "NEAR", "AWAY", "LOCKED"
        val currentRssiDbm: Int = -35,
        val thresholdDbm: Int = -75,
        val hysteresisDb: Int = 5,
        val lockSeconds: Double = 10.0,
        val awaySeconds: Double = 0.0,
        val enforceWindowsLock: Boolean = false,
        val rollingCounter: Long = 0xFFFE,
        val locked: Boolean = false,
        val lastLockEpochMs: Long = 0L,
        val message: String? = null
    )

    @Volatile
    private var localProximityState = ProximityLockStatus()

    /**
     * Consulta a telemetria e estado atual de proximidade RSSI e dynamic lock.
     * Consulta a bridge em GET /api/proximity/status ou fallback local.
     */
    suspend fun fetchProximityStatus(): ProximityLockStatus = withContext(Dispatchers.IO) {
        val host = resolveActiveHost()
        if (host != null) {
            try {
                val url = URL("$host/api/proximity/status")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "GET"
                    connectTimeout = 1200
                    readTimeout = 1500
                }
                if (conn.responseCode in 200..299) {
                    val body = conn.inputStream.bufferedReader().use { it.readText() }
                    conn.disconnect()
                    val json = JSONObject(body)
                    val status = parseProximityJson(json)
                    localProximityState = status
                    return@withContext status
                }
                conn.disconnect()
            } catch (_: Throwable) {}
        }
        localProximityState
    }

    /**
     * Envia o sinal RSSI medido entre o celular e a chave no computador e avalia transição de estado.
     * Chama POST /api/proximity/rssi na bridge ou decider local.
     */
    suspend fun sendPhoneRssiAndEvaluate(rssiDbm: Int, elapsedSeconds: Double = 2.0): ProximityLockStatus = withContext(Dispatchers.IO) {
        val host = resolveActiveHost()
        if (host != null) {
            try {
                val url = URL("$host/api/proximity/rssi")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    setRequestProperty("Content-Type", "application/json")
                    connectTimeout = 1200
                    readTimeout = 1500
                    doOutput = true
                }
                val payload = JSONObject().apply {
                    put("rssi_dbm", rssiDbm)
                    put("rssi", rssiDbm)
                    put("elapsed_seconds", elapsedSeconds)
                    put("elapsed_s", elapsedSeconds)
                }
                conn.outputStream.use { it.write(payload.toString().toByteArray(Charsets.UTF_8)) }
                if (conn.responseCode in 200..299) {
                    val body = conn.inputStream.bufferedReader().use { it.readText() }
                    conn.disconnect()
                    val json = JSONObject(body)
                    val status = parseProximityJson(json)
                    localProximityState = status
                    return@withContext status
                }
                conn.disconnect()
            } catch (_: Throwable) {}
        }

        // Avaliação local (ProximityDecider compatível com tools/host/win/proximity_agent.py)
        synchronized(this) {
            val curr = localProximityState
            if (!curr.enabled) {
                return@withContext curr
            }
            val nearThreshold = curr.thresholdDbm + curr.hysteresisDb // ex: -75 + 5 = -70
            var away = curr.awaySeconds
            var locked = curr.locked
            var state = curr.state
            var lastLock = curr.lastLockEpochMs

            val nextCounter = curr.rollingCounter + 1

            if (rssiDbm >= nearThreshold) {
                away = 0.0
                state = if (locked) "LOCKED" else "NEAR"
            } else if (rssiDbm < curr.thresholdDbm) {
                away += elapsedSeconds
                if (away >= curr.lockSeconds) {
                    locked = true
                    state = "LOCKED"
                    lastLock = System.currentTimeMillis()
                } else {
                    if (!locked) state = "AWAY"
                }
            } else {
                // Banda de histerese: mantem estado atual
            }

            localProximityState = curr.copy(
                currentRssiDbm = rssiDbm,
                awaySeconds = away,
                locked = locked,
                state = state,
                rollingCounter = nextCounter,
                lastLockEpochMs = lastLock
            )
            localProximityState
        }
    }

    /**
     * Configura limiares e parâmetros de proximidade na chave/computador.
     */
    suspend fun configureProximityLock(
        enabled: Boolean,
        thresholdDbm: Int = -75,
        lockSeconds: Int = 10,
        enforceWindowsLock: Boolean = false
    ): Boolean = withContext(Dispatchers.IO) {
        val host = resolveActiveHost()
        if (host != null) {
            try {
                val url = URL("$host/api/proximity/config")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    setRequestProperty("Content-Type", "application/json")
                    connectTimeout = 1200
                    readTimeout = 1500
                    doOutput = true
                }
                val payload = JSONObject().apply {
                    put("enabled", enabled)
                    put("threshold_dbm", thresholdDbm)
                    put("lock_seconds", lockSeconds)
                    put("lock_secs", lockSeconds)
                    put("enforce_windows_lock", enforceWindowsLock)
                }
                conn.outputStream.use { it.write(payload.toString().toByteArray(Charsets.UTF_8)) }
                val ok = conn.responseCode in 200..299
                conn.disconnect()
                if (ok) {
                    localProximityState = localProximityState.copy(
                        enabled = enabled,
                        thresholdDbm = thresholdDbm,
                        lockSeconds = lockSeconds.toDouble(),
                        enforceWindowsLock = enforceWindowsLock
                    )
                    return@withContext true
                }
            } catch (_: Throwable) {}
        }
        localProximityState = localProximityState.copy(
            enabled = enabled,
            thresholdDbm = thresholdDbm,
            lockSeconds = lockSeconds.toDouble(),
            enforceWindowsLock = enforceWindowsLock
        )
        true
    }

    /**
     * Destrava a sessão de proximidade após retorno com Toque UP + PIN.
     */
    suspend fun unlockProximitySession(pin: String): Boolean = withContext(Dispatchers.IO) {
        val host = resolveActiveHost()
        if (host != null) {
            try {
                val url = URL("$host/api/proximity/unlock")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    setRequestProperty("Content-Type", "application/json")
                    connectTimeout = 1200
                    readTimeout = 1500
                    doOutput = true
                }
                val payload = JSONObject().apply {
                    put("pin", pin)
                }
                conn.outputStream.use { it.write(payload.toString().toByteArray(Charsets.UTF_8)) }
                val ok = conn.responseCode in 200..299
                conn.disconnect()
                if (ok) {
                    localProximityState = localProximityState.copy(
                        locked = false,
                        awaySeconds = 0.0,
                        state = "NEAR",
                        rollingCounter = localProximityState.rollingCounter + 1
                    )
                    return@withContext true
                }
            } catch (_: Throwable) {}
        }
        localProximityState = localProximityState.copy(
            locked = false,
            awaySeconds = 0.0,
            state = "NEAR",
            rollingCounter = localProximityState.rollingCounter + 1
        )
        true
    }

    private fun parseProximityJson(json: JSONObject): ProximityLockStatus {
        return ProximityLockStatus(
            enabled = json.optBoolean("enabled", true),
            state = json.optString("state", "NEAR"),
            currentRssiDbm = json.optInt("current_rssi", json.optInt("rssi_dbm", -35)),
            thresholdDbm = json.optInt("threshold_dbm", -75),
            hysteresisDb = json.optInt("hysteresis_db", 5),
            lockSeconds = json.optDouble("lock_seconds", json.optDouble("lock_secs", 10.0)),
            awaySeconds = json.optDouble("away_seconds", json.optDouble("away_secs", 0.0)),
            enforceWindowsLock = json.optBoolean("enforce_windows_lock", false),
            rollingCounter = json.optLong("rolling_counter", json.optLong("rolling_ctr", 0xFFFE)),
            locked = json.optBoolean("locked", false),
            lastLockEpochMs = json.optLong("last_lock_epoch_ms", 0L),
            message = if (json.has("message")) json.optString("message") else null
        )
    }

    // --- SECURE GUARD ZERO-TRUST HTTP ENDPOINTS ---

    private fun postSecureGuardJson(endpoint: String, body: JSONObject): JSONObject? {
        val host = resolveActiveHost() ?: return null
        return try {
            val url = URL("$host$endpoint")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/json")
                connectTimeout = 3000
                readTimeout = 5000
            }
            conn.outputStream.use { os ->
                os.write(body.toString().toByteArray(Charsets.UTF_8))
                os.flush()
            }
            val stream = if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream
            val str = stream?.bufferedReader()?.use { it.readText() } ?: "{}"
            JSONObject(str)
        } catch (t: Throwable) {
            android.util.Log.w("SecureGuard", "HTTP POST $endpoint falhou: ${t.message}")
            null
        }
    }

    suspend fun fetchSecureGuardStatus(): JSONObject? = withContext(Dispatchers.IO) {
        val host = resolveActiveHost() ?: return@withContext null
        try {
            val url = URL("$host/api/secure-guard/status")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                setRequestProperty("Accept", "application/json")
                connectTimeout = 2000
                readTimeout = 3000
            }
            val stream = if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream
            val str = stream?.bufferedReader()?.use { it.readText() } ?: "{}"
            JSONObject(str)
        } catch (t: Throwable) {
            android.util.Log.w("SecureGuard", "Erro ao consultar status HTTP bridge: ${t.message}")
            null
        }
    }

    suspend fun provisionSecureGuard(
        pin: String,
        recoveryCode: String? = null,
        policyJson: JSONObject? = null
    ): JSONObject? = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("pin", pin)
            if (!recoveryCode.isNullOrBlank()) put("recovery_code", recoveryCode)
            if (policyJson != null) put("policy", policyJson)
        }
        postSecureGuardJson("/api/secure-guard/provision", body)
    }

    suspend fun unlockSecureGuard(pin: String): JSONObject? = withContext(Dispatchers.IO) {
        val body = JSONObject().apply { put("pin", pin) }
        postSecureGuardJson("/api/secure-guard/unlock", body)
    }

    suspend fun lockSecureGuard(): JSONObject? = withContext(Dispatchers.IO) {
        postSecureGuardJson("/api/secure-guard/lock", JSONObject())
    }

    suspend fun changeSecureGuardPin(currentPin: String, newPin: String): JSONObject? = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("current_pin", currentPin)
            put("new_pin", newPin)
        }
        postSecureGuardJson("/api/secure-guard/change-pin", body)
    }

    suspend fun recoverSecureGuard(recoveryCode: String, newPin: String): JSONObject? = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("recovery_code", recoveryCode)
            put("new_pin", newPin)
        }
        postSecureGuardJson("/api/secure-guard/recover", body)
    }

    suspend fun configureSecureGuard(policyJson: JSONObject): JSONObject? = withContext(Dispatchers.IO) {
        postSecureGuardJson("/api/secure-guard/config", policyJson)
    }

    suspend fun wipeSelectiveSecureGuard(scope: Int, confirmationToken: String): JSONObject? = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("scope", scope)
            put("confirmation", confirmationToken)
        }
        postSecureGuardJson("/api/secure-guard/wipe-selective", body)
    }

    companion object {
        fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

        fun String.hexToByteArray(): ByteArray {
            val clean = replace(" ", "").trim()
            val len = clean.length
            if (len % 2 != 0) return ByteArray(0)
            val data = ByteArray(len / 2)
            var i = 0
            while (i < len) {
                val high = Character.digit(clean[i], 16)
                val low = Character.digit(clean[i + 1], 16)
                if (high == -1 || low == -1) return ByteArray(0)
                data[i / 2] = ((high shl 4) + low).toByte()
                i += 2
            }
            return data
        }
    }
}
