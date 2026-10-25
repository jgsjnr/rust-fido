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
