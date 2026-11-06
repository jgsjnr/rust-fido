package dev.aegiskey.app.data.repository

import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.data.cbor.SecureGuardCbor
import dev.aegiskey.app.data.transport.BleKeyTransport
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import dev.aegiskey.app.domain.repository.ConnectedKeysRepository
import dev.aegiskey.app.domain.repository.SecureGuardRepository
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.transportlock.TransportLossCause
import dev.aegiskey.app.transportlock.TransportSessionLock
import dev.aegiskey.app.transportlock.TransportSnapshot
import dev.aegiskey.app.usb.UsbCtaphid
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Implementação do repositório Secure Guard para Android.
 *
 * Despacha ordens via HostUsbUartBridgeClient (quando bridge estiver ativa),
 * UsbCtaphid (OTG direto com opcodes 0x3A..0x3E) ou BleKeyTransport (BLE direto).
 *
 * Imune a erros de com.sun.jna.Native: utiliza o parser CBOR puro de SecureGuardCbor
 * para empacotar requisições e decodificar envelopes binários retornados pelo hardware.
 * Nunca persiste PIN ou Recovery Code em armazenamento local.
 */
class SecureGuardRepositoryImpl(
    private val hostBridgeClient: HostUsbUartBridgeClient,
    private val usbCtaphid: UsbCtaphid? = null,
    private val bleKeyTransport: BleKeyTransport? = null,
    private val connectedKeysRepository: ConnectedKeysRepository? = null,
    private val simulatedTransport: SimulatedRenodeTransport? = null
) : SecureGuardRepository {

    companion object {
        const val OP_TRIGGER_PAIRING_OPEN: Int = 0x2F
        const val OP_RECOVERY_UNLOCK: Int = 0x2D

        /**
         * Janela de validade do PIN em RAM quando não há `session_remaining_ms`
         * autoritativo de um 0x3A fresco (ex.: atribuição direta em testes ou
         * fluxos legados). O firmware usa 300_000 ms como duração padrão de
         * sessão; todo 0x3A real sobrescreve com o valor atestado.
         */
        const val DEFAULT_SESSION_WINDOW_MS: Long = 300_000L

        /**
         * Chave mestra de mock em tempo de execução (builds debug apenas):
         * quando true E [simulatedTransport] presente E `BuildConfig.DEBUG`,
         * o Secure Guard é roteado pelo transporte simulado determinístico
         * (respostas CBOR 0x3A..0x3E). Release ignora (fail-closed, hardware real).
         */
        @Volatile
        var mockRoutingEnabled: Boolean = false

        /**
         * H-02: PIN verificado da sessão, em RAM apenas. A validade é
         * vinculada ao `session_remaining_ms` atestado pelo 0x3A: expirou
         * (ou sessão zerada/bloqueada) => PIN descartado. Nunca persiste.
         */
        @Volatile
        var lastVerifiedSessionPin: String? = null
            set(value) {
                field = value
                if (value.isNullOrBlank()) {
                    sessionPinExpiresAtMs = 0L
                } else if (sessionPinExpiresAtMs <= System.currentTimeMillis()) {
                    sessionPinExpiresAtMs = System.currentTimeMillis() + DEFAULT_SESSION_WINDOW_MS
                }
            }

        /**
         * H-02: deadline wall-clock (ms) até o qual o PIN em RAM é válido.
         * Atualizado a cada 0x3A autoritativo (`agora + session_remaining_ms`).
         */
        @Volatile
        var sessionPinExpiresAtMs: Long = 0L

        fun clearSessionPin() {
            lastVerifiedSessionPin = null
            sessionPinExpiresAtMs = 0L
        }

        /**
         * H-02: validade do PIN de sessão. Expirado (deadline 0x3A estourado
         * ou sessão zerada) => descarta imediatamente e retorna false.
         */
        fun isSessionPinValid(): Boolean {
            if (!hasLiveSessionPin()) {
                if (!lastVerifiedSessionPin.isNullOrBlank()) clearSessionPin()
                return false
            }
            return true
        }

        /**
         * H-02: leitura pura (sem efeitos) da validade — usada onde um 0x3A
         * autoritativo fresco ainda pode renovar a deadline (getStatus).
         */
        fun hasLiveSessionPin(): Boolean =
            !lastVerifiedSessionPin.isNullOrBlank() &&
                System.currentTimeMillis() < sessionPinExpiresAtMs

        /**
         * H-02: único acesso ao PIN em RAM fora do repositório. Retorna null
         * quando expirado (fail-closed), nunca um PIN morto.
         */
        fun currentSessionPin(): String? =
            if (isSessionPinValid()) lastVerifiedSessionPin else null

        /**
         * H-02: ancora o PIN em RAM no `session_remaining_ms` atestado pelo
         * 0x3A. Sessão viva com saldo > 0 renova a deadline; qualquer outro
         * estado (LOCKED, saldo zerado, expirado) descarta o PIN.
         */
        fun refreshSessionPinFromStatus(status: dev.aegiskey.app.domain.model.SecureGuardStatus) {
            if (status.isUnlocked && status.sessionRemainingMs > 0L) {
                if (!lastVerifiedSessionPin.isNullOrBlank()) {
                    sessionPinExpiresAtMs = System.currentTimeMillis() + status.sessionRemainingMs
                }
            } else {
                clearSessionPin()
            }
        }
    }

    private fun isMockRoutingActive(): Boolean =
        mockRoutingEnabled &&
            simulatedTransport != null &&
            dev.aegiskey.app.BuildConfig.DEBUG

    private val _statusFlow = MutableStateFlow(SecureGuardStatus())
    override val statusFlow: StateFlow<SecureGuardStatus> = _statusFlow.asStateFlow()

    init {
        usbCtaphid?.addOnHardwareDetachedListener {
            onTransportLost(setOf(TransportLossCause.USB_CABLE_DOWN))
        }
        usbCtaphid?.addOnHardwareAttachedListener {
            CoroutineScope(Dispatchers.IO).launch {
                runCatching { getStatus() }
            }
        }
        bleKeyTransport?.client?.state?.onEach { bleState ->
            if (bleState.connection != AegisBleClient.Connection.READY) {
                val isUsbPresent = usbCtaphid?.isUsbPhysicallyPresent() ?: false
                if (!isUsbPresent) {
                    onTransportLost(setOf(TransportLossCause.BLE_DISCONNECTED))
                }
            }
        }?.launchIn(CoroutineScope(Dispatchers.IO))
    }

    override fun onHardwareDetached() {
        lastVerifiedSessionPin = null
        clearSessionPin()
        val lockedStatus = _statusFlow.value.copy(
            state = SecureGuardStateEnum.LOCKED,
            isUnlocked = false,
            sessionRemainingMs = 0L,
            failedAttempts = 0,
            rateLimitRemainingMs = 0L
        )
        _statusFlow.value = lockedStatus
    }

    /**
     * Transport-loss auto-lock (BT/Wi-Fi/cabo/bridge). Same fail-closed
     * effect as a hardware detach — LOCKED, session PIN wiped from memory —
     * with the loss cause attributed by the transportlock module for logs.
     */
    override fun onTransportLost(causes: Set<TransportLossCause>) {
        if (causes.isEmpty()) return
        DeviceLog.append(
            DeviceLog.Category.LOCK,
            "transport lost -> LOCKED (" + causes.joinToString(",") + ")"
        )
        onHardwareDetached()
    }

    /**
     * Evaluates an observed transport snapshot for the session carrier and
     * locks when the carrier is gone. Returns true when it locked. Pure
     * translation of [TransportSessionLock.evaluate] into session effects.
     */
    fun notifyTransportSnapshot(
        activeTransport: dev.aegiskey.app.domain.model.ConnectionTransportType?,
        snapshot: TransportSnapshot,
    ): Boolean {
        val decision = TransportSessionLock.evaluate(activeTransport, snapshot)
        if (decision.shouldLock) onTransportLost(decision.causes)
        return decision.shouldLock
    }

    private suspend fun sendHardwareVendor(opcode: Int, payload: ByteArray): ByteArray? {
        // 0. Mock determinístico (debug apenas): simulador antes do hardware real.
        if (isMockRoutingActive()) {
            val resp = simulatedTransport?.sendVendor(opcode, payload)
            if (resp != null && resp.isNotEmpty()) return resp
        }

        // 1. Tenta USB OTG se conectado fisicamente
        val usb = usbCtaphid
        if (usb != null && usb.isUsbPhysicallyPresent()) {
            val resp = usb.sendVendor(opcode, payload)
            if (resp != null && resp.isNotEmpty()) return resp
        }

        // 2. Tenta BLE se pronto
        val ble = bleKeyTransport
        if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
            val resp = ble.sendVendor(opcode, payload)
            if (resp != null && resp.isNotEmpty()) return resp
        }

        // 3. Fallback: Host Bridge via vendor endpoint
        val bridgeResp = hostBridgeClient.sendVendor(opcode, payload)
        if (bridgeResp != null && bridgeResp.isNotEmpty()) return bridgeResp

        // 4. Última tentativa nos transportes caso conexão estivesse em transição
        if (usb != null) {
            val resp = usb.sendVendor(opcode, payload)
            if (resp != null && resp.isNotEmpty()) return resp
        }
        if (ble != null) {
            val resp = ble.sendVendor(opcode, payload)
            if (resp != null && resp.isNotEmpty()) return resp
        }

        return null
    }

    /**
     * Mensagem de erro do unlock direto ao silício (CBOR 0x3B via USB/BLE/
     * vendor): erro do silício verbatim + contador autoritativo
     * `remaining_attempts` (paridade com `app-tray/aegis_tray.py`
     * `_format_unlock_error`). O ViewModel preserva mensagens com
     * "Restam"/"tentativas" verbatim, então o usuário sempre vê o veredito
     * real do silício — nunca um palpite do espelho.
     */
    private fun unlockFailureMessage(unlockRes: SecureGuardCbor.UnlockResult): String {
        val remaining = unlockRes.remainingAttempts
        val siliconError = unlockRes.errorMessage?.takeIf { it.isNotBlank() }
        if (siliconError != null &&
            !siliconError.contains("Restam", ignoreCase = true) &&
            !siliconError.contains("tentativa", ignoreCase = true)
        ) {
            return "$siliconError (Restam $remaining tentativas.)"
        }
        return siliconError ?: (
            if (remaining == 0) "Limite de tentativas excedido. Cofre bloqueado. (Restam 0 tentativas.)"
            else "PIN incorreto. Restam $remaining tentativas."
        )
    }

    /**
     * Veredito autoritativo do silício via `POST /api/secure-guard/unlock`
     * (compat da bridge: ela mesma resolve o 0x3B estrito no silício e
     * espelha os contadores; `silicon_reachable=false` é fail-closed).
     * Campos `failed/remaining` aqui são os reais — o espelho
     * (`GET /api/secure-guard/status`) nunca decide autenticação.
     */
    private data class BridgeUnlockVerdict(
        val success: Boolean,
        val siliconReachable: Boolean,
        val state: SecureGuardStateEnum,
        val failedAttempts: Int,
        val remainingAttempts: Int?,
        val maxAttempts: Int,
        val rateLimitRemainingMs: Long,
        val sessionRemainingMs: Long?,
        val error: String?,
    )

    private fun parseBridgeUnlockVerdict(json: JSONObject): BridgeUnlockVerdict {
        val success = json.optBoolean("success", json.optBoolean("ok", false))
        // Compat legada: bridges antigas não enviam `silicon_reachable`;
        // nesse caso um `ok/success=true` continua valendo (não quebrar o
        // caminho de sucesso existente). `false` explícito é fail-closed.
        val reachable = if (json.has("silicon_reachable")) json.optBoolean("silicon_reachable", false) else true
        val stateName = json.optString("state_name", "")
        val stateCode = json.optInt("state", -1)
        val parsed = when {
            stateName.isNotBlank() -> {
                val byName = SecureGuardStateEnum.fromString(stateName)
                if (byName == SecureGuardStateEnum.DEVICE_UNAVAILABLE && stateCode >= 0) {
                    SecureGuardStateEnum.fromWireCode(stateCode)
                } else byName
            }
            stateCode >= 0 -> SecureGuardStateEnum.fromWireCode(stateCode)
            else -> SecureGuardStateEnum.DEVICE_UNAVAILABLE
        }
        val state = if (parsed == SecureGuardStateEnum.DEVICE_UNAVAILABLE) {
            if (success) SecureGuardStateEnum.UNLOCKED else SecureGuardStateEnum.LOCKED
        } else parsed
        return BridgeUnlockVerdict(
            success = success,
            siliconReachable = reachable,
            state = state,
            failedAttempts = json.optInt("failed_attempts", 0),
            remainingAttempts = if (json.has("remaining_attempts")) json.optInt("remaining_attempts", 5) else null,
            maxAttempts = json.optInt("max_attempts", 5),
            rateLimitRemainingMs = json.optLong("rate_limit_remaining_ms", 0L),
            sessionRemainingMs = if (json.has("session_remaining_ms")) json.optLong("session_remaining_ms", 0L) else null,
            error = json.optString("error", "").takeIf { it.isNotBlank() },
        )
    }

    /**
     * Mensagem de erro do unlock via bridge (`POST /api/secure-guard/unlock`):
     * erro do silício verbatim + `remaining_attempts` real quando presente.
     * Sem contadores no JSON (bridge legada), não inventa número: repassa só
     * o erro. Formato espelha `unlockFailureMessage` (CBOR) e o recurso
     * `guard_unlock_incorrect_remaining`.
     */
    private fun bridgeUnlockFailureMessage(json: JSONObject): String {
        val remaining = if (json.has("remaining_attempts")) json.optInt("remaining_attempts", 5) else null
        val siliconError = json.optString("error", "").takeIf { it.isNotBlank() }
        if (siliconError != null &&
            !siliconError.contains("Restam", ignoreCase = true) &&
            !siliconError.contains("tentativa", ignoreCase = true)
        ) {
            return if (remaining != null) "$siliconError (Restam $remaining tentativas.)" else siliconError
        }
        return siliconError ?: (
            if (remaining == null) "PIN incorreto"
            else if (remaining == 0) "Limite de tentativas excedido. Cofre bloqueado. (Restam 0 tentativas.)"
            else "PIN incorreto. Restam $remaining tentativas."
        )
    }

    /**
     * Publica os contadores de negação do silício no espelho de exibição
     * ANTES de lançar a falha, para que selo/badge mostrem o
     * `failed/remaining` autoritativo mesmo que o próximo poll de status
     * atrase. Exibição apenas: não decide autenticação (a decisão já foi o
     * veredito 0x3B acima). Prefere o JSON do `POST /unlock` (silício via
     * bridge); sem contadores nele, usa o último veredito CBOR 0x3B.
     */
    private fun publishSiliconDenialCounters(
        bridgeJson: JSONObject?,
        cborDenial: SecureGuardCbor.UnlockResult?,
    ) {
        val hasBridgeCounters = bridgeJson != null && bridgeJson.has("remaining_attempts")
        val failed = when {
            hasBridgeCounters -> bridgeJson!!.optInt("failed_attempts", 0)
            cborDenial != null -> cborDenial.failedAttempts
            else -> return
        }
        val remaining = when {
            hasBridgeCounters -> bridgeJson!!.optInt("remaining_attempts", 5)
            cborDenial != null -> cborDenial.remainingAttempts
            else -> return
        }
        val rateLimitMs = when {
            hasBridgeCounters -> bridgeJson!!.optLong("rate_limit_remaining_ms", 0L)
            cborDenial != null -> cborDenial.rateLimitRemainingMs
            else -> 0L
        }
        val maxAttempts = when {
            hasBridgeCounters -> bridgeJson!!.optInt("max_attempts", 5)
            else -> 5
        }
        val siliconState = when {
            hasBridgeCounters -> parseBridgeUnlockVerdict(bridgeJson!!).state
            cborDenial != null -> cborDenial.state
            else -> SecureGuardStateEnum.LOCKED
        }
        val displayState = if (siliconState == SecureGuardStateEnum.UNLOCKED ||
            siliconState == SecureGuardStateEnum.UNPROVISIONED ||
            siliconState == SecureGuardStateEnum.DEVICE_UNAVAILABLE
        ) {
            SecureGuardStateEnum.LOCKED
        } else siliconState
        _statusFlow.value = _statusFlow.value.copy(
            state = displayState,
            isUnlocked = false,
            failedAttempts = failed,
            remainingAttempts = remaining,
            maxAttempts = maxAttempts,
            rateLimitRemainingMs = rateLimitMs,
            sessionRemainingMs = 0L,
        )
    }

    private fun sanitizeStatus(status: SecureGuardStatus): SecureGuardStatus {
        // H-02: PIN expirado conta como ausente (leitura pura: o 0x3A fresco
        // do getStatus ainda pode renovar a deadline em seguida).
        if (!hasLiveSessionPin() && _statusFlow.value.state == SecureGuardStateEnum.LOCKED) {
            if (status.state == SecureGuardStateEnum.RATE_LIMITED || status.rateLimitRemainingMs > 0) {
                return status.copy(
                    state = SecureGuardStateEnum.LOCKED,
                    isUnlocked = false,
                    rateLimitRemainingMs = 0L,
                    failedAttempts = 0
                )
            }
        }
        return status
    }

    override suspend fun getStatus(): Result<SecureGuardStatus> = withContext(Dispatchers.IO) {
        runCatching {
            val usb = usbCtaphid
            val isUsbPresent = usb?.isUsbPhysicallyPresent() ?: false
            val ble = bleKeyTransport
            val isBleConnected = ble?.client?.state?.value?.connection == AegisBleClient.Connection.READY

            // Sem USB físico e sem BLE: consulta a bridge ANTES de forçar LOCKED.
            // Só força LOCKED (e zera o PIN) se a bridge também não atestar
            // sessão provisionada com autoridade — nunca pule o bridge quando
            // ele detém a sessão viva; UNPROVISIONED sem transporte local é
            // ausência de sinal, nunca afirmação sobre o dispositivo.
            if (usb != null && !isUsbPresent && !isBleConnected) {
                if (isMockRoutingActive()) {
                    val mockResp = runCatching {
                        simulatedTransport?.sendVendor(0x3A, SecureGuardCbor.encodeStatusRequest())
                    }.getOrNull()
                    if (mockResp != null && mockResp.isNotEmpty()) {
                        val frame = SecureGuardCbor.parseTransportFrame(0x3A, mockResp)
                        val parsed = SecureGuardCbor.parseStatus(frame.cborPayload)
                        if (parsed != null) {
                            val safe = sanitizeStatus(parsed)
                            refreshSessionPinFromStatus(safe)
                            _statusFlow.value = safe
                            return@runCatching safe
                        }
                    }
                }
                val bridgeJson = runCatching { hostBridgeClient.fetchSecureGuardStatus() }.getOrNull()
                if (bridgeJson != null && (bridgeJson.optBoolean("ok", true) || bridgeJson.has("state") || bridgeJson.has("state_name"))) {
                    val parsed = parseStatusFromJson(bridgeJson)
                    // Fail-closed: sem transporte local vivo (USB destacado,
                    // BLE fora), UNPROVISIONED/sem-provisionamento vindo da
                    // bridge não é afirmação sobre o dispositivo — é ausência
                    // de sinal (daemon vivo sem dispositivo/sessão). Só uma
                    // sessão provisionada atestada pela bridge vence o LOCKED
                    // forçado; UNPROVISIONED exige canal vivo (USB/BLE/mock).
                    if (parsed.isProvisioned && parsed.state != SecureGuardStateEnum.UNPROVISIONED) {
                        val safe = sanitizeStatus(parsed)
                        refreshSessionPinFromStatus(safe)
                        _statusFlow.value = safe
                        return@runCatching safe
                    }
                }
                // Sem USB físico, sem BLE e sem autoridade na bridge: perda de
                // transporte em todos os caminhos sondados -> trava automática.
                onTransportLost(
                    setOf(
                        TransportLossCause.USB_CABLE_DOWN,
                        TransportLossCause.BLE_DISCONNECTED,
                        TransportLossCause.BRIDGE_OFFLINE,
                    )
                )
                return@runCatching _statusFlow.value
            }

            // 1. Tenta USB OTG se fisicamente presente
            if (usb != null && isUsbPresent) {
                val req = SecureGuardCbor.encodeStatusRequest()
                val resp = usb.sendVendor(0x3A, req)
                if (resp != null && resp.isNotEmpty()) {
                    val frame = SecureGuardCbor.parseTransportFrame(0x3A, resp)
                    val parsed = SecureGuardCbor.parseStatus(frame.cborPayload)
                    if (parsed != null) {
                        tryAutoPairBle(frame.cborPayload)
                        val safe = sanitizeStatus(parsed)
                        refreshSessionPinFromStatus(safe)
                        _statusFlow.value = safe
                        return@runCatching safe
                    }
                }
            }

            // 2. Tenta BLE se conectado
            if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
                val req = SecureGuardCbor.encodeStatusRequest()
                val resp = ble.sendVendor(0x3A, req)
                if (resp != null && resp.isNotEmpty()) {
                    val frame = SecureGuardCbor.parseTransportFrame(0x3A, resp)
                    val parsed = SecureGuardCbor.parseStatus(frame.cborPayload)
                    if (parsed != null) {
                        val safe = sanitizeStatus(parsed)
                        refreshSessionPinFromStatus(safe)
                        _statusFlow.value = safe
                        return@runCatching safe
                    }
                }
            }

            // 3. Tenta HTTP bridge client
            val json = hostBridgeClient.fetchSecureGuardStatus()
            if (json != null && (json.optBoolean("ok", true) || json.has("state") || json.has("state_name"))) {
                val parsed = parseStatusFromJson(json)
                val safe = sanitizeStatus(parsed)
                refreshSessionPinFromStatus(safe)
                _statusFlow.value = safe
                return@runCatching safe
            }

            // 4. Fallback genérico de hardware
            val req = SecureGuardCbor.encodeStatusRequest()
            val resp = sendHardwareVendor(0x3A, req)
            if (resp != null && resp.isNotEmpty()) {
                val frame = SecureGuardCbor.parseTransportFrame(0x3A, resp)
                val parsed = SecureGuardCbor.parseStatus(frame.cborPayload)
                if (parsed != null) {
                    if (isUsbPresent) {
                        tryAutoPairBle(frame.cborPayload)
                    }
                    val safe = sanitizeStatus(parsed)
                    refreshSessionPinFromStatus(safe)
                    _statusFlow.value = safe
                    return@runCatching safe
                }
            }

            // Se nenhum hardware respondeu, a chave está inacessível/desconectada:
            // encerra a sessão imediatamente (perda de transporte nos caminhos
            // sondados — USB/BLE quando existirem, mais a bridge sem autoridade).
            onTransportLost(
                buildSet {
                    if (usbCtaphid != null) add(TransportLossCause.USB_CABLE_DOWN)
                    if (bleKeyTransport != null) add(TransportLossCause.BLE_DISCONNECTED)
                    add(TransportLossCause.BRIDGE_OFFLINE)
                }
            )
            _statusFlow.value
        }
    }

    override suspend fun provision(
        pin: String,
        recoveryCode: String?,
        policy: SecureGuardPolicy?
    ): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            if (pin.length < 4) throw IllegalArgumentException("PIN deve ter no mínimo 4 caracteres")

            val polJson = policy?.let {
                JSONObject().apply {
                    put("wipe_on_5_failures", it.wipeOn5Failures)
                    put("protect_keys_and_aegn", it.protectKeysAndAegn)
                    put("protect_oath", it.protectOath)
                    put("test_mode_non_destructive_wipe", it.testModeNonDestructiveWipe)
                    put("session_duration_ms", it.sessionDurationMs)
                    put("inactivity_timeout_ms", it.inactivityTimeoutMs)
                }
            }

            var generatedRc: String? = null

            // 1. Tenta Hardware direto via CBOR (USB OTG, BLE ou Bridge Vendor)
            val encReq = SecureGuardCbor.encodeProvisionRequest(
                pin = pin.toByteArray(Charsets.UTF_8),
                recoveryCode = recoveryCode?.toByteArray(Charsets.UTF_8),
                policy = policy
            )
            val resp = sendHardwareVendor(0x3B, encReq)
            if (resp != null && resp.isNotEmpty()) {
                val frame = SecureGuardCbor.parseTransportFrame(0x3B, resp)
                val provRes = SecureGuardCbor.parseProvisionResult(frame.cborPayload)
                generatedRc = provRes?.recoveryCode?.takeIf { it.isNotEmpty() }
                    ?: recoveryCode
                    ?: "GEN-RECOVERY-CODE"
            }

            // 2. Tenta HTTP bridge se ativa (sincronizando se ambos existirem)
            val json = hostBridgeClient.provisionSecureGuard(pin, recoveryCode, polJson)
            if (json != null && (json.optBoolean("ok", false) || json.optString("status") == "provisioned")) {
                if (generatedRc == null) {
                    generatedRc = json.optString("recovery_code", recoveryCode ?: "GEN-RECOVERY-CODE")
                }
            }

            if (generatedRc != null) {
                lastVerifiedSessionPin = pin
                // H-02: ancora a deadline no saldo de sessão recém-aberto.
                sessionPinExpiresAtMs = System.currentTimeMillis() + 300_000L
                val usb = usbCtaphid
                if (usb != null && usb.isUsbPhysicallyPresent()) {
                    usb.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
                }
                val ble = bleKeyTransport
                if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
                    ble.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
                }
                runCatching {
                    hostBridgeClient.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
                }

                val provisionedStatus = _statusFlow.value.copy(
                    state = SecureGuardStateEnum.UNLOCKED,
                    isProvisioned = true,
                    isUnlocked = true,
                    failedAttempts = 0,
                    remainingAttempts = 5,
                    sessionRemainingMs = 300_000L,
                    lastGeneratedRecoveryCode = generatedRc
                )
                _statusFlow.value = provisionedStatus
                return@runCatching generatedRc
            }

            throw IllegalStateException(json?.optString("error") ?: "Falha ao provisionar Secure Guard")
        }
    }

    /**
     * Confirma o estado do dispositivo SOMENTE via round-trip real 0x3A ao
     * silício (USB/BLE direto ou vendor 0x3A via bridge — que também é o
     * silício, não o espelho). O espelho (`GET /api/secure-guard/status`)
     * é exibição fail-closed e NUNCA confirma provisionamento: um espelho
     * `Unprovisioned` não pode disparar provision, e um espelho `Locked`
     * não prova nada sobre o silício. Retorna null quando NENHUM transporte
     * ao silício responde com autoridade.
     */
    private suspend fun fetchConfirmedSiliconStatus(): SecureGuardStatus? {
        val usb = usbCtaphid
        if (usb != null && usb.isUsbPhysicallyPresent()) {
            val resp = runCatching { usb.sendVendor(0x3A, SecureGuardCbor.encodeStatusRequest()) }.getOrNull()
            if (resp != null && resp.isNotEmpty()) {
                val parsed = runCatching {
                    SecureGuardCbor.parseStatus(SecureGuardCbor.parseTransportFrame(0x3A, resp).cborPayload)
                }.getOrNull()
                if (parsed != null) return parsed
            }
        }

        val ble = bleKeyTransport
        if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
            val resp = runCatching { ble.sendVendor(0x3A, SecureGuardCbor.encodeStatusRequest()) }.getOrNull()
            if (resp != null && resp.isNotEmpty()) {
                val parsed = runCatching {
                    SecureGuardCbor.parseStatus(SecureGuardCbor.parseTransportFrame(0x3A, resp).cborPayload)
                }.getOrNull()
                if (parsed != null) return parsed
            }
        }

        // Vendor 0x3A via bridge = silício através da bridge (autoritativo),
        // diferente do espelho JSON de display. Usado quando não há USB/BLE
        // direto mas a bridge alcança o silício.
        val resp = runCatching { sendHardwareVendor(0x3A, SecureGuardCbor.encodeStatusRequest()) }.getOrNull()
        if (resp != null && resp.isNotEmpty()) {
            val parsed = runCatching {
                SecureGuardCbor.parseStatus(SecureGuardCbor.parseTransportFrame(0x3A, resp).cborPayload)
            }.getOrNull()
            if (parsed != null) return parsed
        }
        return null
    }

    override suspend fun unlock(pin: String): Result<SecureGuardStatus> = withContext(Dispatchers.IO) {
        runCatching {
            if (pin.length < 4) throw IllegalArgumentException("PIN deve ter no mínimo 4 caracteres")

            // Auto-provisionamento transparente SOMENTE com UNPROVISIONED confirmado
            // pelo SILÍCIO (round-trip real 0x3A). O espelho (GET status da
            // bridge) é exibição fail-closed e nunca confirma: um espelho
            // `Unprovisioned` jamais dispara provision (prova do bug: app dizia
            // "PIN incorreto" para o PIN correto porque o veredito nunca chegava
            // ao silício e o app confiava no espelho). Estado local forçado
            // (LOCKED sem transporte, UNPROVISIONED inicial sem resposta) também
            // nunca dispara provision.
            val confirmed = runCatching { fetchConfirmedSiliconStatus() }.getOrNull()
            if (confirmed != null && (confirmed.state == SecureGuardStateEnum.UNPROVISIONED || !confirmed.isProvisioned)) {
                provision(pin = pin, recoveryCode = null, policy = null).getOrThrow()
            }

            var hardwareUnlocked = false
            var hardwareError: String? = null
            // Vereditos do silício capturados por transporte para publicar os
            // contadores reais (failed/remaining) em vez de forjar 0/5.
            var cborSuccessVerdict: SecureGuardCbor.UnlockResult? = null
            var cborDenialVerdict: SecureGuardCbor.UnlockResult? = null
            // Falhas por transporte (USB -> BLE -> bridge -> fallback genérico).
            // Nenhuma falha individual interrompe as tentativas seguintes: o erro
            // agregado só é lançado após TODOS os transportes falharem.
            val transportErrors = mutableListOf<String>()
            val pinBytes = pin.toByteArray(Charsets.UTF_8)
            val encReq = SecureGuardCbor.encodeUnlockRequest(pinBytes)

            // Sincroniza diretamente com o transporte físico USB OTG se disponível
            val usb = usbCtaphid
            if (usb != null && usb.isUsbPhysicallyPresent()) {
                val resp = runCatching { usb.sendVendor(0x3B, encReq) }.getOrNull()
                if (resp != null && resp.isNotEmpty()) {
                    val frame = SecureGuardCbor.parseTransportFrame(0x3B, resp)
                    val unlockRes = SecureGuardCbor.parseUnlockResult(frame.status, frame.cborPayload)
                    if (unlockRes.success) {
                        hardwareUnlocked = true
                        cborSuccessVerdict = unlockRes
                        usb.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
                    } else {
                        cborDenialVerdict = unlockRes
                        transportErrors += "USB: " + unlockFailureMessage(unlockRes)
                    }
                } else {
                    transportErrors += "USB: sem resposta do hardware"
                }
            }

            // Sincroniza diretamente com o transporte BLE se disponível
            val ble = bleKeyTransport
            if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
                val resp = runCatching { ble.sendVendor(0x3B, encReq) }.getOrNull()
                if (resp != null && resp.isNotEmpty()) {
                    val frame = SecureGuardCbor.parseTransportFrame(0x3B, resp)
                    val unlockRes = SecureGuardCbor.parseUnlockResult(frame.status, frame.cborPayload)
                    if (unlockRes.success) {
                        hardwareUnlocked = true
                        if (cborSuccessVerdict == null) cborSuccessVerdict = unlockRes
                        ble.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
                    } else {
                        if (cborDenialVerdict == null) cborDenialVerdict = unlockRes
                        transportErrors += "BLE: " + unlockFailureMessage(unlockRes)
                    }
                } else {
                    transportErrors += "BLE: sem resposta do hardware"
                }
            }

            // Sincroniza com HTTP hostBridgeClient se disponível.
            // `POST /api/secure-guard/unlock` carrega o veredito do SILÍCIO
            // (a bridge resolve o 0x3B estrito no chip): `failed_attempts` /
            // `remaining_attempts` aqui são os reais. `silicon_reachable=false`
            // explícito é fail-closed (nunca autentica), e o espelho nunca é
            // consultado para decidir — só exibição.
            val json = hostBridgeClient.unlockSecureGuard(pin)
            val bridgeVerdict = json?.let { runCatching { parseBridgeUnlockVerdict(it) }.getOrNull() }
            val bridgeSuccess = bridgeVerdict != null && bridgeVerdict.success && bridgeVerdict.siliconReachable
            if (json != null && !bridgeSuccess && !hardwareUnlocked) {
                hardwareError = bridgeUnlockFailureMessage(json)
                transportErrors += "Bridge: $hardwareError"
            }

            // Fallback para outros transportes via sendHardwareVendor se nem USB nem BLE responderam
            if (!hardwareUnlocked && !bridgeSuccess && (usb == null || !usb.isUsbPhysicallyPresent()) && (ble == null || ble.client.state.value.connection != AegisBleClient.Connection.READY)) {
                val resp = runCatching { sendHardwareVendor(0x3B, encReq) }.getOrNull()
                if (resp != null && resp.isNotEmpty()) {
                    val frame = SecureGuardCbor.parseTransportFrame(0x3B, resp)
                    val unlockRes = SecureGuardCbor.parseUnlockResult(frame.status, frame.cborPayload)
                    if (unlockRes.success) {
                        hardwareUnlocked = true
                        if (cborSuccessVerdict == null) cborSuccessVerdict = unlockRes
                        sendHardwareVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
                    } else {
                        if (cborDenialVerdict == null) cborDenialVerdict = unlockRes
                        transportErrors += "Hardware: " + unlockFailureMessage(unlockRes)
                    }
                } else {
                    transportErrors += "Hardware: sem resposta dos transportes"
                }
            }

            if (!hardwareUnlocked && !bridgeSuccess) {
                // Espelho de exibição recebe os contadores do silício antes de
                // lançar, para o badge nunca exibir um `remaining` obsoleto.
                publishSiliconDenialCounters(json, cborDenialVerdict)
                val detail = transportErrors.filter { it.isNotBlank() }.joinToString(" | ")
                val base = hardwareError ?: "Chave não respondeu ou PIN incorreto. Verifique a conexão."
                DeviceLog.append(
                    DeviceLog.Category.LOCK,
                    "unlock negado pelo silício: " + (if (detail.isNotBlank()) "$base ($detail)" else base)
                )
                throw SecurityException(if (detail.isNotBlank()) "$base ($detail)" else base)
            }

            lastVerifiedSessionPin = pin
            // H-02: ancora a deadline no saldo de sessão recém-aberto.
            // O próximo 0x3A (getStatus) sobrescreve com o valor atestado.
            sessionPinExpiresAtMs = System.currentTimeMillis() + 300_000L
            val usbTransport = usbCtaphid
            if (usbTransport != null && usbTransport.isUsbPhysicallyPresent()) {
                usbTransport.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
            }
            val bleTransport = bleKeyTransport
            if (bleTransport != null && bleTransport.client.state.value.connection == AegisBleClient.Connection.READY) {
                bleTransport.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
            }
            runCatching {
                hostBridgeClient.sendVendor(OP_TRIGGER_PAIRING_OPEN, byteArrayOf())
            }

            // Estado honesto a partir do veredito do SILÍCIO (nunca forjado,
            // nunca o espelho): `failed/remaining` reais do 0x3B vencedor
            // (CBOR direto) ou do `POST /api/secure-guard/unlock`.
            // `session_remaining_ms` ausente no veredito = default de firmware
            // (300s); o próximo 0x3A atesta o saldo real.
            val siliconFailed: Int
            val siliconRemaining: Int
            val siliconMax: Int
            val siliconRateLimitMs: Long
            val siliconSessionMs: Long
            if (bridgeSuccess && bridgeVerdict != null && cborSuccessVerdict == null) {
                siliconFailed = bridgeVerdict.failedAttempts
                siliconRemaining = bridgeVerdict.remainingAttempts ?: 5
                siliconMax = bridgeVerdict.maxAttempts
                siliconRateLimitMs = bridgeVerdict.rateLimitRemainingMs
                siliconSessionMs = bridgeVerdict.sessionRemainingMs ?: 300_000L
            } else {
                val v = cborSuccessVerdict
                siliconFailed = v?.failedAttempts ?: 0
                siliconRemaining = v?.remainingAttempts ?: 5
                siliconMax = 5
                siliconRateLimitMs = v?.rateLimitRemainingMs ?: 0L
                siliconSessionMs = 300_000L
            }
            val unlockedStatus = _statusFlow.value.copy(
                state = SecureGuardStateEnum.UNLOCKED,
                isProvisioned = true,
                isUnlocked = true,
                failedAttempts = siliconFailed,
                remainingAttempts = siliconRemaining,
                maxAttempts = siliconMax,
                rateLimitRemainingMs = siliconRateLimitMs,
                sessionRemainingMs = siliconSessionMs
            )
            _statusFlow.value = unlockedStatus
            unlockedStatus
        }
    }

    override suspend fun lock(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            lastVerifiedSessionPin = null
            clearSessionPin()
            hostBridgeClient.lockSecureGuard()
            val encReq = SecureGuardCbor.encodeLockRequest()
            val usb = usbCtaphid
            if (usb != null && usb.isUsbPhysicallyPresent()) {
                usb.sendVendor(0x3C, encReq)
            }
            val ble = bleKeyTransport
            if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
                ble.sendVendor(0x3C, encReq)
            }
            sendHardwareVendor(0x3C, encReq)

            val lockedStatus = _statusFlow.value.copy(
                state = SecureGuardStateEnum.LOCKED,
                isProvisioned = true,
                isUnlocked = false,
                failedAttempts = 0,
                remainingAttempts = 5,
                rateLimitRemainingMs = 0L,
                sessionRemainingMs = 0L
            )
            _statusFlow.value = lockedStatus
            val fetched = runCatching { getStatus().getOrNull() }.getOrNull()
            if (fetched != null && (fetched.state == SecureGuardStateEnum.RATE_LIMITED || fetched.rateLimitRemainingMs > 0)) {
                _statusFlow.value = lockedStatus
            }
            Unit
        }
    }

    override suspend fun changePin(currentPin: String, newPin: String): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            if (newPin.length < 4) throw IllegalArgumentException("Novo PIN deve ter no mínimo 4 dígitos")
            val json = hostBridgeClient.changeSecureGuardPin(currentPin, newPin)
            if (json != null && (json.optBoolean("ok", false) || json.optString("status") == "pin_changed")) {
                getStatus()
                return@runCatching Unit
            }

            val encReq = SecureGuardCbor.encodeChangePinRequest(
                currentPin.toByteArray(Charsets.UTF_8),
                newPin.toByteArray(Charsets.UTF_8)
            )
            val resp = sendHardwareVendor(0x3B, encReq)
            if (resp != null && resp.isNotEmpty()) {
                getStatus()
                return@runCatching Unit
            }

            throw IllegalStateException(json?.optString("error") ?: "Falha ao alterar PIN")
        }
    }

    override suspend fun recover(recoveryCode: String, newPin: String): Result<String?> = withContext(Dispatchers.IO) {
        runCatching {
            if (newPin.length < 4) throw IllegalArgumentException("Novo PIN deve ter no mínimo 4 dígitos")
            val json = hostBridgeClient.recoverSecureGuard(recoveryCode, newPin)
            if (json != null && (json.optBoolean("ok", false) || json.optString("status") == "recovered")) {
                val newRc = if (json.has("new_recovery_code")) json.optString("new_recovery_code") else null
                getStatus()
                return@runCatching newRc
            }

            val encReq = SecureGuardCbor.encodeRecoverRequest(
                recoveryCode.toByteArray(Charsets.UTF_8),
                newPin.toByteArray(Charsets.UTF_8)
            )
            val resp = sendHardwareVendor(0x3B, encReq)
            if (resp != null && resp.isNotEmpty()) {
                val frame = SecureGuardCbor.parseTransportFrame(0x3B, resp)
                val decoded = SecureGuardCbor.decode(frame.cborPayload) as? Map<*, *>
                val newRc = decoded?.get("new_recovery_code") as? String
                getStatus()
                return@runCatching newRc
            }

            throw IllegalStateException(json?.optString("error") ?: "Falha na recuperação de emergência")
        }
    }

    override suspend fun updatePolicy(policy: SecureGuardPolicy): Result<SecureGuardPolicy> = withContext(Dispatchers.IO) {
        runCatching {
            val body = JSONObject().apply {
                put("wipe_on_5_failures", policy.wipeOn5Failures)
                put("protect_keys_and_aegn", policy.protectKeysAndAegn)
                put("protect_oath", policy.protectOath)
                put("test_mode_non_destructive_wipe", policy.testModeNonDestructiveWipe)
                put("session_duration_ms", policy.sessionDurationMs)
                put("inactivity_timeout_ms", policy.inactivityTimeoutMs)
            }
            val json = hostBridgeClient.configureSecureGuard(body)
            if (json != null && json.optBoolean("ok", false)) {
                getStatus()
                return@runCatching policy
            }

            val encReq = SecureGuardCbor.encodeConfigRequest(policy)
            val resp = sendHardwareVendor(0x3D, encReq)
            if (resp != null && resp.isNotEmpty()) {
                getStatus()
                return@runCatching policy
            }

            throw IllegalStateException(json?.optString("error") ?: "Falha ao configurar políticas")
        }
    }

    override suspend fun wipeSelective(scope: Int, confirmationToken: String): Result<Boolean> = withContext(Dispatchers.IO) {
        runCatching {
            var simulated = false
            var wipeSuccess = false

            val json = hostBridgeClient.wipeSelectiveSecureGuard(scope, confirmationToken)
            if (json != null && (json.optBoolean("ok", false) || json.optString("status") == "wiped")) {
                simulated = json.optBoolean("simulated", false)
                wipeSuccess = true
            }

            val encReq = SecureGuardCbor.encodeWipeRequest(scope, confirmationToken)
            val usb = usbCtaphid
            if (usb != null && usb.isUsbPhysicallyPresent()) {
                val resp = usb.sendVendor(0x3E, encReq)
                if (resp != null && resp.isNotEmpty()) {
                    wipeSuccess = true
                    val frame = SecureGuardCbor.parseTransportFrame(0x3E, resp)
                    val decoded = SecureGuardCbor.decode(frame.cborPayload) as? Map<*, *>
                    simulated = decoded?.get("simulated") as? Boolean ?: simulated
                }
            }

            val ble = bleKeyTransport
            if (ble != null && ble.client.state.value.connection == AegisBleClient.Connection.READY) {
                val resp = ble.sendVendor(0x3E, encReq)
                if (resp != null && resp.isNotEmpty()) {
                    wipeSuccess = true
                    val frame = SecureGuardCbor.parseTransportFrame(0x3E, resp)
                    val decoded = SecureGuardCbor.decode(frame.cborPayload) as? Map<*, *>
                    simulated = decoded?.get("simulated") as? Boolean ?: simulated
                }
            }

            if (!wipeSuccess) {
                val resp = sendHardwareVendor(0x3E, encReq)
                if (resp != null && resp.isNotEmpty()) {
                    val frame = SecureGuardCbor.parseTransportFrame(0x3E, resp)
                    val decoded = SecureGuardCbor.decode(frame.cborPayload) as? Map<*, *>
                    simulated = decoded?.get("simulated") as? Boolean ?: false
                    wipeSuccess = true
                }
            }

            if (!wipeSuccess) {
                throw IllegalStateException(json?.optString("error") ?: "Falha ao executar wipe")
            }

            lastVerifiedSessionPin = null
            val wipedStatus = SecureGuardStatus(
                state = SecureGuardStateEnum.UNPROVISIONED,
                isProvisioned = false,
                isUnlocked = false,
                failedAttempts = 0,
                remainingAttempts = 5,
                sessionRemainingMs = 0L,
                rateLimitRemainingMs = 0L,
                lastWipeSimulated = simulated
            )
            _statusFlow.value = wipedStatus
            simulated
        }
    }

    private fun parseStatusFromJson(json: JSONObject): SecureGuardStatus {
        val stateName = json.optString("state_name", "Unprovisioned")
        val stateCode = json.optInt("state", 0)
        val stateEnum = SecureGuardStateEnum.fromString(stateName).let {
            if (it == SecureGuardStateEnum.DEVICE_UNAVAILABLE) SecureGuardStateEnum.fromWireCode(stateCode) else it
        }

        val policy = SecureGuardPolicy(
            wipeOn5Failures = json.optBoolean("wipe_on_5_failures", false),
            sessionDurationMs = json.optLong("session_duration_ms", 300_000L),
            inactivityTimeoutMs = json.optLong("inactivity_timeout_ms", 300_000L),
            protectKeysAndAegn = json.optBoolean("protect_keys_and_aegn", true),
            protectOath = json.optBoolean("protect_oath", false),
            testModeNonDestructiveWipe = json.optBoolean("test_mode_non_destructive_wipe", false)
        )

        return SecureGuardStatus(
            state = stateEnum,
            isProvisioned = json.optBoolean("provisioned", stateEnum != SecureGuardStateEnum.UNPROVISIONED),
            isUnlocked = json.optBoolean("unlocked", stateEnum == SecureGuardStateEnum.UNLOCKED),
            failedAttempts = json.optInt("failed_attempts", 0),
            remainingAttempts = json.optInt("remaining_attempts", 5),
            maxAttempts = json.optInt("max_attempts", 5),
            rateLimitRemainingMs = json.optLong("rate_limit_remaining_ms", 0L),
            sessionRemainingMs = json.optLong("session_remaining_ms", 0L),
            policy = policy,
            lastWipeSimulated = json.optBoolean("last_wipe_simulated", false),
            auditCount = json.optLong("audit_count", 0L),
            lastGeneratedRecoveryCode = if (json.has("last_generated_recovery_code")) json.optString("last_generated_recovery_code") else null,
            // Contrato 0x3A `bench_active: bool` via espelho JSON da bridge;
            // ausente = false. Puro read-only, sem efeito de lock/wipe.
            benchActive = json.optBoolean("bench_active", false)
        )
    }

    private suspend fun tryAutoPairBle(cborPayload: ByteArray) {
        val decoded = SecureGuardCbor.decode(cborPayload) as? Map<*, *> ?: return
        val rawMac = decoded["device_ble_mac"]
        val macBytes = when (rawMac) {
            is ByteArray -> rawMac
            is List<*> -> rawMac.mapNotNull { (it as? Number)?.toByte() }.toByteArray()
            else -> null
        }
        val macStr = macBytes?.takeIf { it.size == 6 }?.joinToString(":") { "%02X".format(it) }
        val nameStr = decoded["device_ble_name"] as? String ?: "AegisKey"
        if (!macStr.isNullOrBlank()) {
            runCatching {
                connectedKeysRepository?.autoPairBleDevice(macStr, nameStr)
            }
        }
    }
}
