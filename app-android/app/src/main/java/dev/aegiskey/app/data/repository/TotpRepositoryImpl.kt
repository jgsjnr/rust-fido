package dev.aegiskey.app.data.repository

import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.DevicePresence
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.R
import dev.aegiskey.app.data.debug.DebugHardwareChipMock
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.transport.BleKeyTransport
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.data.transport.UsbKeyTransport
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DeviceError
import dev.aegiskey.app.domain.model.TotpAccountItem
import dev.aegiskey.app.domain.repository.ConnectedKeysRepository
import dev.aegiskey.app.domain.repository.TotpRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import java.util.UUID

class TotpRepositoryImpl(
    private val keysStore: EncryptedKeysStore,
    private val usbKeyTransport: UsbKeyTransport? = null,
    private val bleKeyTransport: BleKeyTransport? = null,
    private val simulatedRenodeTransport: SimulatedRenodeTransport,
    private val connectedKeysRepository: ConnectedKeysRepository,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO)
) : TotpRepository {

    // Construtor de compatibilidade para chamadas legadas e testes unitários
    @Suppress("UNUSED_PARAMETER")
    constructor(
        keysStore: EncryptedKeysStore,
        bleClient: AegisBleClient? = null,
        hostBridgeClient: HostUsbUartBridgeClient = HostUsbUartBridgeClient(),
        simulatedRenodeTransport: SimulatedRenodeTransport,
        connectedKeysRepository: ConnectedKeysRepository,
        scope: CoroutineScope = CoroutineScope(Dispatchers.IO)
    ) : this(
        keysStore = keysStore,
        usbKeyTransport = null,
        bleKeyTransport = if (bleClient != null) BleKeyTransport(bleClient, scope) else null,
        simulatedRenodeTransport = simulatedRenodeTransport,
        connectedKeysRepository = connectedKeysRepository,
        scope = scope
    )

    private val _accounts = MutableStateFlow<List<TotpAccountItem>>(emptyList())
    override val accounts: StateFlow<List<TotpAccountItem>> = _accounts.asStateFlow()

    private val _remainingSeconds = MutableStateFlow(AegisBridge.remainingSeconds(System.currentTimeMillis() / 1000L))
    override val remainingSeconds: StateFlow<Int> = _remainingSeconds.asStateFlow()

    private val _needUpOp = MutableStateFlow<String?>(null)
    override val needUpOp: StateFlow<String?> = _needUpOp.asStateFlow()

    override fun clearNeedUpOp() {
        _needUpOp.value = null
    }

    /**
     * Finding A3: deterministic transport seam for unit tests. When set, it
     * answers vendor ops instead of the real transports. Production leaves it
     * null (real hardware path unchanged).
     */
    internal var vendorOverride: (suspend (opcode: Int, payload: ByteArray) -> ByteArray?)? = null

    /**
     * Fail-closed placeholder shown when there is no live silicon session to
     * back a code. Never a constant fallback code: without a live session
     * there is no code, only this marker plus [TotpAccountItem.requiresTouchToRefresh].
     */
    companion object {
        const val NO_LIVE_CODE = "------"
    }

    init {
        val initialKeyId = connectedKeysRepository.activeKey.value?.id
        if (initialKeyId != null) {
            val list = keysStore.loadTotpAccounts(initialKeyId)
            _accounts.value = list
        }

        connectedKeysRepository.activeKey.onEach { key ->
            if (key != null) {
                _accounts.value = keysStore.loadTotpAccounts(key.id)
            }
        }.launchIn(scope)
    }

    private suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray? {
        // Finding A3 test seam: deterministic answers before real transports.
        vendorOverride?.let { return it(opcode, payload) }

        val activeKey = connectedKeysRepository.activeKey.value
        if (activeKey?.isCurrentlyConnected == false) {
            return null
        }
        val addr = activeKey?.hardwareAddressOrId ?: ""
        return when {
            addr.startsWith("BRIDGE:") || activeKey?.transportType == ConnectionTransportType.USB || addr.startsWith("USB:") -> {
                usbKeyTransport?.sendVendor(opcode, payload)
                    ?: (if (DebugHardwareChipMock.IS_MOCK_ENABLED) simulatedRenodeTransport.sendVendor(opcode, payload) else null)
            }
            activeKey?.transportType == ConnectionTransportType.WIFI || addr.startsWith("WIFI:") -> {
                usbKeyTransport?.sendVendor(opcode, payload)
                    ?: (if (DebugHardwareChipMock.IS_MOCK_ENABLED) simulatedRenodeTransport.sendVendor(opcode, payload) else null)
            }
            activeKey?.transportType == ConnectionTransportType.SIMULATOR -> {
                simulatedRenodeTransport.sendVendor(opcode, payload)
            }
            activeKey?.transportType == ConnectionTransportType.BLE -> {
                bleKeyTransport?.sendVendor(opcode, payload)
                    ?: usbKeyTransport?.sendVendor(opcode, payload)
                    ?: (if (DebugHardwareChipMock.IS_MOCK_ENABLED) simulatedRenodeTransport.sendVendor(opcode, payload) else null)
            }
            else -> {
                usbKeyTransport?.sendVendor(opcode, payload)
                    ?: bleKeyTransport?.sendVendor(opcode, payload)
                    ?: (if (DebugHardwareChipMock.IS_MOCK_ENABLED) simulatedRenodeTransport.sendVendor(opcode, payload) else null)
            }
        }
    }

    /**
     * Finding A3: honest outcome of an on-device code read. A NEED_UP denial
     * is reported distinctly so locally-computed codes are never shown as if
     * they came from the device.
     */
    private sealed interface HardwareOtpResult {
        data class OnDevice(val code: String) : HardwareOtpResult
        data object NeedUp : HardwareOtpResult
        data object Unavailable : HardwareOtpResult
    }

    private fun markNeedUp(op: String) {
        _needUpOp.value = op
    }

    private suspend fun requestHardwareOtpCode(accountName: String, counterOrTimeStep: Long, digits: Int): HardwareOtpResult {
        return try {
            val req = VendorOps.oathCodeRequest(name = accountName, challenge = counterOrTimeStep, digits = digits)
            val resp = sendVendor(VendorOps.OP_OATH_CODE, req) ?: return HardwareOtpResult.Unavailable
            if (resp.size >= 2 && resp[1].toInt() == VendorOps.STATUS_OK) {
                val tlv = resp.copyOfRange(2, resp.size)
                val code = VendorOps.parseOathCodeResponse(tlv)
                if (code != null) HardwareOtpResult.OnDevice(code) else HardwareOtpResult.Unavailable
            } else if (DevicePresence.isNeedUpResponse(resp)) {
                HardwareOtpResult.NeedUp
            } else {
                HardwareOtpResult.Unavailable
            }
        } catch (_: Throwable) {
            HardwareOtpResult.Unavailable
        }
    }

    override suspend fun refreshAccountsAndCodes(keyId: String): Result<List<TotpAccountItem>> = withContext(Dispatchers.IO) {
        runCatching {
            val raw = sendVendor(VendorOps.OP_OATH_LIST, ByteArray(0))
            // Finding A3: a list denial for lack of presence must surface as
            // a presence request, never as an empty (or cached-as-fresh) list.
            if (DevicePresence.isNeedUpResponse(raw)) {
                markNeedUp("oath-list")
                throw DevicePresence.NeedUpRequiredException("oath-list")
            }

            val nowSeconds = System.currentTimeMillis() / 1000L
            val remSecs = AegisBridge.remainingSeconds(nowSeconds)
            _remainingSeconds.value = remSecs

            // Fail-closed: without a live silicon list read there is no
            // session backing any code. Surface placeholders (never cached or
            // locally-computed codes) and fail instead of masquerading stale
            // cache as fresh: no live session = no code.
            if (raw == null || raw.size < 2 || raw[1].toInt() != VendorOps.STATUS_OK) {
                val cached = keysStore.loadTotpAccounts(keyId)
                _accounts.value = cached.map { item ->
                    item.copy(
                        currentCode = NO_LIVE_CODE,
                        formattedCode = formatTotpCode(NO_LIVE_CODE),
                        remainingSeconds = if (item.isHotp) 0 else remSecs,
                        requiresTouchToRefresh = true,
                        isOnDeviceBacked = false
                    )
                }
                throw IllegalStateException("silicon unreachable: no live session (connect the key to refresh codes)")
            }

            val currentCached = keysStore.loadTotpAccounts(keyId).associateBy { it.id }

            val tlv = raw.copyOfRange(2, raw.size)
            val deviceEntries = VendorOps.parseOathList(tlv)

            val resultList = deviceEntries.map { entry ->
                // The device reports the composite "issuer:account" name;
                // cached items store the split parts (as written by
                // addAccount), so match either shape. A missed match
                // would silently drop the cached code/counter and mint a
                // new id on every refresh.
                val existing = currentCached.values.firstOrNull { cached ->
                    cached.accountName == entry.name ||
                        (cached.issuer.isNotBlank() &&
                            "${cached.issuer}:${cached.accountName}" == entry.name)
                }
                val id = existing?.id ?: UUID.randomUUID().toString()
                val parts = entry.name.split(":", limit = 2)
                val issuer = if (parts.size > 1) parts[0].trim() else existing?.issuer ?: ""
                val accountName = if (parts.size > 1) parts[1].trim() else parts[0].trim()

                val isHotp = existing?.isHotp ?: false
                val counter = existing?.counter ?: 0L
                val algorithm = existing?.algorithm ?: "SHA1"
                val period = existing?.periodSeconds ?: 30
                val digits = existing?.digits ?: 6

                val timeStepOrCounter = if (isHotp) counter else (nowSeconds / period)
                // Fail-closed labeling of the code source. Only a code
                // just returned by the device is on-device-backed. A
                // NEED_UP denial keeps the cached value flagged for
                // touch-to-refresh; an unreachable silicon (no live
                // session) shows no code at all — never a locally-computed
                // or fallback code.
                var onDeviceBacked = false
                var touchToRefresh = false
                val code = when (val hw = requestHardwareOtpCode(entry.name, timeStepOrCounter, digits)) {
                    is HardwareOtpResult.OnDevice -> {
                        onDeviceBacked = true
                        hw.code
                    }
                    is HardwareOtpResult.NeedUp -> {
                        markNeedUp("oath-code")
                        touchToRefresh = true
                        existing?.currentCode ?: NO_LIVE_CODE
                    }
                    is HardwareOtpResult.Unavailable -> {
                        touchToRefresh = true
                        NO_LIVE_CODE
                    }
                }
                val formatted = formatTotpCode(code)

                TotpAccountItem(
                    id = id,
                    issuer = issuer,
                    accountName = accountName,
                    currentCode = code,
                    formattedCode = formatted,
                    remainingSeconds = if (isHotp) 0 else remSecs,
                    periodSeconds = period,
                    digits = digits,
                    requiresTouchToRefresh = touchToRefresh,
                    isHotp = isHotp,
                    counter = counter,
                    algorithm = algorithm,
                    isOnDeviceBacked = onDeviceBacked
                )
            }

            keysStore.saveTotpAccounts(keyId, resultList)
            _accounts.value = resultList
            resultList
        }
    }

    override suspend fun addAccount(
        keyId: String,
        issuer: String,
        accountName: String,
        secretOrUri: String,
        digits: Int,
        periodSeconds: Int,
        isHotp: Boolean,
        algorithm: String
    ): Result<TotpAccountItem> = withContext(Dispatchers.IO) {
        runCatching {
            val (resolvedIssuer, resolvedAccount, rawSecret) = parseSecretInput(issuer, accountName, secretOrUri)
            val secretBytes = decodeBase32(rawSecret)
            if (secretBytes.size !in 10..64) throw DeviceError(R.string.oath_err_secret_size)

            val compositeName = if (resolvedIssuer.isNotBlank()) {
                "$resolvedIssuer:$resolvedAccount"
            } else {
                resolvedAccount
            }.take(32)

            // Monta o frame OATH_PUT (0x24) com tipo HOTP ou TOTP + SHA1
            val typeAlgo = if (isHotp) {
                VendorOps.OATH_TYPE_HOTP or VendorOps.OATH_ALGO_SHA1
            } else {
                VendorOps.OATH_TYPE_TOTP or VendorOps.OATH_ALGO_SHA1
            }
            val req = VendorOps.oathPutRequest(
                name = compositeName,
                typeAlgo = typeAlgo,
                digits = digits,
                secret = secretBytes,
                counter = if (isHotp) 0L else null
            )

            val resp = sendVendor(VendorOps.OP_OATH_PUT, req)
                ?: throw DeviceError(R.string.oath_err_no_response_enroll)
            // Finding A3: presence denial surfaces as a prompt, never as a
            // silent close of the add sheet.
            if (DevicePresence.isNeedUpResponse(resp)) {
                markNeedUp("oath-put")
                throw DevicePresence.NeedUpRequiredException("oath-put")
            }
            if (resp.size >= 2 && resp[1].toInt() != VendorOps.STATUS_OK) {
                throw DeviceError(R.string.oath_err_rejected_enroll, VendorOps.statusLabel(resp[1].toInt() and 0xFF))
            }

            val nowSeconds = System.currentTimeMillis() / 1000L
            val remSecs = if (isHotp) 0 else AegisBridge.remainingSeconds(nowSeconds)

            val timeStepOrCounter = if (isHotp) 0L else (nowSeconds / periodSeconds)
            // Fail-closed source labeling for the first code too: only a
            // code just returned by live silicon is device-backed. Without a
            // live code read there is no code — never a locally-computed one.
            var onDeviceBacked = false
            var touchToRefresh = false
            val code = when (val hw = requestHardwareOtpCode(compositeName, timeStepOrCounter, digits)) {
                is HardwareOtpResult.OnDevice -> {
                    onDeviceBacked = true
                    hw.code
                }
                is HardwareOtpResult.NeedUp -> {
                    markNeedUp("oath-code")
                    touchToRefresh = true
                    NO_LIVE_CODE
                }
                is HardwareOtpResult.Unavailable -> {
                    touchToRefresh = true
                    NO_LIVE_CODE
                }
            }

            val accountId = UUID.randomUUID().toString()
            secretBytes.fill(0) // Higienização de segurança do buffer local

            val newItem = TotpAccountItem(
                id = accountId,
                issuer = resolvedIssuer,
                accountName = resolvedAccount,
                currentCode = code,
                formattedCode = formatTotpCode(code),
                remainingSeconds = remSecs,
                periodSeconds = periodSeconds,
                digits = digits,
                requiresTouchToRefresh = touchToRefresh,
                isHotp = isHotp,
                counter = 0L,
                algorithm = algorithm,
                isOnDeviceBacked = onDeviceBacked
            )

            _accounts.update { current ->
                val updated = current + newItem
                keysStore.saveTotpAccounts(keyId, updated)
                updated
            }

            newItem
        }
    }

    override suspend fun incrementHotpCounter(keyId: String, accountId: String): Result<TotpAccountItem> = withContext(Dispatchers.IO) {
        runCatching {
            val currentList = _accounts.value
            val target = currentList.firstOrNull { it.id == accountId }
                ?: throw DeviceError(R.string.oath_err_not_found)
            if (!target.isHotp) throw DeviceError(R.string.oath_err_hot_only)

            val nextCounter = target.counter + 1
            val compositeName = if (target.issuer.isNotBlank()) "${target.issuer}:${target.accountName}" else target.accountName
            // Fail-closed: without a live silicon answer there is no new
            // code — the HOTP counter never advances locally. A NEED_UP
            // denial surfaces as a presence prompt, never as a code.
            var hotpOnDevice = false
            val code = when (val hw = requestHardwareOtpCode(compositeName, nextCounter, target.digits)) {
                is HardwareOtpResult.OnDevice -> {
                    hotpOnDevice = true
                    hw.code
                }
                is HardwareOtpResult.NeedUp -> {
                    markNeedUp("oath-code")
                    throw DevicePresence.NeedUpRequiredException("oath-code")
                }
                is HardwareOtpResult.Unavailable -> {
                    throw IllegalStateException("silicon unreachable: no live session (HOTP counter not advanced)")
                }
            }

            val updatedItem = target.copy(
                counter = nextCounter,
                currentCode = code,
                formattedCode = formatTotpCode(code),
                requiresTouchToRefresh = false,
                isOnDeviceBacked = hotpOnDevice
            )

            _accounts.update { list ->
                val updatedList = list.map { if (it.id == accountId) updatedItem else it }
                keysStore.saveTotpAccounts(keyId, updatedList)
                updatedList
            }

            updatedItem
        }
    }

    override suspend fun deleteAccount(keyId: String, accountId: String): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val target = _accounts.value.firstOrNull { it.id == accountId }
            if (target != null) {
                val compositeName = if (target.issuer.isNotBlank()) "${target.issuer}:${target.accountName}" else target.accountName
                val req = VendorOps.writeTlv(VendorOps.TAG_OATH_NAME, compositeName.toByteArray(Charsets.UTF_8))
                val resp = sendVendor(VendorOps.OP_OATH_DELETE, req)
                    ?: throw DeviceError(R.string.oath_err_no_response_delete)
                // Finding A3: presence denial surfaces as a prompt.
                if (DevicePresence.isNeedUpResponse(resp)) {
                    markNeedUp("oath-delete")
                    throw DevicePresence.NeedUpRequiredException("oath-delete")
                }
                if (resp.size >= 2 && resp[1].toInt() != VendorOps.STATUS_OK) {
                    throw DeviceError(R.string.oath_err_rejected_delete, VendorOps.statusLabel(resp[1].toInt() and 0xFF))
                }
            }

            _accounts.update { list ->
                val filtered = list.filterNot { it.id == accountId }
                keysStore.saveTotpAccounts(keyId, filtered)
                filtered
            }
        }
    }

    override fun tickTimer(nowEpochSeconds: Long) {
        val remSecs = AegisBridge.remainingSeconds(nowEpochSeconds)
        _remainingSeconds.value = remSecs

        // Fail-closed: the countdown ticks locally, but codes never advance
        // without silicon. Only the remaining-seconds display updates; codes
        // change exclusively on a live hardware refresh (no live session =
        // no code, never a locally recomputed one).
        _accounts.update { list ->
            list.map { item ->
                if (item.isHotp) {
                    item
                } else {
                    item.copy(remainingSeconds = remSecs)
                }
            }
        }
    }

    private fun parseSecretInput(
        issuer: String,
        account: String,
        secretOrUri: String
    ): Triple<String, String, String> {
        val trimmed = secretOrUri.trim()
        val parsed = AegisBridge.parseOtpInput(trimmed)
        if (parsed != null) {
            return Triple(
                if (issuer.isNotBlank()) issuer else parsed.issuer,
                if (account.isNotBlank()) account else parsed.accountName,
                parsed.secretBase32
            )
        }
        return Triple(issuer, account, trimmed)
    }

    private fun decodeBase32(input: String): ByteArray {
        val clean = input.uppercase().replace("=", "").replace(" ", "").trim()
        val out = mutableListOf<Byte>()
        var buffer = 0
        var bitsLeft = 0
        for (c in clean) {
            val value = when (c) {
                in 'A'..'Z' -> c - 'A'
                in '2'..'7' -> c - '2' + 26
                else -> continue
            }
            buffer = (buffer shl 5) or value
            bitsLeft += 5
            if (bitsLeft >= 8) {
                bitsLeft -= 8
                out.add(((buffer shr bitsLeft) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }

    private fun formatTotpCode(code: String): String {
        return if (code.length == 6) {
            "${code.substring(0, 3)} ${code.substring(3)}"
        } else if (code.length == 8) {
            "${code.substring(0, 4)} ${code.substring(4)}"
        } else {
            code
        }
    }
}
