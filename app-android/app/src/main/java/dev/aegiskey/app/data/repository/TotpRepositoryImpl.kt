package dev.aegiskey.app.data.repository

import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.data.debug.DebugHardwareChipMock
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.transport.BleKeyTransport
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.data.transport.UsbKeyTransport
import dev.aegiskey.app.domain.model.ConnectionTransportType
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
import java.nio.ByteBuffer
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

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

    // Segredos mantidos em memória volátil da sessão para recálculo local dos códigos
    private val volatileSecrets = mutableMapOf<String, ByteArray>()

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

    private suspend fun requestHardwareOtpCode(accountName: String, counterOrTimeStep: Long, digits: Int): String? {
        return try {
            val req = VendorOps.oathCodeRequest(name = accountName, challenge = counterOrTimeStep, digits = digits)
            val resp = sendVendor(VendorOps.OP_OATH_CODE, req) ?: return null
            if (resp.size >= 2 && resp[1].toInt() == VendorOps.STATUS_OK) {
                val tlv = resp.copyOfRange(2, resp.size)
                VendorOps.parseOathCodeResponse(tlv)
            } else {
                null
            }
        } catch (_: Throwable) {
            null
        }
    }

    override suspend fun refreshAccountsAndCodes(keyId: String): Result<List<TotpAccountItem>> = withContext(Dispatchers.IO) {
        runCatching {
            val raw = sendVendor(VendorOps.OP_OATH_LIST, ByteArray(0))
            val currentCached = keysStore.loadTotpAccounts(keyId).associateBy { it.id }

            val nowSeconds = System.currentTimeMillis() / 1000L
            val remSecs = AegisBridge.remainingSeconds(nowSeconds)
            _remainingSeconds.value = remSecs

            if (raw != null && raw.size >= 2 && raw[1].toInt() == VendorOps.STATUS_OK) {
                val tlv = raw.copyOfRange(2, raw.size)
                val deviceEntries = VendorOps.parseOathList(tlv)

                val resultList = deviceEntries.map { entry ->
                    val existing = currentCached.values.firstOrNull { it.accountName == entry.name }
                    val id = existing?.id ?: UUID.randomUUID().toString()
                    val parts = entry.name.split(":", limit = 2)
                    val issuer = if (parts.size > 1) parts[0].trim() else existing?.issuer ?: ""
                    val accountName = if (parts.size > 1) parts[1].trim() else parts[0].trim()

                    val isHotp = existing?.isHotp ?: false
                    val counter = existing?.counter ?: 0L
                    val algorithm = existing?.algorithm ?: "SHA1"
                    val period = existing?.periodSeconds ?: 30
                    val digits = existing?.digits ?: 6

                    val secret = volatileSecrets[id]
                    val timeStepOrCounter = if (isHotp) counter else (nowSeconds / period)
                    val hwCode = requestHardwareOtpCode(entry.name, timeStepOrCounter, digits)

                    val code = hwCode ?: if (secret != null) {
                        if (isHotp) {
                            calculateHotpCode(secret, counter, digits)
                        } else {
                            calculateTotpCode(secret, nowSeconds, period, digits)
                        }
                    } else {
                        existing?.currentCode ?: "------"
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
                        requiresTouchToRefresh = false,
                        isHotp = isHotp,
                        counter = counter,
                        algorithm = algorithm
                    )
                }

                keysStore.saveTotpAccounts(keyId, resultList)
                _accounts.value = resultList
                resultList
            } else {
                val cached = keysStore.loadTotpAccounts(keyId).map { item ->
                    if (item.isHotp) {
                        item
                    } else {
                        val secret = volatileSecrets[item.id]
                        val code = if (secret != null) {
                            calculateTotpCode(secret, nowSeconds, item.periodSeconds, item.digits)
                        } else {
                            item.currentCode
                        }
                        item.copy(
                            currentCode = code,
                            formattedCode = formatTotpCode(code),
                            remainingSeconds = remSecs
                        )
                    }
                }
                _accounts.value = cached
                cached
            }
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
            require(secretBytes.size in 10..64) { "O segredo OATH deve conter entre 10 e 64 bytes" }

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
                ?: throw IllegalStateException("Sem resposta da chave para cadastro OATH")
            if (resp.size >= 2 && resp[1].toInt() != VendorOps.STATUS_OK) {
                throw IllegalStateException("Chave rejeitou o cadastro OATH: " + VendorOps.statusLabel(resp[1].toInt() and 0xFF))
            }

            val nowSeconds = System.currentTimeMillis() / 1000L
            val remSecs = if (isHotp) 0 else AegisBridge.remainingSeconds(nowSeconds)

            val timeStepOrCounter = if (isHotp) 0L else (nowSeconds / periodSeconds)
            val hwCode = requestHardwareOtpCode(compositeName, timeStepOrCounter, digits)

            val code = hwCode ?: if (isHotp) {
                calculateHotpCode(secretBytes, 0L, digits)
            } else {
                calculateTotpCode(secretBytes, nowSeconds, periodSeconds, digits)
            }

            val accountId = UUID.randomUUID().toString()
            volatileSecrets[accountId] = secretBytes.copyOf()
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
                requiresTouchToRefresh = false,
                isHotp = isHotp,
                counter = 0L,
                algorithm = algorithm
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
                ?: throw IllegalArgumentException("Conta OATH não encontrada")
            require(target.isHotp) { "Apenas contas HOTP baseadas em contador suportam incremento manual" }

            val nextCounter = target.counter + 1
            val compositeName = if (target.issuer.isNotBlank()) "${target.issuer}:${target.accountName}" else target.accountName
            val hwCode = requestHardwareOtpCode(compositeName, nextCounter, target.digits)

            val secret = volatileSecrets[accountId]
            val code = hwCode ?: if (secret != null) {
                calculateHotpCode(secret, nextCounter, target.digits)
            } else {
                target.currentCode
            }

            val updatedItem = target.copy(
                counter = nextCounter,
                currentCode = code,
                formattedCode = formatTotpCode(code)
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
                    ?: throw IllegalStateException("Sem resposta da chave para exclusão TOTP")
                if (resp.size >= 2 && resp[1].toInt() != VendorOps.STATUS_OK) {
                    throw IllegalStateException("Chave rejeitou a exclusão TOTP: " + VendorOps.statusLabel(resp[1].toInt() and 0xFF))
                }
            }

            volatileSecrets.remove(accountId)
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

        _accounts.update { list ->
            list.map { item ->
                if (item.isHotp) {
                    item
                } else {
                    val secret = volatileSecrets[item.id]
                    val code = if (secret != null && (remSecs == 30 || item.currentCode.contains("-"))) {
                        calculateTotpCode(secret, nowEpochSeconds, item.periodSeconds, item.digits)
                    } else {
                        item.currentCode
                    }
                    item.copy(
                        currentCode = code,
                        formattedCode = formatTotpCode(code),
                        remainingSeconds = remSecs
                    )
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

    private fun calculateTotpCode(
        secret: ByteArray,
        epochSeconds: Long,
        period: Int,
        digits: Int
    ): String {
        return try {
            val counter = epochSeconds / period
            val buffer = ByteBuffer.allocate(8).putLong(counter).array()
            val mac = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(secret, "HmacSHA1")) }
            val hash = mac.doFinal(buffer)
            val offset = hash[hash.size - 1].toInt() and 0x0F
            val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
                ((hash[offset + 1].toInt() and 0xFF) shl 16) or
                ((hash[offset + 2].toInt() and 0xFF) shl 8) or
                (hash[offset + 3].toInt() and 0xFF)
            val modulo = Math.pow(10.0, digits.toDouble()).toInt()
            val otp = binary % modulo
            otp.toString().padStart(digits, '0')
        } catch (_: Throwable) {
            "000000"
        }
    }

    private fun calculateHotpCode(
        secret: ByteArray,
        counter: Long,
        digits: Int
    ): String {
        return try {
            val buffer = ByteBuffer.allocate(8).putLong(counter).array()
            val mac = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(secret, "HmacSHA1")) }
            val hash = mac.doFinal(buffer)
            val offset = hash[hash.size - 1].toInt() and 0x0F
            val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
                ((hash[offset + 1].toInt() and 0xFF) shl 16) or
                ((hash[offset + 2].toInt() and 0xFF) shl 8) or
                (hash[offset + 3].toInt() and 0xFF)
            val modulo = Math.pow(10.0, digits.toDouble()).toInt()
            val otp = binary % modulo
            otp.toString().padStart(digits, '0')
        } catch (_: Throwable) {
            "0".repeat(digits)
        }
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
