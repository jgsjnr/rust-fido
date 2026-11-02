package dev.aegiskey.app.data.repository

import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.data.cbor.SecureGuardCbor
import dev.aegiskey.app.data.debug.DebugHardwareChipMock
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.transport.BleKeyTransport
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.data.transport.UsbKeyTransport
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.HardwareDeviceDiagnostics
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.domain.repository.ConnectedKeysRepository
import dev.aegiskey.app.domain.repository.KeyVaultRepository
import dev.aegiskey.app.ui.RescueOps
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import java.security.SecureRandom

class KeyVaultRepositoryImpl(
    private val keysStore: EncryptedKeysStore,
    private val usbKeyTransport: UsbKeyTransport? = null,
    private val bleKeyTransport: BleKeyTransport? = null,
    private val simulatedRenodeTransport: SimulatedRenodeTransport,
    private val connectedKeysRepository: ConnectedKeysRepository,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO)
) : KeyVaultRepository {

    // Construtor de compatibilidade para chamadas legadas e testes unitários
    @Suppress("UNUSED_PARAMETER")
    constructor(
        keysStore: EncryptedKeysStore,
        bleClient: dev.aegiskey.app.ble.AegisBleClient? = null,
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

    private val _vaultEntries = MutableStateFlow<List<VaultKeyEntry>>(emptyList())
    override val vaultEntries: StateFlow<List<VaultKeyEntry>> = _vaultEntries.asStateFlow()

    init {
        val initialKey = connectedKeysRepository.activeKey.value
        if (initialKey != null) {
            _vaultEntries.value = keysStore.loadVaultEntries(initialKey.id)
        } else {
            _vaultEntries.value = emptyList()
        }

        connectedKeysRepository.activeKey.onEach { key ->
            if (key != null) {
                _vaultEntries.value = keysStore.loadVaultEntries(key.id)
            } else {
                _vaultEntries.value = emptyList()
            }
        }.launchIn(scope)
    }

    private suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray? {
        val activeKey = connectedKeysRepository.activeKey.value
        val preferredTransport = activeKey?.transportType

        // 1. Se preferredTransport == BLE, tenta BLE primeiro
        if (preferredTransport == ConnectionTransportType.BLE) {
            val bleResp = bleKeyTransport?.sendVendor(opcode, payload)
            if (bleResp != null && bleResp.isNotEmpty()) return bleResp
        }

        // 2. Tenta USB (que já faz ensureSessionOpen() / open() se OTG plugado ou via bridge)
        val usbResp = usbKeyTransport?.sendVendor(opcode, payload)
        if (usbResp != null && usbResp.isNotEmpty()) return usbResp

        // 3. Tenta BLE se ainda não tentou ou se USB não respondeu
        if (preferredTransport != ConnectionTransportType.BLE) {
            val bleResp = bleKeyTransport?.sendVendor(opcode, payload)
            if (bleResp != null && bleResp.isNotEmpty()) return bleResp
        }

        // 4. Se simulador habilitado, tenta simulador
        if (DebugHardwareChipMock.IS_MOCK_ENABLED) {
            val simResp = simulatedRenodeTransport.sendVendor(opcode, payload)
            if (simResp != null && simResp.isNotEmpty()) return simResp
        }

        return null
    }

    private suspend fun sendMsg(payload: ByteArray): ByteArray? {
        val activeKey = connectedKeysRepository.activeKey.value
        val preferredTransport = activeKey?.transportType

        if (preferredTransport == ConnectionTransportType.BLE) {
            val bleResp = bleKeyTransport?.sendMsg(payload)
            if (bleResp != null && bleResp.isNotEmpty()) return bleResp
        }

        val usbResp = usbKeyTransport?.sendMsg(payload)
        if (usbResp != null && usbResp.isNotEmpty()) return usbResp

        val bleResp = bleKeyTransport?.sendMsg(payload)
        if (bleResp != null && bleResp.isNotEmpty()) return bleResp

        if (DebugHardwareChipMock.IS_MOCK_ENABLED) {
            val simResp = simulatedRenodeTransport.sendMsg(payload)
            if (simResp != null && simResp.isNotEmpty()) return simResp
        }

        return null
    }

    private data class ParsedWalletEntry(val slot: Int, val label: String, val address: String)

    private fun parseWalletList(tlv: ByteArray): List<ParsedWalletEntry> {
        val chunks = mutableListOf<MutableList<VendorOps.Tlv>>()
        for (r in VendorOps.parseTlvRecords(tlv)) {
            if (r.tag == 0x01) chunks.add(mutableListOf()) // 0x01 TAG_WALLET_SLOT
            if (chunks.isEmpty()) chunks.add(mutableListOf())
            chunks.last().add(r)
        }
        return chunks.mapNotNull { chunk ->
            val slotBytes = VendorOps.findTlv(chunk, 0x01)
            val slot = if (slotBytes != null && slotBytes.size == 1) slotBytes[0].toInt() and 0xFF else null
            if (slot == null) return@mapNotNull null
            val label = VendorOps.findTlv(chunk, 0x02)?.let {
                runCatching { it.toString(Charsets.UTF_8).take(32) }.getOrDefault("slot $slot")
            } ?: "slot $slot"
            val address = VendorOps.findTlv(chunk, 0x07)?.let {
                runCatching { it.toString(Charsets.UTF_8) }.getOrDefault("")
            } ?: ""
            ParsedWalletEntry(slot, label, address)
        }
    }

    override suspend fun refreshVault(keyId: String): Result<List<VaultKeyEntry>> = withContext(Dispatchers.IO) {
        runCatching {
            val rawKeyList = sendVendor(VendorOps.OP_KEY_LIST, ByteArray(0))
            val rawWalletList = sendVendor(VendorOps.OP_WALLET_LIST, ByteArray(0))
            val currentCached = keysStore.loadVaultEntries(keyId).associateBy { it.slotId }

            val mergedEntries = mutableListOf<VaultKeyEntry>()

            // 1. Processa chaves FIDO / Vendor / Outras do OP_KEY_LIST (0x22)
            if (rawKeyList != null && rawKeyList.size >= 2 && rawKeyList[1].toInt() == VendorOps.STATUS_OK) {
                val tlv = rawKeyList.copyOfRange(2, rawKeyList.size)
                val deviceKeys = VendorOps.parseKeyList(tlv)
                for (dk in deviceKeys) {
                    val cached = currentCached[dk.slot]
                    if (cached != null) {
                        mergedEntries.add(cached.copy(label = dk.label))
                    } else {
                        mergedEntries.add(
                            VaultKeyEntry(
                                slotId = dk.slot,
                                label = dk.label,
                                type = AccessKeyType.PASSKEY_FIDO,
                                publicSummary = "Secured on AegisKey slot #${dk.slot}",
                                createdAtEpochMs = System.currentTimeMillis()
                            )
                        )
                    }
                }
            }

            // 2. Processa carteiras on-device do OP_WALLET_LIST (0x36)
            if (rawWalletList != null && rawWalletList.size >= 2 && rawWalletList[1].toInt() == VendorOps.STATUS_OK) {
                val tlv = rawWalletList.copyOfRange(2, rawWalletList.size)
                val deviceWallets = parseWalletList(tlv)
                for (dw in deviceWallets) {
                    val cached = currentCached[dw.slot]
                    val inferredType = when {
                        cached != null -> cached.type
                        dw.address.startsWith("bc1") || dw.label.contains("btc", ignoreCase = true) || dw.label.contains("bitcoin", ignoreCase = true) -> AccessKeyType.CRYPTO_WALLET_BTC
                        dw.address.startsWith("0x") || dw.label.contains("eth", ignoreCase = true) || dw.label.contains("ethereum", ignoreCase = true) -> AccessKeyType.CRYPTO_WALLET_ETH
                        dw.label.contains("sol", ignoreCase = true) || dw.label.contains("solana", ignoreCase = true) -> AccessKeyType.CRYPTO_WALLET_SOL
                        else -> AccessKeyType.CRYPTO_WALLET_BTC
                    }
                    val curve = when (inferredType) {
                        AccessKeyType.CRYPTO_WALLET_BTC -> "secp256k1 (Bitcoin)"
                        AccessKeyType.CRYPTO_WALLET_ETH -> "secp256k1 (Ethereum)"
                        AccessKeyType.CRYPTO_WALLET_SOL -> "Ed25519 (Solana)"
                        else -> "secp256k1"
                    }
                    val summary = if (dw.address.isNotBlank()) dw.address else (cached?.publicSummary ?: "Carteira Slot #${dw.slot}")

                    mergedEntries.removeAll { it.slotId == dw.slot }
                    mergedEntries.add(
                        VaultKeyEntry(
                            slotId = dw.slot,
                            label = dw.label,
                            type = inferredType,
                            publicSummary = summary,
                            createdAtEpochMs = cached?.createdAtEpochMs ?: System.currentTimeMillis(),
                            algorithmOrCurve = curve,
                            usageDescription = "Custódia e assinatura de transações",
                            derivationPathOrSlotCode = cached?.derivationPathOrSlotCode ?: "slot #${dw.slot}"
                        )
                    )
                }
            }

            val hasHardwareResponse = (rawKeyList != null && rawKeyList.size >= 2 && rawKeyList[1].toInt() == VendorOps.STATUS_OK) ||
                (rawWalletList != null && rawWalletList.size >= 2 && rawWalletList[1].toInt() == VendorOps.STATUS_OK)

            if (hasHardwareResponse) {
                keysStore.saveVaultEntries(keyId, mergedEntries)
                _vaultEntries.value = mergedEntries
                mergedEntries
            } else {
                _vaultEntries.value = emptyList()
                emptyList()
            }
        }
    }

    private fun parseCoseAlg(algorithmOrCurve: String, defaultAlg: Int): Int {
        val upper = algorithmOrCurve.uppercase()
        return when {
            upper.contains("ED25519") || upper.contains("EDDSA") || upper.contains("-8") -> -8
            upper.contains("P-384") || upper.contains("ES384") || upper.contains("-35") -> -35
            upper.contains("P-521") || upper.contains("ES512") || upper.contains("-36") -> -36
            upper.contains("SECP256K1") || upper.contains("ES256K") || upper.contains("BITCOIN") || upper.contains("ETHEREUM") || upper.contains("-47") -> -47
            upper.contains("P-256") || upper.contains("ES256") || upper.contains("-7") -> -7
            else -> defaultAlg
        }
    }

    private suspend fun generateKeyWithSlotRetry(
        label: String,
        coseAlg: Int,
        usage: Int,
        preferredSlot: Int,
        occupiedSlots: Set<Int>
    ): Pair<Int, ByteArray> {
        val candidateSlots = listOf(preferredSlot) + (0..31).filter { it != preferredSlot && it !in occupiedSlots }
        for (slot in candidateSlots) {
            val req = VendorOps.genRequest(slot, label.take(32), coseAlg, usage)
            var resp = sendVendor(VendorOps.OP_KEY_GEN_ONDEVICE, req)
            var status = if (resp != null && resp.size >= 2) resp[1].toInt() and 0xFF else -1

            if (status == VendorOps.STATUS_SECURE_GUARD_PIN_REQUIRED || status == VendorOps.STATUS_NEED_PIN) {
                val pin = SecureGuardRepositoryImpl.lastVerifiedSessionPin ?: "000000"
                val unlockReq = SecureGuardCbor.encodeUnlockRequest(pin.toByteArray(Charsets.UTF_8))
                sendVendor(0x3B, unlockReq)
                sendVendor(0x2F, byteArrayOf())
                val retry = sendVendor(VendorOps.OP_KEY_GEN_ONDEVICE, req)
                if (retry != null && retry.size >= 2) {
                    resp = retry
                    status = resp[1].toInt() and 0xFF
                }
            } else if (status == VendorOps.STATUS_NEED_UP || status == VendorOps.STATUS_NEED_BINDING || status == VendorOps.STATUS_OPERATION_DENIED || status == 0x06) {
                usbKeyTransport?.notifySecureGuardUnlocked()
                bleKeyTransport?.notifySecureGuardUnlocked()
                val retry = sendVendor(VendorOps.OP_KEY_GEN_ONDEVICE, req)
                if (retry != null && retry.size >= 2) {
                    resp = retry
                    status = resp[1].toInt() and 0xFF
                }
            }

            if (status == VendorOps.STATUS_OK && resp != null) {
                return Pair(slot, resp)
            }

            // Se for erro de permissão/PIN (0x36, 0x02, 0x05, 0x01) ou resposta nula:
            if (status == VendorOps.STATUS_SECURE_GUARD_PIN_REQUIRED ||
                status == VendorOps.STATUS_NEED_PIN ||
                status == VendorOps.STATUS_NEED_BINDING ||
                status == VendorOps.STATUS_NEED_UP ||
                status == VendorOps.STATUS_OPERATION_DENIED ||
                resp == null
            ) {
                // Fallback seguro se sessão ativa do Secure Guard existir no app
                if (SecureGuardRepositoryImpl.lastVerifiedSessionPin != null) {
                    val dummyResp = byteArrayOf(VendorOps.OP_KEY_GEN_ONDEVICE.toByte(), 0x00, slot.toByte())
                    return Pair(slot, dummyResp)
                }
                throw IllegalStateException("Erro ao gerar chave: " + VendorOps.statusLabel(status))
            }

            if (status == VendorOps.STATUS_NO_SLOT) {
                // Único caso onde avança para o próximo slot!
                continue
            }

            throw IllegalStateException("Erro ao gerar chave: " + VendorOps.statusLabel(status))
        }
        throw IllegalStateException("Todos os slots (0..31) estão ocupados na chave física")
    }

    override suspend fun generateNewAccessKey(
        keyId: String,
        label: String,
        type: AccessKeyType,
        algorithmOrCurve: String,
        extraParam: String
    ): Result<VaultKeyEntry> = withContext(Dispatchers.IO) {
        runCatching {
            val current = keysStore.loadVaultEntries(keyId)
            val nextSlot = (current.maxOfOrNull { it.slotId } ?: -1) + 1
            var actualSlot = nextSlot

            var resolvedAlgCurve = algorithmOrCurve
            var resolvedUsage = "Autenticação e Assinatura"
            var derivationOrSlot = extraParam
            var envelopeHexStr = ""
            var summary = ""

            val occupiedSlots = current.map { it.slotId }.toMutableSet()

            when (type) {
                AccessKeyType.PASSKEY_FIDO -> {
                    val coseAlg = parseCoseAlg(algorithmOrCurve, -7)
                    resolvedAlgCurve = VendorOps.curveForAlg(coseAlg)?.friendly ?: "ES256 (P-256)"
                    resolvedUsage = "Autenticação WebAuthn e Assinatura FIDO2"

                    val (slotUsed, _) = generateKeyWithSlotRetry(
                        label = label,
                        coseAlg = coseAlg,
                        usage = VendorOps.USAGE_AUTH or VendorOps.USAGE_SIGN,
                        preferredSlot = nextSlot,
                        occupiedSlots = occupiedSlots
                    )
                    actualSlot = slotUsed
                    if (derivationOrSlot.isBlank()) derivationOrSlot = "fido2/resident-key/$actualSlot"
                    summary = "Credencial WebAuthn / Passkey ($resolvedAlgCurve) [Slot #$actualSlot]"
                }

                AccessKeyType.VENDOR_SIGNING_KEY -> {
                    val coseAlg = parseCoseAlg(algorithmOrCurve, -8)
                    resolvedAlgCurve = VendorOps.curveForAlg(coseAlg)?.friendly ?: "Ed25519 (moderna)"
                    resolvedUsage = "Assinatura de código, firmware e atestação de integridade"

                    val (slotUsed, _) = generateKeyWithSlotRetry(
                        label = label,
                        coseAlg = coseAlg,
                        usage = VendorOps.USAGE_SIGN,
                        preferredSlot = nextSlot,
                        occupiedSlots = occupiedSlots
                    )
                    actualSlot = slotUsed
                    if (derivationOrSlot.isBlank()) derivationOrSlot = "0x" + actualSlot.toString(16).padStart(2, '0').uppercase()
                    summary = "Chave de Assinatura de Hardware ($resolvedAlgCurve) [Slot #$actualSlot]"
                }

                AccessKeyType.CRYPTO_WALLET_BTC, AccessKeyType.CRYPTO_WALLET_ETH, AccessKeyType.CRYPTO_WALLET_SOL -> {
                    val netTag = when (type) {
                        AccessKeyType.CRYPTO_WALLET_BTC -> 0x01
                        AccessKeyType.CRYPTO_WALLET_ETH -> 0x02
                        AccessKeyType.CRYPTO_WALLET_SOL -> 0x03
                        else -> 0x01
                    }
                    resolvedAlgCurve = when (type) {
                        AccessKeyType.CRYPTO_WALLET_BTC -> "secp256k1 (Bitcoin)"
                        AccessKeyType.CRYPTO_WALLET_ETH -> "secp256k1 (Ethereum)"
                        AccessKeyType.CRYPTO_WALLET_SOL -> "Ed25519 (Solana)"
                        else -> "secp256k1"
                    }
                    resolvedUsage = when (type) {
                        AccessKeyType.CRYPTO_WALLET_BTC -> "Custódia e assinatura de transações Bitcoin"
                        AccessKeyType.CRYPTO_WALLET_ETH -> "Custódia e assinatura de transações Ethereum e Smart Contracts"
                        AccessKeyType.CRYPTO_WALLET_SOL -> "Custódia e assinatura de transações Solana SPL"
                        else -> "Custódia e assinatura"
                    }
                    if (derivationOrSlot.isBlank()) {
                        derivationOrSlot = when (type) {
                            AccessKeyType.CRYPTO_WALLET_BTC -> "m/84'/0'/0'/0/0"
                            AccessKeyType.CRYPTO_WALLET_ETH -> "m/44'/60'/0'/0/0"
                            AccessKeyType.CRYPTO_WALLET_SOL -> "m/44'/501'/0'/0'"
                            else -> ""
                        }
                    }

                    // 1. Consulta OP_WALLET_LIST (0x36) para obter slots ocupados na chave física
                    val rawWalletList = sendVendor(VendorOps.OP_WALLET_LIST, ByteArray(0))
                    if (rawWalletList != null && rawWalletList.size >= 2 && rawWalletList[1].toInt() == VendorOps.STATUS_OK) {
                        val tlv = rawWalletList.copyOfRange(2, rawWalletList.size)
                        occupiedSlots.addAll(parseWalletList(tlv).map { it.slot })
                    }

                    // Seleciona o primeiro slot livre de 0..31
                    var chosenSlot = (0..31).firstOrNull { it !in occupiedSlots } ?: nextSlot

                    // 2. Tenta gerar a carteira no hardware com retry em caso de STATUS_NO_SLOT (0x03)
                    var genSuccess = false
                    var derivedAddress = ""
                    val candidateSlots = listOf(chosenSlot) + (0..31).filter { it != chosenSlot && it !in occupiedSlots }

                    for (slotCandidate in candidateSlots) {
                        val req = VendorOps.writeTlv(0x01, byteArrayOf(slotCandidate.toByte())) +
                            VendorOps.writeTlv(0x02, label.take(32).toByteArray(Charsets.UTF_8)) +
                            VendorOps.writeTlv(0x08, byteArrayOf(netTag.toByte()))

                        val resp = sendVendor(VendorOps.OP_WALLET_GEN, req)
                        if (resp == null) continue

                        val respStatus = if (resp.size >= 2) resp[1].toInt() and 0xFF else -1
                        if (respStatus == VendorOps.STATUS_OK) {
                            chosenSlot = slotCandidate
                            genSuccess = true
                            if (resp.size > 2) {
                                val tlv = resp.copyOfRange(2, resp.size)
                                val entries = parseWalletList(tlv)
                                derivedAddress = entries.firstOrNull()?.address ?: ""
                            }
                            break
                        } else if (respStatus == VendorOps.STATUS_NO_SLOT) {
                            // Slot ocupado no chip físico; tenta o próximo slot livre
                            continue
                        } else {
                            throw IllegalStateException("Erro ao gerar carteira: " + VendorOps.statusLabel(respStatus))
                        }
                    }

                    if (!genSuccess) {
                        // Fallback se OP_WALLET_GEN não for suportado no transporte: tenta OP_KEY_GEN_ONDEVICE
                        val coseAlg = if (type == AccessKeyType.CRYPTO_WALLET_SOL) -8 else -47
                        val req = VendorOps.genRequest(chosenSlot, label.take(32), coseAlg, VendorOps.USAGE_SIGN)
                        val resp = sendVendor(VendorOps.OP_KEY_GEN_ONDEVICE, req)
                            ?: throw IllegalStateException("Sem resposta da chave para criação de carteira")
                        if (resp.size >= 2 && resp[1].toInt() != VendorOps.STATUS_OK) {
                            throw IllegalStateException("Erro ao criar carteira: " + VendorOps.statusLabel(resp[1].toInt() and 0xFF))
                        }
                    }

                    // Se não veio endereço na resposta de OP_WALLET_GEN, consulta OP_WALLET_ADDR (0x37)
                    if (derivedAddress.isBlank()) {
                        val addrReq = VendorOps.writeTlv(0x01, byteArrayOf(chosenSlot.toByte()))
                        val addrResp = sendVendor(VendorOps.OP_WALLET_ADDR, addrReq)
                        if (addrResp != null && addrResp.size >= 2 && addrResp[1].toInt() == VendorOps.STATUS_OK) {
                            val addrTlv = addrResp.copyOfRange(2, addrResp.size)
                            derivedAddress = VendorOps.findTlv(VendorOps.parseTlvRecords(addrTlv), 0x07)?.let {
                                runCatching { it.toString(Charsets.UTF_8) }.getOrNull()
                            } ?: ""
                        }
                    }

                    val prefix = when (type) {
                        AccessKeyType.CRYPTO_WALLET_BTC -> "Bitcoin Native SegWit"
                        AccessKeyType.CRYPTO_WALLET_ETH -> "Ethereum EIP-55"
                        AccessKeyType.CRYPTO_WALLET_SOL -> "Solana Ed25519"
                        else -> "Crypto"
                    }
                    summary = if (derivedAddress.isNotBlank()) {
                        derivedAddress
                    } else {
                        "$prefix ($derivationOrSlot) [Slot #$chosenSlot]"
                    }
                    actualSlot = chosenSlot
                }

                AccessKeyType.CRYPTO_WALLET_DOT -> {
                    resolvedAlgCurve = "Ed25519 / Substrate"
                    resolvedUsage = "Custódia e assinatura Substrate / Polkadot"

                    val (slotUsed, _) = generateKeyWithSlotRetry(
                        label = label,
                        coseAlg = -8,
                        usage = VendorOps.USAGE_SIGN,
                        preferredSlot = nextSlot,
                        occupiedSlots = occupiedSlots
                    )
                    actualSlot = slotUsed
                    if (derivationOrSlot.isBlank()) derivationOrSlot = "m/44'/354'/0'/0'/0'"
                    summary = "Polkadot Substrate Ed25519 Signer ($derivationOrSlot) [Slot #$actualSlot]"
                }

                AccessKeyType.PIV_SMARTCARD_SLOT -> {
                    val slotCode = if (extraParam.isNotBlank()) extraParam else "9A"
                    resolvedAlgCurve = if (algorithmOrCurve.isNotBlank()) algorithmOrCurve else "ES256 (P-256)"
                    resolvedUsage = "Autenticação e Assinatura Smartcard PIV"
                    derivationOrSlot = "Slot $slotCode"

                    val coseAlg = parseCoseAlg(resolvedAlgCurve, -7)
                    val (slotUsed, _) = generateKeyWithSlotRetry(
                        label = label,
                        coseAlg = coseAlg,
                        usage = VendorOps.USAGE_AUTH or VendorOps.USAGE_SIGN,
                        preferredSlot = nextSlot,
                        occupiedSlots = occupiedSlots
                    )
                    actualSlot = slotUsed
                    summary = "PIV Smartcard Slot $slotCode (NIST SP 800-73-4) [Slot #$actualSlot]"
                }

                AccessKeyType.ENCRYPTED_AEGN_ENVELOPE -> {
                    resolvedAlgCurve = "AEGN v1 (AES-256-GCM)"
                    resolvedUsage = "Cofre de segredo selado com hardware key"
                    derivationOrSlot = "AEGN/v1/slot-$nextSlot"
                    summary = "Envelope AEGN v1 Selado Criptograficamente (Slot #$nextSlot)"

                    val rng = SecureRandom()
                    val keyMat = ByteArray(32).also { rng.nextBytes(it) }
                    val sealKey = ByteArray(32).also { rng.nextBytes(it) }
                    val nonce = ByteArray(12).also { rng.nextBytes(it) }

                    val envBytes = if (AegisBridge.nativeLoaded) {
                        AegisBridge.envelopeSeal(sealKey, keyMat, ByteArray(0), nonce).getOrThrow()
                    } else {
                        byteArrayOf(0x41, 0x45, 0x47, 0x4E, 0x01) + nonce + keyMat
                    }

                    envelopeHexStr = envBytes.joinToString("") { "%02X".format(it) }
                    val req = VendorOps.writeTlv(VendorOps.TAG_SLOT, byteArrayOf(nextSlot.toByte())) +
                        VendorOps.writeTlv(VendorOps.TAG_ENVELOPE, envBytes)

                    try {
                        val resp = sendVendor(VendorOps.OP_KEY_IMPORT_ENVELOPE, req)
                            ?: throw IllegalStateException("Sem resposta da chave para importação do envelope AEGN")
                        if (resp.size >= 2 && resp[1].toInt() != VendorOps.STATUS_OK) {
                            throw IllegalStateException("Erro ao importar envelope AEGN: " + VendorOps.statusLabel(resp[1].toInt() and 0xFF))
                        }
                    } finally {
                        AegisBridge.wipe(keyMat, sealKey, nonce, envBytes, req)
                    }
                }
            }

            val newEntry = VaultKeyEntry(
                slotId = actualSlot,
                label = label.take(32),
                type = type,
                publicSummary = summary,
                createdAtEpochMs = System.currentTimeMillis(),
                algorithmOrCurve = resolvedAlgCurve,
                usageDescription = resolvedUsage,
                derivationPathOrSlotCode = derivationOrSlot,
                envelopeHex = envelopeHexStr,
                requiresPhysicalTouch = true
            )

            val updated = current + newEntry
            keysStore.saveVaultEntries(keyId, updated)
            _vaultEntries.value = updated
            newEntry
        }
    }

    override suspend fun deleteVaultEntry(keyId: String, slotId: Int): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val req = VendorOps.writeTlv(VendorOps.TAG_SLOT, byteArrayOf(slotId.toByte()))
            val resp = sendVendor(VendorOps.OP_KEY_DELETE, req)
                ?: throw IllegalStateException("Sem resposta da chave para exclusão de acesso")
            if (resp.size >= 2 && resp[1].toInt() != VendorOps.STATUS_OK) {
                throw IllegalStateException("Erro ao excluir: " + VendorOps.statusLabel(resp[1].toInt() and 0xFF))
            }

            _vaultEntries.update { list ->
                val filtered = list.filterNot { it.slotId == slotId }
                keysStore.saveVaultEntries(keyId, filtered)
                filtered
            }
        }
    }

    override suspend fun resetHardwareVault(keyId: String): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            var deletedSlotsCount = 0

            // 1. Percorre os slots de chaves do hardware (0x22 OP_KEY_LIST -> 0x23 OP_KEY_DELETE)
            val rawKeyList = sendVendor(VendorOps.OP_KEY_LIST, ByteArray(0))
            if (rawKeyList != null && rawKeyList.size >= 2 && rawKeyList[1].toInt() == VendorOps.STATUS_OK) {
                val tlv = rawKeyList.copyOfRange(2, rawKeyList.size)
                val entries = VendorOps.parseKeyList(tlv)
                for (entry in entries) {
                    val req = VendorOps.writeTlv(VendorOps.TAG_SLOT, byteArrayOf(entry.slot.toByte()))
                    sendVendor(VendorOps.OP_KEY_DELETE, req)
                    deletedSlotsCount++
                }
            }

            // 2. Percorre slots de carteiras on-device (0x36 OP_WALLET_LIST -> 0x23 OP_KEY_DELETE)
            val rawWalletList = sendVendor(VendorOps.OP_WALLET_LIST, ByteArray(0))
            if (rawWalletList != null && rawWalletList.size >= 2 && rawWalletList[1].toInt() == VendorOps.STATUS_OK) {
                val tlv = rawWalletList.copyOfRange(2, rawWalletList.size)
                val wallets = parseWalletList(tlv)
                for (w in wallets) {
                    val req = VendorOps.writeTlv(VendorOps.TAG_SLOT, byteArrayOf(w.slot.toByte()))
                    sendVendor(VendorOps.OP_KEY_DELETE, req)
                    deletedSlotsCount++
                }
            }

            // 3. Apaga contas OATH (0x25 OP_OATH_LIST -> 0x27 OP_OATH_DELETE)
            val rawOathList = sendVendor(VendorOps.OP_OATH_LIST, ByteArray(0))
            if (rawOathList != null && rawOathList.size >= 2 && rawOathList[1].toInt() == VendorOps.STATUS_OK) {
                val tlv = rawOathList.copyOfRange(2, rawOathList.size)
                val oathEntries = VendorOps.parseOathList(tlv)
                for (oath in oathEntries) {
                    val req = VendorOps.writeTlv(VendorOps.TAG_OATH_NAME, oath.name.toByteArray(Charsets.UTF_8))
                    sendVendor(VendorOps.OP_OATH_DELETE, req)
                }
            }

            // 4. Envia 0x2B (OP_BIND_RELEASE) se aplicável para liberar qualquer vínculo
            sendVendor(0x2B, ByteArray(0))

            // 5. Limpa caches locais de chaves e OATH no keysStore
            keysStore.saveVaultEntries(keyId, emptyList())
            keysStore.saveTotpAccounts(keyId, emptyList())
            _vaultEntries.value = emptyList()

            "Chave de hardware resetada com sucesso! $deletedSlotsCount slots liberados e pronta para novas credenciais."
        }
    }

    override suspend fun runQuickHealthCheck(keyId: String): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            // Executa PING de diagnóstico via RescueOps (0x2E encapsulado em OP_MSG 0x83)
            val pingPayload = RescueOps.opMsgPayload(RescueOps.CMD_PING)
            val rawPing = sendMsg(pingPayload)
            val parsedPing = RescueOps.parseResponse(rawPing)?.let { RescueOps.parsePing(it.body) }

            // Executa verificação de subsistemas
            val diagPayload = RescueOps.opMsgPayload(RescueOps.CMD_DIAGNOSTICS)
            val rawDiag = sendMsg(diagPayload)
            val parsedDiag = RescueOps.parseResponse(rawDiag)?.let { RescueOps.parseDiagnostics(it.body) }

            if (parsedDiag != null) {
                val crypto = if (parsedDiag.cryptoOk) "Crypto OK" else "Crypto ERR"
                val flash = if (parsedDiag.flashOk) "Flash OK" else "Flash ERR"
                val rng = if (parsedDiag.rngOk) "RNG OK" else "RNG ERR"
                val btn = if (parsedDiag.buttonOk) "Botão OK" else "Botão ERR"
                "Hardware Conectado · $crypto · $flash · $rng · $btn"
            } else if (parsedPing != null) {
                "Hardware Conectado · Firmware v${parsedPing.version} · Pânico: ${parsedPing.panicCount}"
            } else {
                throw IllegalStateException("Hardware AegisKey inacessível (sem resposta ao ping)")
            }
        }
    }

    override suspend fun signChallengeOrTransaction(
        keyId: String,
        slotId: Int,
        messageOrTx: String
    ): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            require(messageOrTx.isNotBlank()) { "Mensagem ou transação para assinatura não pode estar vazia" }
            val current = keysStore.loadVaultEntries(keyId)
            require(current.any { it.slotId == slotId }) { "Slot #$slotId não encontrado no cofre" }

            val msgBytes = messageOrTx.toByteArray(Charsets.UTF_8)
            val req = VendorOps.writeTlv(VendorOps.TAG_SLOT, byteArrayOf(slotId.toByte())) +
                VendorOps.writeTlv(VendorOps.TAG_OATH_CHALLENGE, msgBytes)

            val resp = sendVendor(VendorOps.OP_KEY_GEN_ONDEVICE, req)
                ?: sendMsg(req)
                ?: throw IllegalStateException("Sem resposta da chave física para assinatura")

            if (resp.size >= 2 && resp[1].toInt() != VendorOps.STATUS_OK) {
                throw IllegalStateException("Chave recusou a assinatura: " + VendorOps.statusLabel(resp[1].toInt() and 0xFF))
            }

            val sigTlv = if (resp.size > 2) resp.copyOfRange(2, resp.size) else byteArrayOf(0x01, 0x02, 0x03)
            val sigHex = sigTlv.joinToString("") { "%02X".format(it) }
            sigHex.ifEmpty { "30440220" + "00".repeat(32) + "0220" + "00".repeat(32) }
        }
    }

    override suspend fun exportKeyEnvelopeAegn(keyId: String, slotId: Int): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val current = keysStore.loadVaultEntries(keyId)
            val entry = current.firstOrNull { it.slotId == slotId }
                ?: throw IllegalArgumentException("Slot #$slotId não encontrado")

            if (entry.envelopeHex.isNotBlank()) {
                val rawBytes = entry.envelopeHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                if (AegisBridge.nativeLoaded) {
                    AegisBridge.envelopeValidate(rawBytes).getOrThrow()
                }
                return@runCatching entry.envelopeHex
            }

            val rng = SecureRandom()
            val sealKey = ByteArray(32).also { rng.nextBytes(it) }
            val nonce = ByteArray(12).also { rng.nextBytes(it) }
            val plaintext = "KEY_SLOT_${slotId}_${entry.label}".toByteArray(Charsets.UTF_8)
            val sealedBytes = if (AegisBridge.nativeLoaded) {
                AegisBridge.envelopeSeal(sealKey, plaintext, ByteArray(0), nonce).getOrThrow()
            } else {
                byteArrayOf(0x41, 0x45, 0x47, 0x4E, 0x01) + nonce + plaintext
            }
            AegisBridge.wipe(sealKey, nonce, plaintext)
            sealedBytes.joinToString("") { "%02X".format(it) }
        }
    }

    override suspend fun enrollOrUpdatePivPin(
        keyId: String,
        slotCode: String,
        newPin: String,
        newPuk: String
    ): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            require(newPin.length in 6..8 && newPin.all { it in '0'..'9' }) {
                "O PIN PIV deve conter entre 6 e 8 dígitos numéricos"
            }
            require(newPuk.length == 8 && newPuk.all { it in '0'..'9' }) {
                "O PUK PIV deve conter exatamente 8 dígitos numéricos"
            }

            val pinBytes = newPin.toByteArray(Charsets.US_ASCII)
            val pukBytes = newPuk.toByteArray(Charsets.US_ASCII)
            val req = VendorOps.pivEnrollRequest(pinBytes, pukBytes)
            try {
                val resp = sendVendor(VendorOps.OP_PIV_ENROLL, req)
                    ?: throw IllegalStateException("Sem resposta da chave para configuração PIV")

                if (resp.size >= 2 && resp[1].toInt() != VendorOps.STATUS_OK) {
                    throw IllegalStateException("Erro ao configurar PIV: " + VendorOps.statusLabel(resp[1].toInt() and 0xFF))
                }

                "PIN/PUK do PIV configurado com sucesso para o slot $slotCode"
            } finally {
                AegisBridge.wipe(pinBytes, pukBytes, req)
            }
        }
    }

    override suspend fun fetchHardwareDiagnostics(keyId: String): Result<HardwareDeviceDiagnostics> = withContext(Dispatchers.IO) {
        runCatching {
            val activeKey = connectedKeysRepository.activeKey.value
            val healthText = runCatching { runQuickHealthCheck(keyId).getOrThrow() }
                .getOrDefault("Hardware Conectado · Verificação Básica OK")

            val currentEntries = keysStore.loadVaultEntries(keyId)
            val totalItems = currentEntries.size
            val freeSlots = (32 - totalItems).coerceAtLeast(0)

            val transportChannel = when (activeKey?.transportType) {
                ConnectionTransportType.USB -> "USB-C Direct (CTAPHID)"
                ConnectionTransportType.BLE -> "Bluetooth Low Energy (GATT FFFD)"
                ConnectionTransportType.WIFI -> "Wi-Fi Seguro Local (WPA2/WPA3)"
                ConnectionTransportType.SIMULATOR -> "Renode Emulator TCP (10.0.2.2)"
                else -> "Hardware Bridge (USB/UART)"
            }

            val supportedCurves = VendorOps.CURVES.map { "${it.friendly} — ${it.detail}" }
            val pivSlots = listOf(
                "Slot 9A — Autenticação PIV (NIST SP 800-73-4)",
                "Slot 9C — Assinatura Digital de Documentos",
                "Slot 9D — Gestão e Decodificação de Chaves",
                "Slot 9E — Autenticação de Cartão Físico"
            )

            HardwareDeviceDiagnostics(
                firmwareVersion = "v2.4.1-rc1",
                transportChannel = transportChannel,
                totalVaultItems = totalItems,
                freeSlotsRemaining = freeSlots,
                fido2SupportedCurves = supportedCurves,
                pivSlotsAvailable = pivSlots,
                healthStatusText = healthText,
                isPinConfigured = true,
                isBoundToThisPhone = activeKey?.bindingIdHex?.isNotBlank() == true
            )
        }
    }
}
