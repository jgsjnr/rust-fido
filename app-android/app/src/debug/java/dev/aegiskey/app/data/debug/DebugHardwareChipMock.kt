package dev.aegiskey.app.data.debug

import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DiscoveredKeyCandidate
import dev.aegiskey.app.domain.model.TotpAccountItem
import dev.aegiskey.app.domain.model.VaultKeyEntry
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.nio.ByteBuffer
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Mock inteligente e realista do chip físico ESP32-S3 + ATECC608A.
 * Compilado EXCLUSIVAMENTE no source set 'debug' (:app:assembleDebug).
 * NÃO existe no pacote de release da aplicação real.
 */
object DebugHardwareChipMock {

    var IS_MOCK_ENABLED: Boolean = false
    val isDebugMode: Boolean get() = IS_MOCK_ENABLED

    // Candidatos pré-configurados do chip simulado para cada transporte em DEBUG
    val MOCK_BLE_CANDIDATE = DiscoveredKeyCandidate(
        id = "AA:BB:CC:AE:61:01",
        name = "AegisKey FIDO2 BLE (Chip Simulado)",
        signalRssi = -46,
        transportType = ConnectionTransportType.BLE
    )

    val MOCK_USB_CANDIDATE = DiscoveredKeyCandidate(
        id = "USB:303A:AE61:01",
        name = "AegisKey USB-C Hardware (Chip Simulado)",
        signalRssi = 0,
        transportType = ConnectionTransportType.USB
    )

    val MOCK_SIMULATOR_CANDIDATE = DiscoveredKeyCandidate(
        id = "SIM:RENODE:5678",
        name = "AegisKey Renode Chip (10.0.2.2:5678)",
        signalRssi = -35,
        transportType = ConnectionTransportType.SIMULATOR
    )

    val MOCK_WIFI_CANDIDATE = DiscoveredKeyCandidate(
        id = "WIFI:http://192.168.4.1",
        name = "AegisKey Wi-Fi AP (192.168.4.1)",
        signalRssi = -35,
        transportType = ConnectionTransportType.WIFI
    )

    private val _isHoldSimulated = MutableStateFlow(false)
    val isHoldSimulated: StateFlow<Boolean> = _isHoldSimulated.asStateFlow()

    private val _isTouchSimulated = MutableStateFlow(false)
    val isTouchSimulated: StateFlow<Boolean> = _isTouchSimulated.asStateFlow()

    private val _isChipConnected = MutableStateFlow(true)
    val isChipConnected: StateFlow<Boolean> = _isChipConnected.asStateFlow()

    fun getCandidateForTransport(transport: ConnectionTransportType): DiscoveredKeyCandidate? {
        return when (transport) {
            ConnectionTransportType.BLE -> MOCK_BLE_CANDIDATE
            ConnectionTransportType.USB -> MOCK_USB_CANDIDATE
            ConnectionTransportType.WIFI -> MOCK_WIFI_CANDIDATE
            ConnectionTransportType.SIMULATOR -> MOCK_SIMULATOR_CANDIDATE
        }
    }

    fun isMockCandidate(candidateId: String?): Boolean {
        if (candidateId == null) return false
        return candidateId == MOCK_BLE_CANDIDATE.id ||
            candidateId == MOCK_USB_CANDIDATE.id ||
            candidateId == MOCK_SIMULATOR_CANDIDATE.id ||
            candidateId == MOCK_WIFI_CANDIDATE.id ||
            candidateId.startsWith("tcp:10.0.2.2") ||
            candidateId.startsWith("SIM:") ||
            candidateId.startsWith("WIFI:")
    }

    fun simulateHold5s() {
        _isHoldSimulated.value = true
    }

    fun simulateTouch() {
        _isTouchSimulated.value = true
    }

    fun simulateToggleConnection(): Boolean {
        _isChipConnected.value = !_isChipConnected.value
        return _isChipConnected.value
    }

    fun simulateHealthPing(): String {
        return "Chip ESP32-S3 (v1.4.0) • ATECC608A Seguro • Flash 16MB OK • Bateria 98%"
    }

    /**
     * Injeta dados ricos e realistas simulando a memória permanente NVS do chip
     * para a chave recém-conectada em ambiente de teste/debug.
     */
    fun seedChipDataForKey(keyId: String, store: EncryptedKeysStore) {
        // 1. Chaves de Cofre (Passkeys e Carteiras Web3)
        val sampleVault = listOf(
            VaultKeyEntry(
                slotId = 0,
                label = "GitHub Enterprise Passkey",
                type = AccessKeyType.PASSKEY_FIDO,
                publicSummary = "FIDO2 ES256 (P-256) • Residente no Chip • Slot #01",
                createdAtEpochMs = System.currentTimeMillis() - 86400000L * 5
            ),
            VaultKeyEntry(
                slotId = 1,
                label = "Google Conta Principal",
                type = AccessKeyType.PASSKEY_FIDO,
                publicSummary = "FIDO2 ES256 (P-256) • Residente no Chip • Slot #02",
                createdAtEpochMs = System.currentTimeMillis() - 86400000L * 3
            ),
            VaultKeyEntry(
                slotId = 2,
                label = "Carteira Bitcoin Principal",
                type = AccessKeyType.CRYPTO_WALLET_BTC,
                publicSummary = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                createdAtEpochMs = System.currentTimeMillis() - 86400000L * 2
            ),
            VaultKeyEntry(
                slotId = 3,
                label = "Carteira Ethereum Cofre",
                type = AccessKeyType.CRYPTO_WALLET_ETH,
                publicSummary = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
                createdAtEpochMs = System.currentTimeMillis() - 86400000L
            ),
            VaultKeyEntry(
                slotId = 4,
                label = "Carteira Solana Principal",
                type = AccessKeyType.CRYPTO_WALLET_SOL,
                publicSummary = "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH",
                createdAtEpochMs = System.currentTimeMillis()
            )
        )
        store.saveVaultEntries(keyId, sampleVault)

        // 2. Contas TOTP com segredos reais RFC 6238
        val nowSecs = System.currentTimeMillis() / 1000L
        val rem = 30 - (nowSecs % 30).toInt()

        val totpSecrets = listOf(
            Triple("GitHub", "junior@aegiskey.dev", "JBSWY3DPEHPK3PXP"),
            Triple("Google", "junior.fido@gmail.com", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
            Triple("AWS Cloud", "admin@aegiskey.cloud", "MFRGGZDFMZTWQ2LK"),
            Triple("Microsoft", "junior@outlook.com", "KRSXG5CTMVRXEZLU")
        )

        val sampleTotp = totpSecrets.map { (issuer, account, secret) ->
            val code = computeMockTotp(secret, nowSecs)
            val formatted = if (code.length == 6) "${code.substring(0, 3)} ${code.substring(3)}" else code
            TotpAccountItem(
                id = UUID.randomUUID().toString(),
                issuer = issuer,
                accountName = account,
                currentCode = code,
                formattedCode = formatted,
                remainingSeconds = if (rem == 0) 30 else rem,
                periodSeconds = 30,
                digits = 6,
                requiresTouchToRefresh = false
            )
        }
        store.saveTotpAccounts(keyId, sampleTotp)
    }

    /** Adiciona uma nova passkey e conta TOTP sob demanda pelo painel de debug. */
    fun injectExtraSample(keyId: String, store: EncryptedKeysStore) {
        val existingVault = store.loadVaultEntries(keyId)
        val nextSlot = (existingVault.maxOfOrNull { it.slotId } ?: -1) + 1
        val newVault = existingVault + VaultKeyEntry(
            slotId = nextSlot,
            label = "Bitwarden Passkey #${nextSlot + 1}",
            type = AccessKeyType.PASSKEY_FIDO,
            publicSummary = "FIDO2 Resident Credential • Slot #$nextSlot",
            createdAtEpochMs = System.currentTimeMillis()
        )
        store.saveVaultEntries(keyId, newVault)

        val nowSecs = System.currentTimeMillis() / 1000L
        val rem = 30 - (nowSecs % 30).toInt()
        val existingTotp = store.loadTotpAccounts(keyId)
        val newSecret = "JBSWY3DPEHPK3PXP"
        val code = computeMockTotp(newSecret, nowSecs)
        val newTotp = existingTotp + TotpAccountItem(
            id = UUID.randomUUID().toString(),
            issuer = "Binance Crypto",
            accountName = "trade@aegiskey.dev",
            currentCode = code,
            formattedCode = "${code.substring(0, 3)} ${code.substring(3)}",
            remainingSeconds = rem,
            periodSeconds = 30,
            digits = 6
        )
        store.saveTotpAccounts(keyId, newTotp)
    }

    private fun computeMockTotp(base32Secret: String, epochSeconds: Long): String {
        return try {
            val keyBytes = decodeBase32(base32Secret)
            val counter = epochSeconds / 30L
            val buffer = ByteBuffer.allocate(8).putLong(counter).array()
            val mac = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(keyBytes, "HmacSHA1")) }
            val hash = mac.doFinal(buffer)
            val offset = hash[hash.size - 1].toInt() and 0x0F
            val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
                ((hash[offset + 1].toInt() and 0xFF) shl 16) or
                ((hash[offset + 2].toInt() and 0xFF) shl 8) or
                (hash[offset + 3].toInt() and 0xFF)
            (binary % 1000000).toString().padStart(6, '0')
        } catch (_: Throwable) {
            "739102"
        }
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

    fun purgeResidualMockData(store: EncryptedKeysStore) {
        runCatching {
            val mockIds = setOf("AA:BB:CC:AE:61:01", "USB:303A:AE61:01", "SIM:RENODE:5678")
            val allKeys = store.loadConnectedKeys()
            val filteredKeys = allKeys.filterNot { key ->
                key.hardwareAddressOrId in mockIds ||
                    key.id in mockIds ||
                    key.displayName.contains("Chip Simulado") ||
                    key.displayName.contains("Chip Debug")
            }
            if (filteredKeys.size != allKeys.size) {
                store.saveConnectedKeys(filteredKeys)
                for (mockId in mockIds) {
                    store.removeKeyVaultAndTotp(mockId)
                }
                val active = store.loadActiveKeyId()
                if (active in mockIds || filteredKeys.none { it.id == active }) {
                    store.saveActiveKeyId(filteredKeys.firstOrNull()?.id)
                }
            }

            for (key in filteredKeys) {
                val vault = store.loadVaultEntries(key.id)
                val cleanVault = vault.filterNot { it.label.contains("Enterprise Passkey") }
                if (cleanVault.size != vault.size) {
                    store.saveVaultEntries(key.id, cleanVault)
                }
            }
        }
    }
}
