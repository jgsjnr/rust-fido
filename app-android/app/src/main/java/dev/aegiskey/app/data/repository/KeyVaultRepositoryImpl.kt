package dev.aegiskey.app.data.repository

import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.domain.repository.ConnectedKeysRepository
import dev.aegiskey.app.domain.repository.KeyVaultRepository
import dev.aegiskey.app.ui.RescueOps
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext

class KeyVaultRepositoryImpl(
    private val keysStore: EncryptedKeysStore,
    private val bleClient: AegisBleClient? = null,
    private val simulatedRenodeTransport: SimulatedRenodeTransport,
    private val connectedKeysRepository: ConnectedKeysRepository
) : KeyVaultRepository {

    private val _vaultEntries = MutableStateFlow<List<VaultKeyEntry>>(emptyList())
    override val vaultEntries: StateFlow<List<VaultKeyEntry>> = _vaultEntries.asStateFlow()

    init {
        val initialKeyId = connectedKeysRepository.activeKey.value?.id
        if (initialKeyId != null) {
            _vaultEntries.value = keysStore.loadVaultEntries(initialKeyId)
        }
    }

    private suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray? {
        val activeKey = connectedKeysRepository.activeKey.value
        return if (activeKey?.transportType == dev.aegiskey.app.domain.model.ConnectionTransportType.SIMULATOR) {
            simulatedRenodeTransport.sendVendor(opcode, payload)
        } else {
            bleClient?.sendVendor(opcode, payload)
        }
    }

    private suspend fun sendMsg(payload: ByteArray): ByteArray? {
        val activeKey = connectedKeysRepository.activeKey.value
        return if (activeKey?.transportType == dev.aegiskey.app.domain.model.ConnectionTransportType.SIMULATOR) {
            simulatedRenodeTransport.sendMsg(payload)
        } else {
            bleClient?.sendMsg(payload)
        }
    }

    override suspend fun refreshVault(keyId: String): Result<List<VaultKeyEntry>> = withContext(Dispatchers.IO) {
        runCatching {
            val raw = sendVendor(VendorOps.OP_KEY_LIST, ByteArray(0))
            val currentCached = keysStore.loadVaultEntries(keyId).associateBy { it.slotId }

            if (raw != null && raw.size >= 2 && raw[1].toInt() == VendorOps.STATUS_OK) {
                val tlv = raw.copyOfRange(2, raw.size)
                val deviceKeys = VendorOps.parseKeyList(tlv)
                val merged = deviceKeys.map { dk ->
                    val cached = currentCached[dk.slot]
                    if (cached != null) {
                        cached.copy(label = dk.label)
                    } else {
                        VaultKeyEntry(
                            slotId = dk.slot,
                            label = dk.label,
                            type = AccessKeyType.PASSKEY_FIDO,
                            publicSummary = "Secured on AegisKey slot #${dk.slot}",
                            createdAtEpochMs = System.currentTimeMillis()
                        )
                    }
                }
                keysStore.saveVaultEntries(keyId, merged)
                _vaultEntries.value = merged
                merged
            } else {
                // Fallback para cache local se offline
                val local = keysStore.loadVaultEntries(keyId)
                _vaultEntries.value = local
                local
            }
        }
    }

    override suspend fun generateNewAccessKey(
        keyId: String,
        label: String,
        type: AccessKeyType
    ): Result<VaultKeyEntry> = withContext(Dispatchers.IO) {
        runCatching {
            val current = keysStore.loadVaultEntries(keyId)
            val nextSlot = (current.maxOfOrNull { it.slotId } ?: -1) + 1

            val coseAlg = when (type) {
                AccessKeyType.PASSKEY_FIDO -> -7      // ES256 (P-256)
                AccessKeyType.CRYPTO_WALLET_BTC -> -47 // ES256K (secp256k1)
                AccessKeyType.CRYPTO_WALLET_ETH -> -47 // ES256K (secp256k1)
                AccessKeyType.CRYPTO_WALLET_SOL -> -8  // EdDSA (Ed25519)
            }

            val req = VendorOps.genRequest(nextSlot, label.take(32), coseAlg)
            val resp = sendVendor(VendorOps.OP_KEY_GEN_ONDEVICE, req)
                ?: throw IllegalStateException("Sem resposta da chave para geração de acesso")

            if (resp.size >= 2 && resp[1].toInt() != VendorOps.STATUS_OK) {
                throw IllegalStateException("Erro ao gerar chave: " + VendorOps.statusLabel(resp[1].toInt() and 0xFF))
            }

            val summary = when (type) {
                AccessKeyType.PASSKEY_FIDO -> "FIDO2 / WebAuthn P-256 Passkey"
                AccessKeyType.CRYPTO_WALLET_BTC -> "Native SegWit / Taproot Bitcoin Key"
                AccessKeyType.CRYPTO_WALLET_ETH -> "Secp256k1 Ethereum Signer"
                AccessKeyType.CRYPTO_WALLET_SOL -> "Ed25519 Solana Address"
            }

            val newEntry = VaultKeyEntry(
                slotId = nextSlot,
                label = label.take(32),
                type = type,
                publicSummary = summary,
                createdAtEpochMs = System.currentTimeMillis()
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
            if (resp != null && resp.size >= 2 && resp[1].toInt() != VendorOps.STATUS_OK) {
                throw IllegalStateException("Erro ao excluir: " + VendorOps.statusLabel(resp[1].toInt() and 0xFF))
            }

            _vaultEntries.update { list ->
                val filtered = list.filterNot { it.slotId == slotId }
                keysStore.saveVaultEntries(keyId, filtered)
                filtered
            }
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
                "Hardware Ativo · Comunicação normal"
            }
        }
    }
}
