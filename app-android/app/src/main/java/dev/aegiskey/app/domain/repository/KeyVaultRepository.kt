package dev.aegiskey.app.domain.repository

import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.HardwareDeviceDiagnostics
import dev.aegiskey.app.domain.model.VaultKeyEntry
import kotlinx.coroutines.flow.StateFlow

interface KeyVaultRepository {
    val vaultEntries: StateFlow<List<VaultKeyEntry>>

    suspend fun refreshVault(keyId: String): Result<List<VaultKeyEntry>>
    suspend fun generateNewAccessKey(
        keyId: String,
        label: String,
        type: AccessKeyType,
        algorithmOrCurve: String = "ES256 (P-256)",
        extraParam: String = ""
    ): Result<VaultKeyEntry>

    suspend fun deleteVaultEntry(keyId: String, slotId: Int): Result<Unit>
    suspend fun resetHardwareVault(keyId: String): Result<String>
    suspend fun runQuickHealthCheck(keyId: String): Result<String>

    suspend fun signChallengeOrTransaction(keyId: String, slotId: Int, messageOrTx: String): Result<String>
    suspend fun exportKeyEnvelopeAegn(keyId: String, slotId: Int): Result<String>
    suspend fun enrollOrUpdatePivPin(keyId: String, slotCode: String, newPin: String, newPuk: String): Result<String>
    suspend fun fetchHardwareDiagnostics(keyId: String): Result<HardwareDeviceDiagnostics>

    /**
     * Per-credential touch (UP) policy (touchpolicy module, §8.4).
     * Local read with the fail-safe default (`true`) when unknown; SET
     * requires an unlocked session and translates the `0x40` response.
     */
    suspend fun getTouchRequired(keyId: String, slotId: Int): Boolean
    suspend fun setTouchRequired(keyId: String, slotId: Int, requireTouch: Boolean): Result<Unit>
    fun clearMemoryVault() {}
}
