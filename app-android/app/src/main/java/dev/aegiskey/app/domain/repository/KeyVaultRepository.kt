package dev.aegiskey.app.domain.repository

import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.VaultKeyEntry
import kotlinx.coroutines.flow.StateFlow

interface KeyVaultRepository {
    val vaultEntries: StateFlow<List<VaultKeyEntry>>

    suspend fun refreshVault(keyId: String): Result<List<VaultKeyEntry>>
    suspend fun generateNewAccessKey(keyId: String, label: String, type: AccessKeyType): Result<VaultKeyEntry>
    suspend fun deleteVaultEntry(keyId: String, slotId: Int): Result<Unit>
    suspend fun runQuickHealthCheck(keyId: String): Result<String>
}
