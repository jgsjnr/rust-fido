package dev.aegiskey.app.domain.usecase

import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.domain.repository.KeyVaultRepository
import kotlinx.coroutines.flow.StateFlow

class GetVaultEntriesUseCase(
    private val repository: KeyVaultRepository
) {
    operator fun invoke(): StateFlow<List<VaultKeyEntry>> = repository.vaultEntries
}

class RefreshVaultUseCase(
    private val repository: KeyVaultRepository
) {
    suspend operator fun invoke(keyId: String): Result<List<VaultKeyEntry>> =
        repository.refreshVault(keyId)
}

class GenerateAccessKeyUseCase(
    private val repository: KeyVaultRepository
) {
    suspend operator fun invoke(keyId: String, label: String, type: AccessKeyType): Result<VaultKeyEntry> =
        repository.generateNewAccessKey(keyId, label, type)
}

class DeleteVaultEntryUseCase(
    private val repository: KeyVaultRepository
) {
    suspend operator fun invoke(keyId: String, slotId: Int): Result<Unit> =
        repository.deleteVaultEntry(keyId, slotId)
}

class RunHealthCheckUseCase(
    private val repository: KeyVaultRepository
) {
    suspend operator fun invoke(keyId: String): Result<String> =
        repository.runQuickHealthCheck(keyId)
}
