package dev.aegiskey.app.domain.usecase

import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.HardwareDeviceDiagnostics
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
    suspend operator fun invoke(
        keyId: String,
        label: String,
        type: AccessKeyType,
        algorithmOrCurve: String = "ES256 (P-256)",
        extraParam: String = ""
    ): Result<VaultKeyEntry> =
        repository.generateNewAccessKey(keyId, label, type, algorithmOrCurve, extraParam)
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

class SignChallengeOrTransactionUseCase(
    private val repository: KeyVaultRepository
) {
    suspend operator fun invoke(keyId: String, slotId: Int, messageOrTx: String): Result<String> =
        repository.signChallengeOrTransaction(keyId, slotId, messageOrTx)
}

class ExportKeyEnvelopeAegnUseCase(
    private val repository: KeyVaultRepository
) {
    suspend operator fun invoke(keyId: String, slotId: Int): Result<String> =
        repository.exportKeyEnvelopeAegn(keyId, slotId)
}

class EnrollOrUpdatePivPinUseCase(
    private val repository: KeyVaultRepository
) {
    suspend operator fun invoke(keyId: String, slotCode: String, newPin: String, newPuk: String): Result<String> =
        repository.enrollOrUpdatePivPin(keyId, slotCode, newPin, newPuk)
}

class FetchHardwareDiagnosticsUseCase(
    private val repository: KeyVaultRepository
) {
    suspend operator fun invoke(keyId: String): Result<HardwareDeviceDiagnostics> =
        repository.fetchHardwareDiagnostics(keyId)
}
