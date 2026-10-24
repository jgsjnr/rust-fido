package dev.aegiskey.app.domain.usecase

import dev.aegiskey.app.domain.model.TotpAccountItem
import dev.aegiskey.app.domain.repository.TotpRepository
import kotlinx.coroutines.flow.StateFlow

class GetTotpAccountsUseCase(
    private val repository: TotpRepository
) {
    operator fun invoke(): StateFlow<List<TotpAccountItem>> = repository.accounts
}

class RefreshTotpCodesUseCase(
    private val repository: TotpRepository
) {
    suspend operator fun invoke(keyId: String): Result<List<TotpAccountItem>> =
        repository.refreshAccountsAndCodes(keyId)
}

class AddTotpAccountUseCase(
    private val repository: TotpRepository
) {
    suspend operator fun invoke(
        keyId: String,
        issuer: String,
        accountName: String,
        secretOrUri: String,
        digits: Int = 6
    ): Result<TotpAccountItem> =
        repository.addAccount(keyId, issuer, accountName, secretOrUri, digits)
}

class DeleteTotpAccountUseCase(
    private val repository: TotpRepository
) {
    suspend operator fun invoke(keyId: String, accountId: String): Result<Unit> =
        repository.deleteAccount(keyId, accountId)
}

class TickTotpTimerUseCase(
    private val repository: TotpRepository
) {
    operator fun invoke(nowEpochSeconds: Long = System.currentTimeMillis() / 1000L) =
        repository.tickTimer(nowEpochSeconds)
}
