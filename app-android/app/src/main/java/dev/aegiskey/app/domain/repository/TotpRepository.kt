package dev.aegiskey.app.domain.repository

import dev.aegiskey.app.domain.model.TotpAccountItem
import kotlinx.coroutines.flow.StateFlow

interface TotpRepository {
    val accounts: StateFlow<List<TotpAccountItem>>
    val remainingSeconds: StateFlow<Int>

    suspend fun refreshAccountsAndCodes(keyId: String): Result<List<TotpAccountItem>>
    suspend fun addAccount(keyId: String, issuer: String, accountName: String, secretOrUri: String, digits: Int = 6): Result<TotpAccountItem>
    suspend fun deleteAccount(keyId: String, accountId: String): Result<Unit>
    fun tickTimer(nowEpochSeconds: Long = System.currentTimeMillis() / 1000L)
}
