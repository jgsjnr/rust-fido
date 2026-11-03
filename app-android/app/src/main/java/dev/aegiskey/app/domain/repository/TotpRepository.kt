package dev.aegiskey.app.domain.repository

import dev.aegiskey.app.domain.model.TotpAccountItem
import kotlinx.coroutines.flow.StateFlow

interface TotpRepository {
    val accounts: StateFlow<List<TotpAccountItem>>
    val remainingSeconds: StateFlow<Int>

    /**
     * Finding A3: outstanding device User Presence request. Holds the denied
     * op label ("oath-list" / "oath-code" / "oath-put" / ...) while the user
     * has not touched the key, or null when no presence is outstanding.
     */
    val needUpOp: StateFlow<String?>

    /** Dismisses the outstanding presence request (user cancelled). */
    fun clearNeedUpOp()

    suspend fun refreshAccountsAndCodes(keyId: String): Result<List<TotpAccountItem>>
    suspend fun addAccount(
        keyId: String,
        issuer: String,
        accountName: String,
        secretOrUri: String,
        digits: Int = 6,
        periodSeconds: Int = 30,
        isHotp: Boolean = false,
        algorithm: String = "SHA1"
    ): Result<TotpAccountItem>
    suspend fun deleteAccount(keyId: String, accountId: String): Result<Unit>
    suspend fun incrementHotpCounter(keyId: String, accountId: String): Result<TotpAccountItem>
    fun tickTimer(nowEpochSeconds: Long = System.currentTimeMillis() / 1000L)
}
