package dev.aegiskey.app.domain.repository

import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStatus

/**
 * Contrato de repositório para o cofre de autoridade on-device Secure Guard (Zero-Trust).
 *
 * Todas as operações são confirmadas em hardware e nunca expõem ou persistem
 * PINs ou Recovery Codes em texto plano na camada móvel.
 */
interface SecureGuardRepository {
    suspend fun getStatus(): Result<SecureGuardStatus>
    suspend fun provision(pin: String, recoveryCode: String? = null, policy: SecureGuardPolicy? = null): Result<String>
    suspend fun unlock(pin: String): Result<SecureGuardStatus>
    suspend fun lock(): Result<Unit>
    suspend fun changePin(currentPin: String, newPin: String): Result<Unit>
    suspend fun recover(recoveryCode: String, newPin: String): Result<String?>
    suspend fun updatePolicy(policy: SecureGuardPolicy): Result<SecureGuardPolicy>
    suspend fun wipeSelective(scope: Int = 0, confirmationToken: String): Result<Boolean>
}
