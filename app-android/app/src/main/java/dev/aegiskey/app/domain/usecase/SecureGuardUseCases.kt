package dev.aegiskey.app.domain.usecase

import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStatus
import dev.aegiskey.app.domain.repository.SecureGuardRepository

class GetSecureGuardStatusUseCase(val repo: SecureGuardRepository) {
    val statusFlow get() = repo.statusFlow
    suspend operator fun invoke(): Result<SecureGuardStatus> = repo.getStatus()
}

class ProvisionSecureGuardUseCase(private val repo: SecureGuardRepository) {
    suspend operator fun invoke(
        pin: String,
        recoveryCode: String? = null,
        policy: SecureGuardPolicy? = null
    ): Result<String> = repo.provision(pin, recoveryCode, policy)
}

class UnlockSecureGuardUseCase(private val repo: SecureGuardRepository) {
    suspend operator fun invoke(pin: String): Result<SecureGuardStatus> = repo.unlock(pin)
}

class LockSecureGuardUseCase(private val repo: SecureGuardRepository) {
    suspend operator fun invoke(): Result<Unit> = repo.lock()
}

class ChangeSecureGuardPinUseCase(private val repo: SecureGuardRepository) {
    suspend operator fun invoke(currentPin: String, newPin: String): Result<Unit> =
        repo.changePin(currentPin, newPin)
}

class RecoverSecureGuardUseCase(private val repo: SecureGuardRepository) {
    suspend operator fun invoke(recoveryCode: String, newPin: String): Result<String?> =
        repo.recover(recoveryCode, newPin)
}

class UpdateSecureGuardPolicyUseCase(private val repo: SecureGuardRepository) {
    suspend operator fun invoke(policy: SecureGuardPolicy): Result<SecureGuardPolicy> =
        repo.updatePolicy(policy)
}

class TriggerSelectiveWipeTestUseCase(private val repo: SecureGuardRepository) {
    suspend operator fun invoke(scope: Int = 0, confirmationToken: String): Result<Boolean> =
        repo.wipeSelective(scope, confirmationToken)
}
