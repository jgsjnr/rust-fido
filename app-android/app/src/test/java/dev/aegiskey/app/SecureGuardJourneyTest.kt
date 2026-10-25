package dev.aegiskey.app

import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import dev.aegiskey.app.domain.repository.SecureGuardRepository
import dev.aegiskey.app.domain.usecase.ChangeSecureGuardPinUseCase
import dev.aegiskey.app.domain.usecase.GetSecureGuardStatusUseCase
import dev.aegiskey.app.domain.usecase.LockSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.ProvisionSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.RecoverSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.TriggerSelectiveWipeTestUseCase
import dev.aegiskey.app.domain.usecase.UnlockSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.UpdateSecureGuardPolicyUseCase
import dev.aegiskey.app.ui.viewmodel.SecureGuardViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Bateria de Testes Unitários das 13 Jornadas de UX do Secure Guard (UX Seção 11.2).
 * Valida a máquina de estados canônica (FSM), contadores de tentativas,
 * penalidades de taxa (rate-limit), recuperação e wipe seletivo.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SecureGuardJourneyTest {

    private val testDispatcher = StandardTestDispatcher()

    private class TestSecureGuardRepository : SecureGuardRepository {
        var currentStatus = SecureGuardStatus()
        var storedPin = ""
        var storedRecoveryCode = ""

        override suspend fun getStatus(): Result<SecureGuardStatus> = Result.success(currentStatus)

        override suspend fun provision(
            pin: String,
            recoveryCode: String?,
            policy: SecureGuardPolicy?
        ): Result<String> {
            if (pin.length < 4) return Result.failure(IllegalArgumentException("PIN muito curto"))
            storedPin = pin
            storedRecoveryCode = recoveryCode ?: "ABCD-EFGH-JKLM-NPQR"
            val activePolicy = policy ?: SecureGuardPolicy()
            currentStatus = currentStatus.copy(
                state = SecureGuardStateEnum.UNLOCKED,
                isProvisioned = true,
                isUnlocked = true,
                failedAttempts = 0,
                remainingAttempts = 5,
                policy = activePolicy,
                lastGeneratedRecoveryCode = storedRecoveryCode,
                sessionRemainingMs = activePolicy.sessionDurationMs
            )
            return Result.success(storedRecoveryCode)
        }

        override suspend fun unlock(pin: String): Result<SecureGuardStatus> {
            if (!currentStatus.isProvisioned) {
                return Result.failure(IllegalStateException("Cofre não provisionado"))
            }
            if (currentStatus.state == SecureGuardStateEnum.RECOVERY_REQUIRED) {
                return Result.failure(SecurityException("Recuperação de emergência necessária"))
            }
            if (currentStatus.state == SecureGuardStateEnum.RATE_LIMITED && currentStatus.rateLimitRemainingMs > 0) {
                return Result.failure(SecurityException("Penalidade de taxa ativa"))
            }

            if (pin == storedPin) {
                currentStatus = currentStatus.copy(
                    state = SecureGuardStateEnum.UNLOCKED,
                    isUnlocked = true,
                    failedAttempts = 0,
                    remainingAttempts = 5,
                    rateLimitRemainingMs = 0,
                    sessionRemainingMs = currentStatus.policy.sessionDurationMs
                )
                return Result.success(currentStatus)
            } else {
                val nextFailed = currentStatus.failedAttempts + 1
                val remaining = (5 - nextFailed).coerceAtLeast(0)
                if (nextFailed >= 5) {
                    if (currentStatus.policy.wipeOn5Failures) {
                        currentStatus = SecureGuardStatus(
                            state = SecureGuardStateEnum.UNPROVISIONED,
                            isProvisioned = false,
                            lastWipeSimulated = currentStatus.policy.testModeNonDestructiveWipe
                        )
                        return Result.failure(SecurityException("Wipe acionado após 5 falhas"))
                    } else {
                        currentStatus = currentStatus.copy(
                            state = SecureGuardStateEnum.RECOVERY_REQUIRED,
                            failedAttempts = nextFailed,
                            remainingAttempts = 0,
                            isUnlocked = false
                        )
                        return Result.failure(SecurityException("5 falhas: recuperação de emergência necessária"))
                    }
                } else {
                    val backoffMs = (1L shl (nextFailed - 1)) * 1000L
                    currentStatus = currentStatus.copy(
                        state = SecureGuardStateEnum.RATE_LIMITED,
                        failedAttempts = nextFailed,
                        remainingAttempts = remaining,
                        rateLimitRemainingMs = backoffMs,
                        isUnlocked = false
                    )
                    return Result.failure(SecurityException("PIN inválido. Penalidade ${backoffMs / 1000}s"))
                }
            }
        }

        override suspend fun lock(): Result<Unit> {
            if (currentStatus.isProvisioned) {
                currentStatus = currentStatus.copy(
                    state = SecureGuardStateEnum.LOCKED,
                    isUnlocked = false,
                    sessionRemainingMs = 0
                )
            }
            return Result.success(Unit)
        }

        override suspend fun changePin(currentPin: String, newPin: String): Result<Unit> {
            if (currentPin != storedPin) return Result.failure(SecurityException("PIN atual incorreto"))
            if (newPin.length < 4) return Result.failure(IllegalArgumentException("Novo PIN muito curto"))
            storedPin = newPin
            currentStatus = currentStatus.copy(
                state = SecureGuardStateEnum.LOCKED,
                isUnlocked = false,
                sessionRemainingMs = 0
            )
            return Result.success(Unit)
        }

        override suspend fun recover(recoveryCode: String, newPin: String): Result<String?> {
            if (recoveryCode.trim() != storedRecoveryCode) {
                return Result.failure(SecurityException("Código de recuperação inválido"))
            }
            if (newPin.length < 4) return Result.failure(IllegalArgumentException("Novo PIN muito curto"))
            storedPin = newPin
            val newRc = "XXXX-YYYY-ZZZZ-WWWW"
            storedRecoveryCode = newRc
            currentStatus = currentStatus.copy(
                state = SecureGuardStateEnum.LOCKED,
                isUnlocked = false,
                failedAttempts = 0,
                remainingAttempts = 5,
                lastGeneratedRecoveryCode = newRc
            )
            return Result.success(newRc)
        }

        override suspend fun updatePolicy(policy: SecureGuardPolicy): Result<SecureGuardPolicy> {
            currentStatus = currentStatus.copy(policy = policy)
            return Result.success(policy)
        }

        override suspend fun wipeSelective(scope: Int, confirmationToken: String): Result<Boolean> {
            if (confirmationToken != "CONFIRM_WIPE_AEGIS_GUARD") {
                return Result.failure(IllegalArgumentException("Token inválido"))
            }
            val simulated = currentStatus.policy.testModeNonDestructiveWipe
            currentStatus = SecureGuardStatus(
                state = SecureGuardStateEnum.UNPROVISIONED,
                isProvisioned = false,
                lastWipeSimulated = simulated
            )
            return Result.success(simulated)
        }
    }

    private lateinit var repo: TestSecureGuardRepository
    private lateinit var viewModel: SecureGuardViewModel

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        repo = TestSecureGuardRepository()
        viewModel = SecureGuardViewModel(
            getSecureGuardStatusUseCase = GetSecureGuardStatusUseCase(repo),
            provisionSecureGuardUseCase = ProvisionSecureGuardUseCase(repo),
            unlockSecureGuardUseCase = UnlockSecureGuardUseCase(repo),
            lockSecureGuardUseCase = LockSecureGuardUseCase(repo),
            changeSecureGuardPinUseCase = ChangeSecureGuardPinUseCase(repo),
            recoverSecureGuardUseCase = RecoverSecureGuardUseCase(repo),
            updateSecureGuardPolicyUseCase = UpdateSecureGuardPolicyUseCase(repo),
            triggerSelectiveWipeTestUseCase = TriggerSelectiveWipeTestUseCase(repo)
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun journey01_initialUnprovisionedState() = runTest {
        testDispatcher.scheduler.runCurrent()
        val state = viewModel.uiState.first()
        assertEquals(SecureGuardStateEnum.UNPROVISIONED, state.status.state)
        assertFalse(state.status.isProvisioned)
        assertFalse(state.status.isUnlocked)
        assertEquals(5, state.status.remainingAttempts)
    }

    @Test
    fun journey02_provisioningSuccess() = runTest {
        viewModel.provision("123456", "RECOVERY-1234-5678", null)
        testDispatcher.scheduler.runCurrent()

        val state = viewModel.uiState.first()
        assertEquals(SecureGuardStateEnum.UNLOCKED, state.status.state)
        assertTrue(state.status.isProvisioned)
        assertTrue(state.status.isUnlocked)
        assertEquals("RECOVERY-1234-5678", state.generatedRecoveryCode)
    }

    @Test
    fun journey03_instantLockSession() = runTest {
        viewModel.provision("123456", null, null)
        testDispatcher.scheduler.runCurrent()

        viewModel.lock()
        testDispatcher.scheduler.runCurrent()

        val state = viewModel.uiState.first()
        assertEquals(SecureGuardStateEnum.LOCKED, state.status.state)
        assertFalse(state.status.isUnlocked)
        assertEquals(0L, state.status.sessionRemainingMs)
    }

    @Test
    fun journey04_unlockWithCorrectPin() = runTest {
        viewModel.provision("123456", null, null)
        viewModel.lock()
        testDispatcher.scheduler.runCurrent()

        viewModel.unlock("123456")
        testDispatcher.scheduler.runCurrent()

        val state = viewModel.uiState.first()
        assertEquals(SecureGuardStateEnum.UNLOCKED, state.status.state)
        assertTrue(state.status.isUnlocked)
        assertEquals(0, state.status.failedAttempts)
    }

    @Test
    fun journey05_wrongPinFirstAttemptBackoff() = runTest {
        viewModel.provision("123456", null, null)
        viewModel.lock()
        testDispatcher.scheduler.runCurrent()

        viewModel.unlock("999999")
        testDispatcher.scheduler.runCurrent()

        val state = viewModel.uiState.first()
        assertEquals(SecureGuardStateEnum.RATE_LIMITED, state.status.state)
        assertEquals(1, state.status.failedAttempts)
        assertEquals(4, state.status.remainingAttempts)
        assertEquals(1000L, state.status.rateLimitRemainingMs)
        assertNotNull(state.errorMessage)
    }

    @Test
    fun journey06_wrongPinGraduatedBackoff() = runTest {
        viewModel.provision("123456", null, null)
        viewModel.lock()
        testDispatcher.scheduler.runCurrent()

        // 1st wrong attempt -> 1s
        viewModel.unlock("999999")
        testDispatcher.scheduler.runCurrent()
        assertEquals(1000L, viewModel.uiState.value.status.rateLimitRemainingMs)

        // Clear penalty
        repo.currentStatus = repo.currentStatus.copy(rateLimitRemainingMs = 0)

        // 2nd wrong attempt -> 2s
        viewModel.unlock("999999")
        testDispatcher.scheduler.runCurrent()
        assertEquals(2000L, viewModel.uiState.value.status.rateLimitRemainingMs)
        assertEquals(3, viewModel.uiState.value.status.remainingAttempts)

        // Clear penalty
        repo.currentStatus = repo.currentStatus.copy(rateLimitRemainingMs = 0)

        // 3rd wrong attempt -> 4s
        viewModel.unlock("999999")
        testDispatcher.scheduler.runCurrent()
        assertEquals(4000L, viewModel.uiState.value.status.rateLimitRemainingMs)
        assertEquals(2, viewModel.uiState.value.status.remainingAttempts)

        // Clear penalty
        repo.currentStatus = repo.currentStatus.copy(rateLimitRemainingMs = 0)

        // 4th wrong attempt -> 8s
        viewModel.unlock("999999")
        testDispatcher.scheduler.runCurrent()
        assertEquals(8000L, viewModel.uiState.value.status.rateLimitRemainingMs)
        assertEquals(1, viewModel.uiState.value.status.remainingAttempts)
    }

    @Test
    fun journey07_rateLimitedRejection() = runTest {
        viewModel.provision("123456", null, null)
        viewModel.lock()
        viewModel.unlock("wrong_pin")
        testDispatcher.scheduler.runCurrent()

        // Still rate limited
        viewModel.unlock("123456")
        testDispatcher.scheduler.runCurrent()

        val state = viewModel.uiState.first()
        assertEquals(SecureGuardStateEnum.RATE_LIMITED, state.status.state)
        assertFalse(state.status.isUnlocked)
    }

    @Test
    fun journey08_fifthFailureRecoveryRequired() = runTest {
        viewModel.provision("123456", null, SecureGuardPolicy(wipeOn5Failures = false))
        viewModel.lock()
        testDispatcher.scheduler.runCurrent()

        for (i in 1..5) {
            repo.currentStatus = repo.currentStatus.copy(rateLimitRemainingMs = 0)
            viewModel.unlock("wrong_pin")
            testDispatcher.scheduler.runCurrent()
        }

        val state = viewModel.uiState.first()
        assertEquals(SecureGuardStateEnum.RECOVERY_REQUIRED, state.status.state)
        assertEquals(0, state.status.remainingAttempts)
        assertEquals(5, state.status.failedAttempts)
    }

    @Test
    fun journey09_emergencyRecoveryWithRecoveryCode() = runTest {
        viewModel.provision("123456", "RECOVERY-1234-5678", null)
        viewModel.lock()
        testDispatcher.scheduler.runCurrent()

        // Force into RECOVERY_REQUIRED
        repo.currentStatus = repo.currentStatus.copy(state = SecureGuardStateEnum.RECOVERY_REQUIRED, failedAttempts = 5)

        viewModel.recover("RECOVERY-1234-5678", "654321")
        testDispatcher.scheduler.runCurrent()

        val state = viewModel.uiState.first()
        assertEquals(SecureGuardStateEnum.LOCKED, state.status.state)
        assertEquals(0, state.status.failedAttempts)
        assertEquals(5, state.status.remainingAttempts)

        // Now unlock with the new PIN
        viewModel.unlock("654321")
        testDispatcher.scheduler.runCurrent()
        assertTrue(viewModel.uiState.value.status.isUnlocked)
    }

    @Test
    fun journey10_authenticatedChangePin() = runTest {
        viewModel.provision("123456", null, null)
        testDispatcher.scheduler.runCurrent()

        viewModel.changePin("123456", "987654")
        testDispatcher.scheduler.runCurrent()

        val state = viewModel.uiState.first()
        assertEquals(SecureGuardStateEnum.LOCKED, state.status.state)

        viewModel.unlock("987654")
        testDispatcher.scheduler.runCurrent()
        assertTrue(viewModel.uiState.value.status.isUnlocked)
    }

    @Test
    fun journey11_policyConfigurationUpdate() = runTest {
        viewModel.provision("123456", null, null)
        testDispatcher.scheduler.runCurrent()

        val updatedPolicy = SecureGuardPolicy(
            wipeOn5Failures = true,
            sessionDurationMs = 600_000L,
            inactivityTimeoutMs = 180_000L,
            protectKeysAndAegn = true,
            protectOath = true,
            testModeNonDestructiveWipe = true
        )
        viewModel.updatePolicy(updatedPolicy)
        testDispatcher.scheduler.runCurrent()

        val state = viewModel.uiState.first()
        assertTrue(state.status.policy.wipeOn5Failures)
        assertTrue(state.status.policy.protectOath)
        assertTrue(state.status.policy.testModeNonDestructiveWipe)
        assertEquals(600_000L, state.status.policy.sessionDurationMs)
    }

    @Test
    fun journey12_fifthFailureAutoWipeWhenEnabled() = runTest {
        viewModel.provision("123456", null, SecureGuardPolicy(wipeOn5Failures = true, testModeNonDestructiveWipe = true))
        viewModel.lock()
        testDispatcher.scheduler.runCurrent()

        for (i in 1..5) {
            repo.currentStatus = repo.currentStatus.copy(rateLimitRemainingMs = 0)
            viewModel.unlock("wrong_pin")
            testDispatcher.scheduler.runCurrent()
        }

        val state = viewModel.uiState.first()
        assertEquals(SecureGuardStateEnum.UNPROVISIONED, state.status.state)
        assertFalse(state.status.isProvisioned)
        assertTrue(state.status.lastWipeSimulated)
    }

    @Test
    fun journey13_selectiveWipeWithConfirmationToken() = runTest {
        viewModel.provision("123456", null, null)
        testDispatcher.scheduler.runCurrent()

        viewModel.wipeSelective(0, "CONFIRM_WIPE_AEGIS_GUARD")
        testDispatcher.scheduler.runCurrent()

        val state = viewModel.uiState.first()
        assertEquals(SecureGuardStateEnum.UNPROVISIONED, state.status.state)
        assertFalse(state.status.isProvisioned)
        assertFalse(state.status.isUnlocked)
    }
}
