package dev.aegiskey.app

import dev.aegiskey.app.data.cbor.SecureGuardCbor
import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import dev.aegiskey.app.domain.usecase.*
import dev.aegiskey.app.ui.viewmodel.SecureGuardViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class SecureGuardRepositoryAndCborTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun cborRoundTrip_encodeAndDecodeStatus() {
        val testMap = linkedMapOf<String, Any?>(
            "state" to 2,
            "state_name" to "Unlocked",
            "provisioned" to true,
            "unlocked" to true,
            "failed_attempts" to 0,
            "remaining_attempts" to 5,
            "max_attempts" to 5,
            "rate_limit_remaining_ms" to 0L,
            "session_remaining_ms" to 300_000L,
            "wipe_on_5_failures" to true
        )

        val encoded = SecureGuardCbor.encodeMap(testMap)
        assertTrue(encoded.isNotEmpty())

        val status = SecureGuardCbor.parseStatus(encoded)
        assertNotNull(status)
        assertEquals(SecureGuardStateEnum.UNLOCKED, status!!.state)
        assertTrue(status.isProvisioned)
        assertTrue(status.isUnlocked)
        assertEquals(0, status.failedAttempts)
        assertEquals(5, status.remainingAttempts)
        assertTrue(status.policy.wipeOn5Failures)
    }

    @Test
    fun cborTransportFrame_handlesAllFramingVariants() {
        val cborBody = SecureGuardCbor.encodeMap(
            mapOf("success" to true, "state" to 2)
        )

        // Variante 1: [opcode, status, ...body]
        val frame1 = SecureGuardCbor.parseTransportFrame(0x3B, byteArrayOf(0x3B.toByte(), 0x00) + cborBody)
        assertEquals(0x3B, frame1.opcode)
        assertEquals(0x00, frame1.status)
        assertArrayEquals(cborBody, frame1.cborPayload)

        // Variante 2: [status, ...body]
        val frame2 = SecureGuardCbor.parseTransportFrame(0x3B, byteArrayOf(0x00) + cborBody)
        assertEquals(0x00, frame2.status)
        assertArrayEquals(cborBody, frame2.cborPayload)

        // Variante 3: body direto
        val frame3 = SecureGuardCbor.parseTransportFrame(0x3B, cborBody)
        assertEquals(0x00, frame3.status)
        assertArrayEquals(cborBody, frame3.cborPayload)
    }

    @Test
    fun cborUnlockResult_parsesErrorCorrectlyWithoutException() {
        val errorCbor = SecureGuardCbor.encodeMap(
            mapOf(
                "success" to false,
                "state" to 1,
                "state_name" to "Locked",
                "failed_attempts" to 2,
                "remaining_attempts" to 3,
                "rate_limit_remaining_ms" to 0L,
                "error" to "PinAuthInvalid"
            )
        )

        val unlockRes = SecureGuardCbor.parseUnlockResult(0x32, errorCbor)
        assertFalse(unlockRes.success)
        assertEquals(SecureGuardStateEnum.LOCKED, unlockRes.state)
        assertEquals(2, unlockRes.failedAttempts)
        assertEquals(3, unlockRes.remainingAttempts)
        assertEquals("PinAuthInvalid", unlockRes.errorMessage)
    }

    @Test
    fun viewModel_neverExposesJnaClassInErrorMessage() = runTest(testDispatcher) {
        val failingRepo = object : dev.aegiskey.app.domain.repository.SecureGuardRepository {
            override val statusFlow = kotlinx.coroutines.flow.MutableStateFlow(SecureGuardStatus())
            override suspend fun getStatus() = Result.success(SecureGuardStatus())
            override suspend fun provision(pin: String, recoveryCode: String?, policy: SecureGuardPolicy?) =
                Result.failure<String>(NoClassDefFoundError("Could not initialize class com.sun.jna.Native"))
            override suspend fun unlock(pin: String) =
                Result.failure<SecureGuardStatus>(IllegalStateException("com.sun.jna.Native error loading symbols"))
            override suspend fun lock() = Result.success(Unit)
            override suspend fun changePin(currentPin: String, newPin: String) = Result.success(Unit)
            override suspend fun recover(recoveryCode: String, newPin: String) = Result.success(null)
            override suspend fun updatePolicy(policy: SecureGuardPolicy) = Result.success(policy)
            override suspend fun wipeSelective(scope: Int, confirmationToken: String) = Result.success(false)
        }

        val vm = SecureGuardViewModel(
            getSecureGuardStatusUseCase = GetSecureGuardStatusUseCase(failingRepo),
            provisionSecureGuardUseCase = ProvisionSecureGuardUseCase(failingRepo),
            unlockSecureGuardUseCase = UnlockSecureGuardUseCase(failingRepo),
            lockSecureGuardUseCase = LockSecureGuardUseCase(failingRepo),
            changeSecureGuardPinUseCase = ChangeSecureGuardPinUseCase(failingRepo),
            recoverSecureGuardUseCase = RecoverSecureGuardUseCase(failingRepo),
            updateSecureGuardPolicyUseCase = UpdateSecureGuardPolicyUseCase(failingRepo),
            triggerSelectiveWipeTestUseCase = TriggerSelectiveWipeTestUseCase(failingRepo)
        )

        vm.unlock("1234")
        testScheduler.runCurrent()

        val err = vm.uiState.value.errorMessage
        assertNotNull(err)
        assertFalse("Não deve expor jna", err!!.contains("jna", ignoreCase = true))
        assertFalse("Não deve expor Native", err.contains("Native", ignoreCase = true))
        assertTrue("Deve ser mensagem amigável", err.contains("Falha na comunicação", ignoreCase = true) || err.contains("hardware", ignoreCase = true))
    }

    @Test
    fun viewModel_unlockClosesPromptAndSetsUnlockedTrue() = runTest(testDispatcher) {
        val unlockedStatus = SecureGuardStatus(
            state = SecureGuardStateEnum.UNLOCKED,
            isProvisioned = true,
            isUnlocked = true,
            failedAttempts = 0,
            remainingAttempts = 5,
            sessionRemainingMs = 300_000L
        )

        val successRepo = object : dev.aegiskey.app.domain.repository.SecureGuardRepository {
            override val statusFlow = kotlinx.coroutines.flow.MutableStateFlow(unlockedStatus)
            override suspend fun getStatus() = Result.success(unlockedStatus)
            override suspend fun provision(pin: String, recoveryCode: String?, policy: SecureGuardPolicy?) = Result.success("RECOVERY-123")
            override suspend fun unlock(pin: String) = Result.success(unlockedStatus)
            override suspend fun lock() = Result.success(Unit)
            override suspend fun changePin(currentPin: String, newPin: String) = Result.success(Unit)
            override suspend fun recover(recoveryCode: String, newPin: String) = Result.success(null)
            override suspend fun updatePolicy(policy: SecureGuardPolicy) = Result.success(policy)
            override suspend fun wipeSelective(scope: Int, confirmationToken: String) = Result.success(false)
        }

        val vm = SecureGuardViewModel(
            getSecureGuardStatusUseCase = GetSecureGuardStatusUseCase(successRepo),
            provisionSecureGuardUseCase = ProvisionSecureGuardUseCase(successRepo),
            unlockSecureGuardUseCase = UnlockSecureGuardUseCase(successRepo),
            lockSecureGuardUseCase = LockSecureGuardUseCase(successRepo),
            changeSecureGuardPinUseCase = ChangeSecureGuardPinUseCase(successRepo),
            recoverSecureGuardUseCase = RecoverSecureGuardUseCase(successRepo),
            updateSecureGuardPolicyUseCase = UpdateSecureGuardPolicyUseCase(successRepo),
            triggerSelectiveWipeTestUseCase = TriggerSelectiveWipeTestUseCase(successRepo)
        )

        vm.openUnlockPrompt()
        assertTrue("Prompt deve abrir", vm.uiState.value.isUnlockPromptOpen)

        vm.unlock("1234")
        testScheduler.runCurrent()

        assertFalse("Prompt deve fechar imediatamente após unlock com sucesso", vm.uiState.value.isUnlockPromptOpen)
        assertTrue("Status deve estar desbloqueado", vm.uiState.value.status.isUnlocked)
        assertEquals(SecureGuardStateEnum.UNLOCKED, vm.uiState.value.status.state)
    }

    @Test
    fun viewModel_wipeSelectiveRestoresToUnprovisionedAndClosesPrompt() = runTest(testDispatcher) {
        val initialStatus = SecureGuardStatus(
            state = SecureGuardStateEnum.UNLOCKED,
            isProvisioned = true,
            isUnlocked = true
        )

        val wipeRepo = object : dev.aegiskey.app.domain.repository.SecureGuardRepository {
            override val statusFlow = kotlinx.coroutines.flow.MutableStateFlow(initialStatus)
            override suspend fun getStatus() = Result.success(statusFlow.value)
            override suspend fun provision(pin: String, recoveryCode: String?, policy: SecureGuardPolicy?) = Result.success("RC")
            override suspend fun unlock(pin: String) = Result.success(initialStatus)
            override suspend fun lock() = Result.success(Unit)
            override suspend fun changePin(currentPin: String, newPin: String) = Result.success(Unit)
            override suspend fun recover(recoveryCode: String, newPin: String) = Result.success(null)
            override suspend fun updatePolicy(policy: SecureGuardPolicy) = Result.success(policy)
            override suspend fun wipeSelective(scope: Int, confirmationToken: String): Result<Boolean> {
                val wiped = SecureGuardStatus(
                    state = SecureGuardStateEnum.UNPROVISIONED,
                    isProvisioned = false,
                    isUnlocked = false
                )
                statusFlow.value = wiped
                return Result.success(false)
            }
        }

        val vm = SecureGuardViewModel(
            getSecureGuardStatusUseCase = GetSecureGuardStatusUseCase(wipeRepo),
            provisionSecureGuardUseCase = ProvisionSecureGuardUseCase(wipeRepo),
            unlockSecureGuardUseCase = UnlockSecureGuardUseCase(wipeRepo),
            lockSecureGuardUseCase = LockSecureGuardUseCase(wipeRepo),
            changeSecureGuardPinUseCase = ChangeSecureGuardPinUseCase(wipeRepo),
            recoverSecureGuardUseCase = RecoverSecureGuardUseCase(wipeRepo),
            updateSecureGuardPolicyUseCase = UpdateSecureGuardPolicyUseCase(wipeRepo),
            triggerSelectiveWipeTestUseCase = TriggerSelectiveWipeTestUseCase(wipeRepo)
        )

        vm.openUnlockPrompt()
        assertTrue(vm.uiState.value.isUnlockPromptOpen)

        vm.wipeSelective(0, "CONFIRM_TOKEN")
        advanceUntilIdle()

        assertFalse("Prompt deve fechar após wipe", vm.uiState.value.isUnlockPromptOpen)
        assertFalse("Deve desprovisionar", vm.uiState.value.status.isProvisioned)
        assertFalse("Deve bloquear", vm.uiState.value.status.isUnlocked)
        assertEquals(SecureGuardStateEnum.UNPROVISIONED, vm.uiState.value.status.state)
    }
}
