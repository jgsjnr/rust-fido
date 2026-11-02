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

    @Test
    fun cborRoundTrip_deviceBleMacAndName() {
        val testMap = linkedMapOf<String, Any?>(
            "state" to 2,
            "state_name" to "Unlocked",
            "provisioned" to true,
            "unlocked" to true,
            "device_ble_mac" to byteArrayOf(0x3C.toByte(), 0x84.toByte(), 0x27.toByte(), 0xC7.toByte(), 0x17.toByte(), 0x78.toByte()),
            "device_ble_name" to "AegisKey"
        )
        val encoded = SecureGuardCbor.encodeMap(testMap)
        val status = SecureGuardCbor.parseStatus(encoded)
        assertNotNull(status)
        assertEquals("3C:84:27:C7:17:78", status!!.deviceBleMac)
        assertEquals("AegisKey", status.deviceBleName)
    }

    @Test
    fun viewModel_cancelsCountdownTickerImmediately_onStatusFlowLocked() = runTest(testDispatcher) {
        val flow = kotlinx.coroutines.flow.MutableStateFlow(
            SecureGuardStatus(
                state = SecureGuardStateEnum.UNLOCKED,
                isProvisioned = true,
                isUnlocked = true,
                sessionRemainingMs = 300_000L
            )
        )

        val repo = object : dev.aegiskey.app.domain.repository.SecureGuardRepository {
            override val statusFlow = flow
            override suspend fun getStatus() = Result.success(flow.value)
            override suspend fun provision(pin: String, recoveryCode: String?, policy: SecureGuardPolicy?) = Result.success("RC")
            override suspend fun unlock(pin: String) = Result.success(flow.value)
            override suspend fun lock(): Result<Unit> {
                flow.value = flow.value.copy(state = SecureGuardStateEnum.LOCKED, isUnlocked = false, sessionRemainingMs = 0L)
                return Result.success(Unit)
            }
            override suspend fun changePin(currentPin: String, newPin: String) = Result.success(Unit)
            override suspend fun recover(recoveryCode: String, newPin: String) = Result.success(null)
            override suspend fun updatePolicy(policy: SecureGuardPolicy) = Result.success(policy)
            override suspend fun wipeSelective(scope: Int, confirmationToken: String) = Result.success(false)
        }

        val vm = SecureGuardViewModel(
            getSecureGuardStatusUseCase = GetSecureGuardStatusUseCase(repo),
            provisionSecureGuardUseCase = ProvisionSecureGuardUseCase(repo),
            unlockSecureGuardUseCase = UnlockSecureGuardUseCase(repo),
            lockSecureGuardUseCase = LockSecureGuardUseCase(repo),
            changeSecureGuardPinUseCase = ChangeSecureGuardPinUseCase(repo),
            recoverSecureGuardUseCase = RecoverSecureGuardUseCase(repo),
            updateSecureGuardPolicyUseCase = UpdateSecureGuardPolicyUseCase(repo),
            triggerSelectiveWipeTestUseCase = TriggerSelectiveWipeTestUseCase(repo),
            repository = repo
        )

        testScheduler.runCurrent()
        assertTrue("Status inicial deve estar unlocked", vm.uiState.value.status.isUnlocked)

        // Simula desconexão USB ou lock disparado pelo hardware
        flow.value = SecureGuardStatus(
            state = SecureGuardStateEnum.LOCKED,
            isProvisioned = true,
            isUnlocked = false,
            sessionRemainingMs = 0L
        )

        testScheduler.runCurrent()

        assertFalse("Status no ViewModel deve estar bloqueado imediatamente", vm.uiState.value.status.isUnlocked)
        assertEquals(SecureGuardStateEnum.LOCKED, vm.uiState.value.status.state)
        assertEquals(0L, vm.uiState.value.status.sessionRemainingMs)
    }

    @Test
    fun connectedKeysRepository_autoPairBleDevice_registersBleTransport() = runTest(testDispatcher) {
        val store = dev.aegiskey.app.data.local.EncryptedKeysStore(null)
        val connectedRepo = dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl(store, null, null)

        connectedRepo.autoPairBleDevice("3C:84:27:C7:17:78", "AegisKey")
        advanceUntilIdle()

        val active = connectedRepo.activeKey.value
        assertNotNull(active)
        assertEquals("3C:84:27:C7:17:78", active!!.hardwareAddressOrId)
        assertEquals(dev.aegiskey.app.domain.model.ConnectionTransportType.BLE, active.transportType)
        assertTrue(active.isCurrentlyConnected)
    }
}
