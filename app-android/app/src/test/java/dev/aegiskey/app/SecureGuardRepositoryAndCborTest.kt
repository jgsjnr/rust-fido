package dev.aegiskey.app

import dev.aegiskey.app.data.cbor.SecureGuardCbor
import dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors
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
    fun viewModel_unlockSurfacesDeviceReportedStatusVerbatim() = runTest(testDispatcher) {
        // O dispositivo responde sucesso com valores próprios (sessão curta,
        // tentativas restantes 4, recovery code gerado): o ViewModel deve
        // espelhá-los em vez de forjar UNLOCKED/300s/5 tentativas.
        val deviceStatus = SecureGuardStatus(
            state = SecureGuardStateEnum.UNLOCKED,
            isProvisioned = true,
            isUnlocked = true,
            failedAttempts = 0,
            remainingAttempts = 4,
            sessionRemainingMs = 12_345L,
            lastGeneratedRecoveryCode = "RC-DEVICE-1"
        )

        val repo = object : dev.aegiskey.app.domain.repository.SecureGuardRepository {
            override val statusFlow = kotlinx.coroutines.flow.MutableStateFlow(deviceStatus)
            override suspend fun getStatus() = Result.success(deviceStatus)
            override suspend fun provision(pin: String, recoveryCode: String?, policy: SecureGuardPolicy?) = Result.success("RC")
            override suspend fun unlock(pin: String) = Result.success(deviceStatus)
            override suspend fun lock() = Result.success(Unit)
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
            triggerSelectiveWipeTestUseCase = TriggerSelectiveWipeTestUseCase(repo)
        )

        vm.unlock("1234")
        testScheduler.runCurrent()

        val st = vm.uiState.value.status
        assertTrue("Deve refletir desbloqueio real", st.isUnlocked)
        assertEquals(SecureGuardStateEnum.UNLOCKED, st.state)
        assertEquals("Deve preservar sessão reportada pelo dispositivo", 12_345L, st.sessionRemainingMs)
        assertEquals("Deve preservar tentativas reportadas pelo dispositivo", 4, st.remainingAttempts)
        assertEquals("RC-DEVICE-1", vm.uiState.value.generatedRecoveryCode)
    }

    @Test
    fun viewModel_unlockSuccessWithLockedDevice_doesNotForgeUnlocked() = runTest(testDispatcher) {
        // Transporte OK mas dispositivo segue bloqueado: sucesso honesto
        // nunca pode forjar UNLOCKED.
        val deviceStatus = SecureGuardStatus(
            state = SecureGuardStateEnum.LOCKED,
            isProvisioned = true,
            isUnlocked = false,
            failedAttempts = 1,
            remainingAttempts = 4,
            sessionRemainingMs = 0L
        )

        val repo = object : dev.aegiskey.app.domain.repository.SecureGuardRepository {
            override val statusFlow = kotlinx.coroutines.flow.MutableStateFlow(deviceStatus)
            override suspend fun getStatus() = Result.success(deviceStatus)
            override suspend fun provision(pin: String, recoveryCode: String?, policy: SecureGuardPolicy?) = Result.success("RC")
            override suspend fun unlock(pin: String) = Result.success(deviceStatus)
            override suspend fun lock() = Result.success(Unit)
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
            triggerSelectiveWipeTestUseCase = TriggerSelectiveWipeTestUseCase(repo)
        )

        vm.openUnlockPrompt()
        vm.unlock("1234")
        testScheduler.runCurrent()

        assertFalse("Prompt deve fechar", vm.uiState.value.isUnlockPromptOpen)
        assertEquals("Deve espelhar LOCKED do dispositivo", SecureGuardStateEnum.LOCKED, vm.uiState.value.status.state)
        assertFalse("Nunca forjar desbloqueio", vm.uiState.value.status.isUnlocked)
        assertNull("Sem mensagem de sucesso quando segue bloqueado", vm.uiState.value.successMessage)
    }

    /**
     * Stub HTTP mínimo sobre ServerSocket puro (sem módulos jdk.* que o
     * classpath de unit tests não expõe). Responde /bridge/info, status,
     * unlock e /bridge/vendor com JSON fixo.
     */
    private class StubBridgeServer(val unlockBody: String, val statusBody: String) {
        private val serverSocket = ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"))
        private val executor = Executors.newCachedThreadPool { r -> Thread(r).also { it.isDaemon = true } }
        val port: Int get() = serverSocket.localPort

        fun start() {
            executor.execute {
                while (!serverSocket.isClosed) {
                    try {
                        val socket = serverSocket.accept()
                        executor.execute { handle(socket) }
                    } catch (_: Throwable) {
                        break
                    }
                }
            }
        }

        fun stop() {
            runCatching { serverSocket.close() }
            executor.shutdownNow()
        }

        private fun handle(socket: java.net.Socket) {
            socket.use { s ->
                val input = s.getInputStream()
                val output = s.getOutputStream()
                val reader = input.bufferedReader(StandardCharsets.UTF_8)
                val requestLine = reader.readLine() ?: return
                val path = requestLine.split(" ").getOrNull(1) ?: "/"
                var contentLength = 0
                while (true) {
                    val header = reader.readLine() ?: break
                    if (header.isBlank()) break
                    if (header.startsWith("Content-Length:", ignoreCase = true)) {
                        contentLength = header.substringAfter(":").trim().toIntOrNull() ?: 0
                    }
                }
                if (contentLength > 0) {
                    val remaining = CharArray(contentLength)
                    var read = 0
                    while (read < contentLength) {
                        val n = reader.read(remaining, read, contentLength - read)
                        if (n <= 0) break
                        read += n
                    }
                }
                val body = when {
                    path.startsWith("/bridge/info") -> """{"connected":true}"""
                    path.startsWith("/api/secure-guard/status") -> statusBody
                    path.startsWith("/api/secure-guard/unlock") -> unlockBody
                    else -> """{}"""
                }
                val bytes = body.toByteArray(StandardCharsets.UTF_8)
                val head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
                    "Content-Length: ${bytes.size}\r\nConnection: close\r\n\r\n"
                output.write(head.toByteArray(StandardCharsets.UTF_8))
                output.write(bytes)
                output.flush()
            }
        }
    }

    private fun stubBridgeServer(
        unlockBody: String,
        statusBody: String = """{"ok":true,"state":1,"state_name":"Locked","provisioned":true,"unlocked":false,"failed_attempts":0,"remaining_attempts":5,"max_attempts":5,"rate_limit_remaining_ms":0,"session_remaining_ms":0,"wipe_on_5_failures":false,"session_duration_ms":300000,"inactivity_timeout_ms":300000,"protect_keys_and_aegn":true,"protect_oath":false,"test_mode_non_destructive_wipe":false,"last_wipe_simulated":false,"audit_count":0}"""
    ): StubBridgeServer {
        return StubBridgeServer(unlockBody, statusBody).also { it.start() }
    }

    @Test
    fun repository_unlockAggregatesFailuresAfterTryingAllTransports() = runTest(testDispatcher) {
        // Bridge alcançável mas recusa o PIN; sem USB/BLE. O unlock deve tentar
        // bridge + fallback e lançar UM SecurityException agregado (nunca
        // curto-circuitar e nunca silenciar o erro da bridge).
        val server = stubBridgeServer("""{"ok":false,"error":"PIN incorreto"}""")
        try {
            val bridge = HostUsbUartBridgeClient(listOf("http://127.0.0.1:${server.port}"))
            val repo = SecureGuardRepositoryImpl(hostBridgeClient = bridge, usbCtaphid = null, bleKeyTransport = null)

            val result = repo.unlock("1234")

            assertTrue("Unlock deve falhar", result.isFailure)
            val ex = result.exceptionOrNull()
            assertTrue("Falha agregada deve ser SecurityException", ex is SecurityException)
            val msg = ex!!.message ?: ""
            assertTrue("Deve preservar o erro da bridge, mas era: $msg", msg.contains("PIN incorreto"))
            assertTrue("Deve registrar a tentativa de bridge, mas era: $msg", msg.contains("Bridge"))
            assertTrue("Deve registrar a tentativa de fallback, mas era: $msg", msg.contains("Hardware"))
        } finally {
            server.stop()
        }
    }

    @Test
    fun repository_unlockViaBridgeSuccessPreserved() = runTest(testDispatcher) {
        // Caminho de sucesso existente via bridge deve continuar desbloqueando.
        val server = stubBridgeServer("""{"ok":true,"success":true}""")
        try {
            val bridge = HostUsbUartBridgeClient(listOf("http://127.0.0.1:${server.port}"))
            val repo = SecureGuardRepositoryImpl(hostBridgeClient = bridge, usbCtaphid = null, bleKeyTransport = null)

            val result = repo.unlock("1234")

            assertTrue("Unlock via bridge deve ter sucesso, mas foi: ${result.exceptionOrNull()}", result.isSuccess)
            val st = result.getOrThrow()
            assertTrue(st.isUnlocked)
            assertEquals(SecureGuardStateEnum.UNLOCKED, st.state)
        } finally {
            server.stop()
        }
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
