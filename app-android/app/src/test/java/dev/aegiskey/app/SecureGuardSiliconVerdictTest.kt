package dev.aegiskey.app

import dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
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
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors

/**
 * Unlock com autoridade do silício via `POST /api/secure-guard/unlock`
 * (sem placa, sem push: stub HTTP local sobre ServerSocket).
 *
 * Contrato sob teste (só app-android):
 * - O veredito que decide autenticação/exibição é o do silício
 *   (`failed_attempts`/`remaining_attempts` reais do POST unlock);
 *   o espelho (`GET /api/secure-guard/status`) é exibição fail-closed e
 *   nunca autentica: espelho `Unprovisioned` não nega um `0x00/success`
 *   do silício nem dispara provision.
 * - A negação do silício expõe o erro real + tentativas restantes reais
 *   (prosa de `guard_unlock_incorrect_remaining`); sem veredito do silício,
 *   fail-closed sem inventar contadores.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SecureGuardSiliconVerdictTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        SecureGuardRepositoryImpl.clearSessionPin()
        SecureGuardRepositoryImpl.mockRoutingEnabled = false
    }

    @After
    fun tearDown() {
        SecureGuardRepositoryImpl.clearSessionPin()
        SecureGuardRepositoryImpl.mockRoutingEnabled = false
        Dispatchers.resetMain()
    }

    private class StubBridgeServer(
        val unlockBody: String,
        val statusBody: String,
        val provisionBody: String = """{"ok":false,"error":"sem hardware"}""",
    ) {
        private val serverSocket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        private val executor = Executors.newCachedThreadPool { r -> Thread(r).also { it.isDaemon = true } }
        val port: Int get() = serverSocket.localPort
        val seenPaths = mutableListOf<String>()

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
                synchronized(seenPaths) { seenPaths.add(path) }
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
                    path.startsWith("/api/secure-guard/provision") -> provisionBody
                    path.startsWith("/bridge/vendor") -> """{}"""
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

    private fun lockedStatusBody(
        failed: Int = 0,
        remaining: Int = 5,
    ): String =
        """{"ok":true,"state":2,"state_name":"Locked","provisioned":true,"unlocked":false,"failed_attempts":$failed,"remaining_attempts":$remaining,"max_attempts":5,"rate_limit_remaining_ms":0,"session_remaining_ms":0,"wipe_on_5_failures":false,"session_duration_ms":300000,"inactivity_timeout_ms":300000,"protect_keys_and_aegn":true,"protect_oath":false,"test_mode_non_destructive_wipe":false,"last_wipe_simulated":false,"audit_count":0}"""

    private fun unprovisionedMirrorBody(): String =
        """{"ok":true,"state":0,"state_name":"Unprovisioned","provisioned":false,"unlocked":false,"failed_attempts":0,"remaining_attempts":5,"max_attempts":5,"rate_limit_remaining_ms":0,"session_remaining_ms":0,"wipe_on_5_failures":false,"session_duration_ms":300000,"inactivity_timeout_ms":300000,"protect_keys_and_aegn":true,"protect_oath":false,"test_mode_non_destructive_wipe":false,"last_wipe_simulated":false,"audit_count":0}"""

    private fun siliconSuccessBody(): String =
        """{"ok":true,"success":true,"silicon_reachable":true,"silicon_status":0,"status":0,"state":4,"state_name":"Unlocked","failed_attempts":0,"remaining_attempts":5,"max_attempts":5,"rate_limit_remaining_ms":0,"session_remaining_ms":300000,"error":null}"""

    private fun siliconDenialBody(): String =
        """{"ok":false,"success":false,"silicon_reachable":true,"silicon_status":50,"status":50,"state":6,"state_name":"RateLimited","failed_attempts":1,"remaining_attempts":4,"max_attempts":5,"rate_limit_remaining_ms":1000,"error":"Invalid PIN (1/5). Backoff 1s"}"""

    @Test
    fun bridgeDenial_surfacesSiliconErrorAndRealRemaining() = runTest(testDispatcher) {
        // Nega do silício: erro real + contadores autoritativos na mensagem
        // e no espelho de exibição (nunca o `remaining` obsoleto do espelho).
        val server = StubBridgeServer(
            unlockBody = siliconDenialBody(),
            statusBody = lockedStatusBody(),
        )
        server.start()
        try {
            val bridge = HostUsbUartBridgeClient(listOf("http://127.0.0.1:${server.port}"))
            val repo = SecureGuardRepositoryImpl(hostBridgeClient = bridge)

            val result = repo.unlock("0000")

            assertTrue("Unlock negado pelo silício deve falhar", result.isFailure)
            val msg = result.exceptionOrNull()?.message ?: ""
            assertTrue("Deve expor o erro real do silício, mas foi: $msg", msg.contains("Invalid PIN (1/5). Backoff 1s"))
            assertTrue("Deve expor as tentativas restantes reais, mas foi: $msg", msg.contains("Restam 4"))
            assertTrue("Deve registrar a tentativa de bridge, mas foi: $msg", msg.contains("Bridge"))

            val published = repo.statusFlow.value
            assertFalse(published.isUnlocked)
            assertEquals("Espelho deve publicar o failed real do silício", 1, published.failedAttempts)
            assertEquals("Espelho deve publicar o remaining real do silício", 4, published.remainingAttempts)
        } finally {
            server.stop()
        }
    }

    @Test
    fun mirrorUnprovisioned_neverDeniesSiliconSuccessNorTriggersProvision() = runTest(testDispatcher) {
        // Regressão do bug provado: espelho `Unprovisioned` + silício
        // `0x00/success` => UNLOCKED (silício vence) e NENHUM provision é
        // disparado a partir do espelho.
        val server = StubBridgeServer(
            unlockBody = siliconSuccessBody(),
            statusBody = unprovisionedMirrorBody(),
        )
        server.start()
        try {
            val bridge = HostUsbUartBridgeClient(listOf("http://127.0.0.1:${server.port}"))
            val repo = SecureGuardRepositoryImpl(hostBridgeClient = bridge)

            val result = repo.unlock("1111")

            assertTrue("Silício 0x00/success deve desbloquear, mas foi: ${result.exceptionOrNull()}", result.isSuccess)
            val st = result.getOrThrow()
            assertTrue(st.isUnlocked)
            assertEquals(SecureGuardStateEnum.UNLOCKED, st.state)
            assertEquals(0, st.failedAttempts)
            assertEquals("Contador real do silício, não forjado", 5, st.remainingAttempts)
            assertEquals("PIN da sessão só ancora no sucesso do silício", "1111", SecureGuardRepositoryImpl.lastVerifiedSessionPin)
            assertTrue(
                "Espelho Unprovisioned nunca dispara provision",
                server.seenPaths.none { it.startsWith("/api/secure-guard/provision") },
            )
        } finally {
            server.stop()
        }
    }

    @Test
    fun siliconUnreachable_failClosedWithoutInventedCounters() = runTest(testDispatcher) {
        // Sem bridge/plataforma: sem veredito do silício => fail-closed,
        // nunca UNLOCKED, nunca "Restam N" inventado.
        val bridge = HostUsbUartBridgeClient(listOf("http://127.0.0.1:1"))
        val repo = SecureGuardRepositoryImpl(hostBridgeClient = bridge)

        val result = repo.unlock("1111")

        assertTrue("Sem silício deve falhar", result.isFailure)
        val msg = result.exceptionOrNull()?.message ?: ""
        assertFalse("Sem veredito, nunca afirma desbloqueio", repo.statusFlow.value.isUnlocked)
        assertFalse("Sem silício, sem contador inventado, mas foi: $msg", msg.contains("Restam"))
    }

    private fun viewModelWithFailingUnlock(
        failure: Throwable,
        statusAfterFailure: SecureGuardStatus,
    ): SecureGuardViewModel {
        val repo = object : dev.aegiskey.app.domain.repository.SecureGuardRepository {
            override val statusFlow = kotlinx.coroutines.flow.MutableStateFlow(statusAfterFailure)
            override suspend fun getStatus() = Result.success(statusAfterFailure)
            override suspend fun provision(pin: String, recoveryCode: String?, policy: SecureGuardPolicy?) =
                Result.success("RC")
            override suspend fun unlock(pin: String) = Result.failure<SecureGuardStatus>(failure)
            override suspend fun lock() = Result.success(Unit)
            override suspend fun changePin(currentPin: String, newPin: String) = Result.success(Unit)
            override suspend fun recover(recoveryCode: String, newPin: String) = Result.success(null)
            override suspend fun updatePolicy(policy: SecureGuardPolicy) = Result.success(policy)
            override suspend fun wipeSelective(scope: Int, confirmationToken: String) = Result.success(false)
        }
        return SecureGuardViewModel(
            getSecureGuardStatusUseCase = GetSecureGuardStatusUseCase(repo),
            provisionSecureGuardUseCase = ProvisionSecureGuardUseCase(repo),
            unlockSecureGuardUseCase = UnlockSecureGuardUseCase(repo),
            lockSecureGuardUseCase = LockSecureGuardUseCase(repo),
            changeSecureGuardPinUseCase = ChangeSecureGuardPinUseCase(repo),
            recoverSecureGuardUseCase = RecoverSecureGuardUseCase(repo),
            updateSecureGuardPolicyUseCase = UpdateSecureGuardPolicyUseCase(repo),
            triggerSelectiveWipeTestUseCase = TriggerSelectiveWipeTestUseCase(repo),
        )
    }

    @Test
    fun viewModel_unlockDenial_showsShortSiliconVerdictWithRealRemaining() = runTest(testDispatcher) {
        // Agregado do repositório (veredito + detalhe de transporte): a UI
        // exibe o veredito curto do silício com o remaining real, sem o
        // detalhe "(Bridge: … | Hardware: …)" e sem texto genérico.
        val aggregated = SecurityException(
            "Invalid PIN (1/5). Backoff 1s (Restam 4 tentativas.) " +
                "(Bridge: Invalid PIN (1/5). Backoff 1s (Restam 4 tentativas.) | Hardware: sem resposta dos transportes)"
        )
        val mirror = SecureGuardStatus(
            state = SecureGuardStateEnum.RATE_LIMITED,
            isProvisioned = true,
            isUnlocked = false,
            failedAttempts = 1,
            remainingAttempts = 4,
            rateLimitRemainingMs = 1000L,
        )
        val vm = viewModelWithFailingUnlock(aggregated, mirror)

        vm.unlock("0000")
        advanceUntilIdle()

        val err = vm.uiState.value.errorMessage
        assertTrue("Deve exibir o veredito do silício, mas foi: $err", err != null && err.contains("Invalid PIN (1/5). Backoff 1s"))
        assertTrue("Deve exibir as tentativas restantes reais, mas foi: $err", err!!.contains("Restam 4"))
        assertFalse("Detalhe de transporte não vai para a UI, mas foi: $err", err.contains("Bridge:"))
        assertEquals("Badge com o remaining real do silício", 4, vm.uiState.value.status.remainingAttempts)
    }

    @Test
    fun viewModel_blockedVerdict_preservedVerbatimWithZeroRemaining() = runTest(testDispatcher) {
        val aggregated = SecurityException(
            "Limite de tentativas excedido. Cofre bloqueado. (Restam 0 tentativas.) (Bridge: Limite de tentativas excedido. Cofre bloqueado. (Restam 0 tentativas.))"
        )
        val mirror = SecureGuardStatus(
            state = SecureGuardStateEnum.LOCKED,
            isProvisioned = true,
            isUnlocked = false,
            failedAttempts = 5,
            remainingAttempts = 0,
        )
        val vm = viewModelWithFailingUnlock(aggregated, mirror)

        vm.unlock("0000")
        advanceUntilIdle()

        val err = vm.uiState.value.errorMessage
        assertTrue("Deve preservar o veredito de bloqueio, mas foi: $err", err != null && err.contains("Limite de tentativas"))
        assertTrue("Deve exibir o zero real, mas foi: $err", err!!.contains("Restam 0"))
    }
}
