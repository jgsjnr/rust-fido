package dev.aegiskey.app

import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl
import dev.aegiskey.app.data.repository.KeyVaultRepositoryImpl
import dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.usb.UsbCtaphid
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors

/**
 * Regressão dos 4 fixes do SECURITY_AUDIT (app-android, sem placa):
 * - C-01: Shamir offline falha fechado (success=false, shares vazias, sem seed).
 * - C-02: key-gen exige PIN explícito; nunca fabrica STATUS_OK sintético.
 * - H-01: unlock só auto-provisiona com UNPROVISIONED confirmado por 0x3A.
 * - H-02: PIN em RAM vinculado ao session_remaining_ms do 0x3A.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SecurityAuditFixesTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = false
        SecureGuardRepositoryImpl.clearSessionPin()
        SecureGuardRepositoryImpl.mockRoutingEnabled = false
    }

    @After
    fun tearDown() {
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = false
        SecureGuardRepositoryImpl.clearSessionPin()
        SecureGuardRepositoryImpl.mockRoutingEnabled = false
        Dispatchers.resetMain()
    }

    // --- C-01: Shamir fail-closed offline ---

    private fun offlineBridge() = HostUsbUartBridgeClient(listOf("http://127.0.0.1:1"))

    @Test
    fun shamirSplit_offline_failsClosedWithEmptyShares() = runTest(testDispatcher) {
        val res = offlineBridge().shamirSplit(totalShares = 3, threshold = 2)

        assertFalse("Sem hardware, Shamir nunca relata success", res.success)
        assertTrue("Sem hardware, nenhuma share determinística", res.shares.isEmpty())
    }

    @Test
    fun shamirRecover_offline_failsClosedWithNullSeed() = runTest(testDispatcher) {
        val res = offlineBridge().shamirRecover(listOf("share-1", "share-2"))

        assertFalse("Sem hardware, recover nunca relata success", res.success)
        assertNull("Sem hardware, nenhuma seed sintética", res.recoveredMasterSeedHex)
    }

    // --- C-02: key-gen com PIN explícito, sem STATUS_OK sintético ---

    private suspend fun keyGenHarness(): KeyVaultRepositoryImpl {
        val store = EncryptedKeysStore(null)
        val connected = ConnectedKeysRepositoryImpl(store, null, null)
        connected.addOrUpdateKey(
            ConnectedKeyDevice(
                id = "audit-key-1",
                displayName = "AegisKey Audit",
                hardwareAddressOrId = "usb:audit",
                bindingIdHex = "AUDIT-BINDING",
                transportType = ConnectionTransportType.USB,
                isCurrentlyConnected = true
            )
        )
        return KeyVaultRepositoryImpl(
            keysStore = store,
            bleClient = null,
            simulatedRenodeTransport = SimulatedRenodeTransport(),
            connectedKeysRepository = connected,
            scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        )
    }

    @Test
    fun keyGen_pinRequired_withoutSessionPin_failsClosedNoDummy() = runTest(testDispatcher) {
        val repo = keyGenHarness()
        SecureGuardRepositoryImpl.clearSessionPin()
        repo.vendorOverride = { _, _ ->
            byteArrayOf(
                VendorOps.OP_KEY_GEN_ONDEVICE.toByte(),
                VendorOps.STATUS_SECURE_GUARD_PIN_REQUIRED.toByte()
            )
        }

        val res = repo.generateNewAccessKey("audit-key-1", "Audit Key", AccessKeyType.PASSKEY_FIDO)

        assertTrue("Sem PIN explícito, key-gen deve falhar", res.isFailure)
        assertTrue(
            "Erro deve exigir PIN explícito, mas foi: ${res.exceptionOrNull()?.message}",
            res.exceptionOrNull()?.message?.contains("PIN") == true
        )
        assertTrue("Nenhuma chave fabricada em memória", repo.vaultEntries.value.isEmpty())
    }

    @Test
    fun keyGen_pinRequired_withExplicitSessionPin_retriesAfterUnlock() = runTest(testDispatcher) {
        val repo = keyGenHarness()
        SecureGuardRepositoryImpl.lastVerifiedSessionPin = "1234"
        var genCalls = 0
        repo.vendorOverride = { opcode, _ ->
            when (opcode) {
                0x3B -> byteArrayOf(0x3B.toByte(), 0x00.toByte())
                VendorOps.OP_KEY_GEN_ONDEVICE -> {
                    genCalls++
                    if (genCalls == 1) {
                        byteArrayOf(
                            VendorOps.OP_KEY_GEN_ONDEVICE.toByte(),
                            VendorOps.STATUS_SECURE_GUARD_PIN_REQUIRED.toByte()
                        )
                    } else {
                        byteArrayOf(VendorOps.OP_KEY_GEN_ONDEVICE.toByte(), 0x00.toByte())
                    }
                }
                else -> null
            }
        }

        val res = repo.generateNewAccessKey("audit-key-1", "Audit Key", AccessKeyType.PASSKEY_FIDO)

        assertTrue("Com PIN explícito válido, unlock + retry deve vencer", res.isSuccess)
        assertEquals(2, genCalls)
    }

    // --- H-01: auto-provision só com UNPROVISIONED confirmado por 0x3A ---

    @Test
    fun unlock_unprovisionedConfirmedViaMock_provisionsAndUnlocks() = runTest(testDispatcher) {
        org.junit.Assume.assumeTrue(
            "Mock routing só existe em build debug",
            dev.aegiskey.app.BuildConfig.DEBUG
        )
        val sim = SimulatedRenodeTransport()
        sim.resetSecureGuardMock() // UNPROVISIONED
        val repo = SecureGuardRepositoryImpl(
            hostBridgeClient = offlineBridge(),
            usbCtaphid = UsbCtaphid(null),
            bleKeyTransport = null,
            connectedKeysRepository = null,
            simulatedTransport = sim
        )
        SecureGuardRepositoryImpl.mockRoutingEnabled = true
        try {
            val result = repo.unlock("1234")

            assertTrue("UNPROVISIONED confirmado deve auto-provisionar e desbloquear", result.isSuccess)
            val status = result.getOrThrow()
            assertEquals(SecureGuardStateEnum.UNLOCKED, status.state)
            assertTrue(status.isProvisioned)
        } finally {
            SecureGuardRepositoryImpl.mockRoutingEnabled = false
        }
    }

    // --- H-02: PIN em RAM vinculado ao session_remaining_ms do 0x3A ---

    @Test
    fun sessionPin_pastDeadline_isDiscardedFailClosed() {
        SecureGuardRepositoryImpl.lastVerifiedSessionPin = "1234"
        assertTrue(SecureGuardRepositoryImpl.isSessionPinValid())

        SecureGuardRepositoryImpl.sessionPinExpiresAtMs = System.currentTimeMillis() - 1L

        assertNull(
            "PIN com deadline estourada nunca é retornado",
            SecureGuardRepositoryImpl.currentSessionPin()
        )
        assertFalse(SecureGuardRepositoryImpl.isSessionPinValid())
        assertNull(SecureGuardRepositoryImpl.lastVerifiedSessionPin)
    }

    private class StubStatusServer(val statusBody: String) {
        private val serverSocket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
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

    private fun statusBody(unlocked: Boolean, sessionMs: Long): String {
        val state = if (unlocked) 4 else 2
        val name = if (unlocked) "Unlocked" else "Locked"
        return """{"ok":true,"state":$state,"state_name":"$name","provisioned":true,"unlocked":$unlocked,"failed_attempts":0,"remaining_attempts":5,"max_attempts":5,"rate_limit_remaining_ms":0,"session_remaining_ms":$sessionMs,"wipe_on_5_failures":false,"session_duration_ms":300000,"inactivity_timeout_ms":300000,"protect_keys_and_aegn":true,"protect_oath":false,"test_mode_non_destructive_wipe":false,"last_wipe_simulated":false,"audit_count":0}"""
    }

    @Test
    fun getStatus_zeroRemaining_clearsRamPin() = runTest(testDispatcher) {
        val server = StubStatusServer(statusBody(unlocked = true, sessionMs = 0L))
        server.start()
        try {
            val bridge = HostUsbUartBridgeClient(listOf("http://127.0.0.1:${server.port}"))
            val repo = SecureGuardRepositoryImpl(bridge, UsbCtaphid(null), null)

            SecureGuardRepositoryImpl.lastVerifiedSessionPin = "9999"
            val status = repo.getStatus().getOrThrow()

            assertTrue(status.isUnlocked)
            assertEquals(0L, status.sessionRemainingMs)
            assertNull(
                "Sessão zerada no 0x3A descarta o PIN em RAM",
                SecureGuardRepositoryImpl.lastVerifiedSessionPin
            )
        } finally {
            server.stop()
        }
    }

    @Test
    fun getStatus_positiveRemaining_renewsExpiredDeadline() = runTest(testDispatcher) {
        val server = StubStatusServer(statusBody(unlocked = true, sessionMs = 60_000L))
        server.start()
        try {
            val bridge = HostUsbUartBridgeClient(listOf("http://127.0.0.1:${server.port}"))
            val repo = SecureGuardRepositoryImpl(bridge, UsbCtaphid(null), null)

            SecureGuardRepositoryImpl.lastVerifiedSessionPin = "9999"
            SecureGuardRepositoryImpl.sessionPinExpiresAtMs = System.currentTimeMillis() - 1L

            val status = repo.getStatus().getOrThrow()

            assertEquals(60_000L, status.sessionRemainingMs)
            assertEquals(
                "0x3A autoritativo com saldo renova o PIN em RAM",
                "9999",
                SecureGuardRepositoryImpl.currentSessionPin()
            )
        } finally {
            server.stop()
        }
    }
}
