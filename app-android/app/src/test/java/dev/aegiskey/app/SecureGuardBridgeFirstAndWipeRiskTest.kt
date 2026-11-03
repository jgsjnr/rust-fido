package dev.aegiskey.app

import dev.aegiskey.app.ble.BleContract
import dev.aegiskey.app.data.cbor.SecureGuardCbor
import dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl
import dev.aegiskey.app.data.transport.BleKeyTransport
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.usb.UsbCtaphid
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors

/**
 * Regressão dos três fixes de app + mock determinístico debug:
 * 1. getStatus consulta a bridge ANTES de forçar LOCKED;
 * 2. unlock só auto-provisiona com UNPROVISIONED confirmado (0x3A real);
 * 3. BLE rito-3 envia 0x3B+CBOR, nunca 0x2D+PIN cru (wipe-risk).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SecureGuardBridgeFirstAndWipeRiskTest {

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
        val vendorHexBody: String? = null,
        val provisionBody: String = """{"ok":false,"error":"sem hardware"}"""
    ) {
        private val serverSocket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        private val executor = Executors.newCachedThreadPool { r -> Thread(r).also { it.isDaemon = true } }
        val port: Int get() = serverSocket.localPort
        val capturedVendorOpcodes = mutableListOf<Int>()

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
                var bodyText = ""
                if (contentLength > 0) {
                    val remaining = CharArray(contentLength)
                    var read = 0
                    while (read < contentLength) {
                        val n = reader.read(remaining, read, contentLength - read)
                        if (n <= 0) break
                        read += n
                    }
                    bodyText = String(remaining, 0, read)
                }
                val body = when {
                    path.startsWith("/bridge/info") -> """{"connected":true}"""
                    path.startsWith("/api/secure-guard/status") -> statusBody
                    path.startsWith("/api/secure-guard/unlock") -> unlockBody
                    path.startsWith("/api/secure-guard/provision") -> provisionBody
                    path.startsWith("/bridge/vendor") -> {
                        val op = Regex("\"opcode\"\\s*:\\s*(\\d+)").find(bodyText)?.groupValues?.getOrNull(1)?.toIntOrNull()
                        if (op != null) synchronized(capturedVendorOpcodes) { capturedVendorOpcodes.add(op) }
                        if (vendorHexBody != null) """{"response_hex":"$vendorHexBody"}""" else """{}"""
                    }
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

    private fun unlockedStatusBody(sessionMs: Long = 12345L): String =
        """{"ok":true,"state":4,"state_name":"Unlocked","provisioned":true,"unlocked":true,"failed_attempts":0,"remaining_attempts":5,"max_attempts":5,"rate_limit_remaining_ms":0,"session_remaining_ms":$sessionMs,"wipe_on_5_failures":false,"session_duration_ms":300000,"inactivity_timeout_ms":300000,"protect_keys_and_aegn":true,"protect_oath":false,"test_mode_non_destructive_wipe":false,"last_wipe_simulated":false,"audit_count":0}"""

    private fun lockedStatusBody(): String =
        """{"ok":true,"state":2,"state_name":"Locked","provisioned":true,"unlocked":false,"failed_attempts":1,"remaining_attempts":4,"max_attempts":5,"rate_limit_remaining_ms":0,"session_remaining_ms":0,"wipe_on_5_failures":false,"session_duration_ms":300000,"inactivity_timeout_ms":300000,"protect_keys_and_aegn":true,"protect_oath":false,"test_mode_non_destructive_wipe":false,"last_wipe_simulated":false,"audit_count":0}"""

    @Test
    fun getStatus_consultsBridgeBeforeForcedLock_whenUsbDetached() = runTest(testDispatcher) {
        val server = StubBridgeServer(
            unlockBody = """{"ok":false,"error":"PIN incorreto"}""",
            statusBody = unlockedStatusBody()
        )
        server.start()
        try {
            val bridge = HostUsbUartBridgeClient(listOf("http://127.0.0.1:${server.port}"))
            val dummyUsb = UsbCtaphid(null)
            val repo = SecureGuardRepositoryImpl(bridge, dummyUsb, null)

            SecureGuardRepositoryImpl.lastVerifiedSessionPin = "9999"
            val res = repo.getStatus()

            assertTrue(res.isSuccess)
            val status = res.getOrThrow()
            assertEquals("Bridge com sessão viva deve vencer o LOCKED forçado", SecureGuardStateEnum.UNLOCKED, status.state)
            assertTrue(status.isUnlocked)
            assertEquals(12345L, status.sessionRemainingMs)
            assertEquals("PIN da sessão viva não pode ser zerado", "9999", SecureGuardRepositoryImpl.lastVerifiedSessionPin)
        } finally {
            server.stop()
        }
    }

    @Test
    fun getStatus_stillForcesLocked_whenBridgeUnreachable() = runTest(testDispatcher) {
        val bridge = HostUsbUartBridgeClient(listOf("http://127.0.0.1:1"))
        val dummyUsb = UsbCtaphid(null)
        val repo = SecureGuardRepositoryImpl(bridge, dummyUsb, null)

        SecureGuardRepositoryImpl.lastVerifiedSessionPin = "9999"
        val res = repo.getStatus()

        assertTrue(res.isSuccess)
        val status = res.getOrThrow()
        assertEquals(SecureGuardStateEnum.LOCKED, status.state)
        assertFalse(status.isUnlocked)
        assertEquals(0L, status.sessionRemainingMs)
        assertNull(SecureGuardRepositoryImpl.lastVerifiedSessionPin)
    }

    @Test
    fun unlock_doesNotProvisionWithoutConfirmedUnprovisioned() = runTest(testDispatcher) {
        // Bridge alcançável: status LOCKED provisionado + unlock recusado.
        // Sem USB/BLE físico. O unlock deve ventilar os transportes
        // (SecurityException agregado) e NUNCA cair em auto-provision local.
        val server = StubBridgeServer(
            unlockBody = """{"ok":false,"error":"PIN incorreto"}""",
            statusBody = lockedStatusBody()
        )
        server.start()
        try {
            val bridge = HostUsbUartBridgeClient(listOf("http://127.0.0.1:${server.port}"))
            val dummyUsb = UsbCtaphid(null)
            val repo = SecureGuardRepositoryImpl(bridge, dummyUsb, null)

            val result = repo.unlock("1234")

            assertTrue("Unlock deve falhar", result.isFailure)
            val ex = result.exceptionOrNull()
            assertNotNull(ex)
            assertTrue("Sem UNPROVISIONED confirmado, a falha deve ser agregada (SecurityException), mas foi: $ex", ex is SecurityException)
            val msg = ex!!.message ?: ""
            assertFalse("Não deve tentar provisionar sem confirmação, mas foi: $msg", msg.contains("Falha ao provisionar"))
            assertTrue("Deve preservar o erro da bridge, mas foi: $msg", msg.contains("PIN incorreto"))
            assertTrue("Deve registrar a tentativa de bridge, mas foi: $msg", msg.contains("Bridge"))
        } finally {
            server.stop()
        }
    }

    @Test
    fun blePinVerify_sends0x3BplusCbor_neverBare0x2DPin() {
        val (op, payload) = BleKeyTransport.pinVerifyRequest("4927")

        assertEquals("Rito-3 BLE deve usar o opcode de auth", BleContract.OP_SG_AUTH, op)
        assertEquals(0x3B, op)
        assertFalse("Nunca 0x2D (recovery-unlock = wipe)", op == 0x2D)

        val expected = SecureGuardCbor.encodeUnlockRequest("4927".toByteArray(Charsets.UTF_8))
        assertArrayEquals("Payload deve ser o CBOR de unlock (semântica USB)", expected, payload)

        val decoded = SecureGuardCbor.decode(payload) as? Map<*, *>
        assertNotNull(decoded)
        assertEquals("unlock", decoded!!["action"])
    }

    @Test
    fun simulatedTransport_answers0x3A_thru_0x3E_withCbor() = runTest(testDispatcher) {
        val sim = SimulatedRenodeTransport()
        sim.resetSecureGuardMock()

        val statusRaw = sim.sendVendor(0x3A, SecureGuardCbor.encodeStatusRequest())
        assertNotNull(statusRaw)
        val statusFrame = SecureGuardCbor.parseTransportFrame(0x3A, statusRaw!!)
        assertEquals(0x3A, statusFrame.opcode)
        assertEquals(0x00, statusFrame.status)
        assertEquals(SecureGuardStateEnum.UNPROVISIONED, SecureGuardCbor.parseStatus(statusFrame.cborPayload)!!.state)

        val provRaw = sim.sendVendor(
            0x3B,
            SecureGuardCbor.encodeProvisionRequest("1234".toByteArray(Charsets.UTF_8), null, null)
        )
        assertNotNull(provRaw)
        val provFrame = SecureGuardCbor.parseTransportFrame(0x3B, provRaw!!)
        assertEquals(0x00, provFrame.status)
        val provRes = SecureGuardCbor.parseProvisionResult(provFrame.cborPayload)
        assertNotNull(provRes)
        assertTrue(provRes!!.recoveryCode.isNotEmpty())

        val unlockedRaw = sim.sendVendor(0x3A, SecureGuardCbor.encodeStatusRequest())
        val unlocked = SecureGuardCbor.parseStatus(SecureGuardCbor.parseTransportFrame(0x3A, unlockedRaw!!).cborPayload)
        assertEquals(SecureGuardStateEnum.UNLOCKED, unlocked!!.state)
        assertTrue(unlocked.isProvisioned)

        val lockRaw = sim.sendVendor(0x3C, SecureGuardCbor.encodeLockRequest())
        assertNotNull(lockRaw)
        val locked = SecureGuardCbor.parseStatus(
            SecureGuardCbor.parseTransportFrame(0x3A, sim.sendVendor(0x3A, SecureGuardCbor.encodeStatusRequest())!!).cborPayload
        )
        assertEquals(SecureGuardStateEnum.LOCKED, locked!!.state)

        val wipeRaw = sim.sendVendor(0x3E, SecureGuardCbor.encodeWipeRequest(0, "CONFIRM"))
        assertNotNull(wipeRaw)
        val wiped = SecureGuardCbor.parseStatus(
            SecureGuardCbor.parseTransportFrame(0x3A, sim.sendVendor(0x3A, SecureGuardCbor.encodeStatusRequest())!!).cborPayload
        )
        assertEquals(SecureGuardStateEnum.UNPROVISIONED, wiped!!.state)
        assertFalse(wiped.isProvisioned)
    }

    @Test
    fun repository_mockRouting_usesSimulatedTransportInDebug() = runTest(testDispatcher) {
        org.junit.Assume.assumeTrue("Mock routing só existe em build debug", dev.aegiskey.app.BuildConfig.DEBUG)

        val sim = SimulatedRenodeTransport()
        sim.resetSecureGuardMock()
        val unreachableBridge = HostUsbUartBridgeClient(listOf("http://127.0.0.1:1"))
        val dummyUsb = UsbCtaphid(null)
        val repo = SecureGuardRepositoryImpl(
            hostBridgeClient = unreachableBridge,
            usbCtaphid = dummyUsb,
            bleKeyTransport = null,
            connectedKeysRepository = null,
            simulatedTransport = sim
        )
        SecureGuardRepositoryImpl.mockRoutingEnabled = true
        try {
            val status = repo.getStatus().getOrThrow()
            assertEquals("Mock deve responder UNPROVISIONED, não LOCKED forçado", SecureGuardStateEnum.UNPROVISIONED, status.state)

            val rc = repo.provision("1234", null, null).getOrThrow()
            assertTrue(rc.isNotEmpty())

            val unlocked = repo.unlock("1234").getOrThrow()
            assertEquals(SecureGuardStateEnum.UNLOCKED, unlocked.state)
            assertTrue(unlocked.isUnlocked)
        } finally {
            SecureGuardRepositoryImpl.mockRoutingEnabled = false
        }
    }
}
