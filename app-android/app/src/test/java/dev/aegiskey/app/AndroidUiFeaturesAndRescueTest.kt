package dev.aegiskey.app

import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.ui.RescueOps
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Testes unitários para as novas funcionalidades da UI Android:
 * 1. TOTP via QR Code (AegisBridge.parseOtpInput com detecção de TOTP, HOTP e segredos puros).
 * 2. Rescue Diagnostics (RescueOps 0x2E PING & DIAGNOSTICS).
 * 3. Persistência de Quorum DKEK (EncryptedKeysStore).
 * 4. Audit Logs (DeviceLog).
 */
class AndroidUiFeaturesAndRescueTest {

    private lateinit var keysStore: EncryptedKeysStore

    @Before
    fun setUp() {
        keysStore = EncryptedKeysStore(context = null)
        keysStore.clearAll()
        DeviceLog.clear()
    }

    @Test
    fun testParseTotpQrCodeUri() {
        val uri = "otpauth://totp/Google:alice%40gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=Google&digits=6&period=30"
        val parsed = AegisBridge.parseOtpInput(uri)

        assertNotNull("Deveria fazer parse de URI TOTP válida", parsed)
        assertEquals("Google", parsed!!.issuer)
        assertEquals("alice@gmail.com", parsed.accountName)
        assertEquals("JBSWY3DPEHPK3PXP", parsed.secretBase32)
        assertEquals(6, parsed.digits)
        assertEquals(30, parsed.period)
        assertEquals(30, parsed.periodSeconds)
        assertFalse("Não deve ser marcado como HOTP", parsed.isHotp)
    }

    @Test
    fun testParseHotpQrCodeUri() {
        val uri = "otpauth://hotp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8&counter=42"
        val parsed = AegisBridge.parseOtpInput(uri)

        assertNotNull("Deveria fazer parse de URI HOTP válida", parsed)
        assertEquals("GitHub", parsed!!.issuer)
        assertEquals("octocat", parsed.accountName)
        assertEquals("JBSWY3DPEHPK3PXP", parsed.secretBase32)
        assertEquals(8, parsed.digits)
        assertTrue("Deve ser marcado como HOTP", parsed.isHotp)
    }

    @Test
    fun testParseRawBase32Secret() {
        val rawSecret = "  jbsw y3dp ehpk 3pxp  "
        val parsed = AegisBridge.parseOtpInput(rawSecret)

        assertNotNull("Deveria aceitar segredo Base32 puro", parsed)
        assertEquals("JBSWY3DPEHPK3PXP", parsed!!.secretBase32)
        assertEquals("", parsed.issuer)
        assertEquals("", parsed.accountName)
        assertEquals(6, parsed.digits)
        assertEquals(30, parsed.period)
        assertFalse(parsed.isHotp)
    }

    @Test
    fun testDkekQuorumPersistenceInStore() {
        val keyId = "aegis-key-test-01"

        // Inicialmente vazio
        assertNull("Quorum inicial deve ser nulo", keysStore.loadDkekQuorum(keyId))

        // Salva Quorum 3-de-5
        val config = EncryptedKeysStore.DkekQuorumConfig(
            totalGuardians = 5,
            threshold = 3,
            lastUpdatedEpochMs = 1700000000000L
        )
        keysStore.saveDkekQuorum(keyId, config)

        val loaded = keysStore.loadDkekQuorum(keyId)
        assertNotNull("Quorum deve ter sido persistido", loaded)
        assertEquals(5, loaded!!.totalGuardians)
        assertEquals(3, loaded.threshold)
        assertEquals(1700000000000L, loaded.lastUpdatedEpochMs)

        // Atualiza para Quorum 2-de-3
        val updated = config.copy(totalGuardians = 3, threshold = 2)
        keysStore.saveDkekQuorum(keyId, updated)

        val reloaded = keysStore.loadDkekQuorum(keyId)
        assertEquals(3, reloaded!!.totalGuardians)
        assertEquals(2, reloaded.threshold)
    }

    @Test
    fun testRescueOpsPingAndDiagnosticsParsing() {
        // 1. Testa frame de envio PING
        val pingReq = RescueOps.opMsgPayload(RescueOps.CMD_PING)
        assertEquals(RescueOps.TRANSPORT_OP.toByte(), pingReq[0])
        assertEquals(0x52.toByte(), pingReq[1]) // 'R'
        assertEquals(0x45.toByte(), pingReq[2]) // 'E'
        assertEquals(0x53.toByte(), pingReq[3]) // 'S'
        assertEquals(0x43.toByte(), pingReq[4]) // 'C'
        assertEquals(RescueOps.CMD_PING.toByte(), pingReq[6])

        // 2. Simula resposta PING: [0x83, status=0x00, VER=0x01, panic=5, wipe=2, recovery=0]
        val rawPingResp = byteArrayOf(
            RescueOps.OP_MSG.toByte(),
            RescueOps.STATUS_OK.toByte(),
            RescueOps.VERSION.toByte(),
            0x00, 0x00, 0x00, 0x05, // panic = 5
            0x00, 0x00, 0x00, 0x02, // wipe = 2
            0x00                     // recovery = false
        )
        val parsedPing = RescueOps.parseResponse(rawPingResp)?.let { RescueOps.parsePing(it.body) }
        assertNotNull(parsedPing)
        assertEquals(RescueOps.VERSION, parsedPing!!.version)
        assertEquals(5L, parsedPing.panicCount)
        assertEquals(2L, parsedPing.wipeCount)
        assertFalse(parsedPing.recoveryMode)

        // 3. Simula resposta DIAGNOSTICS com subsistemas OK:
        val flags = (RescueOps.DIAG_CRYPTO_OK or
            RescueOps.DIAG_FLASH_OK or
            RescueOps.DIAG_RNG_OK or
            RescueOps.DIAG_BUTTON_OK).toByte()

        val rawDiagResp = byteArrayOf(
            RescueOps.OP_MSG.toByte(),
            RescueOps.STATUS_OK.toByte(),
            flags,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        )
        val parsedDiag = RescueOps.parseResponse(rawDiagResp)?.let { RescueOps.parseDiagnostics(it.body) }
        assertNotNull(parsedDiag)
        assertTrue("Crypto HW deve estar OK", parsedDiag!!.cryptoOk)
        assertTrue("Flash / NVS deve estar OK", parsedDiag.flashOk)
        assertTrue("TRNG deve estar OK", parsedDiag.rngOk)
        assertTrue("Botão físico deve estar OK", parsedDiag.buttonOk)
    }

    @Test
    fun testDeviceLogRecordingAndSnapshot() {
        assertEquals(0, DeviceLog.entries.value.size)

        DeviceLog.append(DeviceLog.Category.SYSTEM, "Self-test 0x2E iniciado")
        DeviceLog.append(DeviceLog.Category.LOCK, "DKEK Quorum configurado 2-de-3")
        DeviceLog.append(DeviceLog.Category.BLE, "RX FFF2 status=OK")

        val entries = DeviceLog.entries.value
        assertEquals(3, entries.size)
        assertEquals(DeviceLog.Category.SYSTEM, entries[0].category)
        assertEquals("Self-test 0x2E iniciado", entries[0].line)
        assertEquals(DeviceLog.Category.LOCK, entries[1].category)

        val snapshot = DeviceLog.snapshotText()
        assertTrue(snapshot.contains("[SYSTEM] Self-test 0x2E iniciado"))
        assertTrue(snapshot.contains("[LOCK] DKEK Quorum configurado 2-de-3"))

        DeviceLog.clear()
        assertEquals(0, DeviceLog.entries.value.size)
    }
}
