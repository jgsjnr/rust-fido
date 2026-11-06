package dev.aegiskey.app

import dev.aegiskey.app.ble.DevicePresence.isNeedUpDenial
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl
import dev.aegiskey.app.data.repository.TotpRepositoryImpl
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.TotpAccountItem
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
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Fail-closed OATH: sem sessão viva = sem código.
 *
 * Locks the removal of every locally-invented code path:
 * - bridge/host fallbacks ("344017"/"000000") are covered by
 *   `tools/host_hardware_android_bridge.py --offline-self-test`;
 * - here the Android repository must never compute, cache-forward, or
 *   guess a code without live silicon (no volatile secrets, no fallback
 *   constants, no local TOTP/HOTP math, no tick recompute).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class OathFailClosedTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = false
    }

    @After
    fun tearDown() {
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = false
        Dispatchers.resetMain()
    }

    private suspend fun harness(): Triple<EncryptedKeysStore, ConnectedKeysRepositoryImpl, TotpRepositoryImpl> {
        val store = EncryptedKeysStore(null)
        val connected = ConnectedKeysRepositoryImpl(store, null, null)
        connected.addOrUpdateKey(
            ConnectedKeyDevice(
                id = "failclosed-totp-1",
                displayName = "AegisKey FailClosed",
                hardwareAddressOrId = "usb:failclosed",
                bindingIdHex = "FAILCLOSED-BINDING",
                transportType = ConnectionTransportType.USB,
                isCurrentlyConnected = true
            )
        )
        val repo = TotpRepositoryImpl(
            keysStore = store,
            bleClient = null,
            simulatedRenodeTransport = SimulatedRenodeTransport(),
            connectedKeysRepository = connected,
            scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        )
        return Triple(store, connected, repo)
    }

    private fun oathListOk(vararg names: String): ByteArray {
        var tlv = ByteArray(0)
        for (n in names) {
            val rawName = byteArrayOf(0x21.toByte()) + n.toByteArray(Charsets.UTF_8)
            tlv += VendorOps.writeTlv(VendorOps.TAG_OATH_NAME, rawName)
        }
        return byteArrayOf(VendorOps.OP_OATH_LIST.toByte(), VendorOps.STATUS_OK.toByte()) + tlv
    }

    @Test
    fun refresh_offlineList_failsClosed_showsPlaceholderNotCachedCode() = runTest(testDispatcher) {
        val (store, _, repo) = harness()
        store.saveTotpAccounts(
            "failclosed-totp-1",
            listOf(
                TotpAccountItem(
                    id = "a1",
                    issuer = "GitHub",
                    accountName = "octocat",
                    currentCode = "654321",
                    formattedCode = "654 321",
                    remainingSeconds = 30
                )
            )
        )
        // Silicon unreachable: no transport answer at all.
        repo.vendorOverride = { _, _ -> null }

        val res = repo.refreshAccountsAndCodes("failclosed-totp-1")

        assertTrue("offline list must fail, never masquerade cache as fresh", res.isFailure)
        val item = repo.accounts.value.single()
        assertEquals("no live session = no code", TotpRepositoryImpl.NO_LIVE_CODE, item.currentCode)
        assertNotEquals("stale cached code must not be shown as current", "654321", item.currentCode)
        assertFalse("placeholder is not all digits", item.currentCode.all { it.isDigit() })
        assertNotEquals("never the old bridge fallback", "000000", item.currentCode)
        assertFalse("placeholder must NOT claim device origin", item.isOnDeviceBacked)
        assertTrue("placeholder must flag touch-to-refresh", item.requiresTouchToRefresh)
    }

    @Test
    fun addAccount_codeUnavailable_noLocallyComputedCode() = runTest(testDispatcher) {
        val (_, _, repo) = harness()
        repo.vendorOverride = { opcode, _ ->
            when (opcode) {
                VendorOps.OP_OATH_PUT -> byteArrayOf(VendorOps.OP_OATH_PUT.toByte(), VendorOps.STATUS_OK.toByte())
                else -> null
            }
        }

        val res = repo.addAccount(
            keyId = "failclosed-totp-1",
            issuer = "GitHub",
            accountName = "octocat",
            secretOrUri = "JBSWY3DPEHPK3PXP",
            digits = 6
        )

        assertTrue("enroll on live silicon must still succeed", res.isSuccess)
        val item = res.getOrThrow()
        assertEquals("no live code read = no code, never locally computed", TotpRepositoryImpl.NO_LIVE_CODE, item.currentCode)
        assertFalse("first code is not device-backed", item.isOnDeviceBacked)
        assertTrue("first code flags touch-to-refresh", item.requiresTouchToRefresh)
    }

    @Test
    fun incrementHotp_offline_failsClosed_counterNotAdvanced() = runTest(testDispatcher) {
        val (_, _, repo) = harness()
        repo.vendorOverride = { opcode, _ ->
            when (opcode) {
                VendorOps.OP_OATH_PUT -> byteArrayOf(VendorOps.OP_OATH_PUT.toByte(), VendorOps.STATUS_OK.toByte())
                else -> null
            }
        }
        val added = repo.addAccount(
            keyId = "failclosed-totp-1",
            issuer = "InternalVPN",
            accountName = "admin",
            secretOrUri = "JBSWY3DPEHPK3PXP",
            digits = 8,
            isHotp = true
        ).getOrThrow()
        assertEquals(0L, added.counter)

        val res = repo.incrementHotpCounter("failclosed-totp-1", added.id)

        assertTrue("HOTP increment without live silicon must fail", res.isFailure)
        assertFalse("HOTP denial without presence flag is not a NEED_UP prompt", res.exceptionOrNull()!!.isNeedUpDenial())
        val item = repo.accounts.value.single { it.id == added.id }
        assertEquals("counter must not advance locally", 0L, item.counter)
        assertEquals("no live session = no code", TotpRepositoryImpl.NO_LIVE_CODE, item.currentCode)
    }

    @Test
    fun tickTimer_neverInventsOrRefreshesCodesOffline() = runTest(testDispatcher) {
        val (store, _, repo) = harness()
        store.saveTotpAccounts(
            "failclosed-totp-1",
            listOf(
                TotpAccountItem(
                    id = "a1",
                    issuer = "GitHub",
                    accountName = "octocat",
                    currentCode = TotpRepositoryImpl.NO_LIVE_CODE,
                    formattedCode = "--- ---",
                    remainingSeconds = 7
                )
            )
        )
        repo.vendorOverride = { _, _ -> null }
        repo.refreshAccountsAndCodes("failclosed-totp-1")
        val before = repo.accounts.value.single().currentCode

        repo.tickTimer(System.currentTimeMillis() / 1000L)

        val after = repo.accounts.value.single()
        assertEquals("tick must not invent a code", before, after.currentCode)
        assertEquals(TotpRepositoryImpl.NO_LIVE_CODE, after.currentCode)
        assertTrue("countdown still ticks", after.remainingSeconds in 1..30)
    }

    @Test
    fun oathParse_rejectsBodiesWithoutStrictDeviceCode() {
        assertTrue(AegisBridge.oathParse("""{"ok":true,"account":"a"}""").isFailure)
        assertTrue(AegisBridge.oathParse("""{"account":"a","code":"28a082","remaining_seconds":12}""").isFailure)
        assertTrue(AegisBridge.oathParse("""{"account":"a","code":"123456"}""").isFailure)
        assertTrue(AegisBridge.oathParse("not-json").isFailure)

        val ok = AegisBridge.oathParse(
            """{"account":"GitHub:octocat","code":"123456","remaining_seconds":12}"""
        ).getOrThrow()
        assertEquals("GitHub:octocat", ok.account)
        assertEquals("123456", ok.code)
        assertEquals(12, ok.remainingSeconds)
    }
}
