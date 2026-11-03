package dev.aegiskey.app

import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl
import dev.aegiskey.app.data.repository.KeyVaultRepositoryImpl
import dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.domain.repository.ConnectedKeysRepository
import dev.aegiskey.app.domain.repository.SecureGuardRepository
import dev.aegiskey.app.touchpolicy.TouchPolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Per-credential touch (UP) policy (CAPABILITY_DIET §8.4).
 *
 * - Fail-safe default: require-touch assumed when unknown.
 * - Toggle roundtrip through canned `0x40` responses (echo framing).
 * - NEED_PIN path: local state untouched, typed exception to surface the
 *   existing unlock flow; a locked session never reaches the wire.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TouchPolicyTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = false
        SecureGuardRepositoryImpl.clearSessionPin()
    }

    @After
    fun tearDown() {
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = false
        SecureGuardRepositoryImpl.clearSessionPin()
        Dispatchers.resetMain()
    }

    private fun seedEntry(
        store: EncryptedKeysStore,
        keyId: String,
        binding: String,
        slotId: Int = 3,
        requireTouch: Boolean = true
    ) {
        store.saveVaultEntries(
            keyId,
            listOf(
                VaultKeyEntry(
                    slotId = slotId,
                    label = "GitHub Passkey",
                    type = AccessKeyType.PASSKEY_FIDO,
                    publicSummary = "Secured on slot $slotId",
                    createdAtEpochMs = 123456789L,
                    requiresPhysicalTouch = requireTouch
                )
            ),
            binding
        )
    }

    private suspend fun harness(
        sgRepo: SecureGuardRepository? = null
    ): Triple<EncryptedKeysStore, ConnectedKeysRepository, KeyVaultRepositoryImpl> {
        val store = EncryptedKeysStore(null)
        val connected = ConnectedKeysRepositoryImpl(store, null, null)
        connected.addOrUpdateKey(
            ConnectedKeyDevice(
                id = "touch-key-1",
                displayName = "AegisKey Touch",
                hardwareAddressOrId = "usb:touch",
                bindingIdHex = "TOUCH-BINDING",
                transportType = ConnectionTransportType.USB,
                isCurrentlyConnected = true
            )
        )
        val repo = if (sgRepo == null) {
            KeyVaultRepositoryImpl(
                keysStore = store,
                bleClient = null,
                simulatedRenodeTransport = SimulatedRenodeTransport(),
                connectedKeysRepository = connected,
                scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
            )
        } else {
            KeyVaultRepositoryImpl(
                keysStore = store,
                usbKeyTransport = null,
                bleKeyTransport = null,
                simulatedRenodeTransport = SimulatedRenodeTransport(),
                connectedKeysRepository = connected,
                secureGuardRepository = sgRepo,
                scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
            )
        }
        return Triple(store, connected, repo)
    }

    private class LockedSecureGuardRepository : SecureGuardRepository {
        override val statusFlow: StateFlow<SecureGuardStatus> =
            MutableStateFlow(SecureGuardStatus(state = SecureGuardStateEnum.LOCKED, isUnlocked = false))

        override suspend fun getStatus() = Result.success(statusFlow.value)
        override suspend fun provision(pin: String, recoveryCode: String?, policy: SecureGuardPolicy?) =
            Result.success("RC")

        override suspend fun unlock(pin: String) = Result.success(statusFlow.value)
        override suspend fun lock() = Result.success(Unit)
        override suspend fun changePin(currentPin: String, newPin: String) = Result.success(Unit)
        override suspend fun recover(recoveryCode: String, newPin: String): Result<String?> =
            Result.success(null)

        override suspend fun updatePolicy(policy: SecureGuardPolicy) = Result.success(policy)
        override suspend fun wipeSelective(scope: Int, confirmationToken: String) = Result.success(false)
        override fun onHardwareDetached() = Unit
    }

    // --- Codec: wire shape ------------------------------------------------

    @Test
    fun buildSetRequest_carriesSlotIdentity_oneByteCredId() {
        assertArrayEquals(
            byteArrayOf(0x00.toByte(), 0x01.toByte(), 0x03.toByte()),
            TouchPolicy.buildSetRequest(false, 3)
        )
        assertArrayEquals(
            byteArrayOf(0x01.toByte(), 0x01.toByte(), 0x03.toByte()),
            TouchPolicy.buildSetRequest(true, 3)
        )
    }

    @Test
    fun parseSetResponse_mapsStatusFirstContract() {
        assertTrue(TouchPolicy.parseSetResponse(byteArrayOf(0x40.toByte(), 0x00.toByte())) is TouchPolicy.SetResult.Ok)
        assertTrue(TouchPolicy.parseSetResponse(byteArrayOf(0x40.toByte(), 0x02.toByte())) is TouchPolicy.SetResult.NeedPin)
        assertTrue(TouchPolicy.parseSetResponse(byteArrayOf(0x40.toByte(), 0x03.toByte())) is TouchPolicy.SetResult.NoSlot)
        // Status-first bridge framing is translated, not invented.
        assertTrue(TouchPolicy.parseSetResponse(byteArrayOf(0x00.toByte())) is TouchPolicy.SetResult.Ok)
        val fail = TouchPolicy.parseSetResponse(byteArrayOf(0x40.toByte(), 0x04.toByte()))
        assertTrue(fail is TouchPolicy.SetResult.Failure)
        assertEquals(0x04, (fail as TouchPolicy.SetResult.Failure).status)
        // Absent/empty answers are failures, never success.
        assertTrue(TouchPolicy.parseSetResponse(null) is TouchPolicy.SetResult.Failure)
        assertTrue(TouchPolicy.parseSetResponse(byteArrayOf()) is TouchPolicy.SetResult.Failure)
    }

    // --- Default: require-touch -------------------------------------------

    @Test
    fun defaultRequire_unknownSlot_assumesTouchRequired() = runTest(testDispatcher) {
        val (_, _, repo) = harness()
        assertTrue("fail-safe default is require-touch", repo.getTouchRequired("touch-key-1", 7))
        assertTrue("new entries default to require-touch", VaultKeyEntry(0, "K", AccessKeyType.PASSKEY_FIDO, "ok", 1L).requiresPhysicalTouch)
    }

    // --- Roundtrip: canned 0x40 -------------------------------------------

    @Test
    fun touchToggle_roundtrip_viaCanned0x40_flipsLocalState() = runTest(testDispatcher) {
        val (store, _, repo) = harness()
        seedEntry(store, "touch-key-1", "TOUCH-BINDING", slotId = 3, requireTouch = true)

        val seen = mutableListOf<Pair<Int, ByteArray>>()
        repo.vendorOverride = { opcode, payload ->
            seen.add(opcode to payload)
            byteArrayOf(0x40.toByte(), 0x00.toByte())
        }

        val off = repo.setTouchRequired("touch-key-1", 3, false)
        assertTrue(off.isSuccess)
        assertEquals(1, seen.size)
        assertEquals(TouchPolicy.OP_UP_POLICY_SET, seen[0].first)
        assertArrayEquals(byteArrayOf(0x00.toByte(), 0x01.toByte(), 0x03.toByte()), seen[0].second)
        assertFalse(repo.getTouchRequired("touch-key-1", 3))
        assertFalse(store.loadVaultEntries("touch-key-1", "TOUCH-BINDING").single().requiresPhysicalTouch)

        val on = repo.setTouchRequired("touch-key-1", 3, true)
        assertTrue(on.isSuccess)
        assertArrayEquals(byteArrayOf(0x01.toByte(), 0x01.toByte(), 0x03.toByte()), seen[1].second)
        assertTrue(repo.getTouchRequired("touch-key-1", 3))
        assertTrue(store.loadVaultEntries("touch-key-1", "TOUCH-BINDING").single().requiresPhysicalTouch)
    }

    // --- NEED_PIN path ------------------------------------------------------

    @Test
    fun touchToggle_needPin_surfacesTypedError_stateUnchanged() = runTest(testDispatcher) {
        val (store, _, repo) = harness()
        seedEntry(store, "touch-key-1", "TOUCH-BINDING", slotId = 3, requireTouch = true)

        repo.vendorOverride = { _, _ -> byteArrayOf(0x40.toByte(), VendorOps.STATUS_NEED_PIN.toByte()) }

        val res = repo.setTouchRequired("touch-key-1", 3, false)
        assertTrue("NEED_PIN must fail, never apply locally", res.isFailure)
        assertTrue(res.exceptionOrNull() is TouchPolicy.TouchNeedPinException)
        assertTrue("local flag untouched on NEED_PIN", repo.getTouchRequired("touch-key-1", 3))
        assertTrue(store.loadVaultEntries("touch-key-1", "TOUCH-BINDING").single().requiresPhysicalTouch)
    }

    @Test
    fun touchToggle_lockedSession_neverReachesWire() = runTest(testDispatcher) {
        val (store, _, repo) = harness(LockedSecureGuardRepository())
        seedEntry(store, "touch-key-1", "TOUCH-BINDING", slotId = 3, requireTouch = true)

        var calls = 0
        repo.vendorOverride = { opcode, _ ->
            calls++
            byteArrayOf(opcode.toByte(), 0x00.toByte())
        }

        val res = repo.setTouchRequired("touch-key-1", 3, false)
        assertTrue(res.isFailure)
        assertTrue(res.exceptionOrNull() is TouchPolicy.TouchNeedPinException)
        assertEquals("locked session must not send", 0, calls)
        assertTrue(repo.getTouchRequired("touch-key-1", 3))
    }

    @Test
    fun touchToggle_noSlot_failsClosed() = runTest(testDispatcher) {
        val (store, _, repo) = harness()
        seedEntry(store, "touch-key-1", "TOUCH-BINDING", slotId = 3, requireTouch = true)

        repo.vendorOverride = { _, _ -> byteArrayOf(0x40.toByte(), VendorOps.STATUS_NO_SLOT.toByte()) }

        val res = repo.setTouchRequired("touch-key-1", 3, false)
        assertTrue(res.isFailure)
        assertTrue(res.exceptionOrNull() is TouchPolicy.TouchNoSlotException)
        assertTrue(repo.getTouchRequired("touch-key-1", 3))
        assertTrue(store.loadVaultEntries("touch-key-1", "TOUCH-BINDING").single().requiresPhysicalTouch)
    }
}
