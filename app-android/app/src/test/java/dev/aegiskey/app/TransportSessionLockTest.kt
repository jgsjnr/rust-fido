package dev.aegiskey.app

import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl
import dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.domain.model.ConnectionTransportType
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
import dev.aegiskey.app.transportlock.TransportLossCause
import dev.aegiskey.app.transportlock.TransportSessionLock
import dev.aegiskey.app.transportlock.TransportSnapshot
import dev.aegiskey.app.ui.viewmodel.SecureGuardViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Transport-loss session auto-lock (BT + Wi-Fi + cabo, app-android only).
 *
 * Covers the transportlock module decision matrix plus the session effects:
 * state LOCKED, session PIN wiped from memory, Disconnected surfaced
 * (`isUnlocked == false`, timers zeroed — screens render the existing
 * `status_disconnected` / `vault_disconnected_*` strings), polling cancelled.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TransportSessionLockTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        SecureGuardRepositoryImpl.clearSessionPin()
    }

    @After
    fun tearDown() {
        SecureGuardRepositoryImpl.clearSessionPin()
        Dispatchers.resetMain()
    }

    // --- Decision matrix: BT ---

    @Test
    fun evaluate_bleSession_bleDisconnected_locks() {
        val decision = TransportSessionLock.evaluate(
            ConnectionTransportType.BLE,
            TransportSnapshot(bleReady = false)
        )
        assertTrue(decision.shouldLock)
        assertTrue(decision.isDisconnected)
        assertEquals(setOf(TransportLossCause.BLE_DISCONNECTED), decision.causes)
    }

    @Test
    fun evaluate_bleSession_bleReady_bridgeDown_keepsSession() {
        val decision = TransportSessionLock.evaluate(
            ConnectionTransportType.BLE,
            TransportSnapshot(bleReady = true, bridgeReachable = false)
        )
        assertFalse(decision.shouldLock)
        assertTrue(decision.causes.isEmpty())
    }

    // --- Decision matrix: Wi-Fi ---

    @Test
    fun evaluate_wifiSession_wifiLost_locks_evenWithBridgeUp() {
        val decision = TransportSessionLock.evaluate(
            ConnectionTransportType.WIFI,
            TransportSnapshot(wifiReachable = false, bridgeReachable = true)
        )
        assertTrue(decision.shouldLock)
        assertEquals(setOf(TransportLossCause.WIFI_LOST), decision.causes)
    }

    @Test
    fun evaluate_wifiSession_wifiUp_bridgeDown_keepsSession() {
        val decision = TransportSessionLock.evaluate(
            ConnectionTransportType.WIFI,
            TransportSnapshot(wifiReachable = true, bridgeReachable = false)
        )
        assertFalse(decision.shouldLock)
    }

    // --- Decision matrix: cabo ---

    @Test
    fun evaluate_usbSession_directPulled_bridgeDown_locks() {
        val decision = TransportSessionLock.evaluate(
            ConnectionTransportType.USB,
            TransportSnapshot(usbPresent = false, bridgeReachable = false)
        )
        assertTrue(decision.shouldLock)
        assertEquals(
            setOf(TransportLossCause.USB_CABLE_DOWN, TransportLossCause.BRIDGE_OFFLINE),
            decision.causes
        )
    }

    @Test
    fun evaluate_usbSession_bridgeHoldsCableSession_keepsSession() {
        // Cabo via bridge de bancada: sem OTG direto, mas a bridge responde
        // com autoridade pela sessão.
        val decision = TransportSessionLock.evaluate(
            ConnectionTransportType.USB,
            TransportSnapshot(usbPresent = false, bridgeReachable = true)
        )
        assertFalse(decision.shouldLock)
    }

    @Test
    fun evaluate_usbSession_directLinkLive_bridgeDown_keepsSession() {
        val decision = TransportSessionLock.evaluate(
            ConnectionTransportType.USB,
            TransportSnapshot(usbPresent = true, bridgeReachable = false)
        )
        assertFalse(decision.shouldLock)
    }

    // --- Decision matrix: bridge / desconhecido / simulador ---

    @Test
    fun evaluate_unknownCarrier_allProbedDown_locks() {
        val decision = TransportSessionLock.evaluate(
            null,
            TransportSnapshot(
                bridgeReachable = false,
                bleReady = false,
                usbPresent = false,
                wifiReachable = false
            )
        )
        assertTrue(decision.shouldLock)
        assertTrue(decision.causes.contains(TransportLossCause.BRIDGE_OFFLINE))
    }

    @Test
    fun evaluate_allUnknown_neverLocks_neverInvents() {
        val decision = TransportSessionLock.evaluate(null, TransportSnapshot())
        assertFalse(decision.shouldLock)
        assertTrue(decision.causes.isEmpty())
    }

    @Test
    fun evaluate_simulator_neverLocks() {
        val decision = TransportSessionLock.evaluate(
            ConnectionTransportType.SIMULATOR,
            TransportSnapshot(
                bridgeReachable = false,
                bleReady = false,
                usbPresent = false,
                wifiReachable = false
            )
        )
        assertFalse(decision.shouldLock)
        assertTrue(decision.causes.isEmpty())
    }

    @Test
    fun causesForLinkLoss_mapsEachTransport() {
        assertEquals(
            setOf(TransportLossCause.BLE_DISCONNECTED),
            TransportSessionLock.causesForLinkLoss(ConnectionTransportType.BLE)
        )
        assertEquals(
            setOf(TransportLossCause.WIFI_LOST),
            TransportSessionLock.causesForLinkLoss(ConnectionTransportType.WIFI)
        )
        assertEquals(
            setOf(TransportLossCause.USB_CABLE_DOWN),
            TransportSessionLock.causesForLinkLoss(ConnectionTransportType.USB)
        )
        assertTrue(
            TransportSessionLock.causesForLinkLoss(ConnectionTransportType.SIMULATOR).isEmpty()
        )
    }

    // --- Session effects: repository ---

    @Test
    fun repo_onTransportLost_locksAndWipesSessionMemory() {
        val repo = SecureGuardRepositoryImpl(HostUsbUartBridgeClient(), null, null)
        SecureGuardRepositoryImpl.lastVerifiedSessionPin = "4927"

        repo.onTransportLost(setOf(TransportLossCause.BLE_DISCONNECTED))

        assertNull(
            "PIN da sessão deve ser zerado",
            SecureGuardRepositoryImpl.lastVerifiedSessionPin
        )
        assertEquals(SecureGuardStateEnum.LOCKED, repo.statusFlow.value.state)
        assertFalse("Desconectado: sem sessão ativa", repo.statusFlow.value.isUnlocked)
        assertEquals(0L, repo.statusFlow.value.sessionRemainingMs)
        assertEquals(0L, repo.statusFlow.value.rateLimitRemainingMs)
    }

    @Test
    fun repo_onTransportLost_emptyCauses_isNoop() {
        val repo = SecureGuardRepositoryImpl(HostUsbUartBridgeClient(), null, null)
        SecureGuardRepositoryImpl.lastVerifiedSessionPin = "4927"

        repo.onTransportLost(emptySet())

        assertEquals(
            "Sem causa não há trava",
            "4927",
            SecureGuardRepositoryImpl.lastVerifiedSessionPin
        )
    }

    @Test
    fun repo_notifyTransportSnapshot_wifiLost_locks() {
        val repo = SecureGuardRepositoryImpl(HostUsbUartBridgeClient(), null, null)
        SecureGuardRepositoryImpl.lastVerifiedSessionPin = "7359"

        val locked = repo.notifyTransportSnapshot(
            ConnectionTransportType.WIFI,
            TransportSnapshot(wifiReachable = false, bridgeReachable = true)
        )

        assertTrue(locked)
        assertNull(SecureGuardRepositoryImpl.lastVerifiedSessionPin)
        assertEquals(SecureGuardStateEnum.LOCKED, repo.statusFlow.value.state)
        assertFalse(repo.statusFlow.value.isUnlocked)
    }

    @Test
    fun repo_notifyTransportSnapshot_bleLive_keepsSession() {
        val repo = SecureGuardRepositoryImpl(HostUsbUartBridgeClient(), null, null)

        val locked = repo.notifyTransportSnapshot(
            ConnectionTransportType.BLE,
            TransportSnapshot(bleReady = true, bridgeReachable = false)
        )

        assertFalse(locked)
    }

    // --- Session effects: viewmodel (LOCKED + polling cancelado) ---

    private class UnlockedFakeRepo : SecureGuardRepository {
        val flow = MutableStateFlow(
            SecureGuardStatus(
                state = SecureGuardStateEnum.UNLOCKED,
                isProvisioned = true,
                isUnlocked = true,
                failedAttempts = 0,
                remainingAttempts = 5,
                sessionRemainingMs = 300_000L
            )
        )
        override val statusFlow: StateFlow<SecureGuardStatus> = flow
        var detachedCalls = 0

        override suspend fun getStatus() = Result.success(flow.value)
        override suspend fun provision(pin: String, recoveryCode: String?, policy: SecureGuardPolicy?) =
            Result.success("RC")

        override suspend fun unlock(pin: String) = Result.success(flow.value)
        override suspend fun lock() = Result.success(Unit)
        override suspend fun changePin(currentPin: String, newPin: String) = Result.success(Unit)
        override suspend fun recover(recoveryCode: String, newPin: String) = Result.success(null)
        override suspend fun updatePolicy(policy: SecureGuardPolicy) = Result.success(policy)
        override suspend fun wipeSelective(scope: Int, confirmationToken: String) = Result.success(false)
        override fun onHardwareDetached() {
            detachedCalls += 1
            SecureGuardRepositoryImpl.lastVerifiedSessionPin = null
            flow.value = flow.value.copy(
                state = SecureGuardStateEnum.LOCKED,
                isUnlocked = false,
                sessionRemainingMs = 0L
            )
        }
    }

    private fun viewModel(repo: SecureGuardRepository) = SecureGuardViewModel(
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

    @Test
    fun viewModel_onTransportLost_locksImmediately_andCancelsPolling() = runTest(testDispatcher) {
        val repo = UnlockedFakeRepo()
        val vm = viewModel(repo)
        testScheduler.runCurrent()

        // Polling de sessão ativo: o countdown drena o tempo restante.
        advanceTimeBy(2_000L)
        runCurrent()
        val draining = vm.uiState.value.status.sessionRemainingMs
        assertTrue("Polling deve drenar a sessão", draining < 300_000L)
        assertTrue(vm.uiState.value.status.isUnlocked)

        // Perda de transporte (Wi-Fi): trava imediata + polling cancelado.
        SecureGuardRepositoryImpl.lastVerifiedSessionPin = "2460"
        vm.onTransportLost(setOf(TransportLossCause.WIFI_LOST))
        runCurrent()

        assertEquals(SecureGuardStateEnum.LOCKED, vm.uiState.value.status.state)
        assertFalse("Desconectado: sem sessão ativa", vm.uiState.value.status.isUnlocked)
        assertEquals(0L, vm.uiState.value.status.sessionRemainingMs)
        assertNull(SecureGuardRepositoryImpl.lastVerifiedSessionPin)
        assertEquals(1, repo.detachedCalls)

        // Polling cancelado: o tempo restante não volta a mexer.
        advanceTimeBy(10_000L)
        runCurrent()
        assertEquals(SecureGuardStateEnum.LOCKED, vm.uiState.value.status.state)
        assertEquals(0L, vm.uiState.value.status.sessionRemainingMs)
    }

    @Test
    fun viewModel_onTransportLost_emptyCauses_isNoop() = runTest(testDispatcher) {
        val repo = UnlockedFakeRepo()
        val vm = viewModel(repo)
        testScheduler.runCurrent()

        vm.onTransportLost(emptySet())
        runCurrent()

        assertEquals(SecureGuardStateEnum.UNLOCKED, vm.uiState.value.status.state)
        assertEquals(0, repo.detachedCalls)
    }

    // --- Link-monitor seam ---

    @Test
    fun connectedKeys_onLinkLost_defaultsNull_andIsAssignable() {
        val store = EncryptedKeysStore(null)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val repo = ConnectedKeysRepositoryImpl(store, scope)

        assertNull(repo.onLinkLost)

        var seen: ConnectionTransportType? = null
        repo.onLinkLost = { seen = it }
        repo.onLinkLost?.invoke(ConnectionTransportType.WIFI)

        assertEquals(ConnectionTransportType.WIFI, seen)
    }
}
