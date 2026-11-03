package dev.aegiskey.app

import dev.aegiskey.app.ble.DevicePresence
import dev.aegiskey.app.ble.DevicePresence.NeedUpRequiredException
import dev.aegiskey.app.ble.DevicePresence.isNeedUpDenial
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl
import dev.aegiskey.app.data.repository.KeyVaultRepositoryImpl
import dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl
import dev.aegiskey.app.data.repository.TotpRepositoryImpl
import dev.aegiskey.app.data.system.SystemSecurityService
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DiscoveredKeyCandidate
import dev.aegiskey.app.domain.model.HardwareDeviceDiagnostics
import dev.aegiskey.app.domain.model.TotpAccountItem
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.domain.repository.ConnectedKeysRepository
import dev.aegiskey.app.domain.repository.KeyVaultRepository
import dev.aegiskey.app.domain.repository.PairingWizardRepository
import dev.aegiskey.app.domain.repository.TotpRepository
import dev.aegiskey.app.domain.usecase.AddTotpAccountUseCase
import dev.aegiskey.app.domain.usecase.DeleteTotpAccountUseCase
import dev.aegiskey.app.domain.usecase.DeleteVaultEntryUseCase
import dev.aegiskey.app.domain.usecase.GenerateAccessKeyUseCase
import dev.aegiskey.app.domain.usecase.GetActiveKeyUseCase
import dev.aegiskey.app.domain.usecase.GetTotpAccountsUseCase
import dev.aegiskey.app.domain.usecase.GetVaultEntriesUseCase
import dev.aegiskey.app.domain.usecase.IncrementHotpCounterUseCase
import dev.aegiskey.app.domain.usecase.RefreshTotpCodesUseCase
import dev.aegiskey.app.domain.usecase.RefreshVaultUseCase
import dev.aegiskey.app.domain.usecase.RunHealthCheckUseCase
import dev.aegiskey.app.domain.usecase.SimulateButtonSingleTouchUseCase
import dev.aegiskey.app.domain.usecase.TickTotpTimerUseCase
import dev.aegiskey.app.domain.usecase.UpdateKeySecurityTogglesUseCase
import dev.aegiskey.app.ui.viewmodel.KeyVaultViewModel
import dev.aegiskey.app.ui.viewmodel.TotpAuthenticatorViewModel
import androidx.lifecycle.ViewModelStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Finding A3: a device User Presence denial (NEED_UP 0x01) must surface the
 * "touch the key" prompt instead of closing a sheet or showing codes as if
 * they came from the device. TOTP codes must be labeled by honest source.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class NeedUpPresenceTest {

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

    // --- DevicePresence: bridge flag tolerated, status-code fallback --------

    @Test
    fun devicePresence_statusFallback_whenFlagAbsent() {
        assertTrue(DevicePresence.isNeedUp(0x01, null))
        assertFalse(DevicePresence.isNeedUp(0x00, null))
        assertFalse(DevicePresence.isNeedUp(null, null))
        assertFalse(DevicePresence.isNeedUp(0x05, null))
    }

    @Test
    fun devicePresence_explicitFlagWins() {
        assertTrue(DevicePresence.isNeedUp(0x00, true))
        assertTrue(DevicePresence.isNeedUp(null, true))
        assertFalse(DevicePresence.isNeedUp(0x01, false))
        assertFalse(DevicePresence.isNeedUp(null, false))
    }

    @Test
    fun devicePresence_rawResponseParsing() {
        assertTrue(DevicePresence.isNeedUpResponse(byteArrayOf(0x20.toByte(), 0x01.toByte())))
        assertFalse(DevicePresence.isNeedUpResponse(byteArrayOf(0x20.toByte(), 0x00.toByte())))
        assertFalse(DevicePresence.isNeedUpResponse(null))
        assertFalse(DevicePresence.isNeedUpResponse(byteArrayOf(0x01.toByte())))
        assertTrue(DevicePresence.isNeedUpResponse(byteArrayOf(0x20.toByte(), 0x00.toByte()), true))
    }

    @Test
    fun devicePresence_bridgeJsonFlagParsing() {
        assertEquals(true, DevicePresence.needUpFlagFromBridgeJson("""{"ok":false,"status":1,"need_up":true}"""))
        assertEquals(false, DevicePresence.needUpFlagFromBridgeJson("""{"ok":true,"need_up":false}"""))
        assertEquals(true, DevicePresence.needUpFlagFromBridgeJson("""{"needUp":true}"""))
        assertNull(DevicePresence.needUpFlagFromBridgeJson("""{"ok":true,"status":0}"""))
        assertNull(DevicePresence.needUpFlagFromBridgeJson(null))
        assertNull(DevicePresence.needUpFlagFromBridgeJson("  "))
        assertNull(DevicePresence.needUpFlagFromBridgeJson("not-json"))
    }

    @Test
    fun devicePresence_denialCarrier_detection() {
        assertTrue(NeedUpRequiredException("key-gen").isNeedUpDenial())
        val wrapped = IllegalStateException("outer", NeedUpRequiredException("oath-code"))
        assertTrue(wrapped.isNeedUpDenial())
        assertFalse(IllegalStateException("other").isNeedUpDenial())
    }

    /**
     * Settles ViewModel work: bounded virtual-time steps instead of
     * advanceUntilIdle (a VM init ticker would reschedule forever).
     */
    private suspend fun TestScope.settle() {
        repeat(10) {
            runCurrent()
            advanceTimeBy(50)
        }
    }

    // --- Key-gen repository: NEED_UP never fabricates success --------------

    private suspend fun vaultHarness(): Triple<EncryptedKeysStore, ConnectedKeysRepository, KeyVaultRepositoryImpl> {
        val store = EncryptedKeysStore(null)
        val connected = ConnectedKeysRepositoryImpl(store, null, null)
        connected.addOrUpdateKey(
            ConnectedKeyDevice(
                id = "needup-key-1",
                displayName = "AegisKey NEED_UP",
                hardwareAddressOrId = "usb:needup",
                bindingIdHex = "NEEDUP-BINDING",
                transportType = ConnectionTransportType.USB,
                isCurrentlyConnected = true
            )
        )
        val repo = KeyVaultRepositoryImpl(
            keysStore = store,
            bleClient = null,
            simulatedRenodeTransport = SimulatedRenodeTransport(),
            connectedKeysRepository = connected,
            scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        )
        return Triple(store, connected, repo)
    }

    @Test
    fun keyGen_needUp_returnsFailure_notSilentSuccess() = runTest(testDispatcher) {
        val (store, _, repo) = vaultHarness()
        var calls = 0
        repo.vendorOverride = { _, _ ->
            calls++
            byteArrayOf(VendorOps.OP_KEY_GEN_ONDEVICE.toByte(), VendorOps.STATUS_NEED_UP.toByte())
        }

        val res = repo.generateNewAccessKey("needup-key-1", "Touch Key", AccessKeyType.PASSKEY_FIDO)

        assertTrue("NEED_UP must fail, never succeed silently", res.isFailure)
        assertTrue(res.exceptionOrNull()!!.isNeedUpDenial())
        assertTrue("retry happened, still denied", calls >= 2)
        assertTrue("no entry fabricated in memory", repo.vaultEntries.value.isEmpty())
        assertTrue(
            "no entry fabricated in cache",
            store.loadVaultEntries("needup-key-1", "NEEDUP-BINDING").isEmpty()
        )
    }

    @Test
    fun walletGen_needUp_returnsFailure_notSilentSuccess() = runTest(testDispatcher) {
        val (_, _, repo) = vaultHarness()
        repo.vendorOverride = { opcode, _ ->
            when (opcode) {
                VendorOps.OP_WALLET_LIST -> byteArrayOf(VendorOps.OP_WALLET_LIST.toByte(), 0x00.toByte())
                VendorOps.OP_WALLET_GEN -> byteArrayOf(VendorOps.OP_WALLET_GEN.toByte(), VendorOps.STATUS_NEED_UP.toByte())
                else -> null
            }
        }

        val res = repo.generateNewAccessKey("needup-key-1", "Cold BTC", AccessKeyType.CRYPTO_WALLET_BTC)

        assertTrue("wallet NEED_UP must fail", res.isFailure)
        assertTrue(res.exceptionOrNull()!!.isNeedUpDenial())
        assertTrue(repo.vaultEntries.value.isEmpty())
    }

    @Test
    fun keyGen_ok_stillSucceeds_control() = runTest(testDispatcher) {
        val (_, _, repo) = vaultHarness()
        repo.vendorOverride = { opcode, _ -> byteArrayOf(opcode.toByte(), 0x00.toByte()) }

        val res = repo.generateNewAccessKey("needup-key-1", "OK Key", AccessKeyType.PASSKEY_FIDO)

        assertTrue(res.isSuccess)
        assertEquals("OK Key", res.getOrThrow().label)
        assertEquals(1, repo.vaultEntries.value.size)
    }

    // --- TOTP repository: honest source labeling + presence --------------

    private suspend fun totpHarness(): Triple<EncryptedKeysStore, ConnectedKeysRepository, TotpRepositoryImpl> {
        val store = EncryptedKeysStore(null)
        val connected = ConnectedKeysRepositoryImpl(store, null, null)
        connected.addOrUpdateKey(
            ConnectedKeyDevice(
                id = "needup-totp-1",
                displayName = "AegisKey TOTP",
                hardwareAddressOrId = "usb:totp",
                bindingIdHex = "TOTP-BINDING",
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
        return byteArrayOf(VendorOps.OP_OATH_LIST.toByte(), 0x00.toByte()) + tlv
    }

    @Test
    fun totpList_needUp_failsAndFlagsPresence_noSilentCodes() = runTest(testDispatcher) {
        val (_, _, repo) = totpHarness()
        repo.vendorOverride = { opcode, _ ->
            if (opcode == VendorOps.OP_OATH_LIST) {
                byteArrayOf(VendorOps.OP_OATH_LIST.toByte(), VendorOps.STATUS_NEED_UP.toByte())
            } else {
                null
            }
        }

        val res = repo.refreshAccountsAndCodes("needup-totp-1")

        assertTrue("list denial must fail, never masquerade as empty/fresh", res.isFailure)
        assertTrue(res.exceptionOrNull()!!.isNeedUpDenial())
        assertEquals("oath-list", repo.needUpOp.value)
        assertTrue("no codes fabricated", repo.accounts.value.isEmpty())
    }

    @Test
    fun totpCode_needUp_labelsLocalFallback_andFlagsTouch() = runTest(testDispatcher) {
        val (store, _, repo) = totpHarness()
        store.saveTotpAccounts(
            "needup-totp-1",
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
        repo.vendorOverride = { opcode, _ ->
            when (opcode) {
                VendorOps.OP_OATH_LIST -> oathListOk("GitHub:octocat")
                VendorOps.OP_OATH_CODE -> byteArrayOf(VendorOps.OP_OATH_CODE.toByte(), VendorOps.STATUS_NEED_UP.toByte())
                else -> null
            }
        }

        val res = repo.refreshAccountsAndCodes("needup-totp-1")

        assertTrue(res.isSuccess)
        val item = res.getOrThrow().single()
        assertEquals("cached code kept, not invented", "654321", item.currentCode)
        assertFalse("must NOT claim device origin", item.isOnDeviceBacked)
        assertTrue("must flag touch-to-refresh", item.requiresTouchToRefresh)
        assertEquals("oath-code", repo.needUpOp.value)
    }

    @Test
    fun totpCode_ok_labelsOnDeviceBacked() = runTest(testDispatcher) {
        val (store, _, repo) = totpHarness()
        store.saveTotpAccounts(
            "needup-totp-1",
            listOf(
                TotpAccountItem(
                    id = "a1",
                    issuer = "GitHub",
                    accountName = "octocat",
                    currentCode = "------",
                    formattedCode = "--- ---",
                    remainingSeconds = 30
                )
            )
        )
        val codeTlv = VendorOps.writeTlv(VendorOps.TAG_OATH_RESPONSE, "123456".toByteArray(Charsets.UTF_8))
        repo.vendorOverride = { opcode, _ ->
            when (opcode) {
                VendorOps.OP_OATH_LIST -> oathListOk("GitHub:octocat")
                VendorOps.OP_OATH_CODE -> byteArrayOf(VendorOps.OP_OATH_CODE.toByte(), 0x00.toByte()) + codeTlv
                else -> null
            }
        }

        val item = repo.refreshAccountsAndCodes("needup-totp-1").getOrThrow().single()

        assertEquals("123456", item.currentCode)
        assertTrue("device code is on-device-backed", item.isOnDeviceBacked)
        assertFalse(item.requiresTouchToRefresh)
        assertNull(repo.needUpOp.value)
    }

    @Test
    fun totpAdd_codeNeedUp_labelsLocal_andKeepsPresence() = runTest(testDispatcher) {
        val (_, _, repo) = totpHarness()
        repo.vendorOverride = { opcode, _ ->
            when (opcode) {
                VendorOps.OP_OATH_PUT -> byteArrayOf(VendorOps.OP_OATH_PUT.toByte(), 0x00.toByte())
                VendorOps.OP_OATH_CODE -> byteArrayOf(VendorOps.OP_OATH_CODE.toByte(), VendorOps.STATUS_NEED_UP.toByte())
                else -> null
            }
        }

        val res = repo.addAccount(
            keyId = "needup-totp-1",
            issuer = "GitHub",
            accountName = "octocat",
            secretOrUri = "JBSWY3DPEHPK3PXP",
            digits = 6
        )

        assertTrue(res.isSuccess)
        val item = res.getOrThrow()
        assertEquals(6, item.currentCode.length)
        assertFalse("first code is local, not device-backed", item.isOnDeviceBacked)
        assertTrue(item.requiresTouchToRefresh)
        assertEquals("oath-code", repo.needUpOp.value)
        repo.clearNeedUpOp()
        assertNull(repo.needUpOp.value)
    }

    // --- ViewModels: NEED_UP shows the prompt, never closes silently -----

    private class FakeVaultRepo : KeyVaultRepository {
        private val _entries = MutableStateFlow<List<VaultKeyEntry>>(emptyList())
        override val vaultEntries: StateFlow<List<VaultKeyEntry>> = _entries
        var genCalls = 0
        var genHandler: () -> Result<VaultKeyEntry> = {
            Result.success(VaultKeyEntry(0, "K", AccessKeyType.PASSKEY_FIDO, "ok", 1L))
        }

        override suspend fun refreshVault(keyId: String) = Result.success(emptyList<VaultKeyEntry>())
        override suspend fun generateNewAccessKey(
            keyId: String,
            label: String,
            type: AccessKeyType,
            algorithmOrCurve: String,
            extraParam: String
        ): Result<VaultKeyEntry> {
            genCalls++
            return genHandler()
        }

        override suspend fun deleteVaultEntry(keyId: String, slotId: Int) = Result.success(Unit)
        override suspend fun resetHardwareVault(keyId: String) = Result.success("ok")
        override suspend fun runQuickHealthCheck(keyId: String) = Result.success("ok")
        override suspend fun signChallengeOrTransaction(keyId: String, slotId: Int, messageOrTx: String) =
            Result.success("sig")

        override suspend fun exportKeyEnvelopeAegn(keyId: String, slotId: Int) = Result.success("env")
        override suspend fun enrollOrUpdatePivPin(keyId: String, slotCode: String, newPin: String, newPuk: String) =
            Result.success("ok")

        override suspend fun getTouchRequired(keyId: String, slotId: Int) = true
        override suspend fun setTouchRequired(keyId: String, slotId: Int, requireTouch: Boolean) =
            Result.success(Unit)

        override suspend fun fetchHardwareDiagnostics(keyId: String) = Result.success(
            HardwareDeviceDiagnostics(
                firmwareVersion = "test",
                transportChannel = "test",
                totalVaultItems = 0,
                freeSlotsRemaining = 32,
                fido2SupportedCurves = emptyList(),
                pivSlotsAvailable = emptyList(),
                healthStatusText = "ok",
                isPinConfigured = false,
                isBoundToThisPhone = false
            )
        )
    }

    private class FakePairingRepo : PairingWizardRepository {
        override val discoveredCandidates: StateFlow<List<DiscoveredKeyCandidate>> =
            MutableStateFlow(emptyList())
        override val isScanning: StateFlow<Boolean> = MutableStateFlow(false)
        override val buttonHoldSimulatedOrDetected: StateFlow<Boolean> = MutableStateFlow(false)
        override val isUsbDetected: StateFlow<Boolean> = MutableStateFlow(false)
        override suspend fun startDiscovery(transport: ConnectionTransportType) = Unit
        override suspend fun stopDiscovery() = Unit
        override suspend fun simulatePhysicalButtonHold5s() = Result.success(Unit)
        override suspend fun simulatePhysicalButtonSingleTouch() = Result.success(Unit)
        override suspend fun connectToCandidate(candidate: DiscoveredKeyCandidate) = Result.success(Unit)
        override suspend fun performBiometricBinding(keyAliasName: String, recoveryPin: String?) =
            throw UnsupportedOperationException("unused")

        override suspend fun autoValidatePresence(
            candidate: DiscoveredKeyCandidate?,
            transport: ConnectionTransportType
        ) = Result.success(Unit)

        override suspend fun registerConfiguredKeyOrSkip() =
            throw UnsupportedOperationException("unused")

        override suspend fun connectUsbDeviceAndRegister() =
            throw UnsupportedOperationException("unused")
    }

    private suspend fun keyVaultViewModelHarness(fake: FakeVaultRepo): Pair<ConnectedKeysRepository, KeyVaultViewModel> {
        val store = EncryptedKeysStore(null)
        val connected = ConnectedKeysRepositoryImpl(store, null, null)
        connected.addOrUpdateKey(
            ConnectedKeyDevice(
                id = "vm-key-1",
                displayName = "VM Key",
                hardwareAddressOrId = "usb:vm",
                bindingIdHex = "VM-BIND",
                transportType = ConnectionTransportType.USB,
                isCurrentlyConnected = true
            )
        )
        val vm = KeyVaultViewModel(
            getActiveKeyUseCase = GetActiveKeyUseCase(connected),
            getVaultEntriesUseCase = GetVaultEntriesUseCase(fake),
            refreshVaultUseCase = RefreshVaultUseCase(fake),
            generateAccessKeyUseCase = GenerateAccessKeyUseCase(fake),
            deleteVaultEntryUseCase = DeleteVaultEntryUseCase(fake),
            runHealthCheckUseCase = RunHealthCheckUseCase(fake),
            updateKeySecurityTogglesUseCase = UpdateKeySecurityTogglesUseCase(connected),
            simulateButtonSingleTouchUseCase = SimulateButtonSingleTouchUseCase(FakePairingRepo()),
            securityService = SystemSecurityService(null)
        )
        return connected to vm
    }

    @Test
    fun keyVaultViewModel_needUp_showsPrompt_noSilentCloseOrSuccess() = runTest(testDispatcher) {
        val fake = FakeVaultRepo()
        fake.genHandler = { Result.failure(NeedUpRequiredException("key-gen")) }
        val (_, vm) = keyVaultViewModelHarness(fake)
        val job = backgroundScope.launch { vm.uiState.collect {} }

        vm.generateKey("Touch Key", AccessKeyType.PASSKEY_FIDO)
        settle()

        val st = vm.uiState.value
        assertNotNull("presence prompt must be shown", st.presenceRequest)
        assertEquals("key-gen", st.presenceRequest?.op)
        assertNull("no silent success message", st.userMessage)
        assertNull("no error in place of the prompt", st.errorMessage)

        vm.dismissPresenceRequest()
        settle()
        assertNull(vm.uiState.value.presenceRequest)
        job.cancel()
    }

    @Test
    fun keyVaultViewModel_retryAfterTouch_regenerates() = runTest(testDispatcher) {
        val fake = FakeVaultRepo()
        fake.genHandler = { Result.failure(NeedUpRequiredException("key-gen")) }
        val (_, vm) = keyVaultViewModelHarness(fake)
        val job = backgroundScope.launch { vm.uiState.collect {} }

        vm.generateKey("Touch Key", AccessKeyType.PASSKEY_FIDO)
        settle()
        assertNotNull(vm.uiState.value.presenceRequest)

        fake.genHandler = {
            Result.success(VaultKeyEntry(0, "Touch Key", AccessKeyType.PASSKEY_FIDO, "ok", 1L))
        }
        vm.retryPendingKeyGen()
        settle()

        val st = vm.uiState.value
        assertNull("prompt cleared after successful retry", st.presenceRequest)
        assertNotNull("success surfaced after touch", st.userMessage)
        assertEquals(2, fake.genCalls)
        job.cancel()
    }

    private class FakeTotpRepo : TotpRepository {
        private val _accounts = MutableStateFlow<List<TotpAccountItem>>(emptyList())
        override val accounts: StateFlow<List<TotpAccountItem>> = _accounts
        override val remainingSeconds: StateFlow<Int> = MutableStateFlow(30)
        private val _needUpOp = MutableStateFlow<String?>(null)
        override val needUpOp: StateFlow<String?> = _needUpOp
        override fun clearNeedUpOp() {
            _needUpOp.value = null
        }

        fun denyUp(op: String) {
            _needUpOp.value = op
        }

        var refreshHandler: suspend (String) -> Result<List<TotpAccountItem>> = {
            Result.success(_accounts.value)
        }
        var addHandler: suspend () -> Result<TotpAccountItem> = {
            Result.success(
                TotpAccountItem("n", "I", "a", "123456", "123 456", 30)
            )
        }

        override suspend fun refreshAccountsAndCodes(keyId: String) = refreshHandler(keyId)
        override suspend fun addAccount(
            keyId: String,
            issuer: String,
            accountName: String,
            secretOrUri: String,
            digits: Int,
            periodSeconds: Int,
            isHotp: Boolean,
            algorithm: String
        ) = addHandler()

        override suspend fun deleteAccount(keyId: String, accountId: String) = Result.success(Unit)
        override suspend fun incrementHotpCounter(keyId: String, accountId: String) =
            throw UnsupportedOperationException("unused")

        override fun tickTimer(nowEpochSeconds: Long) = Unit
    }

    private suspend fun totpViewModelHarness(fake: FakeTotpRepo): TotpAuthenticatorViewModel {
        val store = EncryptedKeysStore(null)
        val connected = ConnectedKeysRepositoryImpl(store, null, null)
        connected.addOrUpdateKey(
            ConnectedKeyDevice(
                id = "vm-totp-1",
                displayName = "VM TOTP",
                hardwareAddressOrId = "usb:vmtotp",
                bindingIdHex = "VM-TOTP-BIND",
                transportType = ConnectionTransportType.USB,
                isCurrentlyConnected = true
            )
        )
        return TotpAuthenticatorViewModel(
            getActiveKeyUseCase = GetActiveKeyUseCase(connected),
            getTotpAccountsUseCase = GetTotpAccountsUseCase(fake),
            refreshTotpCodesUseCase = RefreshTotpCodesUseCase(fake),
            addTotpAccountUseCase = AddTotpAccountUseCase(fake),
            deleteTotpAccountUseCase = DeleteTotpAccountUseCase(fake),
            tickTotpTimerUseCase = TickTotpTimerUseCase(fake),
            securityService = SystemSecurityService(null),
            incrementHotpCounterUseCase = IncrementHotpCounterUseCase(fake),
            keysStore = null,
            totpRepository = fake
        )
    }

    @Test
    fun totpViewModel_needUp_showsPrompt_noSilentFeedback() = runTest(testDispatcher) {
        val fake = FakeTotpRepo()
        fake.refreshHandler = {
            fake.denyUp("oath-list")
            Result.failure(NeedUpRequiredException("oath-list"))
        }
        // The VM's init 1s ticker reschedules forever: register the VM so
        // viewModelScope is cancelled before runTest's implicit end-of-test
        // drain, otherwise advanceUntilIdle never terminates.
        val vmStore = ViewModelStore()
        val vm = totpViewModelHarness(fake)
        vmStore.put("totp-vm", vm)
        try {
            val job = backgroundScope.launch { vm.uiState.collect {} }
            settle()

            vm.refreshCodes()
            settle()

            val st = vm.uiState.value
            assertNotNull("presence prompt must be shown", st.presenceRequest)
            assertEquals("oath-list", st.presenceRequest?.op)
            assertNull("no silent success feedback", st.feedbackMessage)
            assertNull("no error in place of the prompt", st.errorMessage)

            vm.dismissPresence()
            settle()
            assertNull(vm.uiState.value.presenceRequest)
            job.cancel()
        } finally {
            vmStore.clear()
        }
    }

    @Test
    fun totpViewModel_needUpFlow_surfacesPrompt() = runTest(testDispatcher) {
        val fake = FakeTotpRepo()
        // Same ticker rule as above: cancel viewModelScope before the drain.
        val vmStore = ViewModelStore()
        val vm = totpViewModelHarness(fake)
        vmStore.put("totp-vm", vm)
        try {
            val job = backgroundScope.launch { vm.uiState.collect {} }
            settle()

            fake.denyUp("oath-code")
            settle()

            assertEquals("oath-code", vm.uiState.value.presenceRequest?.op)
            job.cancel()
        } finally {
            vmStore.clear()
        }
    }
}
