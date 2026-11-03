package dev.aegiskey.app

import androidx.lifecycle.ViewModelStore
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl
import dev.aegiskey.app.data.repository.TotpRepositoryImpl
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DeviceError
import dev.aegiskey.app.domain.model.DiscoveredKeyCandidate
import dev.aegiskey.app.domain.model.FirmwareVersion
import dev.aegiskey.app.domain.model.HardwareDeviceDiagnostics
import dev.aegiskey.app.domain.model.OnboardingStep
import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.domain.repository.KeyVaultRepository
import dev.aegiskey.app.domain.repository.PairingWizardRepository
import dev.aegiskey.app.domain.repository.SecureGuardRepository
import dev.aegiskey.app.domain.usecase.AddTotpAccountUseCase
import dev.aegiskey.app.domain.usecase.ChangeSecureGuardPinUseCase
import dev.aegiskey.app.domain.usecase.ConnectCandidateUseCase
import dev.aegiskey.app.domain.usecase.DeleteTotpAccountUseCase
import dev.aegiskey.app.domain.usecase.DeleteVaultEntryUseCase
import dev.aegiskey.app.domain.usecase.GenerateAccessKeyUseCase
import dev.aegiskey.app.domain.usecase.GetActiveKeyUseCase
import dev.aegiskey.app.domain.usecase.GetSecureGuardStatusUseCase
import dev.aegiskey.app.domain.usecase.GetTotpAccountsUseCase
import dev.aegiskey.app.domain.usecase.GetVaultEntriesUseCase
import dev.aegiskey.app.domain.usecase.LockSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.PerformBiometricBindingUseCase
import dev.aegiskey.app.domain.usecase.ProvisionSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.RecoverSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.RefreshTotpCodesUseCase
import dev.aegiskey.app.domain.usecase.RefreshVaultUseCase
import dev.aegiskey.app.domain.usecase.RunHealthCheckUseCase
import dev.aegiskey.app.domain.usecase.SimulateButtonHoldUseCase
import dev.aegiskey.app.domain.usecase.SimulateButtonSingleTouchUseCase
import dev.aegiskey.app.domain.usecase.StartDiscoveryUseCase
import dev.aegiskey.app.domain.usecase.StopDiscoveryUseCase
import dev.aegiskey.app.domain.usecase.TickTotpTimerUseCase
import dev.aegiskey.app.domain.usecase.TriggerSelectiveWipeTestUseCase
import dev.aegiskey.app.domain.usecase.UnlockSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.UpdateKeySecurityTogglesUseCase
import dev.aegiskey.app.domain.usecase.UpdateSecureGuardPolicyUseCase
import dev.aegiskey.app.data.system.SystemSecurityService
import dev.aegiskey.app.data.transport.KeyTransport
import dev.aegiskey.app.domain.usecase.ArmBleOobUseCase
import dev.aegiskey.app.net.WifiApi
import dev.aegiskey.app.ui.navigation.AppRoutes
import dev.aegiskey.app.ui.viewmodel.KeyVaultViewModel
import dev.aegiskey.app.ui.viewmodel.OnboardingWizardViewModel
import dev.aegiskey.app.ui.viewmodel.SecureGuardViewModel
import dev.aegiskey.app.ui.viewmodel.TotpAuthenticatorViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
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
import java.io.File

/**
 * Click-through findings batch (reports/testing/CLICKTHROUGH.md, F1–F8).
 *
 * Behavioral coverage for the four parent-assigned fixes:
 * 1. Dead PIV navigation wired to the real destination ([AppRoutes.PIV]).
 * 2. Hardcoded PT user strings moved to `strings.xml` EN + `values-pt`.
 * 3. Wi-Fi test always surfaces a visible result (incl. networks seen).
 * 4. Generate-Key gated on the unlocked guard state (fail-closed).
 * 5. Firmware/slot drift unified behind [FirmwareVersion] (rule documented).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ClickThroughFindingsTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = false
        dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl.clearSessionPin()
    }

    @After
    fun tearDown() {
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = false
        try {
            dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl.clearSessionPin()
        } catch (_: Throwable) {}
        Dispatchers.resetMain()
    }

    // --- F2: PIV destination is registered (was dead navigation) ----------

    @Test
    fun pivRoute_isRegisteredInAppRoutes() {
        assertEquals("piv", AppRoutes.PIV)
        assertTrue(
            "NavHost must register every route",
            AppRoutes.ALL.containsAll(
                setOf("vault", "codes", "keys", "settings", "ota2", "caps", "piv", "onboarding-wizard")
            )
        )
        // Hub scaffold routes stay consistent with the single source of truth.
        assertEquals(dev.aegiskey.app.ui.atomic.templates.HubDestination.VAULT.route, AppRoutes.VAULT)
        assertEquals(dev.aegiskey.app.ui.atomic.templates.HubDestination.CODES.route, AppRoutes.CODES)
        assertEquals(dev.aegiskey.app.ui.atomic.templates.HubDestination.KEYS.route, AppRoutes.KEYS)
        assertEquals(dev.aegiskey.app.ui.atomic.templates.HubDestination.SETTINGS.route, AppRoutes.SETTINGS)
    }

    // --- F7: single source of truth for version + slots --------------------

    @Test
    fun firmwareVersion_deviceReportedWins_appVersionFallback() {
        assertEquals("v2.4.1-rc1", FirmwareVersion.resolve("v2.4.1-rc1"))
        assertEquals(FirmwareVersion.appVersion, FirmwareVersion.resolve(null))
        assertEquals(FirmwareVersion.appVersion, FirmwareVersion.resolve(""))
        assertEquals(FirmwareVersion.appVersion, FirmwareVersion.resolve("   "))
        assertTrue("fallback must never be blank", FirmwareVersion.appVersion.isNotBlank())
    }

    @Test
    fun firmwareVersion_freeSlots_derivesFromMaxSlots() {
        assertEquals(32, FirmwareVersion.MAX_SLOTS)
        assertEquals(32, FirmwareVersion.freeSlots(0))
        assertEquals(2, FirmwareVersion.freeSlots(30))
        assertEquals(0, FirmwareVersion.freeSlots(32))
        assertEquals("over-capacity clamps, never negative", 0, FirmwareVersion.freeSlots(99))
    }

    // --- F1: onboarding errors resolve via strings.xml --------------------

    private class EmptyPairingRepo : PairingWizardRepository {
        override val discoveredCandidates: StateFlow<List<DiscoveredKeyCandidate>> =
            MutableStateFlow(emptyList())
        override val isScanning: StateFlow<Boolean> = MutableStateFlow(false)
        override val buttonHoldSimulatedOrDetected: StateFlow<Boolean> = MutableStateFlow(false)
        override val isUsbDetected: StateFlow<Boolean> = MutableStateFlow(false)

        override suspend fun startDiscovery(transport: ConnectionTransportType) = Unit
        override suspend fun stopDiscovery() = Unit
        override suspend fun simulatePhysicalButtonHold5s(): Result<Unit> = Result.success(Unit)
        override suspend fun simulatePhysicalButtonSingleTouch(): Result<Unit> = Result.success(Unit)
        override suspend fun connectToCandidate(candidate: DiscoveredKeyCandidate): Result<Unit> =
            Result.success(Unit)
        override suspend fun performBiometricBinding(keyAliasName: String, recoveryPin: String?): Result<ConnectedKeyDevice> =
            Result.failure(IllegalStateException("no hardware in unit test"))
        override suspend fun autoValidatePresence(candidate: DiscoveredKeyCandidate?, transport: ConnectionTransportType): Result<Unit> =
            Result.success(Unit)
        override suspend fun registerConfiguredKeyOrSkip(): Result<ConnectedKeyDevice> =
            Result.failure(IllegalStateException("no hardware in unit test"))
        override suspend fun connectUsbDeviceAndRegister(): Result<ConnectedKeyDevice> =
            Result.failure(IllegalStateException("no hardware in unit test"))
    }

    private fun onboardingVm(repo: PairingWizardRepository = EmptyPairingRepo()) =
        OnboardingWizardViewModel(
            pairingWizardRepository = repo,
            startDiscoveryUseCase = StartDiscoveryUseCase(repo),
            stopDiscoveryUseCase = StopDiscoveryUseCase(repo),
            connectCandidateUseCase = ConnectCandidateUseCase(repo),
            simulateButtonHoldUseCase = SimulateButtonHoldUseCase(repo),
            simulateButtonSingleTouchUseCase = SimulateButtonSingleTouchUseCase(repo),
            performBiometricBindingUseCase = PerformBiometricBindingUseCase(repo),
            armBleOobUseCase = ArmBleOobUseCase(NoOobUsbTransport()),
        )

    private class NoOobUsbTransport : KeyTransport {
        override val transportType: ConnectionTransportType = ConnectionTransportType.USB
        override val isConnected: StateFlow<Boolean> = MutableStateFlow(false)
        override suspend fun connect(target: String): Result<Unit> =
            Result.failure(IllegalStateException("no hardware in unit test"))

        override suspend fun disconnect() = Unit
        override suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray? = null
        override suspend fun sendMsg(payload: ByteArray): ByteArray? = null
        override suspend fun cancel(): Boolean = true
    }

    @Test
    fun onboarding_noSelection_setsStringRes_notHardcodedPt() = runTest(testDispatcher) {
        val vm = onboardingVm()
        vm.selectTransport(ConnectionTransportType.BLE)
        testScheduler.runCurrent()

        vm.nextStep() // WELCOME -> HOLD
        testScheduler.advanceUntilIdle()
        assertEquals(OnboardingStep.HOLD_PHYSICAL_BUTTON, vm.uiState.value.currentStep)

        vm.nextStep() // HOLD -> DISCOVER
        testScheduler.advanceUntilIdle()
        assertEquals(OnboardingStep.DISCOVER_AND_CONNECT, vm.uiState.value.currentStep)

        vm.nextStep() // DISCOVER with zero candidates: fail-closed on this step
        testScheduler.advanceUntilIdle()
        assertEquals(
            "wizard must stay on discover with no selection",
            OnboardingStep.DISCOVER_AND_CONNECT,
            vm.uiState.value.currentStep
        )
        assertNull("dynamic fallback must stay null for static errors", vm.uiState.value.errorMessage)
        assertEquals(
            R.string.onb_err_no_selection,
            vm.uiState.value.errorResId
        )
    }

    // --- F1: OATH repository + viewmodel failures resolve via strings.xml -

    private suspend fun totpHarness(): Triple<EncryptedKeysStore, ConnectedKeysRepositoryImpl, TotpRepositoryImpl> {
        val store = EncryptedKeysStore(null)
        val connected = ConnectedKeysRepositoryImpl(store, null, null)
        connected.addOrUpdateKey(
            ConnectedKeyDevice(
                id = "totp-f1",
                displayName = "AegisKey F1",
                hardwareAddressOrId = "usb:f1",
                bindingIdHex = "F1-BINDING",
                transportType = ConnectionTransportType.USB,
                isCurrentlyConnected = true
            )
        )
        val repo = TotpRepositoryImpl(
            keysStore = store,
            usbKeyTransport = null,
            bleKeyTransport = null,
            simulatedRenodeTransport = SimulatedRenodeTransport(),
            connectedKeysRepository = connected,
            scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        )
        return Triple(store, connected, repo)
    }

    @Test
    fun totpEnroll_noHardwareResponse_failsClosedWithStringRes() = runTest(testDispatcher) {
        val (_, _, repo) = totpHarness()
        // No transports wired and no vendor override: the key cannot answer.
        val result = AddTotpAccountUseCase(repo)(
            keyId = "totp-f1",
            issuer = "GitHub",
            accountName = "user",
            secretOrUri = "JBSWY3DPEHPK3PXP",
            digits = 6,
            periodSeconds = 30,
            isHotp = false,
            algorithm = "SHA1"
        )
        assertTrue("enroll without hardware must fail, never succeed silently", result.isFailure)
        val deviceError = generateSequence<Throwable>(result.exceptionOrNull()!!) { it.cause }
            .filterIsInstance<DeviceError>()
            .firstOrNull()
        assertNotNull("failure must be a typed DeviceError, not a PT literal", deviceError)
        assertEquals(R.string.oath_err_no_response_enroll, deviceError!!.resId)
    }

    @Test
    fun totpViewModel_enrollFailure_surfacesStringRes() = runTest(testDispatcher) {
        val (_, connected, repo) = totpHarness()
        // The VM's init 1s ticker reschedules forever: register the VM so
        // viewModelScope is cancelled before runTest's implicit end-of-test
        // drain, otherwise advanceUntilIdle never terminates.
        val vmStore = ViewModelStore()
        val vm = TotpAuthenticatorViewModel(
            getActiveKeyUseCase = GetActiveKeyUseCase(connected),
            getTotpAccountsUseCase = GetTotpAccountsUseCase(repo),
            refreshTotpCodesUseCase = RefreshTotpCodesUseCase(repo),
            addTotpAccountUseCase = AddTotpAccountUseCase(repo),
            deleteTotpAccountUseCase = DeleteTotpAccountUseCase(repo),
            tickTotpTimerUseCase = TickTotpTimerUseCase(repo),
            securityService = SystemSecurityService(null),
            totpRepository = repo
        )
        vmStore.put("totp-vm", vm)
        try {
            // combine(...).stateIn(WhileSubscribed) only runs while collected.
            backgroundScope.launch { vm.uiState.collect {} }
            testScheduler.runCurrent()

            vm.addAccount(
                issuer = "GitHub",
                accountName = "user",
                secretOrUri = "JBSWY3DPEHPK3PXP"
            )
            // Bounded wait: repo fails fast (no transports), VM maps DeviceError.
            for (i in 0 until 200) {
                testScheduler.runCurrent()
                if (vm.uiState.value.errorResId != null) break
                Thread.sleep(20)
            }
            testScheduler.runCurrent()
            assertEquals(
                R.string.oath_err_no_response_enroll,
                vm.uiState.value.errorResId
            )
            assertNull(vm.uiState.value.errorMessage)
        } finally {
            vmStore.clear()
        }
    }

    // --- F1: Secure Guard success messages resolve via strings.xml --------

    private fun lockedGuardRepo(initial: SecureGuardStatus = SecureGuardStatus(
        state = SecureGuardStateEnum.LOCKED,
        isUnlocked = false
    )): SecureGuardRepository {
        val flow = MutableStateFlow(initial)
        return object : SecureGuardRepository {
            override val statusFlow: StateFlow<SecureGuardStatus> = flow
            override suspend fun getStatus() = Result.success(flow.value)
            override suspend fun provision(pin: String, recoveryCode: String?, policy: SecureGuardPolicy?) =
                Result.success("RC-UNIT")
            override suspend fun unlock(pin: String): Result<SecureGuardStatus> {
                val unlocked = flow.value.copy(
                    state = SecureGuardStateEnum.UNLOCKED,
                    isUnlocked = true,
                    isProvisioned = true,
                    sessionRemainingMs = 300_000L
                )
                flow.value = unlocked
                return Result.success(unlocked)
            }
            override suspend fun lock() = Result.success(Unit)
            override suspend fun changePin(currentPin: String, newPin: String) = Result.success(Unit)
            override suspend fun recover(recoveryCode: String, newPin: String) = Result.success(null)
            override suspend fun updatePolicy(policy: SecureGuardPolicy) = Result.success(policy)
            override suspend fun wipeSelective(scope: Int, confirmationToken: String) = Result.success(false)
            override fun onHardwareDetached() = Unit
        }
    }

    private fun guardVm(repo: SecureGuardRepository) = SecureGuardViewModel(
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
    fun secureGuard_provisionAndUnlock_reportStringRes() = runTest(testDispatcher) {
        // The guard countdown ticker self-terminates (counts remaining ms to
        // zero), so the drains below are finite. The VM is still registered
        // for a scope cancel as hygiene so no ticker outlives the test.
        val vmStore = ViewModelStore()
        val vm = guardVm(lockedGuardRepo())
        vmStore.put("guard-vm", vm)
        try {
            testScheduler.runCurrent()

            vm.provision("1234")
            testScheduler.advanceUntilIdle()
            assertEquals(R.string.guard_provision_success, vm.uiState.value.successResId)

            vm.unlock("1234")
            testScheduler.advanceUntilIdle()
            assertEquals(R.string.guard_unlock_success, vm.uiState.value.successResId)
        } finally {
            vmStore.clear()
        }
    }

    // --- F4: Generate-Key gated on unlocked state --------------------------

    private class CountingVaultRepo : KeyVaultRepository {
        var generateCalls = 0
        override val vaultEntries: StateFlow<List<VaultKeyEntry>> =
            MutableStateFlow(emptyList())
        override suspend fun refreshVault(keyId: String) = Result.success(emptyList<VaultKeyEntry>())
        override suspend fun generateNewAccessKey(
            keyId: String,
            label: String,
            type: AccessKeyType,
            algorithmOrCurve: String,
            extraParam: String
        ): Result<VaultKeyEntry> {
            generateCalls++
            return Result.failure(IllegalStateException("must not reach wire while locked"))
        }
        override suspend fun deleteVaultEntry(keyId: String, slotId: Int) = Result.success(Unit)
        override suspend fun resetHardwareVault(keyId: String) = Result.success("ok")
        override suspend fun runQuickHealthCheck(keyId: String) = Result.success("ok")
        override suspend fun signChallengeOrTransaction(keyId: String, slotId: Int, messageOrTx: String) =
            Result.success("sig")
        override suspend fun exportKeyEnvelopeAegn(keyId: String, slotId: Int) = Result.success("env")
        override suspend fun enrollOrUpdatePivPin(keyId: String, slotCode: String, newPin: String, newPuk: String) =
            Result.success("ok")
        override suspend fun fetchHardwareDiagnostics(keyId: String) = Result.success(
            HardwareDeviceDiagnostics(
                firmwareVersion = FirmwareVersion.appVersion,
                transportChannel = "test",
                totalVaultItems = 0,
                freeSlotsRemaining = FirmwareVersion.MAX_SLOTS,
                fido2SupportedCurves = emptyList(),
                pivSlotsAvailable = emptyList(),
                healthStatusText = "ok",
                isPinConfigured = false,
                isBoundToThisPhone = false
            )
        )
        override suspend fun getTouchRequired(keyId: String, slotId: Int) = true
        override suspend fun setTouchRequired(keyId: String, slotId: Int, requireTouch: Boolean) =
            Result.success(Unit)
    }

    @Test
    fun keyGen_lockedGuard_deniesWithoutReachingWire() = runTest(testDispatcher) {
        val store = EncryptedKeysStore(null)
        val connected = ConnectedKeysRepositoryImpl(store, null, null)
        val counting = CountingVaultRepo()
        val locked = lockedGuardRepo()
        val vm = KeyVaultViewModel(
            getActiveKeyUseCase = GetActiveKeyUseCase(connected),
            getVaultEntriesUseCase = GetVaultEntriesUseCase(counting),
            refreshVaultUseCase = RefreshVaultUseCase(counting),
            generateAccessKeyUseCase = GenerateAccessKeyUseCase(counting),
            deleteVaultEntryUseCase = DeleteVaultEntryUseCase(counting),
            runHealthCheckUseCase = RunHealthCheckUseCase(counting),
            updateKeySecurityTogglesUseCase = UpdateKeySecurityTogglesUseCase(connected),
            simulateButtonSingleTouchUseCase = SimulateButtonSingleTouchUseCase(EmptyPairingRepo()),
            securityService = SystemSecurityService(null),
            secureGuardRepository = locked
        )
        // combine(...).stateIn(WhileSubscribed) only runs while collected.
        backgroundScope.launch { vm.uiState.collect {} }
        testScheduler.runCurrent()

        assertFalse("precondition: guard is locked", vm.uiState.value.isGuardUnlocked)

        vm.createNewKey(
            label = "Should Not Exist",
            type = AccessKeyType.PASSKEY_FIDO
        )
        testScheduler.advanceUntilIdle()

        assertEquals("locked denial must be localized", R.string.vault_err_guard_locked, vm.uiState.value.errorResId)
        assertEquals("locked session must never reach the wire", 0, counting.generateCalls)
    }

    // --- F3: Wi-Fi test always surfaces a result ----------------------------

    @Test
    fun wifiTest_returnsBoundedReportWithNetworksList() {
        val start = System.currentTimeMillis()
        val report = WifiApi.testConnectionDetailed(
            baseUrl = "http://192.168.4.1",
            perAttemptTimeoutMs = 300,
            overallTimeoutMs = 4000L
        )
        val elapsed = System.currentTimeMillis() - start
        assertTrue("probe must stay bounded, took ${elapsed}ms", elapsed < 15000)
        assertNotNull(report.networksSeen)
        if (!report.reachable) {
            assertNull("no endpoint answers without hardware", report.endpoint)
        } else {
            assertNotNull("success must name the answering endpoint", report.endpoint)
        }
        assertTrue("latency must be non-negative", report.latencyMs >= 0)
    }

    // --- F1: strings present in EN + PT, no emojis ---------------------------

    private fun readRes(name: String): String {
        val direct = File("src/main/res/$name/strings.xml")
        if (direct.isFile) return direct.readText(Charsets.UTF_8)
        val alt = File("app/src/main/res/$name/strings.xml")
        assertTrue("strings.xml for $name must exist", alt.isFile)
        return alt.readText(Charsets.UTF_8)
    }

    private fun stringNames(xml: String): Set<String> =
        Regex("""<string name="([^"]+)"""").findAll(xml).map { it.groupValues[1] }.toSet()

    private fun valueFor(xml: String, name: String): String? =
        Regex("""<string name="$name">(.*?)</string>""", RegexOption.DOT_MATCHES_ALL)
            .find(xml)?.groupValues?.get(1)

    @Test
    fun clickThroughStrings_presentInBothLocales_withoutEmoji() {
        val en = readRes("values")
        val pt = readRes("values-pt")
        val enNames = stringNames(en)
        val ptNames = stringNames(pt)

        val required = listOf(
            "onb_err_no_selection",
            "onb_err_connect_failed",
            "onb_err_usb",
            "onb_err_bind_failed",
            "oath_err_no_response_enroll",
            "oath_err_rejected_enroll",
            "vault_err_guard_locked",
            "vault_generate_locked_hint",
            "set_wifi_nets_seen",
            "set_wifi_nets_none",
            "piv_title",
            "piv_desc"
        )
        for (key in required) {
            assertTrue("EN strings.xml must define $key", enNames.contains(key))
            assertTrue("values-pt strings.xml must define $key", ptNames.contains(key))
        }

        // Emoji guard: explicit \u escapes only (no literal non-ASCII glyphs),
        // so the check is immune to source-encoding variance. Two Java-regex
        // traps shaped this form (both verified with standalone repros):
        // 1) adjacent surrogate escapes fold: [\uD83C-\uDBFF\uDC00-\uDFFF]
        //    leaves a literal '-' in the class, matching hyphens.
        // 2) surrogate-range classes never match halves of a real astral
        //    char (matcher works on code points), so astral emoji are
        //    caught with [^\u0000-\uFFFF] instead of a surrogate pair.
        val emoji = Regex("[^\\u0000-\\uFFFF]|[\\u2600-\\u27BF\\u2B00-\\u2BFF\\uFE0F]")
        for (key in required) {
            val enVal = valueFor(en, key).orEmpty()
            val ptVal = valueFor(pt, key).orEmpty()
            assertFalse("EN $key must not contain emoji: $enVal", emoji.containsMatchIn(enVal))
            assertFalse("PT $key must not contain emoji: $ptVal", emoji.containsMatchIn(ptVal))
        }
    }
}
