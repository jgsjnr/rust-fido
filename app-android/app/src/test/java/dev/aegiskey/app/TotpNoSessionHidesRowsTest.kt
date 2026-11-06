package dev.aegiskey.app

import androidx.lifecycle.ViewModelStore
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl
import dev.aegiskey.app.data.repository.TotpRepositoryImpl
import dev.aegiskey.app.data.system.SystemSecurityService
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.TOTP_NO_LIVE_CODE
import dev.aegiskey.app.domain.model.TotpAccountItem
import dev.aegiskey.app.domain.model.hasLiveCode
import dev.aegiskey.app.domain.model.isLiveTotpCode
import dev.aegiskey.app.domain.model.withLiveCodesOnly
import dev.aegiskey.app.domain.repository.TotpRepository
import dev.aegiskey.app.domain.usecase.AddTotpAccountUseCase
import dev.aegiskey.app.domain.usecase.DeleteTotpAccountUseCase
import dev.aegiskey.app.domain.usecase.GetActiveKeyUseCase
import dev.aegiskey.app.domain.usecase.GetTotpAccountsUseCase
import dev.aegiskey.app.domain.usecase.IncrementHotpCounterUseCase
import dev.aegiskey.app.domain.usecase.RefreshTotpCodesUseCase
import dev.aegiskey.app.domain.usecase.TickTotpTimerUseCase
import dev.aegiskey.app.ui.viewmodel.TotpAuthenticatorViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
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
import kotlinx.coroutines.Dispatchers
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Sem sessão viva o TOTP não mostra a linha "------": lista vazia com
 * mensagem neutra ("conecte a chave") em vez de fileira contando.
 * Vale para lista e detalhe (ambos consomem o estado filtrado).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TotpNoSessionHidesRowsTest {

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

    private fun placeholderItem(id: String = "p1") = TotpAccountItem(
        id = id,
        issuer = "GitHub",
        accountName = "octocat",
        currentCode = TOTP_NO_LIVE_CODE,
        formattedCode = "--- ---",
        remainingSeconds = 30,
        requiresTouchToRefresh = true,
        isOnDeviceBacked = false
    )

    private fun liveItem(id: String = "l1") = TotpAccountItem(
        id = id,
        issuer = "GitHub",
        accountName = "octocat",
        currentCode = "123456",
        formattedCode = "123 456",
        remainingSeconds = 30,
        requiresTouchToRefresh = false,
        isOnDeviceBacked = true
    )

    @Test
    fun placeholderMarker_matchesRepositoryConstant() {
        assertEquals(
            "single source of truth for the no-session marker",
            TotpRepositoryImpl.NO_LIVE_CODE,
            TOTP_NO_LIVE_CODE
        )
        assertFalse(isLiveTotpCode(TOTP_NO_LIVE_CODE))
        assertTrue(isLiveTotpCode("123456"))
    }

    @Test
    fun predicate_hidesOnlyPlaceholder() {
        assertFalse(placeholderItem().hasLiveCode)
        assertTrue(liveItem().hasLiveCode)
        // Cached NEED_UP fallback ("654321") is not the no-session marker:
        // only "------" rows are hidden.
        assertTrue(liveItem().copy(currentCode = "654321", isOnDeviceBacked = false).hasLiveCode)
    }

    @Test
    fun liveOnlyFilter_dropsPlaceholders_keepsLive() {
        val mixed = listOf(placeholderItem("p1"), liveItem("l1"), placeholderItem("p2"))
        val visible = mixed.withLiveCodesOnly()
        assertEquals(listOf("l1"), visible.map { it.id })
        assertTrue(placeholderItem().withLivePlaceholderList().isEmpty())
    }

    private fun TotpAccountItem.withLivePlaceholderList() = listOf(this).withLiveCodesOnly()

    private class FakeTotpRepo : TotpRepository {
        private val _accounts = MutableStateFlow<List<TotpAccountItem>>(emptyList())
        override val accounts: StateFlow<List<TotpAccountItem>> = _accounts
        override val remainingSeconds: StateFlow<Int> = MutableStateFlow(30)
        private val _needUpOp = MutableStateFlow<String?>(null)
        override val needUpOp: StateFlow<String?> = _needUpOp
        override fun clearNeedUpOp() {
            _needUpOp.value = null
        }

        fun emit(items: List<TotpAccountItem>) {
            _accounts.value = items
        }

        override suspend fun refreshAccountsAndCodes(keyId: String) =
            Result.success(_accounts.value)

        override suspend fun addAccount(
            keyId: String,
            issuer: String,
            accountName: String,
            secretOrUri: String,
            digits: Int,
            periodSeconds: Int,
            isHotp: Boolean,
            algorithm: String
        ): Result<TotpAccountItem> = throw UnsupportedOperationException("unused")

        override suspend fun deleteAccount(keyId: String, accountId: String) =
            Result.success(Unit)

        override suspend fun incrementHotpCounter(keyId: String, accountId: String) =
            throw UnsupportedOperationException("unused")

        override fun tickTimer(nowEpochSeconds: Long) = Unit
    }

    private suspend fun viewModelHarness(fake: FakeTotpRepo): TotpAuthenticatorViewModel {
        val store = EncryptedKeysStore(null)
        val connected = ConnectedKeysRepositoryImpl(store, null, null)
        connected.addOrUpdateKey(
            ConnectedKeyDevice(
                id = "nosession-totp-1",
                displayName = "AegisKey TOTP",
                hardwareAddressOrId = "usb:totp",
                bindingIdHex = "TOTP-BINDING",
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

    private suspend fun TestScope.settle() {
        repeat(10) {
            runCurrent()
            advanceTimeBy(50)
        }
    }

    @Test
    fun viewModel_noLiveSession_noRowsWithConnectHint() = runTest(testDispatcher) {
        val fake = FakeTotpRepo()
        fake.emit(listOf(placeholderItem("p1"), placeholderItem("p2")))
        val vmStore = ViewModelStore()
        val vm = viewModelHarness(fake)
        vmStore.put("totp-vm", vm)
        try {
            val job = backgroundScope.launch { vm.uiState.collect {} }
            settle()

            val st = vm.uiState.value
            assertTrue("placeholder rows must not render", st.accounts.isEmpty())
            assertTrue("neutral connect-key hint drives the empty state", st.hasNoLiveSession)
            job.cancel()
        } finally {
            vmStore.clear()
        }
    }

    @Test
    fun viewModel_liveSession_rowsShownNormally() = runTest(testDispatcher) {
        val fake = FakeTotpRepo()
        fake.emit(listOf(liveItem("l1"), liveItem("l2")))
        val vmStore = ViewModelStore()
        val vm = viewModelHarness(fake)
        vmStore.put("totp-vm", vm)
        try {
            val job = backgroundScope.launch { vm.uiState.collect {} }
            settle()

            val st = vm.uiState.value
            assertEquals(listOf("l1", "l2"), st.accounts.map { it.id })
            assertFalse(st.hasNoLiveSession)
            job.cancel()
        } finally {
            vmStore.clear()
        }
    }

    @Test
    fun viewModel_mixedList_keepsLiveOnly_noConnectHint() = runTest(testDispatcher) {
        val fake = FakeTotpRepo()
        fake.emit(listOf(placeholderItem("p1"), liveItem("l1")))
        val vmStore = ViewModelStore()
        val vm = viewModelHarness(fake)
        vmStore.put("totp-vm", vm)
        try {
            val job = backgroundScope.launch { vm.uiState.collect {} }
            settle()

            val st = vm.uiState.value
            assertEquals(listOf("l1"), st.accounts.map { it.id })
            assertFalse("partial live session is not a no-session empty", st.hasNoLiveSession)
            job.cancel()
        } finally {
            vmStore.clear()
        }
    }
}
