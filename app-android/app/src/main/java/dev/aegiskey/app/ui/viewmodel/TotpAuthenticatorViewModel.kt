package dev.aegiskey.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import dev.aegiskey.app.ble.DevicePresence.isNeedUpDenial
import dev.aegiskey.app.data.debug.DebugHardwareChipMock
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.system.SystemSecurityService
import dev.aegiskey.app.di.AppContainer
import dev.aegiskey.app.R
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.DeviceError
import dev.aegiskey.app.domain.model.TotpAccountItem
import dev.aegiskey.app.domain.repository.TotpRepository
import dev.aegiskey.app.domain.usecase.AddTotpAccountUseCase
import dev.aegiskey.app.domain.usecase.DeleteTotpAccountUseCase
import dev.aegiskey.app.domain.usecase.GetActiveKeyUseCase
import dev.aegiskey.app.domain.usecase.GetTotpAccountsUseCase
import dev.aegiskey.app.domain.usecase.IncrementHotpCounterUseCase
import dev.aegiskey.app.domain.usecase.RefreshTotpCodesUseCase
import dev.aegiskey.app.domain.usecase.TickTotpTimerUseCase
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

data class TotpAuthenticatorUiState(
    val activeKey: ConnectedKeyDevice? = null,
    val accounts: List<TotpAccountItem> = emptyList(),
    val remainingSeconds: Int = 30,
    val isLoading: Boolean = false,
    val isAddingAccount: Boolean = false,
    val feedbackMessage: String? = null,
    val errorMessage: String? = null,
    /**
     * Click-through F1: typed device failures resolve through `strings.xml`
     * (EN + values-pt). [errorResId] wins when set; [errorMessage] stays as
     * the dynamic fallback (non-device detail) so unit tests can assert the
     * resource without a Context.
     */
    val errorResId: Int? = null,
    val errorArgs: List<String> = emptyList(),
    /**
     * Finding A3: outstanding device presence request. While non-null the
     * TOTP sheet stays open showing the "touch the key" prompt and every
     * visible code must be labeled by its honest source (device vs local).
     */
    val presenceRequest: PresenceRequest? = null
)

private data class TotpInternalState(
    val isLoading: Boolean = false,
    val isAddingAccount: Boolean = false,
    val feedbackMessage: String? = null,
    val errorMessage: String? = null,
    val errorResId: Int? = null,
    val errorArgs: List<String> = emptyList(),
    val pendingAdd: PendingTotpAdd? = null
)

/** Add-account params retained so the user can retry after touching the key. */
private data class PendingTotpAdd(
    val issuer: String,
    val accountName: String,
    val secretOrUri: String,
    val digits: Int,
    val periodSeconds: Int,
    val isHotp: Boolean,
    val algorithm: String
)

class TotpAuthenticatorViewModel(
    private val getActiveKeyUseCase: GetActiveKeyUseCase,
    private val getTotpAccountsUseCase: GetTotpAccountsUseCase,
    private val refreshTotpCodesUseCase: RefreshTotpCodesUseCase,
    private val addTotpAccountUseCase: AddTotpAccountUseCase,
    private val deleteTotpAccountUseCase: DeleteTotpAccountUseCase,
    private val tickTotpTimerUseCase: TickTotpTimerUseCase,
    private val securityService: SystemSecurityService,
    private val incrementHotpCounterUseCase: IncrementHotpCounterUseCase? = null,
    private val keysStore: EncryptedKeysStore? = null,
    private val totpRepository: TotpRepository? = null
) : ViewModel() {

    val activeKey: StateFlow<ConnectedKeyDevice?> = getActiveKeyUseCase()
    val accounts: StateFlow<List<TotpAccountItem>> = getTotpAccountsUseCase()

    private val needUpOp: StateFlow<String?> =
        totpRepository?.needUpOp ?: MutableStateFlow(null)

    private val _remainingSeconds = MutableStateFlow(30)
    val remainingSeconds: StateFlow<Int> = _remainingSeconds.asStateFlow()

    private val _internalState = MutableStateFlow(TotpInternalState())

    val uiState: StateFlow<TotpAuthenticatorUiState> = combine(
        activeKey,
        accounts,
        _remainingSeconds,
        _internalState,
        needUpOp
    ) { key, accs, secs, internal, needUp ->
        TotpAuthenticatorUiState(
            activeKey = key,
            accounts = accs,
            remainingSeconds = secs,
            isLoading = internal.isLoading,
            isAddingAccount = internal.isAddingAccount,
            feedbackMessage = internal.feedbackMessage,
            errorMessage = internal.errorMessage,
            errorResId = internal.errorResId,
            errorArgs = internal.errorArgs,
            presenceRequest = needUp?.let { PresenceRequest(op = it) }
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = TotpAuthenticatorUiState(
            activeKey = activeKey.value,
            accounts = accounts.value,
            remainingSeconds = _remainingSeconds.value
        )
    )

    init {
        // Ticker de 1s para contagem regressiva viva e suave no anel de 30s
        viewModelScope.launch {
            while (isActive) {
                val nowSecs = System.currentTimeMillis() / 1000L
                val rem = 30 - (nowSecs % 30).toInt()
                _remainingSeconds.value = if (rem == 0) 30 else rem
                tickTotpTimerUseCase(nowSecs)
                delay(1000)
            }
        }

        // Carrega os códigos da chave ativa atual
        val initialKey = activeKey.value
        if (initialKey != null) {
            refreshCodes()
        }
    }

    fun clearFeedback() {
        _internalState.update { it.copy(feedbackMessage = null, errorMessage = null, errorResId = null, errorArgs = emptyList()) }
    }

    /**
     * Click-through F1: splits a failure into a `strings.xml` resource when
     * the repository reports a typed [DeviceError], else an EN fallback
     * template so no hardcoded PT ever reaches the snackbar.
     */
    private fun localizedFailure(err: Throwable, fallbackResId: Int): Triple<String?, Int?, List<String>> {
        val device = generateSequence<Throwable>(err) { (it as? Exception)?.cause }.filterIsInstance<DeviceError>().firstOrNull()
        if (device != null) {
            val args = listOfNotNull(device.message?.take(120)).filter { it.isNotBlank() }
            return Triple(null, device.resId, args)
        }
        val detail = err.localizedMessage?.take(120)?.trim().orEmpty()
        return if (detail.isEmpty()) Triple(null, fallbackResId, listOf("")) else Triple(null, fallbackResId, listOf(detail))
    }

    fun refreshCodes() {
        val currentKey = activeKey.value ?: return
        viewModelScope.launch {
            _internalState.update { it.copy(isLoading = true) }
            try {
                val result = refreshTotpCodesUseCase(currentKey.id)
                result.onSuccess {
                    // A successful device read supersedes any stale prompt.
                    totpRepository?.clearNeedUpOp()
                }.onFailure { err ->
                    // Finding A3: NEED_UP is already exposed as presenceRequest
                    // via needUpOp — no error banner, no silent list.
                    if (!err.isNeedUpDenial()) {
                        _internalState.update {
                            it.copy(errorMessage = "Falha ao atualizar códigos: ${err.localizedMessage ?: "Verifique a chave física."}")
                        }
                    }
                }
            } finally {
                _internalState.update { it.copy(isLoading = false) }
            }
        }
    }

    /** Retries the denied op after the user touched the key. */
    fun retryAfterPresence() {
        val pending = _internalState.value.pendingAdd
        if (pending != null) {
            addAccount(
                issuer = pending.issuer,
                accountName = pending.accountName,
                secretOrUri = pending.secretOrUri,
                digits = pending.digits,
                periodSeconds = pending.periodSeconds,
                isHotp = pending.isHotp,
                algorithm = pending.algorithm
            )
        } else {
            refreshCodes()
        }
    }

    /** Dismisses the presence prompt (user cancelled; pending add dropped). */
    fun dismissPresence() {
        _internalState.update { it.copy(pendingAdd = null) }
        totpRepository?.clearNeedUpOp()
    }

    fun addAccount(
        issuer: String,
        accountName: String,
        secretOrUri: String,
        digits: Int = 6,
        periodSeconds: Int = 30,
        isHotp: Boolean = false,
        algorithm: String = "SHA1"
    ) {
        val currentKey = activeKey.value
        if (currentKey == null) {
            _internalState.update { it.copy(errorMessage = null, errorResId = R.string.oath_err_no_key, errorArgs = emptyList()) }
            return
        }

        viewModelScope.launch {
            _internalState.update {
                it.copy(
                    isAddingAccount = true,
                    pendingAdd = PendingTotpAdd(
                        issuer = issuer.trim(),
                        accountName = accountName.trim(),
                        secretOrUri = secretOrUri.trim(),
                        digits = digits,
                        periodSeconds = periodSeconds,
                        isHotp = isHotp,
                        algorithm = algorithm
                    )
                )
            }
            try {
                val result = addTotpAccountUseCase(
                    keyId = currentKey.id,
                    issuer = issuer.trim(),
                    accountName = accountName.trim(),
                    secretOrUri = secretOrUri.trim(),
                    digits = digits,
                    periodSeconds = periodSeconds,
                    isHotp = isHotp,
                    algorithm = algorithm
                )
                result.onSuccess { item ->
                    val typeDesc = if (isHotp) "HOTP (Contador)" else "TOTP (${periodSeconds}s)"
                    _internalState.update {
                        it.copy(
                            feedbackMessage = "Código $typeDesc para \"${item.issuer.ifBlank { item.accountName }}\" salvo na sua chave!",
                            pendingAdd = null
                        )
                    }
                    totpRepository?.clearNeedUpOp()
                }.onFailure { err ->
                    // Finding A3: NEED_UP keeps the add sheet open with the
                    // presence prompt (pending params retained for retry).
                    if (err.isNeedUpDenial()) {
                        _internalState.update { it.copy(isAddingAccount = false) }
                    } else {
                        val (_, resId, args) = localizedFailure(err, R.string.oath_err_enroll_failed)
                        _internalState.update {
                            it.copy(
                                errorMessage = null,
                                errorResId = resId,
                                errorArgs = args,
                                pendingAdd = null
                            )
                        }
                    }
                }
            } finally {
                _internalState.update { it.copy(isAddingAccount = false) }
            }
        }
    }

    fun incrementHotp(accountId: String) {
        val currentKey = activeKey.value ?: return
        val incrementUseCase = incrementHotpCounterUseCase ?: return
        viewModelScope.launch {
            _internalState.update { it.copy(isLoading = true) }
            try {
                val result = incrementUseCase(currentKey.id, accountId)
                result.onSuccess { item ->
                    _internalState.update {
                        it.copy(feedbackMessage = "Novo código HOTP #${item.counter} gerado no chip!")
                    }
                    totpRepository?.clearNeedUpOp()
                }.onFailure { err ->
                    // Finding A3: presence denial is shown as a prompt, not an error.
                    if (!err.isNeedUpDenial()) {
                        _internalState.update {
                            it.copy(errorMessage = "Falha ao gerar próximo código HOTP: ${err.localizedMessage}")
                        }
                    }
                }
            } finally {
                _internalState.update { it.copy(isLoading = false) }
            }
        }
    }

    fun deleteAccount(id: String) {
        val currentKey = activeKey.value ?: return
        viewModelScope.launch {
            _internalState.update { it.copy(isLoading = true) }
            try {
                val result = deleteTotpAccountUseCase(currentKey.id, id)
                result.onSuccess {
                    _internalState.update { it.copy(feedbackMessage = "Código temporário removido da sua chave.") }
                    totpRepository?.clearNeedUpOp()
                }.onFailure { err ->
                    // Finding A3: presence denial is shown as a prompt, not an error.
                    if (!err.isNeedUpDenial()) {
                        val (_, resId, args) = localizedFailure(err, R.string.oath_err_delete_failed)
                        _internalState.update {
                            it.copy(errorMessage = null, errorResId = resId, errorArgs = args)
                        }
                    }
                }
            } finally {
                _internalState.update { it.copy(isLoading = false) }
            }
        }
    }

    fun copyCodeToClipboard(code: String) {
        val cleanCode = code.filter { it.isDigit() }
        val copied = securityService.copySensitiveCode("Código de Verificação", cleanCode)
        if (copied) {
            _internalState.update { it.copy(feedbackMessage = "Código $cleanCode copiado com segurança!") }
        } else {
            _internalState.update { it.copy(errorMessage = "Não foi possível copiar para a área de transferência.") }
        }
    }

    fun injectExtraSampleForDebug() {
        if (!DebugHardwareChipMock.IS_MOCK_ENABLED) return
        val currentKey = activeKey.value ?: return
        if (keysStore != null) {
            DebugHardwareChipMock.injectExtraSample(currentKey.id, keysStore)
            refreshCodes()
            _internalState.update { it.copy(feedbackMessage = "Novas contas do Chip Mock sincronizadas!") }
        }
    }

    companion object {
        fun provideFactory(container: AppContainer): ViewModelProvider.Factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return TotpAuthenticatorViewModel(
                        getActiveKeyUseCase = container.getActiveKeyUseCase,
                        getTotpAccountsUseCase = container.getTotpAccountsUseCase,
                        refreshTotpCodesUseCase = container.refreshTotpCodesUseCase,
                        addTotpAccountUseCase = container.addTotpAccountUseCase,
                        deleteTotpAccountUseCase = container.deleteTotpAccountUseCase,
                        tickTotpTimerUseCase = container.tickTotpTimerUseCase,
                        securityService = container.securityService,
                        incrementHotpCounterUseCase = container.incrementHotpCounterUseCase,
                        keysStore = container.keysStore,
                        totpRepository = container.totpRepository
                    ) as T
                }
            }
    }
}
