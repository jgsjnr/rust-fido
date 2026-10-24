package dev.aegiskey.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import dev.aegiskey.app.data.debug.DebugHardwareChipMock
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.system.SystemSecurityService
import dev.aegiskey.app.di.AppContainer
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.TotpAccountItem
import dev.aegiskey.app.domain.usecase.AddTotpAccountUseCase
import dev.aegiskey.app.domain.usecase.DeleteTotpAccountUseCase
import dev.aegiskey.app.domain.usecase.GetActiveKeyUseCase
import dev.aegiskey.app.domain.usecase.GetTotpAccountsUseCase
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
    val errorMessage: String? = null
)

private data class TotpInternalState(
    val isLoading: Boolean = false,
    val isAddingAccount: Boolean = false,
    val feedbackMessage: String? = null,
    val errorMessage: String? = null
)

class TotpAuthenticatorViewModel(
    private val getActiveKeyUseCase: GetActiveKeyUseCase,
    private val getTotpAccountsUseCase: GetTotpAccountsUseCase,
    private val refreshTotpCodesUseCase: RefreshTotpCodesUseCase,
    private val addTotpAccountUseCase: AddTotpAccountUseCase,
    private val deleteTotpAccountUseCase: DeleteTotpAccountUseCase,
    private val tickTotpTimerUseCase: TickTotpTimerUseCase,
    private val securityService: SystemSecurityService,
    private val keysStore: EncryptedKeysStore? = null
) : ViewModel() {

    val activeKey: StateFlow<ConnectedKeyDevice?> = getActiveKeyUseCase()
    val accounts: StateFlow<List<TotpAccountItem>> = getTotpAccountsUseCase()

    private val _remainingSeconds = MutableStateFlow(30)
    val remainingSeconds: StateFlow<Int> = _remainingSeconds.asStateFlow()

    private val _internalState = MutableStateFlow(TotpInternalState())

    val uiState: StateFlow<TotpAuthenticatorUiState> = combine(
        activeKey,
        accounts,
        _remainingSeconds,
        _internalState
    ) { key, accs, secs, internal ->
        TotpAuthenticatorUiState(
            activeKey = key,
            accounts = accs,
            remainingSeconds = secs,
            isLoading = internal.isLoading,
            isAddingAccount = internal.isAddingAccount,
            feedbackMessage = internal.feedbackMessage,
            errorMessage = internal.errorMessage
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
        _internalState.update { it.copy(feedbackMessage = null, errorMessage = null) }
    }

    fun refreshCodes() {
        val currentKey = activeKey.value ?: return
        viewModelScope.launch {
            _internalState.update { it.copy(isLoading = true) }
            try {
                refreshTotpCodesUseCase(currentKey.id)
            } finally {
                _internalState.update { it.copy(isLoading = false) }
            }
        }
    }

    fun addAccount(issuer: String, accountName: String, secretOrUri: String) {
        val currentKey = activeKey.value
        if (currentKey == null) {
            _internalState.update { it.copy(errorMessage = "Conecte sua AegisKey antes de adicionar um código.") }
            return
        }

        viewModelScope.launch {
            _internalState.update { it.copy(isAddingAccount = true) }
            try {
                val result = addTotpAccountUseCase(
                    keyId = currentKey.id,
                    issuer = issuer.trim(),
                    accountName = accountName.trim(),
                    secretOrUri = secretOrUri.trim(),
                    digits = 6
                )
                result.onSuccess { item ->
                    _internalState.update {
                        it.copy(feedbackMessage = "Código para \"${item.issuer.ifBlank { item.accountName }}\" salvo na sua chave!")
                    }
                }.onFailure { err ->
                    _internalState.update {
                        it.copy(errorMessage = "Não foi possível cadastrar o código: ${err.localizedMessage ?: "Verifique a chave secreta informada."}")
                    }
                }
            } finally {
                _internalState.update { it.copy(isAddingAccount = false) }
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
                }.onFailure { err ->
                    _internalState.update { it.copy(errorMessage = "Falha ao remover: ${err.localizedMessage}") }
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
                        keysStore = container.keysStore
                    ) as T
                }
            }
    }
}
