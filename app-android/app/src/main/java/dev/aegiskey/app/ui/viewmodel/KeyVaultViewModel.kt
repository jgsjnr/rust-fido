package dev.aegiskey.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import dev.aegiskey.app.data.debug.DebugHardwareChipMock
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.system.SystemSecurityService
import dev.aegiskey.app.di.AppContainer
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.domain.usecase.DeleteVaultEntryUseCase
import dev.aegiskey.app.domain.usecase.GenerateAccessKeyUseCase
import dev.aegiskey.app.domain.usecase.GetActiveKeyUseCase
import dev.aegiskey.app.domain.usecase.GetVaultEntriesUseCase
import dev.aegiskey.app.domain.usecase.RefreshVaultUseCase
import dev.aegiskey.app.domain.usecase.RunHealthCheckUseCase
import dev.aegiskey.app.domain.usecase.SimulateButtonSingleTouchUseCase
import dev.aegiskey.app.domain.usecase.UpdateKeySecurityTogglesUseCase
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class KeyVaultUiState(
    val activeKey: ConnectedKeyDevice? = null,
    val entries: List<VaultKeyEntry> = emptyList(),
    val isLoading: Boolean = false,
    val healthCheckStatus: String? = null,
    val userMessage: String? = null,
    val errorMessage: String? = null
)

private data class KeyVaultInternalState(
    val isLoading: Boolean = false,
    val healthCheckStatus: String? = null,
    val userMessage: String? = null,
    val errorMessage: String? = null
)

class KeyVaultViewModel(
    private val getActiveKeyUseCase: GetActiveKeyUseCase,
    private val getVaultEntriesUseCase: GetVaultEntriesUseCase,
    private val refreshVaultUseCase: RefreshVaultUseCase,
    private val generateAccessKeyUseCase: GenerateAccessKeyUseCase,
    private val deleteVaultEntryUseCase: DeleteVaultEntryUseCase,
    private val runHealthCheckUseCase: RunHealthCheckUseCase,
    private val updateKeySecurityTogglesUseCase: UpdateKeySecurityTogglesUseCase,
    private val simulateButtonSingleTouchUseCase: SimulateButtonSingleTouchUseCase,
    private val securityService: SystemSecurityService,
    private val keysStore: EncryptedKeysStore? = null,
) : ViewModel() {

    val activeKey: StateFlow<ConnectedKeyDevice?> = getActiveKeyUseCase()
    val vaultEntries: StateFlow<List<VaultKeyEntry>> = getVaultEntriesUseCase()

    private val _internalState = MutableStateFlow(KeyVaultInternalState())

    val isLoading: StateFlow<Boolean> = MutableStateFlow(false)

    val uiState: StateFlow<KeyVaultUiState> = combine(
        activeKey,
        vaultEntries,
        _internalState
    ) { key, entries, internal ->
        KeyVaultUiState(
            activeKey = key,
            entries = entries,
            isLoading = internal.isLoading,
            healthCheckStatus = internal.healthCheckStatus,
            userMessage = internal.userMessage,
            errorMessage = internal.errorMessage
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = KeyVaultUiState(
            activeKey = activeKey.value,
            entries = vaultEntries.value
        )
    )

    init {
        val currentKey = activeKey.value
        if (currentKey != null) {
            refreshVault()
        }
    }

    fun clearMessages() {
        _internalState.update { it.copy(userMessage = null, errorMessage = null) }
    }

    fun refreshVault() {
        val currentKey = activeKey.value ?: return
        viewModelScope.launch {
            _internalState.update { it.copy(isLoading = true) }
            try {
                refreshVaultUseCase(currentKey.id)
            } finally {
                _internalState.update { it.copy(isLoading = false) }
            }
        }
    }

    fun generateKey(label: String, type: AccessKeyType) {
        val currentKey = activeKey.value
        if (currentKey == null) {
            _internalState.update { it.copy(errorMessage = "Nenhuma chave de segurança conectada no momento.") }
            return
        }

        viewModelScope.launch {
            _internalState.update { it.copy(isLoading = true) }
            try {
                val result = generateAccessKeyUseCase(currentKey.id, label, type)
                result.onSuccess { entry ->
                    _internalState.update {
                        it.copy(userMessage = "Chave \"${entry.label}\" gerada e protegida com sucesso no cofre!")
                    }
                }.onFailure { err ->
                    _internalState.update {
                        it.copy(errorMessage = "Não foi possível gerar a chave: ${err.localizedMessage ?: "Verifique se a chave está conectada."}")
                    }
                }
            } finally {
                _internalState.update { it.copy(isLoading = false) }
            }
        }
    }

    fun deleteEntry(slotId: Int) {
        val currentKey = activeKey.value ?: return
        viewModelScope.launch {
            _internalState.update { it.copy(isLoading = true) }
            try {
                val result = deleteVaultEntryUseCase(currentKey.id, slotId)
                result.onSuccess {
                    _internalState.update { it.copy(userMessage = "Chave removida do cofre com segurança.") }
                }.onFailure { err ->
                    _internalState.update { it.copy(errorMessage = "Não foi possível remover: ${err.localizedMessage}") }
                }
            } finally {
                _internalState.update { it.copy(isLoading = false) }
            }
        }
    }

    fun toggleLockOnWalkAway(enabled: Boolean) {
        val currentKey = activeKey.value ?: return
        val updated = currentKey.toggles.copy(lockOnWalkAway = enabled)
        viewModelScope.launch {
            updateKeySecurityTogglesUseCase(currentKey.id, updated)
        }
    }

    fun toggleRequireBiometrics(enabled: Boolean) {
        val currentKey = activeKey.value ?: return
        val updated = currentKey.toggles.copy(requireBiometricsOnOpen = enabled)
        viewModelScope.launch {
            updateKeySecurityTogglesUseCase(currentKey.id, updated)
        }
    }

    fun toggleRequireTouchForCode(enabled: Boolean) {
        val currentKey = activeKey.value ?: return
        val updated = currentKey.toggles.copy(requireTouchForEveryCode = enabled)
        viewModelScope.launch {
            updateKeySecurityTogglesUseCase(currentKey.id, updated)
        }
    }

    fun runHealthCheck() {
        val currentKey = activeKey.value
        if (currentKey == null) {
            _internalState.update { it.copy(healthCheckStatus = "Nenhuma chave física ativa para diagnóstico.") }
            return
        }
        viewModelScope.launch {
            _internalState.update { it.copy(isLoading = true) }
            try {
                val result = runHealthCheckUseCase(currentKey.id)
                result.onSuccess { status ->
                    _internalState.update {
                        it.copy(
                            healthCheckStatus = status,
                            userMessage = "Diagnóstico concluído: hardware funcionando perfeitamente!"
                        )
                    }
                }.onFailure { err ->
                    _internalState.update {
                        it.copy(healthCheckStatus = "Diagnóstico indisponível: ${err.localizedMessage}")
                    }
                }
            } finally {
                _internalState.update { it.copy(isLoading = false) }
            }
        }
    }

    fun simulateTouchIfNeeded() {
        if (!DebugHardwareChipMock.IS_MOCK_ENABLED) return
        val currentKey = activeKey.value
        if (currentKey?.transportType == ConnectionTransportType.SIMULATOR) {
            viewModelScope.launch {
                simulateButtonSingleTouchUseCase()
                _internalState.update { it.copy(userMessage = "Toque físico simulado com sucesso na AegisKey virtual.") }
            }
        }
    }

    fun copyIdentifier(identifier: String) {
        val copied = securityService.copySensitiveCode("Chave AegisKey", identifier)
        if (copied) {
            _internalState.update { it.copy(userMessage = "Copiado para a área de transferência!") }
        }
    }

    fun injectExtraSampleForDebug() {
        if (!DebugHardwareChipMock.IS_MOCK_ENABLED) return
        val currentKey = activeKey.value ?: return
        if (keysStore != null) {
            DebugHardwareChipMock.injectExtraSample(currentKey.id, keysStore)
            refreshVault()
            _internalState.update { it.copy(userMessage = "Nova Passkey e conta TOTP injetadas pelo Chip Mock!") }
        }
    }

    companion object {
        fun provideFactory(container: AppContainer): ViewModelProvider.Factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return KeyVaultViewModel(
                        getActiveKeyUseCase = container.getActiveKeyUseCase,
                        getVaultEntriesUseCase = container.getVaultEntriesUseCase,
                        refreshVaultUseCase = container.refreshVaultUseCase,
                        generateAccessKeyUseCase = container.generateAccessKeyUseCase,
                        deleteVaultEntryUseCase = container.deleteVaultEntryUseCase,
                        runHealthCheckUseCase = container.runHealthCheckUseCase,
                        updateKeySecurityTogglesUseCase = container.updateKeySecurityTogglesUseCase,
                        simulateButtonSingleTouchUseCase = container.simulateButtonSingleTouchUseCase,
                        securityService = container.securityService,
                        keysStore = container.keysStore,
                    ) as T
                }
            }
    }
}
