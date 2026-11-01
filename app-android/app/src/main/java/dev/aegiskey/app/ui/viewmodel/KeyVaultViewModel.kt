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
import dev.aegiskey.app.domain.model.HardwareDeviceDiagnostics
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.domain.usecase.DeleteVaultEntryUseCase
import dev.aegiskey.app.domain.usecase.EnrollOrUpdatePivPinUseCase
import dev.aegiskey.app.domain.usecase.ExportKeyEnvelopeAegnUseCase
import dev.aegiskey.app.domain.usecase.FetchHardwareDiagnosticsUseCase
import dev.aegiskey.app.domain.usecase.GenerateAccessKeyUseCase
import dev.aegiskey.app.domain.usecase.GetActiveKeyUseCase
import dev.aegiskey.app.domain.usecase.GetVaultEntriesUseCase
import dev.aegiskey.app.domain.usecase.RefreshVaultUseCase
import dev.aegiskey.app.domain.usecase.ResetHardwareVaultUseCase
import dev.aegiskey.app.domain.usecase.RunHealthCheckUseCase
import dev.aegiskey.app.domain.usecase.SignChallengeOrTransactionUseCase
import dev.aegiskey.app.domain.usecase.SimulateButtonSingleTouchUseCase
import dev.aegiskey.app.domain.usecase.UpdateKeySecurityTogglesUseCase
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class KeyVaultUiState(
    val activeKey: ConnectedKeyDevice? = null,
    val entries: List<VaultKeyEntry> = emptyList(),
    val selectedEntry: VaultKeyEntry? = null,
    val selectedCategoryFilter: String = "ALL",
    val lastSignatureResult: String? = null,
    val lastExportedEnvelope: String? = null,
    val hardwareDiagnostics: HardwareDeviceDiagnostics? = null,
    val isActionLoading: Boolean = false,
    val isLoading: Boolean = false,
    val isGeneratingKey: Boolean = false,
    val healthCheckStatus: String? = null,
    val userMessage: String? = null,
    val errorMessage: String? = null
)

private data class KeyVaultInternalState(
    val selectedSlotId: Int? = null,
    val selectedCategoryFilter: String = "ALL",
    val lastSignatureResult: String? = null,
    val lastExportedEnvelope: String? = null,
    val hardwareDiagnostics: HardwareDeviceDiagnostics? = null,
    val isActionLoading: Boolean = false,
    val isLoading: Boolean = false,
    val isGeneratingKey: Boolean = false,
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
    private val signChallengeOrTransactionUseCase: SignChallengeOrTransactionUseCase? = null,
    private val exportKeyEnvelopeAegnUseCase: ExportKeyEnvelopeAegnUseCase? = null,
    private val enrollOrUpdatePivPinUseCase: EnrollOrUpdatePivPinUseCase? = null,
    private val fetchHardwareDiagnosticsUseCase: FetchHardwareDiagnosticsUseCase? = null,
    private val resetHardwareVaultUseCase: ResetHardwareVaultUseCase? = null,
    private val keysStore: EncryptedKeysStore? = null,
) : ViewModel() {

    val activeKey: StateFlow<ConnectedKeyDevice?> = getActiveKeyUseCase()
    val vaultEntries: StateFlow<List<VaultKeyEntry>> = getVaultEntriesUseCase()

    private val _internalState = MutableStateFlow(KeyVaultInternalState())

    val uiState: StateFlow<KeyVaultUiState> = combine(
        activeKey,
        vaultEntries,
        _internalState
    ) { key, entries, internal ->
        val selected = entries.find { it.slotId == internal.selectedSlotId }
        KeyVaultUiState(
            activeKey = key,
            entries = entries,
            selectedEntry = selected,
            selectedCategoryFilter = internal.selectedCategoryFilter,
            lastSignatureResult = internal.lastSignatureResult,
            lastExportedEnvelope = internal.lastExportedEnvelope,
            hardwareDiagnostics = internal.hardwareDiagnostics,
            isActionLoading = internal.isActionLoading,
            isLoading = internal.isLoading,
            isGeneratingKey = internal.isLoading,
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
            loadHardwareDiagnostics()
        }
    }

    fun clearMessages() {
        _internalState.update { it.copy(userMessage = null, errorMessage = null) }
    }

    fun openKeyDetail(slotId: Int) {
        _internalState.update {
            it.copy(
                selectedSlotId = slotId,
                lastSignatureResult = null,
                lastExportedEnvelope = null
            )
        }
    }

    fun closeKeyDetail() {
        _internalState.update {
            it.copy(
                selectedSlotId = null,
                lastSignatureResult = null,
                lastExportedEnvelope = null
            )
        }
    }

    fun setCategoryFilter(category: String) {
        _internalState.update { it.copy(selectedCategoryFilter = category) }
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

    fun createNewKey(
        label: String,
        type: AccessKeyType,
        algorithmOrCurve: String = "ES256 (P-256)",
        extraParam: String = ""
    ) {
        val currentKey = activeKey.value
        if (currentKey == null) {
            _internalState.update { it.copy(errorMessage = "Nenhuma chave física conectada no momento.") }
            return
        }

        viewModelScope.launch {
            _internalState.update { it.copy(isLoading = true) }
            try {
                val result = generateAccessKeyUseCase(
                    keyId = currentKey.id,
                    label = label,
                    type = type,
                    algorithmOrCurve = algorithmOrCurve,
                    extraParam = extraParam
                )
                result.onSuccess { entry ->
                    _internalState.update {
                        it.copy(userMessage = "Chave \"${entry.label}\" gerada e protegida com sucesso no cofre!")
                    }
                    refreshVault()
                    loadHardwareDiagnostics()
                }.onFailure { err ->
                    _internalState.update {
                        it.copy(errorMessage = "Não foi possível gerar a chave: ${err.localizedMessage ?: "Verifique a chave física."}")
                    }
                }
            } finally {
                _internalState.update { it.copy(isLoading = false) }
            }
        }
    }

    fun generateKey(
        label: String,
        type: AccessKeyType,
        algorithmOrCurve: String = "ES256 (P-256)",
        extraParam: String = ""
    ) {
        createNewKey(label = label, type = type, algorithmOrCurve = algorithmOrCurve, extraParam = extraParam)
    }

    fun deleteKey(slotId: Int) {
        deleteEntry(slotId)
    }

    fun injectMockKeysForDebug() {
        injectExtraSampleForDebug()
    }

    fun deleteEntry(slotId: Int) {
        val currentKey = activeKey.value ?: return
        viewModelScope.launch {
            _internalState.update { it.copy(isLoading = true) }
            try {
                val result = deleteVaultEntryUseCase(currentKey.id, slotId)
                result.onSuccess {
                    _internalState.update {
                        it.copy(
                            userMessage = "Chave removida do chip com segurança (0x23).",
                            selectedSlotId = if (it.selectedSlotId == slotId) null else it.selectedSlotId
                        )
                    }
                    refreshVault()
                    loadHardwareDiagnostics()
                }.onFailure { err ->
                    _internalState.update { it.copy(errorMessage = "Não foi possível remover: ${err.localizedMessage}") }
                }
            } finally {
                _internalState.update { it.copy(isLoading = false) }
            }
        }
    }

    fun deleteKeyAndCloseDetail(slotId: Int) {
        deleteEntry(slotId)
        closeKeyDetail()
    }

    fun signWithSelectedKey(slotId: Int, messageOrTx: String) {
        val currentKey = activeKey.value ?: return
        val signUseCase = signChallengeOrTransactionUseCase ?: return
        viewModelScope.launch {
            _internalState.update { it.copy(isActionLoading = true) }
            try {
                val result = signUseCase(currentKey.id, slotId, messageOrTx)
                result.onSuccess { signature ->
                    _internalState.update {
                        it.copy(
                            lastSignatureResult = signature,
                            userMessage = "Assinatura gerada pelo chip com sucesso!"
                        )
                    }
                }.onFailure { err ->
                    _internalState.update {
                        it.copy(errorMessage = "Falha ao assinar no chip: ${err.localizedMessage}")
                    }
                }
            } finally {
                _internalState.update { it.copy(isActionLoading = false) }
            }
        }
    }

    fun exportSelectedKeyEnvelope(slotId: Int) {
        val currentKey = activeKey.value ?: return
        val exportUseCase = exportKeyEnvelopeAegnUseCase ?: return
        viewModelScope.launch {
            _internalState.update { it.copy(isActionLoading = true) }
            try {
                val result = exportUseCase(currentKey.id, slotId)
                result.onSuccess { envelope ->
                    _internalState.update {
                        it.copy(
                            lastExportedEnvelope = envelope,
                            userMessage = "Envelope criptografado AEGN gerado com sucesso!"
                        )
                    }
                }.onFailure { err ->
                    _internalState.update {
                        it.copy(errorMessage = "Falha ao exportar envelope AEGN: ${err.localizedMessage}")
                    }
                }
            } finally {
                _internalState.update { it.copy(isActionLoading = false) }
            }
        }
    }

    fun enrollPivPin(slotCode: String, newPin: String, newPuk: String) {
        val currentKey = activeKey.value ?: return
        val pivUseCase = enrollOrUpdatePivPinUseCase ?: return
        viewModelScope.launch {
            _internalState.update { it.copy(isActionLoading = true) }
            try {
                val result = pivUseCase(currentKey.id, slotCode, newPin, newPuk)
                result.onSuccess { msg ->
                    _internalState.update {
                        it.copy(userMessage = msg.ifBlank { "PIN e PUK gravados no smartcard PIV com sucesso!" })
                    }
                }.onFailure { err ->
                    _internalState.update {
                        it.copy(errorMessage = "Falha ao gravar PIN/PUK PIV: ${err.localizedMessage}")
                    }
                }
            } finally {
                _internalState.update { it.copy(isActionLoading = false) }
            }
        }
    }

    fun resetHardwareVault() {
        val currentKey = activeKey.value ?: return
        val resetUseCase = resetHardwareVaultUseCase ?: return
        viewModelScope.launch {
            _internalState.update { it.copy(isActionLoading = true) }
            try {
                val result = resetUseCase(currentKey.id)
                result.onSuccess { msg ->
                    _internalState.update {
                        it.copy(
                            selectedSlotId = null,
                            userMessage = "Reset concluído com sucesso: $msg"
                        )
                    }
                    refreshVault()
                    loadHardwareDiagnostics()
                }.onFailure { err ->
                    _internalState.update {
                        it.copy(errorMessage = "Erro ao resetar hardware: ${err.localizedMessage}")
                    }
                }
            } finally {
                _internalState.update { it.copy(isActionLoading = false) }
            }
        }
    }

    fun loadHardwareDiagnostics() {
        val currentKey = activeKey.value ?: return
        val diagUseCase = fetchHardwareDiagnosticsUseCase ?: return
        viewModelScope.launch {
            try {
                val result = diagUseCase(currentKey.id)
                result.onSuccess { diag ->
                    _internalState.update { it.copy(hardwareDiagnostics = diag) }
                }
            } catch (_: Exception) {}
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
                    loadHardwareDiagnostics()
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
            loadHardwareDiagnostics()
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
                        signChallengeOrTransactionUseCase = container.signChallengeOrTransactionUseCase,
                        exportKeyEnvelopeAegnUseCase = container.exportKeyEnvelopeAegnUseCase,
                        enrollOrUpdatePivPinUseCase = container.enrollOrUpdatePivPinUseCase,
                        fetchHardwareDiagnosticsUseCase = container.fetchHardwareDiagnosticsUseCase,
                        resetHardwareVaultUseCase = container.resetHardwareVaultUseCase,
                        keysStore = container.keysStore,
                    ) as T
                }
            }
    }
}
