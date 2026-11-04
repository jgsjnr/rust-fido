package dev.aegiskey.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import dev.aegiskey.app.ble.DevicePresence.isNeedUpDenial
import dev.aegiskey.app.data.debug.DebugHardwareChipMock
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl
import dev.aegiskey.app.data.system.SystemSecurityService
import dev.aegiskey.app.di.AppContainer
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.FirmwareVersion
import dev.aegiskey.app.domain.model.HardwareDeviceDiagnostics
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import dev.aegiskey.app.domain.repository.SecureGuardRepository
import dev.aegiskey.app.domain.usecase.DeleteVaultEntryUseCase
import dev.aegiskey.app.domain.usecase.EnrollOrUpdatePivPinUseCase
import dev.aegiskey.app.domain.usecase.ExportKeyEnvelopeAegnUseCase
import dev.aegiskey.app.domain.usecase.FetchHardwareDiagnosticsUseCase
import dev.aegiskey.app.domain.usecase.GenerateAccessKeyUseCase
import dev.aegiskey.app.domain.usecase.GetActiveKeyUseCase
import dev.aegiskey.app.domain.usecase.GetKeyTouchRequiredUseCase
import dev.aegiskey.app.domain.usecase.GetVaultEntriesUseCase
import dev.aegiskey.app.domain.usecase.RefreshVaultUseCase
import dev.aegiskey.app.domain.usecase.ResetHardwareVaultUseCase
import dev.aegiskey.app.domain.usecase.RunHealthCheckUseCase
import dev.aegiskey.app.domain.usecase.SetKeyTouchRequiredUseCase
import dev.aegiskey.app.domain.usecase.SignChallengeOrTransactionUseCase
import dev.aegiskey.app.domain.usecase.SimulateButtonSingleTouchUseCase
import dev.aegiskey.app.domain.usecase.UpdateKeySecurityTogglesUseCase
import dev.aegiskey.app.touchpolicy.TouchPolicy
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
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
    val errorMessage: String? = null,
    /**
     * Click-through F1/F4: fail-closed denials resolve through `strings.xml`
     * (EN + values-pt). [errorResId] wins when set; [errorMessage] stays as
     * the dynamic fallback (exception detail) so unit tests can assert the
     * resource without a Context.
     */
    val errorResId: Int? = null,
    val isKeyConnected: Boolean = false,
    val isGuardUnlocked: Boolean = true,
    val guardState: SecureGuardStateEnum = SecureGuardStateEnum.UNLOCKED,
    /**
     * Finding A3: outstanding device presence request. While non-null the
     * key-gen sheet stays open showing the "touch the key" prompt; success
     * and error messages stay null so nothing closes or succeeds silently.
     */
    val presenceRequest: PresenceRequest? = null,
    /**
     * Per-key touch toggle state. While a SET is in flight
     * [isTouchActionLoading] is true; [touchOutcome] carries the structured
     * result for the screen to render via `strings.xml` (PT+EN) and to open
     * the existing unlock flow on NEED_PIN.
     */
    val isTouchActionLoading: Boolean = false,
    val touchOutcome: TouchPolicy.TouchOutcome? = null,
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
    val errorMessage: String? = null,
    val errorResId: Int? = null,
    val presenceRequest: PresenceRequest? = null,
    val pendingKeyGen: PendingKeyGen? = null,
    val touchActionSlot: Int? = null,
    val touchOutcome: TouchPolicy.TouchOutcome? = null
)

/** Key-gen params retained so the user can retry after touching the key. */
private data class PendingKeyGen(
    val keyId: String,
    val label: String,
    val type: AccessKeyType,
    val algorithmOrCurve: String,
    val extraParam: String
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
    private val getKeyTouchRequiredUseCase: GetKeyTouchRequiredUseCase? = null,
    private val setKeyTouchRequiredUseCase: SetKeyTouchRequiredUseCase? = null,
    private val keysStore: EncryptedKeysStore? = null,
    private val secureGuardRepository: SecureGuardRepository? = null,
) : ViewModel() {

    val activeKey: StateFlow<ConnectedKeyDevice?> = getActiveKeyUseCase()
    val vaultEntries: StateFlow<List<VaultKeyEntry>> = getVaultEntriesUseCase()

    val guardStatusFlow: StateFlow<SecureGuardStatus?> = secureGuardRepository?.statusFlow
        ?: MutableStateFlow(null)

    private val _internalState = MutableStateFlow(KeyVaultInternalState())

    val uiState: StateFlow<KeyVaultUiState> = combine(
        activeKey,
        vaultEntries,
        guardStatusFlow,
        _internalState
    ) { key, entries, guardStatus, internal ->
        val isConnected = key?.isCurrentlyConnected == true
        val isGuardUnlocked = guardStatus == null || guardStatus.state == SecureGuardStateEnum.UNLOCKED
        val visibleEntries = if (isConnected && isGuardUnlocked) entries else emptyList()

        val selected = visibleEntries.find { it.slotId == internal.selectedSlotId }
        KeyVaultUiState(
            activeKey = key,
            entries = visibleEntries,
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
            errorMessage = internal.errorMessage,
            errorResId = internal.errorResId,
            isKeyConnected = isConnected,
            isGuardUnlocked = isGuardUnlocked,
            guardState = guardStatus?.state ?: SecureGuardStateEnum.UNLOCKED,
            presenceRequest = internal.presenceRequest,
            isTouchActionLoading = internal.touchActionSlot != null,
            touchOutcome = internal.touchOutcome,
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = KeyVaultUiState(
            activeKey = activeKey.value,
            entries = if (activeKey.value?.isCurrentlyConnected == true) vaultEntries.value else emptyList()
        )
    )

    init {
        val currentKey = activeKey.value
        if (currentKey != null && currentKey.isCurrentlyConnected) {
            refreshVault()
            loadHardwareDiagnostics()
        }

        // Whenever Secure Guard transitions to UNLOCKED, auto-reload real hardware keys
        secureGuardRepository?.statusFlow?.onEach { status: SecureGuardStatus ->
            if (status.state == SecureGuardStateEnum.UNLOCKED) {
                val key = activeKey.value
                if (key != null && key.isCurrentlyConnected) {
                    refreshVault()
                }
            }
        }?.launchIn(viewModelScope)
    }

    fun clearMessages() {
        _internalState.update { it.copy(userMessage = null, errorMessage = null, errorResId = null) }
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
        val targetKeyId = currentKey?.id ?: "default-aegis-key"

        // Click-through F4: fail-closed while LOCKED. Key generation never
        // reaches the wire on a locked session; the screen disables the
        // button and explains via strings.xml (vault_generate_locked_hint).
        // This branch is the second gate for programmatic callers.
        val guardStatus = guardStatusFlow.value
        val isGuardUnlocked = guardStatus == null || guardStatus.isUnlocked || guardStatus.state == SecureGuardStateEnum.UNLOCKED || SecureGuardRepositoryImpl.isSessionPinValid()
        if (!isGuardUnlocked) {
            _internalState.update { it.copy(errorMessage = null, errorResId = dev.aegiskey.app.R.string.vault_err_guard_locked) }
            return
        }

        viewModelScope.launch {
            _internalState.update {
                it.copy(
                    isLoading = true,
                    // A new attempt supersedes any outstanding presence prompt.
                    presenceRequest = null
                )
            }
            try {
                val result = generateAccessKeyUseCase(
                    keyId = targetKeyId,
                    label = label,
                    type = type,
                    algorithmOrCurve = algorithmOrCurve,
                    extraParam = extraParam
                )
                result.onSuccess { entry ->
                    _internalState.update {
                        it.copy(
                            userMessage = "Chave \"${entry.label}\" gerada e protegida com sucesso no cofre!",
                            presenceRequest = null,
                            pendingKeyGen = null
                        )
                    }
                    refreshVault()
                    loadHardwareDiagnostics()
                }.onFailure { err ->
                    // Finding A3: NEED_UP keeps the sheet open with the
                    // presence prompt (pending params retained for retry);
                    // anything else closes with an honest error.
                    if (err.isNeedUpDenial()) {
                        _internalState.update {
                            it.copy(
                                presenceRequest = PresenceRequest(op = "key-gen"),
                                pendingKeyGen = PendingKeyGen(
                                    keyId = targetKeyId,
                                    label = label,
                                    type = type,
                                    algorithmOrCurve = algorithmOrCurve,
                                    extraParam = extraParam
                                )
                            )
                        }
                    } else {
                        _internalState.update {
                            it.copy(
                                errorMessage = "Não foi possível gerar a chave: ${err.localizedMessage ?: "Verifique a chave física."}",
                                pendingKeyGen = null
                            )
                        }
                    }
                }
            } finally {
                _internalState.update { it.copy(isLoading = false) }
            }
        }
    }

    /** Retries the denied key-gen after the user touched the key. */
    fun retryPendingKeyGen() {
        val pending = _internalState.value.pendingKeyGen ?: return
        _internalState.update { it.copy(presenceRequest = null) }
        createNewKey(
            label = pending.label,
            type = pending.type,
            algorithmOrCurve = pending.algorithmOrCurve,
            extraParam = pending.extraParam
        )
    }

    /** Dismisses the presence prompt (user cancelled; pending gen dropped). */
    fun dismissPresenceRequest() {
        _internalState.update { it.copy(presenceRequest = null, pendingKeyGen = null) }
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

    /**
     * Per-key touch toggle (touchpolicy module). Requires an unlocked
     * session: a locked guard opens the existing unlock flow instead of
     * reaching the wire. The structured outcome lands in
     * [KeyVaultUiState.touchOutcome] for the screen to render (PT+EN) and
     * to surface NEED_PIN via the unlock prompt.
     */
    fun setTouchRequired(slotId: Int, requireTouch: Boolean) {
        val currentKey = activeKey.value ?: return
        val setUseCase = setKeyTouchRequiredUseCase
        if (setUseCase == null) {
            _internalState.update {
                it.copy(touchOutcome = TouchPolicy.TouchOutcome.Failed("unavailable"))
            }
            return
        }

        val guardStatus = guardStatusFlow.value
        val isGuardUnlocked = guardStatus == null || guardStatus.isUnlocked ||
            guardStatus.state == SecureGuardStateEnum.UNLOCKED ||
            SecureGuardRepositoryImpl.isSessionPinValid()
        if (!isGuardUnlocked) {
            _internalState.update {
                it.copy(touchOutcome = TouchPolicy.TouchOutcome.NeedPin)
            }
            return
        }

        viewModelScope.launch {
            _internalState.update { it.copy(touchActionSlot = slotId, touchOutcome = null) }
            try {
                val result = setUseCase(currentKey.id, slotId, requireTouch)
                result.onSuccess {
                    _internalState.update {
                        it.copy(touchOutcome = TouchPolicy.TouchOutcome.Applied(requireTouch))
                    }
                    refreshVault()
                    loadHardwareDiagnostics()
                }.onFailure { err ->
                    val outcome = when {
                        err is TouchPolicy.TouchNeedPinException ->
                            TouchPolicy.TouchOutcome.NeedPin
                        err is TouchPolicy.TouchNoSlotException ->
                            TouchPolicy.TouchOutcome.NoSlot
                        else ->
                            TouchPolicy.TouchOutcome.Failed(
                                err.localizedMessage ?: "0x04"
                            )
                    }
                    _internalState.update { it.copy(touchOutcome = outcome) }
                }
            } finally {
                _internalState.update { it.copy(touchActionSlot = null) }
            }
        }
    }

    fun consumeTouchOutcome() {
        _internalState.update { it.copy(touchOutcome = null) }
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
                        getKeyTouchRequiredUseCase = container.getKeyTouchRequiredUseCase,
                        setKeyTouchRequiredUseCase = container.setKeyTouchRequiredUseCase,
                        keysStore = container.keysStore,
                        secureGuardRepository = container.secureGuardRepository,
                    ) as T
                }
            }
    }
}
