package dev.aegiskey.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import dev.aegiskey.app.R
import dev.aegiskey.app.data.debug.DebugHardwareChipMock
import dev.aegiskey.app.di.AppContainer
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DiscoveredKeyCandidate
import dev.aegiskey.app.domain.model.OnboardingStep
import dev.aegiskey.app.domain.repository.PairingWizardRepository
import dev.aegiskey.app.domain.usecase.ArmBleOobUseCase
import dev.aegiskey.app.domain.usecase.ConnectCandidateUseCase
import dev.aegiskey.app.oob.OobPairing
import dev.aegiskey.app.domain.usecase.PerformBiometricBindingUseCase
import dev.aegiskey.app.domain.usecase.SimulateButtonHoldUseCase
import dev.aegiskey.app.domain.usecase.SimulateButtonSingleTouchUseCase
import dev.aegiskey.app.domain.usecase.StartDiscoveryUseCase
import dev.aegiskey.app.domain.usecase.StopDiscoveryUseCase
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * Estado unificado da jornada de onboarding / pareamento linear (Next-Next-Next).
 */
data class OnboardingWizardUiState(
    val currentStep: OnboardingStep = OnboardingStep.WELCOME_TRANSPORT,
    val selectedTransport: ConnectionTransportType = ConnectionTransportType.BLE,
    val candidates: List<DiscoveredKeyCandidate> = emptyList(),
    val selectedCandidate: DiscoveredKeyCandidate? = null,
    val isScanning: Boolean = false,
    val isConnecting: Boolean = false,
    val isBinding: Boolean = false,
    val buttonHoldDetected: Boolean = false,
    val buttonTouchDetected: Boolean = false,
    val isUsbDetected: Boolean = false,
    val keyAlias: String = "Minha Chave Principal",
    val recoveryPin: String = "",
    val errorMessage: String? = null,
    /**
     * Click-through F1: user-facing errors resolve through `strings.xml`
     * (EN + values-pt). [errorResId] wins when set; [errorMessage] stays as
     * the dynamic fallback (exception detail) so unit tests can assert the
     * resource without a Context.
     */
    val errorResId: Int? = null,
    val errorArgs: List<String> = emptyList(),
    val isCompleted: Boolean = false,
    /**
     * OOB-assisted BLE pairing (`0x42`, CAPABILITY_DIET §10): truthful
     * device answer of the last automatic exchange attempt. Non-blocking:
     * binding (0x28) is a separate device gate, so the wizard may proceed
     * while this still reports a denial — the denial stays visible and no
     * success is ever claimed without the `0x00` authority answer.
     */
    val oobArmState: OobArmState = OobArmState.Idle
)

/**
 * Structured UI outcome of the automatic OOB exchange. Rendered via
 * `strings.xml` (PT+EN); the Android bond step itself stays
 * [dev.aegiskey.app.oob.OobPairing.AndroidBondVerdict.BlockedNoPublicOobApi]
 * (no public OS entrypoint consumes the TK).
 */
sealed interface OobArmState {
    data object Idle : OobArmState
    data object Arming : OobArmState
    data object Armed : OobArmState
    data class Failed(val errorResId: Int) : OobArmState
}

class OnboardingWizardViewModel(
    private val pairingWizardRepository: PairingWizardRepository,
    private val startDiscoveryUseCase: StartDiscoveryUseCase,
    private val stopDiscoveryUseCase: StopDiscoveryUseCase,
    private val connectCandidateUseCase: ConnectCandidateUseCase,
    private val simulateButtonHoldUseCase: SimulateButtonHoldUseCase,
    private val simulateButtonSingleTouchUseCase: SimulateButtonSingleTouchUseCase,
    private val performBiometricBindingUseCase: PerformBiometricBindingUseCase,
    private val armBleOobUseCase: ArmBleOobUseCase,
) : ViewModel() {

    private val _uiState = MutableStateFlow(OnboardingWizardUiState())
    val uiState: StateFlow<OnboardingWizardUiState> = _uiState.asStateFlow()

    init {
        // Observa candidatos descobertos pelo repositório
        pairingWizardRepository.discoveredCandidates.onEach { list ->
            _uiState.update { current ->
                val autoSelected = if (current.selectedCandidate != null && list.any { it.id == current.selectedCandidate.id }) {
                    current.selectedCandidate
                } else {
                    list.firstOrNull { it.transportType == current.selectedTransport } ?: list.firstOrNull()
                }
                current.copy(candidates = list, selectedCandidate = autoSelected)
            }
        }.launchIn(viewModelScope)

        pairingWizardRepository.isScanning.onEach { scanning ->
            _uiState.update { it.copy(isScanning = scanning) }
        }.launchIn(viewModelScope)

        pairingWizardRepository.isUsbDetected.onEach { detected ->
            _uiState.update { it.copy(isUsbDetected = detected) }
        }.launchIn(viewModelScope)

        pairingWizardRepository.buttonHoldSimulatedOrDetected.onEach { detected ->
            if (detected) {
                _uiState.update { it.copy(buttonHoldDetected = true) }
            }
        }.launchIn(viewModelScope)
    }

    fun selectTransport(type: ConnectionTransportType) {
        _uiState.update { it.copy(selectedTransport = type, errorMessage = null, errorResId = null, errorArgs = emptyList()) }
        val step = _uiState.value.currentStep
        if (step == OnboardingStep.HOLD_PHYSICAL_BUTTON || step == OnboardingStep.DISCOVER_AND_CONNECT) {
            viewModelScope.launch {
                startDiscoveryUseCase(type)
            }
        }
    }

    /**
     * Reinicia a busca ativa pelo transporte selecionado (botão "Buscar novamente").
     */
    fun refreshDiscovery() {
        viewModelScope.launch {
            val transport = _uiState.value.selectedTransport
            _uiState.update { it.copy(errorMessage = null, errorResId = null, errorArgs = emptyList()) }
            stopDiscoveryUseCase()
            startDiscoveryUseCase(transport)
        }
    }

    fun setKeyAlias(alias: String) {
        _uiState.update { it.copy(keyAlias = alias, errorMessage = null, errorResId = null, errorArgs = emptyList()) }
    }

    fun setRecoveryPin(pin: String) {
        val sanitized = pin.filter { it.isDigit() }.take(6)
        _uiState.update { it.copy(recoveryPin = sanitized, errorMessage = null, errorResId = null, errorArgs = emptyList()) }
    }

    fun clearError() {
        _uiState.update { it.copy(errorMessage = null, errorResId = null, errorArgs = emptyList()) }
    }

    fun simulateButtonHold5s() {
        viewModelScope.launch {
            _uiState.update { it.copy(isConnecting = true, errorMessage = null, errorResId = null, errorArgs = emptyList()) }
            val result = simulateButtonHoldUseCase()
            _uiState.update {
                it.copy(
                    isConnecting = false,
                    buttonHoldDetected = result.isSuccess,
                    errorMessage = result.exceptionOrNull()?.localizedMessage,
                    errorResId = null,
                    errorArgs = emptyList()
                )
            }
        }
    }

    fun simulateSingleButtonTouch() {
        viewModelScope.launch {
            val result = simulateButtonSingleTouchUseCase()
            _uiState.update {
                it.copy(
                    buttonTouchDetected = result.isSuccess,
                    errorMessage = result.exceptionOrNull()?.localizedMessage,
                    errorResId = null,
                    errorArgs = emptyList()
                )
            }
        }
    }

    fun selectCandidateAndConnect(candidate: DiscoveredKeyCandidate) {
        viewModelScope.launch {
            _uiState.update { it.copy(selectedCandidate = candidate, isConnecting = true, errorMessage = null, errorResId = null, errorArgs = emptyList()) }
            val result = connectCandidateUseCase(candidate)
            _uiState.update {
                it.copy(
                    isConnecting = false,
                    errorMessage = result.exceptionOrNull()?.localizedMessage,
                    errorResId = null,
                    errorArgs = emptyList()
                )
            }
        }
    }

    fun nextStep() {
        val current = _uiState.value.currentStep
        when (current) {
            OnboardingStep.WELCOME_TRANSPORT -> {
                val transport = _uiState.value.selectedTransport
                _uiState.update { it.copy(currentStep = OnboardingStep.HOLD_PHYSICAL_BUTTON, errorMessage = null, errorResId = null, errorArgs = emptyList()) }
                // Inicia a busca antecipadamente no Passo 2 para que no Passo 3 os dispositivos já estejam presentes
                viewModelScope.launch {
                    startDiscoveryUseCase(transport)
                }
            }
            OnboardingStep.HOLD_PHYSICAL_BUTTON -> {
                val transport = _uiState.value.selectedTransport
                _uiState.update {
                    it.copy(
                        currentStep = OnboardingStep.DISCOVER_AND_CONNECT,
                        buttonHoldDetected = true,
                        errorMessage = null,
                        errorResId = null,
                        errorArgs = emptyList()
                    )
                }
                viewModelScope.launch {
                    // Se for simulador ou emulador com mocks habilitados, simula o hold do botão
                    if (DebugHardwareChipMock.IS_MOCK_ENABLED && (transport == ConnectionTransportType.SIMULATOR || !_uiState.value.buttonHoldDetected)) {
                        simulateButtonHoldUseCase()
                    }
                    startDiscoveryUseCase(transport)
                }
            }
            OnboardingStep.DISCOVER_AND_CONNECT -> {
                viewModelScope.launch {
                    val transport = _uiState.value.selectedTransport
                    var candidate = _uiState.value.selectedCandidate
                        ?: _uiState.value.candidates.firstOrNull()

                    // Emulador/Simulador ou Debug sem chave física real: provê candidato automático SOMENTE se mocks habilitados
                    if (candidate == null && DebugHardwareChipMock.IS_MOCK_ENABLED && (transport == ConnectionTransportType.SIMULATOR || DebugHardwareChipMock.isDebugMode)) {
                        candidate = DebugHardwareChipMock.getCandidateForTransport(transport)
                    }
                    if (candidate == null) {
                        // Fail-closed: no selection keeps the wizard on this step.
                        // User text resolves via strings.xml (EN + values-pt).
                        _uiState.update {
                            it.copy(errorMessage = null, errorResId = R.string.onb_err_no_selection, errorArgs = emptyList())
                        }
                        return@launch
                    }

                    _uiState.update { it.copy(selectedCandidate = candidate, isConnecting = true, errorMessage = null, errorResId = null, errorArgs = emptyList()) }
                    val connectResult = connectCandidateUseCase(candidate)
                    val isMockCandidate = DebugHardwareChipMock.IS_MOCK_ENABLED && DebugHardwareChipMock.isMockCandidate(candidate.id)
                    if (connectResult.isSuccess || isMockCandidate) {
                        stopDiscoveryUseCase()
                        pairingWizardRepository.autoValidatePresence(candidate, transport)
                        _uiState.update {
                            it.copy(
                                isConnecting = false,
                                currentStep = OnboardingStep.OOB_AUTO_EXCHANGE,
                                buttonTouchDetected = true,
                                errorMessage = null
                            )
                        }
                        armOobExchange()
                    } else {
                        _uiState.update {
                            it.copy(
                                isConnecting = false,
                                errorMessage = null,
                                errorResId = R.string.onb_err_connect_failed,
                                errorArgs = emptyList()
                            )
                        }
                    }
                }
            }
            OnboardingStep.OOB_AUTO_EXCHANGE -> {
                // Non-blocking by design (see oobArmState): the device
                // answer stays visible on this step; binding (0x28) is a
                // separate device gate resolved on the next steps.
                _uiState.update {
                    it.copy(
                        currentStep = OnboardingStep.TOUCH_AND_BIOMETRIC_BIND,
                        errorMessage = null
                    )
                }
            }
            OnboardingStep.TOUCH_AND_BIOMETRIC_BIND -> {
                _uiState.update {
                    it.copy(
                        currentStep = OnboardingStep.NAME_AND_FINISH,
                        buttonTouchDetected = true,
                        errorMessage = null
                    )
                }
                viewModelScope.launch {
                    val candidate = _uiState.value.selectedCandidate
                    if (DebugHardwareChipMock.IS_MOCK_ENABLED && DebugHardwareChipMock.isMockCandidate(candidate?.id)) {
                        simulateButtonSingleTouchUseCase()
                    }
                }
            }
            OnboardingStep.NAME_AND_FINISH -> {
                // Último passo: conclui a vinculação
                performBiometricBinding(
                    alias = _uiState.value.keyAlias,
                    recoveryPin = _uiState.value.recoveryPin.ifBlank { null },
                    onCompleted = {}
                )
            }
        }
    }

    fun previousStep() {
        val current = _uiState.value.currentStep
        val previous = when (current) {
            OnboardingStep.WELCOME_TRANSPORT -> return
            OnboardingStep.HOLD_PHYSICAL_BUTTON -> OnboardingStep.WELCOME_TRANSPORT
            OnboardingStep.DISCOVER_AND_CONNECT -> {
                viewModelScope.launch { stopDiscoveryUseCase() }
                OnboardingStep.HOLD_PHYSICAL_BUTTON
            }
            OnboardingStep.OOB_AUTO_EXCHANGE -> OnboardingStep.DISCOVER_AND_CONNECT
            OnboardingStep.TOUCH_AND_BIOMETRIC_BIND -> OnboardingStep.OOB_AUTO_EXCHANGE
            OnboardingStep.NAME_AND_FINISH -> OnboardingStep.TOUCH_AND_BIOMETRIC_BIND
        }
        _uiState.update { it.copy(currentStep = previous, errorMessage = null, errorResId = null, errorArgs = emptyList()) }
    }

    fun restoreState(step: OnboardingStep, transport: ConnectionTransportType) {
        _uiState.update {
            it.copy(
                currentStep = step,
                selectedTransport = transport
            )
        }
    }

    fun skipOnboardingAndGoToVault(onFinished: () -> Unit) {
        viewModelScope.launch {
            pairingWizardRepository.registerConfiguredKeyOrSkip()
            _uiState.update { it.copy(isCompleted = true) }
            onFinished()
        }
    }

    fun connectUsbDeviceAndOpenVault(onFinished: () -> Unit) {
        viewModelScope.launch {
            _uiState.update { it.copy(isConnecting = true, errorMessage = null, errorResId = null, errorArgs = emptyList()) }
            val result = pairingWizardRepository.connectUsbDeviceAndRegister()
            result.onSuccess {
                _uiState.update { it.copy(isConnecting = false, isCompleted = true) }
                onFinished()
            }.onFailure { error ->
                val detail = error.localizedMessage?.take(120)?.trim().orEmpty()
                _uiState.update {
                    if (detail.isEmpty()) {
                        it.copy(
                            isConnecting = false,
                            errorMessage = null,
                            errorResId = R.string.onb_err_usb_default,
                            errorArgs = emptyList()
                        )
                    } else {
                        it.copy(
                            isConnecting = false,
                            errorMessage = null,
                            errorResId = R.string.onb_err_usb,
                            errorArgs = listOf(detail)
                        )
                    }
                }
            }
        }
    }

    fun completeWizardWithCustomName(
        customName: String,
        onCompleted: (ConnectedKeyDevice) -> Unit = {}
    ) {
        val sanitized = customName.trim().ifBlank { "Minha Chave Principal" }
        _uiState.update { it.copy(keyAlias = sanitized) }
        performBiometricBinding(
            alias = sanitized,
            recoveryPin = _uiState.value.recoveryPin.ifBlank { null },
            onCompleted = onCompleted
        )
    }

    /**
     * Automatic OOB exchange (`0x42` over USB): samples a fresh TK,
     * arms the firmware latch one-shot, and records the truthful device
     * answer. Retried from the OOB wizard step. Never claims success
     * without the `0x00` authority answer.
     */
    fun armOobExchange() {
        if (_uiState.value.oobArmState == OobArmState.Arming) return
        _uiState.update { it.copy(oobArmState = OobArmState.Arming) }
        viewModelScope.launch {
            val result = armBleOobUseCase()
            _uiState.update {
                it.copy(
                    oobArmState = when (result) {
                        OobPairing.ArmResult.Armed -> OobArmState.Armed
                        OobPairing.ArmResult.NeedBinding ->
                            OobArmState.Failed(R.string.oob_err_binding)
                        OobPairing.ArmResult.NeedUp ->
                            OobArmState.Failed(R.string.oob_err_up)
                        OobPairing.ArmResult.NeedPin ->
                            OobArmState.Failed(R.string.oob_err_pin)
                        is OobPairing.ArmResult.BadEnvelope ->
                            OobArmState.Failed(R.string.oob_err_envelope)
                        OobPairing.ArmResult.TransportFailure ->
                            OobArmState.Failed(R.string.oob_err_transport)
                    }
                )
            }
        }
    }

    fun performBiometricBinding(
        alias: String,
        recoveryPin: String?,
        onCompleted: (ConnectedKeyDevice) -> Unit
    ) {
        viewModelScope.launch {
            _uiState.update { it.copy(isBinding = true, errorMessage = null, errorResId = null, errorArgs = emptyList()) }
            val cleanAlias = alias.trim().ifBlank { "Minha Chave Principal" }
            val cleanPin = recoveryPin?.trim()?.ifBlank { null }

            val result = performBiometricBindingUseCase(cleanAlias, cleanPin)
            result.onSuccess { device ->
                _uiState.update { it.copy(isBinding = false, isCompleted = true, errorMessage = null, errorResId = null, errorArgs = emptyList()) }
                onCompleted(device)
            }.onFailure { error ->
                val detail = error.localizedMessage?.take(120)?.trim().orEmpty()
                _uiState.update {
                    if (detail.isEmpty()) {
                        it.copy(
                            isBinding = false,
                            errorMessage = null,
                            errorResId = R.string.onb_err_bind_default,
                            errorArgs = emptyList()
                        )
                    } else {
                        it.copy(
                            isBinding = false,
                            errorMessage = null,
                            errorResId = R.string.onb_err_bind_failed,
                            errorArgs = listOf(detail)
                        )
                    }
                }
            }
        }
    }

    companion object {
        fun provideFactory(container: AppContainer): ViewModelProvider.Factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return OnboardingWizardViewModel(
                        pairingWizardRepository = container.pairingWizardRepository,
                        startDiscoveryUseCase = container.startDiscoveryUseCase,
                        stopDiscoveryUseCase = container.stopDiscoveryUseCase,
                        connectCandidateUseCase = container.connectCandidateUseCase,
                        simulateButtonHoldUseCase = container.simulateButtonHoldUseCase,
                        simulateButtonSingleTouchUseCase = container.simulateButtonSingleTouchUseCase,
                        performBiometricBindingUseCase = container.performBiometricBindingUseCase,
                        armBleOobUseCase = container.armBleOobUseCase,
                    ) as T
                }
            }
    }
}
