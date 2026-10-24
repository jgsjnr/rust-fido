package dev.aegiskey.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import dev.aegiskey.app.di.AppContainer
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DiscoveredKeyCandidate
import dev.aegiskey.app.domain.model.OnboardingStep
import dev.aegiskey.app.domain.repository.PairingWizardRepository
import dev.aegiskey.app.domain.usecase.ConnectCandidateUseCase
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
    val keyAlias: String = "Minha Chave Principal",
    val recoveryPin: String = "",
    val errorMessage: String? = null,
    val isCompleted: Boolean = false
)

class OnboardingWizardViewModel(
    private val pairingWizardRepository: PairingWizardRepository,
    private val startDiscoveryUseCase: StartDiscoveryUseCase,
    private val stopDiscoveryUseCase: StopDiscoveryUseCase,
    private val connectCandidateUseCase: ConnectCandidateUseCase,
    private val simulateButtonHoldUseCase: SimulateButtonHoldUseCase,
    private val simulateButtonSingleTouchUseCase: SimulateButtonSingleTouchUseCase,
    private val performBiometricBindingUseCase: PerformBiometricBindingUseCase,
) : ViewModel() {

    private val _uiState = MutableStateFlow(OnboardingWizardUiState())
    val uiState: StateFlow<OnboardingWizardUiState> = _uiState.asStateFlow()

    init {
        // Observa candidatos descobertos pelo repositório
        pairingWizardRepository.discoveredCandidates.onEach { list ->
            _uiState.update { current ->
                val autoSelected = current.selectedCandidate
                    ?: list.firstOrNull { it.transportType == current.selectedTransport }
                    ?: list.firstOrNull()
                current.copy(candidates = list, selectedCandidate = autoSelected)
            }
        }.launchIn(viewModelScope)

        pairingWizardRepository.isScanning.onEach { scanning ->
            _uiState.update { it.copy(isScanning = scanning) }
        }.launchIn(viewModelScope)

        pairingWizardRepository.buttonHoldSimulatedOrDetected.onEach { detected ->
            if (detected) {
                _uiState.update { it.copy(buttonHoldDetected = true) }
            }
        }.launchIn(viewModelScope)
    }

    fun selectTransport(type: ConnectionTransportType) {
        _uiState.update { it.copy(selectedTransport = type, errorMessage = null) }
        if (_uiState.value.currentStep == OnboardingStep.DISCOVER_AND_CONNECT) {
            viewModelScope.launch {
                startDiscoveryUseCase(type)
            }
        }
    }

    fun setKeyAlias(alias: String) {
        _uiState.update { it.copy(keyAlias = alias, errorMessage = null) }
    }

    fun setRecoveryPin(pin: String) {
        val sanitized = pin.filter { it.isDigit() }.take(6)
        _uiState.update { it.copy(recoveryPin = sanitized, errorMessage = null) }
    }

    fun clearError() {
        _uiState.update { it.copy(errorMessage = null) }
    }

    fun simulateButtonHold5s() {
        viewModelScope.launch {
            _uiState.update { it.copy(isConnecting = true, errorMessage = null) }
            val result = simulateButtonHoldUseCase()
            _uiState.update {
                it.copy(
                    isConnecting = false,
                    buttonHoldDetected = result.isSuccess,
                    errorMessage = result.exceptionOrNull()?.localizedMessage
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
                    errorMessage = result.exceptionOrNull()?.localizedMessage
                )
            }
        }
    }

    fun selectCandidateAndConnect(candidate: DiscoveredKeyCandidate) {
        viewModelScope.launch {
            _uiState.update { it.copy(selectedCandidate = candidate, isConnecting = true, errorMessage = null) }
            val result = connectCandidateUseCase(candidate)
            _uiState.update {
                it.copy(
                    isConnecting = false,
                    errorMessage = result.exceptionOrNull()?.localizedMessage
                )
            }
        }
    }

    fun nextStep() {
        val current = _uiState.value.currentStep
        when (current) {
            OnboardingStep.WELCOME_TRANSPORT -> {
                _uiState.update { it.copy(currentStep = OnboardingStep.HOLD_PHYSICAL_BUTTON, errorMessage = null) }
            }
            OnboardingStep.HOLD_PHYSICAL_BUTTON -> {
                viewModelScope.launch {
                    val transport = _uiState.value.selectedTransport
                    // Se for simulador ou emulador sem dongle, assegura que o hold seja simulado
                    if (transport == ConnectionTransportType.SIMULATOR || !_uiState.value.buttonHoldDetected) {
                        simulateButtonHoldUseCase()
                    }
                    _uiState.update {
                        it.copy(
                            currentStep = OnboardingStep.DISCOVER_AND_CONNECT,
                            buttonHoldDetected = true,
                            errorMessage = null
                        )
                    }
                    startDiscoveryUseCase(transport)
                }
            }
            OnboardingStep.DISCOVER_AND_CONNECT -> {
                viewModelScope.launch {
                    val transport = _uiState.value.selectedTransport
                    var candidate = _uiState.value.selectedCandidate
                        ?: _uiState.value.candidates.firstOrNull()

                    // Emulador/Simulador sem chave física real: provê candidato automático
                    if (candidate == null && transport == ConnectionTransportType.SIMULATOR) {
                        candidate = DiscoveredKeyCandidate(
                            id = "tcp:10.0.2.2:5678",
                            name = "AegisKey Renode Simulator",
                            signalRssi = -20,
                            transportType = ConnectionTransportType.SIMULATOR
                        )
                    } else if (candidate == null) {
                        // Se não encontrou nenhuma chave ainda, informa de modo amigável
                        _uiState.update {
                            it.copy(errorMessage = "Nenhuma chave selecionada. Escolha sua AegisKey na lista abaixo.")
                        }
                        return@launch
                    }

                    _uiState.update { it.copy(selectedCandidate = candidate, isConnecting = true, errorMessage = null) }
                    val connectResult = connectCandidateUseCase(candidate)
                    if (connectResult.isSuccess) {
                        stopDiscoveryUseCase()
                        _uiState.update {
                            it.copy(
                                isConnecting = false,
                                currentStep = OnboardingStep.TOUCH_AND_BIOMETRIC_BIND,
                                errorMessage = null
                            )
                        }
                    } else {
                        // Se falhou ao conectar, e o usuário está testando ou em emulador, permite avançar se for simulador
                        if (transport == ConnectionTransportType.SIMULATOR) {
                            stopDiscoveryUseCase()
                            _uiState.update {
                                it.copy(
                                    isConnecting = false,
                                    currentStep = OnboardingStep.TOUCH_AND_BIOMETRIC_BIND,
                                    errorMessage = null
                                )
                            }
                        } else {
                            _uiState.update {
                                it.copy(
                                    isConnecting = false,
                                    errorMessage = "Não foi possível conectar à chave. Verifique se ela está ligada e próxima ao celular."
                                )
                            }
                        }
                    }
                }
            }
            OnboardingStep.TOUCH_AND_BIOMETRIC_BIND -> {
                viewModelScope.launch {
                    val transport = _uiState.value.selectedTransport
                    if (transport == ConnectionTransportType.SIMULATOR) {
                        simulateButtonSingleTouchUseCase()
                    }
                    _uiState.update {
                        it.copy(
                            currentStep = OnboardingStep.NAME_AND_FINISH,
                            buttonTouchDetected = true,
                            errorMessage = null
                        )
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
            OnboardingStep.TOUCH_AND_BIOMETRIC_BIND -> OnboardingStep.DISCOVER_AND_CONNECT
            OnboardingStep.NAME_AND_FINISH -> OnboardingStep.TOUCH_AND_BIOMETRIC_BIND
        }
        _uiState.update { it.copy(currentStep = previous, errorMessage = null) }
    }

    fun performBiometricBinding(
        alias: String,
        recoveryPin: String?,
        onCompleted: (ConnectedKeyDevice) -> Unit
    ) {
        viewModelScope.launch {
            _uiState.update { it.copy(isBinding = true, errorMessage = null) }
            val cleanAlias = alias.trim().ifBlank { "Minha Chave Principal" }
            val cleanPin = recoveryPin?.trim()?.ifBlank { null }

            val result = performBiometricBindingUseCase(cleanAlias, cleanPin)
            result.onSuccess { device ->
                _uiState.update { it.copy(isBinding = false, isCompleted = true, errorMessage = null) }
                onCompleted(device)
            }.onFailure { error ->
                _uiState.update {
                    it.copy(
                        isBinding = false,
                        errorMessage = "Não foi possível vincular a chave: ${error.localizedMessage ?: "Tente novamente pressionando o botão da chave."}"
                    )
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
                    ) as T
                }
            }
    }
}
