package dev.aegiskey.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import dev.aegiskey.app.domain.usecase.ChangeSecureGuardPinUseCase
import dev.aegiskey.app.domain.usecase.GetSecureGuardStatusUseCase
import dev.aegiskey.app.domain.usecase.LockSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.ProvisionSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.RecoverSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.TriggerSelectiveWipeTestUseCase
import dev.aegiskey.app.domain.usecase.UnlockSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.UpdateSecureGuardPolicyUseCase
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

data class SecureGuardUiState(
    val isLoading: Boolean = false,
    val status: SecureGuardStatus = SecureGuardStatus(),
    val errorMessage: String? = null,
    val successMessage: String? = null,
    val generatedRecoveryCode: String? = null,
    val isUnlockPromptOpen: Boolean = false
)

/**
 * ViewModel que orquestra as 13 jornadas de UX do Secure Guard (UX Seção 11.2).
 */
class SecureGuardViewModel(
    private val getSecureGuardStatusUseCase: GetSecureGuardStatusUseCase,
    private val provisionSecureGuardUseCase: ProvisionSecureGuardUseCase,
    private val unlockSecureGuardUseCase: UnlockSecureGuardUseCase,
    private val lockSecureGuardUseCase: LockSecureGuardUseCase,
    private val changeSecureGuardPinUseCase: ChangeSecureGuardPinUseCase,
    private val recoverSecureGuardUseCase: RecoverSecureGuardUseCase,
    private val updateSecureGuardPolicyUseCase: UpdateSecureGuardPolicyUseCase,
    private val triggerSelectiveWipeTestUseCase: TriggerSelectiveWipeTestUseCase,
) : ViewModel() {

    private val _uiState = MutableStateFlow(SecureGuardUiState())
    val uiState: StateFlow<SecureGuardUiState> = _uiState.asStateFlow()

    private var countdownJob: Job? = null

    init {
        refreshStatus()
    }

    private fun startCountdownTickerIfNeeded() {
        countdownJob?.cancel()
        val current = _uiState.value.status
        val needsTicker = (current.state == SecureGuardStateEnum.RATE_LIMITED && current.rateLimitRemainingMs > 0) ||
                (current.state == SecureGuardStateEnum.UNLOCKED && current.sessionRemainingMs > 0)

        if (needsTicker) {
            countdownJob = viewModelScope.launch {
                while (isActive) {
                    delay(1000L)
                    val st = _uiState.value.status
                    var newRate = st.rateLimitRemainingMs
                    var newSess = st.sessionRemainingMs
                    var newState = st.state

                    if (st.state == SecureGuardStateEnum.RATE_LIMITED && newRate > 0) {
                        newRate = (newRate - 1000L).coerceAtLeast(0L)
                        if (newRate == 0L) {
                            newState = SecureGuardStateEnum.LOCKED
                        }
                    } else if (st.state == SecureGuardStateEnum.UNLOCKED && newSess > 0) {
                        newSess = (newSess - 1000L).coerceAtLeast(0L)
                        if (newSess == 0L) {
                            newState = SecureGuardStateEnum.LOCKED
                        }
                    }

                    _uiState.update { state ->
                        state.copy(
                            status = state.status.copy(
                                state = newState,
                                rateLimitRemainingMs = newRate,
                                sessionRemainingMs = newSess,
                                isUnlocked = newState == SecureGuardStateEnum.UNLOCKED
                            )
                        )
                    }

                    if (newState == SecureGuardStateEnum.LOCKED || (newRate == 0L && newSess == 0L)) {
                        break
                    }
                }
            }
        }
    }

    fun refreshStatus() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true) }
            getSecureGuardStatusUseCase()
                .onSuccess { status ->
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            status = status,
                            generatedRecoveryCode = status.lastGeneratedRecoveryCode
                        )
                    }
                    startCountdownTickerIfNeeded()
                }
                .onFailure { t ->
                    _uiState.update { it.copy(isLoading = false, errorMessage = t.message) }
                }
        }
    }

    fun provision(pin: String, recoveryCode: String? = null, policy: SecureGuardPolicy? = null) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, errorMessage = null) }
            provisionSecureGuardUseCase(pin, recoveryCode, policy)
                .onSuccess { rc ->
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            generatedRecoveryCode = rc,
                            successMessage = "Secure Guard provisionado com sucesso!",
                            isUnlockPromptOpen = false
                        )
                    }
                    refreshStatus()
                }
                .onFailure { t ->
                    _uiState.update { it.copy(isLoading = false, errorMessage = t.message) }
                }
        }
    }

    fun unlock(pin: String) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, errorMessage = null) }
            unlockSecureGuardUseCase(pin)
                .onSuccess { st ->
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            status = st,
                            successMessage = "Cofre desbloqueado com sucesso!",
                            isUnlockPromptOpen = false
                        )
                    }
                    startCountdownTickerIfNeeded()
                }
                .onFailure { t ->
                    val err = t.message ?: "PIN incorreto"
                    getSecureGuardStatusUseCase().onSuccess { st ->
                        _uiState.update {
                            it.copy(
                                isLoading = false,
                                status = st,
                                errorMessage = err
                            )
                        }
                        startCountdownTickerIfNeeded()
                    }.onFailure {
                        _uiState.update {
                            it.copy(
                                isLoading = false,
                                errorMessage = err
                            )
                        }
                    }
                }
        }
    }

    fun lock() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, errorMessage = null) }
            lockSecureGuardUseCase()
                .onSuccess {
                    countdownJob?.cancel()
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            successMessage = "Cofre bloqueado imediatamente."
                        )
                    }
                    refreshStatus()
                }
                .onFailure { t ->
                    _uiState.update { it.copy(isLoading = false, errorMessage = t.message) }
                }
        }
    }

    fun changePin(currentPin: String, newPin: String) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, errorMessage = null) }
            changeSecureGuardPinUseCase(currentPin, newPin)
                .onSuccess {
                    countdownJob?.cancel()
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            successMessage = "PIN alterado com sucesso! Cofre bloqueado."
                        )
                    }
                    refreshStatus()
                }
                .onFailure { t ->
                    _uiState.update { it.copy(isLoading = false, errorMessage = t.message) }
                }
        }
    }

    fun recover(recoveryCode: String, newPin: String) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, errorMessage = null) }
            recoverSecureGuardUseCase(recoveryCode, newPin)
                .onSuccess { newRc ->
                    countdownJob?.cancel()
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            generatedRecoveryCode = newRc,
                            successMessage = "Cofre recuperado! Novo PIN definido.",
                            isUnlockPromptOpen = false
                        )
                    }
                    refreshStatus()
                }
                .onFailure { t ->
                    _uiState.update { it.copy(isLoading = false, errorMessage = t.message) }
                }
        }
    }

    fun updatePolicy(policy: SecureGuardPolicy) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, errorMessage = null) }
            updateSecureGuardPolicyUseCase(policy)
                .onSuccess { updated ->
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            status = it.status.copy(policy = updated),
                            successMessage = "Políticas do Secure Guard atualizadas com sucesso."
                        )
                    }
                }
                .onFailure { t ->
                    _uiState.update { it.copy(isLoading = false, errorMessage = t.message) }
                }
        }
    }

    fun wipeSelective(scope: Int = 0, confirmationToken: String) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, errorMessage = null) }
            triggerSelectiveWipeTestUseCase(scope, confirmationToken)
                .onSuccess { simulated ->
                    countdownJob?.cancel()
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            successMessage = if (simulated) "Simulação de wipe concluída!" else "Wipe seletivo executado com sucesso."
                        )
                    }
                    refreshStatus()
                }
                .onFailure { t ->
                    _uiState.update { it.copy(isLoading = false, errorMessage = t.message) }
                }
        }
    }

    fun openUnlockPrompt() {
        _uiState.update { it.copy(isUnlockPromptOpen = true, errorMessage = null) }
    }

    fun dismissUnlockPrompt() {
        _uiState.update { it.copy(isUnlockPromptOpen = false, errorMessage = null) }
    }

    fun clearMessages() {
        _uiState.update { it.copy(errorMessage = null, successMessage = null) }
    }
}
