package dev.aegiskey.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import dev.aegiskey.app.domain.repository.SecureGuardRepository
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
    private val repository: SecureGuardRepository? = null,
) : ViewModel() {

    private val actualRepo: SecureGuardRepository
        get() = repository ?: getSecureGuardStatusUseCase.repo

    private val _uiState = MutableStateFlow(SecureGuardUiState())
    val uiState: StateFlow<SecureGuardUiState> = _uiState.asStateFlow()

    private var countdownJob: Job? = null

    init {
        viewModelScope.launch {
            actualRepo.statusFlow.collect { status ->
                if (!status.isUnlocked || status.state == SecureGuardStateEnum.LOCKED) {
                    countdownJob?.cancel()
                    countdownJob = null
                    _uiState.update { current ->
                        current.copy(
                            status = status.copy(
                                isUnlocked = false,
                                sessionRemainingMs = 0L
                            )
                        )
                    }
                } else {
                    _uiState.update { current ->
                        current.copy(status = status)
                    }
                    startCountdownTickerIfNeeded()
                }
            }
        }
        refreshStatus()
    }

    private fun sanitizeErrorMessage(t: Throwable?): String {
        if (t == null) return "Erro desconhecido ao comunicar com o cofre."
        val raw = t.message ?: t.javaClass.simpleName ?: ""

        // Proteção contra vazamento de detalhes internos ou classes JNA / JNI
        if (raw.contains("jna", ignoreCase = true) ||
            raw.contains("native", ignoreCase = true) ||
            raw.contains("UnsatisfiedLinkError", ignoreCase = true) ||
            raw.contains("NoClassDefFoundError", ignoreCase = true) ||
            raw.contains("ClassNotFoundException", ignoreCase = true) ||
            raw.contains("NullPointerException", ignoreCase = true)) {
            return "Falha na comunicação com o hardware. Verifique a conexão USB ou BLE."
        }

        // Se for erro de PIN ou autenticação
        if (t is SecurityException || raw.contains("pin", ignoreCase = true) || raw.contains("senha", ignoreCase = true)) {
            if (raw.contains("restam", ignoreCase = true) || raw.contains("tentativas", ignoreCase = true)) {
                return raw
            }
            if (raw.contains("bloqueado", ignoreCase = true) || raw.contains("limit", ignoreCase = true)) {
                return "Muitas tentativas incorretas. Aguarde o tempo de espera do cofre."
            }
            return "PIN incorreto. Tente novamente."
        }

        // Se for hardware indisponível / desconexão
        if (raw.contains("indisponível", ignoreCase = true) || raw.contains("unavailable", ignoreCase = true) ||
            raw.contains("desconectad", ignoreCase = true) || raw.contains("connection", ignoreCase = true) ||
            raw.contains("timeout", ignoreCase = true)) {
            return "Dispositivo indisponível. Conecte sua chave Aegis via USB ou BLE."
        }

        // Se for validação de tamanho de PIN
        if (raw.contains("mínimo", ignoreCase = true) || raw.contains("caracteres", ignoreCase = true) || raw.contains("dígitos", ignoreCase = true)) {
            return raw
        }

        val firstLine = raw.lines().firstOrNull()?.trim() ?: "Erro ao processar solicitação"
        return if (firstLine.length > 80) firstLine.take(80) + "..." else firstLine
    }

    private fun startCountdownTickerIfNeeded() {
        countdownJob?.cancel()
        countdownJob = null
        val current = _uiState.value.status
        if (!current.isUnlocked || (current.state != SecureGuardStateEnum.UNLOCKED && current.state != SecureGuardStateEnum.RATE_LIMITED)) {
            return
        }

        val needsTicker = (current.state == SecureGuardStateEnum.RATE_LIMITED && current.rateLimitRemainingMs > 0) ||
                (current.state == SecureGuardStateEnum.UNLOCKED && current.sessionRemainingMs > 0)

        if (!needsTicker) {
            return
        }

        countdownJob = viewModelScope.launch {
            while (isActive) {
                delay(1000L)
                val st = _uiState.value.status
                if (!st.isUnlocked && st.state != SecureGuardStateEnum.RATE_LIMITED) {
                    countdownJob?.cancel()
                    countdownJob = null
                    break
                }
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
                    countdownJob?.cancel()
                    countdownJob = null
                    if (st.state == SecureGuardStateEnum.UNLOCKED && newSess == 0L) {
                        actualRepo.onHardwareDetached()
                        viewModelScope.launch {
                            runCatching { actualRepo.lock() }
                        }
                    }
                    break
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
                    if (!status.isUnlocked || status.state == SecureGuardStateEnum.LOCKED) {
                        countdownJob?.cancel()
                        countdownJob = null
                    } else {
                        startCountdownTickerIfNeeded()
                    }
                }
                .onFailure { t ->
                    _uiState.update { it.copy(isLoading = false, errorMessage = sanitizeErrorMessage(t)) }
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
                            isUnlockPromptOpen = false,
                            status = it.status.copy(
                                state = SecureGuardStateEnum.UNLOCKED,
                                isUnlocked = true,
                                isProvisioned = true,
                                failedAttempts = 0,
                                remainingAttempts = 5,
                                sessionRemainingMs = 300_000L,
                                lastGeneratedRecoveryCode = rc
                            )
                        )
                    }
                    startCountdownTickerIfNeeded()
                }
                .onFailure { t ->
                    _uiState.update { it.copy(isLoading = false, errorMessage = sanitizeErrorMessage(t)) }
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
                            status = st.copy(
                                state = SecureGuardStateEnum.UNLOCKED,
                                isUnlocked = true,
                                isProvisioned = true,
                                failedAttempts = 0,
                                remainingAttempts = 5,
                                sessionRemainingMs = 300_000L
                            ),
                            successMessage = "Cofre desbloqueado com sucesso!",
                            isUnlockPromptOpen = false
                        )
                    }
                    startCountdownTickerIfNeeded()
                }
                .onFailure { t ->
                    val err = sanitizeErrorMessage(t)
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
            countdownJob?.cancel()
            countdownJob = null
            _uiState.update { current ->
                current.copy(
                    status = current.status.copy(
                        isUnlocked = false,
                        state = SecureGuardStateEnum.LOCKED,
                        sessionRemainingMs = 0L
                    )
                )
            }
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
                    _uiState.update { it.copy(isLoading = false, errorMessage = sanitizeErrorMessage(t)) }
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
                    _uiState.update { it.copy(isLoading = false, errorMessage = sanitizeErrorMessage(t)) }
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
                    _uiState.update { it.copy(isLoading = false, errorMessage = sanitizeErrorMessage(t)) }
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
                    _uiState.update { it.copy(isLoading = false, errorMessage = sanitizeErrorMessage(t)) }
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
                            isUnlockPromptOpen = false,
                            status = it.status.copy(
                                state = SecureGuardStateEnum.UNPROVISIONED,
                                isProvisioned = false,
                                isUnlocked = false,
                                sessionRemainingMs = 0L,
                                rateLimitRemainingMs = 0L
                            ),
                            successMessage = if (simulated) "Simulação de wipe concluída!" else "Wipe seletivo executado com sucesso."
                        )
                    }
                }
                .onFailure { t ->
                    _uiState.update { it.copy(isLoading = false, errorMessage = sanitizeErrorMessage(t)) }
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
