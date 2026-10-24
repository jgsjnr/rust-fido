package dev.aegiskey.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import dev.aegiskey.app.di.AppContainer
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.SecurityToggles
import dev.aegiskey.app.domain.repository.ConnectedKeysRepository
import dev.aegiskey.app.domain.usecase.GetActiveKeyUseCase
import dev.aegiskey.app.domain.usecase.GetConnectedKeysUseCase
import dev.aegiskey.app.domain.usecase.RemoveKeyUseCase
import dev.aegiskey.app.domain.usecase.RenameKeyUseCase
import dev.aegiskey.app.domain.usecase.SelectActiveKeyUseCase
import dev.aegiskey.app.domain.usecase.UpdateKeySecurityTogglesUseCase
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class ConnectedKeysUiState(
    val keys: List<ConnectedKeyDevice> = emptyList(),
    val activeKey: ConnectedKeyDevice? = null,
    val hasAnyKey: Boolean = false,
    val isLoading: Boolean = false,
    val userFeedbackMessage: String? = null
)

class ConnectedKeysViewModel(
    private val connectedKeysRepository: ConnectedKeysRepository,
    private val getConnectedKeysUseCase: GetConnectedKeysUseCase,
    private val getActiveKeyUseCase: GetActiveKeyUseCase,
    private val selectActiveKeyUseCase: SelectActiveKeyUseCase,
    private val renameKeyUseCase: RenameKeyUseCase,
    private val removeKeyUseCase: RemoveKeyUseCase,
    private val updateKeySecurityTogglesUseCase: UpdateKeySecurityTogglesUseCase,
) : ViewModel() {

    val connectedKeys: StateFlow<List<ConnectedKeyDevice>> = getConnectedKeysUseCase()
    val activeKey: StateFlow<ConnectedKeyDevice?> = getActiveKeyUseCase()
    val hasAnyConnectedKey: StateFlow<Boolean> = connectedKeysRepository.hasAnyConnectedKey

    private val _userFeedbackMessage = MutableStateFlow<String?>(null)
    val userFeedbackMessage: StateFlow<String?> = _userFeedbackMessage.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    val uiState: StateFlow<ConnectedKeysUiState> = combine(
        connectedKeys,
        activeKey,
        hasAnyConnectedKey,
        _isLoading,
        _userFeedbackMessage
    ) { keys, active, hasAny, loading, message ->
        ConnectedKeysUiState(
            keys = keys,
            activeKey = active,
            hasAnyKey = hasAny,
            isLoading = loading,
            userFeedbackMessage = message
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = ConnectedKeysUiState(
            keys = connectedKeys.value,
            activeKey = activeKey.value,
            hasAnyKey = hasAnyConnectedKey.value
        )
    )

    fun clearFeedback() {
        _userFeedbackMessage.value = null
    }

    fun selectKey(id: String) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                selectActiveKeyUseCase(id)
                val selectedName = connectedKeys.value.firstOrNull { it.id == id }?.displayName ?: "Chave"
                _userFeedbackMessage.value = "$selectedName agora é a chave ativa."
            } finally {
                _isLoading.value = false
            }
        }
    }

    fun renameKey(id: String, newName: String) {
        viewModelScope.launch {
            val clean = newName.trim().take(32)
            if (clean.isBlank()) return@launch
            _isLoading.value = true
            try {
                renameKeyUseCase(id, clean)
                _userFeedbackMessage.value = "Chave renomeada para \"$clean\" com sucesso."
            } finally {
                _isLoading.value = false
            }
        }
    }

    fun removeKey(id: String) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                val removedName = connectedKeys.value.firstOrNull { it.id == id }?.displayName ?: "Chave"
                removeKeyUseCase(id)
                _userFeedbackMessage.value = "$removedName desconectada e removida com segurança."
            } finally {
                _isLoading.value = false
            }
        }
    }

    fun updateToggles(id: String, toggles: SecurityToggles) {
        viewModelScope.launch {
            updateKeySecurityTogglesUseCase(id, toggles)
        }
    }

    companion object {
        fun provideFactory(container: AppContainer): ViewModelProvider.Factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return ConnectedKeysViewModel(
                        connectedKeysRepository = container.connectedKeysRepository,
                        getConnectedKeysUseCase = container.getConnectedKeysUseCase,
                        getActiveKeyUseCase = container.getActiveKeyUseCase,
                        selectActiveKeyUseCase = container.selectActiveKeyUseCase,
                        renameKeyUseCase = container.renameKeyUseCase,
                        removeKeyUseCase = container.removeKeyUseCase,
                        updateKeySecurityTogglesUseCase = container.updateKeySecurityTogglesUseCase,
                    ) as T
                }
            }
    }
}
