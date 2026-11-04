package dev.aegiskey.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import dev.aegiskey.app.di.AppContainer
import dev.aegiskey.app.domain.repository.PmGateError
import dev.aegiskey.app.domain.usecase.GetPmListUseCase
import dev.aegiskey.app.domain.usecase.GetPmReleaseUseCase
import dev.aegiskey.app.domain.usecase.GetPmStatusUseCase
import dev.aegiskey.app.pm.PmCbor
import dev.aegiskey.app.ui.VaultGate
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * Blind-transport viewer state. The phone keeps opaque record ids in
 * RAM only (never disk/log/screenshot payload) and a single transient
 * [PmCbor.PmRelease] while its dialog is open — [closeRelease] wipes it.
 * Gate denials surface as [VaultGate] with the same UX as the vault tabs.
 */
data class PasswordManagerUiState(
    val ids: List<ByteArray> = emptyList(),
    val query: String = "",
    val nextCursor: Long = 0L,
    val hasMore: Boolean = false,
    val entryCount: Long? = null,
    val maxEntries: Long? = null,
    val release: PmCbor.PmRelease? = null,
    val releaseIdHex: String? = null,
    val gate: VaultGate = VaultGate.READY,
    val isLoading: Boolean = false,
    val isReleaseLoading: Boolean = false,
    val userMessage: String? = null,
    val errorMessage: String? = null,
) {
    /** In-memory filter over opaque-id hex handles (device holds no index). */
    val visibleIds: List<ByteArray>
        get() {
            val q = query.trim().lowercase()
            if (q.isEmpty()) return ids
            return ids.filter { PmCbor.opaqueIdHex(it).contains(q) }
        }
}

class PasswordManagerViewModel(
    private val getList: GetPmListUseCase,
    private val getRelease: GetPmReleaseUseCase,
    private val getStatus: GetPmStatusUseCase,
) : ViewModel() {

    private val _uiState = MutableStateFlow(PasswordManagerUiState())
    val uiState: StateFlow<PasswordManagerUiState> = _uiState.asStateFlow()

    init {
        refresh()
    }

    fun clearMessages() {
        _uiState.update { it.copy(userMessage = null, errorMessage = null, gate = VaultGate.READY) }
    }

    fun setQuery(q: String) {
        _uiState.update { it.copy(query = q) }
    }

    fun refresh() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, gate = VaultGate.READY) }
            try {
                val listRes = getList(0L, PmCbor.PM_LIST_DEFAULT_LIMIT)
                listRes.onSuccess { res ->
                    _uiState.update {
                        it.copy(
                            ids = res.page.ids.map { id -> id.copyOf() },
                            nextCursor = res.page.nextCursor,
                            hasMore = res.page.hasMore,
                            errorMessage = null,
                            gate = VaultGate.READY,
                        )
                    }
                }.onFailure { err ->
                    applyGateFailure(err)
                }
                getStatus().onSuccess { st ->
                    _uiState.update { it.copy(entryCount = st.entryCount, maxEntries = st.maxEntries) }
                }
            } finally {
                _uiState.update { it.copy(isLoading = false) }
            }
        }
    }

    fun loadMore() {
        val cur = _uiState.value
        if (cur.isLoading || !cur.hasMore) return
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true) }
            try {
                getList(cur.nextCursor, PmCbor.PM_LIST_DEFAULT_LIMIT)
                    .onSuccess { res ->
                        _uiState.update {
                            it.copy(
                                ids = it.ids + res.page.ids.map { id -> id.copyOf() },
                                nextCursor = res.page.nextCursor,
                                hasMore = res.page.hasMore,
                            )
                        }
                    }
                    .onFailure { err -> applyGateFailure(err) }
            } finally {
                _uiState.update { it.copy(isLoading = false) }
            }
        }
    }

    fun openRelease(id: ByteArray) {
        val idCopy = id.copyOf()
        viewModelScope.launch {
            _uiState.update { it.copy(isReleaseLoading = true, gate = VaultGate.READY) }
            try {
                getRelease(idCopy).onSuccess { rel ->
                    _uiState.value.release?.wipe()
                    _uiState.update {
                        it.copy(
                            release = rel,
                            releaseIdHex = PmCbor.opaqueIdHex(rel.id),
                            errorMessage = null,
                        )
                    }
                }.onFailure { err ->
                    applyGateFailure(err)
                }
            } finally {
                _uiState.update { it.copy(isReleaseLoading = false) }
            }
        }
    }

    /**
     * Closes the release dialog and zeroizes the transient secret +
     * username buffers. Must run on every dialog dismiss (confirm or
     * cancel) so nothing survives the frame.
     */
    fun closeRelease() {
        _uiState.value.release?.wipe()
        _uiState.update { it.copy(release = null, releaseIdHex = null) }
    }

    private fun applyGateFailure(err: Throwable) {
        val gateErr = err as? PmGateError
        val gate = when (gateErr?.kind) {
            PmGateError.Kind.NEED_BINDING -> VaultGate.NEED_BINDING
            PmGateError.Kind.PRESENCE_REQUIRED -> VaultGate.NEED_UP
            PmGateError.Kind.PIN_REQUIRED -> VaultGate.NEED_PIN
            PmGateError.Kind.NO_TRANSPORT -> VaultGate.NO_BLE
            else -> VaultGate.READY
        }
        _uiState.update {
            it.copy(
                errorMessage = if (gate == VaultGate.READY) {
                    (err.message ?: "Password vault denied").take(120)
                } else {
                    null
                },
                gate = gate,
            )
        }
    }

    override fun onCleared() {
        _uiState.value.release?.wipe()
        super.onCleared()
    }

    companion object {
        fun provideFactory(container: AppContainer): ViewModelProvider.Factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return PasswordManagerViewModel(
                        getList = container.getPmListUseCase,
                        getRelease = container.getPmReleaseUseCase,
                        getStatus = container.getPmStatusUseCase,
                    ) as T
                }
            }
    }
}
