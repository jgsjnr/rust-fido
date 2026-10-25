package dev.aegiskey.app.data.repository

import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.SecurityToggles
import dev.aegiskey.app.domain.repository.ConnectedKeysRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext

class ConnectedKeysRepositoryImpl(
    private val keysStore: EncryptedKeysStore,
    scope: CoroutineScope = CoroutineScope(Dispatchers.IO)
) : ConnectedKeysRepository {

    private val _connectedKeys = MutableStateFlow(keysStore.loadConnectedKeys())
    override val connectedKeys: StateFlow<List<ConnectedKeyDevice>> = _connectedKeys.asStateFlow()

    private val _activeKey = MutableStateFlow(resolveInitialActiveKey())
    override val activeKey: StateFlow<ConnectedKeyDevice?> = _activeKey.asStateFlow()

    override val hasAnyConnectedKey: StateFlow<Boolean> = _connectedKeys
        .map { it.isNotEmpty() }
        .stateIn(scope, SharingStarted.Eagerly, _connectedKeys.value.isNotEmpty())

    private fun resolveInitialActiveKey(): ConnectedKeyDevice? {
        val initialKeys = keysStore.loadConnectedKeys()
        val savedId = keysStore.loadActiveKeyId()
        return initialKeys.firstOrNull { it.id == savedId } ?: initialKeys.firstOrNull()
    }

    override suspend fun addOrUpdateKey(device: ConnectedKeyDevice) = withContext(Dispatchers.IO) {
        _connectedKeys.update { current ->
            val index = current.indexOfFirst { it.id == device.id }
            val updated = if (index >= 0) {
                current.toMutableList().apply { set(index, device) }
            } else {
                current + device
            }
            keysStore.saveConnectedKeys(updated)
            updated
        }
        if (_activeKey.value == null || _activeKey.value?.id == device.id) {
            _activeKey.value = device
            keysStore.saveActiveKeyId(device.id)
        }
    }

    override suspend fun selectActiveKey(keyId: String) = withContext(Dispatchers.IO) {
        val target = _connectedKeys.value.firstOrNull { it.id == keyId }
        if (target != null) {
            _activeKey.value = target
            keysStore.saveActiveKeyId(keyId)
        }
    }

    override suspend fun updateKeyToggles(keyId: String, toggles: SecurityToggles) = withContext(Dispatchers.IO) {
        _connectedKeys.update { current ->
            val updated = current.map {
                if (it.id == keyId) it.copy(toggles = toggles) else it
            }
            keysStore.saveConnectedKeys(updated)
            updated
        }
        if (_activeKey.value?.id == keyId) {
            _activeKey.update { it?.copy(toggles = toggles) }
        }
    }

    override suspend fun renameKey(keyId: String, newName: String) = withContext(Dispatchers.IO) {
        val trimmed = newName.trim().take(32)
        if (trimmed.isEmpty()) return@withContext

        _connectedKeys.update { current ->
            val updated = current.map {
                if (it.id == keyId) it.copy(displayName = trimmed) else it
            }
            keysStore.saveConnectedKeys(updated)
            updated
        }
        if (_activeKey.value?.id == keyId) {
            _activeKey.update { it?.copy(displayName = trimmed) }
        }
    }

    override suspend fun removeKey(keyId: String) = withContext(Dispatchers.IO) {
        _connectedKeys.update { current ->
            val updated = current.filterNot { it.id == keyId }
            keysStore.saveConnectedKeys(updated)
            updated
        }
        if (_activeKey.value?.id == keyId) {
            val nextActive = _connectedKeys.value.firstOrNull()
            _activeKey.value = nextActive
            keysStore.saveActiveKeyId(nextActive?.id)
        }
    }
}
