package dev.aegiskey.app.data.repository

import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.transport.BleKeyTransport
import dev.aegiskey.app.data.transport.UsbKeyTransport
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.SecurityToggles
import dev.aegiskey.app.domain.repository.ConnectedKeysRepository
import dev.aegiskey.app.net.WifiApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ConnectedKeysRepositoryImpl(
    private val keysStore: EncryptedKeysStore,
    private val usbKeyTransport: UsbKeyTransport? = null,
    private val bleKeyTransport: BleKeyTransport? = null,
    scope: CoroutineScope = CoroutineScope(Dispatchers.IO)
) : ConnectedKeysRepository {

    constructor(
        keysStore: EncryptedKeysStore,
        scope: CoroutineScope
    ) : this(keysStore, null, null, scope)

    private val _connectedKeys = MutableStateFlow(keysStore.loadConnectedKeys())
    override val connectedKeys: StateFlow<List<ConnectedKeyDevice>> = _connectedKeys.asStateFlow()

    private val _activeKey = MutableStateFlow(resolveInitialActiveKey())
    override val activeKey: StateFlow<ConnectedKeyDevice?> = _activeKey.asStateFlow()

    override val hasAnyConnectedKey: StateFlow<Boolean> = _connectedKeys
        .map { it.isNotEmpty() }
        .stateIn(scope, SharingStarted.Eagerly, _connectedKeys.value.isNotEmpty())

    init {
        if (usbKeyTransport != null || bleKeyTransport != null) {
            val monitorScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            monitorScope.launch {
                while (isActive) {
                    delay(2000)
                    val currentActive = _activeKey.value ?: continue
                    val isConnectedReal = when (currentActive.transportType) {
                        ConnectionTransportType.USB -> {
                            usbKeyTransport?.isPhysicallyReachable() ?: false
                        }
                        ConnectionTransportType.WIFI -> {
                            (usbKeyTransport?.isPhysicallyReachable() ?: false) || WifiApi.testConnection("http://192.168.4.1")
                        }
                        ConnectionTransportType.BLE -> {
                            (bleKeyTransport?.isConnected?.value ?: false) ||
                            (bleKeyTransport?.isPhysicallyReachable() ?: false) ||
                            (usbKeyTransport?.isPhysicallyReachable() ?: false)
                        }
                        ConnectionTransportType.SIMULATOR -> {
                            true
                        }
                    }

                    if (currentActive.isCurrentlyConnected != isConnectedReal) {
                        _activeKey.update { it?.copy(isCurrentlyConnected = isConnectedReal) }
                        _connectedKeys.update { list ->
                            list.map { key ->
                                if (key.id == currentActive.id) key.copy(isCurrentlyConnected = isConnectedReal) else key
                            }
                        }
                    }
                }
            }
        }
    }

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
