package dev.aegiskey.app.domain.repository

import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.SecurityToggles
import kotlinx.coroutines.flow.StateFlow

interface ConnectedKeysRepository {
    val connectedKeys: StateFlow<List<ConnectedKeyDevice>>
    val activeKey: StateFlow<ConnectedKeyDevice?>
    val hasAnyConnectedKey: StateFlow<Boolean>

    suspend fun addOrUpdateKey(device: ConnectedKeyDevice)
    suspend fun selectActiveKey(keyId: String)
    suspend fun updateKeyToggles(keyId: String, toggles: SecurityToggles)
    suspend fun renameKey(keyId: String, newName: String)
    suspend fun removeKey(keyId: String)
}
