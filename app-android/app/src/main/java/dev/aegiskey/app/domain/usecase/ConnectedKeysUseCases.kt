package dev.aegiskey.app.domain.usecase

import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.SecurityToggles
import dev.aegiskey.app.domain.repository.ConnectedKeysRepository
import kotlinx.coroutines.flow.StateFlow

class GetConnectedKeysUseCase(
    private val repository: ConnectedKeysRepository
) {
    operator fun invoke(): StateFlow<List<ConnectedKeyDevice>> = repository.connectedKeys
}

class GetActiveKeyUseCase(
    private val repository: ConnectedKeysRepository
) {
    operator fun invoke(): StateFlow<ConnectedKeyDevice?> = repository.activeKey
}

class SelectActiveKeyUseCase(
    private val repository: ConnectedKeysRepository
) {
    suspend operator fun invoke(keyId: String) = repository.selectActiveKey(keyId)
}

class UpdateKeySecurityTogglesUseCase(
    private val repository: ConnectedKeysRepository
) {
    suspend operator fun invoke(keyId: String, toggles: SecurityToggles) =
        repository.updateKeyToggles(keyId, toggles)
}

class RenameKeyUseCase(
    private val repository: ConnectedKeysRepository
) {
    suspend operator fun invoke(keyId: String, newName: String) =
        repository.renameKey(keyId, newName)
}

class RemoveKeyUseCase(
    private val repository: ConnectedKeysRepository
) {
    suspend operator fun invoke(keyId: String) = repository.removeKey(keyId)
}
