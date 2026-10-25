package dev.aegiskey.app.data.debug

import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DiscoveredKeyCandidate
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Release source set implementation of DebugHardwareChipMock.
 * Pure no-op and zero-mock implementation for production builds.
 * No test secrets, no fake MAC addresses, and mocks are strictly disabled.
 */
object DebugHardwareChipMock {

    const val IS_MOCK_ENABLED: Boolean = false
    val isDebugMode: Boolean get() = false

    val MOCK_BLE_CANDIDATE: DiscoveredKeyCandidate? = null
    val MOCK_USB_CANDIDATE: DiscoveredKeyCandidate? = null
    val MOCK_SIMULATOR_CANDIDATE: DiscoveredKeyCandidate? = null

    private val _isHoldSimulated = MutableStateFlow(false)
    val isHoldSimulated: StateFlow<Boolean> = _isHoldSimulated.asStateFlow()

    private val _isTouchSimulated = MutableStateFlow(false)
    val isTouchSimulated: StateFlow<Boolean> = _isTouchSimulated.asStateFlow()

    private val _isChipConnected = MutableStateFlow(false)
    val isChipConnected: StateFlow<Boolean> = _isChipConnected.asStateFlow()

    fun getCandidateForTransport(transport: ConnectionTransportType): DiscoveredKeyCandidate? = null

    fun isMockCandidate(candidateId: String?): Boolean = false

    fun simulateHold5s() {
        // No-op in release
    }

    fun simulateTouch() {
        // No-op in release
    }

    fun simulateToggleConnection(): Boolean = false

    fun simulateHealthPing(): String = ""

    fun seedChipDataForKey(keyId: String, store: EncryptedKeysStore) {
        // No-op in release: real hardware NVS and cryptographic operations only
    }

    fun injectExtraSample(keyId: String, store: EncryptedKeysStore) {
        // No-op in release
    }

    fun purgeResidualMockData(store: EncryptedKeysStore) {
        // No-op in release: Zero-mock production build has no mock data to purge
    }
}
