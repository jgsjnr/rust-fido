package dev.aegiskey.app.domain.repository

import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DiscoveredKeyCandidate
import kotlinx.coroutines.flow.StateFlow

interface PairingWizardRepository {
    val discoveredCandidates: StateFlow<List<DiscoveredKeyCandidate>>
    val isScanning: StateFlow<Boolean>
    val buttonHoldSimulatedOrDetected: StateFlow<Boolean>
    val isUsbDetected: StateFlow<Boolean>

    suspend fun startDiscovery(transport: ConnectionTransportType)
    suspend fun stopDiscovery()
    suspend fun simulatePhysicalButtonHold5s(): Result<Unit>
    suspend fun simulatePhysicalButtonSingleTouch(): Result<Unit>
    suspend fun connectToCandidate(candidate: DiscoveredKeyCandidate): Result<Unit>
    suspend fun performBiometricBinding(keyAliasName: String, recoveryPin: String?): Result<ConnectedKeyDevice>
    suspend fun autoValidatePresence(candidate: DiscoveredKeyCandidate?, transport: ConnectionTransportType): Result<Unit>
    suspend fun registerConfiguredKeyOrSkip(): Result<ConnectedKeyDevice>
    suspend fun connectUsbDeviceAndRegister(): Result<ConnectedKeyDevice>
}
