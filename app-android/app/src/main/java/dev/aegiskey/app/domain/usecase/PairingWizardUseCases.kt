package dev.aegiskey.app.domain.usecase

import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DiscoveredKeyCandidate
import dev.aegiskey.app.domain.repository.PairingWizardRepository

class StartDiscoveryUseCase(
    private val pairingWizardRepository: PairingWizardRepository
) {
    suspend operator fun invoke(transport: ConnectionTransportType) =
        pairingWizardRepository.startDiscovery(transport)
}

class StopDiscoveryUseCase(
    private val pairingWizardRepository: PairingWizardRepository
) {
    suspend operator fun invoke() = pairingWizardRepository.stopDiscovery()
}

class ConnectCandidateUseCase(
    private val pairingWizardRepository: PairingWizardRepository
) {
    suspend operator fun invoke(candidate: DiscoveredKeyCandidate): Result<Unit> =
        pairingWizardRepository.connectToCandidate(candidate)
}

class SimulateButtonHoldUseCase(
    private val pairingWizardRepository: PairingWizardRepository
) {
    suspend operator fun invoke(): Result<Unit> =
        pairingWizardRepository.simulatePhysicalButtonHold5s()
}

class SimulateButtonSingleTouchUseCase(
    private val pairingWizardRepository: PairingWizardRepository
) {
    suspend operator fun invoke(): Result<Unit> =
        pairingWizardRepository.simulatePhysicalButtonSingleTouch()
}

class PerformBiometricBindingUseCase(
    private val pairingWizardRepository: PairingWizardRepository
) {
    suspend operator fun invoke(keyAliasName: String, recoveryPin: String?): Result<ConnectedKeyDevice> =
        pairingWizardRepository.performBiometricBinding(keyAliasName, recoveryPin)
}
