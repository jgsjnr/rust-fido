package dev.aegiskey.app.domain.usecase

import dev.aegiskey.app.domain.repository.ConnectedKeysRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

class GetAppStartDestinationUseCase(
    private val connectedKeysRepository: ConnectedKeysRepository
) {
    sealed interface StartDestination {
        data object OnboardingWizard : StartDestination
        data object MainHub : StartDestination
    }

    operator fun invoke(): Flow<StartDestination> {
        return connectedKeysRepository.hasAnyConnectedKey.map { hasKeys ->
            if (hasKeys) StartDestination.MainHub else StartDestination.OnboardingWizard
        }
    }
}
