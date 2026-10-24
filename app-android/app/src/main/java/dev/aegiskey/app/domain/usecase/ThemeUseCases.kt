package dev.aegiskey.app.domain.usecase

import dev.aegiskey.app.domain.model.AppThemeMode
import dev.aegiskey.app.domain.model.AppThemePreference
import dev.aegiskey.app.domain.repository.ThemeRepository
import kotlinx.coroutines.flow.StateFlow

class GetThemePreferenceUseCase(
    private val repository: ThemeRepository
) {
    operator fun invoke(): StateFlow<AppThemePreference> = repository.themePreference
}

class SetThemeModeUseCase(
    private val repository: ThemeRepository
) {
    suspend operator fun invoke(mode: AppThemeMode) = repository.setThemeMode(mode)
}

class SetDynamicColorsUseCase(
    private val repository: ThemeRepository
) {
    suspend operator fun invoke(enabled: Boolean) = repository.setDynamicColors(enabled)
}
