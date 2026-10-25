package dev.aegiskey.app.data.repository

import dev.aegiskey.app.data.local.ThemePreferencesStore
import dev.aegiskey.app.domain.model.AppThemeMode
import dev.aegiskey.app.domain.model.AppThemePreference
import dev.aegiskey.app.domain.repository.ThemeRepository
import kotlinx.coroutines.flow.StateFlow

class ThemeRepositoryImpl(
    private val themePreferencesStore: ThemePreferencesStore
) : ThemeRepository {

    override val themePreference: StateFlow<AppThemePreference> =
        themePreferencesStore.themePreference

    override suspend fun setThemeMode(mode: AppThemeMode) {
        themePreferencesStore.setThemeMode(mode)
    }

    override suspend fun setDynamicColors(enabled: Boolean) {
        themePreferencesStore.setDynamicColors(enabled)
    }
}
