package dev.aegiskey.app.domain.repository

import dev.aegiskey.app.domain.model.AppThemeMode
import dev.aegiskey.app.domain.model.AppThemePreference
import kotlinx.coroutines.flow.StateFlow

interface ThemeRepository {
    val themePreference: StateFlow<AppThemePreference>

    suspend fun setThemeMode(mode: AppThemeMode)
    suspend fun setDynamicColors(enabled: Boolean)
}
