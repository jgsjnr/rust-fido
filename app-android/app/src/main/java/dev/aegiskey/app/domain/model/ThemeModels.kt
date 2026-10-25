package dev.aegiskey.app.domain.model

enum class AppThemeMode { SYSTEM, LIGHT, DARK }

data class AppThemePreference(
    val mode: AppThemeMode = AppThemeMode.SYSTEM,
    val useDynamicColors: Boolean = true
)
