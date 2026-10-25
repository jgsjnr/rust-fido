package dev.aegiskey.app.data.local

import android.content.Context
import android.content.SharedPreferences
import dev.aegiskey.app.domain.model.AppThemeMode
import dev.aegiskey.app.domain.model.AppThemePreference
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * Armazena e expõe de forma reativa as preferências de tema do app (modo claro/escuro e cores dinâmicas).
 */
class ThemePreferencesStore(private val context: Context?) {

    private val prefs: SharedPreferences? = try {
        context?.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    } catch (_: Throwable) {
        null
    }

    private val _themePreference = MutableStateFlow(loadInitialPreference())
    val themePreference: StateFlow<AppThemePreference> = _themePreference.asStateFlow()

    private fun loadInitialPreference(): AppThemePreference {
        val modeStr = prefs?.getString(KEY_THEME_MODE, AppThemeMode.SYSTEM.name) ?: AppThemeMode.SYSTEM.name
        val mode = try {
            AppThemeMode.valueOf(modeStr)
        } catch (_: IllegalArgumentException) {
            AppThemeMode.SYSTEM
        }
        val dynamicColors = prefs?.getBoolean(KEY_DYNAMIC_COLORS, true) ?: true
        return AppThemePreference(mode = mode, useDynamicColors = dynamicColors)
    }

    fun setThemeMode(mode: AppThemeMode) {
        _themePreference.update { it.copy(mode = mode) }
        prefs?.edit()?.putString(KEY_THEME_MODE, mode.name)?.apply()
    }

    fun setDynamicColors(enabled: Boolean) {
        _themePreference.update { it.copy(useDynamicColors = enabled) }
        prefs?.edit()?.putBoolean(KEY_DYNAMIC_COLORS, enabled)?.apply()
    }

    companion object {
        private const val PREFS_NAME = "aegis_theme_preferences"
        private const val KEY_THEME_MODE = "app_theme_mode"
        private const val KEY_DYNAMIC_COLORS = "app_use_dynamic_colors"
    }
}
