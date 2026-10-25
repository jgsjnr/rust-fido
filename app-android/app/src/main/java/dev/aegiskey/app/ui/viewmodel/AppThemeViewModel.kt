package dev.aegiskey.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import dev.aegiskey.app.di.AppContainer
import dev.aegiskey.app.domain.model.AppThemeMode
import dev.aegiskey.app.domain.model.AppThemePreference
import dev.aegiskey.app.domain.repository.ThemeRepository
import dev.aegiskey.app.domain.usecase.GetThemePreferenceUseCase
import dev.aegiskey.app.domain.usecase.SetDynamicColorsUseCase
import dev.aegiskey.app.domain.usecase.SetThemeModeUseCase
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class AppThemeViewModel(
    private val getThemePreferenceUseCase: GetThemePreferenceUseCase,
    private val setThemeModeUseCase: SetThemeModeUseCase,
    private val setDynamicColorsUseCase: SetDynamicColorsUseCase,
) : ViewModel() {

    val themePreference: StateFlow<AppThemePreference> = getThemePreferenceUseCase()

    fun setThemeMode(mode: AppThemeMode) {
        viewModelScope.launch {
            setThemeModeUseCase(mode)
        }
    }

    fun cycleThemeMode() {
        val current = themePreference.value.mode
        val next = when (current) {
            AppThemeMode.SYSTEM -> AppThemeMode.LIGHT
            AppThemeMode.LIGHT -> AppThemeMode.DARK
            AppThemeMode.DARK -> AppThemeMode.SYSTEM
        }
        setThemeMode(next)
    }

    fun setDynamicColors(enabled: Boolean) {
        viewModelScope.launch {
            setDynamicColorsUseCase(enabled)
        }
    }

    companion object {
        fun provideFactory(container: AppContainer): ViewModelProvider.Factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return AppThemeViewModel(
                        getThemePreferenceUseCase = container.getThemePreferenceUseCase,
                        setThemeModeUseCase = container.setThemeModeUseCase,
                        setDynamicColorsUseCase = container.setDynamicColorsUseCase,
                    ) as T
                }
            }
    }
}
