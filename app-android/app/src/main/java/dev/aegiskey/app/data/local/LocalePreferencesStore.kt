package dev.aegiskey.app.data.local

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * Stores and exposes the app language choice (system / English / Portuguese).
 * Mirrors [ThemePreferencesStore]: SharedPreferences persistence, reactive flow.
 * Tags follow BCP-47 ("en", "pt-BR"); "system" means no override.
 */
class LocalePreferencesStore(private val context: Context?) {

    private val prefs: SharedPreferences? = try {
        context?.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    } catch (_: Throwable) {
        null
    }

    private val _languageTag = MutableStateFlow(currentTag())
    val languageTag: StateFlow<String> = _languageTag.asStateFlow()

    fun currentTag(): String =
        prefs?.getString(KEY_LANGUAGE_TAG, TAG_SYSTEM) ?: TAG_SYSTEM

    fun setLanguageTag(tag: String) {
        val safe = when (tag) {
            TAG_ENGLISH, TAG_PORTUGUESE -> tag
            else -> TAG_SYSTEM
        }
        _languageTag.update { safe }
        prefs?.edit()?.putString(KEY_LANGUAGE_TAG, safe)?.apply()
    }

    companion object {
        private const val PREFS_NAME = "aegis_locale_preferences"
        private const val KEY_LANGUAGE_TAG = "app_language_tag"
        const val TAG_SYSTEM = "system"
        const val TAG_ENGLISH = "en"
        const val TAG_PORTUGUESE = "pt-BR"
    }
}
