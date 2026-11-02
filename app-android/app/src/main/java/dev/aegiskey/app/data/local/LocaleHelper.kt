package dev.aegiskey.app.data.local

import android.content.Context
import android.content.res.Configuration
import java.util.Locale

/**
 * Applies the persisted [LocalePreferencesStore] language to a [Context].
 * Manual resource-configuration override (no appcompat dependency):
 * [MainActivity.attachBaseContext] wraps the base context, and the settings
 * screen triggers `Activity.recreate()` after a change.
 */
object LocaleHelper {

    fun wrap(base: Context, tag: String): Context {
        if (tag == LocalePreferencesStore.TAG_SYSTEM) return base
        val locale = localeFor(tag)
        Locale.setDefault(locale)
        val config = Configuration(base.resources.configuration)
        config.setLocale(locale)
        return base.createConfigurationContext(config)
    }

    fun localeFor(tag: String): Locale = when (tag) {
        LocalePreferencesStore.TAG_PORTUGUESE -> Locale.forLanguageTag("pt-BR")
        LocalePreferencesStore.TAG_ENGLISH -> Locale.ENGLISH
        else -> Locale.getDefault()
    }
}
