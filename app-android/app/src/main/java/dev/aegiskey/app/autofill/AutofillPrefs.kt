package dev.aegiskey.app.autofill

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * Master switch for vault autofill in other apps.
 *
 * Fail-closed default OFF: a fresh install (or a cleared preference)
 * offers nothing until the user explicitly enables it in Settings AND
 * selects AegisKey as the system autofill service. The switch gates
 * only the *offer*; every fill additionally requires a live Secure
 * Guard session ([AutofillGate]).
 */
class AutofillPrefs(context: Context?) {

    private val prefs: SharedPreferences? = try {
        context?.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    } catch (_: Throwable) {
        null
    }

    private val _enabled = MutableStateFlow(loadInitial())
    val enabled: StateFlow<Boolean> = _enabled.asStateFlow()

    private fun loadInitial(): Boolean =
        try {
            prefs?.getBoolean(KEY_ENABLED, DEFAULT_ENABLED) ?: DEFAULT_ENABLED
        } catch (_: Throwable) {
            DEFAULT_ENABLED
        }

    fun isEnabled(): Boolean = _enabled.value

    fun setEnabled(value: Boolean) {
        _enabled.update { value }
        runCatching { prefs?.edit()?.putBoolean(KEY_ENABLED, value)?.apply() }
    }

    companion object {
        const val DEFAULT_ENABLED = false
        private const val PREFS_NAME = "aegis_autofill_preferences"
        private const val KEY_ENABLED = "autofill_enabled"
    }
}
