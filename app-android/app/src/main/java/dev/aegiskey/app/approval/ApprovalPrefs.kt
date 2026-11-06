package dev.aegiskey.app.approval

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * Master switch for approval-signal notifications.
 *
 * Fail-closed default OFF: a fresh install (or a cleared preference) posts
 * nothing until the user explicitly enables it in Settings. The switch gates
 * only the *signal*: pending approvals still wait in the app and still deny
 * without session/transport/biometry via [ApprovalSignal.evaluateApprove].
 */
class ApprovalPrefs(context: Context?) {

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
        private const val PREFS_NAME = "aegis_approval_preferences"
        private const val KEY_ENABLED = "approval_notifications_enabled"
    }
}
