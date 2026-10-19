package dev.aegiskey.app.security

import android.content.Context
import android.view.Window
import android.view.WindowManager
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * App security primitives.
 *
 * Invariants (see docs/app-journey.md):
 * - Secrets/keys are NEVER persisted. [SecureStore] holds only non-secret
 *   metadata (e.g. user-chosen device label) under EncryptedSharedPreferences.
 * - [SanitizedLog] records fixed event names only — never values, accounts,
 *   codes, SSIDs or envelopes. Safe to display in Settings.
 * - Code screens run under FLAG_SECURE (set once in MainActivity).
 */
object SanitizedLog {
    enum class Event {
        SCAN_STARTED,
        DEVICE_CONNECTED,
        BOND_CHANGED,
        REVISION_OK,
        REVISION_MISMATCH,
        STATUS_NOTIFY,
        CTAP_SENT,
        CTAP_RESPONSE,
        OATH_FETCHED,
        WIFI_PASSWORD_CHANGED,
        LOCAL_WIPE,
        APP_LOCK_SET,
        APP_UNLOCKED,
        APP_LOCK_FAILED,
        DEVICE_PRESS_CANCELLED,
        INTEGRITY_CHECK,
    }

    private const val MAX_EVENTS = 128
    private val ring = ArrayDeque<String>(MAX_EVENTS)

    @Synchronized
    fun record(event: Event) {
        if (ring.size >= MAX_EVENTS) ring.removeFirst()
        ring.addLast("${System.currentTimeMillis()}/$event")
    }

    @Synchronized
    fun snapshot(): List<String> = ring.toList()
}

/** Encrypted metadata store. Non-secret values only — never keys/secrets. */
class SecureStore(context: Context) {
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "aegis_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun lastDeviceLabel(): String? = prefs.getString("last_device", null)

    fun setLastDeviceLabel(label: String) {
        prefs.edit().putString("last_device", label.take(64)).apply()
    }

    /** Local wipe (double-confirmed in Settings). Device state untouched. */
    fun wipeAll() {
        prefs.edit().clear().apply()
        SanitizedLog.record(SanitizedLog.Event.LOCAL_WIPE)
    }
}

/** Blocks screenshots / recent-apps thumbnails on code screens. */
fun applyScreenshotProtection(window: Window) {
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
}

/**
 * Play Integrity hook (stub). Wire `com.google.android.play:integrity` here
 * before release; fail closed on verdict mismatch. Until enrolled this
 * returns [Result.Unavailable] and logs only the event name.
 */
object PlayIntegrity {
    sealed interface Result {
        data object Unavailable : Result
        data object Passed : Result
        data class Failed(val code: String) : Result
    }

    fun check(): Result {
        SanitizedLog.record(SanitizedLog.Event.INTEGRITY_CHECK)
        // TODO(release): request integrity token, verify on server, fail closed.
        return Result.Unavailable
    }
}
