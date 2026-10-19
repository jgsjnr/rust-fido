package dev.aegiskey.app.security

import android.content.Context
import android.view.Window
import android.view.WindowManager
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import dev.aegiskey.app.log.DeviceLog

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
        forward(event)
    }

    @Synchronized
    fun snapshot(): List<String> = ring.toList()

    /**
     * Mirrors pairing/lock/system events into the live DeviceLog.
     * BLE FFF1/FFF2 traffic and HTTP WiFi have detailed hooks in
     * AegisBleClient/WifiApi, so those events are skipped here to
     * avoid double lines. No values ever forwarded (names only).
     */
    private fun forward(event: Event) {
        when (event) {
            Event.SCAN_STARTED -> DeviceLog.append(DeviceLog.Category.BLE, "scan 0xFFFD started")
            Event.DEVICE_CONNECTED -> DeviceLog.append(DeviceLog.Category.BLE, "device connected (GATT ready)")
            Event.BOND_CHANGED -> DeviceLog.append(DeviceLog.Category.PAIRING, "bond state changed")
            Event.REVISION_OK -> DeviceLog.append(DeviceLog.Category.BLE, "RD FFF4 revision 0x01 ok")
            Event.REVISION_MISMATCH -> DeviceLog.append(DeviceLog.Category.BLE, "RD FFF4 revision mismatch")
            Event.LOCAL_WIPE -> DeviceLog.append(DeviceLog.Category.LOCK, "local wipe done (device untouched)")
            Event.APP_LOCK_SET -> DeviceLog.append(DeviceLog.Category.LOCK, "app lock enrolled")
            Event.APP_UNLOCKED -> DeviceLog.append(DeviceLog.Category.LOCK, "app unlocked")
            Event.APP_LOCK_FAILED -> DeviceLog.append(DeviceLog.Category.LOCK, "app unlock failed")
            Event.DEVICE_PRESS_CANCELLED -> DeviceLog.append(DeviceLog.Category.BLE, "TX FFF1 OP_CANCEL(0xBE) user cancelled")
            Event.INTEGRITY_CHECK -> DeviceLog.append(DeviceLog.Category.SYSTEM, "integrity check")
            Event.STATUS_NOTIFY,
            Event.CTAP_SENT,
            Event.CTAP_RESPONSE,
            Event.OATH_FETCHED,
            Event.WIFI_PASSWORD_CHANGED -> Unit
        }
    }
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
