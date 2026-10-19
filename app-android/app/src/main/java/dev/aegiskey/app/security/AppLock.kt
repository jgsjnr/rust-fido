package dev.aegiskey.app.security

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import dev.aegiskey.app.bridge.AegisBridge
import java.security.MessageDigest
import java.security.SecureRandom

private const val PREFS_FILE = "aegis_applock"
private const val KEY_SALT = "applock_salt_b64"
private const val KEY_VERIFIER = "applock_verifier_b64"
private const val SALT_BYTES = 16

/** Minimum app-lock password length (local hint; the bridge enforces 1..128B). */
const val MIN_APP_PASSWORD_LEN = 8

/**
 * Wave7 app lock: local password gate reusing the Rust bridge PBKDF2-SHA1
 * (AegisBridge.appLockDerive — the same primitive as YKOATH set_password).
 * No new crypto: the KDF lives in the bridge; only salt + verifier are kept,
 * inside EncryptedSharedPreferences. The password itself is never persisted.
 * Fail closed: without the native lib every derive throws.
 *
 * [derive] consumes and zeroizes the given password array; callers pass a
 * fresh copy and drop their own reference afterwards.
 */
class AppLock(context: Context) {
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        PREFS_FILE,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun isEnrolled(): Boolean =
        prefs.contains(KEY_SALT) && prefs.contains(KEY_VERIFIER)

    fun enroll(password: CharArray) {
        require(password.size >= MIN_APP_PASSWORD_LEN) { "password too short" }
        val salt = ByteArray(SALT_BYTES).also { SecureRandom().nextBytes(it) }
        val verifier = derive(password, salt)
        prefs.edit()
            .putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
            .putString(KEY_VERIFIER, Base64.encodeToString(verifier, Base64.NO_WRAP))
            .apply()
        SanitizedLog.record(SanitizedLog.Event.APP_LOCK_SET)
    }

    fun verify(password: CharArray): Boolean {
        val saltB64 = prefs.getString(KEY_SALT, null) ?: return false
        val expectB64 = prefs.getString(KEY_VERIFIER, null) ?: return false
        return try {
            val salt = Base64.decode(saltB64, Base64.NO_WRAP)
            val expect = Base64.decode(expectB64, Base64.NO_WRAP)
            val got = derive(password, salt)
            val ok = MessageDigest.isEqual(got, expect)
            SanitizedLog.record(
                if (ok) SanitizedLog.Event.APP_UNLOCKED else SanitizedLog.Event.APP_LOCK_FAILED
            )
            ok
        } catch (_: Exception) {
            false
        }
    }

    fun clear() {
        prefs.edit().remove(KEY_SALT).remove(KEY_VERIFIER).apply()
    }

    private fun derive(password: CharArray, salt: ByteArray): ByteArray {
        val bytes = password.concatToString().toByteArray(Charsets.UTF_8)
        try {
            return AegisBridge.appLockDerive(bytes, salt).getOrThrow()
        } finally {
            bytes.fill(0)
            password.fill('\u0000')
        }
    }
}
