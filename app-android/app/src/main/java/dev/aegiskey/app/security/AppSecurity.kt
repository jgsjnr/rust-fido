package dev.aegiskey.app.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Base64
import android.view.Window
import android.view.WindowManager
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import dev.aegiskey.app.log.DeviceLog
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull
import java.security.SecureRandom

/**
 * App security primitives.
 *
 * Invariants (see docs/app-journey.md):
 * - Secrets/keys are NEVER persisted. [SecureStore] holds only non-secret
 *   metadata (e.g. user-chosen device label) under EncryptedSharedPreferences.
 * - [SanitizedLog] records fixed event names only — never values, accounts,
 *   codes, SSIDs or envelopes. Safe to display in Settings.
 * - Code screens run under FLAG_SECURE (set once in MainActivity, disabled in debug/QA).
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
        BINDING_KEY_CREATED,
        BINDING_CLAIMED,
        BINDING_SIGNED,
        BINDING_CLEARED,
        RECOVERY_PIN_SET,
        RECOVERY_UNLOCKED,
        BACKUP_KEY_SAVED,
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
            Event.BINDING_KEY_CREATED -> DeviceLog.append(DeviceLog.Category.PAIRING, "binding key created (phone only)")
            Event.BINDING_CLAIMED -> DeviceLog.append(DeviceLog.Category.PAIRING, "binding claimed (owner set)")
            Event.BINDING_SIGNED -> DeviceLog.append(DeviceLog.Category.PAIRING, "binding challenge signed")
            Event.BINDING_CLEARED -> DeviceLog.append(DeviceLog.Category.PAIRING, "binding cleared")
            Event.RECOVERY_PIN_SET -> DeviceLog.append(DeviceLog.Category.PAIRING, "recovery pin set (device only)")
            Event.RECOVERY_UNLOCKED -> DeviceLog.append(DeviceLog.Category.PAIRING, "recovery unlock ok (re-claim free)")
            Event.BACKUP_KEY_SAVED -> DeviceLog.append(DeviceLog.Category.PAIRING, "backup key saved (phone only)")
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

/** Blocks screenshots / recent-apps thumbnails on code screens when enabled (disabled in debug/QA). */
fun applyScreenshotProtection(window: Window, forceEnable: Boolean = false) {
    if (!dev.aegiskey.app.BuildConfig.DEBUG || forceEnable) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    } else {
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
}

/**
 * Play Integrity real (sem stub): pede o token via
 * `com.google.android.play:integrity` quando presente e o entrega opaco
 * p/ verificacao no servidor. Fail-closed: sem Play, sem rede ou veredito
 * negativo nunca viram sucesso — [Result.Unavailable]/[Result.Failed].
 *
 * Sem dependencia Gradle nova (build fora do escopo): acesso por reflexao,
 * aceitando o pacote novo (`play.integrity`) e o legado
 * (`play.core.integrity`). Sem Play no device = [Result.Unavailable].
 * O token/nonce nunca entra em log (so o nome do evento, via SanitizedLog).
 */
object PlayIntegrity {
    sealed interface Result {
        /** Token opaco: so sai p/ o servidor verificar; nunca logado. */
        data class Passed(val token: String) : Result
        data object Unavailable : Result
        data class Failed(val code: String) : Result
    }

    private const val PKG_NEW = "com.google.android.play.integrity"
    private const val PKG_LEGACY = "com.google.android.play.core.integrity"
    private const val INTEGRITY_TIMEOUT_MS = 15000L
    private const val POLL_INTERVAL_MS = 100L
    private const val NONCE_BYTES = 16

    /**
     * Atestacao real. [nonce] (uso unico, uso do chamador) e copiado e a
     * copia zerada apos o uso; null = 16B TRNG. Retorna o token opaco p/
     * o servidor decidir; o app nunca interpreta o veredito localmente.
     */
    suspend fun verify(context: Context, nonce: ByteArray? = null): Result {
        SanitizedLog.record(SanitizedLog.Event.INTEGRITY_CHECK)
        val pkg = listOf(PKG_NEW, PKG_LEGACY).firstOrNull { pkgName ->
            runCatching { Class.forName("$pkgName.IntegrityManagerFactory") }.isSuccess
        } ?: return Result.Unavailable
        return try {
            val factory = Class.forName("$pkg.IntegrityManagerFactory")
            val manager = factory.getMethod("create", Context::class.java)
                .invoke(null, context.applicationContext) ?: return Result.Unavailable
            val bytes = nonce?.copyOf() ?: ByteArray(NONCE_BYTES).also { SecureRandom().nextBytes(it) }
            val nonceStr = Base64.encodeToString(
                bytes,
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
            )
            bytes.fill(0)
            val requestCls = Class.forName("$pkg.IntegrityTokenRequest")
            val builder = requestCls.getMethod("builder").invoke(null)
            builder.javaClass.getMethod("setNonce", String::class.java).invoke(builder, nonceStr)
            val request = builder.javaClass.getMethod("build").invoke(builder)
            val task = manager.javaClass.getMethod("requestIntegrityToken", requestCls)
                .invoke(manager, request) ?: return Result.Failed("no-task")
            awaitToken(task)
        } catch (_: ClassNotFoundException) {
            Result.Unavailable
        } catch (e: Exception) {
            DeviceLog.append(DeviceLog.Category.SYSTEM, "integrity request failed")
            Result.Failed((e.message ?: "integrity-failed").take(64))
        }
    }

    /**
     * Espera a Task (gms-tasks) por polling reflexivo — sem linkar
     * OnSuccessListener em compilacao. Timeout = falha, nunca sucesso.
     */
    private suspend fun awaitToken(task: Any): Result {
        val taskCls = task.javaClass
        val isComplete = runCatching { taskCls.getMethod("isComplete") }.getOrNull()
            ?: return Result.Failed("bad-task")
        val isSuccessful = runCatching { taskCls.getMethod("isSuccessful") }.getOrNull()
            ?: return Result.Failed("bad-task")
        val getResult = runCatching { taskCls.getMethod("getResult") }.getOrNull()
            ?: runCatching { taskCls.getMethod("result") }.getOrNull()
        val getException = runCatching { taskCls.getMethod("getException") }.getOrNull()
            ?: runCatching { taskCls.getMethod("exception") }.getOrNull()
        withTimeoutOrNull(INTEGRITY_TIMEOUT_MS) {
            while (!(isComplete.invoke(task) as? Boolean ?: false)) delay(POLL_INTERVAL_MS)
        } ?: return Result.Failed("timeout")
        return if ((isSuccessful.invoke(task) as? Boolean) == true && getResult != null) {
            val raw = runCatching { getResult.invoke(task) }.getOrNull()
            val token = runCatching {
                raw?.javaClass?.getMethod("token")?.invoke(raw) as? String
            }.getOrNull()
            if (token.isNullOrEmpty()) Result.Failed("empty-token")
            else Result.Passed(token)
        } else {
            val cause = runCatching { getException?.invoke(task) as? Exception }.getOrNull()
            Result.Failed((cause?.message ?: "integrity-failed").take(64))
        }
    }
}
