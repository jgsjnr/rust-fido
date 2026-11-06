package dev.aegiskey.app.security

import android.app.Activity
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import dev.aegiskey.app.R
import java.security.KeyStore
import java.security.Signature

/**
 * Wave7 biometric gate: BiometricPrompt + CryptoObject bound to the
 * AndroidKeyStore [BindingKey] P-256 key (user-auth-bound, StrongBox/TEE).
 *
 * Fail-closed: [cryptoObject] returns null when the KeyStore, the key, the
 * Signature instance, or the biometric sensor is unavailable. Callers fall
 * back to the password lock while null.
 */
object BiometricGate {
    sealed interface Result {
        data object Unavailable : Result
        data object Success : Result
        data class Failed(val code: String) : Result
    }

    /**
     * Real CryptoObject bound to the AndroidKeyStore binding key.
     * Returns null (fail-closed) when the KeyStore/key/sensor is unavailable.
     */
    fun cryptoObject(): BiometricPrompt.CryptoObject? = runCatching {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val privateKey = ks.getKey(BindingKey.ALIAS, null) as? java.security.PrivateKey
            ?: return null
        Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }
    }.getOrNull()?.let { BiometricPrompt.CryptoObject(it) }

    /** Back-compat alias for the former stub; delegates to [cryptoObject]. */
    @Deprecated("Use cryptoObject() (KeyStore-bound, fail-closed).")
    fun stubCryptoObject(): BiometricPrompt.CryptoObject? = cryptoObject()

    /** True only with a usable sensor AND a real KeyStore-bound CryptoObject. */
    fun available(context: Context): Boolean {
        if (cryptoObject() == null) return false
        val mgr = context.getSystemService(BiometricManager::class.java) ?: return false
        return mgr.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }

    /** Authenticates with a caller-provided CryptoObject; fail closed on misuse. */
    fun authenticate(
        activity: Activity,
        crypto: BiometricPrompt.CryptoObject,
        onResult: (Result) -> Unit,
    ) {
        val mgr = activity.getSystemService(BiometricManager::class.java)
        if (mgr == null || mgr.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK) !=
            BiometricManager.BIOMETRIC_SUCCESS
        ) {
            onResult(Result.Unavailable)
            return
        }
        val prompt = BiometricPrompt.Builder(activity)
            .setTitle(activity.getString(R.string.biogate_title))
            .setSubtitle(activity.getString(R.string.biogate_subtitle))
            .setNegativeButton(activity.getString(R.string.biogate_use_pw), activity.mainExecutor) { _, _ ->
                onResult(Result.Unavailable)
            }
            .build()
        prompt.authenticate(
            crypto,
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                    onResult(Result.Success)
                }

                override fun onAuthenticationFailed() {
                    onResult(Result.Failed("mismatch"))
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                    onResult(Result.Failed("error-$errorCode"))
                }
            }
        )
    }
}
