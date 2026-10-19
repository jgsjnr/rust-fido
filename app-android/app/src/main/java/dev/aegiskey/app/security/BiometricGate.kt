package dev.aegiskey.app.security

import android.app.Activity
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal

/**
 * Wave7 biometric gate (stub): full BiometricPrompt + CryptoObject wiring,
 * but the CryptoObject is a stub (null) until a release AndroidKeyStore key
 * is bound (TODO below). Callers fall back to the password lock while null.
 * Framework APIs only (minSdk 31) — no new dependency, no new crypto.
 */
object BiometricGate {
    sealed interface Result {
        data object Unavailable : Result
        data object Success : Result
        data class Failed(val code: String) : Result
    }

    /**
     * Stub CryptoObject: null until release binds an AndroidKeyStore key.
     * TODO(release): create a user-auth-bound KeyStore key, init a Cipher
     * with it, and return CryptoObject(cipher) here.
     */
    fun stubCryptoObject(): BiometricPrompt.CryptoObject? = null

    /** True only with a usable sensor AND a real CryptoObject (false in stub). */
    fun available(context: Context): Boolean {
        if (stubCryptoObject() == null) return false
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
            .setTitle("Unlock AegisKey")
            .setSubtitle("Confirm device biometrics")
            .setNegativeButton("Use password", activity.mainExecutor) { _, _ ->
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
