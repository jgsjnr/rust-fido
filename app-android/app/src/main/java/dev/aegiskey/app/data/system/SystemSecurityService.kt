package dev.aegiskey.app.data.system

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.os.Build
import android.os.PersistableBundle
import dev.aegiskey.app.security.BindingKey
import dev.aegiskey.app.security.BiometricGate
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Serviço de segurança integrado com o sistema operacional Android:
 * - Android KeyStore EC P-256 (StrongBox/TEE) via [BindingKey]
 * - Verificação de biometria via [BiometricGate] / [BiometricManager]
 * - Geração de números pseudo-aleatórios criptográficos (CSPRNG) via [SecureRandom]
 * - Área de transferência protegida com marcação [ClipDescription.EXTRA_IS_SENSITIVE] (Android 13+)
 */
open class SystemSecurityService(private val context: Context?) {

    private val secureRandom = SecureRandom()
    private var jvmFallbackKeyPair: KeyPair? = null
    private var jvmFallbackBindingId: ByteArray? = null

    // --- KeyStore & Binding P-256 ---

    open fun ensureBindingKey(): BindingKey.KeyInfo {
        return try {
            BindingKey.ensureKey()
        } catch (_: Throwable) {
            if (jvmFallbackKeyPair == null) {
                val kpg = KeyPairGenerator.getInstance("EC")
                kpg.initialize(ECGenParameterSpec("secp256r1"))
                jvmFallbackKeyPair = kpg.generateKeyPair()
            }
            BindingKey.KeyInfo(strongBox = false)
        }
    }

    open fun hasBindingKey(): Boolean {
        return try {
            BindingKey.hasKey()
        } catch (_: Throwable) {
            jvmFallbackKeyPair != null
        }
    }

    open fun getPublicKeyUncompressed(): ByteArray? {
        val pub = runCatching { BindingKey.publicKeyUncompressed() }.getOrNull()
        if (pub != null) return pub

        val ecPub = jvmFallbackKeyPair?.public as? ECPublicKey ?: return null
        val xRaw = ecPub.w.affineX.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        val yRaw = ecPub.w.affineY.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        val fixedX = ByteArray(32 - xRaw.size) + xRaw
        val fixedY = ByteArray(32 - yRaw.size) + yRaw
        return byteArrayOf(0x04) + fixedX + fixedY
    }

    open fun generateBindingId(): ByteArray {
        return try {
            BindingKey.generateBindingId()
        } catch (_: Throwable) {
            val b = ByteArray(16)
            secureRandom.nextBytes(b)
            b
        }
    }

    open fun saveBindingId(bindingId: ByteArray) {
        val ctx = context
        if (ctx != null) {
            runCatching { BindingKey.saveBindingId(ctx, bindingId) }
        }
        jvmFallbackBindingId = bindingId.copyOf()
    }

    open fun loadBindingId(): ByteArray? {
        val ctx = context
        return if (ctx != null) {
            runCatching { BindingKey.loadBindingId(ctx) }.getOrNull() ?: jvmFallbackBindingId
        } else {
            jvmFallbackBindingId
        }
    }

    open fun clearBinding() {
        val ctx = context
        if (ctx != null) {
            runCatching { BindingKey.clearBinding(ctx) }
        }
        jvmFallbackBindingId = null
        jvmFallbackKeyPair = null
    }

    // --- Random Generation ---

    open fun generateSecureRandomBytes(size: Int): ByteArray {
        val bytes = ByteArray(size)
        secureRandom.nextBytes(bytes)
        return bytes
    }

    /**
     * Gera um segredo Base32 aleatório (alfabeto RFC 4648) seguro para contas TOTP.
     */
    open fun generateRandomBase32Secret(byteCount: Int = 20): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val bytes = generateSecureRandomBytes(byteCount)
        val sb = StringBuilder()
        for (b in bytes) {
            val index = (b.toInt() and 0xFF) % alphabet.length
            sb.append(alphabet[index])
        }
        return sb.toString()
    }

    // --- Biometrics Availability ---

    open fun isBiometricsAvailable(): Boolean {
        val ctx = context ?: return false
        val mgr = ctx.getSystemService(BiometricManager::class.java) ?: return false
        val result = mgr.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.BIOMETRIC_WEAK
        )
        return result == BiometricManager.BIOMETRIC_SUCCESS
    }

    // --- Sensitive Clipboard (Android 13+ EXTRA_IS_SENSITIVE) ---

    open fun copySensitiveCode(label: String, sensitiveCode: String): Boolean {
        val ctx = context ?: return false
        return try {
            val clipboard = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return false
            val clip = ClipData.newPlainText(label, sensitiveCode)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val extras = PersistableBundle().apply {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                }
                clip.description.extras = extras
            }

            clipboard.setPrimaryClip(clip)
            true
        } catch (_: Throwable) {
            false
        }
    }
}
