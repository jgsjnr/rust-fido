package dev.aegiskey.app.security

import android.app.Activity
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.ProviderException
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Chave de vinculo do app dono (P-256 no Android Keystore).
 *
 * Espelha `crates/aegis-fido-firmware/src/binding.rs`:
 * - A chave privada NUNCA sai do celular: gerada dentro do Keystore
 *   (StrongBox quando disponivel, senao TEE) e nao-exportavel por
 *   construcao. So a publica SEC1 (65B `0x04||X||Y`) viaja, no claim.
 * - `binding_id` (16B) e sorteado pelo app e ecoado no claim
 *   (anti-confusao entre donos); guardado em EncryptedFile (metadados).
 * - Cada assinatura cobre `challenge(32) || op(1B) || sha256(dados)(32)`
 *   = 65B ([coveredMessage], mesma montagem de `signed_message`).
 *   Release usa op `0x52` (`BIND_OP_RELEASE`) sobre `sha256(binding_id)`.
 * - Cada uso da chave exige digital na hora (amarrada a biometria forte,
 *   sem timeout): sem [authenticateAndSign] a chave nao assina.
 * - Sem Log com PII: so eventos [SanitizedLog], nunca valores.
 */
object BindingKey {

    const val ALIAS = "aegis_binding_p256"
    const val BINDING_ID_BYTES = 16
    private const val BINDING_ID_FILE = "binding_id.aegis"

    private const val CHALLENGE_BYTES = 32
    private const val HASH_BYTES = 32
    private const val RAW_SIG_BYTES = 64

    /** Forca do cofre onde a chave nasceu (so texto p/ ajuda, sem PII). */
    data class KeyInfo(val strongBox: Boolean)

    sealed interface SignResult {
        data class Signed(val signatureDer: ByteArray) : SignResult
        data object Unavailable : SignResult
        data class Failed(val code: String) : SignResult
    }

    fun hasKey(): Boolean = runCatching {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        ks.containsAlias(ALIAS)
    }.getOrDefault(false)

    /**
     * Garante a chave P-256: tenta StrongBox, cai para TEE se indisponivel.
     * Idempotente (reusa se ja existir). Falha fechado com mensagem curta.
     */
    fun ensureKey(): KeyInfo {
        if (hasKey()) return KeyInfo(strongBox = isStrongBoxBacked())
        return try {
            generate(strongBox = true)
            SanitizedLog.record(SanitizedLog.Event.BINDING_KEY_CREATED)
            KeyInfo(strongBox = true)
        } catch (_: StrongBoxUnavailableException) {
            generate(strongBox = false)
            SanitizedLog.record(SanitizedLog.Event.BINDING_KEY_CREATED)
            KeyInfo(strongBox = false)
        } catch (e: ProviderException) {
            if ((e.message ?: "").contains("StrongBox", ignoreCase = true)) {
                generate(strongBox = false)
                SanitizedLog.record(SanitizedLog.Event.BINDING_KEY_CREATED)
                KeyInfo(strongBox = false)
            } else {
                throw IllegalStateException("binding key failed")
            }
        }
    }

    private fun generate(strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        gen.initialize(spec)
        gen.generateKeyPair()
    }

    private fun isStrongBoxBacked(): Boolean = runCatching {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = ks.getKey(ALIAS, null) as? java.security.PrivateKey ?: return false
        val factory = java.security.KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
        val info = factory.getKeySpec(key, android.security.keystore.KeyInfo::class.java)
        info.isInsideSecureHardware && runCatching {
            android.security.keystore.KeyInfo::class.java.getMethod("isStrongBoxBacked")
                .invoke(info) as Boolean
        }.getOrDefault(false)
    }.getOrDefault(false)

    /** Publica SEC1 em formato 0x04||X||Y (65B). A privada nunca e exposta. */
    fun publicKeyUncompressed(): ByteArray? = runCatching {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val pub = ks.getCertificate(ALIAS)?.publicKey as? ECPublicKey ?: return null
        val x = unsignedFixed(pub.w.affineX.toByteArray(), 32)
        val y = unsignedFixed(pub.w.affineY.toByteArray(), 32)
        byteArrayOf(0x04) + x + y
    }.getOrNull()

    private fun unsignedFixed(raw: ByteArray, size: Int): ByteArray {
        val stripped = raw.dropWhile { it == 0.toByte() }.toByteArray()
        require(stripped.size <= size) { "coordinate too large" }
        return ByteArray(size - stripped.size) + stripped
    }

    fun deleteKey() {
        runCatching {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                .deleteEntry(ALIAS)
        }
    }

    // -- binding_id (16B opaco em EncryptedFile, nunca segredo) -----------------

    /** Sorteia o id do vinculo (16B, TRNG). Zerar apos o envio do claim. */
    fun generateBindingId(): ByteArray =
        ByteArray(BINDING_ID_BYTES).also { SecureRandom().nextBytes(it) }

    fun saveBindingId(context: Context, bindingId: ByteArray) {
        require(bindingId.size == BINDING_ID_BYTES) { "binding_id invalido" }
        val key = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        val file = File(context.filesDir, BINDING_ID_FILE)
        EncryptedFile.Builder(
            context, file, key,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build().openFileOutput().use { it.write(bindingId) }
    }

    fun loadBindingId(context: Context): ByteArray? = runCatching {
        val file = File(context.filesDir, BINDING_ID_FILE)
        if (!file.exists()) return null
        val key = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedFile.Builder(
            context, file, key,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build().openFileInput().use { it.readBytes() }
            .takeIf { it.size == BINDING_ID_BYTES }
    }.getOrNull()

    /** Apaga vinculo local (binding_id + chave). O dispositivo sai via reset fisico. */
    fun clearBinding(context: Context) {
        runCatching { File(context.filesDir, BINDING_ID_FILE).delete() }
        deleteKey()
        SanitizedLog.record(SanitizedLog.Event.BINDING_CLEARED)
    }

    // -- mensagem coberta + assinatura ------------------------------------------

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    /**
     * Monta `challenge(32) || op(1B) || hash(32)` (65B, igual a
     * `BindingManager::signed_message`). [op] e o byte da operacao
     * (ex.: opcode vendor 0x20-0x27, ou 0x52 no release). Nunca assina aberto.
     */
    fun coveredMessage(challenge: ByteArray, op: Int, payloadHash: ByteArray): ByteArray {
        require(challenge.size == CHALLENGE_BYTES) { "challenge invalido" }
        require(op in 0..255) { "op invalida" }
        require(payloadHash.size == HASH_BYTES) { "hash invalido" }
        return challenge + op.toByte() + payloadHash
    }

    private fun signatureForSign(): Signature {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val privateKey = ks.getKey(ALIAS, null) as? java.security.PrivateKey
            ?: throw IllegalStateException("no binding key")
        return Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }
    }

    private fun biometricsReady(activity: Activity): Boolean {
        val mgr = activity.getSystemService(BiometricManager::class.java) ?: return false
        return mgr.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }

    /**
     * Pede a digital (BiometricPrompt + CryptoObject) e assina [message].
     * Sem biometria valida: [SignResult.Unavailable]. Erros curtos, sem PII.
     */
    fun authenticateAndSign(
        activity: Activity,
        title: String,
        subtitle: String,
        message: ByteArray,
        onResult: (SignResult) -> Unit,
    ) {
        if (!hasKey() || !biometricsReady(activity)) {
            onResult(SignResult.Unavailable)
            return
        }
        val signature = runCatching { signatureForSign() }.getOrNull()
        if (signature == null) {
            onResult(SignResult.Failed("key-unavailable"))
            return
        }
        val prompt = BiometricPrompt.Builder(activity)
            .setTitle(title.take(64))
            .setSubtitle(subtitle.take(128))
            .setNegativeButton("Cancelar", activity.mainExecutor) { _, _ ->
                onResult(SignResult.Failed("cancelled"))
            }
            .build()
        prompt.authenticate(
            BiometricPrompt.CryptoObject(signature),
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                    val active = result?.cryptoObject?.signature ?: signature
                    val der = runCatching {
                        active.update(message)
                        active.sign()
                    }.getOrNull()
                    if (der == null) {
                        onResult(SignResult.Failed("sign-failed"))
                    } else {
                        SanitizedLog.record(SanitizedLog.Event.BINDING_SIGNED)
                        onResult(SignResult.Signed(der))
                    }
                }

                override fun onAuthenticationFailed() {
                    onResult(SignResult.Failed("mismatch"))
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                    onResult(SignResult.Failed("error-$errorCode"))
                }
            }
        )
    }

    /**
     * Converte assinatura DER (JCA) para r||s cru (64B). O firmware aceita
     * DER ou raw (`verify_p256_sec1`); cru e menor no BLE. Funcao pura.
     */
    fun derToRawRS(der: ByteArray): ByteArray? = runCatching {
        // SEQ(0x30) len 0x02 lenR r... 0x02 lenS s...
        require(der.size >= 8 && der[0] == 0x30.toByte()) { "bad der" }
        var i = 2
        if (der[1] == 0x81.toByte()) i = 3
        require(der[i] == 0x02.toByte()) { "bad der r" }
        val lenR = der[i + 1].toInt() and 0xFF
        val r = der.copyOfRange(i + 2, i + 2 + lenR)
        val j = i + 2 + lenR
        require(der[j] == 0x02.toByte()) { "bad der s" }
        val lenS = der[j + 1].toInt() and 0xFF
        val s = der.copyOfRange(j + 2, j + 2 + lenS)
        unsignedFixed(r, 32) + unsignedFixed(s, 32)
    }.getOrNull()?.takeIf { it.size == RAW_SIG_BYTES }
}
