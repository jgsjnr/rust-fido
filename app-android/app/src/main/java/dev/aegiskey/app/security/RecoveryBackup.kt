package dev.aegiskey.app.security

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import java.io.File
import java.security.SecureRandom

/**
 * Chave-reserva (opcao A da secao "Protecao e recuperacao").
 *
 * - 32B sorteados no celular (TRNG), guardados em EncryptedFile
 *   (mesmo padrao de [BindingKey.saveBindingId]: AES256_GCM_HKDF_4KB).
 * - Sozinha ela nao abre nada: so funciona junto do seu dispositivo
 *   (o vinculo + o botao continuam mandando). E uma rede extra.
 * - Sem Log com PII: so eventos [SanitizedLog], nunca valores.
 */
object RecoveryBackup {

    const val BACKUP_KEY_BYTES = 32
    private const val BACKUP_FILE = "recovery_backup_key.aegis"

    /** Gera a chave-reserva (32B TRNG). Zerar apos salvar. */
    fun generate(): ByteArray =
        ByteArray(BACKUP_KEY_BYTES).also { SecureRandom().nextBytes(it) }

    fun hasBackup(context: Context): Boolean =
        File(context.filesDir, BACKUP_FILE).exists()

    fun save(context: Context, key: ByteArray) {
        require(key.size == BACKUP_KEY_BYTES) { "chave-reserva invalida" }
        val master = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        val file = File(context.filesDir, BACKUP_FILE)
        EncryptedFile.Builder(
            context, file, master,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build().openFileOutput().use { it.write(key) }
        SanitizedLog.record(SanitizedLog.Event.BACKUP_KEY_SAVED)
    }

    /** Apaga a chave-reserva deste celular (o dispositivo nao muda). */
    fun clear(context: Context) {
        runCatching { File(context.filesDir, BACKUP_FILE).delete() }
    }
}
