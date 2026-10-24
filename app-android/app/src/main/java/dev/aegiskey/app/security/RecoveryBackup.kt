package dev.aegiskey.app.security

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Chave-reserva (opcao A da secao "Protecao e recuperacao").
 *
 * - 32B sorteados no celular (TRNG), guardados em EncryptedFile
 *   (mesmo padrao de [BindingKey.saveBindingId]: AES256_GCM_HKDF_4KB).
 * - Sozinha ela nao abre nada: so funciona junto do seu dispositivo
 *   (o vinculo + o botao continuam mandando). E uma rede extra.
 * - Sem Log com PII: so eventos [SanitizedLog], nunca valores.
 *
 * A5 backup/restore (envelope AEGN) + frase 24 + DKEK n-de-m:
 * - Facade-first: selo/abertura via [AegisBridge] (SDK/uniffi-bridge);
 *   o app nunca importa crate interna nem duplica o teto: o teto de
 *   plaintext e lido do SDK via [AegisBridge.maxPlaintextBytes].
 * - O app gera a chave (TRNG) e o device guarda SO o blob cifrado;
 *   segredo nunca em claro fora do envelope, nunca em log/prefs:
 *   so EncryptedFile p/ blobs (metadados nao-secretos lidos do
 *   proprio arquivo: tamanho/data). Sem SecureStore novo aqui.
 * - Frase 24: entropia 256 b + checksum SHA-256 (8 b) em layout
 *   24 x 11 b; exibida p/ anotacao em papel, nunca salva.
 * - DKEK: split/recover executam no device; aqui so bookkeeping de
 *   quorum (x + tamanho por share), sem reconstruir fora do device.
 * - Fakes so em teste (esta unidade nao tem fake: TRNG/SHA-256/Bridge).
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

    // -- A5: framing AEGN (espelho doc do bridge; o TETO mora no SDK) --------

    /** Magia "AEGN" (bytes 0-3; espelha bridge ENVELOPE_MAGIC). */
    val ENVELOPE_MAGIC: ByteArray = byteArrayOf(0x41, 0x45, 0x47, 0x4E)

    /** Versao do envelope (byte 4; espelha bridge ENVELOPE_VERSION). */
    const val ENVELOPE_VERSION: Byte = 0x01
    const val ENVELOPE_KEY_BYTES = 32
    const val ENVELOPE_NONCE_BYTES = 12
    const val ENVELOPE_TAG_BYTES = 16

    /** Cabecalho: magia[4] | ver[1] | nonce[12]. */
    const val ENVELOPE_HEADER_BYTES = 17

    /** Menor envelope valido (cabecalho + tag, ciphertext vazio). */
    const val ENVELOPE_MIN_BYTES = ENVELOPE_HEADER_BYTES + ENVELOPE_TAG_BYTES

    /** Pre-validacao local de formato + versao (ANTES de qualquer envio). */
    sealed interface EnvelopeCheck {
        data class Ok(val cipherBytes: Int) : EnvelopeCheck
        data object TooShort : EnvelopeCheck
        data object BadMagic : EnvelopeCheck
        data object BadVersion : EnvelopeCheck
        data object ZeroNonce : EnvelopeCheck
        data object TooLarge : EnvelopeCheck
    }

    /** Token fixo p/ log (nunca o envelope, nunca valores). */
    fun checkToken(check: EnvelopeCheck): String = when (check) {
        is EnvelopeCheck.Ok -> "ok"
        EnvelopeCheck.TooShort -> "curto"
        EnvelopeCheck.BadMagic -> "sem-magia"
        EnvelopeCheck.BadVersion -> "versao"
        EnvelopeCheck.ZeroNonce -> "nonce-zero"
        EnvelopeCheck.TooLarge -> "teto"
    }

    /** Texto honesto p/ cada recusa local (sem segredo, sem PII). */
    fun envelopeProblem(check: EnvelopeCheck): String? = when (check) {
        is EnvelopeCheck.Ok -> null
        EnvelopeCheck.TooShort -> "envelope curto demais (minimo 33 B)"
        EnvelopeCheck.BadMagic -> "magia AEGN ausente (bytes 0-3)"
        EnvelopeCheck.BadVersion -> "versao diferente de 0x01 (byte 4)"
        EnvelopeCheck.ZeroNonce -> "nonce zerado (o device nunca emite zero)"
        EnvelopeCheck.TooLarge -> "acima do teto do SDK (releia maxPlaintextBytes)"
    }

    /**
     * Valida formato + versao + tamanhos sem cripto e sem transporte.
     * [maxPlaintextBytes] e o teto lido do SDK (quando null, o teto fica
     * p/ o bridge, que nega fail-closed com Overflow).
     */
    fun preValidateEnvelope(envelope: ByteArray, maxPlaintextBytes: Int? = null): EnvelopeCheck {
        if (envelope.size < ENVELOPE_MIN_BYTES) return EnvelopeCheck.TooShort
        if (!envelope.copyOfRange(0, 4).contentEquals(ENVELOPE_MAGIC)) return EnvelopeCheck.BadMagic
        if (envelope[4] != ENVELOPE_VERSION) return EnvelopeCheck.BadVersion
        if (envelope.copyOfRange(5, ENVELOPE_HEADER_BYTES).all { it == 0.toByte() }) {
            return EnvelopeCheck.ZeroNonce
        }
        if (maxPlaintextBytes != null && envelope.size > maxPlaintextBytes + ENVELOPE_MIN_BYTES) {
            return EnvelopeCheck.TooLarge
        }
        return EnvelopeCheck.Ok(envelope.size - ENVELOPE_HEADER_BYTES)
    }

    /** Resultado do selo: envelope p/ o device + chave p/ anotar (zerar apos). */
    data class SealedExport(val envelope: ByteArray, val key: ByteArray)

    /** Chave de envelope (32B TRNG). Transitoria: zerar apos o uso. */
    fun generateEnvelopeKey(): ByteArray =
        ByteArray(ENVELOPE_KEY_BYTES).also { SecureRandom().nextBytes(it) }

    /** Nonce fresco (12B TRNG, nunca zero: o bridge rejeita nonce zerado). */
    fun freshNonce(): ByteArray {
        val nonce = ByteArray(ENVELOPE_NONCE_BYTES)
        do {
            SecureRandom().nextBytes(nonce)
        } while (nonce.all { it == 0.toByte() })
        return nonce
    }

    /**
     * Sela [plaintext] num envelope AEGN (chave+nonce TRNG transitorios).
     * Respeita o teto do SDK ([AegisBridge.maxPlaintextBytes]) antes de
     * selar; o bridge reaplica fail-closed. Na falha a chave e zerada;
     * no sucesso o chamador assume a chave (exibir 1x e zerar).
     */
    fun sealForExport(plaintext: ByteArray, aad: ByteArray = ByteArray(0)): Result<SealedExport> {
        val key = generateEnvelopeKey()
        val nonce = freshNonce()
        try {
            val ceiling = AegisBridge.maxPlaintextBytes().getOrThrow()
            if (plaintext.size > ceiling) {
                return Result.failure(IllegalStateException("payload acima do teto do SDK"))
            }
            val envelope = AegisBridge.envelopeSeal(key, plaintext, aad, nonce).getOrThrow()
            DeviceLog.append(DeviceLog.Category.SYSTEM, "backup export sealed bytes=" + envelope.size)
            return Result.success(SealedExport(envelope, key))
        } catch (e: Exception) {
            AegisBridge.wipe(key)
            return Result.failure(IllegalStateException((e.message ?: "falha ao selar").take(64)))
        } finally {
            AegisBridge.wipe(nonce)
        }
    }

    /**
     * Abre um envelope (base do restore). Pre-valida formato + versao
     * ANTES de qualquer envio/cripto; erro vira R4 honesto via
     * SdkGate.mapBridgeError no chamador. Chave transitoria (zerar apos).
     */
    fun openForImport(key: ByteArray, envelope: ByteArray, aad: ByteArray = ByteArray(0)): Result<ByteArray> {
        val pre = preValidateEnvelope(envelope)
        if (pre !is EnvelopeCheck.Ok) {
            DeviceLog.append(DeviceLog.Category.SYSTEM, "backup import recusado " + checkToken(pre))
            return Result.failure(IllegalStateException(envelopeProblem(pre)))
        }
        return try {
            val plain = AegisBridge.envelopeOpen(key, envelope, aad).getOrThrow()
            DeviceLog.append(DeviceLog.Category.SYSTEM, "backup import aberto bytes=" + plain.size)
            Result.success(plain)
        } catch (e: Exception) {
            DeviceLog.append(DeviceLog.Category.SYSTEM, "backup import falhou")
            Result.failure(IllegalStateException((e.message ?: "falha ao abrir").take(64)))
        }
    }

    // -- A5: blobs em EncryptedFile (nunca em prefs, nunca em log) -----------

    private const val ENVELOPE_DIR = "backup_envelopes"
    private const val ENVELOPE_SUFFIX = ".aegn"

    /** Ids de blob: 1-32 chars [A-Za-z0-9_-] (vira nome de arquivo). */
    fun envelopeIdValid(id: String): Boolean =
        id.length in 1..32 && id.all { it.isLetterOrDigit() || it == '-' || it == '_' }

    private fun envelopeMaster(context: Context): MasterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private fun envelopeFile(context: Context, id: String): File {
        require(envelopeIdValid(id)) { "id de envelope invalido" }
        val dir = File(context.filesDir, ENVELOPE_DIR).apply { mkdirs() }
        return File(dir, id + ENVELOPE_SUFFIX)
    }

    /** Guarda o blob cifrado (metadados: tamanho/data do proprio arquivo). */
    fun saveEnvelopeBlob(context: Context, id: String, envelope: ByteArray): Result<Int> = runCatching {
        val file = envelopeFile(context, id)
        EncryptedFile.Builder(
            context, file, envelopeMaster(context),
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        ).build().openFileOutput().use { it.write(envelope) }
        DeviceLog.append(DeviceLog.Category.SYSTEM, "backup blob salvo bytes=" + envelope.size)
        envelope.size
    }.recoverCatching { throw IllegalStateException((it.message ?: "falha ao salvar").take(64)) }

    fun loadEnvelopeBlob(context: Context, id: String): Result<ByteArray> = runCatching {
        val file = envelopeFile(context, id)
        check(file.exists()) { "blob ausente" }
        EncryptedFile.Builder(
            context, file, envelopeMaster(context),
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        ).build().openFileInput().use { it.readBytes() }
    }.recoverCatching { throw IllegalStateException((it.message ?: "falha ao ler").take(64)) }

    fun listEnvelopeIds(context: Context): List<String> =
        File(context.filesDir, ENVELOPE_DIR).listFiles()
            ?.filter { it.isFile && it.name.endsWith(ENVELOPE_SUFFIX) }
            ?.map { it.name.removeSuffix(ENVELOPE_SUFFIX) }
            ?.filter(::envelopeIdValid)
            ?.sorted() ?: emptyList()

    fun deleteEnvelopeBlob(context: Context, id: String): Boolean =
        runCatching { envelopeFile(context, id).delete() }.getOrDefault(false)

    // -- A5: frase 24 (entropia + checksum p/ anotacao, sem salvar) -----------

    const val PHRASE_ENTROPY_BYTES = 32
    const val PHRASE_WORDS = 24
    const val PHRASE_BITS_PER_WORD = 11
    const val WORDLIST_SIZE = 2048

    /** Entropia da frase (32B TRNG = a propria chave do envelope). */
    fun generatePhraseEntropy(): ByteArray =
        ByteArray(PHRASE_ENTROPY_BYTES).also { SecureRandom().nextBytes(it) }

    /** Checksum: primeiro byte do SHA-256 da entropia (8 b). */
    fun phraseChecksumByte(entropy: ByteArray): Byte {
        require(entropy.size == PHRASE_ENTROPY_BYTES) { "entropia invalida" }
        return MessageDigest.getInstance("SHA-256").digest(entropy)[0]
    }

    /**
     * 24 indices de 11 b sobre entropia(256 b) + checksum(8 b), MSB-first.
     * Sem wordlist embutida: [wordsOrIndices] resolve via lista externa
     * (2048 entradas) ou rende rotulos de indice p/ anotacao.
     */
    fun phraseIndices(entropy: ByteArray): IntArray {
        require(entropy.size == PHRASE_ENTROPY_BYTES) { "entropia invalida" }
        val stream = entropy + phraseChecksumByte(entropy)
        return IntArray(PHRASE_WORDS) { w ->
            var v = 0
            for (b in 0 until PHRASE_BITS_PER_WORD) {
                val bit = w * PHRASE_BITS_PER_WORD + b
                val byte = stream[bit / 8].toInt() and 0xFF
                v = (v shl 1) or ((byte shr (7 - (bit % 8))) and 1)
            }
            v
        }
    }

    fun toHex(bytes: ByteArray): String =
        buildString(bytes.size * 2) {
            for (b in bytes) {
                val v = b.toInt() and 0xFF
                append("0123456789abcdef"[v shr 4])
                append("0123456789abcdef"[v and 0x0F])
            }
        }

    /** Hex -> bytes (null se vazio, impar ou com digito invalido). */
    fun fromHex(hex: String): ByteArray? {
        val clean = hex.trim().lowercase()
        if (clean.isEmpty() || clean.length % 2 != 0) return null
        if (!clean.all { it in '0'..'9' || it in 'a'..'f' }) return null
        return ByteArray(clean.length / 2) { i ->
            ((clean[i * 2].digitToInt(16) shl 4) or clean[i * 2 + 1].digitToInt(16)).toByte()
        }
    }

    /**
     * Indices -> palavras (lista externa de 2048) ou rotulos honestos
     * "palavra NN #XXXX" quando a lista nao vem (o app nao inventa
     * vocabulario: sem lista, anota-se indice + entropia + checksum).
     */
    fun wordsOrIndices(indices: IntArray, wordlist: List<String>?): List<String> {
        require(indices.size == PHRASE_WORDS) { "frase invalida" }
        val wl = wordlist?.takeIf { it.size == WORDLIST_SIZE && it.all { w -> w.isNotBlank() } }
        return indices.mapIndexed { i, v ->
            if (wl != null) wl[v]
            else "palavra " + (i + 1).toString().padStart(2, '0') + " #" + v.toString().padStart(4, '0')
        }
    }

    // -- A5: DKEK n-de-m (quorum tracking; split/recover so no device) --------

    const val DKEK_MIN = 2
    const val DKEK_MAX = 32

    /** Valida 2 <= m <= n <= 32 (espelha firmware BadParams). Null = ok. */
    fun validateDkekParams(n: Int, m: Int): String? = when {
        n !in DKEK_MIN..DKEK_MAX -> "total n deve estar em 2..32"
        m !in DKEK_MIN..n -> "limiar m deve estar em 2..n"
        else -> null
    }

    /**
     * Quorum: guarda SO x + tamanho por share (nunca o conteudo y).
     * A reconstrucao executa no device; este app nunca junta shares.
     */
    class DkekQuorum(val total: Int, val threshold: Int) {
        init {
            require(validateDkekParams(total, threshold) == null) { "quorum invalido" }
        }

        private val shares = mutableMapOf<Int, Int>()

        sealed interface AddResult {
            data object Added : AddResult
            data class Rejected(val why: String) : AddResult
        }

        /** Registra presenca de um share (x 1..n, yLen 1..64). */
        fun addShare(x: Int, yLen: Int): AddResult {
            if (x !in 1..total) return AddResult.Rejected("x fora de 1..n")
            if (yLen !in 1..64) return AddResult.Rejected("tamanho fora de 1..64")
            if (shares.containsKey(x)) return AddResult.Rejected("x duplicado")
            val first = shares.values.firstOrNull()
            if (first != null && first != yLen) return AddResult.Rejected("tamanho diverge")
            shares[x] = yLen
            DeviceLog.append(DeviceLog.Category.SYSTEM, "dkek share registrado " + shares.size + " de " + total)
            return AddResult.Added
        }

        fun received(): Int = shares.size
        fun remaining(): Int = (threshold - shares.size).coerceAtLeast(0)
        fun quorumMet(): Boolean = shares.size >= threshold
        fun slots(): Map<Int, Int> = shares.toSortedMap()
    }
}