package dev.aegiskey.app.ble

/**
 * Fase6 apendice 9 (docs/ble-protocol.md): Keys/OATH sobre BLE (FFF1).
 *
 * - Opcodes vendor 0x20-0x27, framing S3 reutilizado sem mudanca
 *   ([op, len_hi, len_lo, TLV...] + continuacao [seq, ..], via AegisBridge).
 * - Inner payload TLV (tag:1, len:BER, value), mesmo codec de
 *   crates/aegis-fido-core/src/oath/tlv.rs: len < 0x80 direto,
 *   0x81 + 1B, 0x82 + 2B.
 * - Response wire: [op:1, status:1, TLV...] (status S9.5).
 * - Direcao de dados S9.7: SAI so metadados/codigos; NUNCA privada/secret.
 *   Nenhum payload sensivel e logado (so opcodes/status/tamanhos).
 *
 * GEN (0x20) request normativo: 0x01 slot + 0x02 label. O algoritmo
 * (5 curvas) vai como hint privado 0x05 (i32 big-endian, 4B): decoders
 * Wave4/firmware atual ignoram tags desconhecidos per S9.6, firmware
 * futuro pode ler. Nunca reenvia como 0x83 MSG.
 */

object VendorOps {
    const val OP_KEY_GEN_ONDEVICE: Int = 0x20
    const val OP_KEY_IMPORT_ENVELOPE: Int = 0x21
    const val OP_KEY_LIST: Int = 0x22
    const val OP_KEY_DELETE: Int = 0x23
    const val OP_OATH_PUT: Int = 0x24
    const val OP_OATH_LIST: Int = 0x25
    const val OP_OATH_CODE: Int = 0x26
    const val OP_OATH_DELETE: Int = 0x27

    const val STATUS_OK: Int = 0x00
    const val STATUS_NEED_UP: Int = 0x01
    const val STATUS_NEED_PIN: Int = 0x02
    const val STATUS_NO_SLOT: Int = 0x03
    const val STATUS_BAD_ENVELOPE: Int = 0x04

    const val TAG_SLOT: Int = 0x01
    const val TAG_LABEL: Int = 0x02
    const val TAG_PUBKEY_HANDLE: Int = 0x03
    const val TAG_ENVELOPE: Int = 0x04
    /** Hint privado: algoritmo COSE i32 (4B big-endian). Ignorado per S9.6. */
    const val TAG_ALG_HINT: Int = 0x05
    /** Hint privado: mascara de uso (bit0 = assinar, bit1 = autenticar). Ignorado per S9.6. */
    const val TAG_USAGE_HINT: Int = 0x06
    const val USAGE_SIGN: Int = 0x01
    const val USAGE_AUTH: Int = 0x02

    const val TAG_OATH_NAME: Int = 0x71
    const val TAG_OATH_KEY: Int = 0x73
    const val TAG_OATH_CHALLENGE: Int = 0x74
    const val TAG_OATH_RESPONSE: Int = 0x75
    const val TAG_OATH_TRUNCATED: Int = 0x76
    const val TAG_OATH_IMF: Int = 0x7A
    /** Nibbles tipo/algo OATH (oath/types.rs): tipo alto, algoritmo baixo. */
    const val OATH_TYPE_HOTP: Int = 0x10
    const val OATH_TYPE_TOTP: Int = 0x20
    const val OATH_ALGO_SHA1: Int = 0x01

    fun statusLabel(status: Int): String = when (status) {
        STATUS_OK -> "ok"
        STATUS_NEED_UP -> "toque no dispositivo (UP)"
        STATUS_NEED_PIN -> "PIN necessario"
        STATUS_NO_SLOT -> "slot/nome inexistente"
        STATUS_BAD_ENVELOPE -> "dados invalidos"
        else -> "erro desconhecido"
    }

    /** Uma curva por entrada: 5 curvas do Rust (curves.rs) com nome amigavel. */
    data class CurveOption(val coseAlg: Int, val friendly: String, val detail: String)

    val CURVES: List<CurveOption> = listOf(
        CurveOption(-7, "P-256 (recomendada)", "WebAuthn / passkeys — ES256"),
        CurveOption(-8, "Ed25519 (moderna)", "Chaves rapidas — EdDSA"),
        CurveOption(-35, "P-384 (extra)", "Nivel maior — ES384"),
        CurveOption(-36, "P-521 (maxima)", "Nivel maximo — ES512"),
        CurveOption(-47, "secp256k1 (Bitcoin)", "Curva Koblitz — ES256K"),
    )

    fun curveForAlg(alg: Int): CurveOption? = CURVES.firstOrNull { it.coseAlg == alg }

    /** Registro TLV decodificado. */
    data class Tlv(val tag: Int, val value: ByteArray)

    /** Escreve um TLV (tag:1 + len BER + value). */
    fun writeTlv(tag: Int, value: ByteArray): ByteArray {
        require(tag in 0..255) { "bad tag" }
        require(value.size <= 0xFFFF) { "tlv too large" }
        val lenBytes = when {
            value.size < 0x80 -> byteArrayOf(value.size.toByte())
            value.size <= 0xFF -> byteArrayOf(0x81.toByte(), value.size.toByte())
            else -> byteArrayOf(
                0x82.toByte(),
                ((value.size shr 8) and 0xFF).toByte(),
                (value.size and 0xFF).toByte(),
            )
        }
        return byteArrayOf(tag.toByte()) + lenBytes + value
    }

    /** Le registros TLV (ignora tags desconhecidos no consumo, per S9.6). */
    fun parseTlvRecords(raw: ByteArray): List<Tlv> {
        val out = mutableListOf<Tlv>()
        var i = 0
        while (i < raw.size) {
            val tag = raw[i].toInt() and 0xFF
            i += 1
            if (i >= raw.size) break
            val first = raw[i].toInt() and 0xFF
            i += 1
            val len = when {
                first < 0x80 -> first
                first == 0x81 -> {
                    if (i >= raw.size) break
                    val v = raw[i].toInt() and 0xFF
                    i += 1
                    v
                }
                first == 0x82 -> {
                    if (i + 1 >= raw.size) break
                    val v = ((raw[i].toInt() and 0xFF) shl 8) or (raw[i + 1].toInt() and 0xFF)
                    i += 2
                    v
                }
                else -> break
            }
            if (i + len > raw.size) break
            out.add(Tlv(tag, raw.copyOfRange(i, i + len)))
            i += len
        }
        return out
    }

    fun findTlv(records: List<Tlv>, tag: Int): ByteArray? =
        records.firstOrNull { it.tag == tag }?.value

    /** Request GEN: 0x01 slot + 0x02 label + hint 0x05 alg + opt hint 0x06 uso (ignorados per S9.6). */
    fun genRequest(slot: Int, label: String, coseAlg: Int, usageMask: Int? = null): ByteArray {
        require(slot in 0..255) { "slot fora de 0..255" }
        val labelBytes = label.toByteArray(Charsets.UTF_8)
        require(labelBytes.size in 1..32) { "nome 1..32 letras" }
        val algBytes = byteArrayOf(
            ((coseAlg shr 24) and 0xFF).toByte(),
            ((coseAlg shr 16) and 0xFF).toByte(),
            ((coseAlg shr 8) and 0xFF).toByte(),
            (coseAlg and 0xFF).toByte(),
        )
        var req = writeTlv(TAG_SLOT, byteArrayOf(slot.toByte())) +
            writeTlv(TAG_LABEL, labelBytes) +
            writeTlv(TAG_ALG_HINT, algBytes)
        if (usageMask != null) {
            require(usageMask in 1..3) { "uso invalido" }
            req += writeTlv(TAG_USAGE_HINT, byteArrayOf(usageMask.toByte()))
        }
        return req
    }

    /** Chave listada (so metadados: slot + label, nunca privada). */
    /**
     * Request OATH_PUT (0x24): 0x71 nome + 0x73 [typeAlgo, digits, segredo...]
     * + opt 0x7A contador (HOTP, 4B big-endian). O segredo vive no buffer
     * retornado: zerar com wipe apos sendVendor (nunca persiste no celular).
     */
    fun oathPutRequest(
        name: String,
        typeAlgo: Int,
        digits: Int,
        secret: ByteArray,
        counter: Long? = null,
    ): ByteArray {
        val nameBytes = name.trim().toByteArray(Charsets.UTF_8)
        require(nameBytes.size in 1..32) { "conta 1..32 letras" }
        require(
            typeAlgo == (OATH_TYPE_TOTP or OATH_ALGO_SHA1) ||
                typeAlgo == (OATH_TYPE_HOTP or OATH_ALGO_SHA1),
        ) { "tipo invalido" }
        require(digits in 6..8) { "digitos 6..8" }
        require(secret.size in 10..64) { "segredo 10..64 bytes" }
        val key = byteArrayOf(typeAlgo.toByte(), digits.toByte()) + secret
        var req = writeTlv(TAG_OATH_NAME, nameBytes) + writeTlv(TAG_OATH_KEY, key)
        key.fill(0)
        if (counter != null) {
            require(counter in 0..0xFFFFFFFFL) { "contador invalido" }
            req += writeTlv(
                TAG_OATH_IMF,
                byteArrayOf(
                    ((counter shr 24) and 0xFF).toByte(),
                    ((counter shr 16) and 0xFF).toByte(),
                    ((counter shr 8) and 0xFF).toByte(),
                    (counter and 0xFF).toByte(),
                ),
            )
        }
        return req
    }

    data class KeyEntry(val slot: Int, val label: String)

    /** Parse LIST response TLV: repeticao de (0x01 slot + 0x02 label). */
    fun parseKeyList(tlv: ByteArray): List<KeyEntry> {
        val records = parseTlvRecords(tlv)
        val out = mutableListOf<KeyEntry>()
        var pendingSlot: Int? = null
        for (r in records) {
            when (r.tag) {
                TAG_SLOT -> pendingSlot = if (r.value.size == 1) r.value[0].toInt() and 0xFF else null
                TAG_LABEL -> {
                    val slot = pendingSlot
                    if (slot != null) {
                        val label = runCatching { r.value.toString(Charsets.UTF_8).take(32) }.getOrDefault("slot " + slot)
                        out.add(KeyEntry(slot, label))
                    }
                    pendingSlot = null
                }
                else -> Unit
            }
        }
        return out.take(64)
    }

    /** Conta OATH listada (so nome + prefixo type/algo, nunca secret). */
    data class OathEntry(val name: String)

    /** Parse OATH_LIST response: repeticao de 0x71 name. */
    fun parseOathList(tlv: ByteArray): List<OathEntry> {
        return parseTlvRecords(tlv)
            .filter { it.tag == TAG_OATH_NAME && it.value.isNotEmpty() }
            .map { r ->
                val raw = r.value
                val nameBytes = if (raw.size > 1) raw.copyOfRange(1, raw.size) else raw
                val name = runCatching { nameBytes.toString(Charsets.UTF_8).take(64) }.getOrDefault("conta")
                OathEntry(name)
            }
            .take(64)
    }

    /** Resposta vendor: [op, status, TLV...]. */
    data class VendorResponse(val op: Int, val status: Int, val tlv: ByteArray)

    fun parseResponse(raw: ByteArray?): VendorResponse? {
        if (raw == null || raw.size < 2) return null
        val op = raw[0].toInt() and 0xFF
        val status = raw[1].toInt() and 0xFF
        return VendorResponse(op, status, raw.copyOfRange(2, raw.size))
    }
}
