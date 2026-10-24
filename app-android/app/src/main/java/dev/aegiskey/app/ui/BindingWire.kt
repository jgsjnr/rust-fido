package dev.aegiskey.app.ui

/**
 * Fio binding 0x28-0x2D convergente com o firmware atual.
 *
 * Formas normativas (`docs/ble-protocol.md` secao 11.1, `dispatch_bind.rs`,
 * `serial_vendor.rs::dispatch_serial_bind_mgmt`): payloads crus, sem TLV —
 * o firmware compara comprimentos exatos e rejeita qualquer outra forma
 * com `InvalidFragment (0x04)`:
 *
 * - `0x28` claim: `app_pub SEC1 (65B) || binding_id (16B)` = 81B crus;
 *   volta `[op, 0x00, binding_id(16)]` (eco cru, sem tag `0x11`).
 * - `0x29` challenge: vazio (0B — o desafio e TRNG de uso unico do
 *   device, sem parametro); volta `[op, 0x00, challenge(32)]` cru.
 * - `0x2B` release: `challenge(32) || sha256(binding_id)(32) || sig(var)`
 *   crus, onde `sig` cobre `challenge || 0x52 || sha256(binding_id)`
 *   ([BindingKey.coveredMessage]); volta `[op, 0x00]`.
 * - `0x2C/0x2D` recovery: ASCII `4..6` digitos (ver
 *   [BindingOps.recoveryPinRequest], inalterado).
 *
 * Transporte: segue o `sendVendor` padrao do app (mesma chamada das
 * demais telas). Respostas sao `[op, status, body]` (`notify_frame`).
 * So opcodes/status/tamanhos vao ao Log — nunca chaves, ids ou PINs.
 */
object BindingWire {
    /** Eco cru do claim tem 16B (binding_id, sem TLV). */
    const val BINDING_ID_BYTES = 16

    /** Pubkey SEC1 `0x04||X||Y` tem 65B. */
    const val PUBKEY_BYTES = 65

    /** Desafio TRNG de uso unico tem 32B. */
    const val CHALLENGE_BYTES = 32

    /** `SHA-256(binding_id)` tem 32B. */
    const val HASH_BYTES = 32

    /** Claim cru: `pub(65) || id(16)` = 81B (firmware exige exato). */
    fun claimPayload(pubkeyUncompressed: ByteArray, bindingId: ByteArray): ByteArray {
        require(pubkeyUncompressed.size == PUBKEY_BYTES && pubkeyUncompressed[0] == 0x04.toByte()) {
            "pubkey invalida"
        }
        require(bindingId.size == BINDING_ID_BYTES) { "binding_id invalido" }
        return pubkeyUncompressed + bindingId
    }

    /** Challenge cru: vazio (o device emite o TRNG; parametro = `0x04`). */
    fun challengePayload(): ByteArray = ByteArray(0)

    /**
     * Release cru: `challenge(32) || hash(32) || sig(var)`.
     * `sig` e DER ou cru r||s sobre `challenge || 0x52 || hash`
     * ([BindingKey.coveredMessage] com `BIND_OP_RELEASE`).
     */
    fun releasePayload(challenge: ByteArray, payloadHash: ByteArray, signature: ByteArray): ByteArray {
        require(challenge.size == CHALLENGE_BYTES) { "challenge invalido" }
        require(payloadHash.size == HASH_BYTES) { "hash invalido" }
        require(signature.isNotEmpty()) { "assinatura invalida" }
        return challenge + payloadHash + signature
    }

    /** Confere o eco cru do claim (16B) em tempo constante. */
    fun echoMatches(body: ByteArray, bindingId: ByteArray): Boolean {
        if (body.size != BINDING_ID_BYTES || bindingId.size != BINDING_ID_BYTES) return false
        var diff = 0
        for (i in body.indices) diff = diff or (body[i].toInt() xor bindingId[i].toInt())
        return diff == 0
    }

    /** Le o desafio cru (32B) da resposta. Null se malformado. */
    fun parseChallenge(body: ByteArray): ByteArray? =
        body.takeIf { it.size == CHALLENGE_BYTES }?.copyOf()
}
