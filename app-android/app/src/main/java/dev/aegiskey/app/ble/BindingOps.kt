package dev.aegiskey.app.ble

import java.security.MessageDigest

/**
 * Vinculo app-dono, lado app (espelha `firmware/src/binding.rs`).
 *
 * Semantica confirmada no firmware:
 * - Claim: pubkey SEC1 (65B) + binding_id (16B sorteado pelo app, ecoado),
 *   exige janela de pareamento (hold 5s) + UP. Sem assinatura no claim.
 * - Challenge 32B (TRNG, uso unico); assinatura cobre
 *   `challenge(32) || op(1B) || payload_hash(32)` (65B).
 * - Release: op `0x52` (`BIND_OP_RELEASE`) sobre `sha256(binding_id)`;
 *   sucesso faz wipe (novo dono faz claim novo). Reset fisico tambem solta.
 * - Status: `0x05` NEED_BINDING (gates BLE/WiFi; USB nunca ve).
 *   `AlreadyClaimed` mapeia `0x04`: num claim bem-formado, `0x04` = ja tem
 *   dono = "dispositivo de outra pessoa".
 * - Reusa framing S3 via AegisBleClient.sendVendor e TLV BER de [VendorOps]
 *   (tags 0x10-0x13 livres: KEY usa 0x01-0x06, OATH usa 0x71+).
 *
 * PENDENCIA (track firmware): o despacho GATT do claim/challenge/verify/
 * release ainda nao existe no `ble_gatt.rs` (faixa vendor golden 0x20-0x27,
 * `0x28` hoje = InvalidOpcode). Os opcodes 0x28-0x2B abaixo sao a proposta
 * de transporte — convergir com o firmware antes do release IRL.
 * Nenhum payload sensivel e logado (so opcodes/status/tamanhos no chamador).
 */
object BindingOps {
    const val OP_BINDING_CLAIM = 0x28
    const val OP_BINDING_CHALLENGE = 0x29
    const val OP_BINDING_VERIFY = 0x2A
    const val OP_BINDING_RELEASE = 0x2B
    const val OP_RECOVERY_SET = 0x2C
    const val OP_RECOVERY_UNLOCK = 0x2D

    const val STATUS_NEED_BINDING = 0x05

    /** Op interno assinado no release (`BIND_OP_RELEASE` no firmware). */
    const val BIND_OP_RELEASE = 0x52

    const val TAG_PUBKEY = 0x10
    const val TAG_BINDING_ID = 0x11
    const val TAG_CHALLENGE = 0x12
    const val TAG_SIGNATURE = 0x13

    const val PUBKEY_BYTES = 65
    const val BINDING_ID_BYTES = 16
    const val CHALLENGE_BYTES = 32
    const val RAW_SIG_BYTES = 64

    fun isBindingOp(op: Int): Boolean = op in OP_BINDING_CLAIM..OP_RECOVERY_UNLOCK

    fun opName(op: Int): String = when (op) {
        OP_BINDING_CLAIM -> "0x28 binding-claim"
        OP_BINDING_CHALLENGE -> "0x29 binding-challenge"
        OP_BINDING_VERIFY -> "0x2A binding-verify"
        OP_BINDING_RELEASE -> "0x2B binding-release"
        OP_RECOVERY_SET -> "0x2C recovery-set"
        OP_RECOVERY_UNLOCK -> "0x2D recovery-unlock"
        else -> "0x" + String.format("%02X", op)
    }

    fun statusLabel(status: Int): String = when (status) {
        STATUS_NEED_BINDING -> "sem vinculo — faca a primeira configuracao"
        else -> VendorOps.statusLabel(status)
    }

    /**
     * Num claim bem-formado, `0x04` significa `AlreadyClaimed` (o firmware
     * nao tem status proprio p/ isso): o dispositivo ja tem dono.
     */
    fun claimMeansAlreadyOwned(status: Int): Boolean =
        status == VendorOps.STATUS_BAD_ENVELOPE

    /** Claim: 0x10 pubkey SEC1 (65B) + 0x11 binding_id (16B). Exige UP + janela. */
    fun claimRequest(pubkeyUncompressed: ByteArray, bindingId: ByteArray): ByteArray {
        require(pubkeyUncompressed.size == PUBKEY_BYTES && pubkeyUncompressed[0] == 0x04.toByte()) {
            "pubkey invalida"
        }
        require(bindingId.size == BINDING_ID_BYTES) { "binding_id invalido" }
        return VendorOps.writeTlv(TAG_PUBKEY, pubkeyUncompressed) +
            VendorOps.writeTlv(TAG_BINDING_ID, bindingId)
    }

    /** Confere o eco do binding_id (16B) na resposta do claim. */
    fun echoMatches(tlv: ByteArray, bindingId: ByteArray): Boolean {
        val echo = VendorOps.findTlv(VendorOps.parseTlvRecords(tlv), TAG_BINDING_ID)
            ?: return false
        return MessageDigest.isEqual(echo, bindingId)
    }

    const val RECOVERY_PIN_MIN_LEN = 4
    const val RECOVERY_PIN_MAX_LEN = 6

    /** Senha de 4-6 digitos? (mesma regra do firmware is_valid_recovery_pin). */
    fun isValidRecoveryPin(pin: String): Boolean =
        pin.length in RECOVERY_PIN_MIN_LEN..RECOVERY_PIN_MAX_LEN && pin.all { it.isDigit() }

    /** Recovery 0x2C/0x2D: so o texto da senha em ASCII (4-6B, sem TLV). Zerar apos o envio; nunca logar. */
    fun recoveryPinRequest(pin: String): ByteArray {
        require(isValidRecoveryPin(pin)) { "senha 4..6 digitos" }
        return pin.toByteArray(Charsets.US_ASCII)
    }

    /** Texto simples p/ erro do recovery (0x2D nunca devolve 0x05; tentativas contam no device). */
    fun recoveryStatusLabel(status: Int): String = when (status) {
        VendorOps.STATUS_OK -> "ok"
        VendorOps.STATUS_NEED_UP -> "toque no botao do dispositivo e tente de novo"
        VendorOps.STATUS_NEED_PIN -> "senha errada ou bloqueada - confira os digitos"
        STATUS_NEED_BINDING -> "sem vinculo - faca a primeira configuracao"
        else -> VendorOps.statusLabel(status)
    }

    /** Challenge: 0x11 binding_id (pede novo desafio 32B p/ assinar). */
    fun challengeRequest(bindingId: ByteArray): ByteArray {
        require(bindingId.size == BINDING_ID_BYTES) { "binding_id invalido" }
        return VendorOps.writeTlv(TAG_BINDING_ID, bindingId)
    }

    /** Le challenge (0x12, 32B) da resposta. */
    fun parseChallenge(tlv: ByteArray): ByteArray? =
        VendorOps.findTlv(VendorOps.parseTlvRecords(tlv), TAG_CHALLENGE)
            ?.takeIf { it.size == CHALLENGE_BYTES }

    /** Release: 0x11 binding_id + 0x13 assinatura crua r||s (64B). */
    fun releaseRequest(bindingId: ByteArray, signatureRaw: ByteArray): ByteArray {
        require(bindingId.size == BINDING_ID_BYTES) { "binding_id invalido" }
        require(signatureRaw.size == RAW_SIG_BYTES) { "assinatura invalida" }
        return VendorOps.writeTlv(TAG_BINDING_ID, bindingId) +
            VendorOps.writeTlv(TAG_SIGNATURE, signatureRaw)
    }
}
