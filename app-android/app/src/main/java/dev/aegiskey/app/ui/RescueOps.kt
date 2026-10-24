package dev.aegiskey.app.ui

/**
 * Rescue `0x2E` sobre BLE (espelha `crates/aegis-fido-core/src/otp/rescue.rs`).
 *
 * Transporte normativo (firmware `run/ble_dispatch.rs`, doc `APP-INTEGRACAO`
 * secao 3.7): o frame RESC viaja como **payload de `OP_MSG (0x83)`**, nunca
 * como opcode de fragmento — `gatt_core.rs` rejeita `0x2E` no reassembler
 * (`InvalidOpcode`, teste `rescue_transport_op_nunca_desvia_*`), e o
 * dispatch BLE so desvia `p[0] == 0x2E` para
 * `dispatch_serial_rescue` dentro do ramo `OP_MSG`.
 *
 * Fio (ida): `sendMsg([0x2E] + frame)` onde
 * `frame = MAGIC "RESC"(4) | VER 0x01(1) | CMD(1) | LEN_BE(2) | PAYLOAD`.
 * Fio (volta): `notify_frame(0x83, status, body)` = `[0x83, status, body...]`
 * com status RESC (`CONFIRMATION_FAILED 0x04` cobre UP/PIN negado).
 *
 * PING (`0x01`) e DIAGNOSTICS (`0x02`) exigem so UP fisico (latch 1,5 s,
 * single-shot). Destrutivos (`0x03` wipe, `0x04` pin-recovery, `0x05`
 * reboot, `0x06` killswitch) exigem UP+PIN (sessao pinUvAuth viva no
 * device) e NAO tem envio nesta tela (fail-closed, sem botao de um toque).
 * Nenhum payload/token e logado (so cmd/status/tamanhos no chamador).
 */
object RescueOps {
    /** Opcode de transporte rescue (primeiro byte do payload de OP_MSG). */
    const val TRANSPORT_OP = 0x2E

    /** Eco esperado no primeiro byte da resposta (ramo OP_MSG). */
    const val OP_MSG = 0x83

    /** Magic `RESC` do frame (rescue.rs `RESCUE_MAGIC`). */
    val MAGIC: ByteArray = byteArrayOf(0x52, 0x45, 0x53, 0x43)

    /** Versao do frame (`RESCUE_VERSION`). */
    const val VERSION = 0x01

    /** Somente-leitura: prova de vida + contadores (so UP). */
    const val CMD_PING = 0x01

    /** Somente-leitura: flags por subsistema (so UP). */
    const val CMD_DIAGNOSTICS = 0x02

    /** Destrutivo: documentado, sem envio pela UI (UP+PIN). */
    const val CMD_EMERGENCY_WIPE = 0x03

    /** Sensivel: documentado, sem envio pela UI (UP+PIN). */
    const val CMD_PIN_RECOVERY = 0x04

    /** Sensivel: documentado, sem envio pela UI (UP+PIN). */
    const val CMD_REBOOT = 0x05

    /** Destrutivo: documentado, sem envio pela UI (UP+PIN + token). */
    const val CMD_KILLSWITCH = 0x06

    const val STATUS_OK = 0x00
    const val STATUS_INVALID_MAGIC = 0x01
    const val STATUS_INVALID_VERSION = 0x02
    const val STATUS_INVALID_COMMAND = 0x03
    const val STATUS_CONFIRMATION_FAILED = 0x04
    const val STATUS_EXECUTION_ERROR = 0x05

    /** Flags de diagnostico (`DIAG_*_OK` no firmware). */
    const val DIAG_CRYPTO_OK = 0x01
    const val DIAG_FLASH_OK = 0x02
    const val DIAG_RNG_OK = 0x04
    const val DIAG_BUTTON_OK = 0x08

    /** Teto do ponto de controle (payload interno deve caber com folga). */
    const val CONTROL_POINT_LENGTH = 512

    fun statusLabel(status: Int): String = when (status) {
        STATUS_OK -> "ok"
        STATUS_INVALID_MAGIC -> "resposta ilegivel (magic)"
        STATUS_INVALID_VERSION -> "versao de resgate incompativel"
        STATUS_INVALID_COMMAND -> "comando desconhecido"
        STATUS_CONFIRMATION_FAILED -> "toque no botao do dispositivo e tente de novo"
        STATUS_EXECUTION_ERROR -> "falha ao executar — tente de novo"
        else -> "erro de resgate (0x" + String.format("%02X", status) + ")"
    }

    fun cmdName(cmd: Int): String = when (cmd) {
        CMD_PING -> "ping"
        CMD_DIAGNOSTICS -> "diagnostico"
        else -> "0x" + String.format("%02X", cmd)
    }

    /**
     * Monta um frame RESC: `[MAGIC(4) | VER(1) | CMD(1) | LEN_BE(2) | PAYLOAD]`.
     * Mesma montagem de `build_packet` no firmware. Falha fechado acima do teto.
     */
    fun buildFrame(cmd: Int, payload: ByteArray): ByteArray {
        require(cmd in 0..255) { "cmd invalido" }
        require(payload.size <= CONTROL_POINT_LENGTH - TRANSPORT_OVERHEAD) { "frame grande demais" }
        val len = payload.size
        return MAGIC + byteArrayOf(VERSION.toByte(), cmd.toByte()) +
            byteArrayOf(((len shr 8) and 0xFF).toByte(), (len and 0xFF).toByte()) +
            payload
    }

    /**
     * Payload pronto p/ `sendMsg` (OP_MSG): `[0x2E] + frame`.
     * O `0x2E` e primeiro byte do **payload**, nunca opcode de fragmento.
     */
    fun opMsgPayload(cmd: Int, payload: ByteArray = ByteArray(0)): ByteArray =
        byteArrayOf(TRANSPORT_OP.toByte()) + buildFrame(cmd, payload)

    /** Resposta rescue: `[0x83, status, body...]`. */
    data class RescueResponse(val status: Int, val body: ByteArray)

    /** Extrai `[status, body]`; null se nao for eco de OP_MSG. */
    fun parseResponse(raw: ByteArray?): RescueResponse? {
        if (raw == null || raw.size < 2) return null
        if ((raw[0].toInt() and 0xFF) != OP_MSG) return null
        return RescueResponse(raw[1].toInt() and 0xFF, raw.copyOfRange(2, raw.size))
    }

    /** Corpo do PING: `[VER(1) | panic u32be | wipe u32be | recovery(1)]` = 10B. */
    data class PingInfo(
        val version: Int,
        val panicCount: Long,
        val wipeCount: Long,
        val recoveryMode: Boolean,
    )

    /** Le o corpo do PING (so contadores/flags — sem segredo). Null se malformado. */
    fun parsePing(body: ByteArray): PingInfo? {
        if (body.size != 10) return null
        if ((body[0].toInt() and 0xFF) != VERSION) return null
        return PingInfo(
            version = body[0].toInt() and 0xFF,
            panicCount = u32be(body, 1),
            wipeCount = u32be(body, 5),
            recoveryMode = body[9].toInt() != 0,
        )
    }

    /** Flags por subsistema do DIAGNOSTICS: `[flags(1) | reservado(7)]`. */
    data class Diagnostics(
        val cryptoOk: Boolean,
        val flashOk: Boolean,
        val rngOk: Boolean,
        val buttonOk: Boolean,
    )

    /** Le o corpo do DIAGNOSTICS. Null se malformado. */
    fun parseDiagnostics(body: ByteArray): Diagnostics? {
        if (body.size != 8) return null
        val flags = body[0].toInt() and 0xFF
        return Diagnostics(
            cryptoOk = (flags and DIAG_CRYPTO_OK) != 0,
            flashOk = (flags and DIAG_FLASH_OK) != 0,
            rngOk = (flags and DIAG_RNG_OK) != 0,
            buttonOk = (flags and DIAG_BUTTON_OK) != 0,
        )
    }

    private fun u32be(b: ByteArray, at: Int): Long =
        ((b[at].toLong() and 0xFF) shl 24) or
            ((b[at + 1].toLong() and 0xFF) shl 16) or
            ((b[at + 2].toLong() and 0xFF) shl 8) or
            (b[at + 3].toLong() and 0xFF)

    /** 1B do transporte + cabecalho RESC (8B) descontados do teto. */
    private const val TRANSPORT_OVERHEAD = 1 + 8
}
