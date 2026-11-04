package dev.aegiskey.app.domain.repository

import dev.aegiskey.app.pm.PmCbor

/**
 * Blind-transport viewer for the device password vault (F-PM2).
 *
 * The phone is a blind transport: list pages carry opaque record ids
 * only (no labels), and the single released field set is transient
 * (display + zeroize, never persisted). Fail-closed gate denials ride
 * [PmGateError] with the frozen §9.5 wire bytes; enforcement lives on
 * the device, never here.
 */
interface PasswordManagerRepository {
    suspend fun listPage(cursor: Long, limit: Int): Result<PmListResult>
    suspend fun getRelease(id: ByteArray): Result<PmCbor.PmRelease>
    suspend fun getStatus(): Result<PmCbor.PmStatus>
}

data class PmListResult(
    val page: PmCbor.PmPage,
    /** Raw status byte of the answering frame (0x00 on success). */
    val status: Int,
)

/**
 * Fail-closed transport/gate failure. [statusName] is log-only
 * (mirrors `pm_status_name`); it never carries payloads or secrets.
 */
class PmGateError(
    val kind: Kind,
    val status: Int,
    val statusName: String,
    message: String,
) : IllegalStateException(message) {
    enum class Kind {
        NEED_BINDING,
        PRESENCE_REQUIRED,
        PIN_REQUIRED,
        DENIED,
        NO_TRANSPORT,
        INVALID_ENVELOPE,
    }
}
