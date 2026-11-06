package dev.aegiskey.app.domain.model

/**
 * Marker shown when there is no live silicon session backing a code.
 * Single source of truth for the "------" placeholder: the repository
 * writes it, the UI hides any row carrying it (empty list + neutral
 * "connect the key" hint instead of a counting placeholder row).
 */
const val TOTP_NO_LIVE_CODE = "------"

/** True when [TotpAccountItem.currentCode] carries a live-session code. */
val TotpAccountItem.hasLiveCode: Boolean
    get() = currentCode != TOTP_NO_LIVE_CODE

/** True for a raw code string backed by a live session. */
fun isLiveTotpCode(code: String): Boolean = code != TOTP_NO_LIVE_CODE

/** Drops placeholder rows (no live session) for list/detail rendering. */
fun List<TotpAccountItem>.withLiveCodesOnly(): List<TotpAccountItem> =
    filter { it.hasLiveCode }

data class TotpAccountItem(
    val id: String,
    val issuer: String,
    val accountName: String,
    val currentCode: String,
    val formattedCode: String,
    val remainingSeconds: Int,
    val periodSeconds: Int = 30,
    val digits: Int = 6,
    val requiresTouchToRefresh: Boolean = false,
    val isHotp: Boolean = false,
    val counter: Long = 0L,
    val algorithm: String = "SHA1",
    /**
     * Finding A3: true only when [currentCode] was just returned by the
     * device (OP_OATH_CODE). False (fail-safe default, including all cached
     * items of unknown provenance) means the code was computed locally or is
     * stale: the UI must label it honestly instead of implying device origin.
     */
    val isOnDeviceBacked: Boolean = false
)
